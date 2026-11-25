"""Offline tests of the IS-IS lab "IPv6 multi-topologie, segment routing et BFD"
(lab/sre/_DRAFT_misc/isis-ipv6-sr-bfd.py).

No Docker, no FRR: a model of the four sites (``World``) holds what has been done, as a set of
features (``mt_ipv6``, ``sr_no_php``, ``bfd_bfd``...), and renders the outputs the grader reads in
the shapes captured live on Debian 13 (FRR 10.3: the ``isis_*`` / ``bfd_*`` / ``config_isis_*``
fixtures of ``tests/mock_data/frr``, the MPLS shapes of ``tests/mock_data/mpls``).  The behaviours
follow what was seen live: in single topology the IPv6 route of ``mt_r2`` towards ``mt_lan4`` goes
through ``mt_r1`` (which sends it back), with the multi-topology through ``mt_r3``; the label of a
segment routing hop is the SRGB of the next hop plus the index; a silent cut of the bridge costs the
whole cut without BFD and a fraction of a second with it.  Covers the data, the topology, the state
ops, the two-pass grading contract (nothing done: 0; everything: 100 + 6 bonus points; **each part
alone gives exactly its points and everything but one part the rest**) and the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from frr import parse_frr_config  # noqa: E402
from mpls import MPLS_COUNTERS_CMD  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'isis-ipv6-sr-bfd.py'

PARTS = {
    'mt': {'mt_ipv6', 'mt_topology'},
    'sr': {'sr_sr', 'sr_no_php'},
    'bfd': {'bfd_bfd', 'bfd_hello'},
    'tilfa': {'tl_tilfa'},
}
POINTS = {'mt': 34, 'sr': 33, 'bfd': 33, 'tilfa': 6}
SOLVE_STATE = {'mt': 'solve_mt', 'sr': 'solve_sr', 'bfd': 'solve_bfd', 'tilfa': 'solve_tilfa'}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {
    'mt_q_nlpid': 'mt', 'mt_q_mt_id': 'mt', 'mt_q_tlv_st': 'mt', 'mt_q_tlv_mt': 'mt', 'mt_q_single': 'mt',
    'mt_q_nexthop': 'mt',
    'sr_q_push4': 'sr', 'sr_q_label_l23': 'sr', 'sr_q_label_l34': 'sr', 'sr_q_push3': 'sr', 'sr_q_capability': 'sr',
    'sr_q_subtlv': 'sr', 'sr_q_no_php': 'sr',
    'bfd_q_port': 'bfd', 'bfd_q_detection': 'bfd', 'bfd_q_hold': 'bfd', 'bfd_q_outage': 'bfd', 'bfd_q_fast_hold': 'bfd',
    'bfd_q_interface': 'bfd', 'bfd_q_path': 'bfd',
}
FORM_POINTS = {'mt': 6, 'sr': 7, 'bfd': 7}
CHOICE_ELEMENTS = {'mt_q_single', 'mt_q_nexthop', 'sr_q_no_php', 'bfd_q_interface', 'bfd_q_path'}
BONUS_ELEMENTS = ['tl_backup', 'tl_node', 'tl_repair']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('isis_mt_sr_bfd_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _running_name():
    return params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')


def _text(t, lang='fr'):
    return t.resolve(lang) if hasattr(t, 'resolve') else str(t)


def _mentions(text, value):
    """True when *value* appears in *text* as a whole (a random 530 is not in "RFC 5305")."""
    return re.search(r'(?<![0-9A-Za-z.])' + re.escape(value) + r'(?![0-9A-Za-z])', text) is not None


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    if hasattr(ns, 'remount_proc_sys_done'):
        del ns.remount_proc_sys_done
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    return ops


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


def _vtysh_commands(command):
    """The configuration lines of a `vtysh -c "configure terminal" -c ... -c "end" -c "write"`."""
    lines = re.findall(r'-c "([^"]*)"', command)
    assert lines[0] == 'configure terminal' and lines[-2:] == ['end', 'write'], command
    return lines[1:-2]


def _as_frr_config(lines):
    """vtysh session lines rewritten as an frr.conf (statements inside a block indented)."""
    out, depth = [], 0
    for line in lines:
        if line == 'exit':
            depth = max(0, depth - 1)
            out.append(' ' * depth + line)
            continue
        out.append(' ' * depth + line)
        if line.startswith(('router ', 'interface ', 'profile ')) or line == 'bfd':
            depth += 1
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# a model of the sites: features -> what the grader reads
# ---------------------------------------------------------------------------


def _route(prefix, gateway, dev, labels=None, protocol='isis'):
    """One entry of ``ip -j route`` / ``ip -j -6 route`` (host routes without their length)."""
    dst = str(prefix)
    if dst.endswith('/32') or dst.endswith('/128'):
        dst = dst.rsplit('/', 1)[0]
    entry = {'dst': dst}
    if labels:
        entry['encap'] = {'encap_type': 'mpls', 'dst': "/".join(str(x) for x in labels)}
    entry.update({'gateway': str(gateway), 'dev': dev, 'protocol': protocol, 'metric': 20, 'flags': []})
    return entry


def _ilm(label, out=None, via=None, dev=None):
    """One entry of ``ip -j -f mpls route`` (shape of ilm_*_final.json)."""
    entry = {'dst': str(label)}
    if out:
        entry['to'] = "/".join(str(x) for x in out)
    if via:
        entry['via'] = {'family': 'inet', 'host': str(via)}
    entry.update({'dev': dev or 'eth0', 'protocol': 'isis', 'flags': []})
    return entry


def _ping_output(dest, lost):
    """A ``ping -i 0.05`` output in which the echo requests 21 to 20 + *lost* got no reply."""
    count = 160
    lines = [f"PING {dest} ({dest}) 56(84) bytes of data."]
    lines += [f"64 bytes from {dest}: icmp_seq={n} ttl=61 time=2.3 ms" for n in range(1, count + 1)
              if not 21 <= n <= 20 + lost]
    return "\n".join(lines) + f"\n\n--- {dest} ping statistics ---\n{count} packets transmitted, {count - lost} received\n"


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    # -- configurations -------------------------------------------------------------------

    def running_config(self, r):
        f, ns, lab = self.f, self.ns, self.lab
        lines = list(ns._given_lines(r))
        site = lab.site_of(r)
        if site == 'mt':
            if 'mt_ipv6' in f:
                lines += ns.solution_ipv6()[r]
            if 'mt_topology' in f:
                lines += ns.solution_topology()[r]
        elif site == 'sr' and 'sr_sr' in f:
            sr = ns.solution_sr()[r]
            if 'sr_no_php' not in f:
                sr = [x.replace(' no-php-flag', '') for x in sr]
            lines += sr
        elif r in ('bfd_r1', 'bfd_r2') and 'bfd_bfd' in f:
            lines += ns.solution_bfd()[r]
        elif r == 'tl_r1' and 'tl_tilfa' in f:
            lines += ns.solution_tilfa()['tl_r1']
        text = "Building configuration...\n\nCurrent configuration:\n!\nfrr version 10.3\nfrr defaults traditional\n!\n"
        return text + _as_frr_config(lines) + "end\n"

    # -- mt -----------------------------------------------------------------------------

    def kernel6(self, r):
        f, ns = self.f, self.ns
        routes = [{'dst': str(ns.net6(n)), 'dev': f"eth{i}", 'protocol': 'kernel', 'metric': 256, 'flags': []}
                  for i, n in enumerate(self.lab.ROUTER_IFACES[r]) if n in self.lab.MT_IPV6_NETS]
        if 'mt_ipv6' not in f:
            return routes
        ll = "fe80::a8c1:abff:fe00:1"
        if r == 'mt_r1':
            routes += [_route(ns.net6('mt_lan4'), ll, 'eth1'), _route(f"{ns.lo6('mt_r4')}/128", ll, 'eth1')]
        elif r == 'mt_r2':
            # single topology: through mt_r1 (and the IPv4-only mt_l14); multi-topology: mt_r3
            dev = 'eth1' if 'mt_topology' in f else 'eth0'
            routes += [_route(ns.net6('mt_lan4'), ll, dev), _route(f"{ns.lo6('mt_r4')}/128", ll, dev)]
        elif r == 'mt_r4':
            routes.append(_route(ns.net6('mt_lan1'), ll, 'eth1'))
        return routes

    def kernel4(self, r):
        ns, d = self.ns, self.d
        routes = [{'dst': str(ns.net(n)), 'dev': f"eth{i}", 'protocol': 'kernel', 'scope': 'link', 'flags': []}
                  for i, n in enumerate(self.lab.ROUTER_IFACES[r])]
        if r == 'mt_r1':
            routes.append(_route(ns.net('mt_lan4'), ns.addr('mt_r4', 'mt_l14'), 'eth2'))
        elif r == 'sr_r1':
            labels = [d.sr_srgb + d.sr_index4] if 'sr_sr' in self.f else None
            routes.append(_route(f"{ns.lo('sr_r4')}/32", ns.addr('sr_r2', 'sr_l12'), 'eth0', labels))
        return routes

    # -- sr -----------------------------------------------------------------------------

    def ilm(self, r):
        f, d, addr = self.f, self.d, self.ns.addr
        srgb, srgb3, i4 = d.sr_srgb, d.sr_srgb_r3, d.sr_index4
        if 'sr_sr' not in f:
            return []
        if r == 'sr_r2':
            return [_ilm(srgb + i4, [srgb3 + i4], addr('sr_r3', 'sr_l23'), 'eth1')]
        if r == 'sr_r3':
            out = [srgb + i4] if 'sr_no_php' in f else None
            return [_ilm(srgb3 + i4, out, addr('sr_r4', 'sr_l34'), 'eth1')]
        if r == 'sr_r4' and 'sr_no_php' in f:
            return [_ilm(srgb + i4, dev='lo')]
        return []

    def counters(self, r, step):
        rx = 100 + (7 if 'sr_sr' in self.f and step == 3 else 0)
        return [{'ifindex': 2, 'ifname': 'eth0', 'group': 'afstats', 'subgroup': 'mpls',
                 'mpls_stats': {'rx': {'bytes': 84 * rx, 'packets': rx, 'errors': 0, 'dropped': 0, 'noroute': 0},
                                'tx': {'bytes': 0, 'packets': 0, 'errors': 0, 'dropped': 0}}}]

    # -- bfd ----------------------------------------------------------------------------

    def bfd_peers(self, r):
        if 'bfd_bfd' not in self.f:
            return []
        d, ns = self.d, self.ns
        peer = 'bfd_r2' if r == 'bfd_r1' else 'bfd_r1'
        return [{'multihop': False, 'peer': str(ns.addr(peer, 'bfd_l12')), 'local': str(ns.addr(r, 'bfd_l12')),
                 'vrf': 'default', 'interface': self.lab.iface(r, 'bfd_l12'), 'id': 1, 'remote-id': 2,
                 'passive-mode': False, 'status': 'up', 'uptime': 30, 'diagnostic': 'ok', 'remote-diagnostic': 'ok',
                 'type': 'dynamic', 'receive-interval': d.bfd_interval, 'transmit-interval': d.bfd_interval,
                 'echo-receive-interval': 50, 'echo-transmit-interval': 0, 'detect-multiplier': d.bfd_multiplier,
                 'remote-receive-interval': d.bfd_interval, 'remote-transmit-interval': d.bfd_interval,
                 'remote-echo-receive-interval': 50, 'remote-detect-multiplier': d.bfd_multiplier}]

    def bfd_neighbors(self):
        ns = self.ns
        blocks = ["Area CORE:"]
        for peer, link in (('bfd_r2', 'bfd_l12'), ('bfd_r3', 'bfd_l13')):
            lines = [f" {peer:<20}", f"    Interface: {self.lab.iface('bfd_r1', link)}, Level: 2, State: Up, Expires in 28s",
                     "    Adjacency flaps: 1, Last: 1m0s ago", "    Circuit type: L2, Speaks: IPv4",
                     "    SNPA: 2020.2020.2020", "    Area Address(es):", f"      {self.d.bfd_area}",
                     "    IPv4 Address(es):", f"      {ns.addr(peer, link)}"]
            if peer == 'bfd_r2' and 'bfd_bfd' in self.f:
                lines.append("    BFD is active, status Up")
            blocks.append("\n".join(lines) + "\n")
        return "\n".join(blocks)

    def bfd_interfaces(self, r):
        fast = 'bfd_hello' in self.f
        circuits = []
        for i, n in enumerate(self.lab.ROUTER_IFACES[r]):
            hello, count = (1, 3) if fast and n == 'bfd_l34' else (3, 10)
            circuits.append({'circuit': 0, 'interface': {
                'name': f"eth{i}", 'state': 'Up', 'is-passive': 'active', 'circuit-id': '0x0', 'type': 'p2p',
                'level': 'L2', 'levels': [{'level': 'L2', 'metric': 10, 'active-neighbors': 1, 'hello-interval': hello,
                                           'holddown': {'count': count, 'pad': 'yes'}, 'cnsp-interval': 10,
                                           'psnp-interval': 2}]}})
        return json.dumps({'areas': [{'area': 'CORE', 'circuits': circuits}]}, indent=2)

    # -- tl -----------------------------------------------------------------------------

    def tl_routes(self):
        ns = self.ns
        r3 = f"{ns.lo('tl_r3')}/32"
        route = {'prefix': r3, 'protocol': 'isis', 'selected': True, 'installed': True, 'metric': 30,
                 'nexthops': [{'ip': str(ns.addr('tl_r2', 'tl_l12')), 'interfaceName': 'eth0', 'active': True,
                               'fib': True, 'labels': [16003]}]}
        if 'tl_tilfa' in self.f:
            route['backupNexthops'] = [{'ip': str(ns.addr('tl_r4', 'tl_l14')), 'interfaceName': 'eth1',
                                        'active': True, 'labels': [16003]}]
        return {r3: [route]}

    # -- every command ------------------------------------------------------------------

    def output(self, machine, command, step):
        lab = self.lab
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'ip -j -6 route':
            return json.dumps(self.kernel6(machine)), 0
        if command == 'ip -j route':
            return json.dumps(self.kernel4(machine)), 0
        if command == 'ip -j -f mpls route':
            return json.dumps(self.ilm(machine)), 0
        if command == MPLS_COUNTERS_CMD:
            return json.dumps(self.counters(machine, step)), 0
        if command == 'vtysh -c "show bfd peers json"':
            return json.dumps(self.bfd_peers(machine), indent=2), 0
        if command == 'vtysh -c "show isis neighbor detail"' and machine == 'bfd_r1':
            return self.bfd_neighbors(), 0
        if command == 'vtysh -c "show isis interface detail json"':
            return self.bfd_interfaces(machine), 0
        if command == 'vtysh -c "show ip route json"' and machine == 'tl_r1':
            return json.dumps(self.tl_routes()), 0
        if machine == lab.BRIDGE:
            assert command == lab.UNCUT_CMD and step == 1 or 'nft -f -' in command and step == 2, command
            return '', 0
        if machine == 'bfd_h1' and command.startswith('ping -i '):
            lost = 6 if 'bfd_bfd' in self.f else 107
            return _ping_output(str(self.d.ips.bfd_h4.ip), lost), 0
        m = re.fullmatch(r'ping -c 3 -w 5 (\S+)', command)
        if m and machine in ('mt_h1', 'mt_h4'):
            if PARTS['mt'] <= self.f:
                return f"64 bytes from {m.group(1)}: icmp_seq=1 ttl=62 time=1 ms\n", 0
            return "3 packets transmitted, 0 received\n", 1
        if command.startswith('ping -c 5 ') and machine == 'sr_r1':
            return ('5 received\n', 0) if 'sr_sr' in self.f else ('0 received\n', 1)
        raise AssertionError(f"unexpected command on {machine}: {command}")


def _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES, answers='final', instructor_mode=False):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme).  *answers*: the state whose
    cheat answers fill the forms (None: no answer)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    model = World(lab, ns, features)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            grade._answers = dict(grade.get_cheat_answers(answers) or {}) if answers else {}
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = model.output(m, key[0], s)
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _totals(grade):
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus))


def _lost(grade):
    return {title for title, (got, best) in _grades(grade).items() if got != best}


def _parts(grade):
    result = {str(p.title): 0 for p in grade.get_grade_parts()}
    for e in grade.get_grade_list():
        result[str(e.grade_part)] += e.grade
    return result


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_dict() == data.to_dict()
        lab.Data.unpack(data.pack())

    def test_addressing(self, lab, data):
        instance = data.nets.instance
        assert instance.prefixlen == 16 and instance.subnet_of(IPv4Network('10.0.0.0/8'))
        nets = [getattr(data.nets, n) for n in list(lab.LINKS) + lab.LANS]
        nets += [getattr(data.nets, f"{s}_lo") for s in lab.SITE_NUMBER]
        assert all(n.subnet_of(instance) for n in nets)
        assert not any(a.overlaps(b) for i, a in enumerate(nets) for b in nets[i + 1:])
        v6 = data.nets6.instance
        assert v6.prefixlen == 48 and v6.subnet_of(IPv6Network('fd00::/8'))
        nets6 = [getattr(data.nets6, n) for n in lab.MT_IPV6_NETS] + [data.nets6.mt_lo]
        assert all(n.subnet_of(v6) and n.prefixlen == 64 for n in nets6)
        assert len(set(nets6)) == len(nets6)
        assert not hasattr(data.nets6, 'mt_l14') and not hasattr(data.ips6, 'mt_r1_mt_l14')
        # the bridged link is one IP link: both ends in the same /30
        assert data.ips.bfd_r1_bfd_l12.network == data.ips.bfd_r2_bfd_l12.network == data.nets.bfd_l12

    def test_values(self, lab, data):
        assert len({data.mt_area, data.sr_area, data.bfd_area, data.tl_area}) == 4
        assert data.sr_srgb in lab.SR_SRGB_BASES and data.sr_srgb_r3 in lab.SR_R3_SRGB_BASES
        assert len({data.sr_index1, data.sr_index2, data.sr_index3, data.sr_index4}) == 4
        assert data.bfd_interval in lab.BFD_INTERVALS and data.bfd_multiplier in lab.BFD_MULTIPLIERS
        # FRR does not write the default 300 ms in the configuration: the profile always shows its intervals
        assert 300 not in lab.BFD_INTERVALS
        assert data.bfd_interval * data.bfd_multiplier / 1000 + 1 < lab.MAX_OUTAGE < lab.CUT_SECONDS - 1


class TestTopology:
    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert len(specs) == 21
        assert all('routing-frr13' in specs[r]['image'] for r in lab.ROUTER_IFACES)
        assert {m for m, s in specs.items() if s.get('allow_connection') is False} == {'tl_r2', 'tl_r3', 'tl_r4',
                                                                                       'bfd_sw'}
        assert {m for m, s in specs.items() if s.get('ipv6')} == {'mt_r1', 'mt_r2', 'mt_r3', 'mt_r4', 'mt_h1', 'mt_h4'}

    def test_collision_domains(self, lab):
        assert lab._TOPOLOGY['bfd_l1s'] == {'bfd_r1': 1, 'bfd_sw': 0}
        assert lab._TOPOLOGY['bfd_ls2'] == {'bfd_r2': 0, 'bfd_sw': 1}
        assert 'bfd_l12' not in lab._TOPOLOGY
        for net, members in lab._TOPOLOGY.items():
            assert {lab.site_of(m) for m in members} == {lab.site_of(net)}, net

    def test_net_config(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        r1 = ns.net_config['mt_r1']
        assert [len(addresses) for addresses, _routes in r1] == [2, 2, 1]     # mt_l14: IPv4 only
        h1 = ns.net_config['mt_h1'][0][1]
        assert (IPv6Network('::/0'), ns.addr6('mt_r1', 'mt_lan1')) in h1
        assert ns.net_config['bfd_h1'][0][1] == [(IPv4Network('0.0.0.0/0'), ns.addr('bfd_r1', 'bfd_lan1'))]
        assert f"{ns.lo6('mt_r3')}\tmt_r3-lo" in ns.hosts_content


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.ROUTER_IFACES:
            files = _files(ops, 2, r)
            assert 'isisd=yes' in files['/etc/frr/daemons']
            assert ('bfdd=yes' in files['/etc/frr/daemons']) == r.startswith('bfd_')
            assert 'systemctl start frr' in _cmds(ops, 3, r)
        for r in ('mt_r1', 'mt_r4'):
            assert "sysctl -w net.ipv6.conf.eth2.disable_ipv6=1" in _cmds(ops, 1, r)
        assert any(c.startswith('ip -6 addr add') for c in _cmds(ops, 1, 'mt_r2'))
        for r in lab.MPLS_ROUTERS:
            assert any('encap mpls' in c for c in _cmds(ops, 1, r))
            assert f"sysctl -w net.mpls.platform_labels={lab.PLATFORM_LABELS}" in _cmds(ops, 2, r)
        assert not any('mpls' in c for c in _cmds(ops, 1, 'bfd_r1') + _cmds(ops, 2, 'bfd_r1'))
        assert any('type bridge' in c for c in _cmds(ops, 1, 'bfd_sw'))

    def test_given_configurations(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        conf = {r: parse_frr_config(_files(ops, 2, r)['/etc/frr/frr.conf']) for r in lab.ROUTER_IFACES}
        for r in lab.ROUTER_IFACES:
            ri = conf[r]['router_isis']
            assert ri['present'] and ri['is_type'] == 'level-2-only' and ri['nets'] == [ns.net_title(r)]
            assert not ri['topologies'] and all(i['isis']['ipv6'] is None for i in conf[r]['interfaces'].values())
            assert ri['segment_routing']['enabled'] == r.startswith('tl_')
            assert (ri['lsp_gen_interval'] == 1) == r.startswith('bfd_')
        assert conf['mt_r3']['interfaces']['eth1']['isis']['metric'] == {'all': lab.MT_L34_METRIC}
        assert conf['bfd_r1']['interfaces']['eth2']['isis']['metric'] == {'all': lab.BFD_BACKUP_METRIC}
        assert conf['tl_r3']['router_isis']['segment_routing']['prefixes'] == {
            f"{ns.lo('tl_r3')}/32": {'index': 3, 'no_php': False, 'explicit_null': False}}
        assert conf['bfd_r1']['bfd'] == {'profiles': {}}

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'solve_mt')
        assert {m for (step, m) in ops if step == 1} == {'mt_r1', 'mt_r2', 'mt_r3', 'mt_r4'}
        r1 = _vtysh_commands(_cmds(ops, 1, 'mt_r1')[0])
        assert r1.count('ipv6 router isis CORE') == 3 and 'interface eth2' not in r1
        assert _vtysh_commands(_cmds(ops, 2, 'mt_r1')[0]) == ['router isis CORE', 'topology ipv6-unicast', 'exit']
        ops = _state_ops(ns, 'solve_sr')
        r3 = parse_frr_config(_as_frr_config(_vtysh_commands(_cmds(ops, 1, 'sr_r3')[0])))['router_isis']
        assert r3['segment_routing']['srgb'] == (data.sr_srgb_r3, data.sr_srgb_r3 + lab.SRGB_SIZE - 1)
        r4 = parse_frr_config(_as_frr_config(_vtysh_commands(_cmds(ops, 1, 'sr_r4')[0])))['router_isis']
        assert r4['segment_routing']['prefixes'][f"{ns.lo('sr_r4')}/32"] == {
            'index': data.sr_index4, 'no_php': True, 'explicit_null': False}
        ops = _state_ops(ns, 'solve_bfd')
        r1 = parse_frr_config(_as_frr_config(_vtysh_commands(_cmds(ops, 1, 'bfd_r1')[0])))
        assert r1['bfd']['profiles']['FAST'] == {'detect_multiplier': data.bfd_multiplier,
                                                 'receive_interval': data.bfd_interval,
                                                 'transmit_interval': data.bfd_interval}
        assert r1['interfaces']['eth1']['isis']['bfd'] and r1['interfaces']['eth1']['isis']['bfd_profile'] == 'FAST'
        r3 = parse_frr_config(_as_frr_config(_vtysh_commands(_cmds(ops, 1, 'bfd_r3')[0])))
        assert r3['interfaces']['eth1']['isis']['hello_interval'] == {'all': 1}
        assert _cmds(ops, 1, 'bfd_sw') == [lab.UNCUT_CMD]
        ops = _state_ops(ns, 'solve_tilfa')
        tl = parse_frr_config(_as_frr_config(_vtysh_commands(_cmds(ops, 1, 'tl_r1')[0])))
        assert {i['isis']['fast_reroute']['level-2'] for i in tl['interfaces'].values()} == {'node'}

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        union = {}
        for state in SOLVE_STATE.values():
            for (step, m), op_list in _state_ops(ns, state).items():
                if not any(str(o).startswith('sleep ') for o in op_list):
                    union.setdefault(m, []).extend(str(o) for o in op_list)
        final = {}
        for (step, m), op_list in _state_ops(ns, 'final').items():
            if not any(str(o).startswith('sleep ') for o in op_list):
                final.setdefault(m, []).extend(str(o) for o in op_list)
        assert {m: sorted(v) for m, v in final.items()} == {m: sorted(v) for m, v in union.items()}


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 100
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len(elements) == 44 and len({str(e.title) for e in elements}) == 44

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (100, 6)
        assert _parts(grade) == POINTS

    @pytest.mark.parametrize('part', list(PARTS))
    def test_a_part_alone(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=PARTS[part], answers=SOLVE_STATE[part])
        assert _parts(grade) == {key: (POINTS[key] if key == part else 0) for key in POINTS}

    @pytest.mark.parametrize('part', list(PARTS))
    def test_everything_but_a_part(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - PARTS[part], answers='final')
        assert _parts(grade) == {key: (FORM_POINTS.get(part, 0) if key == part else POINTS[key]) for key in POINTS}

    def test_every_data_set(self, lab, tmp_pub_dir):
        for _ in range(10):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (100, 6)
            assert _totals(_simulate(lab, d, tmp_pub_dir, features=set(), answers=None)[0]) == (0, 0)

    def test_scopes_and_bonus(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for e in grade.get_grade_list():
            expected = params.EXO_EVAL_SCOPE if str(e.title) in CHOICE_ELEMENTS else params.BOTH_EVAL_SCOPE
            assert e.scope == expected, e.title
        assert [str(e.title) for e in grade.get_grade_list() if e.bonus] == BONUS_ELEMENTS

    def test_answers_only_and_wrong_answers(self, lab, data, tmp_pub_dir):
        answers_only, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _lost(answers_only) == set(_grades(answers_only)) - set(FORM_ELEMENTS)
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0) == (20, 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (80, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('mt_topology', {'mt_topology', 'mt_r2_path', 'mt_r2_lo', 'mt_ipv4_kept', 'mt_ping6'}),
        ('mt_ipv6', {'mt_ipv6_ifaces', 'mt_prefixes', 'mt_r2_path', 'mt_r2_lo', 'mt_ping6'}),
        ('sr_no_php', {'sr_no_php'}),
        ('sr_sr', {'sr_enabled', 'sr_srgb', 'sr_index', 'sr_r2_swap', 'sr_no_php', 'sr_r1_push', 'sr_ping'}),
        ('bfd_hello', {'bfd_hello'}),
        ('bfd_bfd', {'bfd_profile', 'bfd_isis', 'bfd_up', 'bfd_timers', 'bfd_isis_neighbor', 'bfd_failover'}),
        ('tl_tilfa', set(BONUS_ELEMENTS)),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

    def test_ping_outage(self, lab):
        assert lab._ping_outage(_ping_output('10.0.0.1', 6)) == (154, pytest.approx(0.30))
        assert lab._ping_outage(_ping_output('10.0.0.1', 107))[1] == pytest.approx(5.35)
        assert lab._ping_outage('') == (0, None)

    def test_other_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir)
        cheat = dict(grade.get_cheat_answers('final'))
        forms = {_text(q.title).split('. ', 1)[1]: q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)}

        def regrade(title, **changes):
            q = forms[title]
            stored = cheat[q.question_hash]
            answers = dict(json.loads(stored) if isinstance(stored, str) else stored, **changes)
            changed = dict(cheat, **{q.question_hash: json.dumps(answers) if isinstance(stored, str) else answers})
            return _grades(_simulate_with_answers(lab, data, tmp_pub_dir, changed)[0])

        for spelling, points in (('0x8e', 1), ('0X8E', 1), ('8E', 1), ('8e', 1), ('142', 1), ('0xcc', 0), ('', 0)):
            assert regrade("Observations sur le site mt", nlpid=spelling)['mt_q_nlpid'][0] == points, spelling
        wrong = str(data.sr_srgb + data.sr_index4)      # the SRGB of sr_r2 used on the link sr_l23
        assert regrade("Les labels du segment routing", label_l23=wrong)['sr_q_label_l23'][0] == 0
        assert regrade("Observations sur le site bfd", detection=str(data.bfd_interval))['bfd_q_detection'][0] == 0

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 3
        for state in ['final'] + list(SOLVE_STATE.values()):
            cheat = grade.get_cheat_answers(state) or {}
            for q in forms:
                if q.question_hash not in cheat:
                    continue
                answers = cheat[q.question_hash]
                answers = json.loads(answers) if isinstance(answers, str) else answers
                assert set(answers) == {field['name'] for field in q.fields}
                for field in q.fields:
                    if 'choices' in field:
                        assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])
                    elif 'regex' in field:
                        assert re.fullmatch(field['regex'], answers[field['name']]), field['name']
        assert len(grade.get_cheat_answers('final')) == 3
        assert grade.get_cheat_answers('solve_tilfa') is None


def _simulate_with_answers(lab, data, tmp_pub_dir, cheat):
    original = lab.Grade.get_cheat_answers
    try:
        lab.Grade.get_cheat_answers = lambda self, state: cheat
        return _simulate(lab, data, tmp_pub_dir)
    finally:
        lab.Grade.get_cheat_answers = original


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _all_texts(grade, ns):
    texts = [('informations', _text(ns.informations))]
    for q in grade.get_questions_ordered():
        texts.append((_text(q.title), _text(q.description)))
    for e in grade.get_grade_list():
        texts.append((str(e.title), _text(e.description) if e.description else ''))
    return texts


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 8
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 8 and 'informations' not in with_fragment

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), where
            assert '@@{{' not in text, where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        from SRE.informations import resolve_informations, resolve_text
        resolved, numbering = resolve_informations(ns1.informations)
        informations = _text(resolved)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'reminder', 'ipv6', 'topology', 'sr', 'detection', 'tilfa']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        for value in (str(data.nets.instance.network_address), str(data.sr_srgb_r3), f"{data.bfd_interval} ms",
                      'Partie 1', 'mt_r1', 'bfd_sw'):
            assert not _mentions(informations, value), value

    def test_values_of_the_instance_in_the_first_question(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (f"**{data.sr_srgb_r3} à {data.sr_srgb_r3 + 7999}**", f"`sr_r4` **{data.sr_index4}**",
                      f"**{data.bfd_interval} ms**", f"multiplicateur **{data.bfd_multiplier}**",
                      str(data.nets6.mt_l23), f"`{data.ips6.mt_h4.ip}`", f"`{data.ips.bfd_h4.ip}`", '**`CORE`**'):
            assert value in first, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['nlpid', 'mt_id', 'tlv_st', 'tlv_mt', 'single', 'nexthop', 'push4', 'label_l23', 'label_l34',
                         'push3', 'capability', 'subtlv', 'no_php', 'port', 'detection', 'hold', 'outage', 'fast_hold',
                         'interface', 'path']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 8 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'isis_mt_sr_bfd_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('isis_mt_sr_bfd_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|zone|voisin|bouclage|chemin|niveau|aire|'
                            r'secours|depannage|coupure)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets)) + list(vars(data.ips6)) + list(vars(data.nets6))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [field['name'] for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        names += [c for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []
                  for c in field.get('choices', [])]
        assert 'initial' in names and 'final' in names and 'solve_bfd' in names and 'bfd_sw' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
