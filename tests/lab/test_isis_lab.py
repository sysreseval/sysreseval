"""Offline tests of the IS-IS lab (lab/sre/_DRAFT_misc/isis.py).

No Docker, no FRR: a model of the six sites (``World``) holds what has been done, as a set of
features (``bas_r3``, ``lvl_circuits``, ``fix_mtu``...), and renders the outputs the grader reads in
the shapes captured live on Debian 13 (FRR 10.3: the ``isis_*`` / ``config_isis_*`` fixtures of
``tests/mock_data/frr``).  The behaviours follow what was seen live: an MTU mismatch shows the
adjacency Up on the side with the large MTU only, a router without hello password shows a signed
neighbour Up, a router with a domain password rejects unsigned LSPs, the overload bit stops the
transit only.  Covers the data, the topology, the state ops, the two-pass grading contract (nothing
done: 0; everything: 100 + 6 bonus points; **each part alone gives exactly its points and everything
but one part the rest**) and the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv4Network
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from frr import parse_frr_config, parse_isis_net  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'isis.py'

# what each part configures (the features of the model) and its points
PARTS = {
    'basics': {'bas_r3', 'bas_r4'},
    'levels': {'lvl_r1', 'lvl_r2', 'lvl_circuits', 'lvl_summary'},
    'lan': {'lan_dis', 'lan_metric', 'lan_overload'},
    'auth': {'auth_hello', 'auth_domain'},
    'fix': {'fix_area', 'fix_network', 'fix_mtu', 'fix_overload'},
    'external': {'ext_static', 'ext_default'},
}
POINTS = {'basics': 22, 'levels': 24, 'lan': 20, 'auth': 12, 'fix': 22, 'external': 6}
SOLVE_STATE = {'basics': 'solve_basics', 'levels': 'solve_levels', 'lan': 'solve_lan', 'auth': 'solve_auth',
               'fix': 'solve_fix', 'external': 'solve_external'}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {
    'bas_q_sysid': 'basics', 'bas_q_afi': 'basics', 'bas_q_hold': 'basics', 'bas_q_metric': 'basics',
    'bas_q_transport': 'basics', 'bas_q_mac': 'basics',
    'lvl_q_databases': 'levels', 'lvl_q_l2_lsps': 'levels', 'lvl_q_default_metric': 'levels', 'lvl_q_bit': 'levels',
    'lvl_q_l1_areas': 'levels',
    'lan_q_csnp': 'lan', 'lan_q_pseudonode': 'lan', 'lan_q_metric': 'lan', 'lan_q_narrow': 'lan',
    'lan_q_preemptive': 'lan',
    'auth_q_tlv': 'auth', 'auth_q_domain': 'auth',
    'fix_q_12': 'fix', 'fix_q_23': 'fix', 'fix_q_34': 'fix', 'fix_q_transit': 'fix',
}
FORM_POINTS = {'basics': 6, 'levels': 5, 'lan': 5, 'auth': 2, 'fix': 4}
CHOICE_ELEMENTS = {'bas_q_transport', 'bas_q_mac', 'lvl_q_bit', 'lvl_q_l1_areas', 'lan_q_preemptive', 'auth_q_domain',
                   'fix_q_12', 'fix_q_23', 'fix_q_34', 'fix_q_transit'}
BONUS_ELEMENTS = ['ext_static', 'ext_default', 'ext_ping']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('isis_lab_under_test', _LAB_PATH)
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


def _neighbor_block(name, ifname, level, area, address, circuit_type=None, lan=None, state='Up'):
    """One adjacency of ``show isis neighbor detail`` (shape of isis_neighbor_detail_*.txt)."""
    ct = circuit_type or {1: 'L1', 2: 'L2', 3: 'L1L2'}[level]
    lines = [f" {name:<20}", f"    Interface: {ifname}, Level: {level}, State: {state}, Expires in 28s",
             "    Adjacency flaps: 1, Last: 1m0s ago", f"    Circuit type: {ct}, Speaks: IPv4"]
    if lan:
        snpa, lan_id, prio, dis = lan
        lines += [f"    SNPA: {snpa}, LAN id: {lan_id}",
                  f"    LAN Priority: {prio}, {'is DIS' if dis else 'is not DIS'}, DIS flaps: 1, Last: 1m ago"]
    else:
        lines.append("    SNPA: 2020.2020.2020")
    lines += ["    Area Address(es):", f"      {area}", "    IPv4 Address(es):", f"      {address}", ""]
    return "\n".join(lines)


def _circuit(name, ctype, levels, passive=False):
    """One circuit of ``show isis interface detail json`` (shape of isis_interface_detail_*.json)."""
    return {'circuit': 0, 'interface': {
        'name': name, 'state': 'Up', 'is-passive': 'passive' if passive else 'active', 'circuit-id': '0x0',
        'type': ctype, 'level': 'L2', 'levels': levels}}


def _level(metric=10, lan=None):
    entry = {'level': 'L2', 'metric': metric, 'active-neighbors': 1, 'hello-interval': 3,
             'holddown': {'count': 10, 'pad': 'yes'}, 'cnsp-interval': 10, 'psnp-interval': 2}
    if lan:
        entry['lan'] = {'priority': lan[0], 'is-dis': 'yes' if lan[1] else 'no'}
    return entry


def _lsp(lsp_id, ol=False):
    return {'lsp': {'id': lsp_id, 'own': ' '}, 'pduLen': 100, 'seqNumber': '0x00000004', 'chksum': '0x1234',
            'holdtime': 1100, 'attPOl': f"0/0/{int(ol)}", 'areaAddr': '49.0001', 'hostname': lsp_id.split('.')[0]}


def _route(prefix, gateways, dev='eth0', protocol='isis'):
    """One entry of ``ip -j route`` (ECMP: several gateways)."""
    dst = str(prefix)
    dst = dst[:-3] if dst.endswith('/32') else dst
    if dst == '0.0.0.0/0':
        dst = 'default'
    if len(gateways) > 1:
        return {'dst': dst, 'protocol': protocol, 'metric': 20, 'flags': [],
                'nexthops': [{'gateway': str(g), 'dev': dev, 'weight': 1, 'flags': []} for g in gateways]}
    return {'dst': dst, 'gateway': str(gateways[0]), 'dev': dev, 'protocol': protocol, 'metric': 20, 'flags': []}


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    # -- adjacencies ------------------------------------------------------------------

    def adjacencies(self, r):
        """[(neighbour, link, level)] that *r* sees (Up, except the one-sided ones of ONE_SIDED)."""
        f = self.f
        both = {'bas_r3', 'bas_r4'} <= f
        table = {
            'bas_r3': [('bas_r2', 'bas_l23', 2)] * ('bas_r3' in f) + [('bas_r4', 'bas_l34', 2)] * both,
            'bas_r4': [('bas_r3', 'bas_l34', 2)] * both + [('bas_r1', 'bas_l14', 2)] * ('bas_r4' in f),
            'lvl_r1': [('lvl_r2', 'lvl_l12', 1)] * ({'lvl_r1', 'lvl_r2'} <= f),
            'lvl_r2': ([('lvl_r1', 'lvl_l12', 1)] * ({'lvl_r1', 'lvl_r2'} <= f)
                       + [('lvl_r3', 'lvl_l23', 2)] * ('lvl_r2' in f)),
            'lvl_r3': [('lvl_r2', 'lvl_l23', 2)] * ('lvl_r2' in f) + [('lvl_r4', 'lvl_l34', 2)],
            'auth_r2': [('auth_r1', 'auth_l12', 2)] * ('auth_hello' in f),
            'fix_r1': [('fix_r2', 'fix_l12', 1)] * ('fix_area' in f),
            'fix_r2': [('fix_r1', 'fix_l12', 1)] * ('fix_area' in f) + [('fix_r3', 'fix_l23', 2)] * ('fix_network' in f),
            # the MTU fault: fix_r3 (MTU 1500) sees fix_r4 Initializing, fix_r4 (MTU 1400) sees nothing
            'fix_r3': [('fix_r2', 'fix_l23', 2)] * ('fix_network' in f) + [('fix_r4', 'fix_l34', 2)],
            'fix_r4': [('fix_r3', 'fix_l34', 2)] * ('fix_mtu' in f),
        }
        return table[r]

    def neighbors(self, r):
        ns = self.ns
        blocks = ["Area CORE:"]
        for peer, link, level in self.adjacencies(r):
            # hostnames for most, the system-id for one router (a neighbour without dynamic hostname)
            name = ns.sysid(peer) if peer == 'lvl_r3' else peer
            state = 'Initializing' if (r, peer) == ('fix_r3', 'fix_r4') and 'fix_mtu' not in self.f else 'Up'
            blocks.append(_neighbor_block(name, self.lab.iface(r, link), level, ns.area_of(peer), ns.addr(peer, link),
                                          state=state))
        return "\n".join(blocks) + "\n"

    # -- interfaces, database -------------------------------------------------------------

    def interfaces(self, r):
        f, d, lab = self.f, self.d, self.lab
        if r in ('bas_r3', 'bas_r4'):
            if r not in f:
                return ''
            circuits = []
            for i, n in enumerate(lab.ROUTER_IFACES[r]):
                if n in lab.LINKS:
                    circuits.append(_circuit(f"eth{i}", 'p2p', [_level()]))
                else:
                    circuits.append(_circuit(f"eth{i}", 'lan', [_level()], passive=True))
            circuits.append(_circuit('lo', 'loopback', [{'level': 'L2', 'metric': 10}], passive=True))
        elif r == 'lan_r3':
            dis = 'lan_dis' in f
            prio = d.lan_priority if dis else 64
            circuits = [_circuit('eth0', 'lan', [_level(lan=(prio, dis))]), _circuit('eth1', 'p2p', [_level()]),
                        _circuit('lo', 'loopback', [{'level': 'L2', 'metric': 10}], passive=True)]
        elif r in ('lan_r1', 'lan_r4'):
            metric = d.lan_metric if 'lan_metric' in f else 10
            l14 = lab.iface(r, 'lan_l14')
            circuits = [_circuit(f"eth{i}", 'p2p' if n in lab.LINKS else 'lan',
                                 [_level(metric if f"eth{i}" == l14 else 10,
                                         lan=(lab.LAN_R1_PRIORITY, 'lan_dis' not in f) if n == 'lan_seg' else None)])
                        for i, n in enumerate(lab.ROUTER_IFACES[r])]
        else:
            raise AssertionError(r)
        return json.dumps({'areas': [{'area': 'CORE', 'circuits': circuits}]}, indent=2) + "\n"

    def database(self, r):
        f = self.f
        if r == 'lan_r2':
            lsps = [_lsp('lan_r1.00-00', ol='lan_overload' in f), _lsp('lan_r2.00-00'), _lsp('lan_r3.00-00'),
                    _lsp('lan_r4.00-00'), _lsp('lan_r3.4d-00' if 'lan_dis' in f else 'lan_r1.4d-00')]
        elif r == 'fix_r3':
            lsps = [_lsp('fix_r3.00-00', ol='fix_overload' not in f)]
            if 'fix_network' in f:
                lsps.append(_lsp('fix_r2.00-00'))
        else:
            raise AssertionError(r)
        return json.dumps({'areas': [{'area': {'name': 'CORE'}, 'levels': [{'id': 2, 'lsps': lsps, 'count': len(lsps)}]}]},
                          indent=2) + "\n"

    # -- configurations -------------------------------------------------------------------

    def running_config(self, r):
        f, ns = self.f, self.ns
        text = "Building configuration...\n\nCurrent configuration:\n!\nfrr version 10.3\nfrr defaults traditional\n!\n"
        lines = []
        if r in ('bas_r3', 'bas_r4') and r in f:
            lines = ns.solution_basics()[r]
        elif r == 'lvl_r1' and 'lvl_r1' in f:
            lines = ns.solution_levels()['lvl_r1']
        elif r == 'lvl_r2' and 'lvl_r2' in f:
            lines = ns.solution_levels()['lvl_r2']
            if 'lvl_circuits' not in f:
                lines = [x for x in lines if not x.startswith('isis circuit-type')]
            if 'lvl_summary' not in f:
                lines = [x for x in lines if not x.startswith(('ip route', 'redistribute'))]
        elif r == 'auth_r1':
            lines = ns._given_lines('auth_r1')
            solution = ns.solution_auth()['auth_r1']
            if 'auth_hello' in f:
                lines = lines + solution[:3]
            if 'auth_domain' in f:
                lines = lines + solution[3:]
        return text + _as_frr_config(lines) + "end\n"

    # -- routes and pings ---------------------------------------------------------------------

    def kernel(self, r):
        f, ns, d = self.f, self.ns, self.d
        addr, net, lo = ns.addr, ns.net, ns.lo
        routes = [{'dst': str(net(n)), 'dev': f"eth{i}", 'protocol': 'kernel', 'scope': 'link', 'flags': []}
                  for i, n in enumerate(self.lab.ROUTER_IFACES[r])]
        if r == 'bas_r1':
            if 'bas_r3' in f:
                routes.append(_route(f"{lo('bas_r3')}/32", [addr('bas_r2', 'bas_l12')]))
            if 'bas_r4' in f:
                routes.append(_route(f"{lo('bas_r4')}/32", [addr('bas_r4', 'bas_l14')], 'eth2'))
        elif r == 'bas_r2':
            gws = ([addr('bas_r1', 'bas_l12')] * ('bas_r4' in f)
                   + [addr('bas_r3', 'bas_l23')] * ({'bas_r3', 'bas_r4'} <= f))
            if gws:
                routes.append(_route(net('bas_lan4'), gws))
        elif r == 'lvl_r1' and {'lvl_r1', 'lvl_r2'} <= f:
            routes.append(_route('0.0.0.0/0', [addr('lvl_r2', 'lvl_l12')], 'eth1'))
        elif r == 'lvl_r3':
            routes.append(_route(net('lvl_area_c_block'), [addr('lvl_r4', 'lvl_l34')], 'eth1'))
            if {'lvl_r2', 'lvl_summary'} <= f:
                routes.append(_route(net('lvl_area_a_block'), [addr('lvl_r2', 'lvl_l23')]))
        elif r == 'lan_r1':
            via = [addr('lan_r3', 'lan_seg')] if 'lan_metric' in f else [addr('lan_r4', 'lan_l14')]
            routes.append(_route(net('lan_lan4'), via))
        elif r == 'lan_r2':
            transit_r1 = not ({'lan_metric', 'lan_overload'} & f)
            gws = [addr('lan_r1', 'lan_seg')] * transit_r1 + [addr('lan_r3', 'lan_seg')]
            routes.append(_route(net('lan_lan4'), gws, 'eth1'))
        elif r == 'auth_r2' and {'auth_hello', 'auth_domain'} <= f:
            routes.append(_route(net('auth_lan1'), [addr('auth_r1', 'auth_l12')], 'eth1'))
        elif r == 'ext_r2':
            if 'ext_static' in f:
                routes.append(_route(self.lab.EXT_PUBLIC, [addr('ext_r1', 'ext_l12')], 'eth1'))
            if 'ext_default' in f:
                routes.append(_route('0.0.0.0/0', [addr('ext_r1', 'ext_l12')], 'eth1'))
        return routes

    def ping_ok(self, src, dest):
        f = self.f
        if src in ('bas_h1', 'bas_h4'):
            return 'bas_r4' in f
        if src in ('lvl_h1', 'lvl_h5'):
            return {'lvl_r1', 'lvl_r2', 'lvl_summary'} <= f
        if src == 'lan_h4':
            return True
        if src in ('auth_h1', 'auth_h2'):
            return {'auth_hello', 'auth_domain'} <= f
        if src in ('fix_h1', 'fix_h4'):
            return PARTS['fix'] <= f
        if src == 'ext_h2':
            return bool({'ext_static', 'ext_default'} & f)
        raise AssertionError((src, dest))

    # -- every command ------------------------------------------------------------------

    def output(self, machine, command, step):
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'vtysh -c "show isis neighbor detail"':
            return self.neighbors(machine), 0
        if command == 'vtysh -c "show isis interface detail json"':
            return self.interfaces(machine), 0
        if command == 'vtysh -c "show isis database detail json"':
            return self.database(machine), 0
        if command == 'ip -j route':
            return json.dumps(self.kernel(machine)), 0
        m = re.fullmatch(r'ping -c 3 -w 5 (\S+)', command)
        if m:
            if self.ping_ok(machine, m.group(1)):
                return f"64 bytes from {m.group(1)}: icmp_seq=1 ttl=62 time=1 ms\n", 0
            return "3 packets transmitted, 0 received\n", 1
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
    """(regular points, bonus points)."""
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus))


def _lost(grade):
    return {title for title, (got, best) in _grades(grade).items() if got != best}


def _parts(grade):
    """{part key: points earned}."""
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
        assert all(getattr(data.nets, n).prefixlen == 30 for n in lab.LINKS)
        for r in lab.ROUTER_IFACES:
            assert getattr(data.ips, f"{r}_lo").network.prefixlen == 32
        assert [str(data.ips.lan_r1_lan_seg.ip)[-2:], str(data.ips.lan_r3_lan_seg.ip)[-2:]] == ['.1', '.3']
        # each level 1 area of the lvl site in its own /22, which contains nothing else
        for area, (link, lan, routers) in lab.LVL_AREA_MEMBERS.items():
            block = getattr(data.nets, f"lvl_area_{area}_block")
            assert block.prefixlen == 22
            members = [getattr(data.nets, link), getattr(data.nets, lan)]
            members += [getattr(data.ips, f"{r}_lo").network for r in routers]
            assert all(m.subnet_of(block) for m in members)
            others = [getattr(data.nets, n) for n in list(lab.LINKS) + lab.LANS if n not in (link, lan)]
            others += [getattr(data.ips, f"{r}_lo").network for r in lab.ROUTER_IFACES if r not in routers]
            assert not any(o.overlaps(block) for o in others)

    def test_values(self, lab, data):
        areas = [data.bas_area, data.lvl_area_a, data.lvl_area_b, data.lvl_area_c, data.lan_area, data.auth_area,
                 data.fix_area, data.fix_wrong_area, data.ext_area]
        assert len(set(areas)) == 9 and all(re.fullmatch(r'49\.\d{4}', a) for a in areas)
        assert 90 <= data.lan_priority <= 126 and data.lan_priority > lab.LAN_R1_PRIORITY
        assert 63 < data.lan_metric <= 900
        assert re.fullmatch(r'[A-Za-z0-9]{10}', data.auth_hello_key) and data.auth_hello_key != data.auth_domain_key

    def test_system_ids(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        sysids = [ns.sysid(r) for r in lab.ROUTER_IFACES]
        assert len(set(sysids)) == len(sysids)
        octets = str(ns.lo('bas_r3')).split('.')
        assert ns.sysid('bas_r3').replace('.', '') == "".join(f"{int(o):03d}" for o in octets)
        assert parse_isis_net(ns.net_title('bas_r3', data.bas_area)) == {
            'area': data.bas_area, 'system_id': ns.sysid('bas_r3'), 'nsel': '00'}


class TestTopology:
    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert len(specs) == 33
        assert all(specs[r]['image'].endswith(':' + params.default_docker_image_version) or 'netdev13' in specs[r]['image']
                   for r in lab.ROUTER_IFACES)
        assert all('netdev13' in specs[r]['image'] for r in lab.ROUTER_IFACES)
        assert {m for m, s in specs.items() if s.get('allow_connection') is False} == {'auth_r2', 'ext_isp'}
        assert all('image' not in specs[h] for h in lab.HOSTS) and 'image' not in specs['ext_isp']

    def test_sites_are_islands(self, lab):
        for net, members in lab._TOPOLOGY.items():
            assert {lab.site_of(m) for m in members} == {lab.site_of(net)}, net
        assert len(lab._TOPOLOGY['lan_seg']) == 3

    def test_interfaces_follow_the_lists(self, lab):
        for r, nets in lab.ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                assert lab._TOPOLOGY[n][r] == i

    def test_net_config_and_hosts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.net_config['bas_h1'][0][1] == [(IPv4Network('0.0.0.0/0'), ns.addr('bas_r1', 'bas_lan1'))]
        assert ns.net_config['ext_isp'][0][1] == [(data.nets.instance, ns.addr('ext_r1', 'ext_wan'))]
        assert all(routes == [] for r in lab.ROUTER_IFACES for _addrs, routes in ns.net_config[r])
        assert f"{ns.lo('fix_r3')}\tfix_r3-lo" in ns.hosts_content and "203.0.113.1\tinternet" in ns.hosts_content


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.ROUTER_IFACES:
            files = _files(ops, 2, r)
            assert set(files) == {'/etc/frr/daemons', '/etc/frr/vtysh.conf', '/etc/frr/frr.conf'}
            assert 'isisd=yes' in files['/etc/frr/daemons'] and 'bfdd=no' in files['/etc/frr/daemons']
            assert 'systemctl start frr' in _cmds(ops, 2, r)
            assert f"ip addr add {getattr(data.ips, f'{r}_lo')} dev lo" in _cmds(ops, 1, r)
        assert "ip link set eth1 mtu 1400" in _cmds(ops, 1, 'fix_r4')
        assert "ip addr add 203.0.113.1/32 dev lo" in _cmds(ops, 1, 'ext_isp')
        assert any('ip_forward=0' in c for c in _cmds(ops, 1, 'bas_h1'))
        assert any('ip_forward=1' in c for c in _cmds(ops, 1, 'bas_r1'))

    def _config(self, lab, ns, ops, r):
        return parse_frr_config(_files(ops, 2, r)['/etc/frr/frr.conf'])

    def test_given_configurations_and_faults(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        conf = {r: self._config(lab, ns, ops, r) for r in lab.ROUTER_IFACES}
        # the routers the students configure have no IS-IS
        for r in ('bas_r3', 'bas_r4', 'lvl_r1', 'lvl_r2'):
            assert not conf[r]['router_isis']['present'], r
        assert conf['bas_r1']['router_isis']['nets'] == [ns.net_title('bas_r1', data.bas_area)]
        assert conf['lvl_r3']['router_isis']['is_type'] == 'level-2-only'
        assert conf['lvl_r4']['interfaces']['eth0']['isis']['circuit_type'] == 'level-2-only'
        assert conf['lvl_r5']['router_isis']['is_type'] == 'level-1'
        # FRR announces in level 2 only the own networks of a level 1-2 router: the given ones
        # announce their level 1 part with a redistributed static route
        assert conf['lvl_r4']['static_routes'] == [(str(data.nets.lvl_area_c_block), 'blackhole')]
        assert conf['lvl_r4']['router_isis']['redistribute'] == [('ipv4', 'static', 'level-2')]
        assert conf['fix_r2']['static_routes'] == [(str(data.nets.fix_lan1), str(ns.addr('fix_r1', 'fix_l12')))]
        assert conf['fix_r2']['router_isis']['redistribute'] == [('ipv4', 'static', 'level-2')]
        assert conf['lan_r1']['interfaces']['eth0']['isis']['priority'] == {'all': lab.LAN_R1_PRIORITY}
        assert conf['lan_r2']['interfaces']['eth1']['isis']['network_type'] is None     # lan_seg: broadcast
        assert conf['lan_r4']['interfaces']['eth1']['isis']['network_type'] == 'point-to-point'
        assert conf['auth_r2']['router_isis']['domain_password'] == {'type': 'md5', 'key': data.auth_domain_key}
        assert conf['auth_r2']['interfaces']['eth1']['isis']['password'] == {'type': 'md5', 'key': data.auth_hello_key}
        assert conf['auth_r1']['router_isis']['domain_password'] is None
        # the faults of the fix site
        assert conf['fix_r1']['router_isis']['nets'] == [ns.net_title('fix_r1', data.fix_wrong_area)]
        assert conf['fix_r3']['interfaces']['eth0']['isis']['network_type'] is None
        assert conf['fix_r2']['interfaces']['eth1']['isis']['network_type'] == 'point-to-point'
        assert conf['fix_r3']['router_isis']['overload']
        # the external routes of ext_r1, outside IS-IS on ext_wan
        assert conf['ext_r1']['static_routes'] == [('203.0.113.0/24', str(ns.addr('ext_isp', 'ext_wan'))),
                                                   ('0.0.0.0/0', str(ns.addr('ext_isp', 'ext_wan')))]
        assert conf['ext_r1']['interfaces']['eth1']['isis']['ipv4'] == 'CORE'
        assert 'eth0' not in conf['ext_r1']['interfaces']
        for r in lab.ROUTER_IFACES:
            if conf[r]['router_isis']['present']:
                assert conf[r]['interfaces']['lo']['isis']['passive'], r
                assert conf[r]['router_isis']['name'] == 'CORE'

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        expected = {
            'solve_basics': {'bas_r3', 'bas_r4'}, 'solve_levels': {'lvl_r1', 'lvl_r2'},
            'solve_lan': {'lan_r1', 'lan_r3', 'lan_r4'}, 'solve_auth': {'auth_r1'},
            'solve_fix': {'fix_r1', 'fix_r3', 'fix_r4'}, 'solve_external': {'ext_r1'},
        }
        for state, routers in expected.items():
            ops = _state_ops(ns, state)
            assert {m for (step, m) in ops if step == 1} == routers, state
            assert any(c.startswith('sleep ') for (step, m) in ops if step == 2 for c in _cmds(ops, 2, m)), state
        ops = _state_ops(ns, 'solve_lan')
        r1 = _vtysh_commands(_cmds(ops, 1, 'lan_r1')[0])
        assert f"isis metric {data.lan_metric}" in r1 and 'set-overload-bit' in r1
        assert f"isis priority {data.lan_priority}" in _vtysh_commands(_cmds(ops, 1, 'lan_r3')[0])
        ops = _state_ops(ns, 'solve_fix')
        assert _cmds(ops, 1, 'fix_r4') == ["ip link set eth1 mtu 1500"]
        r1 = _vtysh_commands(_cmds(ops, 1, 'fix_r1')[0])
        assert f"net {ns.net_title('fix_r1', data.fix_area)}" in r1
        assert f"no net {ns.net_title('fix_r1', data.fix_wrong_area)}" in r1
        ops = _state_ops(ns, 'solve_basics')
        r3 = parse_frr_config(_as_frr_config(_vtysh_commands(_cmds(ops, 1, 'bas_r3')[0])))
        assert r3['router_isis']['nets'] == [ns.net_title('bas_r3', data.bas_area)]
        assert r3['interfaces']['eth0']['isis']['network_type'] == 'point-to-point' and r3['interfaces']['lo']['isis']['passive']
        ops = _state_ops(ns, 'solve_levels')
        r2 = parse_frr_config(_as_frr_config(_vtysh_commands(_cmds(ops, 1, 'lvl_r2')[0])))
        assert r2['router_isis']['is_type'] is None
        assert r2['static_routes'] == [(str(data.nets.lvl_area_a_block), 'blackhole')]
        assert r2['router_isis']['redistribute'] == [('ipv4', 'static', 'level-2')]
        assert r2['interfaces']['eth0']['isis']['circuit_type'] == 'level-1'
        assert r2['interfaces']['eth1']['isis']['circuit_type'] == 'level-2-only'

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        union = {}
        for state in SOLVE_STATE.values():
            for (step, m), op_list in _state_ops(ns, state).items():
                if step == 1:
                    union.setdefault(m, []).extend(str(o) for o in op_list)
        final = {m: [str(o) for o in op_list] for (step, m), op_list in _state_ops(ns, 'final').items() if step == 1}
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
        assert len(elements) == 59 and len({str(e.title) for e in elements}) == 59

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
        # the answers of the forms stay: the part keeps the points of its forms
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
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0) == (22, 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (78, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('bas_r3', {'bas_adj_r3', 'bas_adj_r4', 'bas_net', 'bas_level2', 'bas_p2p', 'bas_passive', 'bas_loopbacks',
                    'bas_ecmp'}),
        ('lvl_circuits', {'lvl_circuit_type'}),
        ('lvl_summary', {'lvl_summary', 'lvl_ping'}),
        ('lvl_r1', {'lvl_r1_config', 'lvl_adj_l1', 'lvl_default', 'lvl_l1_only', 'lvl_ping'}),
        ('lan_dis', {'lan_dis', 'lan_priority'}),
        ('lan_metric', {'lan_metric', 'lan_r1_path'}),
        ('lan_overload', {'lan_overload', 'lan_overload_own'}),
        ('auth_domain', {'auth_lsdb', 'auth_md5', 'auth_ping'}),
        ('auth_hello', {'auth_adj', 'auth_lsdb', 'auth_md5', 'auth_ping'}),
        ('fix_area', {'fix_adj_12', 'fix_ping'}),
        ('fix_network', {'fix_adj_23', 'fix_ping'}),
        ('fix_mtu', {'fix_adj_34', 'fix_ping'}),
        ('fix_overload', {'fix_overload', 'fix_ping'}),
        ('ext_default', {'ext_default'}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

    def test_partial_grades(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'bas_r3'})
        g = _grades(grade)
        assert g['bas_adj_r4'] == (1, 2) and g['bas_net'] == (1, 2) and g['bas_p2p'] == (1, 2) and g['bas_ping'] == (3, 3)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'auth_domain'})
        assert _grades(grade)['auth_md5'] == (1, 2)
        # the overload alone already leaves lan_r2 a single path (through lan_r3)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features={'lan_overload'}, answers=None)
        assert _parts(grade)['lan'] == 2 + 3 + 1

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

        sysid = ns.sysid('bas_r3')
        for spelling, points in ((sysid, 1), (sysid.replace('.', ''), 1), (sysid.upper(), 1), (f" {sysid} ", 1),
                                 (ns.sysid('bas_r4'), 0), ('', 0)):
            assert regrade("Observations sur le site bas", sysid=spelling)['bas_q_sysid'][0] == points, spelling
        assert regrade("Observations sur le site bas", hold='10')['bas_q_hold'][0] == 0
        assert regrade("Observations sur le site lvl", l2_lsps='5')['lvl_q_l2_lsps'][0] == 0
        assert regrade("Observations sur le site lan", metric=str(data.lan_metric + 10))['lan_q_metric'][0] == 0

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 5
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
        assert len(grade.get_cheat_answers('final')) == 5
        assert grade.get_cheat_answers('solve_external') is None


def _simulate_with_answers(lab, data, tmp_pub_dir, cheat):
    """_simulate() with the answers *cheat* (``{question hash: answers}``)."""
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
        assert len(g1.get_questions_ordered()) == 12
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 12 and 'informations' not in with_fragment

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
            'principle', 'net', 'pdus', 'adjacency', 'levels', 'dis', 'metrics', 'overload', 'auth', 'external', 'frr',
            'diagnostic']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (str(data.nets.instance.network_address), data.bas_area, str(data.lan_metric), data.auth_hello_key,
                      'Partie 1', 'bas_r1', 'fix_r3'):
            assert not _mentions(informations, value), value

    def test_values_of_the_instance_in_the_questions(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        questions = [_text(q.description) for q in g0.get_questions_ordered()]
        first = questions[0]
        for value in (str(data.nets.bas_l23), f"`{data.ips.fix_h4.ip}`", f"`bas_r3` `{data.ips.bas_r3_lo.ip}`",
                      '**`CORE`**'):
            assert value in first, value
        everything = "\n".join(questions)
        for value in (f"**`{data.bas_area}`**", f"**{data.lan_priority}**", f"**{data.lan_metric}**",
                      f"**`{data.auth_hello_key}`**", f"**`{data.auth_domain_key}`**", f"**`{data.fix_area}`**"):
            assert value in everything, value
        # the faults are for the instructor only; the system-ids are for the students to compute
        for value in (data.fix_wrong_area, 'set-overload-bit', ns.sysid('bas_r3'), 'mtu 1400'):
            assert not _mentions(everything, value), value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['sysid', 'afi', 'hold', 'metric', 'transport', 'mac', 'bit', 'databases', 'l2_lsps',
                         'default_metric', 'l1_areas', 'csnp', 'preemptive', 'pseudonode', 'metric', 'narrow', 'tlv',
                         'domain', 'f12', 'f23', 'f34', 'transit']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 12 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'isis_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('isis_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|zone|voisin|bouclage|chemin|niveau|aire|'
                            r'surcharge|depannage|mot_de_passe)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [field['name'] for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        names += [c for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []
                  for c in field.get('choices', [])]
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'fix_r3' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
