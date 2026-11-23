"""Offline tests of the MPLS lab (lab/sre/_DRAFT_misc/mpls.py).

No Docker, no FRR, no MPLS kernel: a model of the five sites (``World``) holds what has been done,
as a set of features (``st_push``, ``ldp_filter``, ``fix_labels``...), and renders the outputs the
grader reads in the shapes captured live on Debian 13 (FRR 10.3, iproute2 7.3.0: the fixtures of
``tests/mock_data/mpls`` and the ``ldp_*`` / ``mpls_table_*`` / ``ospf_sr_*`` / ``route_*`` ones of
``tests/mock_data/frr``).  The behaviours follow what was seen live: Linux drops an MPLS packet whose
TTL expires (stars in traceroute), a counter of MPLS packets grows even on an interface whose input
is off (the ping gates it), the label of a segment routing hop is the SRGB of the next hop plus the
index.  Covers the data, the topology, the state ops, the two-pass grading contract (nothing done:
0; everything: 100 + 6 bonus points; **each part alone gives exactly its points and everything but
one part the rest**) and the texts.
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

from mpls import MPLS_COUNTERS_CMD  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'mpls.py'

# what each part configures (the features of the model) and its points
PARTS = {
    'static': {'st_sysctl', 'st_push', 'st_swap', 'st_pop', 'st_back'},
    'ldp': {'ldp_ldp', 'ldp_filter', 'ldp_ttl'},
    'sr': {'sr_sr', 'sr_no_php'},
    'fix': {'fix_input', 'fix_labels', 'fix_interface', 'fix_transport'},
    'tilfa': {'tl_tilfa'},
}
POINTS = {'static': 22, 'ldp': 28, 'sr': 28, 'fix': 22, 'tilfa': 6}
SOLVE_STATE = {'static': 'solve_static', 'ldp': 'solve_ldp', 'sr': 'solve_sr', 'fix': 'solve_fix',
               'tilfa': 'solve_tilfa'}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {
    'st_q_ethertype': 'static', 'st_q_max_label': 'static', 'st_q_hops': 'static',
    'ldp_q_php_label': 'ldp', 'ldp_q_port': 'ldp', 'ldp_q_hops': 'ldp',
    'sr_q_push4': 'sr', 'sr_q_label_l2': 'sr', 'sr_q_label_l3': 'sr', 'sr_q_push3': 'sr',
    'fix_q_input': 'fix', 'fix_q_session': 'fix',
}
FORM_POINTS = {'static': 3, 'ldp': 3, 'sr': 6, 'fix': 2}
CHOICE_ELEMENTS = {'fix_q_input', 'fix_q_session'}
BONUS_ELEMENTS = ['tl_backup', 'tl_node', 'tl_repair']
# the LDP labels of the model: local labels of ldp_p1 / ldp_p2 for the loopback of ldp_pe2
L_P1, L_P2 = 20, 23


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('mpls_lab_under_test', _LAB_PATH)
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


def _other_instance(lab, data, values):
    """An instance whose *values(d)* all differ from those of *data*.  A course holding no value of
    the instance is the same text for both, whatever numbers it prints: searching it for a random
    label found the 100, 200 and 300 of its examples, the TTL 255 and the port 646."""
    while True:
        other = lab.Data.generate()
        other.compute_post_generate()
        if all(a != b for a, b in zip(values(other), values(data))):
            return other


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


# ---------------------------------------------------------------------------
# a model of the sites: features -> what the grader reads
# ---------------------------------------------------------------------------


def _ilm(label, out=None, via=None, dev=None, protocol=None):
    """One entry of ``ip -j -f mpls route`` (shape of ilm_*_final.json)."""
    entry = {'dst': str(label)}
    if out:
        entry['to'] = "/".join(str(x) for x in out)
    if via:
        entry['via'] = {'family': 'inet', 'host': str(via)}
    entry['dev'] = dev or 'eth0'
    if protocol:
        entry['protocol'] = protocol
    entry['flags'] = []
    return entry


def _route(prefix, gateway=None, dev='eth0', labels=None, protocol='ospf'):
    """One entry of ``ip -j route`` (shape of iproute_*_final.json)."""
    entry = {'dst': str(prefix).replace('/32', '') if str(prefix).endswith('/32') else str(prefix)}
    if labels:
        entry['encap'] = {'encap_type': 'mpls', 'dst': "/".join(str(x) for x in labels)}
    if gateway:
        entry['gateway'] = str(gateway)
    entry.update({'dev': dev, 'protocol': protocol, 'flags': []})
    return entry


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    # -- static (st) ------------------------------------------------------------

    def st_ok(self):
        return PARTS['static'] <= self.f

    # -- the kernel ----------------------------------------------------------------

    def sysctls(self, r):
        f = self.f
        values = {'platform_labels': self.lab.PLATFORM_LABELS, 'ip_ttl_propagate': 1, 'default_ttl': 255}
        inputs = {name: 1 for name in self.lab.core_ifaces(r)}
        inputs['lo'] = 0
        if r.startswith('st_'):
            values['platform_labels'] = 1000 if 'st_sysctl' in f else 0
            inputs = {f"eth{i}": int('st_sysctl' in f and (r, i) in (('st_p', 0), ('st_p', 1), ('st_pe2', 1)))
                      for i in range(len(self.lab.ROUTER_IFACES[r]))}
            inputs['lo'] = 0
        if r in ('ldp_pe1', 'ldp_pe2') and 'ldp_ttl' in f:
            values['ip_ttl_propagate'] = 0
        if r == 'fix_p1':
            inputs['eth0'] = int('fix_input' in f)
        if r == 'fix_p2' and 'fix_labels' not in f:
            values['platform_labels'] = 0
        lines = [f"/proc/sys/net/mpls/conf/{name}/input:{v}" for name, v in sorted(inputs.items())]
        lines += [f"/proc/sys/net/mpls/{k}:{v}" for k, v in sorted(values.items())]
        return "\n".join(lines) + "\n"

    def ilm(self, r):
        f, d, addr = self.f, self.d, self.ns.addr
        srgb, srgb3 = d.sr_srgb, d.sr_srgb_r3
        i4 = d.sr_index4
        e = []
        if r == 'st_p':
            if 'st_swap' in f:
                e.append(_ilm(d.st_push, [d.st_swap], addr('st_pe2', 'st_l2'), 'eth1'))
            if 'st_back' in f:
                e.append(_ilm(d.st_back, None, addr('st_pe1', 'st_l1'), 'eth0'))
        elif r == 'st_pe2' and 'st_pop' in f:
            e.append(_ilm(d.st_swap, dev='lo'))
        elif r == 'ldp_p1' and 'ldp_ldp' in f:
            e.append(_ilm(L_P1, [L_P2], addr('ldp_p2', 'ldp_l2'), 'eth1', 'ldp'))
        elif r == 'ldp_p2' and 'ldp_ldp' in f:
            e.append(_ilm(L_P2, None, addr('ldp_pe2', 'ldp_l3'), 'eth1', 'ldp'))
        elif r == 'sr_r2' and 'sr_sr' in f:
            e.append(_ilm(srgb + i4, [srgb3 + i4], addr('sr_r3', 'sr_l2'), 'eth1', 'ospf'))
        elif r == 'sr_r3' and 'sr_sr' in f:
            out = [srgb + i4] if 'sr_no_php' in f else None
            e.append(_ilm(srgb3 + i4, out, addr('sr_r4', 'sr_l3'), 'eth1', 'ospf'))
        elif r == 'sr_r4' and {'sr_sr', 'sr_no_php'} <= f:
            e.append(_ilm(srgb + i4, dev='lo', protocol='ospf'))
        elif r == 'fix_p2' and 'fix_labels' in f:
            e.append(_ilm(16, None, addr('fix_pe2', 'fix_l3'), 'eth1', 'ldp'))
        return e

    def kernel(self, r):
        f, d, ns = self.f, self.d, self.ns
        addr, net, lo = ns.addr, ns.net, ns.lo
        routes = [_route(net(n), dev=f"eth{i}", protocol='kernel') for i, n in enumerate(self.lab.ROUTER_IFACES[r])]
        if r == 'st_pe1' and 'st_push' in f:
            routes.append(_route(net('st_lan2'), addr('st_p', 'st_l1'), 'eth1', [d.st_push], protocol=None))
        elif r == 'st_pe2' and 'st_back' in f:
            routes.append(_route(net('st_lan1'), addr('st_p', 'st_l2'), 'eth1', [d.st_back], protocol=None))
        elif r == 'ldp_pe1':
            labelled = 'ldp_ldp' in f
            routes.append(_route(f"{lo('ldp_pe2')}/32", addr('ldp_p1', 'ldp_l1'), 'eth1', [L_P1] if labelled else None))
            routes.append(_route(net('ldp_lan2'), addr('ldp_p1', 'ldp_l1'), 'eth1', [L_P1 + 1] if labelled else None))
        elif r == 'sr_r1':
            labels = [d.sr_srgb + d.sr_index4] if 'sr_sr' in f else None
            routes.append(_route(f"{lo('sr_r4')}/32", addr('sr_r2', 'sr_l1'), 'eth0', labels))
        return [x for x in routes if x.get('protocol', 'x') is not None or x.pop('protocol', None) is None]

    def counters(self, r, step):
        f = self.f
        grew = {'ldp_p1': 'ldp_ldp' in f, 'ldp_p2': 'ldp_ldp' in f, 'sr_r2': 'sr_sr' in f, 'sr_r3': 'sr_sr' in f,
                'fix_p1': True, 'fix_p2': 'fix_interface' in f}.get(r, False)
        rx = 100 + (7 if grew and step == 3 else 0)
        return [{'ifindex': 2, 'ifname': 'eth0', 'group': 'afstats', 'subgroup': 'mpls',
                 'mpls_stats': {'rx': {'bytes': 84 * rx, 'packets': rx, 'errors': 0, 'dropped': 0, 'noroute': 0},
                                'tx': {'bytes': 0, 'packets': 0, 'errors': 0, 'dropped': 0}}}]

    # -- LDP ------------------------------------------------------------------------

    LINE = {'ldp_pe1': ['ldp_p1'], 'ldp_p1': ['ldp_pe1', 'ldp_p2'], 'ldp_p2': ['ldp_p1', 'ldp_pe2'],
            'ldp_pe2': ['ldp_p2']}

    def _neighbor(self, peer):
        lo = str(self.ns.lo(peer))
        return {'addressFamily': 'ipv4', 'neighborId': lo, 'state': 'OPERATIONAL', 'transportAddress': lo,
                'upTime': '00:01:00'}

    def ldp_neighbors(self, r):
        f = self.f
        if r in self.LINE:
            return {'neighbors': [self._neighbor(p) for p in self.LINE[r]]} if 'ldp_ldp' in f else {}
        if r == 'fix_p2':
            peers = (['fix_p1'] if 'fix_interface' in f else []) + (['fix_pe2'] if 'fix_transport' in f else [])
            return {'neighbors': [self._neighbor(p) for p in peers]} if peers else {}
        return {}

    def ldp_discovery(self, r):
        if r != 'fix_p2':
            return {}
        adj = [{'addressFamily': 'ipv4', 'neighborId': str(self.ns.lo('fix_pe2')), 'type': 'link',
                'interface': 'eth1', 'helloHoldtime': 15}]
        if 'fix_interface' in self.f:
            adj.insert(0, {'addressFamily': 'ipv4', 'neighborId': str(self.ns.lo('fix_p1')), 'type': 'link',
                           'interface': 'eth0', 'helloHoldtime': 15})
        return {'adjacencies': adj}

    def ldp_bindings(self, r):
        f, ns = self.f, self.ns
        if r not in self.LINE or 'ldp_ldp' not in f:
            return None
        prefixes = [f"{ns.lo(x)}/32" for x in self.LINE] + [str(ns.net('ldp_lan1')), str(ns.net('ldp_lan2'))]
        if 'ldp_filter' not in f:
            prefixes += [str(ns.net(n)) for n in self.lab.LINKS if n.startswith('ldp_')]
        bindings = []
        for k, prefix in enumerate(prefixes):
            local = str(30 + k)
            if prefix == f"{ns.lo('ldp_pe2')}/32":
                local = {'ldp_p1': str(L_P1), 'ldp_p2': str(L_P2)}.get(r, local)
            for peer in self.LINE[r]:
                bindings.append({'addressFamily': 'ipv4', 'prefix': prefix, 'neighborId': str(ns.lo(peer)),
                                 'localLabel': local, 'remoteLabel': '40', 'inUse': 1})
        return {'bindings': bindings}

    def running_config(self, r):
        f, lo = self.f, self.ns.lo
        text = "Building configuration...\n\nCurrent configuration:\n!\nfrr version 10.3\n!\n"
        if r in ('ldp_pe1', 'ldp_pe2') and 'ldp_ldp' in f:
            text += (f"mpls ldp\n router-id {lo(r)}\n !\n address-family ipv4\n  discovery transport-address {lo(r)}\n"
                     "  !\n  interface eth1\n  exit\n  !\n exit-address-family\n !\nexit\n!\n")
        if r == 'tl_r1':
            text += "router ospf\n ospf router-id {}\n".format(lo(r))
            if 'tl_tilfa' in f:
                text += " fast-reroute ti-lfa node-protection\n"
            text += " capability opaque\n segment-routing on\nexit\n!\n"
        return text + "end\n"

    def traceroute(self):
        ns, f = self.ns, self.f
        pe1, h2 = str(ns.addr('ldp_pe1', 'ldp_lan1')), str(self.d.ips.ldp_h2.ip)
        if 'ldp_ldp' not in f:
            hops = [pe1, str(ns.addr('ldp_p1', 'ldp_l1')), str(ns.addr('ldp_p2', 'ldp_l2')),
                    str(ns.addr('ldp_pe2', 'ldp_l3')), h2]
        elif 'ldp_ttl' in f:
            hops = [pe1, h2]
        else:
            hops = [pe1, '*', '*', str(ns.addr('ldp_pe2', 'ldp_l3')), h2]
        lines = [f"traceroute to {h2} ({h2}), 8 hops max, 60 byte packets"]
        lines += [f" {i}  {h}" + ('' if h == '*' else '  0.500 ms') for i, h in enumerate(hops, 1)]
        return "\n".join(lines) + "\n"

    # -- segment routing ----------------------------------------------------------------

    def sr_database(self, r):
        d, ns = self.d, self.ns
        if 'sr_sr' not in self.f:
            return None
        nodes = []
        for x in ('sr_r1', 'sr_r2', 'sr_r3', 'sr_r4'):
            nodes.append({'routerID': str(ns.lo(x)), 'srgbSize': self.lab.SRGB_SIZE, 'srgbLabel': d.sr_base(x),
                          'srlbSize': 1000, 'srlbLabel': 15000, 'algorithms': [{'0': 'SPF'}],
                          'extendedPrefix': [{'prefix': f"{ns.lo(x)}/32", 'sid': d.sr_index(x),
                                              'inputLabel': 0 if x == r else d.sr_base(r) + d.sr_index(x),
                                              'prefixRoute': []}]})
        return {'srdbID': str(ns.lo(r)), 'srNodes': nodes}

    def tl_routes(self):
        ns = self.ns
        r3 = f"{ns.lo('tl_r3')}/32"
        route = {'prefix': r3, 'protocol': 'ospf', 'selected': True, 'installed': True, 'metric': 20,
                 'nexthops': [{'ip': str(ns.addr('tl_r2', 'tl_l12')), 'interfaceName': 'eth0', 'active': True,
                               'fib': True, 'labels': [16003]}]}
        if 'tl_tilfa' in self.f:
            route['backupNexthops'] = [{'ip': str(ns.addr('tl_r4', 'tl_l14')), 'interfaceName': 'eth1',
                                        'active': True, 'labels': [15003, 16003]}]
        return {r3: [route]}

    # -- every command ------------------------------------------------------------------

    def output(self, machine, command, step):
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'grep -r . /proc/sys/net/mpls':
            return self.sysctls(machine), 0
        if command == 'ip -j -f mpls route':
            return json.dumps(self.ilm(machine)), 0
        if command == 'ip -j route':
            return json.dumps(self.kernel(machine)), 0
        if command == MPLS_COUNTERS_CMD:
            return json.dumps(self.counters(machine, step)), 0
        m = re.fullmatch(r'vtysh -c "(.*) json"', command)
        if m:
            show = m.group(1)
            producers = {'show mpls ldp neighbor': self.ldp_neighbors, 'show mpls ldp discovery': self.ldp_discovery,
                         'show mpls ldp binding': self.ldp_bindings,
                         'show ip ospf database segment-routing': self.sr_database}
            if show in producers:
                result = producers[show](machine)
                if result is None:
                    text = "Segment Routing is disabled on this router\n" if 'segment' in show else ''
                    return text, 0
                return json.dumps(result, indent=2) + "\n", 0
            if show == 'show ip route' and machine == 'tl_r1':
                return json.dumps(self.tl_routes()), 0
        if command.startswith('traceroute ') and machine == 'ldp_h1':
            return self.traceroute(), 0
        if command.startswith('ping -c 3 ') and machine == 'st_h1':
            return ('3 received\n', 0) if self.st_ok() else ('0 received\n', 1)
        if command.startswith('ping -c 5 '):
            ok = {'ldp_h1': True, 'sr_r1': True, 'fix_h1': {'fix_input', 'fix_labels'} <= self.f}[machine]
            return ('5 received\n', 0) if ok else ('0 received\n', 1)
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
        again = lab.Data.from_json(data.to_json())
        assert again.to_json() == data.to_json()

    def test_addressing(self, lab, data):
        instance = data.nets.instance
        assert instance.prefixlen == 16 and instance.subnet_of(IPv4Network('10.0.0.0/8'))
        links = [getattr(data.nets, n) for n in lab.LINKS]
        lans = [getattr(data.nets, n) for n in lab.LANS]
        loopbacks = [getattr(data.nets, f"{s}_lo") for s in lab.SITE_NUMBER]
        everything = links + lans + loopbacks
        assert all(n.prefixlen == 30 for n in links) and all(n.prefixlen == 24 for n in lans + loopbacks)
        assert all(n.subnet_of(instance) for n in everything)
        assert all(not a.overlaps(b) for i, a in enumerate(everything) for b in everything[i + 1:])
        for link, (first, second) in lab.LINKS.items():
            net = getattr(data.nets, link)
            assert getattr(data.ips, f"{first}_{link}").ip == net.network_address + 1
            assert getattr(data.ips, f"{second}_{link}").ip == net.network_address + 2
        for router in lab.LOOPBACKS:
            lo = getattr(data.ips, f"{router}_lo")
            assert lo.network.prefixlen == 32 and lo.ip in getattr(data.nets, f"{lab.site_of(router)}_lo")

    def test_values(self, lab, data):
        labels = (data.st_push, data.st_swap, data.st_back)
        assert len(set(labels)) == 3 and all(lab.LABEL_RANGE[0] <= x <= lab.LABEL_RANGE[1] for x in labels)
        assert data.sr_srgb in lab.SR_SRGB_BASES and data.sr_srgb_r3 in lab.SR_R3_SRGB_BASES
        indexes = [data.sr_index1, data.sr_index2, data.sr_index3, data.sr_index4]
        assert len(set(indexes)) == 4 and all(1 <= i < 100 for i in indexes)
        # the SRGBs never overlap and fit in the given label space
        assert max(lab.SR_SRGB_BASES) + lab.SRGB_SIZE <= min(lab.SR_R3_SRGB_BASES)
        assert max(lab.SR_R3_SRGB_BASES) + lab.SRGB_SIZE <= lab.PLATFORM_LABELS
        assert data.sr_base('sr_r3') == data.sr_srgb_r3 and data.sr_base('sr_r1') == data.sr_srgb
        assert data.sr_index('sr_r4') == data.sr_index4


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 25 == len(lab.NetScheme._machine_specs)
        for m, spec in lab.NetScheme._machine_specs.items():
            assert spec.get('allow_connection', True) == (m not in lab.OPERATORS), m
            assert (spec.get('shape') == 'box') == (m in lab.ROUTER_IFACES)
            if m in lab.ROUTER_IFACES:
                assert spec['image'].endswith(params.sre_docker_image('routing-frr').split('/')[-1])
            else:
                assert 'image' not in spec
        assert lab.OPERATORS == ('tl_r2', 'tl_r3', 'tl_r4')

    def test_sites_are_islands(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for net, members in ns._topology.items():
            assert len({lab.site_of(m) for m in members}) == 1, net
            assert len(members) == 2, net
        for router, nets in lab.ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                assert ns._topology[net][router] == i

    def test_net_config_and_hosts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.net_config['st_p'] == [([data.ips.st_p_st_l1], []), ([data.ips.st_p_st_l2], [])]
        assert ns.net_config['ldp_h1'] == [([data.ips.ldp_h1], [(IPv4Network('0.0.0.0/0'),
                                                                 data.ips.ldp_pe1_ldp_lan1.ip)])]
        assert f"{data.ips.ldp_p1_ldp_l2.ip}\tldp_p1-eth1" in ns.hosts_content
        assert f"{data.ips.sr_r4_lo.ip}\tsr_r4-lo" in ns.hosts_content


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.ROUTER_IFACES:
            cmds = _cmds(ops, 1, r)
            # /proc/sys writable, the MPLS modules loaded before any net.mpls sysctl is written
            assert any('mount -o rw,remount /proc/sys' in c for c in cmds), r
            assert any(c.startswith('ip route add 198.51.100.255/32 encap mpls') for c in cmds), r
            assert not any('net.mpls' in c and 'sysctl -w' in c for c in cmds), r
        for r in lab.FRR_ROUTERS:
            files = _files(ops, 1, r)
            assert set(files) == {'/etc/frr/daemons', '/etc/frr/vtysh.conf', '/etc/frr/frr.conf', '/etc/hosts'}
            assert ('ldpd=yes' in files['/etc/frr/daemons']) == (r in lab.LDP_ROUTERS)
            assert 'ospfd=yes' in files['/etc/frr/daemons']
            assert _cmds(ops, 3, r) == ['systemctl start frr']
        for r in ('st_pe1', 'st_p', 'st_pe2'):
            assert not _cmds(ops, 2, r) and not _cmds(ops, 3, r)
        # the sysctls of the FRR routers, with the two kernel faults of the fix site
        assert 'sysctl -w net.mpls.platform_labels=100000' in _cmds(ops, 2, 'ldp_p1')
        assert 'sysctl -w net.mpls.platform_labels=0' in _cmds(ops, 2, 'fix_p2')
        assert 'sysctl -w net.mpls.conf.eth0.input=0' in _cmds(ops, 2, 'fix_p1')
        assert 'sysctl -w net.mpls.conf.eth1.input=1' in _cmds(ops, 2, 'fix_p1')
        assert 'sysctl -w net.mpls.conf.eth0.input=1' not in _cmds(ops, 2, 'ldp_pe1')
        assert f"ip addr add {data.ips.sr_r2_lo} dev lo" in _cmds(ops, 1, 'sr_r2')

    def test_given_configurations_and_faults(self, lab, data):
        from frr import parse_frr_config
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        conf = {r: parse_frr_config(_files(ops, 1, r)['/etc/frr/frr.conf']) for r in lab.FRR_ROUTERS}
        for r in lab.FRR_ROUTERS:
            assert conf[r]['router_ospf']['router_id'] == str(ns.lo(r))
            for name in lab.core_ifaces(r):
                assert conf[r]['interfaces'][name]['network_type'] == 'point-to-point'
        for r in ('ldp_pe1', 'ldp_p1', 'ldp_p2', 'ldp_pe2', 'sr_r1', 'sr_r4'):
            assert not conf[r]['mpls_ldp']['present'] and not conf[r]['router_ospf']['segment_routing']['enabled']
        assert conf['ldp_pe1']['interfaces']['eth0']['passive'] is True
        # fix: LDP everywhere, eth0 of fix_p2 missing, the loopback of fix_pe2 outside OSPF
        assert conf['fix_p1']['mpls_ldp']['interfaces'] == ['eth0', 'eth1']
        assert conf['fix_p2']['mpls_ldp']['interfaces'] == ['eth1']
        assert conf['fix_pe2']['mpls_ldp']['transport_address'] == str(ns.lo('fix_pe2'))
        assert 'lo' not in conf['fix_pe2']['interfaces'] and conf['fix_pe1']['interfaces']['lo']['area'] == '0.0.0.0'
        # tl: SR given, the costs of the square
        for r in ('tl_r1', 'tl_r2', 'tl_r3', 'tl_r4'):
            sr = conf[r]['router_ospf']['segment_routing']
            assert sr['enabled'] and sr['prefixes'] == {f"{ns.lo(r)}/32": {'index': lab.LOOPBACKS[r], 'no_php': False,
                                                                          'explicit_null': False}}
        assert conf['tl_r3']['interfaces']['eth1']['cost'] == 15 and conf['tl_r1']['router_ospf']['ti_lfa'] is None

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for state, routers in (('solve_static', ['st_pe1', 'st_p', 'st_pe2']),
                               ('solve_ldp', ['ldp_pe1', 'ldp_p1', 'ldp_p2', 'ldp_pe2']),
                               ('solve_sr', ['sr_r1', 'sr_r2', 'sr_r3', 'sr_r4']),
                               ('solve_fix', ['fix_p1', 'fix_p2', 'fix_pe2']), ('solve_tilfa', ['tl_r1'])):
            ops = _state_ops(ns, state)
            assert {m for (s, m) in ops if s == 1} == set(routers), state
            for r in routers:
                for c in _cmds(ops, 1, r):
                    if c.startswith('vtysh -c "configure terminal"'):
                        _vtysh_commands(c)
        static = _state_ops(ns, 'solve_static')
        assert _cmds(static, 1, 'st_pe1') == [
            f"ip route add {data.nets.st_lan2} encap mpls {data.st_push} via {data.ips.st_p_st_l1.ip} dev eth1"]
        assert f"ip -f mpls route add {data.st_swap} dev lo" in _cmds(static, 1, 'st_pe2')
        ldp = _vtysh_commands(_cmds(_state_ops(ns, 'solve_ldp'), 1, 'ldp_pe1')[0])
        assert ldp[:3] == [f"access-list LDP-FEC seq 5 permit {data.nets.ldp_lo}",
                           f"access-list LDP-FEC seq 10 permit {data.nets.ldp_lan1}",
                           f"access-list LDP-FEC seq 15 permit {data.nets.ldp_lan2}"]
        assert 'interface eth1' in ldp and 'interface eth0' not in ldp
        assert 'sysctl -w net.mpls.ip_ttl_propagate=0' in _cmds(_state_ops(ns, 'solve_ldp'), 1, 'ldp_pe2')
        sr = _state_ops(ns, 'solve_sr')
        r3 = _vtysh_commands(_cmds(sr, 1, 'sr_r3')[0])
        assert f"segment-routing global-block {data.sr_srgb_r3} {data.sr_srgb_r3 + 7999}" in r3
        assert _vtysh_commands(_cmds(sr, 1, 'sr_r4')[0])[4].endswith(f"index {data.sr_index4} no-php-flag")
        fix = _state_ops(ns, 'solve_fix')
        assert _cmds(fix, 1, 'fix_p1') == ['sysctl -w net.mpls.conf.eth0.input=1']
        assert _cmds(fix, 1, 'fix_p2')[0] == 'sysctl -w net.mpls.platform_labels=100000'
        assert _cmds(fix, 1, 'fix_p2')[-1] == 'vtysh -c "clear mpls ldp neighbor"'

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = _state_ops(ns, 'final')
        parts = {}
        for state in SOLVE_STATE.values():
            for (step, machine), ops in _state_ops(ns, state).items():
                if step == 1:
                    parts.setdefault(machine, []).extend(str(op) for op in ops)
        for machine, cmds in parts.items():
            assert cmds == _cmds(final, 1, machine), machine
        assert _cmds(final, 2, 'ldp_pe1') == [f"sleep {lab.CONVERGE_WAIT}"]


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
        assert len(elements) == 42 and len({str(e.title) for e in elements}) == 42

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
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0) == (14, 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (86, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('st_sysctl', {'st_platform_labels', 'st_input', 'st_ping'}),
        ('st_pop', {'st_pop', 'st_ping'}),
        ('st_back', {'st_back', 'st_ping'}),
        ('ldp_filter', {'ldp_filter'}),
        ('ldp_ttl', {'ldp_ttl'}),
        ('sr_no_php', {'sr_no_php'}),
        ('fix_input', {'fix_input', 'fix_ping', 'fix_labelled'}),
        ('fix_labels', {'fix_labels', 'fix_ping', 'fix_labelled'}),
        ('fix_interface', {'fix_interface', 'fix_labelled'}),
        ('fix_transport', {'fix_transport'}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

    def test_partial_grades(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'ldp_ttl'})
        assert _grades(grade)['ldp_ttl'] == (0, 3)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'fix_interface'})
        assert _grades(grade)['fix_labelled'] == (2, 4)
        # TTL not propagated without LDP: the two sysctls count, not the traceroute through an LSP
        grade, _ = _simulate(lab, data, tmp_pub_dir, features={'ldp_ttl'}, answers=None)
        assert _grades(grade)['ldp_ttl'] == (2, 3) and _parts(grade)['ldp'] == 2

    def test_other_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        cheat = dict(grade.get_cheat_answers('final'))
        forms = {_text(q.title).split('. ', 1)[1]: q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)}

        def regrade(title, **changes):
            q = forms[title]
            stored = cheat[q.question_hash]
            answers = dict(json.loads(stored) if isinstance(stored, str) else stored, **changes)
            changed = dict(cheat, **{q.question_hash: json.dumps(answers) if isinstance(stored, str) else answers})
            return _grades(_simulate_with_answers(lab, data, tmp_pub_dir, changed)[0])

        for spelling, points in (('8847', 1), ('0X8847', 1), ('34887', 1), ('0x0800', 0), ('', 0)):
            assert regrade("Observations sur le site st", ethertype=spelling)['st_q_ethertype'][0] == points, spelling
        assert regrade("Observations sur le site st", hops='4')['st_q_hops'][0] == 0
        assert regrade("Observations sur le site ldp", php_label='0')['ldp_q_php_label'][0] == 0
        wrong = str(data.sr_srgb + data.sr_index4)      # the SRGB of sr_r2 used on the link sr_l2
        assert regrade("Les labels du segment routing", label_l2=wrong)['sr_q_label_l2'][0] == 0

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 4
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
        assert len(grade.get_cheat_answers('final')) == 4
        assert grade.get_cheat_answers('solve_tilfa') is None


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
        assert len(g1.get_questions_ordered()) == 10
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 10 and 'informations' not in with_fragment

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
            'mpls-why', 'mpls-header', 'mpls-ops', 'mpls-linux', 'ldp', 'ldp-frr', 'mpls-ttl', 'sr', 'sr-frr', 'tilfa',
            'mpls-debug']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance: it is the text
        # of an instance that drew another network, other labels and another SRGB
        for value in ('Partie 1', 'st_pe1', 'fix_p2'):
            assert value not in informations, value
        other = _other_instance(lab, data, lambda d: (d.nets.instance, d.st_push, d.sr_srgb_r3))
        _g, other_ns = _simulate(lab, other, tmp_pub_dir, instructor_mode=True)
        assert _text(resolve_informations(other_ns.informations)[0]) == informations

    def test_values_of_the_instance_in_the_first_question(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (f"**{data.st_push}**", f"**{data.st_back}**", f"**{data.sr_srgb_r3} à {data.sr_srgb_r3 + 7999}**",
                      f"`sr_r4` **{data.sr_index4}**", str(data.nets.ldp_l2), f"`{data.ips.fix_h2.ip}`",
                      f"`sr_r2` `{data.ips.sr_r2_lo.ip}/32`"):
            assert value in first, value
        # the faults are for the instructor only
        everything = "\n".join(t for _w, t in _all_texts(g0, ns))
        for value in ('platform_labels=0', 'input=0', 'hors d\'OSPF'):
            assert value not in everything, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['ethertype', 'max_label', 'hops', 'php_label', 'port', 'hops', 'push4', 'label_l2', 'label_l3',
                         'push3', 'input', 'session']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 10 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'mpls_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('mpls_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|zone|voisin|bouclage|etiquet|chemin|'
                            r'secours|depannage)', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'fix_p2' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.-]+', n)]
        assert bad == []
