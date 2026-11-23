"""Offline tests of the MPLS VPN lab (lab/sre/_DRAFT_misc/mpls-vpn.py).

No Docker, no FRR: a model of the six sites (``World``) holds what has been done, as a set of
features (``l3_vrfs``, ``ce_override``, ``fix_rt``...), and renders the outputs the grader reads in
the shapes captured live on Debian 13 (FRR 10.3, iproute2 7.3.0: the ``bgp_vpn_*``, ``bgp_vrf_*``,
``route_vrf_*``, ``iproute_vrf_*``, ``links_vrf_*`` and ``config_vpn_*`` fixtures of
``tests/mock_data/frr``).  The behaviours follow what was seen live: a CE rejects a route carrying its
own AS (no route without as-override), a VRF without LSP to the remote PE installs the VPN label
alone (the P router drops the packet), an imported route is not exported again (the services VRF is
no bridge between the customers).  Covers the data, the topology, the state ops, the two-pass
grading contract (nothing done: 0; everything: 100 + 6 bonus points; **each part alone gives exactly
its points and everything but one part the rest**) and the texts.
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

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'mpls-vpn.py'

PARTS = {
    'l3vpn': {'l3_vrfs', 'l3_vpnv4', 'l3_vrf_bgp'},
    'pe_ce': {'ce_ebgp', 'ce_override'},
    'extranet': {'ex_imports'},
    'sr_te': {'te_out', 'te_back'},
    'fix': {'fix_rt', 'fix_label', 'fix_activate', 'fix_interface'},
    'vpn_sr': {'sv_sr'},
}
POINTS = {'l3vpn': 24, 'pe_ce': 18, 'extranet': 18, 'sr_te': 20, 'fix': 20, 'vpn_sr': 6}
SOLVE_STATE = {'l3vpn': 'solve_l3', 'pe_ce': 'solve_ce', 'extranet': 'solve_ex', 'sr_te': 'solve_te',
               'fix': 'solve_fix', 'vpn_sr': 'solve_sv'}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {
    'l3_q_stack': 'l3vpn', 'l3_q_rd': 'l3vpn', 'l3_q_rt': 'l3vpn',
    'ce_q_aspath': 'pe_ce', 'ce_q_loop': 'pe_ce', 'ce_q_core': 'pe_ce',
    'ex_q_services': 'extranet', 'ex_q_cust_a': 'extranet', 'ex_q_reexport': 'extranet', 'ex_q_hub': 'extranet',
    'te_q_out': 'sr_te', 'te_q_back': 'sr_te', 'te_q_l34': 'sr_te',
    'fix_q_label': 'fix', 'fix_q_interface': 'fix',
}
FORM_POINTS = {'l3vpn': 3, 'pe_ce': 4, 'extranet': 6, 'sr_te': 4, 'fix': 2}
CHOICE_ELEMENTS = {'l3_q_rd', 'l3_q_rt', 'ce_q_loop', 'ce_q_core', 'ex_q_reexport', 'ex_q_hub', 'fix_q_label',
                   'fix_q_interface'}
BONUS_ELEMENTS = ['sv_sr', 'sv_stack', 'sv_ping']
VPN_LABEL, TRANSPORT_LABEL = 80, 18


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('mpls_vpn_lab_under_test', _LAB_PATH)
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
    """True when *value* appears in *text* as a whole (a random 65000:10 is not in "65000:100")."""
    return re.search(r'(?<![0-9A-Za-z.])' + re.escape(value) + r'(?![0-9A-Za-z])', text) is not None


def _state_ops(ns, name):
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
    lines = re.findall(r'-c "([^"]*)"', command)
    assert lines[0] == 'configure terminal' and lines[-2:] == ['end', 'write'], command
    return lines[1:-2]


# ---------------------------------------------------------------------------
# a model of the sites
# ---------------------------------------------------------------------------


def _route(prefix, gateway=None, dev='eth0', labels=None, protocol='bgp'):
    entry = {'dst': str(prefix)}
    if labels:
        entry['encap'] = {'encap_type': 'mpls', 'dst': "/".join(str(x) for x in labels)}
    if gateway:
        entry['gateway'] = str(gateway)
    entry.update({'dev': dev, 'protocol': protocol, 'flags': []})
    return entry


def _summary(router_id, peers):
    """``show bgp ... summary json`` (shape of bgp_vpn_summary_l3_pe1.json); {} without peer."""
    if not peers:
        return {}
    return {'routerId': str(router_id), 'as': 65000, 'vrfId': 0, 'vrfName': 'default',
            'peers': {str(p): {'remoteAs': asn, 'localAs': 65000, 'state': 'Established', 'peerState': 'OK',
                               'pfxRcd': 1, 'pfxSnt': 1, 'peerUptime': '00:01:00', 'idType': 'ipv4'}
                      for p, asn in peers}}


def _path(prefix, nexthop, aspath, best=True, internal=False):
    return {'valid': True, 'bestpath': best, 'pathFrom': 'internal' if internal else 'external',
            'prefix': str(prefix.network_address), 'prefixLen': prefix.prefixlen, 'network': str(prefix),
            'metric': 0, 'weight': 0, 'peerId': str(nexthop), 'path': " ".join(str(x) for x in aspath),
            'origin': 'IGP', 'nexthops': [{'ip': str(nexthop), 'afi': 'ipv4', 'used': True}]}


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    def l3_ok(self):
        return PARTS['l3vpn'] <= self.f

    def links(self, r):
        f = self.f
        names = [f"eth{i}" for i in range(len(self.lab.ROUTER_IFACES[r]))]
        masters = {}
        vrfs = []
        if r in ('l3_pe1', 'l3_pe2') and 'l3_vrfs' in f:
            vrfs = self.lab.VRFS[r]
            masters = {ifname: vrf for vrf, _t, ifname in vrfs}
        elif r == 'fix_pe2':
            vrfs = self.lab.VRFS[r]
            masters = {'eth0': 'CUST_A'} if 'fix_interface' in f else {}
        links = [{'ifname': 'lo', 'flags': ['LOOPBACK', 'UP']}]
        for vrf, table, _ifname in vrfs:
            links.append({'ifname': vrf, 'flags': ['NOARP', 'MASTER', 'UP', 'LOWER_UP'],
                          'linkinfo': {'info_kind': 'vrf', 'info_data': {'table': table}}})
        for name in names:
            link = {'ifname': name, 'flags': ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP']}
            if name in masters:
                link['master'] = masters[name]
            links.append(link)
        return links

    def vpn_routes(self, r):
        ns, d = self.ns, self.d
        if not self.l3_ok():
            return {'warning': 'Default BGP instance not found'} if 'l3_vpnv4' not in self.f else {'routes': {}}
        other = 'l3_pe2' if r == 'l3_pe1' else 'l3_pe1'
        remote = ns.net('l3_a2_lan') if r == 'l3_pe1' else ns.net('l3_a1_lan')
        local = ns.net('l3_a1_lan') if r == 'l3_pe1' else ns.net('l3_a2_lan')
        by_rd = {}
        for number in (d.rt_a, d.rt_b):
            by_rd[f"65000:{number}"] = {str(remote): [_path(remote, ns.lo(other), [], internal=True)],
                                        str(local): [_path(local, '0.0.0.0', [])]}
        return {'routerId': str(ns.lo(r)), 'routes': {'routeDistinguishers': by_rd}}

    def kernel(self, r, vrf=None):
        f, d, ns = self.f, self.d, self.ns
        addr, net = ns.addr, ns.net
        if vrf and r.startswith('l3_'):
            if 'l3_vrfs' not in f:
                return None
            lan = 'l3_a1_lan' if r == 'l3_pe1' else 'l3_a2_lan'
            remote = net('l3_a2_lan') if r == 'l3_pe1' else net('l3_a1_lan')
            routes = [_route(net(lan), dev='eth0', protocol='kernel')]
            if self.l3_ok():
                gw = addr('l3_p', 'l3_l1' if r == 'l3_pe1' else 'l3_l2')
                routes.append(_route(remote, gw, 'eth2', [TRANSPORT_LABEL, VPN_LABEL]))
            return routes
        if vrf and r == 'sv_pe1':
            stack = [self.lab.SRGB_BASE + d.sv_index('sv_pe2'), VPN_LABEL] if 'sv_sr' in f else [VPN_LABEL]
            return [_route(net('sv_a1_lan'), dev='eth0', protocol='kernel'),
                    _route(net('sv_a2_lan'), addr('sv_p', 'sv_l1'), 'eth1', stack)]
        routes = []
        if r == 'te_pe1':
            routes.append(_route(net('te_lan5'), addr('te_r2', 'te_l12'), 'eth1', protocol='ospf'))
            if 'te_out' in f:
                routes[-1] = _route(net('te_lan5'), addr('te_r4', 'te_l14'), 'eth2', ns.te_stack_out(), 'static')
        elif r == 'te_pe5':
            routes.append(_route(net('te_lan1'), addr('te_r2', 'te_l25'), 'eth1', protocol='ospf'))
            if 'te_back' in f:
                routes[-1] = _route(net('te_lan1'), addr('te_r3', 'te_l35'), 'eth2', ns.te_stack_back(), 'static')
        return routes

    def vpn_summary(self, r):
        ns = self.ns
        if r == 'l3_pe1':
            return _summary(ns.lo(r), [(ns.lo('l3_pe2'), 65000)] if 'l3_vpnv4' in self.f else [])
        if r == 'fix_pe2':
            return _summary(ns.lo(r), [(ns.lo('fix_pe1'), 65000)] if 'fix_activate' in self.f else [])
        return {}

    def vrf_summary(self, r):
        ns = self.ns
        ce, link = ('ce_c1', 'ce_link1') if r == 'ce_pe1' else ('ce_c2', 'ce_link2')
        return _summary(ns.lo(r), [(ns.addr(ce, link), 65101)] if 'ce_ebgp' in self.f else [])

    def ce_routes(self, r):
        ns = self.ns
        own, other = ('ce_site1', 'ce_site2') if r == 'ce_c1' else ('ce_site2', 'ce_site1')
        link = 'ce_link1' if r == 'ce_c1' else 'ce_link2'
        pe = ns.addr('ce_pe1' if r == 'ce_c1' else 'ce_pe2', link)
        routes = {str(ns.net(own)): [_path(ns.net(own), '0.0.0.0', [])]}
        if {'ce_ebgp', 'ce_override'} <= self.f:
            routes[str(ns.net(other))] = [_path(ns.net(other), pe, [65000, 65000])]
        return {'routes': routes}

    def vrf_rib(self, r, vrf):
        ns, f = self.ns, self.f
        own = {('ex_pe1', 'CUST_A'): ['ex_a_lan'], ('ex_pe1', 'CUST_B'): ['ex_b_lan'],
               ('ex_pe2', 'SERVICES'): ['ex_s_lan']}[(r, vrf)]
        if 'ex_imports' in f:
            own = own + (['ex_s_lan'] if vrf != 'SERVICES' else ['ex_a_lan', 'ex_b_lan'])
        return {str(ns.net(n)): [{'prefix': str(ns.net(n)), 'protocol': 'bgp', 'selected': True, 'installed': True,
                                  'nexthops': [{'ip': '10.0.0.1', 'interfaceName': 'eth2', 'labels': [VPN_LABEL]}]}]
                for n in own}

    def running_config(self, r):
        f, ns, d = self.f, self.ns, self.d
        text = "Building configuration...\n!\nfrr version 10.3\n!\n"
        if r == 'fix_pe1':
            text += "router bgp 65000 vrf CUST_A\n !\n address-family ipv4 unicast\n  redistribute connected\n"
            if 'fix_label' in f:
                text += "  label vpn export auto\n"
            text += f"  rd vpn export 65000:{d.rt_a}\n  rt vpn both 65000:{d.rt_a}\n  export vpn\n  import vpn\n" \
                    " exit-address-family\nexit\n!\n"
        elif r == 'fix_pe2':
            imported = d.rt_a if 'fix_rt' in f else d.rt_b
            text += (f"router bgp 65000 vrf CUST_A\n !\n address-family ipv4 unicast\n  label vpn export auto\n"
                     f"  rd vpn export 65000:{d.rt_a}\n  rt vpn import 65000:{imported}\n  rt vpn export 65000:{d.rt_a}\n"
                     "  export vpn\n  import vpn\n exit-address-family\nexit\n!\n")
        return text + "end\n"

    def sr_database(self, r):
        ns, d = self.ns, self.d
        if 'sv_sr' not in self.f:
            return None
        nodes = [{'routerID': str(ns.lo(x)), 'srgbSize': 8000, 'srgbLabel': 16000, 'srlbSize': 1000, 'srlbLabel': 15000,
                  'extendedPrefix': [{'prefix': f"{ns.lo(x)}/32", 'sid': d.sv_index(x), 'inputLabel': 0,
                                      'prefixRoute': []}]} for x in ('sv_pe1', 'sv_p', 'sv_pe2')]
        return {'srdbID': str(ns.lo(r)), 'srNodes': nodes}

    def counters(self, r, step):
        f = self.f
        grows = {('te_r3', 'eth0'): 'te_out' in f, ('te_r3', 'eth1'): 'te_back' in f,
                 ('fix_p', 'eth0'): PARTS['fix'] <= f}
        result = []
        for name in ('eth0', 'eth1'):
            rx = 50 + (6 if grows.get((r, name)) and step == 3 else 0)
            result.append({'ifname': name, 'group': 'afstats', 'subgroup': 'mpls',
                           'mpls_stats': {'rx': {'bytes': rx * 84, 'packets': rx, 'errors': 0, 'dropped': 0,
                                                 'noroute': 0},
                                          'tx': {'bytes': 0, 'packets': 0, 'errors': 0, 'dropped': 0}}})
        return result

    def ping_ok(self, src, dest):
        f, ns, d = self.f, self.ns, self.d
        ip = lambda h: str(getattr(d.ips, h).ip)   # noqa: E731
        table = {('l3_a1', ip('l3_a2')): self.l3_ok(), ('l3_b1', ip('l3_b2')): self.l3_ok(),
                 ('l3_a1', ip('l3_b2')): False,
                 ('ce_c1', str(d.ips.ce_c2_site.ip)): {'ce_ebgp', 'ce_override'} <= f,
                 ('ex_a', ip('ex_s')): 'ex_imports' in f, ('ex_b', ip('ex_s')): 'ex_imports' in f,
                 ('ex_a', ip('ex_b')): False,
                 ('te_h1', ip('te_h5')): True,
                 ('fix_a1', ip('fix_a2')): PARTS['fix'] <= f,
                 ('sv_a1', ip('sv_a2')): 'sv_sr' in f}
        return table[(src, dest)]

    def output(self, machine, command, step):
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'ip -j -d link show':
            return json.dumps(self.links(machine)), 0
        if command == MPLS_COUNTERS_CMD:
            return json.dumps(self.counters(machine, step)), 0
        m = re.fullmatch(r'ip -j route show vrf (\S+)', command)
        if m:
            result = self.kernel(machine, m.group(1))
            return ('Cannot find device\n', 1) if result is None else (json.dumps(result), 0)
        if command == 'ip -j route':
            return json.dumps(self.kernel(machine)), 0
        m = re.fullmatch(r'vtysh -c "(.*) json"', command)
        if m:
            show = m.group(1)
            if show == 'show bgp ipv4 vpn summary':
                return json.dumps(self.vpn_summary(machine)), 0
            if show == 'show bgp ipv4 vpn':
                return json.dumps(self.vpn_routes(machine)), 0
            if show == 'show bgp vrf CUST_C ipv4 unicast summary':
                return json.dumps(self.vrf_summary(machine)), 0
            if show == 'show bgp ipv4 unicast':
                return json.dumps(self.ce_routes(machine)), 0
            v = re.fullmatch(r'show ip route vrf (\S+)', show)
            if v:
                return json.dumps(self.vrf_rib(machine, v.group(1))), 0
            if show == 'show ip ospf database segment-routing':
                result = self.sr_database(machine)
                return ("Segment Routing is disabled on this router\n", 0) if result is None else (json.dumps(result), 0)
        p = re.fullmatch(r'ping -c \d+ -i 0\.2 -w \d+(?: -I \S+)? (\S+)', command)
        if p:
            ok = self.ping_ok(machine, p.group(1))
            return ('received\n', 0) if ok else ('0 received\n', 1)
        raise AssertionError(f"unexpected command on {machine}: {command}")


def _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES, answers='final', instructor_mode=False):
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
# data, topology, states
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()

    def test_addressing(self, lab, data):
        assert data.nets.instance.prefixlen == 16 and data.nets.instance.subnet_of(IPv4Network('10.0.0.0/8'))
        # the two customers of the l3 site share their prefixes, never a host address
        assert data.nets.l3_a1_lan == data.nets.l3_b1_lan and data.nets.l3_a2_lan == data.nets.l3_b2_lan
        assert data.nets.l3_a1_lan != data.nets.l3_a2_lan and data.nets.l3_a1_lan.subnet_of(IPv4Network('192.168.0.0/16'))
        assert data.ips.l3_a2.ip != data.ips.l3_b2.ip
        assert int(data.ips.l3_a1.ip) - int(data.nets.l3_a1_lan.network_address) == \
            int(data.ips.l3_a2.ip) - int(data.nets.l3_a2_lan.network_address)
        provider = [getattr(data.nets, n) for n in lab.LINKS] + [getattr(data.nets, f"{s}_lo") for s in lab.SITE_NUMBER]
        assert all(not a.overlaps(b) for i, a in enumerate(provider) for b in provider[i + 1:])
        others = [getattr(data.nets, n) for n in lab.LANS if not n.startswith('l3_')]
        others += [data.nets.ce_link1, data.nets.ce_link2, data.nets.ce_site1, data.nets.ce_site2]
        assert all(not a.overlaps(b) for i, a in enumerate(others) for b in others[i + 1:])
        # the extranet needs distinct customer prefixes
        assert len({data.nets.ex_a_lan, data.nets.ex_b_lan, data.nets.ex_s_lan}) == 3

    def test_values(self, lab, data):
        assert len({data.rt_a, data.rt_b, data.rt_c, data.rt_s}) == 4
        te = [data.te_index(r) for r in ('te_pe1', 'te_r2', 'te_r3', 'te_r4', 'te_pe5')]
        assert len(set(te)) == 5 and te[4] == data.te_index5
        assert len({data.sv_index(r) for r in ('sv_pe1', 'sv_p', 'sv_pe2')}) == 3


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 34 == len(lab.NetScheme._machine_specs)
        for m, spec in lab.NetScheme._machine_specs.items():
            assert spec.get('allow_connection', True) == (m not in lab.OPERATORS), m
            assert (spec.get('shape') == 'box') == (m in lab.ROUTER_IFACES)
        assert lab.OPERATORS == ('ce_c1', 'ce_c2')

    def test_sites_are_islands(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for net, members in ns._topology.items():
            assert len({lab.site_of(m) for m in members}) == 1 and len(members) == 2, net

    def test_te_costs_make_the_waypoint_necessary(self, lab):
        c = lab.TE_COSTS
        # shortest pe1 -> pe5 through te_r2; from te_r4, te_pe5 is closer through te_pe1 than through te_r3
        assert c['te_l12'] + c['te_l25'] < c['te_l14'] + c['te_l34'] + c['te_l35']
        assert c['te_l14'] + c['te_l12'] + c['te_l25'] < c['te_l34'] + c['te_l35']
        # from te_r3, te_pe1 is closer through te_r4 than through te_pe5
        assert c['te_l34'] + c['te_l14'] < c['te_l35'] + c['te_l25'] + c['te_l12']


class TestStates:
    def test_initial(self, lab, data):
        from frr import parse_frr_config, bgp_neighbor_activated
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.PROVIDER_ROUTERS:
            assert any(c.startswith('ip route add 198.51.100.255/32 encap mpls') for c in _cmds(ops, 1, r)), r
            assert f"sysctl -w net.mpls.platform_labels={lab.PLATFORM_LABELS}" in _cmds(ops, 2, r)
        for r in lab.ROUTER_IFACES:
            daemons = _files(ops, 1, r)['/etc/frr/daemons']
            assert ('bgpd=yes' in daemons) == (r in lab.BGP_ROUTERS) and ('ldpd=yes' in daemons) == (r in lab.LDP_ROUTERS)
            assert _cmds(ops, 3, r) == ['systemctl start frr']
        # the VRFs: none on the l3 site, the customer interface of fix_pe2 outside its VRF
        assert not any('type vrf' in c for c in _cmds(ops, 1, 'l3_pe1'))
        assert 'ip link set eth1 master CUST_B' in _cmds(ops, 1, 'ex_pe1')
        assert 'ip link add CUST_A type vrf table 10' in _cmds(ops, 1, 'fix_pe2')
        assert not any('master' in c for c in _cmds(ops, 1, 'fix_pe2'))
        assert 'ip link add lan0 type dummy' in _cmds(ops, 1, 'ce_c1')
        conf = {r: parse_frr_config(_files(ops, 1, r)['/etc/frr/frr.conf']) for r in lab.ROUTER_IFACES}
        assert not conf['l3_pe1']['router_bgp']['present'] and conf['l3_pe1']['mpls_ldp']['present']
        assert not conf['te_pe1']['mpls_ldp']['present'] and conf['te_pe1']['router_ospf']['segment_routing']['enabled']
        assert not conf['sv_pe1']['mpls_ldp']['present'] and not conf['sv_pe1']['router_ospf']['segment_routing']['enabled']
        assert conf['ce_c1']['router_bgp']['as'] == 65101 and conf['ce_c1']['router_bgp']['networks'] == [str(data.nets.ce_site1)]
        assert conf['ce_pe1']['router_bgp_vrfs']['CUST_C']['neighbors'] == {}
        assert conf['ex_pe1']['router_bgp_vrfs']['CUST_A']['vpn']['rt_import'] == [f"65000:{data.rt_a}"]
        # the faults
        assert conf['fix_pe1']['router_bgp_vrfs']['CUST_A']['vpn']['label'] is None
        pe2 = conf['fix_pe2']
        assert not bgp_neighbor_activated(pe2['router_bgp'], str(ns.lo('fix_pe1')), 'ipv4 vpn')
        assert pe2['router_bgp_vrfs']['CUST_A']['vpn']['rt_import'] == [f"65000:{data.rt_b}"]
        assert bgp_neighbor_activated(conf['sv_pe1']['router_bgp'], str(ns.lo('sv_pe2')), 'ipv4 vpn')
        assert conf['te_r3']['interfaces']['eth1']['cost'] == 30

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for state, routers in (('solve_l3', ['l3_pe1', 'l3_pe2']), ('solve_ce', ['ce_pe1', 'ce_pe2']),
                               ('solve_ex', ['ex_pe1', 'ex_pe2']), ('solve_te', ['te_pe1', 'te_pe5']),
                               ('solve_fix', ['fix_pe1', 'fix_pe2']), ('solve_sv', ['sv_pe1', 'sv_p', 'sv_pe2'])):
            ops = _state_ops(ns, state)
            assert {m for (s, m) in ops if s == 1} == set(routers), state
            for r in routers:
                for c in _cmds(ops, 1, r):
                    if c.startswith('vtysh -c "configure terminal"'):
                        _vtysh_commands(c)
        l3 = _cmds(_state_ops(ns, 'solve_l3'), 1, 'l3_pe1')
        assert l3[:3] == ['ip link add CUST_A type vrf table 10', 'ip link set CUST_A up', 'ip link set eth0 master CUST_A']
        vtysh = _vtysh_commands(l3[-1])
        assert 'address-family ipv4 vpn' in vtysh and f"rt vpn both 65000:{data.rt_b}" in vtysh
        assert vtysh.count('label vpn export auto') == 2
        assert 'neighbor 172.18.0.2 as-override' in _vtysh_commands(_cmds(_state_ops(ns, 'solve_ce'), 1, 'ce_pe1')[0])
        te = _vtysh_commands(_cmds(_state_ops(ns, 'solve_te'), 1, 'te_pe1')[0])
        assert te == [f"ip route {data.nets.te_lan5} {data.ips.te_r4_te_l14.ip} label "
                      f"{16000 + data.te_index3}/{16000 + data.te_index5}"]
        fix = _state_ops(ns, 'solve_fix')
        assert _cmds(fix, 1, 'fix_pe2')[0] == 'ip link set eth0 master CUST_A'
        assert _cmds(fix, 1, 'fix_pe2')[-1].startswith('vtysh -c "clear bgp vrf CUST_A')

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
        assert len(elements) == 39 and len({str(e.title) for e in elements}) == 39

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (100, 6) and _parts(grade) == POINTS

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
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0) == (19, 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (81, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('l3_vrfs', {'l3_vrfs', 'l3_export', 'l3_vrf_routes', 'l3_ping', 'l3_isolation'}),
        ('l3_vpnv4', {'l3_vpnv4', 'l3_export', 'l3_vrf_routes', 'l3_ping', 'l3_isolation'}),
        ('ce_override', {'ce_routes', 'ce_ping'}),
        ('te_out', {'te_out', 'te_ping', 'te_waypoint'}),
        ('te_back', {'te_back', 'te_waypoint'}),
        ('fix_rt', {'fix_rt', 'fix_ping', 'fix_labelled'}),
        ('fix_interface', {'fix_interface', 'fix_ping', 'fix_labelled'}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

    def test_partial_grades(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'te_back'})
        assert _grades(grade)['te_waypoint'] == (3, 6)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'ce_override'})
        assert _grades(grade)['ce_sessions'] == (6, 6) and _grades(grade)['ce_routes'] == (0, 4)

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

        s, a, b = (f"65000:{data.rt_s}", f"65000:{data.rt_a}", f"65000:{data.rt_b}")
        assert regrade("Les route targets de l'extranet", services=f"{b} {s}  {a}")['ex_q_services'][0] == 2
        assert regrade("Les route targets de l'extranet", services=f"{s} {a}")['ex_q_services'][0] == 0
        assert regrade("Les route targets de l'extranet", cust_a=f"{a} {s} {b}")['ex_q_cust_a'][0] == 0
        out = f"{16000 + data.te_index3} {16000 + data.te_index5}"
        assert regrade("Les labels du chemin choisi", out=out)['te_q_out'][0] == 2
        assert regrade("Les labels du chemin choisi", out=str(16000 + data.te_index5))['te_q_out'][0] == 0
        assert regrade("Observations sur le site ce", aspath="65000 65101")['ce_q_aspath'][0] == 0

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
        assert len(grade.get_cheat_answers('final')) == 5 and grade.get_cheat_answers('solve_sv') is None


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
        assert len(g1.get_questions_ordered()) == 12
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 12 and 'informations' not in with_fragment

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        from SRE.informations import resolve_informations, resolve_text
        resolved, numbering = resolve_informations(ns1.informations)
        informations = _text(resolved)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'l3vpn', 'vrf-linux', 'rd-rt', 'vpnv4', 'label-stack', 'l3vpn-frr', 'pe-ce', 'vpn-topologies', 'sr-te',
            'vpn-over-sr', 'l3vpn-debug']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        for value in (str(data.nets.instance), f"65000:{data.rt_a}", str(data.nets.l3_a1_lan), 'Partie 1', 'l3_pe1',
                      'fix_pe2'):
            assert not _mentions(informations, value), value

    def test_values_of_the_instance_in_the_first_question(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (f"`CUST_A` **65000:{data.rt_a}**", f"`SERVICES` **65000:{data.rt_s}**",
                      f"`te_r3` **{data.te_index3}**", f"`sv_pe2` **{data.sv_index3}**", str(data.nets.l3_a1_lan),
                      f"`ce_c2` lan0 (`{data.ips.ce_c2_site.ip}`)", "`te_l35` 30"):
            assert value in first, value
        everything = "\n".join(t for _w, t in _all_texts(g0, ns))
        for value in (f"égale à 65000:{data.rt_b}", 'hors de la VRF\n`CUST_A`', 'Les pannes du site'):
            assert value not in everything, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = [field['name'] for q in g1.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        assert names == ['stack', 'rd', 'rt', 'aspath', 'loop', 'core', 'services', 'cust_a', 'reexport', 'hub', 'out',
                         'back', 'l34', 'label', 'interface']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 12 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'mpls_vpn_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('mpls_vpn_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|client|voisin|bouclage|etiquet|chemin|'
                            r'depannage)', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'ce_c1' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.-]+', n)]
        assert bad == []
