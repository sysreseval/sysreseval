"""Offline tests of the EVPN and MPLS lab (lab/sre/_DRAFT_misc/evpn-mpls.py).

No Docker, no FRR: a model of the four sites (``World``) holds what has been done, as a set of
features (``st_evpn``, ``gw_vrf``, ``fix_mpls_input``...), and renders the outputs the grader reads in
the shapes captured live on Debian 13 (FRR 10.3, iproute2 7.3.0: tests/mock_data/vxlan/lab2_*, the
``evpn_*`` and ``bgp_vpn_*`` fixtures of tests/mock_data/frr, tests/mock_data/mpls).  The behaviours
follow what was seen live: the EVPN session between the VTEPs needs ``ebgp-multihop``, the loopbacks
announced and a working VPN data plane (MPLS input on), RFC 8212 stops the routes without route-maps,
1500-byte packets need every link of the path raised (a PE fragments the VXLAN packet otherwise), the
gateway re-originates in both directions, the host routes of the data centre leak into VPNv4 until an
export route-map filters them.  Covers the data, the topology, the state ops, the two-pass grading
contract (nothing done: 0; everything: 74 + 6 bonus points; **each part alone gives exactly its points
and everything but one part the rest**) and the texts.
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
from vxlan import FRAG_CREATES_CMD  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'evpn-mpls.py'

PARTS = {
    'stretch': {'st_evpn', 'st_mtu'},
    'gateway': {'gw_vpnv4', 'gw_vrf'},
    'fix': {'fix_multihop', 'fix_policy', 'fix_loopback', 'fix_mpls_input'},
    'aggregate': {'ag_filter'},
}
POINTS = {'stretch': 26, 'gateway': 28, 'fix': 20, 'aggregate': 6}
SOLVE_STATE = {'stretch': 'solve_stretch', 'gateway': 'solve_gateway', 'fix': 'solve_fix',
               'aggregate': 'solve_aggregate'}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {
    'st_q_labels': 'stretch', 'st_q_overhead': 'stretch', 'st_q_rt': 'stretch', 'st_q_import': 'stretch',
    'st_q_core': 'stretch', 'st_q_policy': 'stretch',
    'gw_q_labels': 'gateway', 'gw_q_vni': 'gateway', 'gw_q_reoriginate': 'gateway', 'gw_q_core': 'gateway',
    'fix_q_multihop': 'fix', 'fix_q_input': 'fix',
}
FORM_POINTS = {'stretch': 6, 'gateway': 4, 'fix': 2}
CHOICE_ELEMENTS = {'st_q_import', 'st_q_core', 'st_q_policy', 'gw_q_reoriginate', 'gw_q_core', 'fix_q_multihop',
                   'fix_q_input'}
BONUS_ELEMENTS = ['ag_no_host', 'ag_ping']
VPN_LABEL, TRANSPORT_LABEL = 80, 16


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('evpn_mpls_lab_under_test', _LAB_PATH)
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


def _mac(host: str) -> str:
    return "02:00:00:00:{:02x}:{:02x}".format(len(host), sum(map(ord, host)) % 256)


def _route(prefix, gateway=None, dev='eth0', labels=None, protocol='bgp'):
    entry = {'dst': str(prefix)}
    if labels:
        entry['encap'] = {'encap_type': 'mpls', 'dst': "/".join(str(x) for x in labels)}
    if gateway:
        entry['gateway'] = str(gateway)
    entry.update({'dev': dev, 'protocol': protocol, 'flags': []})
    return entry


def _summary(router_id, asn, peers, policy=False):
    if not peers:
        return {}
    return {'routerId': str(router_id), 'as': asn, 'peers': {
        str(p): {'remoteAs': remote, 'localAs': asn, 'state': 'Established', 'peerState': 'Policy' if policy else 'OK',
                 'pfxRcd': 1, 'pfxSnt': 1, 'peerUptime': '00:01:00', 'idType': 'ipv4'} for p, remote in peers}}


def _vpn_path(prefix, nexthop):
    net = IPv4Network(prefix)
    return {'valid': True, 'bestpath': True, 'pathFrom': 'internal', 'prefix': str(net.network_address),
            'prefixLen': net.prefixlen, 'network': str(net), 'metric': 0, 'locPrf': 100, 'weight': 0,
            'peerId': str(nexthop), 'path': '', 'origin': 'incomplete',
            'nexthops': [{'ip': str(nexthop), 'afi': 'ipv4', 'used': True}]}


def _evpn_table(routes):
    table = {}
    for rd, prefix, vni, rts, nexthop in routes:
        comm = " ".join(f"RT:{rt}" for rt in rts) + " ET:8"
        path = {'vni': vni, 'valid': True, 'bestpath': {'overall': True}, 'extendedCommunity': {'string': comm},
                'nexthops': [{'ip': str(nexthop), 'afi': 'ipv4', 'used': True}],
                'peer': {'peerId': str(nexthop), 'type': 'external'}}
        table.setdefault(rd, {'rd': rd})[prefix] = {'prefix': prefix, 'paths': [[path]]}
    table.update({'numPrefix': len(routes), 'numPaths': len(routes)})
    return table


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    def gw_ok(self):
        return PARTS['gateway'] <= self.f

    def fix_session(self):
        return {'fix_multihop', 'fix_loopback', 'fix_mpls_input'} <= self.f

    def fix_ok(self):
        return PARTS['fix'] <= self.f

    def running_config(self, m):
        f, ns = self.f, self.ns
        text = "Building configuration...\n!\nfrr version 10.3\n!\n"
        if m == 'fix_dc1':
            peer, pe = ns.lo('fix_dc2'), ns.addr('fix_pe1', 'fix_c1')
            text += (f"router bgp 65101\n no bgp default ipv4-unicast\n neighbor {pe} remote-as 65000\n"
                     f" neighbor {peer} remote-as 65102\n")
            if 'fix_multihop' in f:
                text += f" neighbor {peer} ebgp-multihop 5\n"
            text += (f" neighbor {peer} update-source lo\n !\n address-family ipv4 unicast\n"
                     f"  network {ns.lo('fix_dc1')}/32\n  neighbor {pe} activate\n exit-address-family\n !\n"
                     f" address-family l2vpn evpn\n  neighbor {peer} activate\n  neighbor {peer} route-map ALL in\n"
                     f"  neighbor {peer} route-map ALL out\n  advertise-all-vni\n exit-address-family\nexit\n!\n")
        elif m == 'fix_dc2':
            peer, pe = ns.lo('fix_dc1'), ns.addr('fix_pe2', 'fix_c2')
            text += (f"router bgp 65102\n no bgp default ipv4-unicast\n neighbor {pe} remote-as 65000\n"
                     f" neighbor {peer} remote-as 65101\n neighbor {peer} ebgp-multihop 5\n"
                     f" neighbor {peer} update-source lo\n !\n address-family ipv4 unicast\n")
            if 'fix_loopback' in f:
                text += f"  network {ns.lo('fix_dc2')}/32\n"
            text += (f"  neighbor {pe} activate\n exit-address-family\n !\n address-family l2vpn evpn\n"
                     f"  neighbor {peer} activate\n  neighbor {peer} route-map ALL in\n")
            if 'fix_policy' in f:
                text += f"  neighbor {peer} route-map ALL out\n"
            text += "  advertise-all-vni\n exit-address-family\nexit\n!\n"
        return text + "end\n"

    def evpn_summary(self, m):
        ns = self.ns
        if m == 'st_dc1':
            return _summary(ns.lo(m), 65101, [(ns.lo('st_dc2'), 65102)] if 'st_evpn' in self.f else [])
        if m == 'fix_dc1':
            return _summary(ns.lo(m), 65101, [(ns.lo('fix_dc2'), 65102)] if self.fix_session() else [])
        return {}

    def evpn_routes(self, m):
        ns, d = self.ns, self.d
        routes = []
        if m in ('st_dc1', 'st_dc2') and 'st_evpn' in self.f:
            other, host, asn = ('st_dc2', 'st_h2', 65102) if m == 'st_dc1' else ('st_dc1', 'st_h1', 65101)
            rd = f"{ns.lo(other)}:2"
            routes += [(rd, f"[3]:[0]:[32]:[{ns.lo(other)}]", '', [f"{asn}:{d.st_vni}"], ns.lo(other)),
                       (rd, f"[2]:[0]:[48]:[{_mac(host)}]", str(d.st_vni), [f"{asn}:{d.st_vni}"], ns.lo(other))]
        if m == 'gw_leaf' and self.gw_ok():
            routes.append((f"{ns.lo('gw_border')}:2", f"[5]:[0]:[24]:[{ns.net('gw_remote_net').network_address}]",
                           str(d.gw_l3vni), [f"65000:{d.gw_l3vni}"], ns.lo('gw_border')))
        return _evpn_table(routes)

    def vpn_summary(self, m):
        ns = self.ns
        return _summary(ns.lo(m), 65000, [(ns.lo('gw_pe'), 65000)] if 'gw_vpnv4' in self.f else [])

    def vpn_routes(self, m):
        ns, d = self.ns, self.d
        by_rd = {}
        if m == 'gw_pe':
            by_rd[f"65000:{d.rd_pe}"] = {str(ns.net('gw_remote_net')): [_vpn_path(ns.net('gw_remote_net'), '0.0.0.0')]}
            if self.gw_ok():
                by_rd[f"65000:{d.rd_border}"] = {str(ns.net('gw_net')): [_vpn_path(ns.net('gw_net'), ns.lo('gw_border'))]}
        if m == 'ag_pe':
            routes = {str(ns.net('ag_net')): [_vpn_path(ns.net('ag_net'), ns.lo('ag_border'))]}
            if 'ag_filter' not in self.f:
                host = f"{d.ips.ag_h1.ip}/32"
                routes[host] = [_vpn_path(host, ns.lo('ag_border'))]
            by_rd[f"65000:{d.rd_border}"] = routes
        return {'routerId': str(ns.lo(m)), 'routes': {'routeDistinguishers': by_rd}}

    def vrf_routes(self, m):
        ns, d, lab = self.ns, self.d, self.lab
        if m == 'gw_pe':
            routes = [_route(ns.net('gw_remote_net'), dev='eth0', protocol='kernel')]
            if self.gw_ok():
                routes.append(_route(ns.net('gw_net'), ns.addr('gw_p', 'gw_l2'), 'eth1', [TRANSPORT_LABEL, VPN_LABEL]))
            return routes
        if m == 'gw_leaf':
            routes = [_route(ns.net('gw_net'), dev=lab.br(d.gw_vni), protocol='kernel')]
            if self.gw_ok():
                routes.append(_route(ns.net('gw_remote_net'), ns.lo('gw_border'), lab.br(d.gw_l3vni)))
            return routes
        if m == 'gw_border':
            routes = [_route(ns.net('gw_net'), ns.lo('gw_leaf'), lab.br(d.gw_l3vni))]
            if self.gw_ok():
                routes.append(_route(ns.net('gw_remote_net'), ns.addr('gw_p', 'gw_l1'), 'eth1',
                                     [TRANSPORT_LABEL, VPN_LABEL]))
            return routes
        raise AssertionError(m)

    def kernel(self, m):
        ns = self.ns
        assert m == 'fix_dc1'
        routes = [_route(ns.net('fix_c1'), dev='eth0', protocol='kernel')]
        if 'fix_loopback' in self.f:
            routes.append(_route(f"{ns.lo('fix_dc2')}/32", ns.addr('fix_pe1', 'fix_c1')))
        return routes

    def sysctls(self, m):
        assert m == 'fix_p'
        value = 1 if 'fix_mpls_input' in self.f else 0
        return (f"/proc/sys/net/mpls/conf/eth0/input:1\n/proc/sys/net/mpls/conf/eth1/input:{value}\n"
                f"/proc/sys/net/mpls/conf/lo/input:0\n/proc/sys/net/mpls/default_ttl:255\n"
                f"/proc/sys/net/mpls/ip_ttl_propagate:1\n/proc/sys/net/mpls/platform_labels:100000\n")

    def counters(self, m, step):
        grows = {'st_p': 'st_evpn' in self.f, 'gw_p': self.gw_ok()}[m]
        result = []
        for name in ('eth0', 'eth1'):
            rx = 50 + (6 if grows and step == 3 else 0)
            result.append({'ifname': name, 'group': 'afstats', 'subgroup': 'mpls',
                           'mpls_stats': {'rx': {'bytes': rx * 84, 'packets': rx, 'errors': 0, 'dropped': 0, 'noroute': 0},
                                          'tx': {'bytes': 0, 'packets': 0, 'errors': 0, 'dropped': 0}}})
        return result

    def frag(self, m, step):
        # without the MTU of the core the PEs fragment the VXLAN packets of the 1500-byte ping
        return 4 + (2 if step == 3 and 'st_evpn' in self.f and 'st_mtu' not in self.f else 0)

    def ping_ok(self, src, dest):
        d, ns = self.d, self.ns
        ip = lambda h: str(ns.host_ip(h))   # noqa: E731
        table = {('st_h1', ip('st_h2')): 'st_evpn' in self.f, ('gw_h1', ip('gw_h2')): self.gw_ok(),
                 ('fix_h1', ip('fix_h2')): self.fix_ok(), ('ag_h1', ip('ag_h2')): True,
                 ('ag_h1', str(d.ips.ag_leaf_gw.ip)): True}
        return table[(src, dest)]

    def output(self, machine, command, step):
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'cat /sys/class/net/eth0/address':
            return _mac(machine) + "\n", 0
        if command == FRAG_CREATES_CMD:
            return f"#kernel\nIpFragCreates                   {self.frag(machine, step)}                 0.0\n", 0
        if command == MPLS_COUNTERS_CMD:
            return json.dumps(self.counters(machine, step)), 0
        if command == 'ip -j route show vrf TENANT':
            return json.dumps(self.vrf_routes(machine)), 0
        if command == 'ip -j route':
            return json.dumps(self.kernel(machine)), 0
        if command == 'grep -r . /proc/sys/net/mpls':
            return self.sysctls(machine), 0
        if command == 'sleep 4':
            return '', 0
        m = re.fullmatch(r'vtysh -c "(.*) json"', command)
        if m:
            show = m.group(1)
            if show == 'show bgp l2vpn evpn summary':
                return json.dumps(self.evpn_summary(machine)), 0
            if show == 'show bgp l2vpn evpn route detail':
                return json.dumps(self.evpn_routes(machine)), 0
            if show == 'show bgp ipv4 vpn summary':
                return json.dumps(self.vpn_summary(machine)), 0
            if show == 'show bgp ipv4 vpn':
                return json.dumps(self.vpn_routes(machine)), 0
        if 'ping' in command and '-M do -s 1472' in command:
            dest = command.rsplit(' ', 1)[1]
            ok = self.ping_ok(machine, dest) and 'st_mtu' in self.f
            return ('received\n', 0) if ok else ('sendmsg: Message too long\n', 1)
        p = re.fullmatch(r'ping -c \d+ -i 0\.2 -w \d+ (\S+)', command)
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
        underlay = [getattr(data.nets, n) for n in lab.LINKS] + [getattr(data.nets, f"{s}_lo") for s in lab.SITE_NUMBER]
        assert all(not a.overlaps(b) for i, a in enumerate(underlay) for b in underlay[i + 1:])
        subnets = [getattr(data.nets, s) for s in ('st_net', 'gw_net', 'gw_remote_net', 'fix_net', 'ag_net',
                                                   'ag_remote_net')]
        assert len(set(subnets)) == 6 and all(s.subnet_of(IPv4Network('192.168.0.0/16')) for s in subnets)
        assert data.ips.st_h1.ip != data.ips.st_h2.ip and data.ips.st_h2.ip in data.nets.st_net
        assert data.ips.gw_leaf_gw.ip == data.nets.gw_net.network_address + 1
        assert data.ips.gw_pe_gw.ip == data.nets.gw_remote_net.network_address + 1

    def test_values(self, lab, data):
        assert len({data.st_vni, data.fix_vni, data.gw_vni, data.ag_vni}) == 4
        assert len({data.gw_l3vni, data.ag_l3vni}) == 2 and data.gw_l3vni >= 10000
        assert len({data.rt_dci, data.rt_tenant, data.rd_pe, data.rd_border}) == 4


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 26 == len(lab.NetScheme._machine_specs)
        for m, spec in lab.NetScheme._machine_specs.items():
            assert (spec.get('shape') == 'box') == (m in lab.ROUTER_IFACES), m
        assert set(lab.MPLS_ROUTERS) == {f"{s}_{r}" for s in ('st', 'fix') for r in ('pe1', 'p', 'pe2')} | \
            {f"{s}_{r}" for s in ('gw', 'ag') for r in ('border', 'p', 'pe')}

    def test_sites_are_islands(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for net, members in ns._topology.items():
            assert len({lab.site_of(m) for m in members}) == 1 and len(members) == 2, net


class TestStates:
    def test_initial(self, lab, data):
        from frr import evpn_family, parse_frr_config, bgp_neighbor_activated
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.MPLS_ROUTERS:
            assert any(c.startswith('ip route add 198.51.100.255/32 encap mpls') for c in _cmds(ops, 1, r)), r
            assert f"sysctl -w net.mpls.platform_labels={lab.PLATFORM_LABELS}" in _cmds(ops, 2, r)
        assert 'sysctl -w net.mpls.conf.eth1.input=0' in _cmds(ops, 2, 'fix_p')
        assert 'sysctl -w net.mpls.conf.eth1.input=1' in _cmds(ops, 2, 'st_p')
        for r in lab.ROUTER_IFACES:
            daemons = _files(ops, 1, r)['/etc/frr/daemons']
            assert ('bgpd=yes' in daemons) == (lab.role_of(r) != 'p') and ('ldpd=yes' in daemons) == (r in lab.MPLS_ROUTERS)
            assert _cmds(ops, 3, r) == ['systemctl start frr']
        assert 'ip link set eth0 master DCI' in _cmds(ops, 1, 'st_pe1')
        v = data.st_vni
        assert f"ip link add vxlan{v} type vxlan id {v} local {ns.lo('st_dc1')} dstport 4789 nolearning" in \
            _cmds(ops, 1, 'st_dc1')
        conf = {r: parse_frr_config(_files(ops, 1, r)['/etc/frr/frr.conf']) for r in lab.ROUTER_IFACES}
        # the VTEPs of part 1: their loopback to the PE, no EVPN neighbour yet
        dc1 = conf['st_dc1']['router_bgp']
        assert dc1['as'] == 65101 and list(dc1['neighbors']) == [str(ns.addr('st_pe1', 'st_c1'))]
        assert dc1['networks'] == [f"{ns.lo('st_dc1')}/32"] and not dc1['default_ipv4_unicast']
        assert conf['st_pe1']['router_bgp_vrfs']['DCI']['vpn']['label'] == 'auto'
        assert conf['gw_leaf']['vrfs'] == {'TENANT': {'vni': data.gw_l3vni}}
        assert evpn_family(conf['gw_leaf']['router_bgp_vrfs']['TENANT'])['advertise_ipv4_unicast']
        assert 'TENANT' not in conf['gw_border']['router_bgp_vrfs'] and conf['gw_border']['vrfs']
        assert bgp_neighbor_activated(conf['gw_pe']['router_bgp'], str(ns.lo('gw_border')), 'ipv4 vpn')
        assert conf['ag_border']['router_bgp_vrfs']['TENANT']['vpn']['route_map_export'] is None
        assert not conf['gw_p']['router_bgp']['present'] and conf['gw_p']['mpls_ldp']['present']
        # the faults
        fix1 = conf['fix_dc1']['router_bgp']['neighbors'][str(ns.lo('fix_dc2'))]
        assert fix1['ebgp_multihop'] is None
        fix2 = conf['fix_dc2']['router_bgp']
        assert fix2['networks'] == []
        assert evpn_family(fix2)['neighbors'][str(ns.lo('fix_dc1'))].get('route_map_out') is None
        assert conf['st_dc2']['router_bgp']['networks'] == [f"{ns.lo('st_dc2')}/32"]

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        expected = {'solve_stretch': ['st_dc1', 'st_dc2'], 'solve_gateway': ['gw_border'],
                    'solve_fix': ['fix_dc1', 'fix_dc2', 'fix_p'], 'solve_aggregate': ['ag_border']}
        for state, routers in expected.items():
            ops = _state_ops(ns, state)
            assert {m for (s, m) in ops if s == 1} == set(routers), state
            for (step, m), _o in ops.items():
                for c in _cmds(ops, step, m):
                    if c.startswith('vtysh -c "configure terminal"'):
                        _vtysh_commands(c)
        st = _state_ops(ns, 'solve_stretch')
        vtysh = _vtysh_commands(_cmds(st, 1, 'st_dc1')[1])
        peer = ns.lo('st_dc2')
        assert f"neighbor {peer} ebgp-multihop 5" in vtysh and f"neighbor {peer} route-map ALL out" in vtysh
        assert _cmds(st, 2, 'st_p') == ['ip link set eth0 mtu 1600', 'ip link set eth1 mtu 1600']
        gw = _vtysh_commands(_cmds(_state_ops(ns, 'solve_gateway'), 1, 'gw_border')[1])
        assert f"rd vpn export 65000:{data.rd_border}" in gw and 'advertise ipv4 unicast' in gw
        assert f"neighbor {ns.lo('gw_pe')} activate" in gw
        fix = _state_ops(ns, 'solve_fix')
        assert _cmds(fix, 1, 'fix_p') == ['sysctl -w net.mpls.conf.eth1.input=1']
        assert _cmds(fix, 2, 'fix_dc1')[-1] == 'vtysh -c "clear bgp *"'
        ag = _vtysh_commands(_cmds(_state_ops(ns, 'solve_aggregate'), 1, 'ag_border')[0])
        assert 'route-map vpn export VPN-OUT' in ag and 'ip prefix-list NO-HOST seq 5 deny 0.0.0.0/0 ge 32' in ag

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = _state_ops(ns, 'final')
        # the waits of the solve states (sleep) are replaced by the one of final
        for step in (1, 2):
            parts = {}
            for state in SOLVE_STATE.values():
                for (s, machine), ops in _state_ops(ns, state).items():
                    if s == step:
                        parts.setdefault(machine, []).extend(str(op) for op in ops if not str(op).startswith('sleep '))
            for machine, cmds in parts.items():
                assert cmds == _cmds(final, step, machine), (step, machine)


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 74
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len(elements) == 31 and len({str(e.title) for e in elements}) == 31

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (74, 6) and _parts(grade) == POINTS

    @pytest.mark.parametrize('part', list(PARTS))
    def test_a_part_alone(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=PARTS[part], answers=SOLVE_STATE[part])
        assert _parts(grade) == {key: (POINTS[key] if key == part else 0) for key in POINTS}

    @pytest.mark.parametrize('part', list(PARTS))
    def test_everything_but_a_part(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - PARTS[part], answers='final')
        assert _parts(grade) == {key: (FORM_POINTS.get(part, 0) if key == part else POINTS[key]) for key in POINTS}

    def test_every_data_set(self, lab, tmp_pub_dir):
        for _ in range(8):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (74, 6)
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
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0) == (12, 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (62, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('st_mtu', {'st_mtu'}),
        ('st_evpn', {'st_session', 'st_routes', 'st_ping', 'st_mpls', 'st_mtu'}),
        ('gw_vrf', {'gw_to_vpn', 'gw_to_evpn', 'gw_border_routes', 'gw_ping', 'gw_mpls'}),
        ('gw_vpnv4', {'gw_vpnv4', 'gw_to_vpn', 'gw_to_evpn', 'gw_border_routes', 'gw_ping', 'gw_mpls'}),
        ('fix_policy', {'fix_policy', 'fix_ping'}),
        ('fix_mpls_input', {'fix_mpls_input', 'fix_session', 'fix_ping'}),
        ('ag_filter', {'ag_no_host', 'ag_ping'}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

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

        assert regrade("Observations sur le site st", rt=f"65102 : {data.st_vni}")['st_q_rt'][0] == 0
        assert regrade("Observations sur le site st", rt=f" 65102:{data.st_vni}")['st_q_rt'][0] == 1
        assert regrade("Observations sur le site st", rt=f"65101:{data.st_vni}")['st_q_rt'][0] == 0
        assert regrade("Observations sur le site st", overhead="50")['st_q_overhead'][0] == 0
        assert regrade("Ce que fait la passerelle", vni=str(data.gw_vni))['gw_q_vni'][0] == 0

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
        assert len(grade.get_cheat_answers('final')) == 3 and grade.get_cheat_answers('solve_aggregate') is None


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
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        from SRE.informations import resolve_informations, resolve_text
        resolved, numbering = resolve_informations(ns1.informations)
        informations = _text(resolved)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'dci', 'reminders', 'vxlan-over-l3vpn', 'ebgp-evpn', 'mtu', 'gateway', 'leak', 'debug']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        for value in (str(data.nets.instance), str(data.st_vni), str(data.nets.st_net), 'Partie 1', 'st_dc1',
                      'fix_p', f"65000:{data.rt_tenant}"):
            assert value not in informations, value

    def test_values_of_the_instance_in_the_first_question(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (f"VNI **{data.st_vni}**", f"L3VNI **{data.gw_l3vni}**", f"RT VPN **65000:{data.rt_tenant}**",
                      f"passerelle **65000:{data.rd_border}**", str(data.nets.gw_remote_net), str(data.nets.fix_net)):
            assert value in first, value
        everything = "\n".join(t for _w, t in _all_texts(g0, ns))
        for value in ('Les pannes du site', "pas d'`ebgp-multihop` sur `fix_dc1`", 'entrée MPLS désactivée sur\n'):
            assert value not in everything, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = [field['name'] for q in g1.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        assert names == ['labels', 'overhead', 'rt', 'import', 'core', 'policy', 'labels', 'vni', 'reoriginate', 'core',
                         'multihop', 'input']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 8 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'evpn_mpls_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('evpn_mpls_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (74, 6)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|(?<!c)lien|voisin|bouclage|etiquet|chemin|'
                            r'depannage|passerelle|hote)', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'gw_border' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.-]+', n)]
        assert bad == []
