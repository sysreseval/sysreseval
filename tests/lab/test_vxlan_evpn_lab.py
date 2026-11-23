"""Offline tests of the VXLAN / EVPN lab (lab/sre/_DRAFT_misc/vxlan-evpn.py).

No Docker, no FRR: a model of the five sites (``World``) holds what has been done, as a set of
features (``st_vxlan``, ``l2_sessions``, ``irb_l3vni``...), and renders the outputs the grader reads in
the shapes captured live on Debian 13 (FRR 10.3, iproute2 7.3.0: tests/mock_data/vxlan and the
``evpn_*`` fixtures of tests/mock_data/frr).  The behaviours follow what was seen live: without the
spine as route reflector a leaf learns nothing of the others, a VTEP whose uplink is too small sends an
ICMP *fragmentation needed* (no 1500-byte ping) and a router whose link is too small fragments the VXLAN
packet, a MAC+IP route needs the gateway SVI and the L3VNI, the type-5 routes of the subnets need the
SVIs in the VRF.  Covers the data, the topology, the state ops, the two-pass grading contract (nothing
done: 0; everything: 88 + 6 bonus points; **each part alone gives exactly its points and everything but
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

from vxlan import BRIDGE_PORTS_CMD, FDB_ALL_CMD, FRAG_CREATES_CMD, FLOOD_MAC  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'vxlan-evpn.py'

PARTS = {
    'static': {'st_vxlan', 'st_flood', 'st_mtu'},
    'evpn_l2': {'l2_sessions', 'l2_rr', 'l2_advertise'},
    'irb': {'irb_l3vni', 'irb_gateway', 'irb_suppress', 'irb_type5'},
    'fix': {'fix_vni', 'fix_rr', 'fix_advertise', 'fix_bridge'},
    'mcast': {'mc_vxlan', 'mc_pim'},
}
POINTS = {'static': 20, 'evpn_l2': 22, 'irb': 26, 'fix': 20, 'mcast': 6}
SOLVE_STATE = {'static': 'solve_static', 'evpn_l2': 'solve_l2', 'irb': 'solve_irb', 'fix': 'solve_fix',
               'mcast': 'solve_mcast'}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {
    'st_q_port': 'static', 'st_q_overhead': 'static', 'st_q_copies': 'static',
    'l2_q_rt': 'evpn_l2', 'l2_q_type3': 'evpn_l2', 'l2_q_type2': 'evpn_l2', 'l2_q_rr': 'evpn_l2', 'l2_q_rd': 'evpn_l2',
    'irb_q_l3vni': 'irb', 'irb_q_mac': 'irb', 'irb_q_silent': 'irb', 'irb_q_sym': 'irb',
    'fix_q_vni': 'fix', 'fix_q_rr': 'fix',
}
FORM_POINTS = {'static': 3, 'evpn_l2': 5, 'irb': 4, 'fix': 2}
CHOICE_ELEMENTS = {'st_q_copies', 'l2_q_rr', 'l2_q_rd', 'irb_q_mac', 'irb_q_silent', 'irb_q_sym', 'fix_q_vni',
                   'fix_q_rr'}
BONUS_ELEMENTS = ['mc_vxlan', 'mc_mroute', 'mc_ping']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('vxlan_evpn_lab_under_test', _LAB_PATH)
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


def _link(name, master=None, mtu=1500, kind=None, data=None, slave=None, address=None, up=True):
    link = {'ifname': name, 'flags': ['BROADCAST', 'MULTICAST'] + (['UP', 'LOWER_UP'] if up else []), 'mtu': mtu}
    if master:
        link['master'] = master
    if address:
        link['address'] = address
    if kind:
        link['linkinfo'] = {'info_kind': kind, 'info_data': data or {}}
        if slave:
            link['linkinfo']['info_slave_data'] = slave
    return link


def _vxlan(name, vni, local=None, master=None, learning=False, group=None, dev=None, ttl=0, suppress=False):
    data = {'id': vni, 'port': 4789, 'ttl': ttl, 'df': 'unset', 'learning': learning}
    if local:
        data['local'] = str(local)
    if group:
        data['group'] = group
    if dev:
        data['link'] = dev
    slave = {'state': 'forwarding', 'neigh_suppress': suppress} if master else None
    return _link(name, master=master, kind='vxlan', data=data, slave=slave)


def _fdb(dev, mac, dst=None, extern=False, self_entry=True):
    flags = (['self'] if self_entry else []) + (['extern_learn'] if extern else [])
    entry = {'mac': mac, 'ifname': dev, 'flags': flags, 'state': 'permanent' if mac == FLOOD_MAC else ''}
    if dst:
        entry['dst'] = str(dst)
    return entry


def _summary(router_id, asn, peers):
    if not peers:
        return {}
    return {'routerId': str(router_id), 'as': asn, 'peers': {
        str(p): {'remoteAs': asn, 'localAs': asn, 'state': 'Established', 'peerState': 'OK', 'pfxRcd': 1,
                 'pfxSnt': 1, 'peerUptime': '00:01:00', 'idType': 'ipv4'} for p in peers}}


def _evpn_table(routes):
    """``show bgp l2vpn evpn route detail json`` from (rd, prefix, vni, rts, nexthop, rmac) tuples."""
    table = {}
    for rd, prefix, vni, rts, nexthop, rmac in routes:
        comm = " ".join(f"RT:{rt}" for rt in rts) + " ET:8" + (f" Rmac:{rmac}" if rmac else "")
        path = {'vni': vni, 'valid': True, 'bestpath': {'overall': True}, 'extendedCommunity': {'string': comm},
                'nexthops': [{'ip': str(nexthop), 'afi': 'ipv4', 'used': True}],
                'peer': {'peerId': '10.0.0.1', 'type': 'internal'}}
        table.setdefault(rd, {'rd': rd})[prefix] = {'prefix': prefix, 'paths': [[path]]}
    table.update({'numPrefix': len(routes), 'numPaths': len(routes)})
    return table


def _route(prefix, gateway=None, dev='eth0', protocol='bgp'):
    entry = {'dst': str(prefix), 'dev': dev, 'protocol': protocol, 'flags': ['onlink'] if gateway else []}
    if gateway:
        entry['gateway'] = str(gateway)
    return entry


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    # -- what works ------------------------------------------------------------------

    def st_ok(self):
        return {'st_vxlan', 'st_flood'} <= self.f

    def l2_ok(self):
        return PARTS['evpn_l2'] <= self.f

    def irb_routing(self):
        return {'irb_l3vni', 'irb_gateway'} <= self.f

    def fix_ok(self):
        return PARTS['fix'] <= self.f

    def mc_ok(self):
        return PARTS['mcast'] <= self.f

    # -- kernel ---------------------------------------------------------------------

    def links(self, m):
        f, d, ns, lab = self.f, self.d, self.ns, self.lab
        site = lab.site_of(m)
        nics = [f"eth{i}" for i in range(len(lab.ROUTER_IFACES[m]))]
        masters, extra, mtus = {}, [], {}
        if m in lab.ST_VTEPS and 'st_vxlan' in f:
            v = d.st_vni
            masters = {'eth1': lab.br(v)}
            extra = [_link(lab.br(v), kind='bridge'), _vxlan(lab.vx(v), v, ns.lo(m), lab.br(v), learning=True)]
        if site == 'st' and 'st_mtu' in f:
            mtus = {n: lab.MTU_SOLUTION for n in nics if n != 'eth1' or m == 'st_r'}
        if m in lab.LEAVES['l2'] or m in ('irb_leaf1', 'irb_leaf2'):
            for vni, ifname in d.leaf_vnis(m):
                masters[ifname] = lab.br(vni)
                bridge = _link(lab.br(vni), kind='bridge')
                if site == 'irb' and 'irb_gateway' in f:
                    bridge = _link(lab.br(vni), master=lab.VRF, kind='bridge', address=d.gw_mac)
                extra += [bridge, _vxlan(lab.vx(vni), vni, ns.lo(m), lab.br(vni),
                                         suppress=(site == 'irb' and 'irb_suppress' in f))]
            if site == 'irb' and 'irb_l3vni' in f:
                l3 = d.irb_l3vni
                extra += [_link(lab.VRF, kind='vrf', data={'table': lab.VRF_TABLE}),
                          _link(lab.br(l3), master=lab.VRF, kind='bridge'), _vxlan(lab.vx(l3), l3, ns.lo(m), lab.br(l3))]
        if m in lab.LEAVES['fix']:
            v = d.fix_vni
            masters = {'eth1': lab.br(v)}
            if m == 'fix_leaf1':
                extra = [_link(lab.br(v), kind='bridge'),
                         _vxlan(lab.vx(v), v, ns.lo(m), lab.br(v) if 'fix_bridge' in f else None)]
            else:
                extra = [_link(lab.br(v), kind='bridge'),
                         _vxlan(lab.vx(v), v if 'fix_vni' in f else v + 1, ns.lo(m), lab.br(v))]
        if m in lab.MC_VTEPS:
            v = d.mc_vni
            masters = {'eth1': lab.br(v)}
            extra = [_link(lab.br(v), kind='bridge')]
            if 'mc_vxlan' in f:
                extra.append(_vxlan(lab.vx(v), v, master=lab.br(v), learning=True, group=d.mc_group, dev='eth0',
                                    ttl=lab.MC_TTL))
        links = [{'ifname': 'lo', 'flags': ['LOOPBACK', 'UP'], 'mtu': 65536}]
        links += [_link(n, master=masters.get(n), mtu=mtus.get(n, 1500)) for n in nics]
        return links + extra

    def fdb(self, m, step):
        f, d, ns, lab = self.f, self.d, self.ns, self.lab
        entries = []
        if m in lab.ST_VTEPS and self.st_ok():
            dev = lab.vx(d.st_vni)
            entries += [_fdb(dev, FLOOD_MAC, ns.lo(o)) for o in lab.ST_VTEPS if o != m]
            if m == 'st_vtep1' and step >= 2:
                entries += [_fdb(dev, _mac('st_h2'), ns.lo('st_vtep2')), _fdb(dev, _mac('st_h3'), ns.lo('st_vtep3'))]
        if m in lab.LEAVES['l2'] and self.l2_ok():
            remote = {'l2_leaf1': [(d.l2_vni_a, 'l2_a2', 'l2_leaf2')],
                      'l2_leaf2': [(d.l2_vni_a, 'l2_a1', 'l2_leaf1'), (d.l2_vni_b, 'l2_b3', 'l2_leaf3')],
                      'l2_leaf3': [(d.l2_vni_b, 'l2_b2', 'l2_leaf2')]}[m]
            for vni, host, origin in remote:
                entries += [_fdb(lab.vx(vni), FLOOD_MAC, ns.lo(origin)),
                            _fdb(lab.vx(vni), _mac(host), ns.lo(origin), extern=True),
                            _fdb(lab.vx(vni), _mac(host), extern=True, self_entry=False)]
        if m == 'fix_leaf1' and self.fix_ok():
            dev = lab.vx(d.fix_vni)
            entries += [_fdb(dev, FLOOD_MAC, ns.lo('fix_leaf2')), _fdb(dev, _mac('fix_h2'), ns.lo('fix_leaf2'), extern=True)]
        return entries

    def addresses(self, m):
        d = self.d
        result = [{'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8}]}]
        if 'irb_gateway' in self.f:
            gateways = {d.irb_vni_a: d.ips.irb_gw_a, d.irb_vni_b: d.ips.irb_gw_b}
            for vni, _ifname in d.leaf_vnis(m):
                gw = gateways[vni]
                result.append({'ifname': self.lab.br(vni), 'addr_info': [{'family': 'inet', 'local': str(gw.ip),
                                                                          'prefixlen': 24}]})
        return result

    def bridge_ports(self, m):
        d, lab = self.d, self.lab
        return [{'ifname': lab.vx(vni), 'master': lab.br(vni), 'state': 'forwarding', 'mtu': 1500,
                 'neigh_suppress': 'irb_suppress' in self.f, 'learning': True, 'flood': True}
                for vni, _ifname in d.leaf_vnis(m)]

    def vrf_routes(self, m):
        ns, d, lab = self.ns, self.d, self.lab
        if not ({'irb_l3vni', 'irb_gateway'} & self.f):
            return None
        routes = []
        if self.irb_routing():
            other, host = ('irb_leaf2', 'irb_b2') if m == 'irb_leaf1' else ('irb_leaf1', 'irb_a1')
            routes.append(_route(ns.host_ip(host), ns.lo(other), lab.br(d.irb_l3vni)))
        return routes

    def frag(self, m, step):
        # the VXLAN packets of the 1500-byte pings are fragmented by st_r while its links are at 1500
        return 7 + (3 if step == 3 and self.st_ok() and 'st_mtu' not in self.f else 0)

    # -- FRR ------------------------------------------------------------------------

    def evpn_routes(self, m):
        f, d, ns, lab = self.f, self.d, self.ns, self.lab
        rt = ns.rt
        routes = []
        if m in lab.LEAVES['l2'] and self.l2_ok():
            carried = {leaf: [v for v, _i in d.leaf_vnis(leaf)] for leaf in lab.LEAVES['l2']}
            hosts = {'l2_leaf1': {d.l2_vni_a: 'l2_a1'}, 'l2_leaf2': {d.l2_vni_a: 'l2_a2', d.l2_vni_b: 'l2_b2'},
                     'l2_leaf3': {d.l2_vni_b: 'l2_b3'}}
            for leaf, vnis in carried.items():
                for k, vni in enumerate(vnis):
                    if vni not in carried[m]:
                        continue
                    rd = f"{ns.lo(leaf)}:{k + 2}"
                    routes.append((rd, f"[3]:[0]:[32]:[{ns.lo(leaf)}]", str(vni), [rt(vni)], ns.lo(leaf), None))
                    routes.append((rd, f"[2]:[0]:[48]:[{_mac(hosts[leaf][vni])}]", str(vni), [rt(vni)], ns.lo(leaf), None))
        if m == 'irb_leaf1':
            l3, b = d.irb_l3vni, d.irb_vni_b
            if self.irb_routing():
                routes.append((f"{ns.lo('irb_leaf2')}:3", f"[2]:[0]:[48]:[{_mac('irb_b2')}]:[32]:[{ns.host_ip('irb_b2')}]",
                               f"{b}/{l3}", [rt(b), rt(l3)], ns.lo('irb_leaf2'), '02:aa:00:00:00:02'))
            if 'irb_type5' in f:
                routes.append((f"{ns.lo('irb_border')}:2", f"[5]:[0]:[24]:[{ns.net('irb_ext_net').network_address}]",
                               str(l3), [rt(l3)], ns.lo('irb_border'), '02:aa:00:00:00:20'))
        if m in ('irb_leaf1', 'irb_border') and {'irb_type5', 'irb_gateway', 'irb_l3vni'} <= f:
            l3 = d.irb_l3vni
            subnet = ('irb_net_b', 'irb_leaf2') if m == 'irb_leaf1' else ('irb_net_a', 'irb_leaf1')
            routes.append((f"{ns.lo(subnet[1])}:4", f"[5]:[0]:[24]:[{ns.net(subnet[0]).network_address}]", str(l3),
                           [rt(l3)], ns.lo(subnet[1]), '02:aa:00:00:00:01'))
        return _evpn_table(routes)

    def evpn_vnis(self, m):
        f, d, ns, lab = self.f, self.d, self.ns, self.lab
        result = []
        remote = {}
        if m in lab.LEAVES['l2'] and self.l2_ok():
            remote = {'l2_leaf1': {d.l2_vni_a: ['l2_leaf2']},
                      'l2_leaf2': {d.l2_vni_a: ['l2_leaf1'], d.l2_vni_b: ['l2_leaf3']},
                      'l2_leaf3': {d.l2_vni_b: ['l2_leaf2']}}[m]
        vrf = lab.VRF if (lab.site_of(m) == 'irb' and 'irb_l3vni' in f) else 'default'
        for vni, _ifname in d.leaf_vnis(m):
            result.append({'vni': vni, 'type': 'L2', 'tenantVrf': vrf, 'vxlanInterface': lab.vx(vni),
                           'sviInterface': lab.br(vni), 'vtepIp': str(ns.lo(m)), 'mcastGroup': '0.0.0.0',
                           'remoteVteps': [{'ip': str(ns.lo(o)), 'flood': 'HER'} for o in remote.get(vni, [])]})
        if lab.site_of(m) == 'irb' and 'irb_l3vni' in f:
            result.append({'vni': d.irb_l3vni, 'type': 'L3', 'tenantVrf': lab.VRF, 'localVtepIp': str(ns.lo(m)),
                           'vxlanIntf': lab.vx(d.irb_l3vni), 'sviIntf': lab.br(d.irb_l3vni), 'state': 'Up',
                           'routerMac': '02:aa:00:00:00:01', 'l2Vnis': [v for v, _i in d.leaf_vnis(m)]})
        return result if result else {}

    def running_config(self, m):
        f, ns = self.f, self.ns
        text = "Building configuration...\n!\nfrr version 10.3\n!\n"
        if m == 'fix_spine':
            l1, l2 = ns.lo('fix_leaf1'), ns.lo('fix_leaf2')
            text += (f"router bgp 65000\n neighbor {l1} remote-as 65000\n neighbor {l2} remote-as 65000\n !\n"
                     f" address-family l2vpn evpn\n  neighbor {l1} activate\n")
            if 'fix_rr' in f:
                text += f"  neighbor {l1} route-reflector-client\n"
            text += f"  neighbor {l2} activate\n  neighbor {l2} route-reflector-client\n exit-address-family\nexit\n!\n"
        elif m == 'fix_leaf2':
            spine = ns.lo('fix_spine')
            text += f"router bgp 65000\n neighbor {spine} remote-as 65000\n !\n address-family l2vpn evpn\n" \
                    f"  neighbor {spine} activate\n"
            if 'fix_advertise' in f:
                text += "  advertise-all-vni\n"
            text += " exit-address-family\nexit\n!\n"
        return text + "end\n"

    def mroutes(self):
        d, ns = self.d, self.ns
        if not self.mc_ok():
            return {}
        source = str(ns.addr('mc_vtep1', 'mc_u1'))
        return {d.mc_group: {
            '*': {'source': '*', 'group': d.mc_group, 'installed': 1, 'iif': 'lo', 'flags': 'SC',
                  'oil': {'pimreg': {}, 'eth0': {}, 'eth1': {}, 'eth2': {}}},
            source: {'source': source, 'group': d.mc_group, 'installed': 1, 'iif': 'eth0', 'flags': 'SFT',
                     'oil': {'eth1': {}, 'eth2': {}}}}}

    # -- pings ------------------------------------------------------------------------

    def ping_ok(self, src, dest):
        d, ns = self.d, self.ns
        ip = lambda h: str(ns.host_ip(h))   # noqa: E731
        table = {('st_h1', ip('st_h2')): self.st_ok(), ('st_h1', ip('st_h3')): self.st_ok(),
                 ('st_h2', ip('st_h3')): self.st_ok(),
                 ('l2_a1', ip('l2_a2')): self.l2_ok(), ('l2_b2', ip('l2_b3')): self.l2_ok(), ('l2_a1', ip('l2_b2')): False,
                 ('irb_a1', str(d.ips.irb_gw_a.ip)): 'irb_gateway' in self.f,
                 ('irb_a2', str(d.ips.irb_gw_a.ip)): 'irb_gateway' in self.f,
                 ('irb_b2', str(d.ips.irb_gw_b.ip)): 'irb_gateway' in self.f,
                 ('irb_a1', ip('irb_b2')): self.irb_routing(),
                 ('irb_a1', str(d.ips.irb_ext_addr.ip)): self.irb_routing() and 'irb_type5' in self.f,
                 ('fix_h1', ip('fix_h2')): self.fix_ok(),
                 ('mc_h1', ip('mc_h2')): self.mc_ok(), ('mc_h1', ip('mc_h3')): self.mc_ok()}
        return table[(src, dest)]

    def output(self, machine, command, step):
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'ip -j -d link show':
            return json.dumps(self.links(machine)), 0
        if command == FDB_ALL_CMD:
            return json.dumps(self.fdb(machine, step)), 0
        if command == BRIDGE_PORTS_CMD:
            return json.dumps(self.bridge_ports(machine)), 0
        if command == 'ip -j -4 addr show 2>/dev/null':
            return json.dumps(self.addresses(machine)), 0
        if command == FRAG_CREATES_CMD:
            return f"#kernel\nIpFragCreates                   {self.frag(machine, step)}                 0.0\n", 0
        if command == 'cat /sys/class/net/eth0/address':
            return _mac(machine) + "\n", 0
        if command == 'ip -j route show vrf TENANT':
            result = self.vrf_routes(machine)
            return ('Cannot find device "TENANT"\n', 1) if result is None else (json.dumps(result), 0)
        m = re.fullmatch(r'vtysh -c "(.*) json"', command)
        if m:
            show = m.group(1)
            if show == 'show bgp l2vpn evpn summary':
                ns = self.ns
                peers = [ns.lo(x) for x in self.lab.LEAVES['l2']] if 'l2_sessions' in self.f else []
                return json.dumps(_summary(ns.lo(machine), 65000, peers)), 0
            if show == 'show bgp l2vpn evpn route detail':
                return json.dumps(self.evpn_routes(machine)), 0
            if show == 'show evpn vni detail':
                return json.dumps(self.evpn_vnis(machine)), 0
            if show == 'show ip mroute':
                return json.dumps(self.mroutes()), 0
        if 'ping' in command and '-M do -s 1472' in command:
            dest = command.rsplit(' ', 1)[1]
            ok = self.ping_ok(machine, dest) and 'st_mtu' in self.f
            return ('received\n', 0) if ok else ('sendmsg: Message too long\n', 1)
        p = re.fullmatch(r'(?:sleep \d+; )?ping -c \d+ -i 0\.2 -w \d+ (\S+)', command)
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
        subnets = [getattr(data.nets, s) for s in ('st_net', 'l2_net', 'irb_net_a', 'irb_net_b', 'fix_net', 'mc_net')]
        assert len(set(subnets)) == 6 and all(s.subnet_of(IPv4Network('192.168.0.0/16')) for s in subnets)
        assert data.nets.irb_ext_net.subnet_of(IPv4Network('172.16.0.0/12'))
        hosts = [data.ips.st_h1.ip, data.ips.st_h2.ip, data.ips.st_h3.ip]
        assert len(set(hosts)) == 3 and all(h in data.nets.st_net for h in hosts)
        # the two VNIs of part 2 share one subnet, never an address
        l2 = [getattr(data.ips, h).ip for h in ('l2_a1', 'l2_a2', 'l2_b2', 'l2_b3')]
        assert len(set(l2)) == 4 and all(h in data.nets.l2_net for h in l2)
        assert data.ips.irb_gw_a.ip == data.nets.irb_net_a.network_address + 1
        assert data.ips.irb_a1.ip != data.ips.irb_gw_a.ip and data.ips.irb_b2.ip in data.nets.irb_net_b

    def test_values(self, lab, data):
        vnis = [data.st_vni, data.l2_vni_a, data.l2_vni_b, data.irb_vni_a, data.irb_vni_b, data.fix_vni, data.mc_vni]
        assert len(set(vnis)) == 7 and all(1000 <= v < 10000 for v in vnis) and data.irb_l3vni >= 10000
        assert re.fullmatch(r'239\.\d+\.\d+\.\d+', data.mc_group)
        assert re.fullmatch(r'02:00:5e:[0-9a-f]{2}:[0-9a-f]{2}:01', data.gw_mac)


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 35 == len(lab.NetScheme._machine_specs)
        for m, spec in lab.NetScheme._machine_specs.items():
            assert (spec.get('shape') == 'box') == (m in lab.ROUTER_IFACES), m
            assert ('routing-frr' in spec.get('image', '')) == (m in lab.ROUTER_IFACES), m

    def test_sites_are_islands(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for net, members in ns._topology.items():
            assert len({lab.site_of(m) for m in members}) == 1 and len(members) == 2, net


class TestStates:
    def test_initial(self, lab, data):
        from frr import evpn_family, parse_frr_config
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.ROUTER_IFACES:
            daemons = _files(ops, 1, r)['/etc/frr/daemons']
            assert ('bgpd=yes' in daemons) == (r in lab.BGP_ROUTERS) and ('pimd=yes' in daemons) == (r == 'mc_r')
            assert _cmds(ops, 3, r) == ['systemctl start frr']
        v = data.l2_vni_a
        assert f"ip link add vxlan{v} type vxlan id {v} local {ns.lo('l2_leaf1')} dstport 4789 nolearning" in \
            _cmds(ops, 1, 'l2_leaf1')
        # part 1 and the bonus: nothing VXLAN on the VTEPs (the bonus has its bridges)
        assert not any('vxlan' in c for c in _cmds(ops, 1, 'st_vtep1') + _cmds(ops, 1, 'mc_vtep1'))
        assert f"ip link add br{data.mc_vni} type bridge" in _cmds(ops, 1, 'mc_vtep1')
        # the faults of part 4: the right name, the wrong VNI; a device outside its bridge
        f = data.fix_vni
        assert f"ip link add vxlan{f} type vxlan id {f + 1} local {ns.lo('fix_leaf2')} dstport 4789 nolearning" in \
            _cmds(ops, 1, 'fix_leaf2')
        assert f"ip link set vxlan{f} master br{f}" not in _cmds(ops, 1, 'fix_leaf1')
        conf = {r: parse_frr_config(_files(ops, 1, r)['/etc/frr/frr.conf']) for r in lab.ROUTER_IFACES}
        assert not conf['l2_spine']['router_bgp']['present'] and not conf['l2_leaf1']['router_bgp']['present']
        assert evpn_family(conf['irb_leaf1']['router_bgp'])['advertise_all_vni']
        assert conf['irb_border']['vrfs'] == {'TENANT': {'vni': data.irb_l3vni}}
        assert conf['irb_leaf1']['vrfs'] == {}
        spine = evpn_family(conf['fix_spine']['router_bgp'])['neighbors']
        assert not spine[str(ns.lo('fix_leaf1'))].get('route_reflector_client')
        assert spine[str(ns.lo('fix_leaf2'))]['route_reflector_client']
        assert not evpn_family(conf['fix_leaf2']['router_bgp'])['advertise_all_vni']
        assert evpn_family(conf['fix_leaf1']['router_bgp'])['advertise_all_vni']
        assert 'ip link set eth1 master TENANT' in _cmds(ops, 1, 'irb_border')
        assert 'ip link add ext0 type dummy' in _cmds(ops, 1, 'irb_ext')

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for state, routers in (('solve_static', ['st_r'] + lab.ST_VTEPS),
                               ('solve_l2', ['l2_spine'] + lab.LEAVES['l2']),
                               ('solve_irb', ['irb_leaf1', 'irb_leaf2', 'irb_border']),
                               ('solve_fix', ['fix_spine', 'fix_leaf1', 'fix_leaf2']),
                               ('solve_mcast', ['mc_r'] + lab.MC_VTEPS)):
            ops = _state_ops(ns, state)
            assert {m for (s, m) in ops if s == 1} == set(routers), state
            for r in routers:
                for c in _cmds(ops, 1, r):
                    if c.startswith('vtysh -c "configure terminal"'):
                        _vtysh_commands(c)
        st = _cmds(_state_ops(ns, 'solve_static'), 1, 'st_vtep2')
        assert f"bridge fdb append 00:00:00:00:00:00 dev vxlan{data.st_vni} dst {ns.lo('st_vtep1')}" in st
        assert 'ip link set eth0 mtu 1600' in st and not any('nolearning' in c for c in st)
        l2 = _state_ops(ns, 'solve_l2')
        assert _cmds(l2, 1, 'l2_leaf1')[0].startswith('i=0; while ! ip route get')
        assert 'advertise-all-vni' in _vtysh_commands(_cmds(l2, 1, 'l2_leaf1')[1])
        assert f"neighbor {ns.lo('l2_leaf3')} route-reflector-client" in _vtysh_commands(_cmds(l2, 1, 'l2_spine')[1])
        irb = _cmds(_state_ops(ns, 'solve_irb'), 1, 'irb_leaf2')
        assert f"ip link set br{data.irb_vni_b} address {data.gw_mac}" in irb
        assert f"ip link set vxlan{data.irb_vni_a} type bridge_slave neigh_suppress on" in irb
        vtysh = _vtysh_commands(irb[-1])
        assert vtysh[:3] == ['vrf TENANT', f"vni {data.irb_l3vni}", 'exit-vrf'] and 'advertise ipv4 unicast' in vtysh
        border = _vtysh_commands(_cmds(_state_ops(ns, 'solve_irb'), 1, 'irb_border')[0])
        assert 'redistribute static' in border
        mc = _cmds(_state_ops(ns, 'solve_mcast'), 1, 'mc_vtep1')
        assert mc[0] == f"ip link add vxlan{data.mc_vni} type vxlan id {data.mc_vni} group {data.mc_group} dev eth0 " \
                        f"ttl 5 dstport 4789"

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
        assert sum(e.max_grade for e in elements if not e.bonus) == 88
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len(elements) == 40 and len({str(e.title) for e in elements}) == 40

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (88, 6) and _parts(grade) == POINTS

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
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (88, 6)
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
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (74, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('st_mtu', {'st_mtu'}),
        ('st_flood', {'st_flood', 'st_ping', 'st_learn', 'st_mtu'}),
        ('l2_rr', {'l2_rr', 'l2_vni', 'l2_macs', 'l2_ping', 'l2_isolation'}),
        ('l2_sessions', {'l2_sessions', 'l2_rr', 'l2_vni', 'l2_macs', 'l2_ping', 'l2_isolation'}),
        ('irb_suppress', {'irb_suppress'}),
        ('irb_type5', {'irb_type5', 'irb_ping'}),
        ('irb_gateway', {'irb_gateway', 'irb_macip', 'irb_type5', 'irb_ping'}),
        ('fix_bridge', {'fix_bridge', 'fix_ping', 'fix_macs'}),
        ('mc_pim', {'mc_mroute', 'mc_ping'}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

    def test_partial_grades(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'irb_type5'})
        assert _grades(grade)['irb_ping'] == (3, 6) and _grades(grade)['irb_type5'] == (0, 3)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'st_mtu'})
        assert _grades(grade)['st_vxlan'] == (6, 6) and _grades(grade)['st_mtu'] == (0, 3)

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

        assert regrade("Les routes EVPN", rt=f" 65000:{data.l2_vni_a} ")['l2_q_rt'][0] == 1
        assert regrade("Les routes EVPN", rt=f"65000:{data.l2_vni_b}")['l2_q_rt'][0] == 0
        assert regrade("Observations sur le site st", overhead="54")['st_q_overhead'][0] == 0
        assert regrade("Le routage dans la fabrique", l3vni=str(data.irb_vni_b))['irb_q_l3vni'][0] == 0

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
        assert len(grade.get_cheat_answers('final')) == 4 and grade.get_cheat_answers('solve_mcast') is None


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
        assert len(g1.get_questions_ordered()) == 10
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 10 and 'informations' not in with_fragment

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
            'overlay', 'vxlan-header', 'vxlan-linux', 'bum', 'mtu', 'evpn', 'evpn-rd-rt', 'evpn-frr',
            'arp-suppression', 'irb', 'anycast-gw', 'irb-linux', 'type5', 'mcast-underlay', 'evpn-debug']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course says nothing of this instance nor of the parts
        for value in (str(data.nets.instance), str(data.st_vni), str(data.nets.st_net), 'Partie 1', 'st_vtep1',
                      'fix_leaf2', data.gw_mac):
            assert value not in informations, value

    def test_values_of_the_instance_in_the_first_question(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (f"VNI **{data.st_vni}**", f"VNI A **{data.l2_vni_a}**", f"L3VNI **{data.irb_l3vni}**",
                      f"groupe **{data.mc_group}**", data.gw_mac, str(data.nets.irb_ext_net), str(data.nets.l2_net)):
            assert value in first, value
        everything = "\n".join(t for _w, t in _all_texts(g0, ns))
        for value in ('Les pannes du site', f"le VNI {data.fix_vni + 1}", 'pas client du route reflector sur'):
            assert value not in everything, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = [field['name'] for q in g1.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        assert names == ['port', 'overhead', 'copies', 'rt', 'type3', 'type2', 'rr', 'rd', 'l3vni', 'mac', 'silent',
                         'sym', 'vni', 'rr']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 10 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'vxlan_evpn_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('vxlan_evpn_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (88, 6)

    def test_english_identifiers(self, lab, data):
        # ('client' is English too: rr_client; and holds 'lien')
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
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'irb_ext' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.-]+', n)]
        assert bad == []
