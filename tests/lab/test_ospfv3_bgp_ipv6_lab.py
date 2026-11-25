"""Offline tests of the OSPFv3 + BGP-IPv6 lab (lab/sre/_DRAFT_misc/ospfv3-bgp-ipv6.py).

No Docker and no FRR: a model of the eight sites (``World``) holds what has been configured, as a
set of features (``o1_ospf``, ``eb_policy``, ``fix_mtu``...), and renders the outputs the grader
reads in the shapes of FRR 9.1.3 and iproute2 (the json keys of the fixtures
``tests/mock_data/frr/ospf6_*`` / ``bgp6_*``, captured in an IPv6-only probe).  The behaviours
follow what was seen live (no eBGP exchange without policy, a route with an unreachable next hop is
not installed, the duplicate router-id hides the MTU fault...).  Covers the data, the topology, the
state ops, the two-pass grading contract (nothing done: 0; everything: 100 + 6 bonus points; **each
part alone gives exactly its points and everything but one part the rest**; variants) and the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv6Address, IPv6Network
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from ipv6 import link_local_from_mac  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'ospfv3-bgp-ipv6.py'

# what each part configures (the features of the model) and its points
PARTS = {
    'ospf': {'o1_ospf', 'o1_passive', 'o1_cost'},
    'areas': {'o2_ospf', 'o2_ext', 'o2_range', 'o2_stub'},
    'ebgp': {'eb_bgp', 'eb_policy', 'eb_network'},
    'ibgp': {'ib_mesh', 'ib_nhs'},
    'policy': {'po_lp', 'po_prepend', 'po_out', 'po_in'},
    'fix': {'fix_mtu', 'fix_rid', 'fix_activate', 'fix_network'},
    'unnumbered': {'un_bgp'},
    'auth': {'au_ospf'},
}
POINTS = {'ospf': 17, 'areas': 17, 'ebgp': 17, 'ibgp': 15, 'policy': 18, 'fix': 16, 'unnumbered': 3, 'auth': 3}
SOLVE_STATE = {'ospf': 'solve_ospf', 'areas': 'solve_areas', 'ebgp': 'solve_ebgp', 'ibgp': 'solve_ibgp',
               'policy': 'solve_policy', 'fix': 'solve_fix', 'unnumbered': 'solve_unnumbered', 'auth': 'solve_auth'}
ALL_FEATURES = set().union(*PARTS.values())
# the elements that grade the answers of the forms, and their part
FORM_ELEMENTS = {
    'o1_q_nexthop': 'ospf', 'o1_q_hello_group': 'ospf', 'o1_q_lsa': 'ospf',
    'o2_q_range': 'areas', 'o2_q_summary_lsa': 'areas', 'o2_q_stub': 'areas',
    'eb_q_afi_safi': 'ebgp', 'eb_q_attribute': 'ebgp', 'eb_q_nh_global': 'ebgp', 'eb_q_nh_ll': 'ebgp',
    'ib_q_nh_before': 'ibgp', 'ib_q_mesh': 'ibgp', 'ib_q_why_loopback': 'ibgp', 'ib_q_why_r2': 'ibgp',
    'po_q_path_b': 'policy', 'po_q_decision': 'policy', 'po_q_why_long': 'policy', 'po_q_med': 'policy',
    'fix_q_mtu_state': 'fix', 'fix_q_not_activated': 'fix',
}
FORM_POINTS = {'ospf': 3, 'areas': 3, 'ebgp': 4, 'ibgp': 4, 'policy': 5, 'fix': 2}
CHOICE_ELEMENTS = {'o1_q_lsa', 'o2_q_summary_lsa', 'o2_q_stub', 'eb_q_attribute', 'ib_q_why_loopback', 'ib_q_why_r2',
                   'po_q_decision', 'po_q_why_long', 'po_q_med', 'fix_q_mtu_state', 'fix_q_not_activated'}
BONUS_ELEMENTS = ['un_session', 'un_route', 'un_ping', 'au_adjacency', 'au_auth']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('ospfv3_bgp_ipv6_lab_under_test', _LAB_PATH)
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
    """{(step, machine): [ops]} registered by the state method *name*."""
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
    """The configuration lines of a `vtysh -c "configure terminal" -c ... -c "end" -c "write"`."""
    lines = re.findall(r'-c "([^"]*)"', command)
    assert lines[0] == 'configure terminal' and lines[-2:] == ['end', 'write'], command
    return lines[1:-2]


# ---------------------------------------------------------------------------
# a model of the sites: features -> what the grader reads
# ---------------------------------------------------------------------------


def _path(prefix, peer, aspath, nexthop_global, nexthop_ll=None, valid=True, best=True, locprf=None,
          internal=False):
    """One path of ``show bgp ipv6 unicast json`` (shape of bgp6_routes_p2.json)."""
    nexthops = [{'ip': str(nexthop_global), 'afi': 'ipv6', 'scope': 'global'}]
    if nexthop_ll:
        nexthops.append({'ip': str(nexthop_ll), 'afi': 'ipv6', 'scope': 'link-local', 'used': True})
    else:
        nexthops[0]['used'] = True
    entry = {'pathFrom': 'internal' if internal else 'external', 'prefix': str(prefix.network_address),
             'prefixLen': prefix.prefixlen, 'network': str(prefix), 'metric': 0, 'weight': 0,
             'peerId': str(peer), 'path': " ".join(str(x) for x in aspath), 'origin': 'IGP', 'nexthops': nexthops}
    if valid:
        entry['valid'] = True
    if valid and best:
        entry['bestpath'] = True
    if locprf is not None:
        entry['locPrf'] = locprf
    return entry


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    def ll(self, machine, net):
        return self.ns.ll(machine, net)

    # -- OSPFv3 ----------------------------------------------------------------

    def ospf6_running(self, r):
        f = self.f
        return ((r.startswith('o1_') and 'o1_ospf' in f) or (r.startswith('o2_') and 'o2_ospf' in f)
                or r.startswith('ib_r') or r in ('fix_r1', 'fix_r2', 'au_r2') or (r == 'au_r1' and 'au_ospf' in f))

    def ospf6_info(self, r):
        f, lab = self.f, self.lab
        if not self.ospf6_running(r):
            return None
        rid = lab.ROUTER_ID[r]
        if r == 'fix_r2' and 'fix_rid' not in f:
            rid = lab.ROUTER_ID['fix_r1']
        stub = 'o2_stub' in f
        areas = {'0': {'areaIsStub': False, 'interfacesAttachedToArea': ['eth0']}}
        if r == 'o2_abr':
            areas = {'0': {'areaIsStub': False, 'interfacesAttachedToArea': ['eth0']},
                     '1': {'areaIsStub': stub, 'interfacesAttachedToArea': ['eth1']}}
        elif r == 'o2_r1':
            areas = {'1': {'areaIsStub': stub, 'interfacesAttachedToArea': ['eth0', 'eth1', 'eth2']}}
        return {'routerId': rid, 'numberOfAreaInRouter': len(areas), 'areas': areas}

    @staticmethod
    def _neighbor(rid, ifname, state='Full'):
        return {'neighborId': rid, 'priority': 1, 'deadTime': '00:00:35', 'state': state, 'ifState': 'DR',
                'duration': '00:01:00', 'interfaceName': ifname, 'interfaceState': 'BDR'}

    def ospf6_neighbors(self, r):
        f, rid = self.f, self.lab.ROUTER_ID
        n = []
        if r == 'o1_r1' and 'o1_ospf' in f:
            n = [self._neighbor(rid['o1_r2'], 'eth1'), self._neighbor(rid['o1_r3'], 'eth2')]
        elif r == 'o1_r2' and 'o1_ospf' in f:
            n = [self._neighbor(rid['o1_r1'], 'eth0'), self._neighbor(rid['o1_r3'], 'eth1')]
        elif r == 'o2_r0' and 'o2_ospf' in f:
            n = [self._neighbor(rid['o2_abr'], 'eth1')]
        elif r == 'o2_r1' and 'o2_ospf' in f:
            n = [self._neighbor(rid['o2_abr'], 'eth0')]
        elif r == 'fix_r1' and 'fix_rid' in f:
            # with a duplicate router-id there is no neighbour at all; then the MTU blocks in ExStart
            n = [self._neighbor(rid['fix_r2'], 'eth1', 'Full' if 'fix_mtu' in f else 'ExStart')]
        elif r == 'au_r1' and 'au_ospf' in f:
            n = [self._neighbor(rid['au_r2'], 'eth0')]
        return {'neighbors': n} if self.ospf6_running(r) else None

    @staticmethod
    def _interface(area, cost=10, passive=False, mtu=1500, auth='NULL'):
        return {'status': 'up', 'type': 'BROADCAST', 'attachedToArea': True, 'interfaceMtu': mtu,
                'mtuMismatchDetection': 'enabled', 'areaId': area, 'cost': cost, 'ospf6InterfaceState': 'DR',
                'priority': 1, 'timerIntervalsConfigHello': 10, 'timerIntervalsConfigDead': 40,
                'timerPassiveIface': passive, 'internetAddress': [], 'authInfo': {'authType': auth}}

    def ospf6_interfaces(self, r):
        f, d = self.f, self.d
        if not self.ospf6_running(r):
            return None
        cost = d.o1_cost if 'o1_cost' in f else 10
        passive = 'o1_passive' in f
        if r == 'o1_r1':
            return {'eth0': self._interface('0.0.0.0', passive=passive), 'eth1': self._interface('0.0.0.0'),
                    'eth2': self._interface('0.0.0.0', cost=cost)}
        if r == 'o1_r3':
            return {'eth0': self._interface('0.0.0.0', passive=passive), 'eth1': self._interface('0.0.0.0', cost=cost),
                    'eth2': self._interface('0.0.0.0')}
        if r == 'fix_r1':
            return {'eth0': {'status': 'up', 'type': 'BROADCAST'}, 'eth1': self._interface('0.0.0.0')}
        if r == 'fix_r2':
            return {'eth0': self._interface('0.0.0.0', mtu=1500 if 'fix_mtu' in f else d.fix_mtu),
                    'eth1': self._interface('0.0.0.0', passive=True)}
        if r == 'au_r1':
            return {'eth0': self._interface('0.0.0.0', auth='manualkey')}
        return {}

    def ospf6_routes(self, r):
        f, ns = self.f, self.ns
        if not self.ospf6_running(r):
            return None
        routes = {}

        def add(prefix, code, nexthop='fe80::1', ifname='eth0'):
            routes[str(prefix)] = {'isBestRoute': True, 'destinationType': 'N', 'pathType': code,
                                   'nextHops': [{'nextHop': nexthop, 'interfaceName': ifname}]}

        area1 = [ns.net(n) for n in ('o2_l1', 'o2_lan1a', 'o2_lan1b')]
        if r == 'o2_r0':
            add(ns.net('o2_l0'), 'IA', '::', 'eth1')
            for n in ([self.d.nets6.o2_area1] if 'o2_range' in f else area1):
                add(n, 'IE', 'fe80::2', 'eth1')
        elif r == 'o2_abr':
            add(ns.net('o2_l0'), 'IA', '::')
            for n in area1:
                add(n, 'IA', 'fe80::3', 'eth1')
            if 'o2_ext' in f:
                add(ns.net('o2_ext'), 'E2')
        elif r == 'o2_r1':
            add(ns.net('o2_l0'), 'IE')
            if 'o2_stub' in f:
                add(IPv6Network('::/0'), 'IE')
            elif 'o2_ext' in f:
                add(ns.net('o2_ext'), 'E2')
        return {'routes': routes}

    # -- kernel ------------------------------------------------------------------

    def kernel(self, r):
        f, ns, b, lo = self.f, self.ns, self.ns.block, self.ns.lo
        routes = []

        def add(prefix, gateway, dev, protocol):
            routes.append({'dst': str(prefix), 'gateway': str(gateway), 'dev': dev, 'protocol': protocol,
                           'metric': 20, 'flags': []})

        if r == 'o1_r1' and 'o1_ospf' in f:
            if 'o1_cost' in f:
                add(ns.net('o1_lan3'), self.ll('o1_r2', 'o1_l12'), 'eth1', 'ospf')
            else:
                add(ns.net('o1_lan3'), self.ll('o1_r3', 'o1_l13'), 'eth2', 'ospf')
        if r == 'o1_r3' and 'o1_ospf' in f:
            if 'o1_cost' in f:
                add(ns.net('o1_lan1'), self.ll('o1_r2', 'o1_l23'), 'eth2', 'ospf')
            else:
                add(ns.net('o1_lan1'), self.ll('o1_r1', 'o1_l13'), 'eth1', 'ospf')
        if r == 'eb_r1' and {'eb_bgp', 'eb_policy'} <= f:
            add(b('eb_isp'), self.ll('eb_isp', 'eb_link'), 'eth1', 'bgp')
        if r == 'ib_r2' and {'ib_mesh', 'ib_nhs'} <= f:
            # without next-hop-self the next hop (ib_isp on ib_link) is unknown: nothing installed
            add(b('ib_isp'), self.ll('ib_r1', 'ib_l12'), 'eth0', 'bgp')
        if r == 'un_r1' and 'un_bgp' in f:
            add(IPv6Network(f"{lo('un_r2')}/128"), self.ll('un_r2', 'un_link'), 'eth0', 'bgp')
        routes.append({'dst': 'fe80::/64', 'dev': 'eth0', 'protocol': 'kernel', 'metric': 256, 'flags': []})
        return routes

    # -- BGP ---------------------------------------------------------------------

    def bgp_summary(self, r):
        f, a, lab = self.f, self.ns.addr, self.lab

        def peer(remote_as, established=True, policy=False, received=1):
            return {'remoteAs': remote_as, 'state': 'Established' if established else 'Active',
                    'peerState': 'Policy' if policy else 'OK', 'pfxRcd': received if established and not policy else 0,
                    'pfxSnt': 1, 'idType': 'ipv6'}

        if r == 'eb_isp':
            return {'routerId': lab.ROUTER_ID[r], 'as': lab.AS_OF[r],
                    'peers': {str(a('eb_r1', 'eb_link')): peer(lab.AS_OF['eb_r1'], established='eb_bgp' in self.f)}}
        if r == 'eb_r1' and 'eb_bgp' in f:
            return {'routerId': lab.ROUTER_ID[r], 'as': lab.AS_OF[r],
                    'peers': {str(a('eb_isp', 'eb_link')): peer(lab.AS_OF['eb_isp'], policy='eb_policy' not in f)}}
        if r == 'un_r1' and 'un_bgp' in f:
            return {'routerId': lab.ROUTER_ID[r], 'as': lab.AS_OF[r],
                    'peers': {'eth0': dict(peer(lab.AS_OF['un_r2']), idType='interface')}}
        return {}

    def bgp_routes(self, r):
        f, a, b, lo, lab, d = self.f, self.ns.addr, self.ns.block, self.ns.lo, self.lab, self.d
        routes = {}

        def add(prefix, *paths):
            routes[str(prefix)] = list(paths)

        if r == 'eb_isp' and {'eb_bgp', 'eb_policy', 'eb_network'} <= f:
            add(b('eb'), _path(b('eb'), a('eb_r1', 'eb_link'), [65010], a('eb_r1', 'eb_link'),
                               self.ll('eb_r1', 'eb_link')))
        if r == 'ib_r3' and 'ib_mesh' in f:
            nhs = 'ib_nhs' in f
            add(b('ib_isp'), _path(b('ib_isp'), lo('ib_r1'), [lab.AS_OF['ib_isp']],
                                   lo('ib_r1') if nhs else a('ib_isp', 'ib_link'), valid=nhs, internal=True,
                                   locprf=100))
        if r == 'po_r1':
            ispa, ispb = a('po_ispa', 'po_la'), a('po_ispb', 'po_lb')
            lp = 'po_lp' in f
            add(b('po_inet'),
                _path(b('po_inet'), ispa, [65110, 65110, 65000], ispa, best=lp, locprf=200 if lp else 100),
                _path(b('po_inet'), ispb, [65120, 65000], ispb, best=not lp, locprf=100))
            if 'po_in' not in f:
                for junk in (d.nets6.junk_ula, d.nets6.junk_doc, d.nets6.junk_long):
                    add(junk, _path(junk, ispb, [65120], ispb))
        if r == 'po_inet':
            via_a, via_b = a('po_ispa', 'po_ia'), a('po_ispb', 'po_ib')
            prepend = 'po_prepend' in f
            path_b = [65120] + [65030] * (3 if prepend else 1)
            add(b('po'), _path(b('po'), via_a, [65110, 65110, 65030], via_a, best=prepend),
                _path(b('po'), via_b, path_b, via_b, best=not prepend))
        if r == 'fix_r1' and 'fix_activate' in f:
            isp = a('fix_isp', 'fix_link')
            add(b('fix_isp'), _path(b('fix_isp'), isp, [65300], isp, self.ll('fix_isp', 'fix_link')))
        if r == 'fix_isp' and {'fix_activate', 'fix_network'} <= f:
            add(b('fix'), _path(b('fix'), a('fix_r1', 'fix_link'), [65040], a('fix_r1', 'fix_link')))
        if r == 'un_r1' and 'un_bgp' in f:
            prefix = IPv6Network(f"{lo('un_r2')}/128")
            peer = self.ll('un_r2', 'un_link')
            add(prefix, _path(prefix, peer, [65051], peer, peer))
        return {'routerId': lab.ROUTER_ID.get(r), 'routes': routes}

    def bgp_neighbor(self, r, peer):
        lab, lo = self.lab, self.ns.lo
        if r.startswith('ib_r') and 'ib_mesh' in self.f:
            other = next(x for x in ('ib_r1', 'ib_r2', 'ib_r3') if str(lo(x)) == peer)
            return {peer: {'remoteAs': 65020, 'localAs': 65020, 'nbrInternalLink': True, 'bgpState': 'Established',
                           'hostLocal': str(lo(r)), 'hostForeign': str(lo(other)),
                           'addressFamilyInfo': {'ipv6Unicast': {'acceptedPrefixCounter': 1}}}}
        return {'bgpNoSuchNeighbor': True} if r in lab.BGP_ROUTERS else {}

    def advertised(self, r, peer):
        b = self.ns.block
        prefixes = [b('po')]
        if 'po_out' not in self.f:
            prefixes += [b('po_inet'), b('po_ispa'), b('po_ispb')]
        return {'advertisedRoutes': {str(p): {'nextHopGlobal': '::', 'path': '', 'origin': 'IGP'} for p in prefixes}}

    # -- the commands ------------------------------------------------------------

    def ping_ok(self, src):
        f = self.f
        return {'o1_h1': 'o1_ospf' in f, 'o2_h1': {'o2_ospf', 'o2_ext'} <= f,
                'eb_h': {'eb_bgp', 'eb_policy', 'eb_network'} <= f, 'ib_h': {'ib_mesh', 'ib_nhs'} <= f,
                'fix_h': PARTS['fix'] <= f, 'un_r1': 'un_bgp' in f}[src]

    def output(self, machine, command):
        if command == 'vtysh -c "show running-config"':
            if machine == 'eb_r1' and 'eb_bgp' in self.f:
                return "Building configuration...\n!\nrouter bgp 65010\n bgp router-id 3.0.0.1\nexit\n!\nend\n", 0
            return 'Building configuration...\n', 0
        m = re.fullmatch(r'vtysh -c "(.*) json"', command)
        if m:
            show = m.group(1)
            producers = {'show ipv6 ospf6': self.ospf6_info, 'show ipv6 ospf6 neighbor': self.ospf6_neighbors,
                         'show ipv6 ospf6 interface': self.ospf6_interfaces, 'show ipv6 ospf6 route': self.ospf6_routes,
                         'show bgp ipv6 unicast summary': self.bgp_summary, 'show bgp ipv6 unicast': self.bgp_routes}
            if show in producers:
                result = producers[show](machine)
                return ('' if result is None else json.dumps(result, indent=2) + "\n"), 0
            n = re.fullmatch(r'show bgp neighbors (\S+)', show)
            if n:
                return json.dumps(self.bgp_neighbor(machine, n.group(1))), 0
            n = re.fullmatch(r'show bgp ipv6 unicast neighbors (\S+) advertised-routes', show)
            if n and machine == 'po_r1':
                return json.dumps(self.advertised(machine, n.group(1))), 0
        if command == 'ip -j -6 route':
            return json.dumps(self.kernel(machine)), 0
        if command == 'ip -j -6 addr show dev eth0' and machine == 'un_r1':
            return json.dumps([{'ifname': 'eth0', 'addr_info': [
                {'family': 'inet6', 'local': str(self.ll('un_r1', 'un_link')), 'prefixlen': 64, 'scope': 'link'}]}]), 0
        if command.startswith('ping -c 2 -w 4 '):
            ok = self.ping_ok(machine)
            return ('64 bytes from x: icmp_seq=1 ttl=62 time=0.1 ms\n' if ok else '2 packets transmitted, 0 received\n'), \
                (0 if ok else 1)
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
                    cmds[key] = model.output(m, key[0])
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
        instance = data.nets6.instance
        assert instance.prefixlen == 32 and instance.subnet_of(lab.DOC_SPACE)
        for name in lab.BLOCKS:
            block = getattr(data.nets6, f"as_{name}")
            assert block.prefixlen == 48 and block.subnet_of(instance)
        nets = [getattr(data.nets6, n) for n in lab.NET6_PLAN]
        assert len(set(nets)) == len(nets) and all(n.prefixlen == 64 for n in nets)
        # the three networks of area 1 are exactly the /60 to configure
        area1 = data.nets6.o2_area1
        assert area1.prefixlen == 60 and area1.subnet_of(data.nets6.as_o2)
        assert all(getattr(data.nets6, n).subnet_of(area1) for n in ('o2_l1', 'o2_lan1a', 'o2_lan1b'))
        assert not any(getattr(data.nets6, n).subnet_of(area1) for n in ('o2_l0', 'o2_ext'))
        # a customer link is in the ISP's /48, the ISP side is ::1
        assert data.nets6.eb_link.subnet_of(data.nets6.as_eb_isp)
        assert int(data.ips6.eb_isp_eb_link.ip) - int(data.nets6.eb_link.network_address) == 1
        for router, (block, _n) in lab.LOOPBACKS.items():
            lo = getattr(data.ips6, f"{router}_lo")
            assert lo.network.prefixlen == 128 and lo.ip in getattr(data.nets6, f"as_{block}")

    def test_junk_prefixes(self, lab, data):
        assert data.nets6.junk_ula.subnet_of(IPv6Network('fc00::/7'))
        assert data.nets6.junk_doc.subnet_of(lab.BOGON_DOC)
        assert data.nets6.junk_long.prefixlen == 64 and data.nets6.junk_long.subnet_of(data.nets6.as_po_ispb)

    def test_values(self, lab, data):
        assert data.o1_cost in lab.O1_COSTS and data.fix_mtu in lab.FIX_MTUS
        assert re.fullmatch(r'[A-Za-z0-9]{6,12}', data.au_key) and 1 <= data.au_key_id <= 255
        # with any of the costs the path from o1_r1 to o1_lan3 goes through o1_r2 (10 + 10 < cost)
        assert min(lab.O1_COSTS) > 20


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 35 == len(lab.NetScheme._machine_specs)
        for m, spec in lab.NetScheme._machine_specs.items():
            assert spec['image'].startswith('sysreseval/netdev13:'), m
            assert spec['sysctls'] == lab.SYSCTLS
            assert spec.get('allow_connection', True) == (m not in lab.OPERATORS), m
            assert (spec.get('shape') == 'box') == (m in lab.ROUTER_IFACES)
        assert lab.ipv6 is True

    def test_interfaces_follow_the_tables(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        topology = ns._topology
        for router, nets in lab.ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                iface, mac = topology[net][router]
                assert iface == i and mac == getattr(data.macs, f"{router}_{i}")
        for host, (net, _gw) in lab.HOSTS.items():
            assert topology[net][host][0] == 0
        # every site is a separate island: no network joins two sites
        for net, members in topology.items():
            assert len({lab.site_of(m) for m in members}) == 1, net

    def test_fixed_macs_give_the_link_locals(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        macs = [str(v) for v in vars(data.macs).values()]
        assert len(set(macs)) == len(macs) and all(m.upper().startswith('02-53-52') for m in macs)
        assert ns.ll('o1_r2', 'o1_l12') == link_local_from_mac(data.macs.o1_r2_0)
        assert ns.ll('eb_isp', 'eb_link') == link_local_from_mac(data.macs.eb_isp_0)
        assert ns.ll('fix_isp', 'fix_link').is_link_local

    def test_net_config(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.net_config['un_r1'] == [([], [])] and ns.net_config['un_r2'] == [([], [])]
        assert ns.net_config['o1_r1'][2][0] == [data.ips6.o1_r1_o1_l13]
        assert ns.net_config['o2_h1'] == [([data.ips6.o2_h1], [(IPv6Network('::/0'), data.ips6.o2_r1_o2_lan1a.ip)])]
        assert all(addr.version == 6 for entry in ns.net_config.values() for addrs, _ in entry for addr in addrs)
        assert f"{data.ips6.o1_r2_o1_l23.ip}\to1_r2-eth1" in ns.hosts_content
        assert f"{data.ips6.ib_r1_lo.ip}\tib_r1-lo" in ns.hosts_content


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.ROUTER_IFACES:
            files = _files(ops, 1, r)
            assert set(files) >= {'/etc/frr/daemons', '/etc/frr/vtysh.conf', '/etc/frr/frr.conf', '/etc/hosts'}
            daemons = files['/etc/frr/daemons']
            assert ('ospf6d=yes' in daemons) == (r in lab.OSPF6_ROUTERS) and ('bgpd=yes' in daemons) == (r in lab.BGP_ROUTERS)
            assert 'systemctl start frr' in _cmds(ops, 2, r)
        assert f"ip link set dev eth0 mtu {data.fix_mtu}" in _cmds(ops, 1, 'fix_r2')
        assert f"ip addr add {data.ips6.un_r1_lo} dev lo" in _cmds(ops, 1, 'un_r1')
        # the hosts do not forward
        assert any('net.ipv6.conf.all.forwarding' in c and '0' in c for c in _cmds(ops, 1, 'o1_h1'))

    def test_given_configurations_and_faults(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        conf = {r: _files(_state_ops(ns, 'initial'), 1, r)['/etc/frr/frr.conf'] for r in lab.ROUTER_IFACES}
        from frr import parse_frr_config, bgp_neighbor_activated
        parsed = {r: parse_frr_config(text) for r, text in conf.items()}
        for r in ('o1_r1', 'o1_r2', 'o1_r3', 'o2_r0', 'o2_abr', 'o2_r1', 'eb_r1', 'un_r1', 'au_r1'):
            assert not parsed[r]['router_bgp']['present'] and not parsed[r]['router_ospf6']['present'], r
        # fix: duplicate router-id, neighbour not activated, network without route
        assert parsed['fix_r2']['router_ospf6']['router_id'] == parsed['fix_r1']['router_ospf6']['router_id']
        rb = parsed['fix_r1']['router_bgp']
        assert not bgp_neighbor_activated(rb, str(ns.addr('fix_isp', 'fix_link')), 'ipv6')
        assert rb['networks'] == [str(ns.block('fix'))] and parsed['fix_r1']['static_routes6'] == []
        assert parsed['fix_r1']['router_ospf6']['default_information_always']
        # the operators announce their /48 with a blackhole route, activated in IPv6 only
        for r in ('eb_isp', 'ib_isp', 'po_ispa', 'po_ispb', 'po_inet', 'fix_isp'):
            rb = parsed[r]['router_bgp']
            assert rb['default_ipv4_unicast'] is False and rb['router_id'] == lab.ROUTER_ID[r]
            assert all(bgp_neighbor_activated(rb, p, 'ipv6') for p in rb['neighbors'])
            assert (str(ns.block(r)), 'blackhole') in parsed[r]['static_routes6']
        assert 'set as-path prepend 65110' in conf['po_ispa']
        for junk in (data.nets6.junk_ula, data.nets6.junk_doc, data.nets6.junk_long):
            assert f"  network {junk}" in conf['po_ispb']
        assert {'ISPA-IN', 'ISPA-OUT', 'ISPB-IN', 'ISPB-OUT'} <= set(parsed['po_r1']['route_maps'])
        assert parsed['un_r2']['router_bgp']['neighbors']['eth0']['interface'] is True
        auth = parsed['au_r2']['interfaces']['eth0']['ospf6']['authentication']
        assert auth == {'key_id': data.au_key_id, 'hash_algo': 'hmac-sha-256', 'key': data.au_key}
        # ib: OSPFv3 given on the three routers (loopbacks included), the eBGP session of ib_r1
        for r in ('ib_r1', 'ib_r2', 'ib_r3'):
            assert parsed[r]['interfaces']['lo']['ospf6']['area'] == '0.0.0.0'
        assert parsed['ib_r3']['interfaces']['eth1']['ospf6']['passive'] is True

    def test_solutions_are_vtysh_sessions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for state, routers in (('solve_ospf', ['o1_r1', 'o1_r2', 'o1_r3']), ('solve_areas', ['o2_r0', 'o2_abr', 'o2_r1']),
                               ('solve_ebgp', ['eb_r1']), ('solve_ibgp', ['ib_r1', 'ib_r2', 'ib_r3']),
                               ('solve_policy', ['po_r1']), ('solve_fix', ['fix_r2', 'fix_r1']),
                               ('solve_unnumbered', ['un_r1']), ('solve_auth', ['au_r1'])):
            ops = _state_ops(ns, state)
            for r in routers:
                sessions = [c for c in _cmds(ops, 1, r) if c.startswith('vtysh -c "configure terminal"')]
                assert sessions, (state, r)
                for c in sessions:
                    _vtysh_commands(c)
            # only the machines of its own site are touched
            touched = {m for (_s, m) in ops}
            assert {lab.site_of(m) for m in touched} == {lab.site_of(routers[0])}, state
        fix = _state_ops(ns, 'solve_fix')
        assert _cmds(fix, 1, 'fix_r2')[0] == 'ip link set dev eth0 mtu 1500'
        assert _cmds(fix, 1, 'fix_r2')[-1] == 'vtysh -c "clear ipv6 ospf6 process"'
        ibgp = _cmds(_state_ops(ns, 'solve_ibgp'), 1, 'ib_r1')
        # first wait for the OSPFv3 routes to the two other loopbacks, then configure
        assert ibgp[0].startswith('i=0; until ip -6 route show') and str(ns.lo('ib_r3')) in ibgp[0]
        r1 = _vtysh_commands(ibgp[1])
        assert f"neighbor {ns.lo('ib_r3')} update-source lo" in r1 and f"neighbor {ns.lo('ib_r3')} next-hop-self" in r1
        po = _vtysh_commands(_cmds(_state_ops(ns, 'solve_policy'), 1, 'po_r1')[0])
        assert "set as-path prepend 65030 65030" in po and "set local-preference 200" in po

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = _state_ops(ns, 'final')
        parts = {}
        for state in SOLVE_STATE.values():
            for (step, machine), ops in _state_ops(ns, state).items():
                if step == 1:
                    parts.setdefault(machine, []).extend(str(op) for op in ops)
        for machine, cmds in parts.items():
            assert sorted(cmds) == sorted(_cmds(final, 1, machine)), machine
        assert any(c == f"sleep {lab.OSPF_WAIT}" for c in _cmds(final, 2, 'o1_r1'))


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
        assert len(elements) == 62 and len({str(e.title) for e in elements}) == 62

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
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0) == (21, 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (79, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('o1_passive', {'o1_passive'}),
        ('o1_cost', {'o1_cost'}),
        ('o2_ext', {'o2_external', 'o2_ping'}),
        ('o2_range', {'o2_range'}),
        ('o2_stub', {'o2_stub'}),
        ('eb_policy', {'eb_policy', 'eb_announce', 'eb_kernel', 'eb_ping'}),
        ('eb_network', {'eb_announce', 'eb_ping'}),
        ('ib_nhs', {'ib_next_hop_self', 'ib_r2_route', 'ib_ping'}),
        ('po_lp', {'po_local_pref'}),
        ('po_prepend', {'po_prepend'}),
        ('po_out', {'po_no_transit_a', 'po_no_transit_b'}),
        ('po_in', {'po_bogons'}),
        ('fix_mtu', {'fix_mtu', 'fix_adjacency', 'fix_ping'}),
        ('fix_rid', {'fix_router_id', 'fix_adjacency', 'fix_ping'}),
        ('fix_activate', {'fix_activate', 'fix_network', 'fix_ping'}),
        ('fix_network', {'fix_network', 'fix_ping'}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

    def test_stub_partly_scores(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'o2_stub'})
        assert _grades(grade)['o2_stub'] == (0, 3)

    def test_other_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir)
        cheat = dict(grade.get_cheat_answers('final'))
        # titles carry their section number: '1.1. Observations sur le site o1'
        forms = {_text(q.title).split('. ', 1)[1]: q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)}

        def regrade(title, **changes):
            q = forms[title]
            stored = cheat[q.question_hash]
            answers = dict(json.loads(stored) if isinstance(stored, str) else stored, **changes)
            changed = dict(cheat, **{q.question_hash: json.dumps(answers) if isinstance(stored, str) else answers})
            return _grades(_simulate_with_answers(lab, data, tmp_pub_dir, changed)[0])

        ll = ns.ll('o1_r2', 'o1_l12')
        exploded = IPv6Address(ll).exploded.upper()
        assert regrade("Observations sur le site o1", nexthop=f"{exploded}%eth1")['o1_q_nexthop'][0] == 1
        assert regrade("Observations sur le site o1", nexthop=str(ns.ll('o1_r3', 'o1_l13')))['o1_q_nexthop'][0] == 0
        assert regrade("Observations sur le site eb", afi_safi="2 / 1")['eb_q_afi_safi'][0] == 1
        assert regrade("Observations sur le site eb", afi_safi="1/1")['eb_q_afi_safi'][0] == 0
        assert regrade("Observations sur le site o2", range=str(data.nets6.o2_area1).upper())['o2_q_range'][0] == 1
        assert regrade("Observations sur le site o2", range=str(data.nets6.as_o2))['o2_q_range'][0] == 0
        assert regrade("Questions sur le site po", path_b="65120 65030 65030")['po_q_path_b'][0] == 0

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 6
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
        assert len(grade.get_cheat_answers('final')) == 6


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
        assert len(g1.get_questions_ordered()) == 15
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 15 and 'informations' not in with_fragment

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
            'ipv6-routing', 'ospfv3', 'frr-ospf6', 'mpbgp', 'frr-bgp', 'diagnostic', 'tools']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (str(data.nets6.instance), str(data.nets6.as_eb), data.au_key, 'Partie 1', 'o1_r1', 'po_ispa'):
            assert value not in informations, value

    def test_values_of_the_instance_in_the_first_question(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (str(data.nets6.instance), str(data.nets6.o1_l13), str(data.nets6.as_po_inet), data.au_key,
                      f"**{data.o1_cost}**", str(data.ips6.un_r2_lo.ip), '| `fix_r2` | `6.0.0.2` | — |',
                      '| `po_r1` | `5.0.0.1` | 65030 |'):
            assert value in first, value
        # the faults and the junk prefixes are for the instructor only; so are the link-locals asked
        everything = "\n".join(t for _w, t in _all_texts(g0, ns))
        for value in (str(data.nets6.junk_ula), str(data.nets6.junk_doc), f"mtu {data.fix_mtu}",
                      str(ns.ll('o1_r2', 'o1_l12')), str(ns.ll('eb_isp', 'eb_link'))):
            assert value not in everything, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['nexthop', 'hello_group', 'lsa', 'range', 'summary_lsa', 'stub_gets', 'afi_safi', 'attribute',
                         'nh_global', 'nh_ll', 'why_loopback', 'nh_before', 'why_r2', 'mesh10', 'decision', 'path_b',
                         'why_long', 'med', 'mtu_state', 'not_activated']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 15 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'ospfv3_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('ospfv3_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|zone|voisin|fournisseur|bouclage|'
                            r'domaine|chemin|externe)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips6)) + list(vars(data.nets6)) + list(vars(data.macs))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [field['name'] for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        names += [c for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []
                  for c in field.get('choices', [])]
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'po_ispa' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.-]+', n)]
        assert not bad, bad
