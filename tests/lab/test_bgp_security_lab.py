"""Offline tests of the BGP security lab (lab/sre/_DRAFT_misc/bgp-security.py).

No Docker, no FRR: a model of the five sites (``World``) holds what has been done, as a set of
features (``rov_cache``, ``pfx_c2``, ``bh_rtbh``...), and renders the outputs the grader reads in the
shapes captured live on Debian 13 (FRR 10.3 + stayrtr: the ``bgpops_*`` fixtures of
``tests/mock_data/frr``).  The behaviours follow what was seen live: without a connection to the
cache every route is ``notfound``, a route rejected as invalid comes back at rov_peer only after a
``clear bgp * soft in`` (the evaluation does it), a session over its maximum-prefix shows
``Idle (PfxCt)``, a GTSM session comes up only when both ends have it, the BLACKHOLE /32 is
installed towards the discard interface only through the next hop rewrite.  Covers the data, the
topology, the state ops, the two-pass grading contract (nothing done: 0; everything: 73 + 6 bonus
points; **each part alone gives exactly its points and everything but one part the rest**) and the
texts.
"""
import ast
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

from frr import parse_frr_config  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'bgp-security.py'

# what each part configures (the features of the model) and its points
PARTS = {
    'rov': {'rov_cache', 'rov_policy', 'rov_roa'},
    'pfx': {'pfx_c1', 'pfx_c2'},
    'gtsm': {'gtsm_isp', 'gtsm_par'},
    'bh': {'bh_rtbh'},
    'bfd': {'bfd'},
}
POINTS = {'rov': 25, 'pfx': 16, 'gtsm': 14, 'bh': 18, 'bfd': 6}
FORM_POINTS = {'rov': 5, 'pfx': 4, 'gtsm': 4, 'bh': 4}
SOLVE_STATE = {part: f"solve_{part}" for part in PARTS}
ALL_FEATURES = set().union(*PARTS.values())
CHOICE_ELEMENTS = {'rov_q_state', 'rov_q_why', 'rov_q_refresh', 'pfx_q_restore', 'pfx_q_warning', 'gtsm_q_oneside',
                   'bh_q_added', 'bh_q_scope'}
BONUS_ELEMENTS = ['bfd_conf', 'bfd_up', 'bfd_failover']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('bgp_security_lab_under_test', _LAB_PATH)
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


def _as_frr_config(lines):
    """vtysh session lines rewritten as an frr.conf (statements inside a block indented)."""
    out, depth = [], 0
    for line in lines:
        if line in ('exit', 'exit-address-family'):
            depth = max(0, depth - 1)
            out.append(' ' * depth + line)
            continue
        out.append(' ' * depth + line)
        if line.startswith(('router ', 'route-map ', 'address-family ', 'profile ')) or line in ('rpki', 'bfd'):
            depth += 1
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# a model of the sites: features -> what the grader reads
# ---------------------------------------------------------------------------


def _path(peer, aspath, best=False, rpki=None, locprf=None, community=None, multipath=False):
    """One path of ``show bgp ipv4 unicast json`` (whole table) or, with *community*, of a prefix."""
    e = {'valid': True, 'pathFrom': 'external', 'peerId': str(peer), 'path': aspath, 'origin': 'IGP',
         'nexthops': [{'ip': str(peer), 'afi': 'ipv4', 'used': True}]}
    if best:
        e['bestpath'] = True
    if multipath:
        e['multipath'] = True
    if locprf is not None:
        e['locPrf'] = locprf
    if rpki:
        e[{'valid': 'rpkiValid', 'invalid': 'rpkiInvalid', 'notfound': 'rpkiNotFound'}[rpki]] = True
    return e


def _local(prefix):
    return {'valid': True, 'bestpath': True, 'pathFrom': 'external', 'peerId': '(unspec)', 'path': '',
            'weight': 32768, 'nexthops': [{'ip': '0.0.0.0', 'used': True}]}


def _prefix_path(peer, aspath, rpki=None, community=None):
    """One path of ``show bgp ipv4 unicast P json``."""
    e = {'aspath': {'string': aspath}, 'valid': True, 'bestpath': {'overall': True},
         'nexthops': [{'ip': str(peer), 'accessible': True, 'used': True}],
         'peer': {'peerId': str(peer), 'type': 'external'}}
    if rpki:
        e['rpkiValidationState'] = {'notfound': 'not found'}.get(rpki, rpki)
    if community:
        e['community'] = {'string': " ".join(community), 'list': community}
    return e


def _route(prefix, gateways, dev='eth0'):
    dst = str(prefix)
    dst = dst[:-3] if dst.endswith('/32') else dst
    if len(gateways) > 1:
        return {'dst': dst, 'protocol': 'bgp', 'metric': 20, 'flags': [],
                'nexthops': [{'gateway': str(g), 'dev': dev, 'weight': 1, 'flags': []} for g in gateways]}
    return {'dst': dst, 'gateway': str(gateways[0]), 'dev': dev, 'protocol': 'bgp', 'metric': 20, 'flags': []}


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    @property
    def rov_filters(self):
        """The ROV policy works only with the cache connected (else every route is notfound)."""
        return {'rov_cache', 'rov_policy'} <= self.f

    # -- running configurations -------------------------------------------------------

    def running_config(self, r):
        ns, f = self.ns, self.f
        lines = ns._frr_conf(r)
        extra = []
        if r == 'rov_r1':
            solution = ns.solution_rov()['rov_r1']
            if 'rov_cache' in f:
                extra += solution[:3]
            if 'rov_policy' in f:
                extra += solution[3:]
        elif r == 'pfx_r1':
            head, c1, c2, tail = (lambda s: (s[:2], s[2], s[3], s[4:]))(ns.solution_pfx()['pfx_r1'])
            if f & {'pfx_c1', 'pfx_c2'}:
                extra += head + [c1] * ('pfx_c1' in f) + [c2] * ('pfx_c2' in f) + tail
        elif r == 'gtsm_r1':
            s = ns.solution_gtsm()['gtsm_r1']
            if f & {'gtsm_isp', 'gtsm_par'}:
                extra += [s[0]] + [s[1]] * ('gtsm_isp' in f) + s[2:4] * ('gtsm_par' in f) + [s[4]]
        elif r == 'bh_r1':
            if 'bh_rtbh' in f:
                extra += ns.solution_bh()['bh_r1']
        elif r == 'bfd_r1':
            if 'bfd' in f:
                extra += ns.solution_bfd()['bfd_r1']
        return lines + (_as_frr_config(extra) if extra else '')

    # -- rov ---------------------------------------------------------------------------

    def rov_routes(self):
        ns, d, addr, net = self.ns, self.d, self.ns.addr, self.ns.net
        isp1, isp2, peer = addr('rov_isp1', 'rov_l1'), addr('rov_isp2', 'rov_l2'), addr('rov_peer', 'rov_l3')
        cache, filters = 'rov_cache' in self.f, self.rov_filters
        state = (lambda s: s if cache else 'notfound')
        lp = (lambda s: 200 if filters and s == 'valid' else None)
        p2 = "65020 65020 65020"
        routes = {str(net('rov_own')): [_local(net('rov_own'))], str(net('rov_te')): [_local(net('rov_te'))],
                  str(net('rov_v1')): [_path(isp1, "65010", True, state('valid'), lp('valid'))],
                  str(net('rov_n1')): [_path(isp1, "65010", True, state('notfound'))],
                  str(net('rov_m')): [_path(isp2, p2, True, state('valid'), lp('valid'))],
                  str(net('rov_v2')): [_path(isp2, p2, True, state('valid'), lp('valid'))],
                  str(net('rov_p')): [_path(peer, "65030", True, state('notfound'))]}
        h_legit = _path(isp2, p2, filters, state('valid'), lp('valid'))
        routes[str(net('rov_h'))] = [h_legit] if filters else [_path(isp1, "65010", True, state('invalid')), h_legit]
        if not filters:
            routes[str(net('rov_m24'))] = [_path(isp1, "65010 65020", True, state('invalid'))]
        return routes

    def rov_kernel(self):
        addr, net = self.ns.addr, self.ns.net
        isp1, isp2 = addr('rov_isp1', 'rov_l1'), addr('rov_isp2', 'rov_l2')
        routes = [_route(net('rov_m'), [isp2], 'eth1'), _route(net('rov_v2'), [isp2], 'eth1'),
                  _route(net('rov_v1'), [isp1]), _route(net('rov_n1'), [isp1])]
        if self.rov_filters:
            routes.append(_route(net('rov_h'), [isp2], 'eth1'))
        else:
            routes += [_route(net('rov_h'), [isp1]), _route(net('rov_m24'), [isp1])]
        return routes

    def rov_peer_prefix(self, prefix):
        net, r1 = self.ns.net, self.ns.addr('rov_r1', 'rov_l3')
        if str(prefix) == str(net('rov_own')):
            return {'prefix': str(prefix), 'paths': [_prefix_path(r1, str(self.d.our_as), 'valid')]}
        if str(prefix) == str(net('rov_te')) and 'rov_roa' in self.f:
            return {'prefix': str(prefix), 'paths': [_prefix_path(r1, str(self.d.our_as), 'valid')]}
        return {}

    # -- pfx, gtsm ------------------------------------------------------------------------

    def summary(self, r):
        addr, f = self.ns.addr, self.f
        peers = {}

        def peer(ip, asn, up, pfx, pfxct=False):
            if pfxct:
                peers[str(ip)] = {'remoteAs': asn, 'state': 'Idle (PfxCt)', 'peerState': 'PfxCt', 'pfxRcd': 0}
            elif up:
                peers[str(ip)] = {'remoteAs': asn, 'state': 'Established', 'peerState': 'OK', 'pfxRcd': pfx}
            else:
                peers[str(ip)] = {'remoteAs': asn, 'state': 'Idle', 'peerState': 'OK', 'pfxRcd': 0}

        if r == 'pfx_r1':
            peer(addr('pfx_isp', 'pfx_l1'), 65040, True, 1)
            peer(addr('pfx_c1', 'pfx_l2'), 65041, True, 4)
            peer(addr('pfx_c2', 'pfx_l3'), 65042, True, 2 + self.lab.LEAK_COUNT, pfxct='pfx_c2' in f)
        elif r == 'gtsm_r1':
            peer(addr('gtsm_isp', 'gtsm_l1'), 65050, 'gtsm_isp' in f, 1)
            peer(self.ns.lo('gtsm_par'), 65051, 'gtsm_par' in f, 1)
        else:
            raise AssertionError(r)
        return {'routerId': str(self.ns.lo(r)), 'as': self.d.our_as, 'peers': peers}

    def pfx_isp_routes(self):
        lab, net, r1 = self.lab, self.ns.net, self.ns.addr('pfx_r1', 'pfx_l1')
        routes = {str(net(p)): [_path(r1, f"{self.d.our_as} 65041", True)] for p in lab.PFX_C1}
        if 'pfx_c2' not in self.f:
            for p in [net(x) for x in lab.PFX_C2] + lab.leaked_prefixes(net('pub')):
                routes[str(p)] = [_path(r1, f"{self.d.our_as} 65042", True)]
        routes[str(net('pfx_own'))] = [_path(r1, str(self.d.our_as), True)]
        routes[str(net('pfx_isp'))] = [_local(net('pfx_isp'))]
        return routes

    def gtsm_routes(self):
        net, addr, f = self.ns.net, self.ns.addr, self.f
        routes = {str(net('gtsm_own')): [_local(net('gtsm_own'))]}
        if 'gtsm_isp' in f:
            routes[str(net('gtsm_isp'))] = [_path(addr('gtsm_isp', 'gtsm_l1'), "65050", True)]
        if 'gtsm_par' in f:
            routes[str(net('gtsm_par'))] = [_path(self.ns.lo('gtsm_par'), "65051", True)]
        return routes

    # -- bh -------------------------------------------------------------------------------

    def bh_routes(self, r):
        d, net, addr = self.d, self.ns.net, self.ns.addr
        victim = f"{d.ips.bh_srv_victim.ip}/32"
        if r == 'bh_r1':
            routes = {str(net('bh_own')): [_local(net('bh_own'))],
                      str(net('bh_cust')): [_path(addr('bh_cust', 'bh_l2'), "65061", True)],
                      str(net('bh_isp')): [_path(addr('bh_isp', 'bh_l1'), "65060", True)]}
            if 'bh_rtbh' in self.f:
                routes[victim] = [_path(self.lab.DISCARD_NEXT_HOP, "65061", True)]
            return routes
        r1 = addr('bh_r1', 'bh_l1')
        return {str(net('bh_isp')): [_local(net('bh_isp'))],
                str(net('bh_own')): [_path(r1, str(d.our_as), True)],
                str(net('bh_cust')): [_path(r1, f"{d.our_as} 65061", True)]}

    def bh_victim_prefix(self):
        if 'bh_rtbh' not in self.f:
            return {}
        return {'prefix': f"{self.d.ips.bh_srv_victim.ip}/32",
                'paths': [_prefix_path(self.lab.DISCARD_NEXT_HOP, "65061", community=['blackhole', 'noExport'])]}

    def bh_kernel(self):
        net, addr = self.ns.net, self.ns.addr
        routes = [_route(net('bh_cust'), [addr('bh_cust', 'bh_l2')], 'eth1'),
                  _route(net('bh_isp'), [addr('bh_isp', 'bh_l1')])]
        if 'bh_rtbh' in self.f:
            routes.append(_route(f"{self.d.ips.bh_srv_victim.ip}/32", [self.lab.DISCARD_NEXT_HOP],
                                 self.lab.DISCARD_IFACE))
        return routes

    # -- pings ----------------------------------------------------------------------------

    def ping_ok(self, src, dest):
        d = self.d
        if src == 'bh_isp':
            if dest == str(d.ips.bh_srv_victim.ip):
                return 'bh_rtbh' not in self.f
            return dest == str(d.ips.bh_srv_control.ip)
        if src == 'bh_r1':
            return dest == str(self.ns.host('bh_isp'))
        raise AssertionError((src, dest))

    def bfd_pings(self):
        """bfd_r1's ping series during the cut: 0.3 s lost with BFD, the whole cut without."""
        lab = self.lab
        lost = 6 if 'bfd' in self.f else int(lab.CUT_SECONDS / lab.PING_INTERVAL)
        seqs = [i for i in range(1, lab.PING_COUNT + 1) if not 21 <= i < 21 + lost]
        return "".join(f"64 bytes from x: icmp_seq={i} ttl=63 time=0.1 ms\n" for i in seqs)

    # -- every command ------------------------------------------------------------------

    def output(self, machine, command, step):
        ns, d, net = self.ns, self.d, self.ns.net
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'vtysh -c "show rpki cache-connection json"':
            if 'rov_cache' in self.f:
                return json.dumps({'connectedGroup': 1, 'connections': [
                    {'mode': 'tcp', 'host': str(ns.rpki_addr()), 'port': str(self.lab.RTR_PORT), 'preference': 1,
                     'state': 'connected'}]}), 0
            return json.dumps({'error': 'No connection to RPKI cache server.'}), 0
        if command == 'vtysh -c "show rpki prefix-table json"':
            if 'rov_cache' not in self.f:
                return json.dumps({'error': 'No Connection to RPKI cache server.'}), 0
            prefixes = [{'prefix': r['prefix'].split('/')[0], 'prefixLenMin': int(r['prefix'].split('/')[1]),
                         'prefixLenMax': r['maxLength'], 'asn': r['asn']}
                        for r in ns.roas(fixed='rov_roa' in self.f)]
            return json.dumps({'prefixes': prefixes, 'ipv4PrefixCount': len(prefixes)}), 0
        if command == 'vtysh -c "show bgp ipv4 unicast json"':
            routes = {'rov_r1': self.rov_routes, 'pfx_isp': self.pfx_isp_routes, 'gtsm_r1': self.gtsm_routes,
                      'bh_r1': lambda: self.bh_routes('bh_r1'), 'bh_isp': lambda: self.bh_routes('bh_isp')}[machine]()
            return json.dumps({'routerId': '1.1.1.1', 'routes': routes}), 0
        if command == 'vtysh -c "show bgp ipv4 unicast summary json"':
            return json.dumps(self.summary(machine)), 0
        m = re.fullmatch(r'vtysh -c "show bgp ipv4 unicast (\S+) json"', command)
        if m:
            if machine == 'rov_peer':
                return json.dumps(self.rov_peer_prefix(m.group(1))), 0
            if machine == 'bh_r1':
                return json.dumps(self.bh_victim_prefix()), 0
        if command == 'ip -j route':
            return json.dumps({'rov_r1': self.rov_kernel, 'bh_r1': self.bh_kernel}[machine]()), 0
        if command == 'vtysh -c "show bfd peers json"':
            if 'bfd' in self.f:
                return json.dumps([{'peer': str(ns.addr('bfd_isp1', 'bfd_l1')), 'status': 'up',
                                    'receive-interval': d.bfd_interval, 'transmit-interval': d.bfd_interval,
                                    'detect-multiplier': d.bfd_multiplier}]), 0
            return "[]", 0
        if command.startswith(('nft ', 'sleep 1; echo', "vtysh -c 'clear bgp * soft in'", 'cat /etc/stayrtr')):
            return "", 0
        if command.startswith('ping -I') and machine == 'bfd_r1':
            return self.bfd_pings(), 0
        m = re.fullmatch(r'ping -c 3 -w 5(?: -I \S+)? (\S+)', command)
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
        again = lab.Data.from_dict(json.loads(json.dumps(data.to_dict())))
        assert again.to_dict() == data.to_dict()

    def test_addressing(self, lab, data):
        assert data.nets.instance.subnet_of(IPv4Network('10.0.0.0/8'))
        assert data.nets.pub.subnet_of(IPv4Network('172.16.0.0/12'))
        for name in lab.PUB:
            assert getattr(data.nets, name).subnet_of(data.nets.pub), name
        assert data.nets.rov_te.subnet_of(data.nets.rov_own) and data.nets.rov_m24.subnet_of(data.nets.rov_m)
        for net, (a, b) in lab.LINKS.items():
            network = getattr(data.nets, net)
            assert network.prefixlen == 30
            assert getattr(data.ips, f"{a}_{net}").ip in network and getattr(data.ips, f"{b}_{net}").ip in network
        for p in lab.leaked_prefixes(data.nets.pub):
            assert p.subnet_of(data.nets.pub) and not any(p.overlaps(getattr(data.nets, n)) for n in lab.PUB)
        assert data.ips.bh_srv_victim.ip != data.ips.bh_srv_control.ip
        assert data.ips.bh_srv_victim.ip in data.nets.bh_cust

    def test_values(self, lab, data):
        assert 64600 <= data.our_as <= 64999 and data.our_as not in lab.EXT_AS.values()
        assert data.pfx_limit in lab.PFX_LIMITS and data.pfx_limit < 2 + lab.LEAK_COUNT
        assert data.pfx_threshold in lab.PFX_THRESHOLDS and data.pfx_threshold != 75
        assert data.bfd_interval in lab.BFD_INTERVALS and data.bfd_multiplier in lab.BFD_MULTIPLIERS


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 21
        specs = lab.NetScheme._machine_specs
        assert {m for m, s in specs.items() if s.get('allow_connection', True)} == set(lab.TERMINALS)
        assert all(specs[m]['image'].split('/')[-1].startswith('netdev13:') for m in lab.FRR_ROUTERS)

    def test_sites_are_islands(self, lab):
        for net, members in lab._TOPOLOGY.items():
            assert {lab.site_of(m) for m in members} == {lab.site_of(net)}, net

    def test_net_config_and_hosts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.net_config['bh_srv'][0][0] == [data.ips.bh_srv_victim, data.ips.bh_srv_control]
        assert ns.iface_addr('bfd_r1', 'bfd_l1s') == data.ips.bfd_r1_bfd_l1
        assert f"{data.ips.gtsm_par_lo.ip}\tgtsm_par-lo" in ns.hosts_content
        # gtsm_mid routes between the loopbacks
        assert [str(n) for n, _gw in ns.net_config['gtsm_mid'][0][1]] == [f"{data.ips.gtsm_r1_lo.ip}/32"]

    def test_weight(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.get_weight() == pytest.approx(116)


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        # the validator starts at step 1, FRR at step 2 (a failed first connection waits 10 minutes)
        stayrtr = [c for c in _cmds(ops, 1, 'rov_rpki') if 'setsid -f stayrtr' in c]
        assert len(stayrtr) == 1 and f'-bind :{lab.RTR_PORT}' in stayrtr[0] and '-checktime=false' in stayrtr[0]
        assert json.loads(_files(ops, 1, 'rov_rpki')[lab.ROA_FILE]) == {'roas': ns.roas()}
        for r in lab.FRR_ROUTERS:
            assert 'systemctl start frr' in _cmds(ops, 2, r), r
            files = _files(ops, 2, r)
            assert ('-M rpki' in files['/etc/frr/daemons']) == (r in lab.RPKI_ROUTERS), r
            assert ('bfdd=yes' in files['/etc/frr/daemons']) == (lab.site_of(r) == 'bfd'), r
        assert any(lab.DISCARD_IFACE in c and 'dummy' in c for c in _cmds(ops, 1, 'bh_r1'))
        assert not any('stayrtr' in c for (s, m), _ in ops.items() for c in _cmds(ops, s, m) if m != 'rov_rpki')

    def test_given_configurations(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        cfg = {r: parse_frr_config(ns._frr_conf(r)) for r in lab.FRR_ROUTERS}
        # rov: the forged origin of the sub-prefix, the prepend of the legitimate provider, the ROA mistake
        assert ['ip address prefix-list FORGED'] == cfg['rov_isp1']['route_maps']['OUT'][0]['match']
        assert cfg['rov_isp1']['route_maps']['OUT'][0]['set'] == ['as-path prepend 65020']
        assert cfg['rov_isp2']['route_maps']['OUT'][0]['set'] == ['as-path prepend 65020 65020']
        assert cfg['rov_peer']['rpki']['cache_servers'][0]['host'] == str(ns.rpki_addr())
        assert not cfg['rov_r1']['rpki']['present']
        assert [r for r in ns.roas() if r['asn'] == data.our_as] == [
            {'prefix': str(data.nets.rov_own), 'maxLength': 22, 'asn': data.our_as}]
        # pfx: the leak
        assert len([s for s in cfg['pfx_c2']['static_routes']]) == 2 + lab.LEAK_COUNT
        assert 'static' in cfg['pfx_c2']['router_bgp']['redistribute']
        # gtsm: the providers demand it, gtsm_r1 starts with ebgp-multihop
        assert cfg['gtsm_isp']['router_bgp']['neighbors'][str(ns.addr('gtsm_r1', 'gtsm_l1'))]['ttl_security'] == 1
        assert cfg['gtsm_par']['router_bgp']['neighbors'][str(ns.lo('gtsm_r1'))]['ttl_security'] == 2
        par = cfg['gtsm_r1']['router_bgp']['neighbors'][str(ns.lo('gtsm_par'))]
        assert par['ebgp_multihop'] == 2 and par['ttl_security'] is None
        # bh: the customer tags its two requests; bh_r1 accepts only the /24
        assert cfg['bh_cust']['route_maps']['TO-PROVIDER'][0]['set'] == ['community blackhole']
        assert cfg['bh_r1']['prefix_lists']['CUSTOMER'][0]['prefix'] == str(data.nets.bh_cust)
        # bfd: the profile exists on bfd_isp1 but is not applied (FRR keeps BGP Idle while BFD is down)
        assert cfg['bfd_isp1']['bfd']['profiles'][lab.BFD_PROFILE]
        assert not any(n['bfd'] for n in cfg['bfd_isp1']['router_bgp']['neighbors'].values())

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        rov = parse_frr_config(ns._frr_conf('rov_r1') + _as_frr_config(ns.solution_rov()['rov_r1']))
        assert rov['rpki']['cache_servers'] == [{'mode': 'tcp', 'host': str(ns.rpki_addr()), 'port': lab.RTR_PORT,
                                                  'preference': 1}]
        assert [e['match'] for e in rov['route_maps']['RPKI-IN']] == [['rpki invalid'], ['rpki valid'], []]
        pfx = parse_frr_config(ns._frr_conf('pfx_r1') + _as_frr_config(ns.solution_pfx()['pfx_r1']))
        for peer in (ns.addr('pfx_c1', 'pfx_l2'), ns.addr('pfx_c2', 'pfx_l3')):
            assert pfx['router_bgp']['neighbors'][str(peer)]['maximum_prefix'] == {
                'limit': data.pfx_limit, 'threshold': data.pfx_threshold, 'warning_only': False, 'restart': None,
                'force': False}
        gtsm = parse_frr_config(ns._frr_conf('gtsm_r1') + _as_frr_config(ns.solution_gtsm()['gtsm_r1']))
        par = gtsm['router_bgp']['neighbors'][str(ns.lo('gtsm_par'))]
        assert par['ttl_security'] == 2 and par['ebgp_multihop'] is None
        bh = parse_frr_config(ns._frr_conf('bh_r1') + _as_frr_config(ns.solution_bh()['bh_r1']))
        seq5 = bh['route_maps']['FROM-CUSTOMER'][-1]
        assert seq5['seq'] == 5 and f"ip next-hop {lab.DISCARD_NEXT_HOP}" in seq5['set']
        assert json.loads(ns.roa_file(fixed=True))['roas'][-1]['maxLength'] == 24

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())

        def commands(state):
            ops = _state_ops(ns, state)
            return sorted(c for (s, m), lst in ops.items() for c in _cmds(ops, s, m) if not c.startswith('sleep'))

        union = sorted(c for part in PARTS for c in commands(SOLVE_STATE[part]))
        assert commands('final') == union


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 73
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len(elements) == 43 and len({str(e.title) for e in elements}) == 43

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (73, 6)
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
        for _ in range(8):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (73, 6)
            assert _totals(_simulate(lab, d, tmp_pub_dir, features=set(), answers=None)[0]) == (0, 0)

    def test_scopes_and_bonus(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for e in grade.get_grade_list():
            expected = params.EXO_EVAL_SCOPE if str(e.title) in CHOICE_ELEMENTS else params.BOTH_EVAL_SCOPE
            assert e.scope == expected, e.title
        assert [str(e.title) for e in grade.get_grade_list() if e.bonus] == BONUS_ELEMENTS

    def test_answers_only(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _totals(grade) == (sum(FORM_POINTS.values()), 0) == (17, 0)

    @pytest.mark.parametrize('features, lost', [
        ({'rov_policy', 'rov_roa'}, {'rov_cache_conf', 'rov_cache_up', 'rov_vrps', 'rov_hijack', 'rov_subprefix',
                                     'rov_kernel', 'rov_notfound', 'rov_valid_pref'}),
        ({'rov_cache', 'rov_roa'}, {'rov_hijack', 'rov_subprefix', 'rov_kernel', 'rov_notfound', 'rov_valid_pref'}),
        ({'rov_cache', 'rov_policy'}, {'rov_roa'}),
        ({'pfx_c1'}, {'pfx_conf_c2', 'pfx_c2_down', 'pfx_leak'}),
        ({'pfx_c2'}, {'pfx_conf_c1', 'pfx_c1_up'}),
        ({'gtsm_isp'}, {'gtsm_par_conf', 'gtsm_par_up'}),
        ({'gtsm_par'}, {'gtsm_isp_conf', 'gtsm_isp_up'}),
    ])
    def test_half_done(self, lab, data, tmp_pub_dir, features, lost):
        part = next(p for p, fs in PARTS.items() if features <= fs)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=features, answers=SOLVE_STATE[part])
        assert _lost(grade) & {e for e in _grades(grade) if e.startswith(part + '_')} == lost

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
        assert grade.get_cheat_answers('solve_bfd') is None


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _tr_literals():
    import check_sre_translations
    return check_sre_translations.get_tr_strings(ast.parse(_LAB_PATH.read_text()))


def _instructor_literals():
    literals = []
    for node in ast.walk(ast.parse(_LAB_PATH.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'instructor':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, 'id', '') == 'tr' and sub.args \
                        and isinstance(sub.args[0], ast.Constant):
                    literals.append(sub.args[0].value)
    return literals


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
            'threats', 'rpki', 'maxprefix', 'gtsm', 'rtbh', 'bfd', 'frr', 'diagnostic']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (str(data.nets.pub.network_address), str(data.our_as), 'Partie 1', 'rov_r1', 'bh_cust'):
            assert not _mentions(informations, value), value
        # ... whatever the instance: no example of the course is an AS number the students may draw
        # (the check above failed one time in four hundred while an example said 64999)
        for number in range(64600, 65000):
            assert not _mentions(informations, str(number)), number

    def test_values_of_the_instance_in_the_questions(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        questions = [_text(q.description) for q in g0.get_questions_ordered()]
        first = questions[0]
        for value in (f"**AS {data.our_as}**", str(data.nets.pub), f"`gtsm_par` `{data.ips.gtsm_par_lo.ip}`"):
            assert value in first, value
        everything = "\n".join(questions)
        for value in (f"**{data.pfx_limit}**", f"alerte à {data.pfx_threshold} %", f"**{data.bfd_interval}**",
                      str(data.nets.rov_m24), str(data.ips.bh_srv_victim.ip)):
            assert value in everything, value
        # the solutions are for the instructor only
        for value in ('match rpki invalid', 'ttl-security hops 2', f'set ip next-hop {lab.DISCARD_NEXT_HOP}'):
            assert value not in everything, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['port', 'origin', 'state', 'why', 'refresh', 'state', 'count', 'restore', 'warning',
                         'minttl', 'sent', 'default', 'oneside', 'community', 'rfc', 'added', 'scope']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == len(_instructor_literals()) == 10 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        assert b'**For the instructor.**' not in result.data and b'instructor(' not in result.data
        stripped = tmp_path / 'bgp_security_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('bgp_security_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the English of the instructor texts goes with them, the rest stays
        kept = module._TRANSLATIONS['en']
        assert not set(kept) & set(_instructor_literals())
        assert len(kept) == len(lab._TRANSLATIONS['en']) - len(set(_instructor_literals()))
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (73, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_translations(self, lab, data, tmp_pub_dir):
        """The texts are French with every one translated in _TRANSLATIONS['en'] (the markup kept: checked for
        every lab of the directory by test_draft_misc_translations.py), the instructor texts included."""
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == _tr_literals() and all(english.values())
        assert set(_instructor_literals()) <= set(english)
        assert sum(v.lstrip().startswith(('**Solution.**', '**For the instructor.**')) for v in english.values()) == 10
        assert _text(lab.title, 'en') == "BGP: securing sessions and announcements (RPKI, maximum-prefix, GTSM, RTBH)"
        assert _text(lab.NetScheme.solve_rov._sre_state_description, 'en') == "Part 1: solution (RPKI)"
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en) and fr != en, _text(q.title)
            assert '**Solution.**' in en or '**For the instructor.**' in en, _text(q.title)
            # the values built in code read in the language of the text (the site table, the vtysh blocks)
            assert ' sans terminal' not in en and '` :\n' not in en, _text(q.title)
            assert "{'" not in en and not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", en), _text(q.title)
            markdown_to_html(en, show_instructor=True)
        organisation = _text(g1.get_questions_ordered()[0].description, 'en')
        assert f"`bh_srv` (`{data.ips.bh_srv_victim.ip}` and `{data.ips.bh_srv_control.ip}`)" in organisation
        assert "| 1 — route origin validation (RPKI) | `rov_*` |" in organisation
        solution = _text(g1.get_questions_ordered()[1].description, 'fr')
        assert "`rov_r1` :\n\n```\nconfigure terminal" in solution
        assert "`rov_r1`:\n\n```\nconfigure terminal" in _text(g1.get_questions_ordered()[1].description, 'en')

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|voisin|bouclage|chemin|fuite|'
                            r'client|fournisseur|victime)', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_rov' in names and 'rov_r1' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
