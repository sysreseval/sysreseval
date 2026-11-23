"""Offline tests of the BGP scaling lab (lab/sre/_DRAFT_misc/bgp-scaling.py).

No Docker, no FRR: a model of the five sites (``World``) holds what has been done, as a set of
features (``ne_te``, ``mp_hash``, ``cf_r1``...), and renders the outputs the grader reads in the
shapes captured live on Debian 13 (FRR 10.3: the ``bgpops_*`` fixtures of ``tests/mock_data/frr``).
The behaviours follow what was seen live: a community set by an outbound route-map reaches the peer,
which applies it; FRR load-shares over the two sessions with the same AS by default and adds the
other provider only with ``multipath-relax``; the kernel hashes on the addresses unless
``fib_multipath_hash_policy`` is 1; a confederation hides its member ASes outside, keeps the
local-preference inside, stops ``no-export`` at its border and ``local-AS`` at the member AS; a
suppressed route is not advertised.  Covers the data, the topology, the state ops, the two-pass
grading contract (nothing done: 0; everything: 68 + 6 bonus points; **each part alone gives exactly
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

from frr import parse_frr_config  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'bgp-scaling.py'

PARTS = {
    'ne': {'ne_te', 'ne_c1'},
    'mp': {'mp_relax', 'mp_hash'},
    'cf': {'cf_r1', 'cf_r2'},
    'dmp': {'dmp'},
    'gs': {'gs_neighbor', 'gs_out_tag'},
}
POINTS = {'ne': 16, 'mp': 14, 'cf': 24, 'dmp': 14, 'gs': 6}
FORM_POINTS = {'ne': 4, 'mp': 4, 'cf': 3, 'dmp': 4}
SOLVE_STATE = {part: f"solve_{part}" for part in PARTS}
ALL_FEATURES = set().union(*PARTS.values())
CHOICE_ELEMENTS = {'ne_q_c3', 'mp_q_relax', 'mp_q_hash', 'mp_q_default', 'cf_q_attr', 'cf_q_nexthop', 'dmp_q_code',
                   'dmp_q_why'}
BONUS_ELEMENTS = ['gs_conf', 'gs_out', 'gs_in', 'gs_session']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('bgp_scaling_lab_under_test', _LAB_PATH)
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
    out, depth = [], 0
    for line in lines:
        if line in ('exit', 'exit-address-family'):
            depth = max(0, depth - 1)
            out.append(' ' * depth + line)
            continue
        out.append(' ' * depth + line)
        if line.startswith(('router ', 'route-map ', 'address-family ')):
            depth += 1
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# a model of the sites
# ---------------------------------------------------------------------------


def _path(peer, aspath, best=False, locprf=None, multipath=False, damped=False):
    """One path of ``show bgp ipv4 unicast json`` (whole table)."""
    e = {'valid': True, 'pathFrom': 'external', 'peerId': str(peer), 'path': aspath, 'origin': 'IGP',
         'nexthops': [{'ip': str(peer), 'afi': 'ipv4', 'used': True}]}
    if best:
        e['bestpath'] = True
    if multipath:
        e['multipath'] = True
    if damped:
        e['damped'] = True
    if locprf is not None:
        e['locPrf'] = locprf
    return e


def _local():
    return {'valid': True, 'bestpath': True, 'peerId': '(unspec)', 'path': '', 'weight': 32768,
            'nexthops': [{'ip': '0.0.0.0', 'used': True}]}


def _prefix_path(peer, aspath, best=True, community=None, locprf=None, damped=False, peer_type='external'):
    """One path of ``show bgp ipv4 unicast P json``."""
    e = {'aspath': {'string': aspath}, 'valid': True, 'bestpath': {'overall': best},
         'nexthops': [{'ip': str(peer), 'accessible': True, 'used': True}],
         'peer': {'peerId': str(peer), 'type': peer_type}}
    if community:
        e['community'] = {'string': " ".join(community), 'list': community}
    if locprf is not None:
        e['locPrf'] = locprf
    if damped:
        e['dampeningSuppressed'] = True
    return e


def _route(prefix, gateways, dev='eth0'):
    dst = str(prefix)
    if len(gateways) > 1:
        return {'dst': dst, 'protocol': 'bgp', 'metric': 20, 'flags': [],
                'nexthops': [{'gateway': str(g), 'dev': dev, 'weight': 1, 'flags': []} for g in gateways]}
    return {'dst': dst, 'gateway': str(gateways[0]), 'dev': dev, 'protocol': 'bgp', 'metric': 20, 'flags': []}


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)

    @property
    def confed(self):
        return {'cf_r1', 'cf_r2'} <= self.f

    def running_config(self, r):
        ns, f = self.ns, self.f
        extra = []
        if r == 'ne_r1' and f & PARTS['ne']:
            extra = ns.solution_ne()['ne_r1']
        elif r == 'mp_r1' and 'mp_relax' in f:
            extra = ns.solution_mp()['mp_r1']
        elif r in ('cf_r1', 'cf_r2') and r in f:
            extra = ns.solution_cf()[r]
        elif r == 'dmp_r1' and 'dmp' in f:
            extra = ns.solution_dmp()['dmp_r1']
        elif r == 'gs_r1':
            s = ns.solution_gs()['gs_r1']
            if 'gs_out_tag' in f:
                extra += s[:3] + [s[3], s[5], s[6], s[7], s[8]]
            if 'gs_neighbor' in f:
                extra += [s[3], s[4], s[8]]
        return ns._frr_conf(r) + (_as_frr_config(extra) if extra else '')

    # -- ne -----------------------------------------------------------------------------

    def ne_isp_prefix(self, prefix):
        net, f, r1 = self.ns.net, self.f, self.ns.addr('ne_r1', 'ne_l1')
        our = str(self.d.our_as)
        if prefix in (str(net('ne_te1')), str(net('ne_te2'))):
            return {'prefix': prefix, 'paths': [_prefix_path(r1, our, community=['noExport'])]} if 'ne_te' in f else {}
        if prefix == str(net('ne_c1')):
            community = ['noExport'] if 'ne_c1' in f else None
            return {'prefix': prefix, 'paths': [_prefix_path(r1, f"{our} 65112", community=community)]}
        raise AssertionError(prefix)

    def ne_routes(self, r):
        net, f, d = self.ns.net, self.f, self.d
        our = str(d.our_as)
        if r == 'ne_isp':
            r1, far = self.ns.addr('ne_r1', 'ne_l1'), self.ns.addr('ne_far', 'ne_l3')
            routes = {str(net('ne_own')): [_path(r1, our, True)], str(net('ne_c1')): [_path(r1, f"{our} 65112", True)],
                      str(net('ne_isp')): [_local()], str(net('ne_far')): [_path(far, "65111", True)]}
            if 'ne_te' in f:
                routes.update({str(net(p)): [_path(r1, our, True)] for p in ('ne_te1', 'ne_te2')})
            return routes
        isp = self.ns.addr('ne_isp', 'ne_l3')
        routes = {str(net('ne_own')): [_path(isp, f"65110 {our}", True)], str(net('ne_isp')): [_path(isp, "65110", True)],
                  str(net('ne_far')): [_local()]}
        if 'ne_c1' not in f:
            routes[str(net('ne_c1'))] = [_path(isp, f"65110 {our} 65112", True)]
        return routes

    # -- mp -----------------------------------------------------------------------------

    def mp_peers(self):
        addr = self.ns.addr
        return addr('mp_isp1', 'mp_l1a'), addr('mp_isp1', 'mp_l1b'), addr('mp_isp2', 'mp_l2')

    def mp_routes(self):
        net, (a, b, c) = self.ns.net, self.mp_peers()
        relax = 'mp_relax' in self.f
        return {str(net('mp_q')): [_path(a, "65120", True), _path(b, "65120", multipath=True)],
                str(net('mp_p')): [_path(a, "65120", True), _path(b, "65120", multipath=True),
                                   _path(c, "65121", multipath=relax)],
                str(net('mp_own')): [_local()]}

    def mp_kernel(self):
        net, (a, b, c) = self.ns.net, self.mp_peers()
        p = [a, b] + ([c] if 'mp_relax' in self.f else [])
        return [_route(net('mp_q'), [a, b]), _route(net('mp_p'), p)]

    def mp_counters(self, step):
        if step == 1:
            return [100, 100, 100]
        relax, hashing = 'mp_relax' in self.f, 'mp_hash' in self.f
        if relax and hashing:
            delta = [21, 19, 20]
        elif hashing:
            delta = [31, 29, 0]
        else:
            delta = [60, 0, 0]
        return [100 + x for x in delta]

    # -- cf -----------------------------------------------------------------------------

    def cf_summary(self, r):
        ns, d, f = self.ns, self.d, self.f
        peers = {}
        if r == 'cf_r1' and 'cf_r1' in f:
            peers[str(ns.lo('cf_r2'))] = {'remoteAs': d.cf_sub1, 'state': 'Established' if self.confed else 'Active'}
            peers[str(ns.addr('cf_ext1', 'cf_le1'))] = {'remoteAs': 65131, 'state': 'Established'}
        if r == 'cf_r2' and 'cf_r2' in f:
            peers[str(ns.lo('cf_r1'))] = {'remoteAs': d.cf_sub1, 'state': 'Established' if self.confed else 'Active'}
            peers[str(ns.addr('cf_r3', 'cf_l23'))] = {'remoteAs': d.cf_sub2, 'state': 'Established'}
        if not peers:
            return {}
        return {'routerId': str(ns.lo(r)), 'as': d.cf_sub1, 'peers': peers}

    def cf_routes(self, r):
        ns, d, f, net = self.ns, self.d, self.f, self.ns.net
        our, s2 = d.our_as, d.cf_sub2
        r4 = ns.lo('cf_r4')
        routes = {}
        if r == 'cf_r1':
            if 'cf_r1' in f:
                routes[str(net('cf_e1'))] = [_path(ns.addr('cf_ext1', 'cf_le1'), "65131", True)]
            if self.confed:
                for p in ('cf_s2', 'cf_n'):
                    routes[str(net(p))] = [_path(r4, f"({s2})", True, 100)]
                routes[str(net('cf_e2'))] = [_path(r4, f"({s2}) 65132", True, 150)]
        elif r == 'cf_r2':
            if 'cf_r2' in f:
                for p in ('cf_s2', 'cf_n'):
                    routes[str(net(p))] = [_path(r4, f"({s2})", True, 100)]
                routes[str(net('cf_e2'))] = [_path(r4, f"({s2}) 65132", True, 150)]
        elif r == 'cf_ext1':
            routes[str(net('cf_e1'))] = [_local()]
            if self.confed:
                for p, tail in (('cf_s2', ''), ('cf_e2', ' 65132')):
                    routes[str(net(p))] = [_path(ns.addr('cf_r1', 'cf_le1'), f"{our}{tail}", True)]
        elif r == 'cf_ext2':
            routes[str(net('cf_e2'))] = [_local()]
            routes[str(net('cf_s2'))] = [_path(ns.addr('cf_r4', 'cf_le2'), str(our), True)]
            if self.confed:
                routes[str(net('cf_e1'))] = [_path(ns.addr('cf_r4', 'cf_le2'), f"{our} 65131", True)]
        return routes

    def cf_r1_e2(self):
        if not self.confed:
            return {}
        return {'prefix': str(self.ns.net('cf_e2')), 'paths': [_prefix_path(
            self.ns.lo('cf_r4'), f"({self.d.cf_sub2}) 65132", locprf=150, peer_type='internal')]}

    # -- dmp, gs --------------------------------------------------------------------------

    def dmp_output(self, command):
        net, peer = self.ns.net, self.ns.addr('dmp_cust', 'dmp_l2')
        on = 'dmp' in self.f
        if 'dampened-paths' in command:
            return {'routes': {str(net('dmp_f')): [{'damped': True, 'peerHost': str(peer), 'asPath': '65141',
                                                   'reuseTimerMsecs': 900000}]}} if on else {}
        return {'prefix': str(net('dmp_f')), 'paths': [_prefix_path(peer, "65141", best=not on, damped=on)]}

    def dmp_isp_routes(self):
        net, r1 = self.ns.net, self.ns.addr('dmp_r1', 'dmp_l1')
        our = str(self.d.our_as)
        routes = {str(net('dmp_own')): [_path(r1, our, True)], str(net('dmp_s')): [_path(r1, f"{our} 65141", True)]}
        if 'dmp' not in self.f:
            routes[str(net('dmp_f'))] = [_path(r1, f"{our} 65141", True)]
        return routes

    def gs_routes(self):
        net, addr = self.ns.net, self.ns.addr
        isp1, isp2 = addr('gs_isp1', 'gs_l1'), addr('gs_isp2', 'gs_l2')
        drained = 'gs_neighbor' in self.f
        return {str(net('gs_inet')): [_path(isp1, "65150", not drained, 0 if drained else None),
                                      _path(isp2, "65151 65150", drained)],
                str(net('gs_own')): [_local()]}

    def gs_isp1_own(self):
        addr, our = self.ns.addr, self.d.our_as
        tagged = 'gs_out_tag' in self.f
        return {'prefix': str(self.ns.net('gs_own')), 'paths': [
            _prefix_path(addr('gs_r1', 'gs_l1'), str(our), best=not tagged,
                         community=['gracefulShutdown'] if tagged else None, locprf=0 if tagged else None),
            _prefix_path(addr('gs_isp2', 'gs_l12'), f"65151 {our}", best=tagged)]}

    # -- every command ------------------------------------------------------------------

    def output(self, machine, command, step):
        ns, lab = self.ns, self.lab
        if command == 'vtysh -c "show running-config"':
            return self.running_config(machine), 0
        if command == 'vtysh -c "show bgp ipv4 unicast json"':
            routes = {'ne_isp': lambda: self.ne_routes('ne_isp'), 'ne_far': lambda: self.ne_routes('ne_far'),
                      'mp_r1': self.mp_routes, 'cf_r1': lambda: self.cf_routes('cf_r1'),
                      'cf_r2': lambda: self.cf_routes('cf_r2'), 'cf_ext1': lambda: self.cf_routes('cf_ext1'),
                      'cf_ext2': lambda: self.cf_routes('cf_ext2'), 'dmp_isp': self.dmp_isp_routes,
                      'gs_r1': self.gs_routes}[machine]()
            return json.dumps({'routerId': '1.1.1.1', 'routes': routes}), 0
        if command == 'vtysh -c "show bgp ipv4 unicast summary json"':
            if machine in ('cf_r1', 'cf_r2'):
                return json.dumps(self.cf_summary(machine)), 0
            if machine == 'gs_r1':
                return json.dumps({'routerId': '1.1.1.1', 'as': self.d.our_as, 'peers': {
                    str(ns.addr('gs_isp1', 'gs_l1')): {'remoteAs': 65150, 'state': 'Established'},
                    str(ns.addr('gs_isp2', 'gs_l2')): {'remoteAs': 65151, 'state': 'Established'}}}), 0
        if command == 'vtysh -c "show bgp ipv4 unicast dampening dampened-paths json"':
            return json.dumps(self.dmp_output(command)), 0
        m = re.fullmatch(r'vtysh -c "show bgp ipv4 unicast (\S+) json"', command)
        if m:
            prefix = m.group(1)
            if machine == 'ne_isp':
                return json.dumps(self.ne_isp_prefix(prefix)), 0
            if machine == 'cf_r1':
                return json.dumps(self.cf_r1_e2()), 0
            if machine == 'dmp_r1':
                return json.dumps(self.dmp_output(command)), 0
            if machine == 'gs_isp1':
                return json.dumps(self.gs_isp1_own()), 0
        if command == 'ip -j route' and machine == 'mp_r1':
            return json.dumps(self.mp_kernel()), 0
        if command == f"sysctl -n {ns.MP_SYSCTL}":
            return ("1\n" if 'mp_hash' in self.f else "0\n"), 0
        if command.startswith('cat /sys/class/net/'):
            return "".join(f"{n}\n" for n in self.mp_counters(step)), 0
        if command.startswith(f"python3 {lab.FLOWS_SCRIPT}"):
            return "", 0
        m = re.fullmatch(r'ping -c 3 -w 5 -I (\S+) (\S+)', command)
        if m:
            ok = {'ne_far': True, 'cf_ext1': self.confed}[machine]
            return ("64 bytes from x: icmp_seq=1 ttl=62 time=1 ms\n", 0) if ok else ("0 received\n", 1)
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


class TestData:
    def test_round_trip(self, lab, data):
        again = lab.Data.from_dict(json.loads(json.dumps(data.to_dict())))
        assert again.to_dict() == data.to_dict()

    def test_addressing(self, lab, data):
        assert data.nets.instance.subnet_of(IPv4Network('10.0.0.0/8'))
        assert data.nets.pub.subnet_of(IPv4Network('172.16.0.0/12'))
        for name in lab.PUB:
            assert getattr(data.nets, name).subnet_of(data.nets.pub), name
        assert data.nets.ne_te1.subnet_of(data.nets.ne_own) and data.nets.ne_te2.subnet_of(data.nets.ne_own)
        assert data.nets.mp_lan.subnet_of(data.nets.mp_own) and data.ips.mp_h1.ip in data.nets.mp_lan
        for net, (a, b) in lab.LINKS.items():
            network = getattr(data.nets, net)
            assert getattr(data.ips, f"{a}_{net}").ip in network and getattr(data.ips, f"{b}_{net}").ip in network

    def test_values(self, lab, data):
        assert 64600 <= data.our_as <= 64999 and data.our_as not in lab.EXT_AS.values()
        assert data.cf_sub1 != data.cf_sub2 and 65201 <= min(data.cf_sub1, data.cf_sub2)
        damping = (data.damp_half_life, data.damp_reuse, data.damp_suppress, data.damp_max)
        assert damping in lab.DAMPENING_CHOICES and damping != (15, 750, 2000, 60)
        assert all(r < s for _h, r, s, _m in lab.DAMPENING_CHOICES)


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 20
        specs = lab.NetScheme._machine_specs
        assert {m for m, s in specs.items() if s.get('allow_connection', True)} == set(lab.TERMINALS)

    def test_sites_are_islands(self, lab):
        for net, members in lab._TOPOLOGY.items():
            assert {lab.site_of(m) for m in members} == {lab.site_of(net)}, net

    def test_weight(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.get_weight() == pytest.approx(115)


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for r in lab.FRR_ROUTERS:
            assert 'systemctl start frr' in _cmds(ops, 2, r), r
            assert ('ospfd=yes' in _files(ops, 2, r)['/etc/frr/daemons']) == (r in lab.CONFED_ROUTERS), r
        # the flapping starts once FRR runs
        assert any(lab.FLAP_SCRIPT in c and 'setsid' in c for c in _cmds(ops, 3, 'dmp_cust'))
        script = _files(ops, 1, 'dmp_cust')[lab.FLAP_SCRIPT]
        assert f"no network {data.nets.dmp_f}" in script and f"'network {data.nets.dmp_f}'" in script
        assert lab.FLOWS_SCRIPT in _files(ops, 1, 'mp_h1')

    def test_given_configurations(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        cfg = {r: parse_frr_config(ns._frr_conf(r)) for r in lab.FRR_ROUTERS}
        assert not cfg['cf_r1']['router_bgp']['present'] and not cfg['cf_r2']['router_bgp']['present']
        for r in ('cf_r3', 'cf_r4'):
            rb = cfg[r]['router_bgp']
            assert rb['as'] == data.cf_sub2 and rb['confederation_identifier'] == data.our_as
            assert rb['confederation_peers'] == [data.cf_sub1]
        r4 = cfg['cf_r4']
        assert r4['route_maps']['LOCAL-AS'][0]['set'] == ['community local-AS']
        assert r4['route_maps']['FROM-EXT2'][0]['set'] == [f"local-preference {lab.LOCAL_PREF_EXT2}"]
        assert f"network {data.nets.cf_l} route-map LOCAL-AS" in ns._frr_conf('cf_r4')
        assert f"network {data.nets.ne_c3} route-map NO-ADVERTISE" in ns._frr_conf('ne_cust')
        assert cfg['gs_isp1']['route_maps']['FROM-CUSTOMER'][0]['set'] == ['local-preference 0']
        # the ECMP of mp_r1 needs nothing: two sessions with mp_isp1
        assert len([n for n in cfg['mp_r1']['router_bgp']['neighbors'].values() if n['remote_as'] == 65120]) == 2

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for r in ('cf_r1', 'cf_r2'):
            rb = parse_frr_config(ns._frr_conf(r) + _as_frr_config(ns.solution_cf()[r]))['router_bgp']
            assert rb['as'] == data.cf_sub1 and rb['confederation_identifier'] == data.our_as
            assert rb['confederation_peers'] == [data.cf_sub2]
        rb = parse_frr_config(ns._frr_conf('dmp_r1') + _as_frr_config(ns.solution_dmp()['dmp_r1']))['router_bgp']
        assert rb['dampening'] == (data.damp_half_life, data.damp_reuse, data.damp_suppress, data.damp_max)
        gs = parse_frr_config(ns._frr_conf('gs_r1') + _as_frr_config(ns.solution_gs()['gs_r1']))
        assert gs['router_bgp']['neighbors'][str(ns.addr('gs_isp1', 'gs_l1'))]['graceful_shutdown'] is True
        mp = parse_frr_config(ns._frr_conf('mp_r1') + _as_frr_config(ns.solution_mp()['mp_r1']))
        assert 'as-path multipath-relax' in mp['router_bgp']['bestpath']

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())

        def commands(state):
            ops = _state_ops(ns, state)
            return sorted(c for (s, m), lst in ops.items() for c in _cmds(ops, s, m) if not c.startswith('sleep'))

        assert commands('final') == sorted(c for part in PARTS for c in commands(SOLVE_STATE[part]))


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 68
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len(elements) == 41 and len({str(e.title) for e in elements}) == 41

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (68, 6)
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
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (68, 6)
            assert _totals(_simulate(lab, d, tmp_pub_dir, features=set(), answers=None)[0]) == (0, 0)

    def test_scopes_and_bonus(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for e in grade.get_grade_list():
            expected = params.EXO_EVAL_SCOPE if str(e.title) in CHOICE_ELEMENTS else params.BOTH_EVAL_SCOPE
            assert e.scope == expected, e.title
        assert [str(e.title) for e in grade.get_grade_list() if e.bonus] == BONUS_ELEMENTS

    def test_answers_only(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _totals(grade) == (sum(FORM_POINTS.values()), 0) == (15, 0)

    @pytest.mark.parametrize('features, lost', [
        ({'ne_te'}, {'ne_c1_isp', 'ne_c1_far'}),
        ({'ne_c1'}, {'ne_te_isp', 'ne_te_far', 'ne_reach'}),
        ({'mp_relax'}, {'mp_hash', 'mp_spread'}),
        ({'mp_hash'}, {'mp_relax_conf', 'mp_three_paths', 'mp_bgp_flags', 'mp_spread'}),
        ({'cf_r2'}, {'cf_conf', 'cf_sessions', 'cf_ext1_path', 'cf_ext2_path', 'cf_inside', 'cf_localpref',
                     'cf_no_export', 'cf_ping'}),
        ({'gs_neighbor'}, {'gs_in'}),
        ({'gs_out_tag'}, {'gs_conf', 'gs_out'}),
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
        assert grade.get_cheat_answers('solve_gs') is None


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
        assert len([w for w, t in _all_texts(g1, ns1) if has_instructor(t)]) == 10

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
            'communities', 'multipath', 'confed', 'dampening', 'gshut', 'frr', 'diagnostic']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        for value in (str(data.nets.pub.network_address), str(data.our_as), str(data.cf_sub1), 'Partie 1', 'ne_r1',
                      'cf_r4'):
            assert not _mentions(informations, value), value

    def test_values_of_the_instance_in_the_questions(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        everything = "\n".join(_text(q.description) for q in g0.get_questions_ordered())
        for value in (f"**AS {data.our_as}**", f"**{data.cf_sub1}**", f"**{data.cf_sub2}**",
                      f"**{data.damp_half_life}** min", f"**{data.damp_suppress}**", str(data.nets.ne_te1)):
            assert value in everything, value
        for value in ('multipath-relax', 'bgp confederation identifier', 'bgp dampening', 'fib_multipath_hash_policy=1'):
            assert value not in everything, value

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 10 and result.warnings == []
        stripped = tmp_path / 'bgp_scaling_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('bgp_scaling_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (68, 6)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|voisin|bouclage|chemin|client|fournisseur|'
                            r'oscill|amorti)', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_cf' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
