"""Offline tests of the anycast lab (lab/sre/_DRAFT_misc/anycast.py).

No Docker, no FRR: a model of the nine sites (``World``) holds what has been done, as a set of
features (``near_dns1``, ``te_noexport``, ``bfix_long``...), and renders the outputs the grader
reads: OSPF shortest paths computed over the site (stub routes of cost 0, external type 2 routes
compared on their metric), a small BGP propagation between the operators (shortest AS path, lowest
router-id, no-export not sent to eBGP peers, loop detection), the identity of the instance a
query reaches (by following the next hops), the steps of the health check test, the BFD cut and
the ECMP spread.  Covers the data, the topology, the state ops, the two-pass grading contract
(nothing done: 0; everything: 131 + 12 bonus points; **each part alone gives exactly its points
and everything but one part the rest**) and the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from frr import parse_frr_config  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'anycast.py'

# what each part does (the features of the model) and its points
PARTS = {
    'near': {'near_dns1', 'near_dns2'},
    'prim': {'prim_dns1', 'prim_dns2'},
    'hc': {'hc_dns1', 'hc_dns2'},
    'ofix': {'ofix_rid', 'ofix_address', 'ofix_source', 'ofix_rogue'},
    'bgp': {'bgp_dns1', 'bgp_dns2'},
    'te': {'te_prepend', 'te_noexport'},
    'bfix': {'bfix_policy', 'bfix_long', 'bfix_importcheck', 'bfix_noaddr'},
    'bfd': {'bfd'},
    'ecmp': {'ecmp'},
}
POINTS = {'near': 20, 'prim': 16, 'hc': 17, 'ofix': 20, 'bgp': 21, 'te': 19, 'bfix': 18, 'bfd': 6, 'ecmp': 6}
REGULAR, BONUS = 131, 12
SOLVE_STATE = {part: f"solve_{part}" for part in PARTS}
ALL_FEATURES = set().union(*PARTS.values())
FORM_POINTS = {'near': 4, 'prim': 3, 'hc': 3, 'ofix': 4, 'bgp': 3, 'te': 3, 'bfix': 4}
CHOICE_ELEMENTS = {'near_q_nearest', 'near_q_rid', 'prim_q_e1', 'prim_q_e2', 'hc_q_anycast', 'hc_q_frozen',
                   'ofix_q_flap', 'ofix_q_missing', 'ofix_q_r3', 'ofix_q_r2', 'bgp_q_length', 'bgp_q_loop',
                   'te_q_noexport', 'te_q_tie', 'bfix_q_d1send', 'bfix_q_d1isp', 'bfix_q_d2send', 'bfix_q_d2answer'}
BONUS_ELEMENTS = ['bfd_session', 'bfd_failover', 'ecmp_policy', 'ecmp_spread']
ISP_AS = {'ispa': 65010, 'ispb': 65020, 'ispc': 65030}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('anycast_lab_under_test', _LAB_PATH)
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
    """True when *value* appears in *text* as a whole."""
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


# ---------------------------------------------------------------------------
# a model of the sites: features -> what the grader reads
# ---------------------------------------------------------------------------


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.f = lab, ns, set(features)
        self.d = ns.data

    # -- OSPF sites ---------------------------------------------------------------

    def _ospf_up(self, m):
        """Does *m* run OSPF with its neighbours?"""
        if m in self.lab.ROUTERS:
            return True
        return self.lab.site_of(m) != 'near' or m in self.f

    def _neighbours(self, m):
        """[(neighbour, its address on the shared network, cost of m's interface)]."""
        lab, result = self.lab, []
        for net in lab.ROUTER_IFACES[m]:
            for other in lab.ROUTER_IFACES:
                if other != m and net in lab.ROUTER_IFACES[other] and self._ospf_up(other) and self._ospf_up(m):
                    cost = lab.BFD_BACKUP_COST if (m, net) == ('bfd_r1', 'bfd_lan2') else lab.DEFAULT_COST
                    result.append((other, str(self.ns.addr(other, net)), cost))
        return result

    def _distances(self, src):
        """Dijkstra from *src*: {machine: (cost, set of first hops (neighbour, address))}."""
        best = {src: (0, set())}
        todo = [src]
        while todo:
            todo.sort(key=lambda x: best[x][0])
            m = todo.pop(0)
            for other, address, cost in self._neighbours(m):
                c = best[m][0] + cost
                hops = {(other, address)} if m == src else best[m][1]
                if other not in best or c < best[other][0]:
                    best[other] = (c, set(hops))
                    todo.append(other)
                elif c == best[other][0]:
                    best[other][1].update(hops)
        return best

    def ospf_announcers(self, site, step=1):
        """{announcer: ('stub', 0) | ('e2', metric)} of the service address of an OSPF site."""
        f, d = self.f, self.d
        if site == 'near':
            return {m: ('stub', 0) for m in ('near_dns1', 'near_dns2') if m in f}
        if site == 'prim':
            result = {}
            if 'prim_dns1' in f:
                result['prim_dns1'] = ('e2', d.prim_metric1)
            if 'prim_dns2' in f:
                result['prim_dns2'] = ('e2', d.prim_metric2)
            return result
        if site == 'hc':
            result = {'hc_dns1': ('stub', 0), 'hc_dns2': ('stub', 0)}
            if step == 3 and 'hc_dns1' in f:
                del result['hc_dns1']
            if step == 5 and 'hc_dns2' in f:
                del result['hc_dns2']
            return result
        if site == 'ofix':
            result = {}
            if 'ofix_rid' in f:          # duplicate router-ids: the LSAs of both instances fight
                if 'ofix_address' in f:
                    result['ofix_dns1'] = ('stub', 0)
                result['ofix_dns2'] = ('stub', 0)
            if 'ofix_rogue' not in f:
                result['ofix_r2'] = ('stub', 0)
            return result
        return {m: ('stub', 0) for m in self.lab.SERVERS if self.lab.site_of(m) == site}

    def ospf_route(self, router, step=1):
        """(kind, [(neighbour, address)]) of the route of *router* to the service; kind 'local',
        'stub', 'e2' or None."""
        announcers = self.ospf_announcers(self.lab.site_of(router), step)
        if router in announcers:
            return 'local', []
        dist = self._distances(router)
        reachable = {a: v for a, v in announcers.items() if a in dist}
        if not reachable:
            return None, []
        if any(kind == 'e2' for kind, _ in reachable.values()):
            best_metric = min(metric for _kind, metric in reachable.values())
            cands = [a for a, (_k, metric) in reachable.items() if metric == best_metric]
            best_cost = min(dist[a][0] for a in cands)
            hops = set().union(*(dist[a][1] for a in cands if dist[a][0] == best_cost))
            return 'e2', sorted(hops, key=lambda h: h[1])
        best_cost = min(dist[a][0] for a in reachable)
        hops = set().union(*(dist[a][1] for a in reachable if dist[a][0] == best_cost))
        return 'stub', sorted(hops, key=lambda h: h[1])

    def serves(self, m, step=1):
        """Does instance *m* answer queries to the service address at *step*?"""
        f = self.f
        if m not in self.lab.SERVERS:
            return False
        if m == 'hc_dns1' and step == 3:
            return False                   # frozen
        if m == 'hc_dns2' and step == 5:
            return False                   # stopped
        if m == 'ofix_dns2' and 'ofix_source' not in f:
            return False                   # replies from the unicast address
        if m == 'bfix_dns2' and 'bfix_noaddr' not in f:
            return False                   # no service address on lo
        return True

    def ospf_reached(self, src, step=1):
        """The machine where a query of *src* ends (following the next hops; the first of ECMP)."""
        m, seen = src, set()
        while m not in seen:
            seen.add(m)
            kind, hops = self.ospf_route(m, step)
            if kind == 'local':
                return m
            if not hops:
                return None
            m = hops[0][0]
        return None

    # -- BGP sites ------------------------------------------------------------------

    def bgp_server_path(self, server):
        """(as_list, communities) that *server* sends to its operator for the anycast /24, or None."""
        f, asn = self.f, self.d.asn
        site = self.lab.site_of(server)
        if site == 'bgp':
            return ([asn], []) if server in f else None
        if site == 'te':
            if server == 'te_dns2' and 'te_prepend' in f:
                return [asn] * 4, []
            if server == 'te_dns3' and 'te_noexport' in f:
                return [asn], ['noExport']
            return [asn], []
        if server == 'bfix_dns1':
            return ([asn], []) if {'bfix_policy', 'bfix_long'} <= f else None
        return ([asn], []) if 'bfix_importcheck' in f else None

    def _router_id(self, sender):
        return IPv4Address(str(self.ns.unicast(sender) if sender in self.lab.SERVERS else self.ns.lo(sender)))

    def bgp_tables(self, site):
        """{isp: [path]} after convergence; a path = {'as_list', 'from', 'communities', 'best'}."""
        lab = self.lab
        isps = [m for m in lab.ISPS if lab.site_of(m) == site]
        best = {i: None for i in isps}
        tables = {}
        for _round in range(6):
            tables = {}
            for i in isps:
                paths = []
                server = next(s for s in lab.SERVERS if lab.isp_of(s) == i)
                sent = self.bgp_server_path(server)
                if sent:
                    paths.append({'as_list': sent[0], 'from': server, 'communities': sent[1]})
                for j in isps:
                    if j == i or best[j] is None:
                        continue
                    if any(c == 'noExport' for c in best[j]['communities']):
                        continue
                    as_list = [ISP_AS[lab.role_of(j)]] + best[j]['as_list']
                    if ISP_AS[lab.role_of(i)] in as_list:
                        continue
                    paths.append({'as_list': as_list, 'from': j, 'communities': list(best[j]['communities'])})
                paths.sort(key=lambda p: (len(p['as_list']), self._router_id(p['from'])))
                for k, p in enumerate(paths):
                    p['best'] = k == 0
                tables[i] = paths
            new_best = {i: (tables[i][0] if tables[i] else None) for i in isps}
            if new_best == best:
                break
            best = new_best
        return tables

    def bgp_reached(self, client):
        lab = self.lab
        tables = self.bgp_tables(lab.site_of(client))
        m, seen = lab.HOSTS[client][1], set()
        while m in tables and m not in seen:
            seen.add(m)
            if not tables[m]:
                return None
            m = tables[m][0]['from']
        return m if m in lab.SERVERS else None

    # -- outputs ---------------------------------------------------------------------

    def identity(self, src, step=1):
        lab = self.lab
        site = lab.site_of(src)
        if site in lab.BGP_SITES:
            m = self.bgp_reached(src)
        elif src == 'ecmp_c1':
            m = self.ospf_reached('ecmp_r1', step)
        else:
            m = self.ospf_reached(src, step)
        if m is not None and self.serves(m, step):
            return f'"{m}"\n'
        return f";; communications error to {self.ns.service(site)}#53: timed out\n;; no servers could be reached\n"

    def kernel(self, router, step):
        kind, hops = self.ospf_route(router, step)
        routes = [{'dst': 'default', 'gateway': '10.255.255.254', 'dev': 'eth0', 'protocol': 'static'}]
        if kind in ('stub', 'e2'):
            dst = str(self.ns.s_ospf)
            if len(hops) == 1:
                routes.append({'dst': dst, 'gateway': hops[0][1], 'dev': 'eth0', 'protocol': 'ospf', 'metric': 20})
            else:
                routes.append({'dst': dst, 'protocol': 'ospf', 'metric': 20,
                               'nexthops': [{'gateway': a, 'dev': 'eth0', 'weight': 1} for _m, a in hops]})
        return json.dumps(routes)

    def neighbors(self, router):
        rows = ["Neighbor ID     Pri State           Up Time         Dead Time Address         Interface"
                "                        RXmtL RqstL DBsmL"]
        for other, address, _cost in self._neighbours(router):
            rid = address if other in self.lab.SERVERS else str(self.ns.lo(other))
            rows.append(f"{rid:<15}   1 Full/DROther    1m0s              35.000s {address:<15} eth0:10.0.0.1"
                        f"                       0     0     0")
        return "\n".join(rows) + "\n"

    def ospf_info(self, server):
        if not self._ospf_up(server):
            return ""
        rid = self.ns.unicast(server)
        if server.startswith('ofix') and 'ofix_rid' not in self.f:
            rid = self.ns.s_ospf
        return f" OSPF Routing Process, Router ID: {rid}\n Supports only single TOS (TOS0) routes\n"

    def external_lsas(self):
        lsas = []
        for m, (kind, metric) in self.ospf_announcers('prim').items():
            lsas.append({'lsaAge': 10, 'linkStateId': str(self.ns.s_ospf), 'advertisingRouter': str(self.ns.unicast(m)),
                         'networkMask': 32, 'metricType': 'E2 (Larger than any link state path)', 'metric': metric,
                         'forwardAddress': '0.0.0.0', 'externalRouteTag': 0})
        return json.dumps({'routerId': str(self.ns.lo('prim_r2')), 'asExternalLinkStates': lsas})

    def ospf_routes_text(self, router):
        kind, hops = self.ospf_route(router)
        lines = ["============ OSPF network routing table ============"]
        if kind == 'e2':
            announcers = self.ospf_announcers('prim')
            metric = min(m for _k, m in announcers.values())
            cost = min(self._distances(router)[a][0] for a, (_k, m) in announcers.items() if m == metric)
            lines.append(f"N E2 {self.ns.s_ospf}/32        [{cost}/{metric}] tag: 0")
            lines += [f"                           via {a}, eth1" for _m, a in hops]
        return "\n".join(lines) + "\n"

    def bgp_summary(self, isp):
        server = next(s for s in self.lab.SERVERS if self.lab.isp_of(s) == isp)
        up = self.bgp_server_path(server) is not None or server not in self.f and False
        configured = server in self.f if self.lab.site_of(isp) == 'bgp' else True
        peers = {str(self.ns.unicast(server)): {'remoteAs': self.d.asn, 'state': 'Established' if configured else 'Active',
                                               'peerState': 'OK', 'pfxRcd': int(up), 'pfxSnt': 3}}
        return json.dumps({'ipv4Unicast': {'routerId': str(self.ns.lo(isp)), 'as': ISP_AS[self.lab.role_of(isp)],
                                           'peers': peers}})

    def _path_json(self, p, detailed=False):
        nh = str(self.ns.unicast(p['from'])) if p['from'] in self.lab.SERVERS else str(self.ns.lo(p['from']))
        path = " ".join(str(a) for a in p['as_list'])
        if detailed:
            entry = {'aspath': {'string': path}, 'bestpath': {'overall': p['best']}, 'valid': True,
                     'peer': {'peerId': nh, 'type': 'external'}, 'nexthops': [{'ip': nh, 'used': True}]}
            if p['communities']:
                entry['community'] = {'string': 'no-export', 'list': list(p['communities'])}
            return entry
        return {'valid': True, 'bestpath': p['best'], 'path': path, 'peerId': nh, 'nexthops': [{'ip': nh, 'used': True}]}

    def bgp_routes(self, isp):
        paths = self.bgp_tables(self.lab.site_of(isp))[isp]
        routes = {str(self.ns.prefix): [self._path_json(p) for p in paths]} if paths else {}
        return json.dumps({'routerId': str(self.ns.lo(isp)), 'routes': routes})

    def bgp_prefix(self, isp):
        paths = self.bgp_tables(self.lab.site_of(isp))[isp]
        if not paths:
            return "{}"
        return json.dumps({'prefix': str(self.ns.prefix), 'paths': [self._path_json(p, True) for p in paths]})

    def advertised(self, server):
        sent = self.bgp_server_path(server)
        routes = {str(self.ns.prefix): {'path': '', 'nextHop': '0.0.0.0'}} if sent else {}
        return json.dumps({'advertisedRoutes': routes, 'totalPrefixCounter': len(routes)})

    def output(self, machine, command, step):
        lab, ns = self.lab, self.ns
        if command == 'vtysh -c "show running-config"':
            return "", 0
        if command == 'vtysh -c "show ip ospf neighbor"':
            return self.neighbors(machine), 0
        if command == 'vtysh -c "show ip ospf"':
            return self.ospf_info(machine), 0
        if command == 'vtysh -c "show ip ospf route"':
            return self.ospf_routes_text(machine), 0
        if command == 'vtysh -c "show ip ospf database external json"':
            return self.external_lsas(), 0
        if command == 'ip -j route':
            return self.kernel(machine, step), 0
        if command == 'vtysh -c "show bgp ipv4 unicast summary json"':
            return self.bgp_summary(machine), 0
        if command == 'vtysh -c "show bgp ipv4 unicast json"':
            return self.bgp_routes(machine), 0
        if command == f'vtysh -c "show bgp ipv4 unicast {ns.prefix} json"':
            return self.bgp_prefix(machine), 0
        m = re.fullmatch(r'vtysh -c "show bgp ipv4 unicast neighbors (\S+) advertised-routes json"', command)
        if m:
            assert m.group(1) == str(ns.addr(lab.isp_of(machine), lab.server_net(machine)))
            return self.advertised(machine), 0
        if command == 'vtysh -c "show bfd peers json"':
            if 'bfd' not in self.f:
                return "[]", 0
            peer = {'peer': str(ns.unicast('bfd_dns1')), 'status': 'up', 'interface': 'eth0',
                    'receive-interval': 100, 'transmit-interval': 100, 'detect-multiplier': 3,
                    'remote-receive-interval': 100, 'remote-transmit-interval': 100, 'remote-detect-multiplier': 3}
            return json.dumps([peer]), 0
        if command == 'sysctl -n net.ipv4.fib_multipath_hash_policy':
            return ("1\n" if 'ecmp' in self.f else "0\n"), 0
        single = f"dig +time=1 +tries=1 +short @{ns.service(lab.site_of(machine))} id.server CH TXT 2>&1"
        if command == single:
            return self.identity(machine, step), 0
        if command == f"for i in $(seq {lab.ECMP_QUERIES}); do {single}; done":
            names = ['ecmp_dns1', 'ecmp_dns2'] if 'ecmp' in self.f else ['ecmp_dns1']
            return "".join(f'"{names[k % len(names)]}"\n' for k in range(lab.ECMP_QUERIES)), 0
        if command == f"ping -n -q -c {lab.BFD_PINGS} -i {lab.BFD_INTERVAL} -W 1 {ns.s_ospf}":
            received = lab.BFD_PINGS - (8 if 'bfd' in self.f else 80)
            return f"--- ping statistics ---\n{lab.BFD_PINGS} packets transmitted, {received} received\n", 0
        if machine in ('hc_dns1', 'hc_dns2', 'bfd_dns1'):
            assert step in (1, 2, 4, 6), (machine, command, step)
            return "", 0
        raise AssertionError(f"unexpected command on {machine} (step {step}): {command}")


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
        again = lab.Data.from_dict(data.to_dict())
        assert again.to_dict() == data.to_dict()

    def test_addresses(self, lab, data):
        assert data.ips.service_ospf.ip in IPv4Network("172.16.0.0/12")
        assert int(data.ips.service_ospf.ip) % 256 == 53 and data.ips.service_ospf.network.prefixlen == 32
        assert int(data.ips.service_typo.ip) - int(data.ips.service_ospf.ip) == 256
        assert data.ips.service_typo.ip in IPv4Network("172.16.0.0/12")
        assert data.nets.anycast.prefixlen == 24 and data.nets.anycast.subnet_of(IPv4Network("198.18.0.0/15"))
        assert data.ips.service_bgp.ip == data.nets.anycast.network_address + 53
        assert 64512 <= data.asn <= 64999
        assert 20 <= data.prim_metric1 <= 90 < 150 <= data.prim_metric2 <= 500

    def test_addressing_is_disjoint(self, lab, data):
        nets = [getattr(data.nets, n) for n in list(lab.LINKS) + lab.LANS]
        nets += [getattr(data.nets, f"{s}_lo") for s in lab.SITE_NUMBER]
        for i, a in enumerate(nets):
            assert a.subnet_of(data.nets.instance)
            for b in nets[i + 1:]:
                assert not a.overlaps(b), (a, b)
        addresses = [str(getattr(data.ips, k).ip) for k in vars(data.ips)]
        assert len(addresses) == len(set(addresses))

    def test_every_data_set(self, lab):
        for _ in range(20):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert d.ips.service_typo.ip in IPv4Network("172.16.0.0/12")


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 45
        assert len(lab.SERVERS) == 19 and len(lab.ISPS) == 7 and len(lab.HOSTS) == 7
        for m in lab.MACHINES:
            spec = lab.NetScheme._machine_specs[m]
            assert ('image' in spec) == (m in lab.ROUTER_IFACES)
            assert spec.get('allow_connection', True) == (m not in lab.ISPS)

    def test_sites_are_islands(self, lab):
        for net, members in lab._TOPOLOGY.items():
            assert {lab.site_of(m) for m in members} == {lab.site_of(net)}, net

    def test_every_server_has_one_interface_and_a_gateway(self, lab):
        for s in lab.SERVERS:
            assert len(lab.ROUTER_IFACES[s]) == 1
            assert lab.server_gateway(s) in lab.ROUTERS

    def test_net_config_and_hosts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for s in lab.SERVERS:
            ((addresses, routes),) = ns.net_config[s]
            assert routes == [(IPv4Network("0.0.0.0/0"), ns.addr(lab.server_gateway(s), lab.server_net(s)))]
        for site in lab.SITE_NUMBER:
            assert f"{ns.service(site)}\tanycast" in ns.hosts_by_site[site]
        assert f"{data.ips.service_bgp.ip}\tanycast" in ns.hosts_by_site['te']


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        s, typo, sb = data.ips.service_ospf.ip, data.ips.service_typo.ip, data.ips.service_bgp.ip
        for srv in lab.SERVERS:
            on_lo = [c for c in _cmds(ops, 1, srv) if 'dev lo' in c]
            expected = {'near_dns1': [], 'near_dns2': [], 'bfix_dns2': [], 'ofix_dns1': [f"ip addr add {typo}/32 dev lo"]}
            site = lab.site_of(srv)
            default = [f"ip addr add {sb if site in lab.BGP_SITES else s}/32 dev lo"]
            assert on_lo == expected.get(srv, default), srv
            files = _files(ops, 2, srv)
            assert ('interface-automatic: yes' in files['/etc/unbound/unbound.conf']) == (srv != 'ofix_dns2')
            assert f'identity: "{srv}"' in files['/etc/unbound/unbound.conf']
            assert "systemctl start unbound" in _cmds(ops, 2, srv)
        assert f"ip addr add {s}/32 dev lo" in _cmds(ops, 1, 'ofix_r2')
        for m in lab.ROUTER_IFACES:
            daemons = _files(ops, 2, m)['/etc/frr/daemons']
            assert ('bgpd=yes' in daemons) == (lab.site_of(m) in lab.BGP_SITES)
            assert ('bfdd=yes' in daemons) == (lab.site_of(m) == 'bfd')
            assert "systemctl start frr" in _cmds(ops, 2, m)

    def _config(self, lab, ns, ops, m):
        return parse_frr_config(_files(ops, 2, m)['/etc/frr/frr.conf'])

    def test_given_configurations_and_faults(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        s = data.ips.service_ospf.ip
        conf = {m: _files(ops, 2, m)['/etc/frr/frr.conf'] for m in lab.ROUTER_IFACES}
        assert 'router ospf' not in conf['near_dns1'] and 'router bgp' not in conf['bgp_dns1']
        assert f"ospf router-id {s}" in conf['ofix_dns1'] and f"ospf router-id {s}" in conf['ofix_dns2']
        assert f"network {data.ips.service_typo.ip}/32 area 0" in conf['ofix_dns1']
        assert f"network {s}/32 area 0" in conf['ofix_r2']
        assert f"network {s}/32 area 0" in conf['hc_dns1'] and f"network {s}/32" not in conf['prim_dns1']
        assert "redistribute" not in conf['prim_dns1']
        assert "ip ospf cost 100" in conf['bfd_r1'] and "ip ospf dead-interval 8" in conf['bfd_dns1']
        for m in ('te_dns1', 'te_dns2', 'te_dns3', 'bfix_dns2'):
            assert f"network {data.nets.anycast}" in conf[m] and "route-map TO-ISP out" in conf[m]
        assert f"ip route {data.nets.anycast} blackhole" in conf['te_dns1']
        assert "blackhole" not in conf['bfix_dns2']
        assert f"network {data.ips.service_bgp.ip}/32" in conf['bfix_dns1'] and "TO-ISP out" not in conf['bfix_dns1']
        for isp in lab.ISPS:
            assert "le 24" in conf[isp] and "FROM-ANYCAST in" in conf[isp] and f"remote-as {data.asn}" in conf[isp]
        rb = parse_frr_config(conf['te_ispb'])['router_bgp']
        assert rb['as'] == 65020

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        s, asn = data.ips.service_ospf.ip, data.asn
        ops = _state_ops(ns, 'solve_near')
        for m in ('near_dns1', 'near_dns2'):
            cmds = _cmds(ops, 1, m)
            assert cmds[0] == f"ip addr add {s}/32 dev lo"
            lines = _vtysh_commands(cmds[1])
            assert f"ospf router-id {ns.unicast(m)}" in lines and f"network {s}/32 area 0" in lines
        ops = _state_ops(ns, 'solve_prim')
        assert f"set metric {data.prim_metric1}" in _vtysh_commands(_cmds(ops, 1, 'prim_dns1')[0])
        assert f"set metric {data.prim_metric2}" in _vtysh_commands(_cmds(ops, 1, 'prim_dns2')[0])
        ops = _state_ops(ns, 'solve_hc')
        assert f"SERVICE={s}" in _files(ops, 1, 'hc_dns2')[lab.HEALTH_SCRIPT]
        assert "@127.0.0.1" in _files(ops, 1, 'hc_dns1')[lab.HEALTH_SCRIPT]
        ops = _state_ops(ns, 'solve_ofix')
        assert 'vtysh -c "clear ip ospf process"' in _cmds(ops, 1, 'ofix_dns1')
        assert any('interface-automatic: yes' in c for c in _cmds(ops, 1, 'ofix_dns2'))
        assert f"ip addr del {s}/32 dev lo" in _cmds(ops, 1, 'ofix_r2')
        ops = _state_ops(ns, 'solve_te')
        assert f"set as-path prepend {asn} {asn} {asn}" in _vtysh_commands(_cmds(ops, 1, 'te_dns2')[0])
        assert "set community no-export" in _vtysh_commands(_cmds(ops, 1, 'te_dns3')[0])
        ops = _state_ops(ns, 'solve_bfix')
        assert f"network {data.nets.anycast}" in _vtysh_commands(_cmds(ops, 1, 'bfix_dns1')[0])
        assert f"ip addr add {data.ips.service_bgp.ip}/32 dev lo" in _cmds(ops, 1, 'bfix_dns2')
        ops = _state_ops(ns, 'solve_bfd')
        for m in ('bfd_r1', 'bfd_dns1'):
            lines = _vtysh_commands(_cmds(ops, 1, m)[0])
            assert "ip ospf bfd profile fast" in lines and "transmit-interval 100" in lines
        ops = _state_ops(ns, 'solve_ecmp')
        assert "sysctl -w net.ipv4.fib_multipath_hash_policy=1" in _cmds(ops, 1, 'ecmp_r1')

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = _state_ops(ns, 'final')
        def described(op_list):
            return [op if isinstance(op, str) else (op.filename, op.content) for op in op_list]

        union = {}
        for part in PARTS:
            for key, op_list in _state_ops(ns, SOLVE_STATE[part]).items():
                if key[0] == 1:
                    union.setdefault(key, []).extend(described(op_list))
        assert {k: described(v) for k, v in final.items() if k[0] == 1} == union


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == REGULAR
        assert sum(e.max_grade for e in elements if e.bonus) == BONUS
        assert len(elements) == 66 and len({str(e.title) for e in elements}) == 66

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (REGULAR, BONUS)
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
        for _ in range(8):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (REGULAR, BONUS)
            assert _totals(_simulate(lab, d, tmp_pub_dir, features=set(), answers=None)[0]) == (0, 0)

    def test_scopes_and_bonus(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for e in grade.get_grade_list():
            expected = params.EXO_EVAL_SCOPE if str(e.title) in CHOICE_ELEMENTS else params.BOTH_EVAL_SCOPE
            assert e.scope == expected, e.title
        assert [str(e.title) for e in grade.get_grade_list() if e.bonus] == BONUS_ELEMENTS

    def test_answers_only_and_wrong_answers(self, lab, data, tmp_pub_dir):
        answers_only, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _totals(wrong) == (REGULAR - sum(FORM_POINTS.values()), BONUS)

    @pytest.mark.parametrize('features, lost', [
        ({'near_dns1'}, {'near_adj', 'near_rid', 'near_r3', 'near_ecmp'}),
        ({'prim_dns1'}, {'prim_ext2', 'prim_only'}),
        ({'prim_dns2'}, {'prim_ext1', 'prim_only', 'prim_r2', 'prim_r1'}),
        ({'hc_dns1'}, {'hc_withdraw2', 'hc_failover2', 'hc_return2'}),
        ({'hc_dns2'}, {'hc_withdraw1', 'hc_failover1', 'hc_return1'}),
        # the stale copy on ofix_r2 is as close to ofix_r3 as ofix_dns2: ECMP, a query may reach it
        ({'ofix_rid', 'ofix_address', 'ofix_source'}, {'ofix_r1', 'ofix_rogue', 'ofix_source'}),
        ({'ofix_rid', 'ofix_address', 'ofix_rogue'}, {'ofix_source'}),
        ({'bgp_dns1'}, {'bgp_sessions', 'bgp_ispb', 'bgp_second', 'bgp_only', 'bgp_cb'}),
        ({'te_prepend'}, {'te_noexport', 'te_contained', 'te_cc'}),
        ({'te_noexport'}, {'te_prepend', 'te_cb'}),
        ({'bfix_policy', 'bfix_long'}, {'bfix_ispb', 'bfix_cb'}),
        ({'bfix_importcheck', 'bfix_noaddr', 'bfix_policy'}, {'bfix_ispa', 'bfix_ca'}),
        ({'bfix_importcheck', 'bfix_policy', 'bfix_long'}, {'bfix_cb'}),
    ])
    def test_partial_work(self, lab, data, tmp_pub_dir, features, lost):
        part = next(p for p, f in PARTS.items() if features <= f)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=features, answers=SOLVE_STATE[part])
        part_elements = {t for t in _grades(grade) if t.startswith(part + '_')}
        assert _lost(grade) & part_elements == lost

    def test_other_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        cheat = dict(grade.get_cheat_answers('final'))
        for q in forms:
            stored = cheat[q.question_hash]
            answers = dict(json.loads(stored) if isinstance(stored, str) else stored)
            for key in ('aspath',):
                if key in answers:
                    answers[key] = "  " + answers[key].replace(" ", "   ") + " "
            for key in ('cost', 'hops', 'fwd', 'lsa'):
                if key in answers:
                    answers[key] = f" {answers[key]} "
            cheat[q.question_hash] = json.dumps(answers) if isinstance(stored, str) else answers
        grade, _ = _simulate_with_answers(lab, data, tmp_pub_dir, cheat)
        assert _totals(grade) == (REGULAR, BONUS)

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 7
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
        assert len(grade.get_cheat_answers('final')) == 7
        assert grade.get_cheat_answers('solve_bfd') is None and grade.get_cheat_answers('solve_ecmp') is None


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
        assert len(g1.get_questions_ordered()) == 17
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 17 and 'informations' not in with_fragment

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
            'principle', 'uses', 'service', 'ospf', 'external', 'health', 'bfd', 'ecmp', 'bgp', 'te', 'frr',
            'diagnostic']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (str(data.nets.instance.network_address), str(data.ips.service_ospf.ip),
                      str(data.nets.anycast), str(data.asn), 'Partie 1', 'near_r1', 'te_dns3', 'bfix'):
            assert not _mentions(informations, value), value

    def test_values_of_the_instance_in_the_questions(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        questions = [_text(q.description) for q in g0.get_questions_ordered()]
        first = questions[0]
        for value in (str(data.nets.near_l12), f"`{data.ips.bgp_ca.ip}`", f"`near_r2` `{data.ips.near_r2_lo.ip}`",
                      f"`{data.ips.service_ospf.ip}`", f"`{data.nets.anycast}`", f"**{data.asn}**"):
            assert value in first, value
        everything = "\n".join(questions)
        for value in (f"**{data.prim_metric1}**", f"**{data.prim_metric2}**", lab.HEALTH_SCRIPT):
            assert value in everything, value
        # the faults are for the instructor only
        for value in (str(data.ips.service_typo.ip), 'interface-automatic', 'blackhole` pour'):
            assert not _mentions(everything, value), value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['cost', 'hops', 'nearest', 'rid', 'fwd', 'e1', 'e2', 'anycast', 'frozen', 'lsa', 'flap',
                         'missing', 'r3', 'r2', 'aspath', 'length', 'loop', 'aspath', 'noexport', 'tie', 'd1send',
                         'd1isp', 'd2send', 'd2answer']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 17 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'anycast_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('anycast_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (REGULAR, BONUS)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|zone|voisin|bouclage|chemin|instance_|'
                            r'secours|principal|depannage|serveur|client_)', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_ofix' in names and 'te_ispc' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
