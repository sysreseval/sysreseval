"""Offline tests of the route redistribution lab (lab/sre/_DRAFT_misc/redistribution.py).

No Docker, no FRR: a model of the eight sites (``World``) holds what has been done, as a set of
features (``stat_lan``, ``dual_tags``, ``fix_seed``...), and renders the outputs the grader reads —
external and NSSA LSAs (json), ``show ip ospf`` / ``neighbor``, ``show ip rip``, ``ip -j route``,
the BGP table of the operators, pings — as FRR prints them, by rules taken from the course and the
live facts (the first border of the dual site wins, the second one routes through OSPF until the
distance is raised; a naive second redistribution loops; tags stop the routes coming back).
Covers the data, the topology, the state ops, the two-pass grading contract (nothing done: 0;
everything: every point and every bonus; **each part alone gives exactly its points and
everything but one part the rest**) and the texts.
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

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'redistribution.py'

# what each part does (the features of the model) and its points
PARTS = {
    'stat': {'stat_lan', 'stat_far', 'stat_kernel', 'stat_default'},
    'mut': {'mut_rip_to_ospf', 'mut_ospf_to_rip', 'mut_connected'},
    'dual': {'dual_b2', 'dual_tags', 'dual_distance'},
    'edge': {'edge_export', 'edge_default', 'edge_partner'},
    'fix': {'fix_seed', 'fix_filter', 'fix_static', 'fix_connected'},
    'sum': {'sum'},
    'nssa': {'nssa'},
    'agg': {'agg'},
}
POINTS = {'stat': 22, 'mut': 18, 'dual': 24, 'edge': 22, 'fix': 18, 'sum': 6, 'nssa': 6, 'agg': 6}
BONUS_PARTS = ('sum', 'nssa', 'agg')
REGULAR, BONUS = 104, 18
ALL_FEATURES = set().union(*PARTS.values())
CHOICE_ELEMENTS = {'stat_q_kernel', 'stat_q_default', 'mut_q_connected', 'dual_q_loop', 'dual_q_tags',
                   'edge_q_table', 'edge_q_network', 'fix_q_seed', 'fix_q_filter', 'fix_q_static'}
FORM_POINTS = {'stat': 4, 'mut': 4, 'dual': 4, 'edge': 4, 'fix': 4}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('redistribution_lab_under_test', _LAB_PATH)
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
    return re.search(r'(?<![0-9A-Za-z.])' + re.escape(str(value)) + r'(?![0-9A-Za-z])', text) is not None


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

    def n(self, name):
        return self.ns.net(name)

    def a(self, machine, net):
        return str(self.ns.addr(machine, net))

    # -- external LSAs: (prefix, advertising machine, metric type, metric, tag) per observer ----

    def lsas(self, observer):
        f, d, n = self.f, self.d, self.n
        site = self.lab.site_of(observer)
        out = []
        if site == 'stat':
            if 'stat_lan' in f:
                out.append((n('stat_lan'), 'stat_asbr', 2, d.lan_metric, 0))
            if 'stat_leak' in f:
                out += [(n(x), 'stat_asbr', 2, 20, 0) for x in ('stat_mgmt', 'stat_lgw', 'stat_l12')]
            if 'stat_far' in f:
                out += [(n(x), 'stat_asbr', 1, d.far_metric, 0) for x in ('stat_far1', 'stat_far2')]
            if 'stat_kernel' in f:
                out.append((n('stat_far3'), 'stat_asbr', 1, d.far_metric, 0))
            if 'stat_default' in f:
                out.append((IPv4Network('0.0.0.0/0'), 'stat_asbr', 2, 10, 0))
        elif site == 'mut':
            if 'mut_rip_to_ospf' in f:
                out.append((n('mut_lan1'), 'mut_b', 1, d.mut_metric, 0))
            if 'mut_connected' in f:
                out.append((n('mut_lrb'), 'mut_b', 1, d.mut_metric, 0))
        elif site == 'dual':
            tag = d.tag_rip if 'dual_tags' in f else 0
            out.append((n('dual_tagr'), 'dual_ospf1', 2, 20, d.tag_rip))
            out.append((n('dual_lan3'), 'dual_b1', 2, 20, tag))
            if 'dual_tags' not in f:
                out.append((n('dual_tago'), 'dual_b1', 2, 20, d.tag_ospf))
            if 'dual_b2' in f and 'dual_distance' in f:
                out.append((n('dual_lan3'), 'dual_b2', 2, 20, tag))
                if 'dual_tags' not in f:
                    out.append((n('dual_tago'), 'dual_b2', 2, 20, d.tag_ospf))
        elif site == 'edge':
            if 'edge_default' in f:
                out.append((IPv4Network('0.0.0.0/0'), 'edge_b', 2, 10, 0))
            if 'edge_partner' in f:
                out.append((n('edge_partner'), 'edge_b', 1, d.edge_metric, 0))
            if 'edge_bgp_unfiltered' in f:
                out += [(n(x), 'edge_b', 2, 20, 0) for x in ('edge_inet1', 'edge_inet2', 'edge_linet')]
        elif site == 'fix':
            if 'fix_filter' in f:
                out.append((n('fix_lan1'), 'fix_b', 2, 20, 0))
            if 'fix_static' in f:
                out.append((n('fix_srv'), 'fix_b', 2, 20, 0))
            if 'fix_connected' in f:
                out.append((n('fix_lrb'), 'fix_b', 2, 20, 0))
        elif site == 'sum':
            if 'sum' in f:
                out.append((n('sum_block'), 'sum_asbr', 2, 20, d.tag_sum))
            else:
                out += [(x, 'sum_asbr', 2, 20, 0) for x in self.ns.sum_nets()]
        elif site == 'nssa':
            out.append((n('nssa_coreext'), 'nssa_core', 2, 20, 0))
            if 'nssa' in f:
                out += [(n(x), 'nssa_abr', 2, 20, 0) for x in ('nssa_ext1', 'nssa_ext2')]
        return out

    def flushed(self, observer):
        """With the feature ``flushing``: the LSAs a solved site has just withdrawn, still in the
        database at MaxAge (seen live right after ``final``)."""
        if 'flushing' not in self.f:
            return []
        site, n = self.lab.site_of(observer), self.n
        if site == 'dual' and 'dual_tags' in self.f:
            return [(n('dual_tago'), 'dual_b1', 2, 20, self.d.tag_ospf)]
        if site == 'sum' and 'sum' in self.f:
            return [(x, 'sum_asbr', 2, 20, 0) for x in self.ns.sum_nets()]
        if site == 'stat' and 'stat_lan' in self.f:
            return [(n('stat_mgmt'), 'stat_asbr', 2, 20, 0)]
        return []

    def external_json(self, observer):
        entries = []
        rows = [(lsa, 12) for lsa in self.lsas(observer)] + [(lsa, 3600) for lsa in self.flushed(observer)]
        for (prefix, adv, mtype, metric, tag), age in rows:
            entries.append({'lsaAge': age, 'lsaType': 'AS-external-LSA', 'linkStateId': str(prefix.network_address),
                            'advertisingRouter': self.ns.rid(adv), 'networkMask': prefix.prefixlen,
                            'metricType': 'E2 (Larger than any link state path)' if mtype == 2 else 'E1',
                            'tos': 0, 'metric': metric, 'forwardAddress': '0.0.0.0', 'externalRouteTag': tag})
        return json.dumps({'routerId': self.ns.rid(observer), 'asExternalLinkStates': entries})

    # -- kernel routes: {prefix: (gateway, protocol)} per router ----------------------------

    def kernel_routes(self, router):
        f, n, a = self.f, self.n, self.a
        routes = {}
        if router in ('stat_ospf1', 'mut_ospf1', 'edge_ospf1', 'fix_ospf1'):
            site = self.lab.site_of(router)
            border = {'stat': 'stat_asbr', 'mut': 'mut_b', 'edge': 'edge_b', 'fix': 'fix_b'}[site]
            link = self.lab.ROUTER_IFACES[router][0]
            for prefix, adv, *_rest in self.lsas(router):
                if adv == border:
                    routes[str(prefix)] = (a(border, link), 'ospf')
        elif router == 'mut_rip1':
            if 'mut_ospf_to_rip' in f:
                routes[str(n('mut_lan2'))] = (a('mut_b', 'mut_lrb'), 'rip')
            if 'mut_connected' in f:
                routes[str(n('mut_lbo'))] = (a('mut_b', 'mut_lrb'), 'rip')
        elif router == 'dual_rip1':
            routes[str(n('dual_lano'))] = (a('dual_b1', 'dual_l1b1'), 'rip')
            routes[str(n('dual_lan3'))] = (a('dual_rip2', 'dual_l12'), 'rip')
            if 'dual_tags' not in f:
                routes[str(n('dual_tagr'))] = (a('dual_b1', 'dual_l1b1'), 'rip')
        elif router == 'dual_b1':
            routes[str(n('dual_lan3'))] = (a('dual_rip1', 'dual_l1b1'), 'rip')
        elif router == 'dual_b2':
            if 'dual_distance' in f or 'dual_early' in f:
                routes[str(n('dual_lan3'))] = (a('dual_rip1', 'dual_l1b2'), 'rip')
            else:
                routes[str(n('dual_lan3'))] = (a('dual_ospf1', 'dual_lb2o'), 'ospf')
        elif router == 'fix_rip1':
            if 'fix_seed' in f:
                routes[str(n('fix_lan2'))] = (a('fix_b', 'fix_lrb'), 'rip')
        elif router == 'nssa_asbr':
            routes['0.0.0.0/0'] = (a('nssa_abr', 'nssa_l12'), 'ospf')
        return routes

    def kernel_json(self, router):
        entries = [{'dst': 'default' if prefix == '0.0.0.0/0' else prefix, 'gateway': gw, 'dev': 'eth0',
                    'protocol': proto, 'metric': 20} for prefix, (gw, proto) in self.kernel_routes(router).items()]
        return json.dumps(entries)

    # -- RIP tables -----------------------------------------------------------------------

    def rip_rows(self, router):
        """[(code, prefix, nexthop, metric, from, tag)]."""
        f, d, n, a = self.f, self.d, self.n, self.a
        if router == 'mut_rip1':
            rows = [('C(i)', n('mut_lan1'), '0.0.0.0', 1, 'self', 0), ('C(i)', n('mut_lrb'), '0.0.0.0', 1, 'self', 0)]
            gw = a('mut_b', 'mut_lrb')
            if 'mut_ospf_to_rip' in f:
                rows.append(('R(n)', n('mut_lan2'), gw, d.mut_seed + 1, gw, 0))
            if 'mut_connected' in f:
                rows.append(('R(n)', n('mut_lbo'), gw, d.mut_seed + 1, gw, 0))
            return rows
        if router == 'dual_rip1':
            gw = a('dual_b1', 'dual_l1b1')
            tag = d.tag_ospf if 'dual_tags' in f else 0
            rows = [('R(n)', n('dual_lano'), gw, 2, gw, tag),
                    ('R(n)', n('dual_lan3'), a('dual_rip2', 'dual_l12'), 3, a('dual_rip2', 'dual_l12'), 0),
                    ('R(n)', n('dual_tago'), a('dual_rip2', 'dual_l12'), 2, a('dual_rip2', 'dual_l12'), d.tag_ospf)]
            if 'dual_tags' not in f:
                rows.append(('R(n)', n('dual_tagr'), gw, 2, gw, d.tag_rip))
            return rows
        if router == 'fix_rip1':
            gw = a('fix_b', 'fix_lrb')
            return [('C(i)', n('fix_lan1'), '0.0.0.0', 1, 'self', 0),
                    ('R(n)', n('fix_lan2'), gw, 3 if 'fix_seed' in f else 16, gw, 0)]
        raise AssertionError(router)

    def rip_text(self, router):
        lines = ["Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP", "Sub-codes:",
                 "      (n) - normal, (s) - static, (d) - default, (r) - redistribute,", "      (i) - interface", "",
                 "     Network            Next Hop         Metric From            Tag Time"]
        for code, prefix, nexthop, metric, source, tag in self.rip_rows(router):
            time = " 00:35" if source != 'self' else ""
            lines.append(f"{code} {str(prefix):<18} {nexthop:<16} {metric:>2} {source:<16} {tag:>4}{time}")
        return "\n".join(lines) + "\n"

    # -- BGP tables of the operators ------------------------------------------------------------

    def bgp_json(self, isp):
        f, d, n = self.f, self.d, self.n
        routes = {}

        def path(as_path, origin, med, nexthop):
            return [{'valid': True, 'bestpath': True, 'pathFrom': 'external' if as_path else 'internal',
                     'path': as_path, 'origin': origin, 'metric': med, 'weight': 0, 'peerId': nexthop,
                     'nexthops': [{'ip': nexthop, 'used': True}]}]

        if isp == 'edge_isp':
            peer = self.a('edge_b', 'edge_lisp')
            for x in ('edge_partner', 'edge_inet1', 'edge_inet2', 'edge_linet'):
                routes[str(n(x))] = path('', 'IGP', 0, '0.0.0.0')
            exported = []
            if 'edge_export' in f:
                exported += ['edge_lan1', 'edge_lan2']
            if 'edge_export_unfiltered' in f:
                exported += ['edge_l12', 'edge_lisp']
            for x in exported:
                routes[str(n(x))] = path(str(d.asn), 'incomplete', 20 if x.startswith('edge_lan') else 0, peer)
        else:
            peer = self.a('agg_b', 'agg_lisp')
            if 'agg' in f:
                routes[str(n('agg_company'))] = path(str(d.asn), 'incomplete', 0, peer)
            else:
                for x in self.ns.agg_nets():
                    routes[str(x)] = path(str(d.asn), 'incomplete', 20, peer)
        return json.dumps({'routerId': self.ns.rid(isp), 'routes': routes})

    # -- nssa site -------------------------------------------------------------------------------

    def ospf_info(self, router):
        kind = 'NSSA' if 'nssa' in self.f else 'Stub'
        return (f" OSPF Routing Process, Router ID: {self.ns.rid(router)}\n"
                f" Area ID: 0.0.0.{self.lab.NSSA_AREA} ({kind})\n"
                "   Number of interfaces in this area: Total: 1, Active: 1\n"
                "   Number of fully adjacent neighbors in this area: 1\n")

    def ospf_neighbors(self, router):
        rows = ["Neighbor ID     Pri State           Up Time         Dead Time Address         Interface"
                "                        RXmtL RqstL DBsmL"]
        for other, net in (('nssa_core', 'nssa_l01'), ('nssa_asbr', 'nssa_l12')):
            address = self.a(other, net)
            rows.append(f"{self.ns.rid(other):<15}   1 Full/-          1m0s              35.000s {address:<15} "
                        f"eth0:10.0.0.1                        0     0     0")
        return "\n".join(rows) + "\n"

    def nssa_json(self, router):
        """The type 7 LSAs of the ABR (FRR 10.3 shape): the ASBR's two networks once the area is an NSSA."""
        entries = []
        if 'nssa' in self.f:
            for x in ('nssa_ext1', 'nssa_ext2'):
                entries.append({'lsaAge': 20, 'lsaType': 'NSSA-LSA', 'linkStateId': str(self.n(x).network_address),
                                'advertisingRouter': self.ns.rid('nssa_asbr'), 'networkMask': 24,
                                'metricType': 'E2 (Larger than any link state path)', 'tos': 0, 'metric': 20,
                                'nssaForwardAddress': self.a('nssa_asbr', 'nssa_l12'), 'externalRouteTag': 0})
        areas = {'0.0.0.0': [], f"0.0.0.{self.lab.NSSA_AREA}": entries}
        return json.dumps({'routerId': self.ns.rid(router), 'nssaExternalLinkStates': {'areas': areas}})

    # -- pings -----------------------------------------------------------------------------------

    def ping_ok(self, src, dest):
        f, ns = self.f, self.ns
        if src == 'stat_h2':
            if dest == str(ns.host_ip('stat_h1')):
                return 'stat_lan' in f
            if dest == str(ns.first_host(self.n('stat_far1'))):
                return 'stat_far' in f
            return 'stat_default' in f
        if src in ('mut_h1', 'mut_h2'):
            return {'mut_rip_to_ospf', 'mut_ospf_to_rip'} <= f
        if src in ('dual_h1', 'dual_h2'):
            return not ('dual_b2' in f and not {'dual_tags', 'dual_distance'} & f)
        if src == 'edge_h1':
            if dest == str(ns.host_ip('edge_inet')):
                return {'edge_export', 'edge_default'} <= f
            return 'edge_export' in f and bool({'edge_default', 'edge_partner'} & f)
        if src == 'fix_h2':
            if dest == str(ns.host_ip('fix_h1')):
                return {'fix_seed', 'fix_filter'} <= f
            return {'fix_seed', 'fix_connected'} <= f
        if src == 'sum_ospf1':
            return True
        raise AssertionError((src, dest))

    def output(self, machine, command, step):
        if command == 'vtysh -c "show running-config"':
            return "", 0
        if command == 'vtysh -c "show ip ospf database external json"':
            return self.external_json(machine), 0
        if command == 'ip -j route':
            return self.kernel_json(machine), 0
        if command == 'vtysh -c "show ip rip"':
            return self.rip_text(machine), 0
        if command == 'vtysh -c "show bgp ipv4 unicast json"':
            return self.bgp_json(machine), 0
        if command == 'vtysh -c "show ip ospf"':
            return self.ospf_info(machine), 0
        if command == 'vtysh -c "show ip ospf neighbor"':
            return self.ospf_neighbors(machine), 0
        if command == 'vtysh -c "show ip ospf database nssa-external json"':
            return self.nssa_json(machine), 0
        m = re.fullmatch(r'ping -c 3 -w 5 (\S+)', command)
        if m:
            if self.ping_ok(machine, m.group(1)):
                return f"64 bytes from {m.group(1)}: icmp_seq=1 ttl=62 time=0.1 ms\n", 0
            return "3 packets transmitted, 0 received, 100% packet loss\n", 1
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

    def test_values(self, lab, data):
        assert 64512 <= data.asn <= 64999
        assert 31 <= data.lan_metric <= 99 and data.lan_metric % 10
        assert len({data.far_metric, data.mut_metric, data.edge_metric}) == 3
        assert all(101 <= v <= 499 and v % 100 for v in (data.far_metric, data.mut_metric, data.edge_metric))
        assert 2 <= data.mut_seed <= 5
        assert len({data.tag_rip, data.tag_ospf, data.tag_sum}) == 3

    def test_addressing_is_disjoint(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        nets = [ns.net(n) for n in list(lab.LINKS) + lab.LANS]
        nets += [ns.net(n) for n in ('stat_far1', 'stat_far2', 'stat_far3', 'fix_srv', 'sum_block', 'nssa_ext1',
                                     'nssa_ext2', 'nssa_coreext', 'edge_partner', 'edge_inet1', 'edge_inet2',
                                     'agg_company', 'dual_tagr', 'dual_tago', 'router_ids')]
        nets.append(data.ips.stat_inet.network)
        for i, x in enumerate(nets):
            for y in nets[i + 1:]:
                assert not x.overlaps(y), (x, y)

    def test_special_blocks(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        block = ns.net('fix_rip_block')
        assert block.prefixlen == 22
        assert ns.net('fix_lan1').subnet_of(block) and ns.net('fix_lrb').subnet_of(block)
        for x in ('fix_lbo', 'fix_lgw', 'fix_lan2', 'fix_srv'):
            assert not ns.net(x).overlaps(block)
        assert ns.net('sum_block').prefixlen == 21 and len(ns.sum_nets()) == lab.SUM_COUNT
        assert all(x.subnet_of(ns.net('sum_block')) for x in ns.sum_nets())
        # no /24 shares the Link State ID (network address) of the summary
        assert all(x.network_address != ns.net('sum_block').network_address for x in ns.sum_nets())
        assert ns.net('edge_lan1').subnet_of(ns.net('edge_company'))
        assert ns.net('edge_lan2').subnet_of(ns.net('edge_company'))
        assert not ns.net('edge_l12').overlaps(ns.net('edge_company'))
        assert not ns.net('edge_lisp').overlaps(ns.net('edge_company'))
        assert ns.fix_wrong_nexthop() not in ns.net('fix_lgw')
        for name in ('fix_lrb', 'fix_lbo', 'fix_lgw'):
            assert ns.fix_wrong_nexthop() not in ns.net(name)

    def test_every_data_set(self, lab):
        for _ in range(30):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert lab.Data.from_dict(d.to_dict()).to_dict() == d.to_dict()


class TestTopology:
    def test_machines(self, lab):
        assert len(lab.MACHINES) == 39
        assert set(lab.SITE_NUMBER) == set(PARTS)
        for m in lab.MACHINES:
            assert lab.site_of(m) in lab.SITE_NUMBER

    def test_sites_are_islands(self, lab):
        for net, members in lab._TOPOLOGY.items():
            assert {lab.site_of(m) for m in members} == {lab.site_of(net)}, net

    def test_interfaces_follow_the_tables(self, lab):
        for m, nets in lab.ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                assert lab._TOPOLOGY[net][m] == i
        for h, (net, gw) in lab.HOSTS.items():
            assert lab._TOPOLOGY[net][h] == 0 and net in lab.ROUTER_IFACES[gw]

    def test_net_config_and_hosts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for h, (net, gw) in lab.HOSTS.items():
            (addresses, routes), = ns.net_config[h]
            assert addresses == [ns.host_iface(h)]
            assert routes == [(IPv4Network('0.0.0.0/0'), ns.addr(gw, net))]
            assert ns.host_iface(h).ip in ns.net(net)
        for site, text in ns.hosts_by_site.items():
            for m in lab.MACHINES:
                assert (f"\t{m}" in text) == (lab.site_of(m) == site), (site, m)

    def test_specs(self, lab):
        specs = lab.NetScheme._machine_specs
        for m in lab.ROUTER_IFACES:
            assert 'netdev13' in specs[m]['image']
        for m in lab.HOSTS:
            assert 'image' not in specs[m]
        assert all(specs[m].get('allow_connection') is False for m in lab.ISPS)


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        far3, gw = ns.net('stat_far3'), ns.addr('stat_gw', 'stat_lgw')
        assert f"ip route add {far3} via {gw}" in _cmds(ops, 1, 'stat_asbr')
        assert any('ip link add dum3 type dummy' in c for c in _cmds(ops, 1, 'agg_ospf1'))
        assert f"ip addr add {ns.first_host(ns.net('fix_srv'))}/24 dev lo" in _cmds(ops, 1, 'fix_gw')
        assert f"ip addr add {data.ips.stat_inet} dev lo" in _cmds(ops, 1, 'stat_gw')
        for m in lab.ROUTER_IFACES:
            files = _files(ops, 2, m)
            assert {'/etc/frr/daemons', '/etc/frr/vtysh.conf', '/etc/frr/frr.conf'} <= set(files)
            assert "systemctl start frr" in _cmds(ops, 2, m)
            daemons = files['/etc/frr/daemons']
            assert ('ospfd=yes' in daemons) == (m in lab.OSPF_NETS)
            assert ('ripd=yes' in daemons) == (m in lab.RIP_NETS)
            assert ('bgpd=yes' in daemons) == (m in lab.BGP_ROUTERS)
        for m in lab.HOSTS:
            assert not any('/etc/frr/frr.conf' in f for f in _files(ops, 2, m))

    def _conf(self, lab, data, m):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        text = _files(_state_ops(ns, 'initial'), 2, m)['/etc/frr/frr.conf']
        return ns, text, parse_frr_config(text)

    def test_given_ospf(self, lab, data):
        for m, nets in lab.OSPF_NETS.items():
            ns, text, cfg = self._conf(lab, data, m)
            ro = cfg['router_ospf']
            assert ro['present'] and ro['router_id'] == ns.rid(m)
            networks = {(p, a) for p, a in ro['networks']}
            for net in nets:
                assert (str(ns.net(net)), f"0.0.0.{ns.area_of(net)}") in networks
            for net in nets:
                if net in lab.LINKS:
                    assert cfg['interfaces'][lab.iface(m, net)]['network_type'] == 'point-to-point'

    def test_given_rip(self, lab, data):
        for m, nets in lab.RIP_NETS.items():
            ns, text, _cfg = self._conf(lab, data, m)
            assert "router rip" in text and " version 2" in text and " timers basic 10 60 40" in text
            for net in nets:
                assert f" network {ns.net(net)}" in text

    def test_faults_and_given_redistributions(self, lab, data):
        ns, text, cfg = self._conf(lab, data, 'fix_b')
        assert f"ip route {ns.net('fix_srv')} {ns.fix_wrong_nexthop()}" in text
        assert cfg['prefix_lists']['RIP-NETS'] == [{'seq': 10, 'action': 'permit',
                                                    'prefix': str(ns.net('fix_rip_block')), 'ge': None, 'le': None}]
        assert set(cfg['router_ospf']['redistribute']) == {'static', 'rip'}
        assert " redistribute ospf metric 15" in text
        _ns, text, cfg = self._conf(lab, data, 'dual_b1')
        assert cfg['router_ospf']['redistribute'] == ['rip'] and " redistribute ospf" in text
        _ns, text, cfg = self._conf(lab, data, 'dual_b2')
        assert cfg['router_ospf']['redistribute'] == [] and "redistribute" not in text
        _ns, text, _cfg = self._conf(lab, data, 'dual_ospf1')
        assert f"ip route {ns.net('dual_tagr')} blackhole tag {data.tag_rip}" in text
        _ns, text, _cfg = self._conf(lab, data, 'dual_rip2')
        assert f"ip route {ns.net('dual_tago')} blackhole tag {data.tag_ospf}" in text
        for m in ('nssa_abr', 'nssa_asbr'):
            _ns, _text, cfg = self._conf(lab, data, m)
            assert cfg['router_ospf']['areas']['0.0.0.1']['stub']
        _ns, _text, cfg = self._conf(lab, data, 'stat_asbr')
        assert cfg['router_ospf']['redistribute'] == [] and cfg['static_routes'] == []
        _ns, _text, cfg = self._conf(lab, data, 'agg_b')
        assert cfg['router_bgp']['redistribute'] == ['ospf']
        _ns, _text, cfg = self._conf(lab, data, 'edge_isp')
        assert not cfg['router_bgp']['ebgp_requires_policy']
        assert cfg['router_bgp']['neighbors'][str(ns.addr('edge_b', 'edge_lisp'))]['default_originate']

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for site, solution in ns.solutions().items():
            ops = _state_ops(ns, f"solve_{site}")
            for m in solution:
                assert all(m.startswith(site) for m in solution)
                assert _cmds(ops, 1, m), (site, m)
            observers = ns.wait_conditions(site)
            assert observers
            for m in observers:
                waits = _cmds(ops, 2, m)
                assert len(waits) == 1 and waits[0].startswith("for i in $(seq ")
        assert _cmds(_state_ops(ns, 'solve_dual'), 1, 'dual_b2')[1] == 'vtysh -c "clear ip ospf process"'
        lines = _vtysh_commands(_cmds(_state_ops(ns, 'solve_dual'), 1, 'dual_b2')[0])
        assert f"set tag {data.tag_rip}" in lines and f"match tag {data.tag_ospf}" in lines
        assert f"distance ospf external {lab.DUAL_EXTERNAL_DISTANCE}" in lines
        lines = _vtysh_commands(_cmds(_state_ops(ns, 'solve_stat'), 1, 'stat_asbr')[-1])
        assert f"redistribute static metric-type 1 metric {data.far_metric}" in lines

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = _state_ops(ns, 'final')
        for site in PARTS:
            for (step, m), op_list in _state_ops(ns, f"solve_{site}").items():
                if step == 1:
                    assert [str(o) for o in op_list] == _cmds(final, 1, m), (site, m)
        waits = {m for (step, m) in final if step == 2}
        assert waits == {m for site in PARTS for m in ns.wait_conditions(site)}


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ns = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert _totals(grade) == (0, 0), {t: g for t, (g, _m) in _grades(grade).items() if g}

    def test_nothing_done_just_after_the_start(self, lab, data, tmp_pub_dir):
        """An evaluation a few seconds after the start (dual_b2 still routes dual_lan3 by RIP) gives
        nothing either."""
        grade, _ns = _simulate(lab, data, tmp_pub_dir, features={'dual_early'}, answers=None)
        assert _totals(grade) == (0, 0), {t: g for t, (g, _m) in _grades(grade).items() if g}

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ns = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (REGULAR, BONUS)
        assert _parts(grade) == POINTS

    @pytest.mark.parametrize('part', list(PARTS))
    def test_a_part_alone(self, lab, data, tmp_pub_dir, part):
        grade, _ns = _simulate(lab, data, tmp_pub_dir, features=PARTS[part], answers='final')
        parts = _parts(grade)
        expected = {p: (POINTS[p] if p == part else FORM_POINTS.get(p, 0)) for p in PARTS}
        assert parts == expected

    @pytest.mark.parametrize('part', list(PARTS))
    def test_everything_but_a_part(self, lab, data, tmp_pub_dir, part):
        grade, _ns = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - PARTS[part], answers=None)
        parts = _parts(grade)
        expected = {p: (0 if p == part else POINTS[p] - FORM_POINTS.get(p, 0)) for p in PARTS}
        assert parts == expected

    def test_every_data_set(self, lab, tmp_pub_dir):
        for _ in range(5):
            d = lab.Data.generate()
            d.compute_post_generate()
            grade, _ns = _simulate(lab, d, tmp_pub_dir)
            assert _totals(grade) == (REGULAR, BONUS)

    def test_scopes_and_bonus(self, lab, data, tmp_pub_dir):
        grade, _ns = _simulate(lab, data, tmp_pub_dir)
        for e in grade.get_grade_list():
            assert e.bonus == (str(e.grade_part) in BONUS_PARTS), e.title
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICE_ELEMENTS), e.title

    @pytest.mark.parametrize('features, lost', [
        (ALL_FEATURES | {'flushing'}, set()),
        (ALL_FEATURES | {'stat_leak'}, {'stat_filter'}),
        (ALL_FEATURES - {'stat_kernel'}, {'stat_kernel'}),
        (ALL_FEATURES - {'stat_default'}, {'stat_default', 'stat_ping'}),
        (ALL_FEATURES - {'mut_connected'}, {'mut_ospf_link', 'mut_rip_link'}),
        (ALL_FEATURES - {'dual_distance'}, {'dual_redundant', 'dual_tag_rip', 'dual_paths', 'dual_no_return_ospf',
                                            'dual_ping'}),
        (ALL_FEATURES - {'dual_tags'}, {'dual_tag_rip', 'dual_tag_ospf', 'dual_no_return_rip', 'dual_no_return_ospf'}),
        # just after the start, before OSPF converges: dual_b2 has only its RIP route (seen live)
        (ALL_FEATURES - {'dual_b2'} | {'dual_early'}, {'dual_redundant', 'dual_tag_rip', 'dual_no_return_ospf',
                                                       'dual_paths', 'dual_ping'}),
        (ALL_FEATURES - {'dual_tags', 'dual_distance'}, {'dual_redundant', 'dual_tag_rip', 'dual_tag_ospf',
                                                          'dual_paths', 'dual_no_return_rip', 'dual_no_return_ospf',
                                                          'dual_ping'}),
        (ALL_FEATURES | {'edge_export_unfiltered'}, {'edge_export_only'}),
        (ALL_FEATURES | {'edge_bgp_unfiltered'}, {'edge_partner_only'}),
        (ALL_FEATURES - {'edge_default'}, {'edge_default', 'edge_ping'}),
        (ALL_FEATURES - {'fix_seed'}, {'fix_seed', 'fix_ping'}),
        (ALL_FEATURES - {'fix_connected'}, {'fix_connected', 'fix_ping'}),
    ])
    def test_partial_work(self, lab, data, tmp_pub_dir, features, lost):
        grade, _ns = _simulate(lab, data, tmp_pub_dir, features=features)
        assert _lost(grade) == lost

    def test_answers_only_and_wrong_answers(self, lab, data, tmp_pub_dir):
        answers_only, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _totals(wrong) == (REGULAR - sum(FORM_POINTS.values()), BONUS)

    def test_other_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        for spelling in ('incomplete', ' Incomplete ', 'incomplet.'):
            cheat = dict(grade.get_cheat_answers('final'))
            for q in forms:
                stored = cheat[q.question_hash]
                answers = dict(json.loads(stored) if isinstance(stored, str) else stored)
                if 'origin' in answers:
                    answers['origin'] = spelling
                for key in ('cost_far', 'rip_metric', 'med', 'metric_before'):
                    if key in answers:
                        answers[key] = f" {answers[key]} "
                cheat[q.question_hash] = json.dumps(answers) if isinstance(stored, str) else answers
            grade2, _ = _simulate_with_answers(lab, data, tmp_pub_dir, cheat)
            assert _totals(grade2) == (REGULAR, BONUS), spelling

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == len(FORM_POINTS)
        for state in ['final'] + [f"solve_{p}" for p in PARTS]:
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
        assert len(grade.get_cheat_answers('final')) == len(FORM_POINTS)
        for p in PARTS:
            cheat = grade.get_cheat_answers(f"solve_{p}")
            assert (len(cheat or {}) == 1) == (p in FORM_POINTS), p


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


QUESTIONS = 14     # organisation + 2 per regular part + 1 per bonus
FIELDS = ['cost_far', 'dist_ospf', 'dist_kernel', 'kernel', 'default', 'rip_metric', 'ospf_cost', 'seed_rip',
          'seed_ospf', 'connected', 'nexthop', 'dist_chosen', 'dist_rip', 'loop', 'tags', 'origin', 'med', 'table',
          'network', 'metric_before', 'seed', 'plist', 'static']


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        hashes = [q.question_hash for q in g0.get_questions_ordered()]
        assert hashes == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(hashes) == QUESTIONS and len(set(hashes)) == QUESTIONS
        source = _LAB_PATH.read_text()
        assert len(re.findall(r'\bhash="[0-9a-f]{16}"', source)) == QUESTIONS
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == QUESTIONS and 'informations' not in with_fragment

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
            'principle', 'rib', 'metrics', 'policy', 'sources', 'default', 'multipoint', 'bgp', 'summary', 'nssa',
            'frr', 'diagnostic']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no machine of the lab
        for value in ('Partie 1', 'stat_asbr', 'dual_b2', 'edge_isp', 'fix_b', 'nssa_abr'):
            assert not _mentions(informations, value), value

    def test_the_course_holds_no_value_of_the_instance(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        values = {'asn': 64600, 'lan_metric': 77, 'far_metric': 333, 'mut_metric': 222, 'mut_seed': 4, 'tag_rip': 444,
                  'tag_ospf': 555, 'edge_metric': 111, 'tag_sum': 666}
        values = {k: (v if v != getattr(data, k) else v + 1) for k, v in values.items()}
        other = lab.Data.from_dict({**data.to_dict(), **values})
        other.compute_post_generate()
        ns2 = lab.NetScheme(data=other, running_lab_name=_running_name())
        assert _text(ns.informations) == _text(ns2.informations)

    def test_values_of_the_instance_in_the_questions(self, lab, data, tmp_pub_dir):
        g0, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        questions = [_text(q.description) for q in g0.get_questions_ordered()]
        first = questions[0]
        for value in (f"`{ns.net('stat_l12')}`", f"`{ns.host_ip('mut_h1')}`", f"`mut_b` `{ns.rid('mut_b')}`",
                      f"**{data.asn}**"):
            assert value in first, value
        everything = "\n".join(questions)
        for value in (data.lan_metric, data.far_metric, data.mut_metric, data.mut_seed, data.tag_rip, data.tag_ospf,
                      data.edge_metric, data.tag_sum):
            assert f"**{value}**" in everything, value
        # the faults are for the instructor only
        for value in (str(ns.fix_wrong_nexthop()), 'metric 15'):
            assert not _mentions(everything, value), value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                if 'choices' in field:
                    assert len(field['choices']) == len(set(field['choices'])) == 4, field
                names.append(field['name'])
        assert names == FIELDS

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == len(_instructor_literals()) == QUESTIONS and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        assert b'**For the instructor.**' not in result.data and b'instructor(' not in result.data
        stripped = tmp_path / 'redistribution_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('redistribution_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the English of the instructor texts goes with them, the rest stays
        kept = module._TRANSLATIONS['en']
        assert not set(kept) & set(_instructor_literals())
        assert len(kept) == len(lab._TRANSLATIONS['en']) - len(set(_instructor_literals()))
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (REGULAR, BONUS)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_translations(self, lab, data, tmp_pub_dir):
        """The texts are French with every one translated in _TRANSLATIONS['en'] (the markup kept: checked for
        every lab of the directory by test_draft_misc_translations.py), the instructor texts included."""
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == _tr_literals() and all(english.values())
        assert set(_instructor_literals()) <= set(english)
        assert sum(v.lstrip().startswith(('**Solution.**', '**For the instructor.**'))
                   for v in english.values()) == QUESTIONS
        assert _text(lab.title, 'en') == "Route redistribution: exchanging routes between RIP, OSPF, BGP and static routes"
        assert _text(lab.NetScheme.solve_dual._sre_state_description, 'en') == "Part 3: solution (two points, tags)"
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en) and fr != en, _text(q.title)
            assert '**Solution.**' in en or '**For the instructor.**' in en, _text(q.title)
            # the values built in code read in the language of the text (the site table, the addressing plan,
            # the vtysh blocks of the solutions)
            assert 'à configurer' not in en and ' sans terminal' not in en and '` :\n' not in en, _text(q.title)
            assert "{'" not in en and not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", en), _text(q.title)
            markdown_to_html(en, show_instructor=True)
        organisation = _text(g1.get_questions_ordered()[0].description, 'en')
        assert "| 3 — RIP and OSPF, two redistribution points | `dual_*` |" in organisation
        assert f"| `fix_srv` | `{ns1.net('fix_srv')}` | `lo` of `fix_gw` (`.1`) |" in organisation
        solution = g1.get_questions_ordered()[1].description
        assert "`stat_asbr` :\n\n```\n" in _text(solution, 'fr')
        assert "`stat_asbr`:\n\n```\n" in _text(solution, 'en')

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|voisin|passerelle|serveur|hote|frontiere|'
                            r'depannage|resume|agregation|etiquette)', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_dual' in names and 'agg_isp' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
