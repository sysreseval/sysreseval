"""Offline tests of the policy routing lab (lab/sre/_DRAFT_misc/policy-routing.py): data generation (two
ISPs, six sites, the two customers of the VRF site sharing their prefixes), the routes and the rules given
by `initial` (a default route by ISP1 only, the masquerade of both uplinks, the ingress filter of the
ISPs, a strict reverse-path filter on r3), the reference solution of `final`, the multi-pass grading
contract with synthetic outputs (nothing done: 0, the reference solution: 100 + 6 bonus, each part alone,
each part missing, one mistake at a time, the cheap tricks that must score nothing), the forms and their
cheat answers, the numbered course, the questions and their instructor fragments, the HTML of every text,
the stripped lab file and the English identifiers.

No Docker: a model of the six routers answers the probes as the echo servers, `ip -j`, `nft -j` and
`ping` do, from one flag per piece of work.  The lab gives each part its own router so that the parts are
independent: test_parts_are_independent is the check of that requirement.  The JSON shapes of the model
are those of the fixtures captured live (tests/mock_data/policy_routing, tests/test_policy_routing.py).
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
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import strip_instructor  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'policy-routing.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'policy_routing'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('policy_routing_lab_under_test', _LAB_PATH)
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


def _net_scheme(lab, data):
    return lab.NetScheme(data=data, running_lab_name=_running_name())


def _text(t):
    return t.resolve('fr') if hasattr(t, 'resolve') else str(t)


def _ip(obj):
    return str(obj.ip)


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    return ops


def _cmds(ops, machine, step=1):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, machine, step=1):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str) and hasattr(op, 'filename')}


# ---------------------------------------------------------------------------
# a model of the six sites answering the probes
# ---------------------------------------------------------------------------

#: everything done as the reference solution does it: one flag per piece of work
DONE = {
    'guests': 'tables',        # part 1: None | 'default_only' (a table without the LAN routes) | 'tables'
                               #         | 'swap' (the default route moved to ISP2) | 'dnat' (a NAT trick, no rule)
    'own': 'tables',           # part 2: None | 'default_only' | 'tables' | 'swap'
    'mark': 'prerouting',      # part 3: None | 'prerouting' | 'forward' (marked after the routing decision)
                               #         | 'dport_rule' (ip rule ipproto tcp dport, no mark at all)
    'fwmark_rule': True,
    'rp_filter': 'loose',      # 'strict' (as given) | 'loose'
    'output_chain': 'route',   # None | 'route' | 'filter' (a mark set too late for the router's own packets)
    'connmark': 'ct',          # part 4: None | 'ct' | 'from_server' (ip rule from web4) | 'swap'
    'multipath': 'weighted',   # part 5: None | 'weighted' | 'equal' | 'nhid' (a nexthop group) | 'static'
    'vrf': 'vrfs',             # part 6: None | 'vrfs' | 'addresses' (blue addressed, no VRF) | 'one_vrf'
    'closed': True,            # the `unreachable` default route of the VRF tables
    'l3mdev_accept': True,
    'leak': True,
}
#: a project nobody touched
NOTHING = {'guests': None, 'own': None, 'mark': None, 'fwmark_rule': False, 'rp_filter': 'strict',
           'output_chain': None, 'connmark': None, 'multipath': None, 'vrf': None, 'closed': False,
           'l3mdev_accept': False, 'leak': False}
#: the flags of each part, and what its probes are worth (bonus included, the forms apart)
PARTS = {1: ('guests',), 2: ('own',), 3: ('mark', 'fwmark_rule', 'rp_filter', 'output_chain'), 4: ('connmark',),
         5: ('multipath',), 6: ('vrf', 'closed', 'l3mdev_accept', 'leak')}
PROBE_POINTS = {1: 16, 2: 12, 3: 17, 4: 12, 5: 12, 6: 23}
FORM_POINTS = {1: 4, 2: 2, 3: 4, 4: 2, 5: 0, 6: 2}
BONUS = {'router_flows': 3, 'route_leak': 3}
PART_MAX = {1: 20, 2: 14, 3: 18, 4: 14, 5: 12, 6: 22}             # without the bonus

_CURL = re.compile(r"^curl -s -m \d+ (?:--interface (\S+) )?http://([0-9.]+):(\d+)/$")
_PING = re.compile(r"^ping -n -c 1 -W 1 ([0-9.]+) 2>&1; true$")
REFUSED, TIMEOUT = ("", 7), ("", 28)
_BASE_RULES = [{"priority": 0, "src": "all", "table": "local"}, {"priority": 32766, "src": "all", "table": "main"},
               {"priority": 32767, "src": "all", "table": "default"}]


def _only(*parts):
    """The flags of the given parts done, the others untouched."""
    return {flag: (DONE[flag] if any(flag in PARTS[n] for n in parts) else NOTHING[flag]) for flag in DONE}


def _page(server, server_ip, port, client_ip):
    return (f"SERVER={server}\nSERVER_IP={server_ip}\nSERVER_PORT={port}\nCLIENT_IP={client_ip}\n"
            f"CLIENT_PORT=40000\nTTL=62\n", 0)


def _link(name, up=True, master=None, vrf_table=None):
    link = {"ifname": name, "flags": ["BROADCAST", "MULTICAST"] + (["UP", "LOWER_UP"] if up else []),
            "linkinfo": {"info_kind": "tun"}}
    if master:
        link["master"] = master
    if vrf_table is not None:
        link["linkinfo"] = {"info_kind": "vrf", "info_data": {"table": vrf_table}}
    return link


class Model:
    """What the probes get, from what is done on each router."""

    def __init__(self, lab, d, isp1_down=False, **done):
        assert set(done) <= set(DONE), done
        self.lab, self.done, self.isp1_down = lab, {**NOTHING, **done}, isp1_down
        self.ip = {name: _ip(value) for name, value in vars(d.ips).items()}
        self.pub = {(n, isp): _ip(getattr(d.ips, f"r{n}_acc{isp}")) for n in lab.SITES for isp in lab.ISPS}
        self.gw = {isp: _ip(getattr(d.ips, f"isp{isp}_acc{isp}")) for isp in lab.ISPS}
        self.svc = d.nets.svc

    # -- structure ----------------------------------------------------------------------------

    def default_route(self, isp, table=None):
        route = {"dst": "default", "gateway": self.gw[isp], "dev": self.lab.UPLINK[isp], "flags": []}
        if table:
            route["table"] = table
        return route

    def rules(self, router):
        rules = list(_BASE_RULES)
        if router == 'r3':
            if self.done['fwmark_rule']:
                rules.insert(1, {"priority": 1000, "src": "all", "fwmark": "0x2", "table": "102"})
            if self.done['mark'] == 'dport_rule':
                rules.insert(1, {"priority": 900, "src": "all", "ipproto": "tcp", "dport": 8080, "table": "102"})
        return json.dumps(rules)

    def route_tables(self, router):
        routes = []
        if router == 'r3':
            if self.done['fwmark_rule'] or self.done['mark'] == 'dport_rule':
                routes.append(self.default_route(2, table="102"))
            routes.append(self.default_route(1))
        elif router == 'r5':
            hops = [{"gateway": self.gw[isp], "dev": self.lab.UPLINK[isp], "weight": weight, "flags": []}
                    for isp, weight in ((1, 3), (2, 1))]
            kind = self.done['multipath']
            if kind in ('weighted', 'nhid'):
                routes.append({"dst": "default", "flags": [], "nexthops": hops, **({"nhid": 10} if kind == 'nhid' else {})})
            elif kind == 'equal':
                routes.append({"dst": "default", "flags": [], "nexthops": [dict(hop, weight=1) for hop in hops]})
            else:
                routes.append(self.default_route(1))
                if kind == 'static':
                    low, high = list(self.svc.subnets(new_prefix=27))[:2]
                    routes += [{"dst": str(low), "gateway": self.gw[1], "dev": "eth1", "flags": []},
                               {"dst": str(high), "gateway": self.gw[2], "dev": "eth2", "flags": []}]
        return json.dumps(routes)

    def nft_json(self, router):
        """`nft -j list ruleset` of r3: the given NAT table and the marks."""
        assert router == 'r3'
        objects = [{"metainfo": {"version": "1.0.6", "json_schema_version": 1}},
                   {"table": {"family": "ip", "name": "nat", "handle": 1}},
                   {"table": {"family": "ip", "name": "mangle", "handle": 2}}]

        def chain(name, kind, hook, match):
            return [{"chain": {"family": "ip", "table": "mangle", "name": name, "handle": 1, "type": kind, "hook": hook,
                               "prio": -150, "policy": "accept"}},
                    {"rule": {"family": "ip", "table": "mangle", "chain": name, "handle": 2, "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": match[0]}}, "right": match[1]}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}},
                        {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 2}}]}}]

        if self.done['mark'] in ('prerouting', 'forward'):
            objects += chain(self.done['mark'], 'filter', self.done['mark'], ("iifname", "eth0"))
        if self.done['output_chain']:
            objects += chain('output', self.done['output_chain'], 'output', ("oifname", "eth1"))
        return json.dumps({"nftables": objects})

    def links(self, machine):
        if machine == 'isp1':
            return json.dumps([_link('lo'), _link('eth0', up=not self.isp1_down), _link('eth1')])
        assert machine == 'r6'
        kind = self.done['vrf']
        if kind == 'vrfs':
            master = {'eth0': 'vrf-blue', 'eth1': 'vrf-blue', 'eth2': 'vrf-red', 'eth3': 'vrf-red'}
            devices = [_link('vrf-blue', vrf_table=10), _link('vrf-red', vrf_table=20)]
        elif kind == 'one_vrf':
            master = dict.fromkeys(('eth0', 'eth1', 'eth2', 'eth3'), 'vrf-all')
            devices = [_link('vrf-all', vrf_table=10)]
        else:
            master, devices = {}, []
        return json.dumps([_link('lo')] + devices + [_link(f"eth{i}", master=master.get(f"eth{i}")) for i in range(5)])

    # -- probes -------------------------------------------------------------------------------

    def third_way(self):
        """How the marked flow of pc3 fares: 'isp2', 'dropped' (replies lost) or 'isp1'."""
        done = self.done
        if done['mark'] == 'dport_rule':
            return 'isp2'                                     # the reverse lookup swaps the ports too
        if done['mark'] == 'prerouting' and done['fwmark_rule']:
            return 'isp2' if done['rp_filter'] == 'loose' else 'dropped'
        return 'isp1'

    def curl(self, src, source, target, port):
        done, ip, pub = self.done, self.ip, self.pub
        www = ip['www']
        key = (src, target, port)
        # part 1
        if key == ('pc1b', www, 80):
            if done['guests'] == 'dnat':
                return _page('www', str(self.svc.network_address + 9), 80, pub[1, 2])
            return _page('www', www, 80, pub[1, 2] if done['guests'] else pub[1, 1])
        if key in (('pc1a', www, 80), ('r1', www, 80)):
            return _page('www', www, 80, pub[1, 2] if done['guests'] == 'swap' else pub[1, 1])
        if key == ('pc1b', ip['pc1a'], 80):
            return TIMEOUT if done['guests'] == 'default_only' else _page('pc1a', ip['pc1a'], 80, ip['pc1b'])
        # part 2
        if key == ('www', pub[2, 2], 80):
            return _page('r2', pub[2, 2], 80, www) if done['own'] else TIMEOUT
        if key == ('www', pub[2, 1], 80):
            return TIMEOUT if done['own'] == 'swap' else _page('r2', pub[2, 1], 80, www)
        if key == ('r2', www, 80) and source == pub[2, 2]:
            return _page('www', www, 80, pub[2, 2] if done['own'] else pub[2, 1])        # masqueraded on eth1
        if key == ('r2', www, 80):
            assert source is None
            return _page('www', www, 80, pub[2, 2] if done['own'] == 'swap' else pub[2, 1])
        if key == ('pc2', pub[2, 2], 80):
            return TIMEOUT if done['own'] == 'default_only' else _page('r2', pub[2, 2], 80, ip['pc2'])
        # part 3
        if key == ('pc3', www, 8080):
            way = self.third_way()
            return TIMEOUT if way == 'dropped' else _page('www', www, 8080, pub[3, 2 if way == 'isp2' else 1])
        if key in (('pc3', www, 80), ('r3', www, 80)):
            return _page('www', www, 80, pub[3, 1])
        if key == ('r3', www, 8080):
            if done['mark'] == 'dport_rule':
                return _page('www', www, 8080, pub[3, 2])
            if done['output_chain'] == 'route' and done['fwmark_rule']:
                return _page('www', www, 8080, pub[3, 2]) if done['rp_filter'] == 'loose' else TIMEOUT
            return _page('www', www, 8080, pub[3, 1])
        # part 4
        if key == ('www', pub[4, 2], 8080):
            return _page('web4', ip['web4'], 80, www) if done['connmark'] else TIMEOUT
        if key == ('www', pub[4, 1], 8080):
            return TIMEOUT if done['connmark'] in ('from_server', 'swap') else _page('web4', ip['web4'], 80, www)
        if key == ('web4', www, 80):
            return _page('www', www, 80, pub[4, 2] if done['connmark'] in ('from_server', 'swap') else pub[4, 1])
        # part 6
        vrf = done['vrf']
        if key == ('blue1', ip['blue2'], 80):
            return _page('blue2', ip['blue2'], 80, ip['blue1']) if vrf else TIMEOUT
        if key == ('red1', ip['blue2'], 80):
            if vrf == 'vrfs':
                return _page('red2', ip['red2'], 80, ip['red1'])
            return _page('blue2', ip['blue2'], 80, ip['blue1']) if vrf == 'one_vrf' else TIMEOUT
        if key in (('blue1', ip['r6_blue_a'], 80), ('red1', ip['r6_blue_a'], 80)):
            served = (vrf == 'vrfs' and done['l3mdev_accept']) or (vrf == 'addresses' and src == 'blue1')
            return _page('r6', ip['r6_blue_a'], 80, ip['blue1']) if served else (REFUSED if vrf else TIMEOUT)
        if key == ('admin', ip['blue1'], 80):
            reached = (vrf == 'vrfs' and done['leak']) or vrf == 'addresses'
            return _page('blue1', ip['blue1'], 80, ip['admin']) if reached else TIMEOUT
        raise AssertionError(f"unexpected probe {key} (source {source})")

    def spread(self):
        """The 64 pages of the multipath probe: who answered, under which client address."""
        kind, pages = self.done['multipath'], []
        for i in range(1, self.lab.SPREAD + 1):
            if kind in ('weighted', 'equal', 'nhid'):
                isp = 2 if i % 4 == 0 else 1
            elif kind == 'static':
                isp = 1 if i < 32 else 2
            else:
                isp = 1
            pages.append(_page('www', str(self.svc.network_address + i), 80, self.pub[5, isp])[0])
        return "".join(pages), 0

    def ping(self, src, target):
        assert (src, target) == ('red1', self.ip['admin'])
        if self.done['vrf'] == 'vrfs' and self.done['closed']:
            return ((_MOCK / 'ping_red1_unreachable.txt').read_text()
                    .replace('172.28.126.1', self.ip['r6_red_a']).replace('10.56.195.10', target)), 0
        return (_MOCK / 'ping_red1_silent.txt').read_text().replace('10.56.195.10', target), 0

    def __call__(self, machine, command):
        m = _CURL.match(command)
        if m:
            return self.curl(machine, m.group(1), m.group(2), int(m.group(3)))
        m = _PING.match(command)
        if m:
            return self.ping(machine, m.group(1))
        if command.startswith("seq 1 "):
            assert machine == 'pc5' and command == f"seq 1 64 | xargs -P 8 -I {{}} curl -s -m 3 http://" \
                                                   f"{str(self.svc.network_address).rsplit('.', 1)[0]}.{{}}:80/"
            return self.spread()
        if command == "ip -j rule 2>/dev/null":
            return self.rules(machine), 0
        if command == "ip -j route show table all 2>/dev/null":
            return self.route_tables(machine), 0
        if command == "nft -j list ruleset":
            return self.nft_json(machine), 0
        if command == "ip -j -d link show":
            return self.links(machine), 0
        # the diagnostics kept in the archive
        assert command in ("ip -4 -br addr", "ip rule", "ip route show table all", "nft list ruleset",
                           "nft list table ip bcp38"), (machine, command)
        return "", 0


def _simulate(lab, data, tmp_pub_dir, done, instructor_mode=False, cheat=True, **model_options):
    """Multi-pass grade() like run_tests(), the probes answered by the model of *done*: returns (grade, net_scheme)."""
    model = Model(lab, data, **model_options, **done)
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    registered = None
    while grade.step <= grade.max_step:
        grade.reset_before_grade()
        grade.grade()
        current = {key: set(cmds) for key, cmds in grade.get_tests().items()}
        if registered is None:
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == registered, "the registered tests changed between two passes"
        registered = current
        grade.step += 1
        for (machine, step), cmds in grade.get_tests().items():
            if step == grade.step:
                for key in list(cmds):
                    cmds[key] = model(machine, key[0])
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _total(grade):
    return sum(e.grade for e in grade.get_grade_list())


def _part(grade, n):
    return sum(e.grade for e in grade.get_grade_list() if str(e.grade_part) == f'part{n}')


def _lost(grade):
    """{element: points missing} for the elements short of their maximum."""
    return {title: max_grade - got for title, (got, max_grade) in _grades(grade).items() if got != max_grade}


# ---------------------------------------------------------------------------
# data, topology, routes
# ---------------------------------------------------------------------------


def test_data_and_topology(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    machines = sorted(ns.get_machine_names())
    assert len(machines) == 21 and not any(spec.get('hidden') for spec in lab._SPECS.values())
    assert machines == sorted(['isp1', 'isp2', 'www', 'ext', 'admin', 'blue1', 'blue2', 'red1', 'red2']
                              + [f"r{n}" for n in range(1, 7)] + list(lab.LAN_HOST.values()))
    # the ISPs and www have no terminal; ext is the students' Internet client
    assert [m for m, spec in lab._SPECS.items() if spec.get('allow_connection') is False] == ['isp1', 'isp2', 'www']
    # every site router: eth0 = LAN, eth1 = ISP1, eth2 = ISP2
    for n in lab.SITES:
        assert lab._TOPOLOGY['acc1'][f'r{n}'] == 1 and lab._TOPOLOGY['acc2'][f'r{n}'] == 2
        assert any(lab._TOPOLOGY[lan][f'r{n}'] == 0 for lan in lab.SITE_LANS[n].values())
    assert lab._TOPOLOGY['lan1b'] == {'r1': 3, 'pc1b': 0}
    assert {net: members['r6'] for net, members in lab._TOPOLOGY.items() if 'r6' in members} == \
        {'blue_a': 0, 'blue_b': 1, 'red_a': 2, 'red_b': 3, 'mgmt': 4}
    # the access networks and the core are switches, the LANs hubs
    modes = {net: spec.get('mode') for net, spec in lab.NetScheme._network_specs.items()}
    assert {net for net, mode in modes.items() if mode == 'switch'} == {'core', 'acc1', 'acc2'}
    assert set(modes.values()) == {'switch', None}
    # the Internet is visibly not private; the LANs are private and distinct
    public = [data.nets.core, data.nets.acc1, data.nets.acc2, data.nets.svc]
    assert all(net.subnet_of(lab.INTERNET_RANGE) and net.prefixlen == 24 for net in public)
    private = [getattr(data.nets, lan) for lan in lab.LAN_HOST] + [data.nets.mgmt, data.nets.blue_a, data.nets.blue_b]
    assert all(net.is_private and net.prefixlen == 24 for net in private)
    everything = public + private
    assert all(not a.overlaps(b) for i, a in enumerate(everything) for b in everything[i + 1:])
    # the two customers of part 6 share their prefixes and their addresses
    assert data.nets.red_a == data.nets.blue_a and data.nets.red_b == data.nets.blue_b
    assert data.ips.red1 == data.ips.blue1 and data.ips.red2 == data.ips.blue2
    assert data.ips.r6_red_a == data.ips.r6_blue_a and data.ips.r6_red_b == data.ips.r6_blue_b
    # readable host parts: rN is .1N on both access networks, the ISP .1
    for n in lab.SITES:
        for isp in lab.ISPS:
            assert _ip(getattr(data.ips, f"r{n}_acc{isp}")).endswith(f".{10 + n}")
    assert _ip(data.ips.isp1_acc1).endswith('.1') and _ip(data.ips.isp2_acc2).endswith('.1')
    assert str(ns.svc_ip(64)).endswith('.64') and ns.svc_ip(1) in data.nets.svc
    # the data survives its JSON round trip
    assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
    # no save / restore: the work is kernel state
    assert not getattr(lab, 'allow_save_restore', False) and lab.allow_user_states is True


def test_initial_routes(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    default = IPv4Network('0.0.0.0/0')
    config = ns.net_config

    def routes(machine):
        return [route for interface in config[machine] if interface for route in interface[1]]

    assert set(config) == set(ns.get_machine_names())
    # a site router: one default route, by ISP1; its host: a default route by the router
    for n in lab.SITES:
        assert routes(f"r{n}") == [(default, data.ips.isp1_acc1)]
        for lan in lab.SITE_LANS[n].values():
            assert routes(lab.LAN_HOST[lan]) == [(default, getattr(data.ips, f"r{n}_{lan}"))]
    # the Internet knows the public networks only (never a private LAN)
    for machine in ('isp1', 'isp2', 'www', 'ext'):
        assert all(net.subnet_of(lab.INTERNET_RANGE) for net, _ in routes(machine)), machine
    assert routes('www') == [(data.nets.acc1, data.ips.isp1_core), (data.nets.acc2, data.ips.isp2_core)]
    assert routes('ext') == routes('www') + [(data.nets.svc, data.ips.www)]
    assert (data.nets.svc, data.ips.www) in routes('isp1') and (data.nets.acc2, data.ips.isp2_core) in routes('isp1')
    assert (data.nets.svc, data.ips.www) in routes('isp2') and (data.nets.acc1, data.ips.isp1_core) in routes('isp2')
    # r6: the customers' ports are up without an address, the management port is addressed
    assert config['r6'] == [([], [])] * 4 + [([data.ips.r6_mgmt], [])]
    for host in ('blue1', 'red1'):
        assert config[host] == [([data.ips.blue1], [(default, data.ips.r6_blue_a)])]


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


def test_initial_ops(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    ops = _state_ops(ns, 'initial')
    assert {step for step, _ in ops} == {1} and len({m for _, m in ops}) == 21
    # forwarding on the routers and the ISPs only
    for machine in ns.get_machine_names():
        forward = [c for c in _cmds(ops, machine) if 'ip_forward' in c and c.startswith('sysctl')]
        assert forward == [f"sysctl -w net.ipv4.ip_forward={int(machine in lab.FORWARDERS)}"], machine
    # the reverse-path filter is written everywhere it could come from: strict on r3, off elsewhere
    for machine in lab.FORWARDERS:
        values = {c.split('=')[0].split('.')[-2]: c.split('=')[1] for c in _cmds(ops, machine) if 'rp_filter' in c}
        assert set(values) == {'all', 'default'} | set(ns.interfaces(machine)), machine
        assert set(values.values()) == {'1' if machine == 'r3' else '0'}, machine
    # the ISPs drop what does not carry one of their addresses
    for isp in lab.ISPS:
        conf = _files(ops, f"isp{isp}")[lab.CONF_FILE]
        assert f'iifname "eth0" ip saddr != {getattr(data.nets, f"acc{isp}")} counter drop' in conf
        assert f"nft -f {lab.CONF_FILE}" in _cmds(ops, f"isp{isp}")
    # the site routers masquerade on both uplinks, whatever the source; r4 forwards a port on both
    for n in lab.SITES:
        conf = _files(ops, f"r{n}")[lab.CONF_FILE]
        assert conf == ns.given_conf(f"r{n}") and conf.startswith("#!/usr/sbin/nft -f\nflush ruleset\n")
        assert 'oifname "eth1" masquerade' in conf and 'oifname "eth2" masquerade' in conf and 'saddr' not in conf
        assert ('dnat to' in conf) == (n == 4) and 'mangle' not in conf
        assert f"nft -f {lab.CONF_FILE}" in _cmds(ops, f"r{n}")
    assert f'iifname {{ "eth1", "eth2" }} tcp dport 8080 dnat to {_ip(data.ips.web4)}:80' in _files(ops, 'r4')[lab.CONF_FILE]
    assert lab.CONF_FILE not in _files(ops, 'r6')
    # www owns the whole prefix svc; the echo servers
    assert f"ip route replace local {data.nets.svc} dev lo" in _cmds(ops, 'www')
    servers = {m: [c for c in _cmds(ops, m) if 'sre_server_echo.py' in c] for m in ns.get_machine_names()}
    assert {m for m, started in servers.items() if started} == \
        {'www', 'pc1a', 'r2', 'web4', 'blue1', 'blue2', 'red1', 'red2', 'r6', 'admin'}
    assert servers['www'][0].endswith("sre_server_echo.py www 80 8080'")
    assert all(started[0].endswith(f"sre_server_echo.py {m} 80'") for m, started in servers.items()
               if started and m != 'www')
    # www and ext are known names on the Internet side only
    for machine in ns.get_machine_names():
        hosts = _files(ops, machine).get('/etc/hosts')
        assert (hosts is not None) == (machine not in lab.VRF_SITE), machine
        if hosts:
            assert _ip(data.ips.www) in hosts and _ip(data.ips.ext) in hosts
    # nothing of the solution is given
    everything = " ".join(c for m in ns.get_machine_names() for c in _cmds(ops, m))
    assert 'ip rule' not in everything and ' table ' not in everything and 'vrf' not in everything


def test_final_ops(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    ops = _state_ops(ns, 'final')
    assert {m for _, m in ops} == set(lab.ROUTERS) | {'r6'}
    g1, g2 = _ip(data.ips.isp1_acc1), _ip(data.ips.isp2_acc2)
    for n in lab.SITES:
        router = f"r{n}"
        assert _files(ops, router)[lab.CONF_FILE] == ns.reference_conf(router)
        assert ns.reference_conf(router).startswith(ns.given_conf(router))       # the given rules are kept
        cmds = _cmds(ops, router)
        assert f"nft -f {lab.CONF_FILE}" in cmds
        # may be applied twice: routes replaced, rules deleted before being added
        assert all(c.startswith(('nft -f', 'ip route replace', 'ip rule del', 'test -w', 'sysctl -w')) for c in cmds), cmds
        for rule in ns.reference_rules(router):
            assert f"ip rule del {rule} 2>/dev/null; ip rule add {rule}" in cmds
    r1, r2, r3, r4, r5 = (_cmds(ops, f"r{n}") for n in lab.SITES)
    assert f"ip route replace default via {g2} dev eth2 table 102" in r1
    assert f"ip route replace {data.nets.lan1a} dev eth0 table 102" in r1
    assert f"ip route replace {data.nets.lan1b} dev eth3 table 102" in r1
    assert any(f"ip rule add from {data.nets.lan1b} lookup 102" in c for c in r1)
    assert f"ip route replace default via {g1} dev eth1 table 101" in r2
    assert any(f"ip rule add from {_ip(data.ips.r2_acc2)} lookup 102" in c for c in r2)
    assert any(f"ip rule add from {_ip(data.ips.r2_acc1)} lookup 101" in c for c in r2)
    assert f"ip route replace {data.nets.lan2} dev eth0 table 101" in r2
    assert any("ip rule add fwmark 2 lookup 102" in c for c in r3) and "sysctl -w net.ipv4.conf.eth2.rp_filter=2" in r3
    assert 'iifname "eth0" tcp dport 8080 meta mark set 2' in ns.reference_conf('r3')
    assert 'type route hook output priority mangle' in ns.reference_conf('r3')
    assert 'type route' not in ns.mangle_table('r3', bonus=False)
    assert 'iifname "eth2" ct state new ct mark set 2' in ns.reference_conf('r4')
    assert 'iifname "eth0" ct mark 2 meta mark set ct mark' in ns.reference_conf('r4')
    assert any("ip rule add fwmark 2 lookup 102" in c for c in r4)
    assert f"ip route replace default nexthop via {g1} dev eth1 weight 3 nexthop via {g2} dev eth2 weight 1" in r5
    assert ns.mangle_table('r1') == ns.mangle_table('r5') == ''
    r6 = _cmds(ops, 'r6')
    assert "ip link show vrf-blue >/dev/null 2>&1 || ip link add vrf-blue type vrf table 10" in r6
    assert "ip link set eth0 master vrf-blue" in r6 and "ip link set eth3 master vrf-red" in r6
    assert f"ip addr replace {data.ips.r6_blue_a} dev eth0" in r6 and f"ip addr replace {data.ips.r6_red_a} dev eth2" in r6
    assert "ip route replace unreachable default metric 4278198272 table 20" in r6
    assert f"ip route replace {data.nets.blue_a} dev vrf-blue" in r6
    assert f"ip route replace {data.nets.mgmt} dev eth4 table 10" in r6
    assert "sysctl -w net.ipv4.tcp_l3mdev_accept=1" in r6
    # the commands shown to the instructor are the plain ones
    shown = ns.reference_commands('r6')
    assert "ip link add vrf-blue type vrf table 10" in shown and not any('||' in c or 'replace' in c for c in shown)
    assert ns.vrf_commands(leak=False) == shown[:-3]            # the two leak routes, then the sysctl
    assert ns.reference_commands('r5') == ns.reference_routes('r5')


def test_failure_states(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    assert _cmds(_state_ops(ns, 'isp1_down'), 'isp1') == ["ip link set eth0 down"]
    assert _cmds(_state_ops(ns, 'isp1_up'), 'isp1') == ["ip link set eth0 up"]
    states = {name: value for name, value in vars(lab.NetScheme).items() if getattr(value, '_is_sre_state', False)}
    assert sorted(states) == ['final', 'initial', 'isp1_down', 'isp1_up']
    assert {name for name, value in states.items() if value._sre_state_user_allowed} == {'isp1_down', 'isp1_up'}
    assert all(_text(states[name]._sre_state_description) for name in ('isp1_down', 'isp1_up'))


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, NOTHING, cheat=False)
    elements = grade.get_grade_list()
    assert all(e.grade == 0 for e in elements) and len(elements) == 27 and grade.max_step == 1
    assert {str(e.title): e.max_grade for e in elements if e.bonus} == BONUS
    assert sum(e.max_grade for e in elements if not e.bonus) == 100
    assert [str(p.title) for p in grade.get_grade_parts()] == [f'part{n}' for n in PARTS]
    assert {n: sum(e.max_grade for e in elements if str(e.grade_part) == f'part{n}' and not e.bonus)
            for n in PARTS} == PART_MAX
    forms = {str(e.title) for e in elements if str(e.title).startswith('q_')}
    assert {n: sum(e.max_grade for e in elements if str(e.grade_part) == f'part{n}' and str(e.title) in forms)
            for n in PARTS} == FORM_POINTS
    assert not grade.get_errors()
    # the probes: a curl per question asked, never the same command twice on a machine
    tests = grade.get_tests()
    assert {step for _, step in tests} == {1}
    probes = {m: [cmd for cmd, _ in cmds if cmd.startswith('curl')] for (m, _), cmds in tests.items()}
    assert {m: len(cmds) for m, cmds in probes.items() if cmds} == {
        'pc1a': 1, 'pc1b': 2, 'r1': 1, 'www': 4, 'r2': 2, 'pc2': 1, 'pc3': 2, 'r3': 2, 'web4': 1, 'blue1': 2,
        'red1': 2, 'admin': 1}
    assert 'ext' not in {m for m, _ in tests}                   # the students' client is never used
    # the spread probe has its own, longer, time-out
    spread = [(cmd, timeout) for cmd, timeout in tests[('pc5', 1)] if cmd.startswith('seq')]
    assert len(spread) == 1 and spread[0][1] == lab.SPREAD_TIMEOUT


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE)
    assert not _lost(grade) and _total(grade) == 106 and not grade.get_errors()
    assert {n: _part(grade, n) for n in PARTS} == {n: PROBE_POINTS[n] + FORM_POINTS[n] for n in PARTS}
    # the probes alone, without the forms
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE, cheat=False)
    assert {n: _part(grade, n) for n in PARTS} == PROBE_POINTS
    # a nexthop group is a multipath route like another
    grade, _ = _simulate(lab, data, tmp_pub_dir, {**DONE, 'multipath': 'nhid'})
    assert not _lost(grade)


@pytest.mark.parametrize('n', sorted(PARTS))
def test_parts_are_independent(lab, data, tmp_pub_dir, n):
    """A part done alone gives all its points; left out alone, it costs its points and no others."""
    others = [m for m in PARTS if m != n]
    grade, _ = _simulate(lab, data, tmp_pub_dir, _only(n), cheat=False)
    assert _part(grade, n) == PROBE_POINTS[n] and all(_part(grade, m) == 0 for m in others)
    grade, _ = _simulate(lab, data, tmp_pub_dir, _only(*others), cheat=False)
    assert _part(grade, n) == 0 and all(_part(grade, m) == PROBE_POINTS[m] for m in others)
    # with the forms: the whole part, and nothing of the others but their forms
    grade, _ = _simulate(lab, data, tmp_pub_dir, _only(n))
    assert _part(grade, n) == PROBE_POINTS[n] + FORM_POINTS[n]
    assert all(_part(grade, m) == FORM_POINTS[m] for m in others)


@pytest.mark.parametrize('change, lost', [
    # part 1: a table without the LAN routes cuts the two LANs from each other, nothing else
    ({'guests': 'default_only'}, {'lans_joined': 4}),
    # part 2: the same trap, seen from the LAN of the router
    ({'own': 'default_only'}, {'lan_kept': 2}),
    # part 3: the mark and the rule are there, the strict filter still drops the replies
    ({'rp_filter': 'strict'}, {'flows_split': 10, 'router_flows': 3}),
    ({'mark': 'forward'}, {'mark_routing': 4, 'flows_split': 10, 'router_flows': 3}),
    ({'fwmark_rule': False}, {'mark_routing': 4, 'flows_split': 10, 'router_flows': 3}),
    ({'output_chain': None}, {'router_flows': 3}),
    ({'output_chain': 'filter'}, {'router_flows': 3}),
    # part 5
    ({'multipath': 'equal'}, {'weights': 3}),
    # part 6
    ({'closed': False}, {'tables_closed': 3, 'route_leak': 3}),
    ({'l3mdev_accept': False}, {'router_service': 3}),
    ({'leak': False}, {'route_leak': 3}),
])
def test_one_thing_wrong(lab, data, tmp_pub_dir, change, lost):
    grade, _ = _simulate(lab, data, tmp_pub_dir, {**DONE, **change})
    assert _lost(grade) == lost


@pytest.mark.parametrize('trick, part', [
    ({'guests': 'swap'}, 1),             # the default route moved to ISP2: the staff leaves by ISP2 too
    ({'guests': 'dnat'}, 1),             # www reached at another of its addresses, routed by ISP2
    ({'own': 'swap'}, 2),                # ISP2 answers, ISP1 no longer does
    ({'mark': 'dport_rule', 'fwmark_rule': False, 'output_chain': None}, 3),     # ip rule ipproto tcp dport: no mark
    ({'connmark': 'from_server'}, 4),    # everything web4 sends by ISP2
    ({'connmark': 'swap'}, 4),
    ({'multipath': 'static'}, 5),        # two static routes splitting the destinations
    ({'vrf': 'addresses', 'closed': False, 'l3mdev_accept': False, 'leak': False}, 6),   # no VRF at all
    ({'vrf': 'one_vrf'}, 6),             # both customers in one VRF
])
def test_cheap_tricks_score_nothing(lab, data, tmp_pub_dir, trick, part):
    """What passes a single probe without the intended mechanism is worth nothing, alone or among the
    other parts done."""
    grade, _ = _simulate(lab, data, tmp_pub_dir, {**NOTHING, **trick}, cheat=False)
    assert _total(grade) == 0, _grades(grade)
    grade, _ = _simulate(lab, data, tmp_pub_dir, {**DONE, **trick}, cheat=False)
    assert _part(grade, part) == 0 and all(_part(grade, n) == PROBE_POINTS[n] for n in PARTS if n != part)


def test_isp1_cut_is_reported(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE, isp1_down=True)
    errors = grade.get_errors()
    assert len(errors) == 1 and errors[0][0] == 'WARNING' and 'isp1_up' in _text(errors[0][1])
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE)
    assert not grade.get_errors()


# ---------------------------------------------------------------------------
# forms
# ---------------------------------------------------------------------------

#: the form of each question: its fields, in order
_FORMS = {
    '1.1.': ['prio_main', 'table_local'],
    '2.1.': ['reply_if', 'dropper'],
    '3.2.': ['dropper', 'loose'],
    '4.1.': ['reply_source'],
    '6.2.': ['l3mdev_prio'],
}


def _forms(grade):
    return {_text(q.title).split(' ')[0]: q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)}


def test_cheat_answers_fill_every_form(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE)
    cheat = grade.get_cheat_answers('final')
    forms = _forms(grade)
    assert {number: [f['name'] for f in q.fields] for number, q in forms.items()} == _FORMS
    first_choice = 0
    for q in forms.values():
        answers = cheat[q.question_hash]
        answers = json.loads(answers) if isinstance(answers, str) else answers
        assert set(answers) == {f['name'] for f in q.fields}
        for f in q.fields:
            value = answers[f['name']]
            assert isinstance(value, str)
            if 'choices' in f:
                assert value in f['choices'], (f['name'], value)
                first_choice += f['choices'][0] == value
            else:
                assert re.fullmatch(f['regex'], value), (f['name'], value)
    assert first_choice == 0          # an untouched dropdown shows its first option: never the right answer


def test_form_answers(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, NOTHING)
    forms = _forms(grade)

    def regrade(number, **changes):
        q = forms[number]
        answers = json.loads(grade._answers[q.question_hash])
        answers.update(changes)
        grade._answers[q.question_hash] = json.dumps(answers)
        grade.reset_before_grade()
        grade.grade()
        return _grades(grade)

    # the forms alone: every form point, no probe point
    assert _total(grade) == sum(FORM_POINTS.values()) == 14
    assert regrade('1.1.', prio_main=' 32766 ')['q_rule_priority'] == (2, 2)
    assert regrade('1.1.', prio_main='0')['q_rule_priority'] == (0, 2)
    assert regrade('1.1.', table_local='main')['q_local_table'] == (0, 2)
    assert regrade('2.1.', reply_if='eth2')['q_reply_path'] == (1, 2)             # one point per answer
    assert regrade('2.1.', dropper='isp2')['q_reply_path'] == (0, 2)
    assert regrade('3.2.', dropper='isp2')['q_dropper'] == (0, 2)
    assert regrade('3.2.', loose='1')['q_loose_mode'] == (0, 2)
    assert regrade('4.1.', reply_source=f" {_ip(data.ips.web4)}/24 ")['q_reply_source'] == (2, 2)
    assert regrade('4.1.', reply_source=_ip(data.ips.r4_acc2))['q_reply_source'] == (0, 2)
    assert regrade('6.2.', l3mdev_prio='32766')['q_l3mdev_rule'] == (0, 2)
    assert lab._same_ip('x', data.ips.web4) is False and lab._same_ip(None, data.ips.web4) is False


def test_only_choice_answers_are_exo_only(lab, data, tmp_pub_dir):
    # an answer picked from a short list is hidden from the self-evaluation (every choice could be
    # tried), a typed answer is not
    choices = {'q_local_table', 'q_reply_path', 'q_dropper'}
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE)
    for e in grade.get_grade_list():
        expected = params.EXO_EVAL_SCOPE if str(e.title) in choices else params.BOTH_EVAL_SCOPE
        assert e.scope == expected, e.title


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

#: the numbered sections of the course (level 1), in order
_TAGS = ['why', 'rpdb', 'selectors', 'multihoming', 'marks', 'rpfilter', 'multipath', 'vrf', 'persist', 'diag']


def test_course_sections(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    info = _text(ns.informations)
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved)
    sections = numbering.sections('fr')
    assert [s.tag for s in sections if s.level == 1] == _TAGS
    assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, 11)]
    tags = [s.tag for s in sections]
    assert {s.level for s in sections} == {1, 2} and all(tags) and len(set(tags)) == len(tags)
    assert {'tables', 'rules', 'route-get', 'connected', 'bcp38', 'own', 'nat', 'fwmark', 'output', 'connmark', 'ecmp',
            'failover', 'vrf-create', 'vrf-tables', 'vrf-tools', 'vrf-services', 'vrf-leak'} <= set(tags)
    assert '@@' not in course and '- [8. Les VRF](#vrf)' in course
    for words in ('ip rule add from 198.51.100.10 lookup 102 priority 1002', 'suppress_prefixlength 0',
                  'meta mark set 2', 'type route hook output priority mangle', 'meta mark set ct mark',
                  'ct state new ct mark set 2', 'ip rule add fwmark 2 lookup 102 priority 1000',
                  'net.ipv4.conf.eth2.rp_filter=2', 'src_valid_mark', 'TcpExtIPReversePathFilter',
                  'nexthop via 192.0.2.1 dev eth1 weight 3', 'fib_multipath_hash_policy', 'fib_multipath_use_neigh',
                  'ip link add vrf-blue type vrf table 10', 'ip link set eth0 master vrf-blue', '[l3mdev-table]',
                  'unreachable default metric 4278198272', 'tcp_l3mdev_accept', 'ip route add 192.168.1.0/24 dev vrf-blue',
                  'ip route get 203.0.113.80 from 192.168.2.10 iif eth3 mark 2', '/etc/iproute2/rt_tables', 'BCP 38'):
        assert words in info, words
    # the examples use documentation addresses; the course says nothing of this session
    assert '192.0.2.1' in info and '198.51.100.1' in info and '203.0.113.80' in info
    for value in (data.nets.acc1, data.nets.acc2, data.nets.svc, data.ips.www.ip, data.nets.lan1b, data.nets.blue_a):
        assert str(value) not in info
    for word in ('pc1a', 'pc1b', 'web4', 'blue1', 'red1', '`isp1`', '`isp2`', '`r3`', '`r6`', '`www`', 'Dans ce TP'):
        assert word not in info, word
    assert not re.search(r'\(question \d', info) and not re.search(r'[Pp]artie \d', info)
    assert not re.search('[─-╿←-⇿■-◿−]', info)        # plain characters only


def test_questions_and_instructor_fragments(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, DONE, instructor_mode=True)
    _, numbering = resolve_informations(ns.informations)
    questions = list(grade.get_questions_ordered())
    titles = [_text(q.title) for q in questions]
    assert titles[0] == 'Organisation du TP'
    numbers = [title.split(' ')[0] for title in titles[1:]]
    assert numbers == ['1.', '1.1.', '1.2.', '1.3.', '2.', '2.1.', '2.2.', '2.3.', '3.', '3.1.', '3.2.', '3.3.', '4.',
                       '4.1.', '4.2.', '5.', '5.1.', '5.2.', '6.', '6.1.', '6.2.', '6.3.', '6.4.', '6.5.']
    assert sum(title.split(' ', 1)[1].startswith('Bonus') for title in titles[1:]) == 2
    resolved = [_text(resolve_text(q.description, numbering)) for q in questions]
    assert all('@@ref' not in text and '@@sec' not in text for text in resolved)
    first = ' '.join(resolved[0].split())
    assert 'section 4.1)' in first and 'section 6)' in first and 'section 9 dit' in first     # BCP 38, rp_filter, persistence
    descriptions = [_text(q.description) for q in questions]
    assert all(has_instructor(text) for text in descriptions)      # a solution (or the reference) everywhere
    all_text = "".join(descriptions)
    assert "{'" not in all_text and not re.search(r"(?<!@@)(?<!\{)\{[a-z_0-9]+\}", all_text)
    # the addressing is in the first question
    for value in [data.nets.acc1, data.nets.acc2, data.nets.core, data.nets.svc, data.nets.mgmt, data.nets.blue_a,
                  data.nets.blue_b] + [getattr(data.nets, lan) for lan in lab.LAN_HOST] + \
                 [getattr(data.ips, h).ip for h in list(lab.LAN_HOST.values()) + ['www', 'ext', 'admin', 'blue1', 'blue2']] + \
                 [getattr(data.ips, f"r{n}_acc{isp}").ip for n in lab.SITES for isp in lab.ISPS]:
        assert str(value) in descriptions[0], value
    # every command of the reference solution is in the texts of the instructor
    for router in list(lab.ROUTERS) + ['r6']:
        for command in ns.reference_commands(router):
            assert command in all_text, command
    for router in ('r3', 'r4'):
        assert ns.mangle_table(router) in all_text
    for e in grade.get_grade_list():
        desc = _text(e.description)
        assert desc and "{'" not in desc and not re.search(r"\{[a-z_0-9]+\}", desc)
    assert all(_text(part.description).startswith(f'Partie {n} — ') for n, part in enumerate(grade.get_grade_parts(), 1))

    # the student's view: no instructor fragment, the given rules of r4 shown, no solution given away
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, DONE, instructor_mode=False)
    student = [_text(q.description) for q in grade2.get_questions_ordered()]
    student_text = "".join(student)
    assert not has_instructor(student_text) and 'Solution' not in student_text and "Pour l'enseignant" not in student_text
    assert 'q_' not in student_text and ns2.nat_table('r4') in student_text
    for router in list(lab.ROUTERS) + ['r6']:
        for command in ns2.reference_commands(router):
            assert command not in student_text, command
    # (question 4.2 names the statement `meta mark set ct mark`, as the course does: not the rules)
    for hidden in ('ct state new ct mark set', 'ct mark 2 meta mark set', 'type route hook output',
                   'tcp_l3mdev_accept', 'unreachable default metric', 'rp_filter=2'):
        assert hidden not in student_text, hidden
    # the questions of a student and of the instructor are the same ones (same hashes: the answers follow)
    assert [q.question_hash for q in grade2.get_questions_ordered()] == [q.question_hash for q in questions]


def _consistent_tables(html):
    for table in re.findall(r'<table>.*?</table>', html, flags=re.S):
        rows = re.findall(r'<tr>.*?</tr>', table, flags=re.S)
        assert len({len(re.findall(r'<t[hd][ >]', row)) for row in rows}) == 1, rows[0]


def test_course_html(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    resolved, _ = resolve_informations(ns.informations)
    source = _text(resolved)
    html = markdown_to_html(source)
    assert '```' not in html
    assert html.count('<table>') == 7 and html.count('<pre>') == 23
    assert '<h3><a id="connected"></a>3.3.' in html and '<h3><a id="vrf-leak"></a>8.5.' in html
    assert '<h2><a id="diag"></a>10.' in html
    _consistent_tables(html)
    # the commands shown inside the two list items stay in their item, as code
    assert 'ip route add 192.168.1.0/24 dev eth0 table 102' in html and html.count('<ol>') == 1
    # every word of the source reaches the page: nothing is swallowed by a stray tag
    assert 'C\'est la technique de <code>wg-quick</code>' in html and 'des tables étanches' in html


@pytest.mark.parametrize('instructor_mode', [False, True])
def test_questions_html(lab, data, tmp_pub_dir, instructor_mode):
    grade, ns = _simulate(lab, data, tmp_pub_dir, DONE, instructor_mode=instructor_mode)
    _, numbering = resolve_informations(ns.informations)
    blocks = 0
    for q in grade.get_questions_ordered():
        source = _text(resolve_text(q.description, numbering))
        html = markdown_to_html(source, show_instructor=instructor_mode)
        assert '```' not in html, _text(q.title)                   # every fenced block is rendered as code
        assert '<pre>' not in html or '<code>' in html
        blocks += html.count('<pre>')
        _consistent_tables(html)
        # a numbered list keeps its numbering: its items are never cut by a block
        steps = re.findall(r'^(\d)\. ', source, flags=re.M)
        if steps:
            assert html.count('<ol>') == 1 and html.count('<li>') >= len(steps), _text(q.title)
    # for a student: the NAT rules given on r4 and the loop of the multipath question
    assert blocks == (2 if not instructor_mode else 2 + 23)


def test_course_and_questions_pdf(lab, data, tmp_pub_dir):
    """`sre export` writes the course and the questions of a student into informations.pdf: fpdf2 accepts one
    text and one style per table cell."""
    from SRE.pdf import SrePDF, markdown_to_html as pdf_html
    grade, ns = _simulate(lab, data, tmp_pub_dir, DONE)
    resolved, numbering = resolve_informations(ns.informations)
    texts = [_text(resolved)]
    for q in grade.get_questions_ordered():
        texts.append(re.sub(r'@@\{[^:}]+:[^}]*\}@@', '', _text(resolve_text(q.description, numbering))))
    assert len(texts) == 26
    pdf = SrePDF()
    pdf.add_page()
    pdf.set_font(pdf.text_font, size=11)
    for text in texts:
        html = pdf_html(text)
        for cell in re.findall(r'<t[dh]\b[^>]*>(.*?)</t[dh]>', html, flags=re.S):
            assert re.fullmatch(r'[^<]*|<(b|i|code)>[^<]*</\1>', cell), cell
        pdf.write_html(html, tag_styles=pdf.html_tag_styles())
    assert bytes(pdf.output()).startswith(b'%PDF') and pdf.page_no() >= 15


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'policy_routing_stripped', 'exec')
    assert source.count(b'instructor(tr(') == 25                   # one per question
    assert b'Solution' not in stripped and b'Pour l\'enseignant' not in stripped


def test_french_only_and_english_identifiers(lab, data, tmp_pub_dir):
    """The texts are French (no translation table yet); machines, networks, states, data fields, grade
    elements, part keys and form fields are English."""
    assert lab._TRANSLATIONS == {} and lab.default_language == 'fr'
    assert lab.title.resolve('en') == "Policy routing: ip rule, two ISPs and VRFs"
    french = re.compile(r'(routeur|pont|reseau|serveur|sonde|panne|exemple|reponse|commutateur|passerelle|'
                        r'machine_|_machine|exterieur|interne|filtre|regle|journal|parefeu|courrier|adresse|sortie|'
                        r'fournisseur|invite|personnel|marque|bleu|rouge)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += list(vars(data.ips)) + list(vars(data.nets))
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE)
    names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
    names += [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', [])]
    names += [value for q in grade.get_questions_ordered() for f in getattr(q, 'fields', []) for value in f.get('choices', [])]
    bad = [n for n in names if french.search(n)]
    assert not bad, bad
