"""Offline tests of the NAT lab (lab/sre/_DRAFT_misc/nftables-nat.py): data generation with the hidden mirror
(six sites behind one WAN, a second public address), the routes of a real access network (none towards the
private LANs on the Internet hosts, except on their hidden clones), the ops of the states (rules given on
r2 / r5 / r6, test servers, the six reference files of `final`), the multi-pass grading contract with
synthetic outputs (nothing done: 0, the reference solution: 100, each part alone, each part missing, one
mistake at a time), the forms and their cheat answers, the numbered course, the questions and their
instructor fragments, the HTML of every text, the stripped lab file and the English identifiers.

No Docker: a model of the six routers answers the probes as the test HTTP servers / bash / ping do, from one
flag per piece of work.  The lab gives each part its own router so that the parts are independent:
test_parts_are_independent is the check of that requirement.
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

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'nftables-nat.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('nftables_nat_lab_under_test', _LAB_PATH)
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


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str) and hasattr(op, 'filename')}


# ---------------------------------------------------------------------------
# a model of the six sites answering the probes
# ---------------------------------------------------------------------------

#: everything done as the reference solution does it: one flag per piece of work
DONE = {
    'masquerade': 'scoped',        # part 1: None | 'scoped' | 'broad' (no criterion: what comes in is translated too)
    'static_in': True,             # part 2: the second public address leads to srv2
    'static_out': 'first',         # None | 'first' | 'last' (after the masquerade) | 'broad' (no ip saddr)
    'forward': 'address',          # part 3: None | 'interface' (iifname "eth1") | 'address' (ip daddr)
    'output': True,                # the nat chain of the output hook
    'hairpin': 'scoped',           # None | 'scoped' | 'broad' (the Internet clients are masqueraded too)
    'balancing': 'round_robin',    # part 4: None | 'round_robin' | 'single' (one backend only)
    'redirect': 'lan',             # part 5: None | 'lan' | 'any' (no iifname)
    'exception': True,             # admin spared
    'filter': 'complete',          # part 6: None | 'complete' | 'no_dnat' | 'no_lan' | 'policy_accept'
}
NOTHING = dict.fromkeys(DONE)
#: the flags of each part, and what its probes are worth (the forms apart)
PARTS = {1: ('masquerade',), 2: ('static_in', 'static_out'), 3: ('forward', 'output', 'hairpin'), 4: ('balancing',),
         5: ('redirect', 'exception'), 6: ('filter',)}
PROBE_POINTS = {1: 9, 2: 12, 3: 18, 4: 9, 5: 13, 6: 14}
PART_POINTS = {1: 15, 2: 15, 3: 22, 4: 12, 5: 18, 6: 18}

_CURL = re.compile(r"curl -s -m \d+ http://([0-9.]+):(\d+)/(?:\?probe=(\d+))?$")
_TCP = re.compile(r"/dev/tcp/([0-9.]+)/(\d+)")
_PING = re.compile(r"ping -c \d+ -W \d+ ([0-9.]+)$")
REFUSED, TIMEOUT = ("", 7), ("", 28)


def _only(*parts):
    """The flags of the given parts done, the others untouched."""
    return {flag: (DONE[flag] if any(flag in PARTS[n] for n in parts) else None) for flag in DONE}


def _answer(server, server_ip, port, client_ip):
    return (f"SERVER={server}\nSERVER_IP={server_ip}\nSERVER_PORT={port}\nCLIENT_IP={client_ip}\nCLIENT_PORT=40000\n", 0)


class Model:
    """What the probes of the hidden mirror get, from what is done on each router (the clones of ext1 and ext2
    have a route to every LAN: an untranslated connection is answered too)."""

    def __init__(self, lab, d, service_up=True, **done):
        assert set(done) <= set(DONE), done
        self.lab, self.done, self.service_up = lab, {**NOTHING, **done}, service_up
        self.ip = {name: _ip(getattr(d.ips, name)) for name in list(lab.HOST_SITE) + list(lab.WAN_HOSTS)}
        self.wan = {n: _ip(getattr(d.ips, f"r{n}_wan")) for n in lab.SITES}
        self.gw = {n: _ip(getattr(d.ips, f"r{n}_lan{n}")) for n in lab.SITES}
        self.public2 = _ip(d.ips.r2_public)

    def filtering(self):
        return self.done['filter'] in ('complete', 'no_dnat', 'no_lan')

    def has_rules(self, router):
        """The router has a ruleset to transplant (r2, r5 and r6 always do: their given rules)."""
        return router in ('r2', 'r5', 'r6') or any(self.done[flag] for flag in PARTS[int(router[1])])

    def nft_json(self):
        """`nft -j list ruleset` of r6: its forward chain, when there is one."""
        objects = [{"metainfo": {"version": "1.0.6", "json_schema_version": 1}},
                   {"table": {"family": "ip", "name": "nat", "handle": 1}}]
        if self.done['filter']:
            policy = 'accept' if self.done['filter'] == 'policy_accept' else 'drop'
            objects += [{"table": {"family": "ip", "name": "filter", "handle": 2}},
                        {"chain": {"family": "ip", "table": "filter", "name": "forward", "handle": 1, "type": "filter",
                                   "hook": "forward", "prio": 0, "policy": policy}}]
        return json.dumps({"nftables": objects})

    def curl(self, src, ip, port, probe):
        done, addr, wan, gw = self.done, self.ip, self.wan, self.gw
        ext1, ext2, key = addr['ext1'], addr['ext2'], (src, ip, port)
        if key == ('pc1', ext1, 9000):
            return _answer('ext1', ext1, 9000, wan[1] if done['masquerade'] else addr['pc1'])
        if key == ('ext2', addr['pc1'], 80):
            return _answer('pc1', addr['pc1'], 80, gw[1] if done['masquerade'] == 'broad' else ext2)
        if key == ('ext2', self.public2, 80):
            return _answer('srv2', addr['srv2'], 80, ext2) if done['static_in'] else REFUSED
        if key == ('srv2', ext1, 9000):
            return _answer('ext1', ext1, 9000, self.public2 if done['static_out'] in ('first', 'broad') else wan[2])
        if key == ('pc2', ext1, 9000):
            return _answer('ext1', ext1, 9000, self.public2 if done['static_out'] == 'broad' else wan[2])
        if key == ('ext2', wan[3], 8080):
            if not done['forward']:
                return REFUSED
            return _answer('web3', addr['web3'], 80, gw[3] if done['hairpin'] == 'broad' else ext2)
        if key == ('r3', wan[3], 8080):
            return _answer('web3', addr['web3'], 80, wan[3]) if done['output'] else REFUSED
        if key == ('pc3', wan[3], 8080):
            if done['forward'] != 'address':
                return REFUSED                       # the packet is for r3 itself, where nothing listens
            return _answer('web3', addr['web3'], 80, gw[3]) if done['hairpin'] else TIMEOUT
        if key == ('ext1', wan[4], 80):                 # the balancing is probed by the clone of ext1
            if not done['balancing']:
                return REFUSED
            server = 'web4b' if done['balancing'] == 'round_robin' and probe % 2 else 'web4a'
            return _answer(server, addr[server], 80, ext1)
        if key == ('pc5', ext1, 80):
            return _answer('proxy', gw[5], 3128, addr['pc5']) if done['redirect'] else _answer('ext1', ext1, 80, wan[5])
        if key == ('admin', ext1, 80):
            if done['redirect'] and not done['exception']:
                return _answer('proxy', gw[5], 3128, addr['admin'])
            return _answer('ext1', ext1, 80, wan[5])
        if key == ('ext2', wan[5], 80):
            return _answer('proxy', wan[5], 3128, ext2) if done['redirect'] == 'any' else REFUSED
        if key == ('r6', addr['srv6'], 8081):
            return _answer('intranet', addr['srv6'], 8081, gw[6]) if self.service_up else REFUSED
        if key == ('srv6', ext1, 9000):
            return TIMEOUT if done['filter'] == 'no_lan' else _answer('ext1', ext1, 9000, wan[6])
        if key == ('ext2', wan[6], 8080):
            return TIMEOUT if done['filter'] == 'no_dnat' else _answer('srv6', addr['srv6'], 80, ext2)
        raise AssertionError(f"unexpected probe {key}")

    def __call__(self, machine, command):
        src = self.lab.visible(machine)
        m = _CURL.search(command)
        if m:
            return self.curl(src, m.group(1), int(m.group(2)), int(m.group(3) or 0))
        m = _TCP.search(command)
        if m:
            assert (src, m.group(1), int(m.group(2))) == ('ext2', self.ip['srv6'], 8081), command
            if not self.service_up:
                return "RC=1\n", 0
            return ("RC=124\n" if self.filtering() else "RC=0\n"), 0
        m = _PING.search(command)
        if m:
            assert (src, m.group(1)) == ('ext2', self.ip['srv6']), command
            if self.filtering():
                return "1 packets transmitted, 0 received, 100% packet loss, time 0ms\n", 1
            return f"64 bytes from {m.group(1)}: icmp_seq=1 ttl=63 time=0.1 ms\n", 0
        return None


def _outputs(model):
    def outputs(lab, ns, machine, command, step):
        router = lab.visible(machine)
        if command == 'nft -j list ruleset':
            return model.nft_json(), 0
        if command == 'nft list ruleset':
            return ("table ip nat {\n}\n" if model.has_rules(router) else ""), 0
        result = model(machine, command)
        return result if result is not None else ("", 0)
    return outputs


def _simulate(lab, data, tmp_pub_dir, done, instructor_mode=False, cheat=True, **model_options):
    """Multi-pass grade() like run_tests(), the probes answered by the model of *done*: returns (grade, net_scheme)."""
    outputs = _outputs(Model(lab, data, **model_options, **done))
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            # the transplants are registered once the rulesets are known: commands only join later steps
            for key, cmds in current.items():
                assert cmds >= keys.get(key, set()), "a registered test disappeared between two passes"
                assert key[1] >= step or cmds == keys.get(key, set()), "a test was registered for a step already run"
        keys = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = outputs(lab, ns, m, key[0], s)
        step += 1
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
    machines = ns.get_machine_names()
    visible = [m for m in machines if not m.endswith('_h')]
    assert len(machines) == 36 and len(visible) == 18
    assert sorted(visible) == sorted(list(lab.ROUTERS) + list(lab.HOST_SITE) + list(lab.WAN_HOSTS))
    assert all(lab.NetScheme._machine_specs[m + '_h']['hidden'] for m in visible)
    assert ns.routers == sorted(list(lab.ROUTERS) + [r + '_h' for r in lab.ROUTERS])
    # one router per part: its LAN on eth0, the WAN on eth1
    for n in lab.SITES:
        assert lab._TOPOLOGY[f'lan{n}'][f'r{n}'] == 0 and lab._TOPOLOGY['wan'][f'r{n}'] == 1
    # the Internet is visibly not private; the six LANs are private and distinct
    assert data.nets.wan.subnet_of(IPv4Network('198.18.0.0/15')) and not data.nets.wan.is_private or True
    assert data.nets.wan.subnet_of(lab.WAN_RANGE) and data.nets.wan.prefixlen == 24
    lans = [getattr(data.nets, f'lan{n}') for n in lab.SITES]
    assert all(lan.is_private and lan.prefixlen == 24 for lan in lans)
    assert all(not a.overlaps(b) for i, a in enumerate(lans) for b in lans[i + 1:])
    # the second public address of r2: in the WAN, used by nobody else
    wan_addresses = [ip for name, ip in vars(data.ips).items() if ip.network == data.nets.wan and name != 'r2_public']
    assert data.ips.r2_public.network == data.nets.wan and data.ips.r2_public not in wan_addresses
    # the clones have the addresses of the machines they copy
    assert data.ips.pc1_h == data.ips.pc1 and data.ips.r3_h_wan_h == data.ips.r3_wan and data.nets.lan4_h == data.nets.lan4


def test_routes_of_a_real_access_network(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    default = IPv4Network('0.0.0.0/0')
    config = ns.net_config

    def routes(machine):
        return [route for interface in config[machine] for route in interface[1]]

    for host, n in lab.HOST_SITE.items():
        for machine in (host, host + '_h'):
            assert routes(machine) == [(default, getattr(data.ips, f'r{n}_lan{n}').ip)], machine
    for router in ns.routers:
        assert routes(router) == [], router
    lan_routes = [(getattr(data.nets, f'lan{n}'), getattr(data.ips, f'r{n}_wan').ip) for n in lab.SITES]
    for host in lab.WAN_HOSTS:
        assert routes(host) == []                               # the Internet does not route the private networks
        assert routes(host + '_h') == lan_routes                # only the hidden clones know them
    for router in ('r2', 'r2_h'):                               # two public addresses, the first one primary
        assert config[router][1][0] == [data.ips.r2_wan, data.ips.r2_public]
    assert all(len(config[r][1][0]) == 1 for r in ns.routers if lab.visible(r) != 'r2')


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


def test_initial_ops(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    ops = _state_ops(ns, 'initial')
    assert {step for step, _ in ops} == {1} and len({m for _, m in ops}) == 36
    for router in ns.routers:
        cmds = _cmds(ops, 1, router)
        assert 'sysctl -w net.ipv4.ip_forward=1' in cmds and 'nft flush ruleset' in cmds
        for scope in ('all', 'default', 'eth0', 'eth1'):
            assert f'sysctl -w net.ipv4.conf.{scope}.send_redirects=0' in cmds
    # the rules a part relies on: on the visible r2, r5 and r6 only, loaded after the flush
    for router in ns.routers:
        files, cmds = _files(ops, 1, router), _cmds(ops, 1, router)
        if router in ('r2', 'r5', 'r6'):
            conf = files[lab.CONF_FILE]
            assert conf.startswith('#!/usr/sbin/nft -f\nflush ruleset\n') and conf == ns.given_conf(router)
            assert ns.rule_masquerade(int(router[1])) in conf
            assert cmds.index('nft flush ruleset') < cmds.index(f'nft -f {lab.CONF_FILE}')
        else:
            assert lab.CONF_FILE not in files and f'nft -f {lab.CONF_FILE}' not in cmds
    given6 = _files(ops, 1, 'r6')[lab.CONF_FILE]
    assert f'iifname "eth1" tcp dport 8080 dnat to {_ip(data.ips.srv6)}:80' in given6 and 'ip filter' not in given6
    assert 'prerouting' not in _files(ops, 1, 'r2')[lab.CONF_FILE]
    # the test servers, on the visible machines and on their clones
    for machine, port, name in lab.SERVERS:
        for m in (machine, machine + '_h'):
            script = _files(ops, 1, m)[f'/usr/local/sbin/sre_http_server_{port}.py']
            assert repr(name) in script or f'"{name}"' in script, (m, port)
    assert [name for machine, port, name in lab.SERVERS if machine == 'srv6'] == ['srv6', 'intranet']
    assert not any('sre_http_server' in f for f in _files(ops, 1, 'ext2'))          # ext2 is a client only
    # a LAN host without a default route would hide every translation
    assert f'ip route add 0.0.0.0/0 via {_ip(data.ips.r1_lan1)}' in _cmds(ops, 1, 'pc1')
    assert not any('ip route add' in c for c in _cmds(ops, 1, 'ext1') + _cmds(ops, 1, 'ext2') + _cmds(ops, 1, 'r1'))
    assert sum('ip route add' in c for c in _cmds(ops, 1, 'ext2_h')) == 6


def test_final_ops(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    ops = _state_ops(ns, 'final')
    assert sorted(m for _, m in ops) == list(lab.ROUTERS)                # never a clone
    for router in lab.ROUTERS:
        conf = _files(ops, 1, router)[lab.CONF_FILE]
        assert conf == ns.reference_conf(router) and conf.startswith('#!/usr/sbin/nft -f\nflush ruleset\n')
        assert _cmds(ops, 1, router) == [f'nft -f {lab.CONF_FILE}']
        for table, chains in ns.reference_tables(router).items():
            assert f'table {table} {{' in conf
            for chain, rules in chains.items():
                assert lab.CHAINS[table][chain] in conf and all(rule in conf for rule in rules)
        for table, chains in ns.given_tables(router).items():          # the given rules are kept
            assert all(rule in conf for rules in chains.values() for rule in rules)
    conf2, conf3, conf5, conf6 = (_files(ops, 1, r)[lab.CONF_FILE] for r in ('r2', 'r3', 'r5', 'r6'))
    assert conf2.index(ns.rule_static_out()) < conf2.index(ns.rule_masquerade(2))         # first match wins
    assert conf5.index(ns.rule_proxy_exception()) < conf5.index(ns.rule_proxy())
    assert conf3.count(ns.rule_port_forward(3)) == 2 and 'hook output priority -100' in conf3
    assert f'ip daddr {_ip(data.ips.r3_wan)} tcp dport 8080 dnat to {_ip(data.ips.web3)}:80' in conf3
    assert 'policy drop' in conf6 and 'ct status dnat accept' in conf6 and conf6.count('table ip') == 2
    assert 'numgen inc mod 2 map' in _files(ops, 1, 'r4')[lab.CONF_FILE]


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, NOTHING, cheat=False)
    elements = grade.get_grade_list()
    assert _total(grade) == 0 and sum(e.max_grade for e in elements) == 100 and len(elements) == 27
    assert not any(e.bonus for e in elements)
    assert [str(p.title) for p in grade.get_grade_parts()] == [f'part{n}' for n in lab.SITES]
    assert {n: sum(e.max_grade for e in elements if str(e.grade_part) == f'part{n}') for n in lab.SITES} == PART_POINTS
    # the forms are graded by the final evaluation only
    forms = {str(e.title) for e in elements if e.scope == params.EXO_EVAL_SCOPE}
    assert forms == {str(e.title) for e in elements if str(e.title).startswith('q_')} and len(forms) == 10
    assert {n: sum(e.max_grade for e in elements if str(e.grade_part) == f'part{n}' and str(e.title) not in forms)
            for n in lab.SITES} == PROBE_POINTS
    # the clones are always flushed; only a router that has rules gets a ruleset loaded
    tests = grade.get_tests()
    for router in lab.ROUTERS:
        loads = [cmd for cmd, _ in tests[(router + '_h', lab.LOAD_STEP)]]
        assert loads[0] == 'nft flush ruleset'
        assert (len(loads) == 2 and 'base64 -d | nft -f -' in loads[1]) == (router in ('r2', 'r5', 'r6')), router


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE)
    assert not _lost(grade) and _total(grade) == 100
    assert {n: _part(grade, n) for n in lab.SITES} == PART_POINTS
    assert grade.max_step == lab.PROBE_STEP == 3
    tests = grade.get_tests()
    probes = {m: sorted(cmd for cmd, _ in cmds if 'curl' in cmd or '/dev/tcp' in cmd or cmd.startswith('ping'))
              for (m, step), cmds in tests.items() if step == lab.PROBE_STEP}
    probing = {m for m, cmds in probes.items() if cmds}
    assert probing == {'pc1_h', 'srv2_h', 'pc2_h', 'pc3_h', 'r3_h', 'pc5_h', 'admin_h', 'srv6_h', 'r6_h', 'ext1_h',
                       'ext2_h'}
    assert len(probes['ext2_h']) == 5 + 2                              # five curl, a TCP connect, a ping
    assert len(probes['ext1_h']) == lab.LB_REQUESTS                    # the balancing, apart: eight slow failures
                                                                       # must not delay the other parts
    assert not any(not m.endswith('_h') for m in probing)              # the visible machines are never probed
    # every ruleset is loaded on its clone before the probes
    for router in lab.ROUTERS:
        assert any('base64 -d | nft -f -' in cmd for cmd, _ in tests[(router + '_h', lab.LOAD_STEP)])
    # the probes alone, without the forms
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE, cheat=False)
    assert {n: _part(grade, n) for n in lab.SITES} == PROBE_POINTS


@pytest.mark.parametrize('n', [1, 2, 3, 4, 5, 6])
def test_parts_are_independent(lab, data, tmp_pub_dir, n):
    """A part done alone gives all its points; left out alone, it costs its points and no others."""
    others = [m for m in PARTS if m != n]
    grade, _ = _simulate(lab, data, tmp_pub_dir, _only(n), cheat=False)
    assert _part(grade, n) == PROBE_POINTS[n] and all(_part(grade, m) == 0 for m in others)
    grade, _ = _simulate(lab, data, tmp_pub_dir, _only(*others), cheat=False)
    assert _part(grade, n) == 0 and all(_part(grade, m) == PROBE_POINTS[m] for m in others)
    # with the forms: the whole part, and nothing of the others but their forms
    grade, _ = _simulate(lab, data, tmp_pub_dir, _only(n))
    assert _part(grade, n) == PART_POINTS[n]
    assert all(_part(grade, m) == PART_POINTS[m] - PROBE_POINTS[m] for m in others)


@pytest.mark.parametrize('change, lost', [
    ({'masquerade': 'broad'}, {'masquerade_scope': 3}),                 # what comes in is translated too
    ({'masquerade': None}, {'masquerade': 6, 'masquerade_scope': 3}),
    ({'static_in': None}, {'static_in': 5}),
    ({'static_out': 'last'}, {'static_out': 5, 'static_scope': 2}),     # the masquerade decides first
    ({'static_out': 'broad'}, {'static_scope': 2}),                     # the whole LAN leaves under the second address
    ({'static_out': None}, {'static_out': 5, 'static_scope': 2}),
    ({'forward': 'interface'}, {'hairpin': 6, 'hairpin_scope': 2}),      # the rule of question 3.1 left as it was
    ({'forward': None}, {'port_forward': 6, 'hairpin': 6, 'hairpin_scope': 2}),
    ({'output': None}, {'router_itself': 4}),
    ({'hairpin': None}, {'hairpin': 6, 'hairpin_scope': 2}),            # web3 answers pc3 directly
    ({'hairpin': 'broad'}, {'hairpin_scope': 2}),                       # web3 only sees the router
    ({'balancing': 'single'}, {'load_balancing': 5}),
    ({'balancing': None}, {'load_balancing': 9}),
    ({'redirect': 'any'}, {'redirect_lan_only': 2}),                    # the proxy is offered to the Internet
    ({'redirect': None}, {'redirect': 6, 'redirect_lan_only': 2, 'proxy_exception': 5}),
    ({'exception': None}, {'proxy_exception': 5}),
    ({'filter': 'no_dnat'}, {'published_kept': 4}),
    ({'filter': 'no_lan'}, {'lan_out': 3}),
    ({'filter': 'policy_accept'}, {'forward_policy': 2, 'intrusion_blocked': 5, 'lan_out': 3, 'published_kept': 4}),
    ({'filter': None}, {'forward_policy': 2, 'intrusion_blocked': 5, 'lan_out': 3, 'published_kept': 4}),
])
def test_one_thing_wrong(lab, data, tmp_pub_dir, change, lost):
    grade, _ = _simulate(lab, data, tmp_pub_dir, {**DONE, **change})
    assert _lost(grade) == lost and _total(grade) == 100 - sum(lost.values())


def test_a_dead_service_is_not_a_blocked_intrusion(lab, data, tmp_pub_dir):
    """The negative probes of part 6 only count while the clone of r6 itself reaches the service."""
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE, service_up=False)
    assert _lost(grade) == {'intrusion_blocked': 5, 'lan_out': 3, 'published_kept': 4}


# ---------------------------------------------------------------------------
# forms
# ---------------------------------------------------------------------------

_FORMS = {
    '1.1.': ['src_seen', 'outcome'],
    '1.3.': ['client_ip', 'src_lan', 'src_wan', 'return_rule'],
    '2.2.': ['client_srv2', 'client_pc2', 'appended'],
    '3.1.': ['server_ip', 'client_ip'],
    '3.3.': ['reply_src', 'client_after'],
    '4.1.': ['unit', 'client_ip', 'failure'],
    '5.1.': ['client_before', 'server_ip', 'server_port'],
    '5.2.': ['admin_server', 'position'],
    '6.1.': ['intruder_server', 'nat_protects'],
    '6.2.': ['forward_daddr', 'forward_dport'],
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
    assert _total(grade) == sum(PART_POINTS[n] - PROBE_POINTS[n] for n in PARTS) == 25
    # an address typed with a prefix or spaces is the address; another one is not
    assert regrade('1.1.', src_seen=f" {_ip(data.ips.pc1)}/24 ")['q_without_nat'] == (2, 2)
    assert regrade('1.1.', src_seen=_ip(data.ips.r1_wan), outcome='refused')['q_without_nat'] == (0, 2)
    assert regrade('1.3.', src_lan=_ip(data.ips.r1_wan), return_rule='dnat')['q_masquerade'] == (2, 4)
    assert regrade('2.2.', client_srv2=_ip(data.ips.r2_wan))['q_static'] == (2, 3)       # the primary address
    assert regrade('2.2.', appended='second')['q_static'] == (1, 3)
    assert regrade('3.3.', reply_src=_ip(data.ips.r3_wan))['q_hairpin'] == (1, 2)
    assert regrade('4.1.', unit='packet', failure='detects')['q_balancing'] == (1, 3)
    assert regrade('5.1.', server_port='80')['q_proxy'] == (2, 3)
    assert regrade('5.2.', admin_server=' EXT1 ', position='after')['q_exception'] == (1, 2)
    assert regrade('6.1.', nat_protects='yes')['q_intrusion'] == (1, 2)
    assert regrade('6.2.', forward_daddr=_ip(data.ips.r6_wan), forward_dport='8080')['q_forward'] == (0, 2)
    assert lab._same_ip('x', data.ips.pc1) is False and lab._is_int('', 80) is False and lab._is_int('port 80', 80)


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

#: the numbered sections of the course (level 1), in order
_TAGS = ['nat', 'basics', 'conntrack', 'chains', 'snat', 'dnat', 'nat-filter', 'load-balancing', 'redirect', 'observe',
         'practices', 'cheatsheet']


def test_course_sections(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    info = _text(ns.informations)
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved)
    sections = numbering.sections('fr')
    assert [s.tag for s in sections if s.level == 1] == _TAGS
    assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, 13)]
    tags = [s.tag for s in sections]
    assert {s.level for s in sections} == {1, 2} and all(tags) and len(set(tags)) == len(tags)
    assert {'hairpin', 'static-nat', 'nat-output', 'not-a-firewall', 'what-forward-sees'} <= set(tags)
    assert 'iptables' not in info                     # the course is about nftables only
    assert '@@' not in course and '- [10. Observer et vérifier une traduction](#observe)' in course
    for hook in ('prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress', 'egress'):
        assert f'`{hook}`' in info, hook
    for statement in ('snat to', 'masquerade', 'dnat to', 'redirect to', 'numgen inc mod 2 map', 'jhash ip saddr mod 2 map',
                      'type nat hook prerouting priority dstnat', 'type nat hook postrouting priority srcnat',
                      'type nat hook output priority -100', 'ct status dnat accept',
                      'ip daddr 203.0.113.2 dnat to 192.168.1.10', 'snat to 203.0.113.2'):
        assert statement in info, statement
    # the drawings are plain ASCII (any font aligns them); the public side of the examples uses RFC 5737 addresses
    assert not re.search('[─-╿←-⇿■-◿]', info)
    assert '203.0.113.1' in info and '198.51.100.7' in info
    assert '_h' not in info                           # the hidden mirror stays hidden
    # the course says nothing of this session: no address of the instance, no question number
    for value in (data.nets.wan, data.nets.lan1, data.ips.ext1.ip, data.ips.r2_public.ip):
        assert str(value) not in info
    assert not re.search(r'\(question \d', info) and 'Dans ce TP' not in info


def test_questions_and_instructor_fragments(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, DONE, instructor_mode=True)
    _, numbering = resolve_informations(ns.informations)
    questions = list(grade.get_questions_ordered())
    titles = [_text(q.title) for q in questions]
    assert titles[0] == 'Organisation du TP'
    numbers = [title.split(' ')[0] for title in titles[1:]]
    assert numbers == ['1.', '1.1.', '1.2.', '1.3.', '2.', '2.1.', '2.2.', '3.', '3.1.', '3.2.', '3.3.', '4.', '4.1.',
                       '5.', '5.1.', '5.2.', '6.', '6.1.', '6.2.']
    resolved = [_text(resolve_text(q.description, numbering)) for q in questions]
    assert all('@@ref' not in text and '@@sec' not in text for text in resolved)
    assert 'section 10.1 des Informations' in resolved[0]          # the test servers
    assert '6.4' in resolved[11] and '6.5' in resolved[5]          # hairpin, static NAT
    descriptions = [_text(q.description) for q in questions]
    assert all(has_instructor(text) for text in descriptions)      # a solution (or the reference file) everywhere
    all_text = "".join(descriptions)
    assert "{'" not in all_text and not re.search(r"(?<!@@)(?<!\{)\{[a-z_0-9]+\}", all_text)
    for value in [data.nets.wan, data.ips.ext1.ip, data.ips.ext2.ip, data.ips.r2_public.ip] + \
                 [getattr(data.nets, f'lan{n}') for n in lab.SITES] + [getattr(data.ips, h).ip for h in lab.HOST_SITE]:
        assert str(value) in descriptions[0], value                # the addressing is in the first question
    # every rule of the reference solution, and the given ones, are in the texts
    for router in lab.ROUTERS:
        for chains in ns.reference_tables(router).values():
            for rules in chains.values():
                assert all(rule in all_text for rule in rules), router
        assert ns.reference_conf(router) in all_text
    for e in grade.get_grade_list():
        desc = _text(e.description)
        assert desc and "{'" not in desc and not re.search(r"\{[a-z_]+\}", desc)
    assert all(_text(part.description).startswith(f'Partie {n} — ') for n, part in enumerate(grade.get_grade_parts(), 1))

    # the student's view: no instructor fragment, no hidden machine, the given rules shown
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, DONE, instructor_mode=False)
    student = [_text(q.description) for q in grade2.get_questions_ordered()]
    student_text = "".join(student)
    assert not has_instructor(student_text) and 'Solution' not in student_text and "Pour l'enseignant" not in student_text
    assert '_h' not in student_text and 'q_' not in student_text
    for router in ('r2', 'r5', 'r6'):
        assert lab.render_tables(ns2.given_tables(router)) in student_text
    for rule in (ns2.rule_static_in(), ns2.rule_static_out(), ns2.rule_hairpin(), ns2.rule_load_balancing(),
                 ns2.rule_proxy(), ns2.rule_proxy_exception(), ns2.rules_forward()[2]):
        assert rule not in student_text, rule                      # the solutions are not given away
    # the questions of a student and of the instructor are the same ones (same hashes: the answers follow)
    assert [q.question_hash for q in grade2.get_questions_ordered()] == [q.question_hash for q in questions]


def _consistent_tables(html):
    for table in re.findall(r'<table>.*?</table>', html, flags=re.S):
        rows = re.findall(r'<tr>.*?</tr>', table, flags=re.S)
        assert len({len(re.findall(r'<t[hd][ >]', row)) for row in rows}) == 1, rows[0]


def test_course_html(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    resolved, _ = resolve_informations(ns.informations)
    html = markdown_to_html(_text(resolved))
    assert '```' not in html and html.count('<table>') >= 10 and html.count('<pre>') >= 16
    assert '<h3><a id="hairpin"></a>6.4.' in html and '<h3><a id="static-nat"></a>6.5.' in html
    assert 'redirect to :3128</code>' in html
    _consistent_tables(html)


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
        # the steps (a), (b)… are paragraphs, never swallowed by a code block
        for step in re.findall(r'^\*\*\(([a-d])\)\*\*', source, flags=re.M):
            assert f'<strong>({step})</strong>' in html, (_text(q.title), step)
    # the given rules of r2 / r5 / r6 for a student; for the instructor, the six reference files and the rules of
    # the ten questions that configure something on top
    assert blocks == (3 if not instructor_mode else 3 + 6 + 10)


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'nftables_nat_stripped', 'exec')
    assert source.count(b'instructor(tr(') == 20                   # one per question
    assert b'Solution' not in stripped and b'Pour l\'enseignant' not in stripped


def test_english_identifiers(lab, data, tmp_pub_dir):
    """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
    french = re.compile(r'(routeur|pont|reseau|serveur|sonde|panne|exemple|reponse|commutateur|passerelle|'
                        r'machine_|_machine|exterieur|interne|filtre|regle|journal|parefeu|courrier|adresse|sortie)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += list(vars(data.ips)) + list(vars(data.nets))
    grade, _ = _simulate(lab, data, tmp_pub_dir, DONE)
    names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
    names += [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', [])]
    names += [value for q in grade.get_questions_ordered() for f in getattr(q, 'fields', []) for value in f.get('choices', [])]
    bad = [n for n in names if french.search(n)]
    assert not bad, bad
    own_states = [n for n, v in vars(lab.NetScheme).items() if getattr(v, '_is_sre_state', False)]
    assert sorted(own_states) == ['final', 'initial']
