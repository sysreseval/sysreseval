"""Offline tests of the host-firewall lab (lab/sre/_DRAFT_misc/nftables-filter1.py): data generation
with the hidden mirror, topology, the ops of the states (echo servers everywhere, flushed rulesets),
the two-pass grading contract with synthetic outputs (nothing done: 0, the reference solution: 100,
rule order, variants of the syntax, partial answers), texts, instructor fragments, English
identifiers.

No Docker: the `nft -j list ruleset` of m1 is built from the generated data in the JSON shape of
nftables 1.0.6, the probes answer as the echo servers / bash / ping / nc do.
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))

import strip_instructor  # noqa: E402

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'nftables-filter1.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('nftables_filter1_lab_under_test', _LAB_PATH)
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
# synthetic outputs
# ---------------------------------------------------------------------------


def _match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def _payload(proto, field):
    return {"payload": {"protocol": proto, "field": field}}


def _meta(key):
    return {"meta": {"key": key}}


def _rule(family, table, chain, expr, handle):
    return {"rule": {"family": family, "table": table, "chain": chain, "handle": handle, "expr": expr}}


def _nft_json(lab, d, order=None, family='inet', variants=False, ct_states=('established', 'related'),
              log_limit=(5, 'minute'), log_group=0, jump='jump', policy='drop'):
    """nft -j list ruleset of m1 after `final` (or a variant of it).  *order*: the rules of input by
    name; *variants*: the other spellings (iifname, ip protocol udp, reject with tcp reset, a set of
    ports)."""
    table = lab.TABLE
    m2, ext1 = _ip(d.ips.m2), _ip(d.ips.ext1)
    input_rules = {
        'open': [_match(_payload("tcp", "dport"), {"set": [lab.OPEN_PORT, 9090]} if variants else lab.OPEN_PORT), {"accept": None}],
        'ct': [_match({"ct": {"key": "state"}}, {"set": list(ct_states)} if len(ct_states) > 1 else ct_states[0], "in"), {"accept": None}],
        'lo': [_match(_meta("iifname" if variants else "iif"), "lo"), {"accept": None}],
        'icmp': [_match(_payload("icmp", "type"), "echo-reply"), {"accept": None}],
        'udp': [_match(_payload("ip", "saddr"), ext1),
                _match(_payload("ip", "protocol"), "udp") if variants else _match(_meta("l4proto"), "udp"), {"accept": None}],
        'reject': [_match(_payload("ip", "saddr"), m2), {"reject": {"type": "tcp reset"}} if variants else {"reject": None}],
        'jump': [{jump: {"target": lab.LOG_CHAIN}}],
    }
    order = ['open', 'ct', 'lo', 'icmp', 'udp', 'reject', 'jump'] if order is None else order
    objs = [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}},
            {"table": {"family": family, "name": table, "handle": 2}},
            {"chain": {"family": family, "table": table, "name": lab.CHAIN, "handle": 1, "type": "filter", "hook": "input",
                       "prio": 0, "policy": policy}}]
    if 'jump' in order:
        objs.append({"chain": {"family": family, "table": table, "name": lab.LOG_CHAIN, "handle": 7}})
    for i, name in enumerate(order):
        objs.append(_rule(family, table, lab.CHAIN, input_rules[name], 10 + i))
    if 'jump' in order:
        log_expr = []
        if log_limit is not None:
            log_expr.append({"limit": {"rate": log_limit[0], "per": log_limit[1]}})
        log_expr.append({"log": {"prefix": lab.LOG_PREFIX, "group": log_group}} if log_group is not None else {"log": {"prefix": lab.LOG_PREFIX}})
        objs.append(_rule(family, table, lab.LOG_CHAIN, log_expr, 30))
        objs.append(_rule(family, table, lab.LOG_CHAIN, [{"counter": {"packets": 17, "bytes": 1020}}, {"drop": None}], 31))
    return json.dumps({"nftables": objs})


def _echo(name, server_ip, port, client_ip, ttl=64):
    return f"SERVER={name}\nSERVER_IP={server_ip}\nSERVER_PORT={port}\nCLIENT_IP={client_ip}\nCLIENT_PORT=40000\nTTL={ttl}\n"


def _ping_ok(ip):
    return f"PING {ip} ({ip}) 56(84) bytes of data.\n64 bytes from {ip}: icmp_seq=1 ttl=64 time=0.3 ms\n", 0


def _ping_ko(ip):
    return f"PING {ip} ({ip}) 56(84) bytes of data.\n\n--- {ip} ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n", 1


_CURL = re.compile(r"curl -s -m \d+ http://([0-9.]+):(\d+)/")
_NC = re.compile(r"printf x \| nc -u -w \d+ ([0-9.]+) (\d+)")
_TCP = re.compile(r"/dev/tcp/([0-9.]+)/(\d+)")
_PING = re.compile(r"ping -c \d+ -W \d+ ([0-9.]+)")


class Firewall:
    """The behaviour of the reference ruleset on the clone of m1, as the probes see it."""

    def __init__(self, lab, d, open_ports=(8080,), reject_from=('m2',), policy_drop=True, lo=True, udp_from=('ext1',),
                 ct=True, icmp_reply=True):
        self.lab, self.d = lab, d
        self.names = {_ip(d.ips.m1): 'm1', _ip(d.ips.m2): 'm2', _ip(d.ips.m3): 'm3', _ip(d.ips.ext1): 'ext1',
                      '127.0.0.1': 'm1'}
        self.open_ports, self.reject_from, self.policy_drop = set(open_ports), set(reject_from), policy_drop
        self.lo, self.udp_from, self.ct, self.icmp_reply = lo, set(udp_from), ct, icmp_reply

    def inbound_tcp(self, src, port):
        """'open' / 'refused' / 'dropped' for a SYN from *src* (a machine name) to m1:*port*."""
        if not self.policy_drop or port in self.open_ports:
            return 'open'
        return 'refused' if src in self.reject_from else 'dropped'

    def inbound_udp(self, src):
        return not self.policy_drop or src in self.udp_from

    def __call__(self, machine, command):
        d = self.d
        m1 = _ip(d.ips.m1)
        src = self.lab.visible(machine)
        m = _CURL.search(command)
        if m:
            ip, port = m.group(1), int(m.group(2))
            if machine == self.lab.clone('m1'):
                if ip == '127.0.0.1':
                    return (_echo('m1', ip, port, ip), 0) if (self.lo or not self.policy_drop) else ("", 28)
                return (_echo(self.names[ip], ip, port, m1), 0) if (self.ct or not self.policy_drop) else ("", 28)
            return (_echo('m1', m1, port, _ip(getattr(d.ips, src))), 0) if self.inbound_tcp(src, port) == 'open' else ("", 28)
        m = _NC.search(command)
        if m:
            ip, port = m.group(1), int(m.group(2))
            if machine == self.lab.clone('m1'):
                answered = (self.ct or not self.policy_drop) or self.names[ip] in self.udp_from
                return (_echo(self.names[ip], ip, port, m1), 0) if answered else ("", 0)
            return (_echo('m1', m1, port, _ip(getattr(d.ips, src))), 0) if self.inbound_udp(src) else ("", 0)
        m = _TCP.search(command)
        if m:
            verdict = self.inbound_tcp(src, int(m.group(2)))
            return {"open": "RC=0\n", "refused": "RC=1\n", "dropped": "RC=124\n"}[verdict], 0
        m = _PING.search(command)
        if m:
            ip = m.group(1)
            if machine == self.lab.clone('m1'):
                return _ping_ok(ip) if (self.icmp_reply or self.ct or not self.policy_drop) else _ping_ko(ip)
            return _ping_ko(ip) if self.policy_drop else _ping_ok(ip)
        return None


def _outputs_done(lab, ns, machine, command, nft_json=None, fw=None):
    d = ns.data
    if machine == 'm1' and command == 'nft -j list ruleset':
        return (nft_json if nft_json is not None else _nft_json(lab, d)), 0
    if machine == 'm1' and command == 'nft list ruleset':
        return "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n", 0
    probe = (fw or Firewall(lab, d))(machine, command)
    if probe is not None:
        return probe
    return "", 0


def _outputs_nothing(lab, ns, machine, command):
    """Right after the initial state: an empty ruleset, everything answers."""
    if command in ('nft -j list ruleset', 'nft list ruleset'):
        return "", 0
    probe = Firewall(lab, ns.data, policy_drop=False)(machine, command)
    return probe if probe is not None else ("", 0)


def _simulate(lab, data, tmp_pub_dir, outputs, instructor_mode=False, cheat=True):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme)."""
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
            keys = current
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            # the transplant is registered once the ruleset is known: the apply command joins step 2
            for key, cmds in current.items():
                assert cmds >= keys.get(key, set()), "a registered test disappeared between two passes"
            keys = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = outputs(lab, ns, m, key[0])
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


def test_data_generation_and_round_trip(lab, data):
    d = data
    assert d.nets.lan.prefixlen == 24 and d.nets.ext.prefixlen == 24 and d.nets.lan != d.nets.ext
    assert d.nets.lan_h == d.nets.lan and d.nets.ext_h == d.nets.ext
    for key, part in lab.HOST_PARTS.items():
        net = getattr(d.nets, lab.ADDRESSED[key])
        assert getattr(d.ips, key).ip == net.network_address + part and getattr(d.ips, key).network == net
    assert d.ips.m1_h == d.ips.m1 and d.ips.ext1_h == d.ips.ext1
    assert d.ips.gw_h_lan_h == d.ips.gw_lan and d.ips.gw_h_ext_h == d.ips.gw_ext
    blob = d.to_json()
    again = lab.Data.from_json(blob)
    assert again.to_json() == blob and again.ips.m2 == d.ips.m2
    assert lab.ip_of(d, 'm3_h') == d.ips.m3 and lab.visible('gw_h') == 'gw' and lab.clone('m1') == 'm1_h'
    for _ in range(5):
        other = lab.Data.generate()
        assert not other.nets.lan.overlaps(lab.IPv4Network("172.17.0.0/16"))
        assert not other.nets.ext.overlaps(lab.IPv4Network("10.0.0.0/16"))


def test_topology_and_machines(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    assert ns.get_machine_names() == ['m1', 'm2', 'm3', 'gw', 'ext1', 'm1_h', 'm2_h', 'm3_h', 'gw_h', 'ext1_h']
    nets = {n.name: n for n in ns.get_networks()}
    assert set(nets) == {'lan', 'ext', 'lan_h', 'ext_h'} and all(n.mode == 'switch' for n in nets.values())
    assert [m.name for m in nets['lan'].get_machines()] == ['m1', 'm2', 'm3', 'gw']
    assert [m.name for m in nets['ext_h'].get_machines()] == ['gw_h', 'ext1_h']
    assert [n.name for n in ns.get_visible_networks()] == ['lan', 'ext']
    machines = {m.name: m for m in ns.get_machines()}
    assert all(machines[m].hidden and not machines[m].allow_connection for m in machines if m.endswith('_h'))
    assert not any(machines[m].hidden for m in lab.VISIBLE_MACHINES)


def test_initial_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'initial')
    d = data
    for m in ns.get_machine_names():
        cmds = _cmds(ops, 1, m)
        files = _files(ops, 1, m)
        assert 'nft flush ruleset' in cmds
        assert any(f'sysctl -w net.ipv4.ip_forward={1 if lab.visible(m) == "gw" else 0}' in c for c in cmds), m
        start = [c for c in cmds if 'sre_server_echo.py' in c and 'python3' in c]
        assert len(start) == 1 and f" {lab.visible(m)} 80 8080 udp:530 udp:630'" in start[0], (m, start)
        assert '/usr/local/sbin/sre_server_echo.py' in files and files['/etc/resolv.conf'] == ''
        hosts = files['/etc/hosts']
        assert f"{_ip(d.ips.m2)}\t\tm2.lab\tm2" in hosts and f"{_ip(d.ips.gw_lan)}\t\tgw.lab\tgw" in hosts
        assert f"127.0.1.1\t{lab.visible(m)}" in hosts
    for suffix in ('', '_h'):
        assert f"ip address add {d.ips.m1} dev eth0" in _cmds(ops, 1, 'm1' + suffix)
        assert f"ip route add default via {_ip(d.ips.gw_lan)}" in _cmds(ops, 1, 'm3' + suffix)
        assert f"ip link set eth1 up; ip address add {d.ips.gw_ext} dev eth1" in _cmds(ops, 1, 'gw' + suffix)
        assert f"ip route add default via {_ip(d.ips.gw_ext)}" in _cmds(ops, 1, 'ext1' + suffix)


def test_final_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'final')
    assert list(ops) == [(1, 'm1')]
    cmds = _cmds(ops, 1, 'm1')
    assert cmds[0] == 'nft flush ruleset' and cmds[1:] == ns.cmds_all() and len(cmds) == 13
    text = "\n".join(cmds)
    assert "nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'" in text
    assert f"ip saddr {_ip(data.ips.ext1)} meta l4proto udp accept" in text
    assert f"ip saddr {_ip(data.ips.m2)} reject" in text
    assert "nft insert rule inet filter input ct state established,related accept" in text
    assert "nft insert rule inet filter input tcp dport 8080 accept" in text
    assert 'limit rate 5/minute log prefix "input drop: " group 0' in text and "jump logdrop" in text
    assert all(c.startswith('nft ') for c in cmds)


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _outputs_nothing, cheat=False)
    grades = _grades(grade)
    assert sum(g for g, _ in grades.values()) == 0, {k: v for k, v in grades.items() if v[0]}
    assert sum(mx for _, mx in grades.values()) == 100 and len(grades) == 28
    assert [str(p.title) for p in grade.get_grade_parts()] == [f'part{i}' for i in range(1, 10)]
    tests = grade.get_tests()
    # an empty ruleset: the clone is flushed, nothing is loaded
    assert [c for c, _ in tests[('m1_h', 2)]] == ['nft flush ruleset']


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _outputs_done)
    grades = _grades(grade)
    short = {k: v for k, v in grades.items() if v[0] != v[1]}
    assert not short, short
    assert sum(g for g, _ in grades.values()) == 100
    tests = grade.get_tests()
    assert grade.max_step == 3
    step2 = [c for c, _ in tests[('m1_h', 2)]]
    assert step2[0] == 'nft flush ruleset' and len(step2) == 2 and 'base64 -d | nft -f -' in step2[1]
    assert all(s in (1, 3) for (m, s) in tests if m != 'm1_h')
    probes = {m for (m, s) in tests if s == 3}
    assert probes == {'m1_h', 'm2_h', 'm3_h', 'ext1_h'}
    assert sum(len(c) for (m, s), c in tests.items() if s == 3) == 18


def test_rule_order_matters(lab, data, tmp_pub_dir):
    """The 8080 rule after the reject of m2: m2 is refused on 8080 and the order points are lost."""
    d = data
    nft_json = _nft_json(lab, d, order=['ct', 'lo', 'icmp', 'udp', 'reject', 'open', 'jump'])

    class Fw(Firewall):
        def inbound_tcp(self, src, port):
            if src in self.reject_from:
                return 'refused'
            return super().inbound_tcp(src, port)

    grades = _grades(_simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _outputs_done(l, n, m, c, nft_json, Fw(l, d)))[0])
    assert grades['open_rule_order'] == (1, 3) and grades['port_open'] == (8, 12)
    assert grades['reject_m2'] == (4, 4) and grades['reject_rule'] == (2, 2)
    assert sum(g for g, _ in grades.values()) == 94


def test_syntax_variants_are_accepted(lab, data, tmp_pub_dir):
    """ip family, iifname, ip protocol udp, reject with tcp reset, a set of ports, goto, log without group."""
    nft_json = _nft_json(lab, data, family='ip', variants=True, jump='goto', log_group=None)
    grades = _grades(_simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _outputs_done(l, n, m, c, nft_json))[0])
    assert sum(g for g, _ in grades.values()) == 100, {k: v for k, v in grades.items() if v[0] != v[1]}


def test_partial_rulesets(lab, data, tmp_pub_dir):
    d = data
    # only the policy (question 2): what must be blocked is, nothing passes
    nft_json = _nft_json(lab, d, order=[])
    fw = Firewall(lab, d, open_ports=(), reject_from=(), lo=False, udp_from=(), ct=False, icmp_reply=False)
    grades = _grades(_simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _outputs_done(l, n, m, c, nft_json, fw))[0])
    assert grades['policy_drop'] == (4, 4) and grades['base_chain'] == (2, 2)
    assert grades['ping_in_blocked'] == (3, 3) and grades['drop_m3'] == (3, 3) and grades['closed_port_blocked'] == (3, 3)
    assert grades['inbound_still_blocked'] == (2, 2)
    assert grades['lo_works'] == (0, 5) and grades['port_open'] == (0, 12) and grades['reject_m2'] == (0, 4)
    forms = sum(g for k, (g, _) in grades.items() if k.startswith('q_'))
    assert sum(g for g, _ in grades.values()) - forms == 17
    # established only, a log without limit then with a wrong limit, no drop in the named chain
    nft_json = _nft_json(lab, d, ct_states=('established',), log_limit=None)
    grades = _grades(_simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _outputs_done(l, n, m, c, nft_json))[0])
    assert grades['ct_rule'] == (2, 4) and grades['log_limit'] == (0, 3) and grades['log_chain'] == (4, 4)
    nft_json = _nft_json(lab, d, log_limit=(10, 'second'))
    grades = _grades(_simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _outputs_done(l, n, m, c, nft_json))[0])
    assert grades['log_limit'] == (1, 3) and grades['log_jump'] == (3, 3)
    # the jump is not the last rule of input
    nft_json = _nft_json(lab, d, order=['open', 'ct', 'lo', 'icmp', 'udp', 'jump', 'reject'])
    grades = _grades(_simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _outputs_done(l, n, m, c, nft_json))[0])
    assert grades['log_jump'] == (2, 3)
    # policy accept with the same rules: the firewall does not filter, the positive probes do not count
    nft_json = _nft_json(lab, d, policy='accept')
    fw = Firewall(lab, d, policy_drop=False)
    grades = _grades(_simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _outputs_done(l, n, m, c, nft_json, fw))[0])
    assert grades['policy_drop'] == (0, 4) and grades['lo_works'] == (0, 5) and grades['port_open'] == (0, 12)
    assert grades['lo_rule'] == (3, 3) and grades['reject_rule'] == (2, 2)


def test_form_answers(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _outputs_done)
    q1 = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)][0]
    answers = json.loads(grade._answers[q1.question_hash])
    answers.update({"ttl_lan": " 64 ", "ttl_ext": "TTL=63", "client_ip": f"{_ip(data.ips.m1)}/24", "ruleset": "empty"})
    grade._answers[q1.question_hash] = json.dumps(answers)
    grade.reset_before_grade()
    grade.grade()
    assert _grades(grade)['q_before'] == (6, 6)
    answers.update({"ttl_ext": "64", "client_ip": _ip(data.ips.gw_ext)})
    grade._answers[q1.question_hash] = json.dumps(answers)
    grade.reset_before_grade()
    grade.grade()
    assert _grades(grade)['q_before'] == (3, 6)
    assert lab._same_ip('x', data.ips.m1) is False and lab._is_int('', 64) is False


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def test_texts_and_instructor_fragments(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _outputs_done, instructor_mode=True)
    info = _text(ns.informations)
    assert info.count('\n## ') == 11 and 'ct state established,related' in info and 'nflog:0' in info
    assert str(data.nets.lan) not in info     # instance data belongs to the first question
    from SRE.informations import resolve_informations, resolve_text
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved)
    assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 12)]
    assert [s.tag for s in numbering.sections('fr')] == ['intro', 'hooks', 'structure', 'selectors', 'verdicts', 'conntrack',
                                                         'nft-cli', 'logging', 'testing', 'iptables', 'cheatsheet']
    assert '## <a id="conntrack"></a>6. Le suivi de connexion' in course and '- [7. La commande nft](#nft-cli)' in course
    assert '@@' not in course
    questions = list(grade.get_questions_ordered())
    assert len(questions) == 10
    resolved_questions = [_text(resolve_text(q.description, numbering)) for q in questions]
    assert all('@@ref' not in q and '@@sec' not in q for q in resolved_questions)
    assert 'section 9 des Informations' in resolved_questions[0] and 'section 3 des Informations' in resolved_questions[2]
    assert 'section 2 des' in resolved_questions[3] and 'sections 6 et\n7 des Informations' in resolved_questions[7]
    assert 'section 7 des Informations' in resolved_questions[8] and 'section 8 des Informations' in resolved_questions[9]
    with_instructor = [q for q in questions if has_instructor(_text(q.description))]
    assert len(with_instructor) == 10
    all_text = info + "".join(_text(q.description) for q in questions)
    assert "{'" not in all_text and not re.search(r"\{[a-z_0-9]+\}", all_text)
    first = _text(questions[0].description)
    for value in (data.nets.lan, data.nets.ext, data.ips.m1.ip, data.ips.m2.ip, data.ips.ext1.ip, data.ips.gw_ext.ip):
        assert str(value) in first
    for cmd in ns.cmds_all():
        assert cmd in all_text, cmd                   # every command of the solution is in an instructor text
    for e in grade.get_grade_list():
        desc = _text(e.description)
        assert "{'" not in desc and not re.search(r"\{[a-z_]+\}", desc)
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, _outputs_done, instructor_mode=False)
    student_text = _text(ns2.informations) + "".join(_text(q.description) for q in grade2.get_questions_ordered())
    assert not has_instructor(student_text) and "Pour l'enseignant" not in student_text
    assert '_h' not in student_text and 'm1_h' not in student_text     # the hidden mirror stays hidden
    assert 'nft insert rule' in student_text and 'handle N' in student_text
    html = __import__('SRE.instructor_text', fromlist=['markdown_to_html']).markdown_to_html(info)
    assert '<table>' in html and '<code>' in html and 'nc -u -w 1 m2 530</code>' in html


def test_cheat_answers_fill_every_form(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _outputs_done)
    cheat = grade.get_cheat_answers('final')
    forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
    assert len(forms) == 5
    for q in forms:
        answers = cheat[q.question_hash]
        answers = json.loads(answers) if isinstance(answers, str) else answers
        for field in q.fields:
            assert field['name'] in answers, field['name']
            if 'choices' in field:
                assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])
            elif 'regex' in field:
                assert re.fullmatch(field['regex'], answers[field['name']]), (field['name'], answers[field['name']])


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'nftables_filter1_stripped', 'exec')
    assert source.count(b'instructor(tr(') == 10


def test_english_identifiers(lab, data):
    """Machines, networks, states, data fields, grade elements and part keys are English (tr() texts are French)."""
    french = re.compile(r'(routeur|pont|reseau|serveur|sonde|panne|exemple|reponse|commutateur|passerelle|'
                        r'machine_|_machine|exterieur|filtre|regle|journal|parefeu)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.NetScheme._network_specs)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += list(vars(data.ips)) + list(vars(data.nets))
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
    names += [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', [])]
    bad = [n for n in names if french.search(n)]
    assert not bad, bad
    own_states = [n for n, v in vars(lab.NetScheme).items() if getattr(v, '_is_sre_state', False)]
    assert sorted(own_states) == ['final', 'initial']       # save / restore are the empty lifecycle states of NetScheme0
