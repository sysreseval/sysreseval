"""Offline tests of the host-firewall lab (lab/sre/_DRAFT_misc/nftables-filter1.py): data generation
with the hidden mirror, topology, the ops of the states (echo servers everywhere, flushed rulesets),
the multi-pass grading contract with synthetic outputs (nothing done: 0, questions 1 to 9 alone:
100, the reference solution: 140 and the bonus, each later question adding its own points and
costing none of the earlier ones, rule order, variants of the syntax, partial and wrong answers),
texts, instructor fragments, English identifiers.

No Docker.  A ruleset of m1 is a list of named rules per chain (`Ruleset`): its `nft -j list
ruleset` is built from the generated data in the JSON shape of nftables 1.0.6, and the probes are
answered by walking the same named rules, packet by packet (request through one chain, reply through
the other, with the conntrack state a real kernel gives each packet): what the grader reads and what
it probes cannot disagree.
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

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
# a ruleset of m1: its JSON listing and its behaviour
# ---------------------------------------------------------------------------

# The rules of the reference solution, by name, in the order `final` leaves them.
INPUT_9 = ['open', 'ct', 'lo', 'icmp', 'udp', 'reject', 'jump']                 # questions 2 to 9
INPUT_FULL = ['ban_drop', 'trap', 'allowed', 'blocklist'] + INPUT_9             # ... and 11, 13, 14
OUTPUT_10 = ['ct', 'forbidden', 'lo', 'echo', 'web', 'udp', 'reject']           # question 10
OUTPUT_FULL = ['ct', 'forbidden', 'lo', 'echo', 'web_set', 'udp', 'reject']     # ... and 12
LISTENING = (80, 8080, 8888)        # the HTTP ports of the echo server of every machine


def _match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def _payload(proto, field):
    return {"payload": {"protocol": proto, "field": field}}


def _meta(key):
    return {"meta": {"key": key}}


def _packet(src, dst, proto, dport=None, state='new'):
    """A packet seen by a chain of m1: machine names, `proto` tcp / udp / echo-request / echo-reply /
    icmp-error, the destination port of a request (a reply goes to an ephemeral port: None)."""
    return SimpleNamespace(src=src, dst=dst, proto=proto, dport=dport, state=state, lo=(src == dst == 'm1'))


class Ruleset:
    """The ruleset loaded on m1 (and so on its clone): `input` / `output` are the named rules of the
    two base chains in order (`None`: no such chain; `input=None`: no table at all), the other
    arguments spell variants.  `json()` is its `nft -j list ruleset`; `tcp()` / `udp()` / `ping()`
    are what the probes observe, `answer()` the output of a probe command."""

    def __init__(self, lab, d, input=INPUT_FULL, output=OUTPUT_FULL, policy='drop', out_policy='drop', family='inet',
                 variants=False, ct_states=('established', 'related'), out_ct_states=('established', 'related'),
                 log_limit=(5, 'minute'), log_group=0, jump='jump', blocklist=None, ports=None, pairs=None,
                 ban_seconds=None, banned_now=(), other_log_chain=False):
        self.lab, self.d = lab, d
        self.input, self.output = (None if input is None else list(input)), (None if output is None else list(output))
        self.policy, self.out_policy, self.family, self.variants = policy, out_policy, family, variants
        self.ct_states, self.out_ct_states = tuple(ct_states), tuple(out_ct_states)
        self.log_limit, self.log_group, self.jump, self.other_log_chain = log_limit, log_group, jump, other_log_chain
        self.blocklist = (lab.BLOCKED_HOST, lab.BLOCKED_NET) if blocklist is None else tuple(blocklist)
        self.ports = (lab.CLOSED_PORT, lab.SET_PORT) if ports is None else tuple(ports)
        self.pairs = tuple(lab.ALLOWED) if pairs is None else tuple(pairs)
        self.ban_seconds = lab.BAN_SECONDS if ban_seconds is None else ban_seconds
        self.banned_now = tuple(banned_now)         # banned on the real m1 while it was listed
        self.banned = set()                         # banned on the clone: its set starts empty
        self.names = {_ip(getattr(d.ips, name)): name for name in lab.HOSTS}
        self.names['127.0.0.1'] = 'm1'

    # -- behaviour: one packet through one chain ------------------------------------------

    def chain(self, hook, pkt):
        """'accept' / 'drop' / 'reject': the verdict of the chain of *hook* for *pkt*."""
        rules, policy = (self.input, self.policy) if hook == 'input' else (self.output, self.out_policy)
        if self.input is None or rules is None:
            return 'accept'
        prefix = 'in_' if hook == 'input' else 'out_'
        for name in rules:
            verdict = getattr(self, prefix + name)(pkt)
            if verdict is not None:
                return verdict
        return policy

    def in_ban_drop(self, p):
        return 'drop' if p.src in self.banned else None

    def in_trap(self, p):
        if p.proto == 'tcp' and p.dport == self.lab.TRAP_PORT:
            self.banned.add(p.src)                  # the packet reached the `add @banned` statement
            return 'drop'
        return None

    def in_allowed(self, p):
        return 'accept' if p.proto == 'tcp' and (p.src, p.dport) in self.pairs else None

    def in_blocklist(self, p):
        networks = {'guest1': 'guest', 'ext1': 'ext', 'ext2': 'ext', 'ext3': 'ext'}
        return 'drop' if p.src in self.blocklist or networks.get(p.src) in self.blocklist else None

    def in_open(self, p):
        return 'accept' if p.proto == 'tcp' and p.dport == self.lab.OPEN_PORT else None

    def in_ct(self, p):
        return 'accept' if p.state in self.ct_states else None

    def in_lo(self, p):
        return 'accept' if p.lo else None

    def in_icmp(self, p):
        return 'accept' if p.proto == 'echo-reply' else None

    def in_udp(self, p):
        return 'accept' if p.proto == 'udp' and p.src == self.lab.UDP_SERVER else None

    def in_reject(self, p):
        return 'reject' if p.src == self.lab.REJECTED else None

    def in_jump(self, p):
        return 'drop'                               # the logging chain drops whatever reaches it

    def out_ct(self, p):
        return 'accept' if p.state in self.out_ct_states else None

    def out_forbidden(self, p):
        return 'reject' if p.dst == self.lab.FORBIDDEN else None

    def out_forbidden_drop(self, p):
        return 'drop' if p.dst == self.lab.FORBIDDEN else None

    def out_lo(self, p):
        return 'accept' if p.lo else None

    def out_echo(self, p):
        return 'accept' if p.proto == 'echo-request' else None

    def out_web(self, p):
        return 'accept' if p.proto == 'tcp' and p.dport == self.lab.CLOSED_PORT else None

    def out_web_set(self, p):
        return 'accept' if p.proto == 'tcp' and p.dport in self.ports else None

    def out_udp(self, p):
        return 'accept' if p.proto == 'udp' and p.dport in self.lab.UDP_PORTS else None

    def out_reject(self, p):
        return 'reject'

    # -- behaviour: what a probe observes -------------------------------------------------

    def _exchange(self, src, dst, request, reply, dport):
        """'open' / 'refused' / 'dropped' for a request of *src* answered by *dst*.  m1 filters what
        it emits in output and what it receives in input; a reply is `established`, the error
        message of a `reject` is `related` and has to get out of m1 (or back to it through lo)."""
        def error_heard(to):
            if self.chain('output', _packet('m1', to, 'icmp-error', state='related')) != 'accept':
                return False
            return to != 'm1' or self.chain('input', _packet('m1', 'm1', 'icmp-error', state='related')) == 'accept'

        if src == 'm1':
            verdict = self.chain('output', _packet('m1', dst, request, dport))
            if verdict != 'accept':
                return 'refused' if verdict == 'reject' and error_heard('m1') else 'dropped'
        if dst == 'm1':
            verdict = self.chain('input', _packet(src, 'm1', request, dport))
            if verdict != 'accept':
                return 'refused' if verdict == 'reject' and error_heard(src) else 'dropped'
            if self.chain('output', _packet('m1', src, reply, state='established')) != 'accept':
                return 'dropped'
        if src == 'm1' and self.chain('input', _packet(dst, 'm1', reply, state='established')) != 'accept':
            return 'dropped'
        return 'open'

    def tcp(self, src, dst, port):
        verdict = self._exchange(src, dst, 'tcp', 'tcp', port)
        return 'refused' if verdict == 'open' and port not in LISTENING else verdict

    def udp(self, src, dst, port):
        return self._exchange(src, dst, 'udp', 'udp', port) == 'open'

    def ping(self, src, dst):
        return self._exchange(src, dst, 'echo-request', 'echo-reply', None) == 'open'

    def answer(self, machine, command):
        """The output of a probe command run on *machine* (a clone), `None` for any other command."""
        d, src = self.d, self.lab.visible(machine)
        own = '127.0.0.1' if src == 'm1' else _ip(getattr(d.ips, src))
        m = _CURL.search(command)
        if m:
            ip, port = m.group(1), int(m.group(2))
            dst = self.names[ip]
            client = '127.0.0.1' if ip == '127.0.0.1' else _ip(getattr(d.ips, src))
            return (_echo(dst, ip, port, client), 0) if self.tcp(src, dst, port) == 'open' else ("", 28)
        m = _NC.search(command)
        if m:
            ip, port = m.group(1), int(m.group(2))
            dst = self.names[ip]
            return (_echo(dst, ip, port, own), 0) if self.udp(src, dst, port) else ("", 0)
        m = _TCP.search(command)
        if m:
            verdict = self.tcp(src, self.names[m.group(1)], int(m.group(2)))
            return {"open": "RC=0\n", "refused": "RC=1\n", "dropped": "RC=124\n"}[verdict], 0
        m = _PING.search(command)
        if m:
            ip = m.group(1)
            return _ping_ok(ip) if self.ping(src, self.names[ip]) else _ping_ko(ip)
        return None

    # -- the listing ----------------------------------------------------------------------

    def listing(self):
        """`nft list ruleset`: only its being empty or not matters to the grader."""
        return "" if self.input is None else f"table {self.family} filter {{\n\tchain input {{\n\t}}\n}}\n"

    def _expr(self, hook, name):
        lab, d = self.lab, self.d
        ip = lambda machine: _ip(getattr(d.ips, machine))       # noqa: E731
        accept, drop = {"accept": None}, {"drop": None}
        states = lambda s: _match({"ct": {"key": "state"}}, list(s) if len(s) > 1 else s[0], "in")     # noqa: E731
        if hook == 'input':
            return {
                'ban_drop': [_match(_payload("ip", "saddr"), "@" + lab.BAN_SET), drop],
                'trap': [_match(_payload("tcp", "dport"), lab.TRAP_PORT),
                         {"set": {"op": "add", "elem": _payload("ip", "saddr"), "set": "@" + lab.BAN_SET}}, drop],
                'allowed': [_match({"concat": [_payload("ip", "saddr"), _payload("tcp", "dport")]}, "@" + lab.ALLOW_SET), accept],
                'blocklist': [_match(_payload("ip", "saddr"), "@" + lab.BLOCK_SET), drop],
                'open': [_match(_payload("tcp", "dport"), {"set": [lab.OPEN_PORT, 9090]} if self.variants else lab.OPEN_PORT), accept],
                'ct': [states(self.ct_states), accept],
                'lo': [_match(_meta("iifname" if self.variants else "iif"), "lo"), accept],
                'icmp': [_match(_payload("icmp", "type"), "echo-reply"), accept],
                'udp': [_match(_payload("ip", "saddr"), ip(lab.UDP_SERVER)),
                        _match(_payload("ip", "protocol"), "udp") if self.variants else _match(_meta("l4proto"), "udp"), accept],
                'reject': [_match(_payload("ip", "saddr"), ip(lab.REJECTED)),
                           {"reject": {"type": "tcp reset"}} if self.variants else {"reject": {"type": "icmp", "expr": "port-unreachable"}}],
                'jump': [{self.jump: {"target": lab.LOG_CHAIN}}],
            }[name]
        return {
            'ct': [states(self.out_ct_states), accept],
            'forbidden': [_match(_payload("ip", "daddr"), ip(lab.FORBIDDEN)), {"reject": {"type": "icmp", "expr": "port-unreachable"}}],
            'forbidden_drop': [_match(_payload("ip", "daddr"), ip(lab.FORBIDDEN)), drop],
            'lo': [_match(_meta("oifname" if self.variants else "oif"), "lo"), accept],
            'echo': [_match(_payload("icmp", "type"), "echo-request"), accept],
            'web': [_match(_payload("tcp", "dport"), lab.CLOSED_PORT), accept],
            'web_set': [_match(_payload("tcp", "dport"), "@" + lab.PORT_SET), accept],
            'udp': [_match(_payload("udp", "dport"), {"set": list(lab.UDP_PORTS)}), accept],
            'reject': [{"reject": {"type": "icmpx", "expr": "port-unreachable"}}],
        }[name]

    def _sets(self):
        """The set objects the rules refer to, as nftables 1.0.6 lists them."""
        lab, d, used = self.lab, self.d, set(self.input or []) | {'out_' + name for name in self.output or []}
        base = {"family": self.family, "table": lab.TABLE}
        sets = []
        if 'out_web_set' in used:
            sets.append({"set": dict(base, name=lab.PORT_SET, type="inet_service", handle=40, elem=list(self.ports))})
        if 'blocklist' in used:
            elements = []
            for item in self.blocklist:
                if hasattr(d.nets, item):
                    network = getattr(d.nets, item)
                    elements.append({"prefix": {"addr": str(network.network_address), "len": network.prefixlen}})
                else:
                    elements.append(_ip(getattr(d.ips, item)))
            sets.append({"set": dict(base, name=lab.BLOCK_SET, type="ipv4_addr", handle=41, flags=["interval"], elem=elements)})
        if 'allowed' in used:
            pairs = [{"concat": [_ip(getattr(d.ips, machine)), port]} for machine, port in self.pairs]
            sets.append({"set": dict(base, name=lab.ALLOW_SET, type=["ipv4_addr", "inet_service"], handle=42, elem=pairs)})
        if used & {'trap', 'ban_drop'}:
            banned = dict(base, name=lab.BAN_SET, type="ipv4_addr", handle=43, size=65535, flags=["timeout"],
                          timeout=self.ban_seconds)
            if self.banned_now:
                banned["elem"] = [{"elem": {"val": _ip(getattr(d.ips, machine)), "expires": 41}} for machine in self.banned_now]
            sets.append({"set": banned})
        return sets

    def json(self):
        """`nft -j list ruleset` of m1."""
        if self.input is None:
            return ""
        lab, family, table = self.lab, self.family, self.lab.TABLE
        objs = [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}},
                {"table": {"family": family, "name": table, "handle": 2}}]
        objs += self._sets()
        if self.other_log_chain:        # a logging chain input does not jump to, listed before the real one
            objs.append({"chain": {"family": family, "table": table, "name": "audit", "handle": 6}})
        objs.append({"chain": {"family": family, "table": table, "name": lab.CHAIN, "handle": 1, "type": "filter",
                               "hook": "input", "prio": 0, "policy": self.policy}})
        if 'jump' in self.input:
            objs.append({"chain": {"family": family, "table": table, "name": lab.LOG_CHAIN, "handle": 7}})
        if self.output is not None:
            objs.append({"chain": {"family": family, "table": table, "name": lab.OUT_CHAIN, "handle": 8, "type": "filter",
                                   "hook": "output", "prio": 0, "policy": self.out_policy}})
        handle = 100

        def rule(chain, expr):
            nonlocal handle
            handle += 1
            return {"rule": {"family": family, "table": table, "chain": chain, "handle": handle, "expr": expr}}

        if self.other_log_chain:
            objs.append(rule("audit", [{"log": {"prefix": "audit: "}}]))
        for name in self.input:
            objs.append(rule(lab.CHAIN, self._expr('input', name)))
        if 'jump' in self.input:
            log_expr = []
            if self.log_limit is not None:
                log_expr.append({"limit": {"rate": self.log_limit[0], "per": self.log_limit[1]}})
            log = {"prefix": lab.LOG_PREFIX}
            if self.log_group is not None:
                log["group"] = self.log_group
            log_expr.append({"log": log})
            objs.append(rule(lab.LOG_CHAIN, log_expr))
            objs.append(rule(lab.LOG_CHAIN, [{"counter": {"packets": 17, "bytes": 1020}}, {"drop": None}]))
        for name in self.output or []:
            objs.append(rule(lab.OUT_CHAIN, self._expr('output', name)))
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


def _simulate(lab, data, tmp_pub_dir, ruleset=None, instructor_mode=False, cheat=True, clone_loaded=True):
    """Multi-pass grade() like run_tests(), against *ruleset* (default: the reference solution, an
    empty `Ruleset(lab, data, input=None)` for a fresh project): returns (grade, net_scheme)."""
    ruleset = Ruleset(lab, data) if ruleset is None else ruleset
    ruleset.banned = set()
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)

    def output(machine, command):
        if machine == 'm1' and command == 'nft -j list ruleset':
            return ruleset.json(), 0
        if command == 'nft list ruleset':
            return (ruleset.listing() if machine == 'm1' or clone_loaded else ""), 0
        probe = ruleset.answer(machine, command)
        return probe if probe is not None else ("", 0)

    keys = None
    while grade.step <= grade.max_step:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            # a command may join a later step once the ruleset is known (the load on the clone, the
            # flush of its fed sets), never leave, and never join a step that already ran
            for key, cmds in current.items():
                assert cmds >= keys.get(key, set()), "a registered test disappeared between two passes"
                assert key[1] > grade.step or cmds == keys.get(key, set()), f"a test was registered for the past step {key}"
        keys = current
        grade.step += 1
        for (m, s), cmds in grade.get_tests().items():
            if s == grade.step:
                for key in list(cmds):
                    cmds[key] = output(m, key[0])
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _totals(grade):
    """(points of the regular elements, points of the bonus elements)."""
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus)


def _part(grade, number, forms=True):
    """The points of part *number* (without the form elements when *forms* is false: the forms are
    filled by the cheat answers whatever the ruleset)."""
    return sum(e.grade for e in grade.get_grade_list()
               if str(e.grade_part) == f'part{number}' and (forms or not str(e.title).startswith('q_')))


def _parts(grade, numbers, forms=True):
    return sum(_part(grade, number, forms) for number in numbers)


EARLIER = range(1, 10)          # the parts of questions 1 to 9: 100 points


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


def test_data_generation_and_round_trip(lab, data):
    d = data
    nets = [d.nets.lan, d.nets.ext, d.nets.guest]
    assert all(n.prefixlen == 24 for n in nets)
    assert not any(a.overlaps(b) for i, a in enumerate(nets) for b in nets[i + 1:])
    assert d.nets.lan_h == d.nets.lan and d.nets.ext_h == d.nets.ext and d.nets.guest_h == d.nets.guest
    for key, part in lab.HOST_PARTS.items():
        net = getattr(d.nets, lab.ADDRESSED[key])
        assert getattr(d.ips, key).ip == net.network_address + part and getattr(d.ips, key).network == net
    assert d.ips.m1_h == d.ips.m1 and d.ips.ext1_h == d.ips.ext1 and d.ips.ext3_h == d.ips.ext3
    assert d.ips.guest1_h == d.ips.guest1
    assert d.ips.gw_h_lan_h == d.ips.gw_lan and d.ips.gw_h_ext_h == d.ips.gw_ext and d.ips.gw_h_guest_h == d.ips.gw_guest
    blob = d.to_json()
    again = lab.Data.from_json(blob)
    assert again.to_json() == blob and again.ips.m2 == d.ips.m2 and again.nets.guest == d.nets.guest
    assert lab.ip_of(d, 'm3_h') == d.ips.m3 and lab.visible('gw_h') == 'gw' and lab.clone('m1') == 'm1_h'
    assert lab.allowed_pairs(d) == [(_ip(d.ips.ext2), 80), (_ip(d.ips.m3), 8888)]
    for _ in range(5):
        other = lab.Data.generate()
        assert not other.nets.lan.overlaps(lab.IPv4Network("172.17.0.0/16"))
        assert not other.nets.ext.overlaps(lab.IPv4Network("10.0.0.0/16"))


def test_later_questions_use_what_the_first_nine_never_probe(lab):
    """The rule behind "no question costs the points of another": the restrictions of questions 10
    to 14 are observed on other machines and other ports than those of questions 1 to 9."""
    first_nine = {'m2', 'm3', 'ext1'}
    assert {lab.FORBIDDEN, lab.BLOCKED_HOST, lab.BLOCKED_NET_HOST}.isdisjoint(first_nine | {'m1', 'gw'})
    assert lab.UDP_SERVER in first_nine and lab.REJECTED in first_nine
    assert lab.SET_PORT not in (lab.OPEN_PORT, lab.CLOSED_PORT) and lab.SET_PORT in lab.HTTP_PORTS
    assert lab.TRAP_PORT not in lab.HTTP_PORTS
    # the allowlist opens the port of questions 6 and 8 to a new machine only, the new port to an old one
    assert dict(lab.ALLOWED) == {lab.FORBIDDEN: lab.CLOSED_PORT, 'm3': lab.SET_PORT}
    # the ban is probed after every other probe
    assert lab.PROBE_STEP < lab.TRAP_STEP < lab.BAN_STEP


def test_topology_and_machines(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    visible = ['m1', 'm2', 'm3', 'gw', 'ext1', 'ext2', 'ext3', 'guest1']
    assert ns.get_machine_names() == visible + [m + '_h' for m in visible]
    assert sorted(lab.VISIBLE_MACHINES) == sorted(visible)
    nets = {n.name: n for n in ns.get_networks()}
    assert set(nets) == {'lan', 'ext', 'guest', 'lan_h', 'ext_h', 'guest_h'} and all(n.mode == 'switch' for n in nets.values())
    assert [m.name for m in nets['lan'].get_machines()] == ['m1', 'm2', 'm3', 'gw']
    assert [m.name for m in nets['ext_h'].get_machines()] == ['gw_h', 'ext1_h', 'ext2_h', 'ext3_h']
    assert [m.name for m in nets['guest'].get_machines()] == ['gw', 'guest1']
    assert [n.name for n in ns.get_visible_networks()] == ['lan', 'ext', 'guest']
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
        assert len(start) == 1 and f" {lab.visible(m)} 80 8080 8888 udp:530 udp:630'" in start[0], (m, start)
        assert '/usr/local/sbin/sre_server_echo.py' in files and files['/etc/resolv.conf'] == ''
        hosts = files['/etc/hosts']
        assert f"{_ip(d.ips.m2)}\t\tm2.lab\tm2" in hosts and f"{_ip(d.ips.gw_lan)}\t\tgw.lab\tgw" in hosts
        assert f"{_ip(d.ips.ext3)}\t\text3.lab\text3" in hosts and f"{_ip(d.ips.guest1)}\t\tguest1.lab\tguest1" in hosts
        assert f"127.0.1.1\t{lab.visible(m)}" in hosts
    for suffix in ('', '_h'):
        assert f"ip address add {d.ips.m1} dev eth0" in _cmds(ops, 1, 'm1' + suffix)
        assert f"ip route add default via {_ip(d.ips.gw_lan)}" in _cmds(ops, 1, 'm3' + suffix)
        gw = _cmds(ops, 1, 'gw' + suffix)
        assert f"ip link set eth1 up; ip address add {d.ips.gw_ext} dev eth1" in gw
        assert f"ip link set eth2 up; ip address add {d.ips.gw_guest} dev eth2" in gw
        for m in ('ext1', 'ext2', 'ext3'):
            assert f"ip address add {getattr(d.ips, m)} dev eth0" in _cmds(ops, 1, m + suffix)
            assert f"ip route add default via {_ip(d.ips.gw_ext)}" in _cmds(ops, 1, m + suffix)
        assert f"ip address add {d.ips.guest1} dev eth0" in _cmds(ops, 1, 'guest1' + suffix)
        assert f"ip route add default via {_ip(d.ips.gw_guest)}" in _cmds(ops, 1, 'guest1' + suffix)


def test_final_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'final')
    assert list(ops) == [(1, 'm1')]
    cmds = _cmds(ops, 1, 'm1')
    assert cmds[0] == 'nft flush ruleset' and cmds[1:] == ns.cmds_all() and len(cmds) == 36
    text = "\n".join(cmds)
    assert "nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'" in text
    assert f"ip saddr {_ip(data.ips.ext1)} meta l4proto udp accept" in text
    assert f"ip saddr {_ip(data.ips.m2)} reject" in text
    assert "nft insert rule inet filter input ct state established,related accept" in text
    assert "nft insert rule inet filter input tcp dport 8080 accept" in text
    assert 'limit rate 5/minute log prefix "input drop: " group 0' in text and "jump logdrop" in text
    assert all(c.startswith('nft ') for c in cmds)
    # question 10: the chain is created open, filled, and its policy goes to drop last
    ext2, ext3, m3 = _ip(data.ips.ext2), _ip(data.ips.ext3), _ip(data.ips.m3)
    chain = "nft 'add chain inet filter output {{ type filter hook output priority 0; policy {}; }}'"
    assert ns.cmds_output() == [chain.format('accept'),
                                f"nft add rule inet filter output ip daddr {ext2} reject",
                                "nft insert rule inet filter output ct state established,related accept",
                                "nft add rule inet filter output oif lo accept",
                                "nft add rule inet filter output icmp type echo-request accept",
                                "nft add rule inet filter output tcp dport 80 accept",
                                "nft 'add rule inet filter output udp dport { 530, 630 } accept'",
                                "nft add rule inet filter output reject",
                                chain.format('drop')]
    assert ns.cmds_blocklist() == ["nft 'add set inet filter blocklist { type ipv4_addr; flags interval; }'",
                                   f"nft 'add element inet filter blocklist {{ {ext3} }}'",
                                   "nft insert rule inet filter input ip saddr @blocklist drop",
                                   f"nft 'add element inet filter blocklist {{ {data.nets.guest} }}'"]
    assert ns.cmds_port_set() == ["nft 'add set inet filter web_ports { type inet_service; }'",
                                  "nft 'add element inet filter web_ports { 80 }'",
                                  "nft replace rule inet filter output handle $(nft -a list chain inet filter output"
                                  " | awk '/tcp dport 80 accept/ {print $NF}') tcp dport @web_ports accept",
                                  "nft 'add element inet filter web_ports { 8888 }'"]
    assert ns.cmds_allowed() == ["nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'",
                                 f"nft 'add element inet filter allowed {{ {ext2} . 80, {m3} . 8888 }}'",
                                 "nft insert rule inet filter input ip saddr . tcp dport @allowed accept"]
    assert ns.cmds_ban() == ["nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'",
                             "nft 'insert rule inet filter input tcp dport 23 add @banned { ip saddr } drop'",
                             "nft insert rule inet filter input ip saddr @banned drop"]
    # every later rule of input is inserted: the rules of questions 2 to 9 keep their order, the jump stays last
    later = [c for c in ns.cmds_blocklist() + ns.cmds_allowed() + ns.cmds_ban() if ' rule ' in c]
    assert len(later) == 4 and all('insert rule inet filter input ' in c for c in later)
    # ... and the named rules of the model are those commands, in the order they leave
    assert INPUT_FULL == ['ban_drop', 'trap', 'allowed', 'blocklist', 'open', 'ct', 'lo', 'icmp', 'udp', 'reject', 'jump']


# ---------------------------------------------------------------------------
# grading: the two ends, and the two halves
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=None), cheat=False)
    grades = _grades(grade)
    assert sum(g for g, _ in grades.values()) == 0, {k: v for k, v in grades.items() if v[0]}
    elements = grade.get_grade_list()
    assert sum(e.max_grade for e in elements if not e.bonus) == 140 and sum(e.max_grade for e in elements if e.bonus) == 6
    assert len(grades) == 51
    assert [str(p.title) for p in grade.get_grade_parts()] == [f'part{i}' for i in range(1, 15)]
    assert [sum(e.max_grade for e in elements if str(e.grade_part) == f'part{i}') for i in range(1, 15)] == [
        6, 10, 8, 10, 10, 12, 14, 18, 12, 16, 9, 6, 9, 6]
    assert {str(e.grade_part) for e in elements if e.bonus} == {'part14'}
    tests = grade.get_tests()
    # an empty ruleset: the clone is flushed, nothing is loaded
    assert [c for c, _ in tests[('m1_h', 2)]] == ['nft flush ruleset']
    assert grade.get_errors() == []


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir)
    grades = _grades(grade)
    short = {k: v for k, v in grades.items() if v[0] != v[1]}
    assert not short, short
    assert _totals(grade) == (140, 6)
    tests = grade.get_tests()
    assert grade.max_step == 5 and grade.get_errors() == []
    step2 = [c for c, _ in tests[('m1_h', 2)]]
    assert step2[0] == 'nft flush ruleset' and 'base64 -d | nft -f -' in step2[1]
    assert step2[2:] == ['nft flush set inet filter banned']         # the fed set starts empty on the clone
    assert all(s != 2 for (m, s) in tests if m != 'm1_h')
    probes = {m for (m, s) in tests if s == 3}
    assert probes == {'m1_h', 'm2_h', 'm3_h', 'ext1_h', 'ext2_h', 'ext3_h', 'guest1_h'}
    assert {m: len(c) for (m, s), c in tests.items() if s == 3} == {
        'm1_h': 14, 'm2_h': 3, 'm3_h': 4, 'ext1_h': 4, 'ext2_h': 3, 'ext3_h': 1, 'guest1_h': 1}
    # the bonus: one connection to the trap port, then two probes (and the listing of the clone)
    assert {m: len(c) for (m, s), c in tests.items() if s == 4} == {'ext1_h': 1}
    assert {m: len(c) for (m, s), c in tests.items() if s == 5} == {'m1_h': 1, 'ext1_h': 1, 'm3_h': 1}
    assert not any(m in lab.VISIBLE_MACHINES and m != 'm1' for (m, s) in tests)      # only m1 is read, never probed


def test_questions_1_to_9_alone_are_worth_100(lab, data, tmp_pub_dir):
    """The ruleset of questions 2 to 9, without any of the later rules: its 100 points, and nothing
    of the later parts (their forms apart)."""
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=INPUT_9, output=None))
    assert _parts(grade, EARLIER) == 100
    assert [_part(grade, n, forms=False) for n in range(10, 15)] == [0, 0, 0, 0, 0]
    assert _totals(grade) == (100 + 2 + 2 + 1 + 1, 1)            # the forms of questions 10 to 14


def test_each_later_question_adds_its_points_and_costs_none(lab, data, tmp_pub_dir):
    """Questions 10 to 14 done one after the other: each adds exactly its own points, and the 100
    points of questions 1 to 9 are there after each of them."""
    steps = [
        (dict(input=INPUT_9, output=OUTPUT_10), [14, 0, 0, 0, 0]),                                      # question 10
        (dict(input=['blocklist'] + INPUT_9, output=OUTPUT_10), [14, 7, 0, 0, 0]),                      # 11
        (dict(input=['blocklist'] + INPUT_9, output=OUTPUT_FULL), [14, 7, 5, 0, 0]),                    # 12
        (dict(input=['allowed', 'blocklist'] + INPUT_9, output=OUTPUT_FULL), [14, 7, 5, 8, 0]),         # 13
        (dict(input=INPUT_FULL, output=OUTPUT_FULL), [14, 7, 5, 8, 5]),                                 # 14 (bonus)
    ]
    for arguments, expected in steps:
        grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, **arguments))
        assert _parts(grade, EARLIER) == 100, (arguments, {k: v for k, v in _grades(grade).items() if v[0] != v[1]})
        assert [_part(grade, n, forms=False) for n in range(10, 15)] == expected, arguments


def test_intermediate_states_of_question_10_keep_the_earlier_points(lab, data, tmp_pub_dir):
    """(a) the chain and a drop, (b) a reject, (c) the stateful rule, (d) the accept rules and the
    final reject, then the policy: no step of the question takes a point of questions 1 to 9."""
    states = [
        (dict(output=['forbidden_drop'], out_policy='accept'), dict(out_forbidden=(2, 3), out_replies=(0, 3))),
        (dict(output=['forbidden'], out_policy='accept'), dict(out_forbidden=(3, 3), out_replies=(0, 3))),
        (dict(output=['ct', 'forbidden'], out_policy='accept'), dict(out_forbidden=(3, 3), out_replies=(3, 3), out_ct_rule=(2, 2))),
        (dict(output=OUTPUT_10, out_policy='accept'), dict(out_whitelist=(3, 3), out_policy=(0, 2), out_lo=(0, 1))),
        (dict(output=OUTPUT_10, out_policy='drop'), dict(out_whitelist=(3, 3), out_policy=(2, 2), out_lo=(1, 1))),
    ]
    for arguments, expected in states:
        grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=INPUT_9, **arguments))
        grades = _grades(grade)
        assert _parts(grade, EARLIER) == 100, (arguments, {k: v for k, v in grades.items() if v[0] != v[1]})
        assert {k: grades[k] for k in expected} == expected, arguments


def test_one_later_feature_missing_costs_only_its_own_elements(lab, data, tmp_pub_dir):
    """The full solution without one of the later rules: its part falls, every other part is whole."""
    full = {10: 14, 11: 7, 12: 5, 13: 8, 14: 5}
    cases = [
        (dict(input=[r for r in INPUT_FULL if r != 'blocklist']), {11: 0}),
        (dict(output=OUTPUT_10), {12: 0}),                                  # the port set was never made
        (dict(input=[r for r in INPUT_FULL if r != 'allowed']), {13: 0}),
        (dict(input=[r for r in INPUT_FULL if r not in ('trap', 'ban_drop')]), {14: 0}),
        (dict(input=[r for r in INPUT_FULL if r != 'ban_drop']), {14: 1}),  # the set is fed, nothing reads it
        (dict(ports=(80,)), {12: 1}),                                       # the set is there, the new port is not in it
        (dict(blocklist=('ext3',)), {11: 4}),                               # the network was not added: its probe and the element point
        (dict(pairs=(('ext2', 80),)), {13: 4}),                             # one pair only: 1 + 2 + 1
        (dict(ban_seconds=600), {14: 4}),                                   # another delay than the one asked
    ]
    for arguments, changed in cases:
        grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, **arguments))
        assert _parts(grade, EARLIER) == 100, (arguments, {k: v for k, v in _grades(grade).items() if v[0] != v[1]})
        assert {n: _part(grade, n, forms=False) for n in full} == {**full, **changed}, arguments


def test_a_wrong_output_chain_costs_what_it_breaks(lab, data, tmp_pub_dir):
    """What is graded is the final ruleset: the documented coupling between question 10 and the
    probes of questions 1 to 9 that go through the output chain."""
    # `ct state established` without `related`: the error of the reject of question 6 no longer leaves m1
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, out_ct_states=('established',)))
    grades = _grades(grade)
    assert grades['reject_m2'] == (0, 4) and grades['out_ct_rule'] == (1, 2)
    assert _parts(grade, EARLIER) == 96 and _totals(grade) == (140 - 4 - 1, 6)
    # no stateful rule at all: m1 answers nobody (the open port, the UDP server, the refusal)
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, output=[r for r in OUTPUT_FULL if r != 'ct']))
    grades = _grades(grade)
    assert grades['port_open'] == (0, 12) and grades['udp_server_queries'] == (0, 2) and grades['reject_m2'] == (0, 4)
    assert grades['out_replies'] == (0, 3) and grades['allowed_pairs'] == (0, 4) and grades['out_ct_rule'] == (0, 2)
    assert grades['lo_works'] == (5, 5) and grades['local_tcp'] == (5, 5) and grades['ping_out'] == (5, 5)   # what m1 opens still works
    # the policy drop alone: m1 emits nothing
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, output=[]))
    grades = _grades(grade)
    for name in ('lo_works', 'ping_out', 'udp_from_server', 'local_tcp', 'local_udp', 'port_open', 'reject_m2'):
        assert grades[name][0] == 0, name
    assert grades['out_policy'] == (2, 2) and grades['out_forbidden'] == (0, 3) and grades['out_whitelist'] == (0, 3)
    # the forbidden destination before the stateful rule: ext2 is not served any more (10 c), nor let in (13)
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, output=['forbidden', 'ct'] + OUTPUT_FULL[2:]))
    grades = _grades(grade)
    assert grades['out_replies'] == (0, 3) and grades['allowed_pairs'] == (2, 4) and grades['allowed_only'] == (1, 2)
    assert _parts(grade, EARLIER) == 100
    # no final reject: what is not allowed is dropped by the policy (a delay instead of a refusal)
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, output=OUTPUT_FULL[:-1]))
    grades = _grades(grade)
    assert grades['out_whitelist'] == (2, 3) and grades['out_forbidden'] == (3, 3) and _parts(grade, EARLIER) == 100
    # no `oif lo`: the other port of the local server is refused, the one of question 3 is an allowed port
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, output=[r for r in OUTPUT_FULL if r != 'lo']))
    grades = _grades(grade)
    assert grades['out_lo'] == (0, 1) and grades['lo_works'] == (5, 5) and _parts(grade, EARLIER) == 100


def test_rule_order_matters(lab, data, tmp_pub_dir):
    """The 8080 rule after the reject of m2: m2 is refused on 8080 and the order points are lost."""
    order = ['ct', 'lo', 'icmp', 'udp', 'reject', 'open', 'jump']
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=order, output=None))
    grades = _grades(grade)
    assert grades['open_rule_order'] == (1, 3) and grades['port_open'] == (8, 12)
    assert grades['reject_m2'] == (4, 4) and grades['reject_rule'] == (2, 2)
    assert _parts(grade, EARLIER) == 94
    # the same with the later questions on top: their own points are whole
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=INPUT_FULL[:4] + order))
    assert _parts(grade, EARLIER) == 94 and _totals(grade) == (134, 6)
    # question 8 done with a handle, right before the reject (after the stateful rule): every point
    order = ['ct', 'lo', 'icmp', 'udp', 'open', 'reject', 'jump']
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=INPUT_FULL[:4] + order))
    assert _totals(grade) == (140, 6)
    # the blocklist rule after the open port: the blocklisted machines still get it
    order = ['ban_drop', 'trap', 'allowed', 'open', 'blocklist'] + INPUT_9[1:]
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=order))[0])
    assert grades['blocklist_rule'] == (1, 2) and grades['blocklist_host'] == (0, 2) and grades['blocklist_net'] == (0, 2)
    # the allowlist rule appended after the jump: never reached
    order = [r for r in INPUT_FULL if r != 'allowed'] + ['allowed']
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=order))[0])
    assert grades['allowed_set'] == (2, 2) and grades['allowed_pairs'] == (0, 4) and grades['allowed_only'] == (0, 2)
    assert grades['log_jump'] == (3, 3)             # a set rule left after the jump does not undo question 9
    # the ban rules after the open port: the banned machine still gets it
    order = ['allowed', 'blocklist', 'open', 'ban_drop', 'trap'] + INPUT_9[1:]
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=order))[0])
    assert grades['ban_rules'] == (1, 2) and grades['ban_works'] == (0, 2) and grades['ban_set'] == (1, 1)


def test_syntax_variants_are_accepted(lab, data, tmp_pub_dir):
    """ip family, iifname / oifname, ip protocol udp, reject with tcp reset, a set of ports, goto, log without group."""
    ruleset = Ruleset(lab, data, family='ip', variants=True, jump='goto', log_group=None)
    grade, _ = _simulate(lab, data, tmp_pub_dir, ruleset)
    assert _totals(grade) == (140, 6), {k: v for k, v in _grades(grade).items() if v[0] != v[1]}
    # the same for questions 1 to 9 alone
    ruleset = Ruleset(lab, data, input=INPUT_9, output=None, family='ip', variants=True, jump='goto', log_group=None)
    assert _parts(_simulate(lab, data, tmp_pub_dir, ruleset)[0], EARLIER) == 100


def test_later_questions_do_not_disturb_question_9(lab, data, tmp_pub_dir):
    """A rule of the set questions left after the jump (appended by mistake, then inserted), and a
    second logging chain listed before the one input jumps to: question 9 keeps its points."""
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=INPUT_FULL + ['blocklist', 'allowed']))
    assert _totals(grade) == (140, 6), {k: v for k, v in _grades(grade).items() if v[0] != v[1]}
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, other_log_chain=True))
    assert _totals(grade) == (140, 6), {k: v for k, v in _grades(grade).items() if v[0] != v[1]}
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=INPUT_9, output=None, other_log_chain=True))[0])
    assert grades['log_chain'] == (4, 4) and grades['log_jump'] == (3, 3) and grades['log_limit'] == (3, 3)


def test_a_ban_in_progress_on_m1_is_ignored(lab, data, tmp_pub_dir):
    """The listing of m1 holds a banned address (the student was testing): the set is emptied on the
    clone, so the probes of that machine are those of a fresh ruleset."""
    for banned in (('ext1',), ('m3', 'm2')):
        grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, banned_now=banned))
        assert _totals(grade) == (140, 6), (banned, {k: v for k, v in _grades(grade).items() if v[0] != v[1]})
        assert 'nft flush set inet filter banned' in [c for c, _ in grade.get_tests()[('m1_h', 2)]]


def _data_with_networks(lab, lan, ext, guest):
    """The data of an instance whose three networks are known (those of a live capture)."""
    d = lab.Data.generate()
    for name, network in (('lan', lan), ('ext', ext), ('guest', guest)):
        setattr(d.nets, name, lab.IPv4Network(network))
    for key, net in lab.ADDRESSED.items():
        network = getattr(d.nets, net)
        setattr(d.ips, key, lab.IPv4Interface(f"{network.network_address + lab.HOST_PARTS[key]}/{network.prefixlen}"))
    lab.hidden_mirror.copy_addressing(d, lab._TOPOLOGY, suffix=lab.MIRROR)
    d.compute_post_generate()
    return d


def test_live_listing_of_the_reference_solution(lab, tmp_pub_dir):
    """`nft -j list ruleset` of m1 captured on 2026-11-13 after `final` in a running instance
    (nftables 1.0.6, images 1.33; that evaluation gave 140 and the bonus): read by the grader for
    the same addresses, with the probes answered by the model of the same ruleset, the real listing
    is worth every point (the elements of the interval set in address order, the replaced rule at
    its place, `icmp` / `icmpx` rejects)."""
    d = _data_with_networks(lab, '192.168.74.0/24', '172.28.28.0/24', '10.144.56.0/24')
    listing = (Path(__file__).parent / 'mock_data' / 'firewall' / 'nft_json_filter1_full_live.json').read_text()

    class Live(Ruleset):
        def json(self):
            return listing

    grade, _ = _simulate(lab, d, tmp_pub_dir, Live(lab, d))
    assert _totals(grade) == (140, 6), {k: v for k, v in _grades(grade).items() if v[0] != v[1]}
    # ... and the model's own listing of that ruleset reads the same way, element by element
    assert _grades(_simulate(lab, d, tmp_pub_dir, Ruleset(lab, d))[0]) == _grades(grade)


def test_a_ruleset_that_did_not_load_on_the_clone_is_reported(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, clone_loaded=False)
    errors = grade.get_errors()
    assert len(errors) == 1 and 'was not loaded on its hidden copy m1_h' in errors[0][1], errors
    assert _simulate(lab, data, tmp_pub_dir, Ruleset(lab, data, input=None), clone_loaded=False)[0].get_errors() == []


def test_partial_rulesets(lab, data, tmp_pub_dir):
    d = data
    # only the policy (question 2): what must be blocked is, nothing passes
    grade, _ = _simulate(lab, data, tmp_pub_dir, Ruleset(lab, d, input=[], output=None))
    grades = _grades(grade)
    assert grades['policy_drop'] == (4, 4) and grades['base_chain'] == (2, 2)
    assert grades['ping_in_blocked'] == (3, 3) and grades['drop_m3'] == (3, 3) and grades['closed_port_blocked'] == (3, 3)
    assert grades['inbound_still_blocked'] == (2, 2)
    assert grades['lo_works'] == (0, 5) and grades['port_open'] == (0, 12) and grades['reject_m2'] == (0, 4)
    assert _parts(grade, range(1, 15), forms=False) == 17      # nothing of the later parts: their witnesses fail
    # established only, a log without limit then with a wrong limit
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, d, ct_states=('established',), log_limit=None))[0])
    assert grades['ct_rule'] == (2, 4) and grades['log_limit'] == (0, 3) and grades['log_chain'] == (4, 4)
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, d, log_limit=(10, 'second')))[0])
    assert grades['log_limit'] == (1, 3) and grades['log_jump'] == (3, 3)
    # the jump is not the last rule of input: a rule of question 6 comes after it
    order = ['open', 'ct', 'lo', 'icmp', 'udp', 'jump', 'reject']
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, d, input=order, output=None))[0])
    assert grades['log_jump'] == (2, 3) and grades['reject_m2'] == (0, 4)
    # policy accept with the same rules: the firewall does not filter, the positive probes do not count
    grades = _grades(_simulate(lab, data, tmp_pub_dir, Ruleset(lab, d, input=INPUT_9, output=None, policy='accept'))[0])
    assert grades['policy_drop'] == (0, 4) and grades['lo_works'] == (0, 5) and grades['port_open'] == (0, 12)
    assert grades['lo_rule'] == (3, 3) and grades['reject_rule'] == (2, 2)


def test_form_answers(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir)
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
    # question 10: the two "what the program sees" answers go together, the third one alone
    q10 = [q for q in grade.get_questions_ordered() if any(f['name'] == 'with_drop' for f in getattr(q, 'fields', []))][0]
    for answers, expected in (({"with_drop": "timeout", "with_reject": "refused", "from_forbidden": "synack_rejected"}, 2),
                              ({"with_drop": "refused", "with_reject": "refused", "from_forbidden": "synack_rejected"}, 1),
                              ({"with_drop": "timeout", "with_reject": "refused", "from_forbidden": "no_route"}, 1),
                              ({}, 0)):
        grade._answers[q10.question_hash] = json.dumps(answers)
        grade.reset_before_grade()
        grade.grade()
        assert _grades(grade)['q_output'] == (expected, 2), answers
    assert lab._set_pairs({'items': [{'concat': ['192.0.2.2', 80]}, {'concat': [8888, '192.0.2.3']}, {'concat': [1, 2]}, 7]}) == {
        ('192.0.2.2', 80), ('192.0.2.3', 8888)}


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

_LEVEL_1 = ['intro', 'hooks', 'structure', 'selectors', 'verdicts', 'conntrack', 'output', 'nft-cli', 'logging', 'sets',
            'limits', 'nat', 'testing', 'practices', 'cheatsheet']


def test_texts_and_instructor_fragments(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
    info = _text(ns.informations)
    assert info.count('\n## ') == 15 and 'ct state established,related' in info and 'nflog:0' in info
    assert str(data.nets.lan) not in info     # instance data belongs to the first question
    # the examples of the course use the documentation ranges, never an address an instance could draw
    assert not re.search(r'\b(10\.\d+|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+\b', info)
    from SRE.informations import resolve_informations, resolve_text
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved)
    sections = numbering.sections('fr')
    assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, 16)]
    assert [s.tag for s in sections if s.level == 1] == _LEVEL_1
    assert {s.level for s in sections} == {1, 2} and all(s.tag for s in sections)
    hooks = [s.tag for s in sections if s.number.startswith('2.')]
    assert hooks == ['hooks-ip', 'ingress', 'families']        # the ingress / egress hooks have their own section
    assert [s.tag for s in sections if s.number.startswith('7.')] == ['why-output', 'output-view', 'output-state',
                                                                     'output-policies', 'skuid']
    assert [s.tag for s in sections if s.number.startswith('10.')] == ['anonymous-sets', 'named-sets', 'dynamic-sets', 'maps']
    for hook in ('prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress', 'egress'):
        assert f'**`{hook}`**' in info, hook
    assert 'iptables' not in [s.tag for s in sections] and 'iptables -' not in info
    assert '## <a id="conntrack"></a>6. Le suivi de connexion' in course
    assert '- [7. Filtrer ce qui sort : la chaîne output](#output)' in course and '- [8. La commande nft](#nft-cli)' in course
    assert '    - [2.2. Les hooks ingress et egress](#ingress)' in course
    assert '@@' not in course
    # the course says what the lab relies on (facts checked on a live host)
    for needle in ("Couldn't connect to server", 'ping: sendmsg: Operation not permitted', "You must add 'flags interval'",
                   'flags interval', 'ip saddr . tcp dport @allowed', 'flags dynamic,timeout', 'meta skuid', 'oif "lo" accept'):
        assert needle in info, needle
    questions = list(grade.get_questions_ordered())
    assert len(questions) == 15
    assert [_text(q.title) for q in questions[10:]] == [
        "10. Filtrer ce qui sort : la chaîne output", "11. Ensembles nommés : une liste noire",
        "12. Un ensemble de ports pour la sortie", "13. Associations adresse . port : une liste blanche",
        "14. Bonus — ensemble dynamique : bannir les curieux"]
    resolved_questions = [_text(resolve_text(q.description, numbering)) for q in questions]
    assert all('@@ref' not in q and '@@sec' not in q for q in resolved_questions)
    assert 'section 13 des Informations' in resolved_questions[0] and 'section 3 des Informations' in resolved_questions[2]
    assert 'section 2 des' in resolved_questions[3] and 'sections 6 et\n8 des Informations' in resolved_questions[7]
    assert 'section 8 des Informations' in resolved_questions[8] and 'section 9 des Informations' in resolved_questions[9]
    assert 'section 7\ndes Informations' in resolved_questions[10] and 'section 10 des Informations' in resolved_questions[11]
    assert 'section 8.3 des\nInformations' in resolved_questions[12]
    assert 'section 10.2 des Informations' in resolved_questions[13] and 'section 10.3 des Informations' in resolved_questions[14]
    with_instructor = [q for q in questions if has_instructor(_text(q.description))]
    assert len(with_instructor) == 15
    all_text = info + "".join(_text(q.description) for q in questions)
    assert "{'" not in all_text and not re.search(r"\{[a-z_0-9]+\}", all_text)
    first = _text(questions[0].description)
    for value in (data.nets.lan, data.nets.ext, data.nets.guest, data.ips.m1.ip, data.ips.m2.ip, data.ips.ext1.ip,
                  data.ips.ext2.ip, data.ips.ext3.ip, data.ips.guest1.ip, data.ips.gw_ext.ip, data.ips.gw_guest.ip):
        assert str(value) in first
    assert '140/140' in first and 'Aucune question' in first      # the instructor is told about the coupling
    for cmd in ns.cmds_all():
        assert cmd in all_text, cmd                   # every command of the solution is in an instructor text
    for e in grade.get_grade_list():
        desc = _text(e.description)
        assert "{'" not in desc and not re.search(r"\{[a-z_]+\}", desc)
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
    student_questions = [_text(q.description) for q in grade2.get_questions_ordered()]
    student_text = _text(ns2.informations) + "".join(student_questions)
    assert not has_instructor(student_text) and "Pour l'enseignant" not in student_text
    assert '_h' not in student_text and 'm1_h' not in student_text     # the hidden mirror stays hidden
    assert 'nft insert rule' in student_text and 'handle N' in student_text
    # the students are told the instance values of the later questions, and that question 10 can undo the others
    assert str(data.ips.ext2.ip) in student_questions[10] and 'tout ce qui marchait marche encore' in student_questions[10]
    assert str(data.ips.ext3.ip) in student_questions[11] and str(data.nets.guest) in student_questions[11]
    assert f"{data.ips.ext2.ip} . 80" in student_questions[13] and f"{data.ips.m3.ip} . 8888" in student_questions[13]
    html = __import__('SRE.instructor_text', fromlist=['markdown_to_html']).markdown_to_html(info)
    assert '<table>' in html and '<code>' in html and 'nc -u -w 1 m2 530</code>' in html


def test_cheat_answers_fill_every_form(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir)
    cheat = grade.get_cheat_answers('final')
    forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
    assert len(forms) == 10
    assert [f['name'] for q in forms[5:] for f in q.fields] == [
        'with_drop', 'with_reject', 'from_forbidden', 'no_interval', 'rule_place', 'rules_changed', 'pair_missing',
        'ban_effect']
    for q in forms:
        answers = cheat[q.question_hash]
        answers = json.loads(answers) if isinstance(answers, str) else answers
        for field in q.fields:
            assert field['name'] in answers, field['name']
            if 'choices' in field:
                assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])
                assert len(field['choices']) >= 3, field['name']
            elif 'regex' in field:
                assert re.fullmatch(field['regex'], answers[field['name']]), (field['name'], answers[field['name']])


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'nftables_filter1_stripped', 'exec')
    assert source.count(b'instructor(tr(') == 15


def test_english_identifiers(lab, data):
    """Machines, networks, states, data fields, grade elements and part keys are English (tr() texts are French)."""
    french = re.compile(r'(routeur|pont|reseau|serveur|sonde|panne|exemple|reponse|commutateur|passerelle|'
                        r'machine_|_machine|exterieur|filtre|regle|journal|parefeu|invite|ensemble|liste)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.NetScheme._network_specs)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += list(vars(data.ips)) + list(vars(data.nets))
    names += [lab.BLOCK_SET, lab.PORT_SET, lab.ALLOW_SET, lab.BAN_SET, lab.OUT_CHAIN, lab.LOG_CHAIN]
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
