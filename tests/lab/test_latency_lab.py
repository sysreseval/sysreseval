"""Offline tests of the latency lab (lab/sre/latency.py): data generation (the delays of
x, the slow link of m2, the phantom networks), the topology, the state ops (netem per direction,
the routes of x, the opaque x, the reference solution, the user-allowed `reset` = a cleanup of every
machine then the initial configuration again), the two-pass grading contract with synthetic
outputs (nothing done: 0, everything done: 100, an uncorrected answer, the tolerance, a ring broken),
the instructor texts in both languages, the numbered course, the stripped lab file and the English
identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of the
real tools (ip route, ping, sysctl).
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
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

_LAB_PATH = _REPO / 'lab' / 'sre' / 'latency.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('latency_lab_under_test', _LAB_PATH)
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


# ---------------------------------------------------------------------------
# synthetic outputs of the "everything done" project
# ---------------------------------------------------------------------------

def _ping_error(dest, source, message='Time to live exceeded'):
    return (f"PING {dest} ({dest}) 56(84) bytes of data.\nFrom {source} icmp_seq=1 {message}\n\n"
            f"--- {dest} ping statistics ---\n1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\n\n")


def _ping_ok(dest, avg_ms, count=4):
    lines = [f"PING {dest} ({dest}) 56(84) bytes of data."]
    lines += [f"64 bytes from {dest}: icmp_seq={k + 1} ttl=63 time={avg_ms:.1f} ms" for k in range(count)]
    lines += ["", f"--- {dest} ping statistics ---",
              f"{count} packets transmitted, {count} received, 0% packet loss, time {int(count * 300)}ms",
              f"rtt min/avg/max/mdev = {avg_ms - 0.2:.3f}/{avg_ms:.3f}/{avg_ms + 0.2:.3f}/0.100 ms", ""]
    return "\n".join(lines)


_UNREACHABLE = "ping: connect: Network is unreachable\n"


def _ip_route(ns, m, final=True):
    lines = []
    for i, entry in enumerate(ns.net_config[m]):
        for a in entry[0]:
            lines.append(f"{a.network} dev eth{i} proto kernel scope link src {a.ip}")
    if final:
        for net, gw in ns.solution_routes.get(m, []):
            dst = 'default' if net.prefixlen == 0 else str(net)
            lines.append(f"{dst} via {gw.ip} dev eth0")
    return "\n".join(lines) + "\n"


def _synthetic(lab, ns, machine, command, final=True):
    """(output, code) of *command* on *machine* in a project where everything is done."""
    d = ns.data
    if command == 'ip route':
        return _ip_route(ns, machine, final), 0
    if command == 'cat /proc/sys/net/ipv4/ip_forward':
        return ('1\n' if final else '0\n'), 0
    if command.startswith('ping -n -c '):                         # question 1: m1 -> m3 through x, both ways
        dest = command.split()[-1]
        return (_ping_ok(dest, d.delay_to_m3 + d.delay_to_m1 + 0.3), 0) if final else (_UNREACHABLE, 2)
    if command.startswith(f'ping -4 -n -t {lab.RING_TTL} '):     # question 2: two turns of a ring from gw
        dest = command.split()[-1]
        return (_ping_error(dest, ns.addr('m1', 'ext').ip), 1) if final else (_UNREACHABLE, 2)
    return '', 0


def _simulate(lab, data, tmp_pub_dir, instructor_mode=False, everything=True):
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
            if everything:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = _synthetic(lab, ns, m, key[0], final=everything)
        step += 1
    return grade, ns


def _regrade(grade):
    grade.reset_before_grade()
    grade.grade()
    return _by_title(grade)


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


def _set_answer(grade, field, value):
    """Change one form answer, keeping the others (the cheat answers)."""
    for q in grade.get_questions_ordered():
        fields = getattr(q, 'fields', None) or []
        if any(f['name'] == field for f in fields):
            form = json.loads(grade._answers[q.question_hash])
            form[field] = value
            grade._answers[q.question_hash] = json.dumps(form)
            return
    raise KeyError(field)


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()
        again = lab.Data.from_json(data.to_json())
        assert (again.delay_to_m3, again.delay_to_m1, again.local_delay) == (data.delay_to_m3, data.delay_to_m1,
                                                                             data.local_delay)
        assert isinstance(again.delay_to_m3, int) and isinstance(again.nets.net1, IPv4Network)

    def test_delays(self, lab, data):
        lo, hi = lab.X_DELAY_RANGE
        for d in [data] + [lab.Data.generate() for _ in range(40)]:
            assert lo <= d.delay_to_m3 <= hi and lo <= d.delay_to_m1 <= hi
            assert abs(d.delay_to_m3 - d.delay_to_m1) >= lab.X_DELAY_MIN_GAP
            assert lab.LOCAL_DELAY_RANGE[0] <= d.local_delay <= lab.LOCAL_DELAY_RANGE[1]
            # an answer without the local correction (period = delay + local) is out of tolerance
            for delay in (d.delay_to_m3, d.delay_to_m1):
                assert d.local_delay > lab.TOLERANCE_REL * delay + lab.TOLERANCE_ABS_MS
        assert lab.LOCAL_DELAY_RANGE[0] > lab.TOLERANCE_REL * lab.X_DELAY_RANGE[1] + lab.TOLERANCE_ABS_MS

    def test_networks_and_addresses(self, lab, data):
        names = list(lab._TOPOLOGY) + list(lab.PHANTOM_NETS)
        assert set(vars(data.nets)) == set(names) and len(names) == 7
        nets = list(vars(data.nets).values())
        for i, net in enumerate(nets):
            assert net.prefixlen == 24 and net.is_private
            assert not net.overlaps(IPv4Network("172.17.0.0/16")) and not net.overlaps(IPv4Network("10.0.0.0/16"))
            for other in nets[i + 1:]:
                assert not net.overlaps(other)
        for net, members in lab._TOPOLOGY.items():
            for m in members:
                name = m if m in lab._SINGLE_HOMED else f"{m}_{net}"
                assert getattr(data.ips, name).ip in getattr(data.nets, net), name
        assert lab._SINGLE_HOMED == {'gw'}
        assert set(vars(data.ips)) == {'gw', 'm1_ext', 'm1_x1', 'm1_l12', 'x_x1', 'x_x3', 'm3_x3', 'm3_l23',
                                       'm2_l23', 'm2_l12'}
        # nobody on the phantom networks
        for a in vars(data.ips).values():
            assert a.ip not in data.nets.net1 and a.ip not in data.nets.net2


class TestTopology:
    def test_machines_and_networks(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'gw', 'm1', 'm2', 'm3', 'x'}
        assert set(ns.get_accessible_machine_names()) == set(lab.STUDENT_MACHINES) == {'gw', 'm1', 'm2', 'm3'}
        x = ns.x
        assert x.shape == 'star' and not x.allow_connection and not x.hidden
        assert {n.name for n in ns.get_visible_networks()} == set(lab._TOPOLOGY) == {'ext', 'x1', 'x3', 'l23', 'l12'}
        # the ring: m1 - x - m3 - m2 - m1, gw on m1; interface numbers the texts rely on
        assert lab._machine_networks('m1') == [(0, 'ext'), (1, 'x1'), (2, 'l12')]
        assert lab._machine_networks('x') == [(0, 'x1'), (1, 'x3')]
        assert lab._machine_networks('m3') == [(0, 'x3'), (1, 'l23')]
        assert lab._machine_networks('m2') == [(0, 'l23'), (1, 'l12')]
        assert lab._machine_networks('gw') == [(0, 'ext')]
        assert lab.X_DEV == {'m1': 'eth0', 'm3': 'eth1'} and lab.M2_DEV == {'m3': 'eth0', 'm1': 'eth1'}
        assert lab.M1_DEV == {'gw': 'eth0', 'x': 'eth1', 'm2': 'eth2'}
        for m in ns.get_machine_names():
            assert tuple(ns.get_machine(m).sysctls) == lab.RP_FILTER_OFF

    def test_ring_ttl(self, lab):
        # router k of a ring receives TTL RING_TTL + 1 - k: k = RING_TTL is m1 (router 1, 5, 9...) after two turns
        assert lab.RING_ROUTERS == 4 and lab.RING_TTL == 9
        assert (lab.RING_TTL - 1) % lab.RING_ROUTERS == 0 and (lab.RING_TTL - 1) // lab.RING_ROUTERS == 2

    def test_routes_of_the_solution(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        d = data
        addr = ns.addr
        # x: every network of the site, net1 towards m3, net2 towards m1
        assert dict(ns.x_routes) == {d.nets.ext: addr('m1', 'x1'), d.nets.l12: addr('m1', 'x1'),
                                     d.nets.net2: addr('m1', 'x1'), d.nets.l23: addr('m3', 'x3'),
                                     d.nets.net1: addr('m3', 'x3')}
        # ring 1: m1 -> x -> m3 -> m2 -> m1 ; ring 2: m1 -> m2 -> m3 -> x -> m1
        assert ns.ring1_routes == {'m1': (d.nets.net1, addr('x', 'x1')), 'm3': (d.nets.net1, addr('m2', 'l23')),
                                   'm2': (d.nets.net1, addr('m1', 'l12'))}
        assert ns.ring2_routes == {'m1': (d.nets.net2, addr('m2', 'l12')), 'm2': (d.nets.net2, addr('m3', 'l23')),
                                   'm3': (d.nets.net2, addr('x', 'x3'))}
        assert ns.q1_routes == {'m1': (d.nets.x3, addr('x', 'x1')), 'm3': (d.nets.x1, addr('x', 'x3'))}
        assert ns.local_routes == {'m1': (d.nets.l23, addr('m2', 'l12')), 'm2': (d.nets.ext, addr('m1', 'l12')),
                                   'm3': (d.nets.ext, addr('m2', 'l23'))}
        assert ns.gw_route == (IPv4Network("0.0.0.0/0"), addr('m1', 'ext'))
        # every next hop is on a network directly connected to the machine
        for m, routes in list(ns.solution_routes.items()) + [('x', ns.x_routes)]:
            connected = [a.network for entry in ns.net_config[m] for a in entry[0]]
            for _, via in routes:
                assert any(via.ip in net for net in connected), (m, via)
        assert set(ns.solution_routes) == set(lab.STUDENT_MACHINES)
        assert {m: len(r) for m, r in ns.solution_routes.items()} == {'gw': 1, 'm1': 4, 'm2': 3, 'm3': 4}
        # the initial configuration: addresses only
        for m, entries in ns.net_config.items():
            assert all(entry[1] == [] for entry in entries), m
            assert [a for entry in entries for a in entry[0]] == [addr(m, net) for _, net in lab._machine_networks(m)]


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        d = data
        for m in ns.get_machine_names():
            cmds = _cmds(ops, 1, m)
            forward = [c for c in cmds if c.startswith('sysctl -w net.ipv4.ip_forward=')]
            assert forward == [f"sysctl -w net.ipv4.ip_forward={int(m == 'x')}"], m
            assert '/etc/hosts' in _files(ops, 1, m)
            for _, net in lab._machine_networks(m):
                assert f"ip addr add {ns.addr(m, net)} dev eth{lab._TOPOLOGY[net][m]}" in cmds
        # the delays: one per direction on x (egress), the slow link of m2 on both interfaces
        x_cmds = _cmds(ops, 1, 'x')
        assert f"tc qdisc replace dev eth1 root netem delay {d.delay_to_m3}ms" in x_cmds
        assert f"tc qdisc replace dev eth0 root netem delay {d.delay_to_m1}ms" in x_cmds
        m2_cmds = _cmds(ops, 1, 'm2')
        assert [c for c in m2_cmds if 'netem' in c] == [f"tc qdisc replace dev eth0 root netem delay {d.local_delay}ms",
                                                         f"tc qdisc replace dev eth1 root netem delay {d.local_delay}ms"]
        for m in ('gw', 'm1', 'm3'):
            assert not any('netem' in c for c in _cmds(ops, 1, m)), m
        # the routes of x, nobody else's
        x_routes = [c for c in x_cmds if c.startswith('ip route')]
        assert x_routes == [f"ip route replace {dest.compressed} via {via.ip}" for dest, via in ns.x_routes]
        assert f"ip route replace {d.nets.net1} via {ns.addr('m3', 'x3').ip}" in x_routes
        assert f"ip route replace {d.nets.net2} via {ns.addr('m1', 'x1').ip}" in x_routes
        for m in lab.STUDENT_MACHINES:
            assert not any(c.startswith('ip route') for c in _cmds(ops, 1, m)), m
        # x emits no ICMP message of its own
        rules = _files(ops, 1, 'x')[lab.OPAQUE_RULES]
        assert rules == lab.opaque_rules()
        assert 'type filter hook output priority 0' in rules and 'meta l4proto icmp drop' in rules
        assert 'hook input' not in rules and 'hook forward' not in rules
        assert f"nft delete table ip {lab.OPAQUE_TABLE} 2>/dev/null; nft -f {lab.OPAQUE_RULES}" in x_cmds
        for m in lab.STUDENT_MACHINES:
            assert lab.OPAQUE_RULES not in _files(ops, 1, m) and not any('nft' in c for c in _cmds(ops, 1, m)), m
        # the hosts file names every interface, phantom networks apart
        hosts = _files(ops, 1, 'm1')['/etc/hosts']
        for name, a in vars(d.ips).items():
            assert f"{a.ip}\t\t{name}" in hosts, name
        assert str(d.nets.net1.network_address) not in hosts

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        d = data
        for m in lab.RING_MACHINES:
            assert "sysctl -w net.ipv4.ip_forward=1" in _cmds(ops, 1, m), m
        assert not any('ip_forward' in c for c in _cmds(ops, 1, 'gw') + _cmds(ops, 1, 'x'))
        for m, routes in ns.solution_routes.items():
            cmds = [c for c in _cmds(ops, 1, m) if c.startswith('ip route')]
            assert cmds == [f"ip route replace {dest.compressed} via {via.ip}" for dest, via in routes], m
        assert _cmds(ops, 1, 'gw') == [f"ip route replace 0.0.0.0/0 via {ns.addr('m1', 'ext').ip}"]
        # the slow link of m2 and the delays of x again (a student may have removed a qdisc)
        assert [c for c in _cmds(ops, 1, 'm2') if 'netem' in c] == [
            f"tc qdisc replace dev eth0 root netem delay {d.local_delay}ms",
            f"tc qdisc replace dev eth1 root netem delay {d.local_delay}ms"]
        assert _cmds(ops, 1, 'x') == [f"tc qdisc replace dev eth1 root netem delay {d.delay_to_m3}ms",
                                      f"tc qdisc replace dev eth0 root netem delay {d.delay_to_m1}ms"]
        assert not any(_files(ops, 1, m) for m in ns.get_machine_names())
        states = {name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)}
        assert states == {'initial', 'final', 'reset', 'save', 'restore'}
        assert not getattr(lab, 'allow_save_restore', False) and getattr(lab, 'export_kathara_project', True) is False

    def test_reset(self, lab, data):
        """The user-allowed state: the cleanup of every machine, then exactly the initial configuration."""
        from net_config import REMOUNT_PROC_SYS_CMD
        assert lab.allow_user_states is True
        assert lab.NetScheme.reset._sre_state_user_allowed
        assert not lab.NetScheme.initial._sre_state_user_allowed and not lab.NetScheme.final._sre_state_user_allowed
        assert set(lab.NetScheme.get_user_allowed_states()) == {'reset'}
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'reset')
        initial = _state_ops(lab.NetScheme(data=data, running_lab_name=_running_name()), 'initial')
        for m in ns.get_machine_names():
            cmds = _cmds(ops, 1, m)
            interfaces = [f"eth{i}" for i, _ in lab._machine_networks(m)]
            # the initial configuration comes last, as is (its remount of /proc/sys moved up with the sysctls)
            initial_cmds = [c for c in _cmds(initial, 1, m) if c != REMOUNT_PROC_SYS_CMD]
            head, tail = cmds[:-len(initial_cmds)], cmds[-len(initial_cmds):]
            assert tail == initial_cmds, m
            assert _files(ops, 1, m) == _files(initial, 1, m), m
            # the cleanup first: every route (a blackhole one has no interface), the addresses (ip addr add
            # fails on an address already set, and recreates the connected route), the qdiscs of every
            # interface, the creation-time sysctls, the ARP caches
            assert head[0] == lab.ROUTE_FLUSH_CMD == "ip -4 route flush table main", m
            for dev in interfaces:
                assert f"ip addr flush dev {dev}" in head, (m, dev)
                assert f"tc qdisc del dev {dev} root 2>/dev/null; true" in head, (m, dev)
            sysctls = [c for c in head if c.startswith('sysctl -w net.ipv4.conf.')]
            assert sysctls == [lab.reset_sysctl_cmd(interfaces)], m
            for name in ('all', 'default', *interfaces):
                assert f" net.ipv4.conf.{name}.rp_filter=0" in sysctls[0], (m, name)
                assert f" net.ipv4.conf.{name}.accept_local=0" in sysctls[0], (m, name)
            assert head.index(REMOUNT_PROC_SYS_CMD) < head.index(sysctls[0]), m
            assert "ip neigh flush all" in head, m
            assert not any(c.startswith('ip route') or 'netem' in c or 'ip addr add' in c for c in head), m
        # the students' machines end without any route, forwarding off; the delays of x and m2 are back
        for m in lab.STUDENT_MACHINES:
            assert not any(c.startswith('ip route') for c in _cmds(ops, 1, m)), m
            assert "sysctl -w net.ipv4.ip_forward=0" in _cmds(ops, 1, m), m
        assert sum('netem' in c for c in _cmds(ops, 1, 'm2')) == 2 and sum('netem' in c for c in _cmds(ops, 1, 'x')) == 2
        assert not any('netem' in c for m in ('gw', 'm1', 'm3') for c in _cmds(ops, 1, m))


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrading:
    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        assert _totals(grade) == (100, 100)
        parts = {}
        for e in grade.get_grade_list():
            parts[e.grade_part] = parts.get(e.grade_part, 0) + e.max_grade
        assert parts == {'part1': 30, 'part2': 70}
        assert grade.max_step == 1
        tests = {(m, s): [k[0] for k in cmds] for (m, s), cmds in grade.get_tests().items()}
        assert set(tests) == {(m, 1) for m in lab.STUDENT_MACHINES}
        assert f"ping -4 -n -t {lab.RING_TTL} -c 1 -W 3 -w 4 {data.nets.net1[1]}" in tests[('gw', 1)]
        assert f"ping -4 -n -t {lab.RING_TTL} -c 1 -W 3 -w 4 {data.nets.net2[1]}" in tests[('gw', 1)]
        assert f"ping -n -c 5 -i 0.2 -w 4 {ns.addr('m3', 'x3').ip}" in tests[('m1', 1)]
        assert 'cat /proc/sys/net/ipv4/ip_forward' not in tests[('gw', 1)]

    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=False)
        assert _totals(grade) == (0, 100)

    def test_answers_tolerance(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        a, b, local = data.delay_to_m3, data.delay_to_m1, data.local_delay
        margin = lab.TOLERANCE_REL * a + lab.TOLERANCE_ABS_MS
        assert _regrade(grade)['answer_delay_m1_to_m3'].grade == 18
        # the comma, a decimal value, the edge of the tolerance
        for value, expected in ((f"{a + margin - 0.01:.2f}".replace('.', ','), 18), (f"{a - margin + 0.01:.2f}", 18),
                                (f"{a + margin + 0.5:.2f}", 0), (f"{a + local}", 0), ("", 0), ("abc", 0)):
            _set_answer(grade, 'delay_m1_to_m3', value)
            assert _regrade(grade)['answer_delay_m1_to_m3'].grade == expected, value
        _set_answer(grade, 'delay_m3_to_m1', f"{b + local}")     # the period of ring 2 without the correction
        assert _regrade(grade)['answer_delay_m3_to_m1'].grade == 0
        _set_answer(grade, 'rtt_total', f"{a + b + 1.5:.1f}")
        assert _regrade(grade)['answer_rtt_total'].grade == 16
        _set_answer(grade, 'rtt_total', f"{a}")
        assert _regrade(grade)['answer_rtt_total'].grade == 0

    def test_ping_through_x(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        a, b = data.delay_to_m3, data.delay_to_m1
        m3 = str(ns.addr('m3', 'x3').ip)

        def with_ping(output, code=0):
            for (m, s), cmds in grade.get_tests().items():
                for key in cmds:
                    if m == 'm1' and key[0].startswith('ping -n -c '):
                        cmds[key] = (output, code)
            return _regrade(grade)['ping_through_x'].grade

        assert with_ping(_ping_ok(m3, a + b + 0.4)) == 6
        assert with_ping(_ping_ok(m3, b + 0.3)) == 0                 # the reply came back without crossing x
        assert with_ping(_ping_ok(m3, a + b + 50)) == 0            # beyond the tolerance (26 ms at most)
        assert with_ping(_UNREACHABLE, 2) == 0
        assert with_ping("", 1) == 0

    def test_rings(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        by = _by_title(grade)
        assert by['ring1_loop'].grade == 6 and by['ring2_loop'].grade == 6
        assert by['ring1_routes'].grade == 6 and by['ring2_routes'].grade == 6 and by['route_gw_via_m1'].grade == 4
        target1, target2 = str(data.nets.net1[1]), str(data.nets.net2[1])

        def with_loop(target, output, code=1):
            for (m, s), cmds in grade.get_tests().items():
                for key in cmds:
                    if m == 'gw' and key[0].endswith(f" {target}"):
                        cmds[key] = (output, code)
            return _regrade(grade)

        # the error of another router: the packet did not make two turns (a route missing after m1)
        by = with_loop(target1, _ping_error(target1, ns.addr('m2', 'l12').ip))
        assert by['ring1_loop'].grade == 0 and by['ring2_loop'].grade == 6
        by = with_loop(target1, _ping_error(target1, ns.addr('m1', 'ext').ip, 'Destination Net Unreachable'))
        assert by['ring1_loop'].grade == 0
        by = with_loop(target2, "PING x\n\n--- x ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n")
        assert by['ring2_loop'].grade == 0
        by = with_loop(target1, _ping_error(target1, ns.addr('m1', 'ext').ip))
        assert by['ring1_loop'].grade == 6

    def test_routes_scoring(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        d = data

        def with_routes(machine, lines):
            for (m, s), cmds in grade.get_tests().items():
                for key in cmds:
                    if m == machine and key[0] == 'ip route':
                        cmds[key] = ("\n".join(lines) + "\n", 0)
            return _regrade(grade)

        # gw: net1 and net2 via m1 instead of a default route
        by = with_routes('gw', [f"{d.nets.ext} dev eth0 proto kernel scope link src {d.ips.gw.ip}",
                                f"{d.nets.net1} via {ns.addr('m1', 'ext').ip} dev eth0",
                                f"{d.nets.net2} via {ns.addr('m1', 'ext').ip} dev eth0"])
        assert by['route_gw_via_m1'].grade == 4
        by = with_routes('gw', [f"{d.nets.ext} dev eth0 proto kernel scope link src {d.ips.gw.ip}",
                                f"{d.nets.net1} via {ns.addr('m1', 'ext').ip} dev eth0"])
        assert by['route_gw_via_m1'].grade == 0
        # m3: ring 1 via x instead of m2 (a loop that never leaves x and m3), the question 1 route kept
        by = with_routes('m3', [f"{d.nets.x3} dev eth0 proto kernel scope link src {ns.addr('m3', 'x3').ip}",
                                f"{d.nets.l23} dev eth1 proto kernel scope link src {ns.addr('m3', 'l23').ip}",
                                f"{d.nets.x1} via {ns.addr('x', 'x3').ip} dev eth0",
                                f"{d.nets.net1} via {ns.addr('x', 'x3').ip} dev eth0",
                                f"{d.nets.net2} via {ns.addr('x', 'x3').ip} dev eth0"])
        assert by['route_m3_to_x1'].grade == 4 and by['ring1_routes'].grade == 4 and by['ring2_routes'].grade == 6
        by = with_routes('m3', [])
        assert by['route_m3_to_x1'].grade == 0 and by['ring1_routes'].grade == 4 and by['ring2_routes'].grade == 4
        # ip_forward
        for (m, s), cmds in grade.get_tests().items():
            for key in cmds:
                if m == 'm2' and key[0] == 'cat /proc/sys/net/ipv4/ip_forward':
                    cmds[key] = ('0\n', 0)
        by = _regrade(grade)
        assert by['ip_forward_m2'].grade == 0 and by['ip_forward_m1'].grade == 2

    def test_form_elements_scope(self, lab, data, tmp_pub_dir, monkeypatch):
        """`latency_answers_in_self_eval` (module flag, True by default) puts the three measured latencies
        in both evaluations; False keeps them for the instructor's evaluation only (48 points left in the
        self-evaluation); the configuration elements are always in both."""
        assert lab.latency_answers_in_self_eval is True
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=True)
        assert all(e.scope == params.BOTH_EVAL_SCOPE for e in grade.get_grade_list())
        grade.compute_total()
        assert (grade._total_max_self_eval, grade._total_max_exo_eval) == (100, 100)
        assert "L'auto-évaluation note aussi vos trois réponses" in _text(grade.get_questions_ordered()[0].description)

        monkeypatch.setattr(lab, 'latency_answers_in_self_eval', False)
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=True)
        scopes = {str(e.title): e.scope for e in grade.get_grade_list()}
        assert {t for t, s in scopes.items() if s == params.EXO_EVAL_SCOPE} == {
            'answer_rtt_total', 'answer_delay_m1_to_m3', 'answer_delay_m3_to_m1'}
        assert all(s == params.BOTH_EVAL_SCOPE for t, s in scopes.items() if not t.startswith('answer_'))
        grade.compute_total()
        assert (grade._total_max_self_eval, grade._total_max_exo_eval) == (48, 100)
        assert _totals(grade) == (100, 100)
        assert "L'auto-évaluation ne note pas vos trois réponses" in _text(grade.get_questions_ordered()[0].description)

    def test_cheat_answers_match_the_fields(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=True)
        answers = grade.get_cheat_answers('final')
        forms = {}
        for q in grade.get_questions_ordered():
            if not getattr(q, 'fields', None):
                continue
            form = json.loads(answers[q.question_hash])
            for f in q.fields:
                assert f['name'] in form and re.fullmatch(f['regex'], form[f['name']]), (f['name'], form)
            forms.update(form)
        assert forms == {'rtt_total': str(data.delay_to_m3 + data.delay_to_m1),
                         'delay_m1_to_m3': str(data.delay_to_m3), 'delay_m3_to_m1': str(data.delay_to_m1)}


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

def _all_texts(grade, ns, lang='fr'):
    texts = [('informations', _text(ns.informations, lang))]
    for q in grade.get_questions_ordered():
        texts.append((_text(q.title, lang), _text(q.description, lang)))
    for e in grade.get_grade_list():
        texts.append((str(e.title), _text(e.description, lang) if e.description else ''))
    return texts


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 3
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 3 and 'informations' not in with_fragment
        # the delays appear in the instructor texts only (the course quotes orders of magnitude, so the
        # questions alone are checked for the bare values)
        questions = "\n".join(t for w, t in _all_texts(g0, ns0) if w != 'informations')
        for value in (data.delay_to_m3, data.delay_to_m1, data.local_delay, data.delay_to_m3 + data.delay_to_m1,
                      data.delay_to_m3 + data.local_delay, data.delay_to_m1 + data.local_delay, 2 * data.local_delay):
            assert f"{value} ms" not in questions, value
        instructor_texts = "\n".join(t for w, t in _all_texts(g1, ns1) if w != 'informations')
        assert f"**{data.delay_to_m3} ms**" in instructor_texts and f"**{data.delay_to_m1} ms**" in instructor_texts

    def test_instructor_texts_in_both_languages(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en)
            assert fr != en and ('**Solution.**' in en or '**For the instructor.**' in en)
            for lang, text in (('fr', fr), ('en', en)):
                assert "{'" not in text and not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), (lang, text[:80])
                markdown_to_html(text, show_instructor=True)
        # every tr() text of the file has its English translation, the three instructor texts included
        import check_sre_translations as cst
        tree = ast.parse(_LAB_PATH.read_text())
        assert set(lab._TRANSLATIONS) == {'en'}
        assert set(lab._TRANSLATIONS['en']) == cst.get_tr_strings(tree)
        assert None not in lab._TRANSLATIONS['en'].values()
        assert sum('**Solution.**' in v or '**For the instructor.**' in v for v in lab._TRANSLATIONS['en'].values()) == 3

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for lang in ('fr', 'en'):
            for where, text in _all_texts(g1, ns1, lang):
                assert "{'" not in text, (lang, where)
                assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), (lang, where)
                assert '@@{' not in text or where != 'informations'
                markdown_to_html(text, show_instructor=True)
                markdown_to_html(text, show_instructor=False)
        resolved, numbering = resolve_informations(ns1.informations)
        for lang in ('fr', 'en'):
            assert [s.number for s in numbering.sections(lang) if s.level == 1] == [str(i) for i in range(1, 8)]
            assert [s.number for s in numbering.sections(lang) if s.level == 2] == ['4.1', '4.2', '4.3']
            informations = _text(resolved, lang)
            # the course holds neither the session specifics nor a summary of the questions
            assert 'question' not in informations.lower() and '@@' not in informations, lang
            assert str(data.nets.net1) not in informations and 'Organisation' not in informations, lang
        informations = _text(resolved)
        assert '## <a id="ring"></a>4. La méthode de la boucle' in informations
        assert '### <a id="sec.4.3"></a>4.3. Les pièges' in informations
        assert '- [4. La méthode de la boucle](#ring)' in informations and '(section [3](#oneway))' in informations
        english = _text(resolved, 'en')
        assert '## <a id="ring"></a>4. The ring method' in english
        assert '### <a id="sec.4.3"></a>4.3. The pitfalls' in english
        assert '- [4. The ring method](#ring)' in english and '(section [3](#oneway))' in english
        # the references of question 2 resolve to bare section numbers, in both languages
        q2 = g1.get_questions_ordered()[2]
        description = resolve_text(TranslatedText.from_value(q2.description, 'fr'), numbering)
        assert 'section 4 (les captures : section\n5)' in description.resolve('fr')
        assert 'section 4 (the captures: section\n5)' in description.resolve('en')
        assert '@@ref' not in description.resolve('fr') and '@@ref' not in description.resolve('en')

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        fields = 0
        for q in g1.get_questions_ordered():
            for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description)):
                fields += 1
                assert '}' not in m.group(2)
        assert fields == 1 + 2
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert kinds == {'rtt_total': {'name': 'rtt_total', 'regex': '[0-9.,]+'},
                         'delay_m1_to_m3': {'name': 'delay_m1_to_m3', 'regex': '[0-9.,]+'},
                         'delay_m3_to_m1': {'name': 'delay_m3_to_m1', 'regex': '[0-9.,]+'}}

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 3 and result.warnings == []
        stripped = tmp_path / 'latency_stripped.py'
        stripped.write_bytes(result.data)
        assert b'_TRANSLATIONS' in result.data and b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('latency_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the public translations stay, the three of the instructor texts go
        kept = module._TRANSLATIONS['en']
        assert set(module._TRANSLATIONS) == {'en'} and len(kept) == len(lab._TRANSLATIONS['en']) - 3
        assert not any('**Solution.**' in v or '**For the instructor.**' in v for v in kept.values())
        assert kept['Latence de x dans chaque sens'] == 'Latency of x in each direction'
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 100)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements and part keys are English."""
        french = re.compile(r'(routeur|boucle|reseau|anneau|retard|delai|latence|sens|aller|retour|reponse)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.PHANTOM_NETS)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
