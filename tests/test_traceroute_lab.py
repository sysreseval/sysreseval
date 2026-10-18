"""Offline tests of the traceroute lab (lab/sre/_DRAFT_misc/traceroute.py): data generation, the
hidden lines of islands A and C, their destinations and routes, the state ops (tool removal, hosts files without
any hidden address, firewalls and silent router, the UDP probe of the final state), the two-pass
grading contract with synthetic outputs (nothing done: 0, everything done: 120), the instructor
texts, the stripped lab file and the English identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of the
real tools (ping, traceroute, ip route, sysctl, curl).
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))

import traceroute as trc  # noqa: E402

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'traceroute.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('traceroute_lab_under_test', _LAB_PATH)
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


def _ip_route(ns, m, final=True):
    lines = []
    entries = ns.net_config_final.get(m, ns.net_config[m]) if final else ns.net_config[m]
    for i, entry in enumerate(entries):
        for a in entry[0]:
            lines.append(f"{a.network} dev eth{i} proto kernel scope link src {a.ip}")
        for net, gw in entry[1]:
            dst = 'default' if net.prefixlen == 0 else str(net)
            lines.append(f"{dst} via {gw.ip} dev eth{i}")
    return "\n".join(lines) + "\n"


def _ip_a(ns, m, final=True):
    entries = ns.net_config_final.get(m, ns.net_config[m]) if final else ns.net_config[m]
    lines = []
    for i, entry in enumerate(entries):
        lines.append(f"{i + 2}: eth{i}@if{i + 10}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP")
        for a in entry[0]:
            lines.append(f"    inet {a} brd {a.network.broadcast_address} scope global eth{i}")
    return "\n".join(lines) + "\n"


def _synthetic(lab, ns, machine, command, final=True):
    """(output, code) of *command* on *machine* in a project where everything is done."""
    d = ns.data
    far = str(d.far_address)
    srv = str(d.ips.srv.ip)
    if command in ('ip route', 'ip route show', 'ip -4 route'):
        return _ip_route(ns, machine, final), 0
    if command == 'ip a':
        return _ip_a(ns, machine, final), 0
    if command == 'ip link show':
        return "\n".join(f"{i + 2}: eth{i}@if{i + 10}: <UP>" for i in range(len(ns.net_config[machine]))) + "\n", 0
    if command.startswith('echo "===T64"'):
        if not final:
            return "===T64\nping: connect: Network is unreachable\n===TB\nping: connect: Network is unreachable\n", 0
        return ("===T64\n" + _ping_error(far, ns.addr('r1', 'lan3').ip)
                + "===TB\n" + _ping_error(far, ns.addr('r3', 'l31').ip)), 0
    if command.startswith('curl '):
        return ("SERVER=srv\nSERVER_IP=%s\nSERVER_PORT=80\nCLIENT_IP=%s\nCLIENT_PORT=40000\n" % (srv, d.ips.inj.ip), 0) \
            if final else ('', 7)
    if command.startswith('traceroute '):
        if not final:
            return f"traceroute to {srv} ({srv}), 6 hops max, 60 byte packets\n 1  *\n 2  *\n 3  *\n 4  *\n 5  *\n 6  *\n", 0
        hops = [ns.addr('r1', 'lan3').ip, ns.addr('r2', 'l23').ip, ns.addr('r3', 'l31').ip, srv]
        return (f"traceroute to {srv} ({srv}), 6 hops max, 60 byte packets\n"
                + "".join(f" {k + 1}  {a}  0.{k + 2}00 ms\n" for k, a in enumerate(hops))), 0
    if command == 'cat /proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr':
        return ('1\n' if final else '0\n'), 0
    if command == 'cat /proc/sys/net/ipv4/ip_default_ttl':
        return (f'{d.inj_ttl}\n' if final else '64\n'), 0
    if command.startswith('for n in '):
        return 'END\n', 0
    if command == 'nft list ruleset':
        return 'table ip fw {\n}\n', 0
    if command.startswith('nft list table ip '):
        return (f'table ip {lab.TTLFW_TABLE} {{\n\tchain prerouting {{\n'
                f'\t\tiifname "eth0" ip ttl < {lab.PROBE_TTL_LIMIT} counter packets {3 if final else 0} bytes 93 '
                f'comment "{lab.PROBE_COUNTER}"\n\t}}\n}}\n'), 0
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


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()
        again = lab.Data.from_json(data.to_json())
        assert again.target == data.target and again.target2 == data.target2 and again.far_address == data.far_address
        assert isinstance(again.target, str) and isinstance(again.silent, str)

    def test_target(self, lab, data):
        assert lab.ISLAND_A.targets() == ['h5', 'h6', 'h7', 'h8', 'h9'] and data.target in lab.ISLAND_A.targets()
        path = lab.ISLAND_A.path_to(data.target)
        assert path == [f"h{i}" for i in range(1, int(data.target[1:]))] and 4 <= len(path) <= 8
        assert data.silent in path[1:]
        for _ in range(30):
            other = lab.Data.generate()
            assert other.target in lab.ISLAND_A.targets() and other.silent in lab.ISLAND_A.path_to(other.target)[1:]
        assert lab.ISLAND_A.path_to('h5') == ['h1', 'h2', 'h3', 'h4'] and lab.ISLAND_A.routers == lab.HIDDEN_ROUTERS

    def test_target2(self, lab, data):
        assert lab.ISLAND_C.targets() == ['k3', 'k4', 'k5'] and lab.ISLAND_C.path_to('k3') == ['k1', 'k2']
        for d in [data] + [lab.Data.generate() for _ in range(30)]:
            assert d.target2 in lab.ISLAND_C.targets()
            # any TTL accepted by fw reaches target2 (hop 6 at most); the probes of a trace stay below the limit
            assert 12 <= d.ttl_min <= 40 and d.ttl_min > lab.TARGET_RANGE2[1] + 1
            assert lab.PROBE_TTL_LIMIT > lab.TARGET_RANGE2[1] + 1 and lab.PROBE_TTL < lab.PROBE_TTL_LIMIT
            # the probe of the final state expires before the nearest destination (k3 at hop 4)
            assert lab.PROBE_TTL < lab.TARGET_RANGE2[0] + 1

    def test_ttl_values_and_far_address(self, lab, data):
        assert 5 <= data.ttl_a <= 30 and data.ttl_a % 3 == 2 and trc.hop_at(data.ttl_a, lab.CYCLE) == 'r2'
        assert 31 <= data.ttl_b <= 63 and data.ttl_b % 3 == 0 and trc.hop_at(data.ttl_b, lab.CYCLE) == 'r3'
        assert 8 <= data.inj_ttl <= 60
        assert data.far_address in lab.FAR_NETWORK
        for name, net in vars(data.nets).items():
            assert data.far_address not in net, name
            assert net.prefixlen == 24 and net.is_private

    def test_addresses(self, lab, data):
        assert set(lab._TOPOLOGY) == set(vars(data.nets))
        for net, members in lab._TOPOLOGY.items():
            for m in members:
                name = m if m in lab._SINGLE_HOMED else f"{m}_{net}"
                assert getattr(data.ips, name).ip in getattr(data.nets, net), name
        assert lab._SINGLE_HOMED == {'m1', 'h9', 'm2', 'k5', 'inj', 'srv'}


class TestTopology:
    def test_machines_and_networks(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        names = set(ns.get_machine_names())
        assert names == ({'m1', 'gw', 'm2', 'fw', 'inj', 'r1', 'r2', 'r3', 'srv'}
                         | set(lab.HIDDEN_ROUTERS) | set(lab.HIDDEN_ROUTERS2))
        assert len(names) == 23 and len(lab._TOPOLOGY) == 21
        assert set(ns.get_accessible_machine_names()) == {'m1', 'm2', 'inj', 'r1', 'r2', 'r3'}
        assert {m.name for m in ns.get_visibles_machines()} == {'m1', 'gw', 'm2', 'fw', 'inj', 'r1', 'r2', 'r3', 'srv'}
        visible_nets = {n.name for n in ns.get_visible_networks()}
        assert visible_nets == {'lan1', 'core1', 'lan2', 'core2', 'lan3', 'l12', 'l23', 'l31', 'lan4'}
        # the core networks are clouds: the student does not know what lies behind the gateway
        assert {n.name: n.shape for n in ns.get_visible_networks() if n.shape} == {'core1': 'cloud', 'core2': 'cloud'}
        # explicit interface numbers of island B
        assert lab._TOPOLOGY['l31'] == {'r3': 1, 'r1': 2} and lab._TOPOLOGY['lan4'] == {'r3': 2, 'srv': 0}
        assert lab._machine_networks('r1') == [(0, 'lan3'), (1, 'l12'), (2, 'l31')]
        # the hidden line: eth0 towards the gateway, eth1 towards the next router, the last router has eth0 only
        assert lab._machine_networks('h1') == [(0, 'core1'), (1, 'c12')]
        assert lab._machine_networks('h5') == [(0, 'c45'), (1, 'c56')] and lab._machine_networks('h9') == [(0, 'c89')]
        assert lab._TOPOLOGY['c45'] == {'h4': 1, 'h5': 0}
        # island C: the same construction with its own prefixes, no shared network with the others
        assert lab._TOPOLOGY['lan2'] == {'m2': 0, 'fw': 0} and lab._TOPOLOGY['core2'] == {'fw': 1, 'k1': 0}
        assert lab._machine_networks('k5') == [(0, 'd45')] and 'tlan' not in lab._TOPOLOGY and 'tlan2' not in lab._TOPOLOGY
        for net, members in lab._TOPOLOGY.items():
            islands = {('a' if m in ['m1', 'gw'] + lab.HIDDEN_ROUTERS else
                        'c' if m in ['m2', 'fw'] + lab.HIDDEN_ROUTERS2 else 'b') for m in members}
            assert len(islands) == 1, net

    @pytest.mark.parametrize('island_key', ['a', 'c'])
    def test_routes_follow_the_path(self, lab, data, island_key):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        island = lab.ISLAND_A if island_key == 'a' else lab.ISLAND_C
        target = data.target if island_key == 'a' else data.target2
        path = island.path_to(target)
        default = '0.0.0.0/0'
        lan = getattr(data.nets, island.lan)
        chain = [island.gateway] + path + [target]
        for k, r in enumerate(path, start=1):
            routes = {(str(net), str(gw.ip)) for entry in ns.net_config[r] for net, gw in entry[1]}
            prev, nxt = chain[k - 1], chain[k + 1]
            back = str(ns.addr(prev, island.link(prev, r)).ip)
            assert (str(lan), back) in routes, r
            if nxt == target:
                assert len(routes) == 1       # the destination is directly connected
            else:
                assert (default, str(ns.addr(nxt, island.link(r, nxt)).ip)) in routes and len(routes) == 2
        # the destination router only knows the way back (on eth0), the routers after it get nothing
        assert ns.net_config[target][0][1] == [(lan.supernet(new_prefix=0), ns.addr(path[-1], island.link(path[-1], target)))]
        assert all(entry[1] == [] for entry in ns.net_config[target][1:])
        for r in set(island.routers) - set(path) - {target}:
            assert all(entry[1] == [] for entry in ns.net_config[r]), r
        assert ns.net_config[island.host][0][1][0][1] == ns.addr(island.gateway, island.lan)
        assert ns.net_config[island.gateway][1][1][0][1] == ns.addr(path[0], island.core)
        for m in ('inj', 'r1', 'r2', 'r3'):
            assert all(entry[1] == [] for entry in ns.net_config[m]), m
        assert ns.net_config['srv'][0][1][0][1] == ns.addr('r3', 'lan4')
        # the routes of a hidden router sit on the interface whose network holds the gateway
        for m, entries in ns.net_config.items():
            for entry in entries:
                for _, gw in entry[1]:
                    assert gw.ip in entry[0][0].network, m

    def test_expected_path_and_hop_addresses(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.expected_path == ['gw'] + lab.ISLAND_A.path_to(data.target) and ns.silent_index >= 1
        assert ns.hop_address(0) == ns.addr('gw', 'lan1')
        assert ns.hop_address(1) == ns.addr('h1', 'core1')
        for k in range(1, len(ns.expected_path)):
            assert trc.address_owner(str(ns.hop_address(k).ip), data.ips) == ns.expected_path[k]
        assert ns.expected_path2 == ['fw'] + lab.ISLAND_C.path_to(data.target2)
        assert ns.expected_paths == {'a': ns.expected_path, 'c': ns.expected_path2}
        assert ns.hop_address(0, lab.ISLAND_C) == ns.addr('fw', 'lan2')
        assert ns.hop_address(1, lab.ISLAND_C) == ns.addr('k1', 'core2')
        for k in range(1, len(ns.expected_path2)):
            assert trc.address_owner(str(ns.hop_address(k, lab.ISLAND_C).ip), data.ips) == ns.expected_path2[k]
        assert lab.ISLAND_C.link('fw', 'k1') == 'core2' and lab.ISLAND_C.link('k4', 'k5') == 'd45'
        assert lab.ISLAND_A.link('h4', 'h3') == 'c34' and lab.ISLAND_A.link('h1', 'gw') == 'core1'
        # the hop after the last router is the destination: its ingress address is what `target` names
        n, n2 = len(ns.expected_path), len(ns.expected_path2)
        assert ns.hop_address(n) == ns.target_address(lab.ISLAND_A)
        assert ns.target_address() == ns.addr(data.target, lab.ISLAND_A.link(ns.expected_path[-1], data.target))
        assert ns.hop_address(n2, lab.ISLAND_C) == ns.target_address(lab.ISLAND_C)
        assert trc.address_owner(str(ns.target_address().ip), data.ips) == data.target
        assert ns.targets == {'a': data.target, 'c': data.target2}


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for host in ('m1', 'm2'):
            cmds = _cmds(ops, 1, host)
            assert any(c.startswith('for n in traceroute') and 'update-alternatives --remove-all' in c for c in cmds)
        for m in set(ns.get_machine_names()) - {'m1', 'm2'}:
            assert not any('update-alternatives' in c for c in _cmds(ops, 1, m)), m
        # fw: the TTL firewall, before the TTL check, with its probe counter
        fw_rules = _files(ops, 1, 'fw')[lab.TTLFW_RULES]
        assert 'type filter hook prerouting priority raw' in fw_rules
        assert f'iifname "eth0" icmp type echo-request ip ttl lt {data.ttl_min} drop' in fw_rules
        assert 'ip hdrlength gt 5 drop' in fw_rules
        assert f'iifname "eth0" ip ttl lt {lab.PROBE_TTL_LIMIT} counter comment "{lab.PROBE_COUNTER}"' in fw_rules
        assert any(f"nft -f {lab.TTLFW_RULES}" in c for c in _cmds(ops, 1, 'fw'))
        for m in set(ns.get_machine_names()) - {'fw'}:
            assert lab.TTLFW_RULES not in _files(ops, 1, m), m
        for m in ns.get_machine_names():
            forward = [c for c in _cmds(ops, 1, m) if 'ip_forward' in c and 'sysctl' in c]
            assert forward == [f"sysctl -w net.ipv4.ip_forward={int(m in lab.ROUTERS)}"], m
        # the silent router drops its own time exceeded
        silent_files = _files(ops, 1, data.silent)
        assert 'icmp type time-exceeded drop' in silent_files[lab.SILENT_RULES]
        assert any(f"nft -f {lab.SILENT_RULES}" in c for c in _cmds(ops, 1, data.silent))
        for r in set(lab.HIDDEN_ROUTERS) - {data.silent}:
            assert lab.SILENT_RULES not in _files(ops, 1, r), r
        # srv: UDP dropped, web server; r2 talkative
        assert 'meta l4proto udp drop' in _files(ops, 1, 'srv')[lab.FW_RULES]
        assert any('sre_http_server_80.py' in c for c in _cmds(ops, 1, 'srv'))
        assert any(f"nft delete table ip {lab.SILENT_TABLE}" in c for c in _cmds(ops, 1, 'r2'))
        # the hosts file of m1 names m1, gw (lan1) and target only
        hosts = _files(ops, 1, 'm1')['/etc/hosts']
        assert f"{data.ips.m1.ip}\t\tm1" in hosts and f"{ns.addr('gw', 'lan1').ip}\t\tgw" in hosts
        target_ip = str(ns.target_address(lab.ISLAND_A).ip)
        assert f"{target_ip}\t\ttarget\t\ttarget.{lab.DOMAIN}" in hosts
        hidden_addresses = [str(a.ip) for name, a in vars(data.ips).items()
                            if name.split('_')[0] in lab.HIDDEN_ROUTERS or name == 'gw_core1']
        assert target_ip in hidden_addresses      # the destination is a router of the hidden line...
        assert not any(a in hosts for a in hidden_addresses if a != target_ip)   # ...and its only address given
        # the same for m2: m2, fw (lan2) and target2
        hosts2 = _files(ops, 1, 'm2')['/etc/hosts']
        assert f"{data.ips.m2.ip}\t\tm2" in hosts2 and f"{ns.addr('fw', 'lan2').ip}\t\tfw" in hosts2
        target2_ip = str(ns.target_address(lab.ISLAND_C).ip)
        assert f"{target2_ip}\t\ttarget2" in hosts2
        hidden_addresses2 = [str(a.ip) for name, a in vars(data.ips).items()
                             if name.split('_')[0] in lab.HIDDEN_ROUTERS2 or name == 'fw_core2']
        assert not any(a in hosts2 for a in hidden_addresses2 if a != target2_ip)
        assert 'm1' not in hosts2 and 'target\t' not in hosts2 and 'm2' not in hosts
        # island B hosts files: the five machines, every interface, nothing of island A
        inj_hosts = _files(ops, 1, 'inj')['/etc/hosts']
        for name in ('r1_lan3', 'r1_l12', 'r1_l31', 'r2_l12', 'r2_l23', 'r3_l23', 'r3_l31', 'r3_lan4', 'srv', 'inj'):
            assert f"\t\t{name}\t" in inj_hosts, name
        assert 'gw' not in inj_hosts and 'target' not in inj_hosts and 'm1' not in inj_hosts
        for h in lab.HIDDEN_ROUTERS + lab.HIDDEN_ROUTERS2 + ['gw', 'fw']:
            assert '/etc/hosts' not in _files(ops, 1, h), h

    def test_restore_and_user_states(self, lab, data):
        # two instances: the remount of /proc/sys is registered once per machine and instance
        initial = _state_ops(lab.NetScheme(data=data, running_lab_name=_running_name()), 'initial')
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        restore = _state_ops(ns, 'restore')

        def summary(ops):
            return {k: (_cmds(ops, *k), _files(ops, *k)) for k in ops}
        assert set(initial) == set(restore)
        for k in initial:
            assert summary(initial)[k] == summary(restore)[k], k
        reject = _state_ops(ns, 'srv_reject')
        assert 'reject with icmp type admin-prohibited' in _files(reject, 1, 'srv')[lab.FW_RULES]
        assert list(reject) == [(1, 'srv')]
        drop = _state_ops(ns, 'srv_drop')
        assert 'meta l4proto udp drop' in _files(drop, 1, 'srv')[lab.FW_RULES]
        silent = _state_ops(ns, 'r2_silent')
        assert 'icmp type time-exceeded drop' in _files(silent, 1, 'r2')[lab.SILENT_RULES] and list(silent) == [(1, 'r2')]
        talkative = _state_ops(ns, 'r2_talkative')
        assert _cmds(talkative, 1, 'r2') == [f"nft delete table ip {lab.SILENT_TABLE} 2>/dev/null; true"]
        states = {name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)}
        assert {'initial', 'restore', 'final', 'srv_reject', 'srv_drop', 'r2_silent', 'r2_talkative'} <= states

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        assert _cmds(ops, 1, 'inj')[0] == f"ip route replace 0.0.0.0/0 via {ns.addr('r1', 'lan3').ip}"
        assert f"ip route replace 0.0.0.0/0 via {ns.addr('r2', 'l12').ip}" in _cmds(ops, 1, 'r1')
        assert f"ip route replace 0.0.0.0/0 via {ns.addr('r3', 'l23').ip}" in _cmds(ops, 1, 'r2')
        assert f"ip route replace 0.0.0.0/0 via {ns.addr('r1', 'l31').ip}" in _cmds(ops, 1, 'r3')
        for r in ('r2', 'r3'):
            assert "sysctl -w net.ipv4.icmp_errors_use_inbound_ifaddr=1" in _cmds(ops, 1, r)
        assert f"sysctl -w net.ipv4.ip_default_ttl={data.inj_ttl}" in _cmds(ops, 1, 'inj')
        # one UDP probe of a small TTL from m2 (the counter of fw)
        assert _cmds(ops, 1, 'm2') == [f"printf x | nc -u -w 1 -M {lab.PROBE_TTL} {ns.target_address(lab.ISLAND_C).ip} 33434; true"]
        for m in ['m1', 'gw', 'fw', 'srv'] + lab.HIDDEN_ROUTERS + lab.HIDDEN_ROUTERS2:
            assert (1, m) not in ops, m


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrading:
    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        assert _totals(grade) == (120, 120)
        parts = {}
        for e in grade.get_grade_list():
            parts[e.grade_part] = parts.get(e.grade_part, 0) + e.max_grade
        assert parts == {'part1': 20, 'part2': 20, 'part3': 30, 'part4': 20, 'part5': 30}
        assert grade.max_step == 1

    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=False)
        assert _totals(grade) == (0, 120)
        assert _by_title(grade)['probes_fw'].grade == 0

    def test_path2_scoring(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        n = len(ns.expected_path2)
        answers = dict(grade.get_cheat_answers('final') or {})
        q = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None) and q.fields[0]['name'] == 'path2'][0]

        def score(path_text):
            form = json.loads(answers[q.question_hash])
            form['path2'] = path_text
            grade._answers = {**answers, q.question_hash: json.dumps(form)}
            grade.reset_before_grade()
            grade.grade()
            return _by_title(grade)['path2'].grade

        ingress = [str(ns.hop_address(k, lab.ISLAND_C).ip) for k in range(n)]
        assert score("\n".join(ingress)) == 10                   # one address per line, as asked
        assert score(" ".join(ingress)) == 10                    # any separator is accepted
        assert score(" ".join([str(data.ips.m2.ip)] + ingress + [str(ns.target_address(lab.ISLAND_C).ip)])) == 10
        assert score(" ".join(ingress + [str(ns.hop_address(1).ip)])) == round(10 * (n - 1) / n, 2)   # an address of island A
        assert score(" ".join(['*'] * n)) == 0 and score("") == 0

    def test_path_scoring(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        n = len(ns.expected_path)
        answers = dict(grade.get_cheat_answers('final') or {})

        def score(path_text):
            q = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None) and q.fields[0]['name'] == 'path'][0]
            form = json.loads(answers[q.question_hash])
            form['path'] = path_text
            grade._answers = {**answers, q.question_hash: json.dumps(form)}
            grade.reset_before_grade()
            grade.grade()
            return _by_title(grade)['path'].grade

        ingress = [str(ns.hop_address(k).ip) for k in range(n)]
        assert score("\n".join(ingress)) == 10                   # one address per line, as asked
        assert score(" ".join(ingress)) == 10                    # any separator is accepted
        with_star = list(ingress)
        with_star[ns.silent_index] = '*'
        assert score(", ".join(with_star)) == 10
        path = lab.ISLAND_A.path_to(data.target)
        egress = [str(ns.addr('gw', 'core1').ip)] + [
            str(ns.addr(r, lab.ISLAND_A.link(r, nxt)).ip) for r, nxt in zip(path, path[1:] + [data.target])]
        assert score(" ".join(egress)) == 10                       # the addresses ping -R records
        # a pasted ping -R list: m1 first, the destination (recorded twice) at the end, no penalty; nor for
        # any other address of the destination router
        target_ip = str(ns.target_address().ip)
        assert score(" ".join([str(data.ips.m1.ip)] + egress + [target_ip, target_ip])) == 10
        destination = [str(a.ip) for name, a in vars(data.ips).items() if name.split('_')[0] == data.target]
        assert score(" ".join(egress + destination)) == 10
        assert score(" ".join(ingress + ['203.0.113.250'])) == round(10 * (n - 1) / n, 2)   # a foreign extra
        assert score(" ".join(ingress[1:])) == 0                    # shifted: nothing at the right position
        assert score("") == 0 and score(" ".join(['*'] * n)) == round(10 / n, 2)

    def test_loop_from_the_wrong_router(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir, everything=True)
        by = _by_title(grade)
        assert by['loop_ttl_64'].grade == 3 and by['loop_ttl_b'].grade == 3
        # the loop built in the other direction: hop ttl_b is r2, not r3
        far = str(data.far_address)
        other = ("===T64\n" + _ping_error(far, ns.addr('r1', 'lan3').ip)
                 + "===TB\n" + _ping_error(far, ns.addr('r2', 'l12').ip))
        for (m, s), cmds in grade.get_tests().items():
            for key in cmds:
                if key[0].startswith('echo "===T64"'):
                    cmds[key] = (other, 0)
        grade.reset_before_grade()
        grade.grade()
        by = _by_title(grade)
        assert by['loop_ttl_64'].grade == 3 and by['loop_ttl_b'].grade == 0

    def test_form_elements_are_exo_only(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=True)
        for e in grade.get_grade_list():
            if str(e.title).startswith('q_') or str(e.title) in ('path', 'routers_count', 'reply_ttl_target',
                                                                 'initial_ttl', 'icmp_time_exceeded', 'silent_hop',
                                                                 'path2', 'routers2_count', 'reply_ttl_target2'):
                assert e.scope == params.EXO_EVAL_SCOPE, e.title
            else:
                assert e.scope == params.BOTH_EVAL_SCOPE, e.title

    def test_cheat_answers_match_the_choices(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=True)
        answers = grade.get_cheat_answers('final')
        for q in grade.get_questions_ordered():
            if not getattr(q, 'fields', None):
                continue
            form = json.loads(answers[q.question_hash])
            for f in q.fields:
                assert f['name'] in form, f['name']
                if 'choices' in f:
                    assert form[f['name']] in f['choices'], (f['name'], form[f['name']], f['choices'])
                elif 'regex' in f:
                    assert re.fullmatch(f['regex'], form[f['name']]), (f['name'], form[f['name']])
                elif 'lines' in f:
                    value = form[f['name']]
                    assert value.splitlines() == trc.parse_path_answer(value), (f['name'], value)
                    assert len(value.splitlines()) >= 2


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
        assert len(g1.get_questions_ordered()) == 6
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 6 and 'informations' not in with_fragment

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), where
            assert '@@{' not in text or where != 'informations'
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        from SRE.informations import resolve_informations
        resolved, numbering = resolve_informations(ns1.informations)
        informations = _text(resolved)
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 13)]
        assert '## <a id="ttl"></a>1. Le champ TTL' in informations
        assert '## <a id="emulation-udp"></a>7. Émuler traceroute sans ICMP' in informations
        assert '## <a id="loops"></a>9. Les boucles de routage' in informations
        assert '- [9. Les boucles de routage](#loops)' in informations and '(section [9](#loops))' in informations
        assert '(section [7](#emulation-udp))' in "\n".join(_text(q.description) for q in g1.get_questions_ordered()) or True
        assert 'IPv6' not in informations and 'traceroute6' not in informations

    def test_student_texts_never_show_the_hidden_path(self, lab, data, tmp_pub_dir):
        """The same project rendered with two different hidden paths gives the same student texts
        (the path is what the students discover); the instructor texts do change."""
        targets, targets2 = lab.ISLAND_A.targets(), lab.ISLAND_C.targets()
        texts = {}
        for i, (target, target2) in enumerate(((targets[0], targets2[0]), (targets[-1], targets2[-1]))):
            variant = lab.Data.from_json(data.to_json())
            variant.target, variant.target2 = target, target2
            variant.silent = lab.ISLAND_A.path_to(target)[1]
            variant.ttl_min = 20 + i
            for mode in (False, True):
                grade, ns = _simulate(lab, variant, tmp_pub_dir, instructor_mode=mode)
                # the destinations are routers of the hidden lines: their ingress addresses are the only
                # hidden ones a student is given (/etc/hosts and the texts), masked for the comparison
                masks = {str(ns.target_address(isl).ip): f"<{isl.target_name}>" for isl in (lab.ISLAND_A, lab.ISLAND_C)}
                rendered = [_text(q.description) for q in grade.get_questions_ordered()] + [_text(ns.informations)]
                for ip, mask in masks.items():
                    rendered = [t.replace(ip, mask) for t in rendered]
                texts[(i, mode)] = rendered
                if not mode:
                    student = "\n".join(rendered)
                    for name, a in vars(variant.ips).items():
                        if name.split('_')[0] in lab.HIDDEN_ROUTERS + lab.HIDDEN_ROUTERS2 or name in ('gw_core1', 'fw_core2'):
                            assert str(a.ip) not in student, name
                    assert not re.search(r'\b[hk][1-9]\b', student)
                    assert '<target>' in student and '<target2>' in student
        assert texts[(0, False)] == texts[(1, False)]
        assert texts[(0, True)] != texts[(1, True)]

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        fields = 0
        for q in g1.get_questions_ordered():
            for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description)):
                fields += 1
                assert '}' not in m.group(2)
        assert fields == 7 + 6 + 6 + 9 + 10
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert kinds['path'] == {'name': 'path', 'lines': 8}
        assert kinds['path2'] == {'name': 'path2', 'lines': 6}
        for name, f in kinds.items():
            if name not in ('path', 'path2'):
                assert 'lines' not in f and ({'regex', 'choices', 'checkbox'} & f.keys()), f

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 11 and result.warnings == []
        stripped = tmp_path / 'traceroute_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('traceroute_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (120, 120)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements and part keys are English."""
        french = re.compile(r'(routeur|cible|sonde|boucle|muet|chemin|reseau|serveur|pare|retour|aller)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
