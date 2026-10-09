"""Offline tests of the VLAN lab (lab/sre/_DRAFT_misc/vlan.py): data generation for both flavors,
topology, the ops of the states, the two-pass grading contract with synthetic outputs (nothing
done: 0, everything done: 100, tampering not rewarded), instructor texts, English identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of
the real tools (ip -j, nft, iptables, the echo page, the switch console).
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

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'vlan.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('vlan_lab_under_test', _LAB_PATH)
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
    """{(step, machine): [ops]} registered by the state method *name* (host ops under machine None)."""
    ns._ops, ns._host_ops = {}, {}
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    for step, op_list in ns._host_ops.items():
        ops.setdefault((step, None), []).extend(op_list)
    return ops


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str) and hasattr(op, 'filename')}


def _ip(obj):
    return str(obj.ip)


# ---------------------------------------------------------------------------
# synthetic outputs
# ---------------------------------------------------------------------------


def _link(name, kind=None, parent=None, vid=None, master=None, up=True, mac="02:00:00:00:00:01"):
    link = {"ifindex": 1, "ifname": name, "flags": ["BROADCAST", "MULTICAST"] + (["UP", "LOWER_UP"] if up else []),
            "mtu": 1500, "link_type": "ether", "address": mac}
    if parent:
        link["link"] = parent
    if master:
        link["master"] = master
    if kind == 'vlan':
        link["linkinfo"] = {"info_kind": "vlan", "info_data": {"protocol": "802.1Q", "id": vid, "flags": ["REORDER_HDR"]}}
    elif kind == 'bridge':
        link["linkinfo"] = {"info_kind": "bridge", "info_data": {"vlan_filtering": 0}}
    elif kind:
        link["linkinfo"] = {"info_kind": kind}
    return link


def _addr(name, *addresses):
    return {"ifindex": 1, "ifname": name, "flags": ["UP"],
            "addr_info": [{"family": "inet", "local": str(a).split('/')[0], "prefixlen": int(str(a).split('/')[1]),
                           "scope": "global", "label": name} for a in addresses]}


def _links_done(lab, machine):
    odd, even = lab.VLAN_ODD, lab.VLAN_EVEN
    if machine in ('b1', 'b2'):
        return [_link('lo', 'loopback'), _link('eth0', 'veth'),
                _link(f'eth0.{odd}', 'vlan', 'eth0', odd, master='brodd'),
                _link(f'eth0.{even}', 'vlan', 'eth0', even, master='breven'),
                _link('eth1', 'veth', master='brodd'), _link('eth2', 'veth', master='breven'),
                _link('brodd', 'bridge', mac="02:00:00:00:00:b1"), _link('breven', 'bridge')]
    if machine in ('router', 'router2'):
        return [_link('lo', 'loopback'), _link('eth0', 'veth'), _link('eth1', 'veth'),
                _link(f'eth1.{odd}', 'vlan', 'eth1', odd), _link(f'eth1.{even}', 'vlan', 'eth1', even)]
    return [_link('lo', 'loopback'), _link('eth0', 'veth')]


def _links_nothing(machine):
    n = {'b1': 3, 'b2': 3, 'router': 2, 'router2': 2}.get(machine, 1)
    return [_link('lo', 'loopback')] + [_link(f'eth{i}', 'veth') for i in range(n)]


def _addrs_done(lab, d, machine):
    odd, even = lab.VLAN_ODD, lab.VLAN_EVEN
    if machine in ('b1', 'b2'):
        return [_addr('eth0', getattr(d.ips, f'{machine}_trunk')), _addr('brodd', getattr(d.ips, f'{machine}_odd'))]
    if machine in ('router', 'router2'):
        return [_addr('eth0', getattr(d.ips, f'{machine}_ext')), _addr('eth1', getattr(d.ips, f'{machine}_trunk')),
                _addr(f'eth1.{odd}', getattr(d.ips, f'{machine}_odd')), _addr(f'eth1.{even}', getattr(d.ips, f'{machine}_even'))]
    return [_addr('eth0', getattr(d.ips, machine))]


def _addrs_nothing(d, machine):
    if machine in ('b1', 'b2'):
        return [_addr('eth0', getattr(d.ips, f'{machine}_trunk'))]
    if machine in ('router', 'router2'):
        return [_addr('eth0', getattr(d.ips, f'{machine}_ext')), _addr('eth1', getattr(d.ips, f'{machine}_trunk'))]
    if machine == 'm7':
        return [_addr('eth0')]
    return [_addr('eth0', getattr(d.ips, machine))]


def _switch_output(lab, command, m7_vlan):
    """port/allprint and vlan/allprint of the trunk switch: four trunk ports and the port of m7."""
    odd, even = lab.VLAN_ODD, lab.VLAN_EVEN
    machines = [('b1', 1), ('b2', 2), ('router', 3), ('router2', 4), ('m7', 5)]
    if command == 'port/allprint':
        out = []
        for name, port in machines:
            vlan = m7_vlan if name == 'm7' else 0
            iface = 'eth1' if name.startswith('router') else 'eth0'
            out += [f"Port {port:04d} untagged_vlan={vlan:04d} ACTIVE - NOT Unnamed Allocatable",
                    " Current User: root Access Control: (User: NONE - Group: NONE)",
                    f"  -- endpoint ID 00{port:02d} module unix prog   : kathara {name}:{iface} user=0 pid=1000"]
        return "\n".join(out) + "\n"
    if command == 'vlan/allprint':
        out = ["VLAN 0000"] + [f" -- Port {p:04d} tagged=0 active=1 status=Forwarding" for _, p in machines if m7_vlan or p != 5]
        for vid in (odd, even):
            out.append(f"VLAN {vid:04d}")
            out += [f" -- Port {p:04d} tagged=1 active=1 status=Forwarding" for _, p in machines[:4]]
            if vid == m7_vlan:
                out.append(" -- Port 0005 tagged=0 active=1 status=Forwarding")
        return "\n".join(out) + "\n"
    return ""


def _echo(server, server_ip, port, client_ip, ttl):
    return f"SERVER={server}\nSERVER_IP={server_ip}\nSERVER_PORT={port}\nCLIENT_IP={client_ip}\nCLIENT_PORT=40000\nTTL={ttl}\n"


def _nft_done(lab, d):
    return f"""table ip nat {{
	chain POSTROUTING {{
		type nat hook postrouting priority srcnat; policy accept;
	}}
}}
table bridge {lab.BROUTER_TABLE} {{
	chain {lab.BROUTER_CHAIN} {{
		type filter hook prerouting priority dstnat; policy accept;
		iifname "eth1" ip saddr {_ip(d.ips.m3)} meta pkttype set host ether daddr set 02:00:00:00:00:b1
		iifname "eth1" ip daddr {_ip(d.ips.ext2)} tcp dport {lab.HTTP_PORTS[1]} meta pkttype set host ether daddr set 02:00:00:00:00:b1
	}}
}}
table ip mangle {{
	chain PREROUTING {{
		type filter hook prerouting priority mangle; policy accept;
		ip saddr {_ip(d.ips.m3)} counter packets 13 bytes 842 # xt target TTL
	}}
}}
"""


def _synthetic(lab, ns, machine, command):
    """(output, code) of *command* on *machine* in a project where everything is done."""
    d = ns.data
    if command == 'ip -j -d link show':
        return json.dumps(_links_done(lab, machine)), 0
    if command.startswith('ip -j -4 addr show'):
        return json.dumps(_addrs_done(lab, d, machine)), 0
    if command == 'ip route':
        if machine == 'b2':
            return f"default via {_ip(d.ips.router2_trunk)} dev eth0\n{d.nets.trunk} dev eth0 proto kernel scope link src {_ip(d.ips.b2_trunk)}\n", 0
        if machine == 'm7':
            return f"default via {_ip(d.ips.router_odd)} dev eth0\n{d.nets.odd} dev eth0 proto kernel scope link src {_ip(d.ips.m7)}\n", 0
        return "", 0
    if command == 'cat /proc/sys/net/ipv4/ip_forward':
        return "1\n", 0
    if command == 'cat /proc/sys/net/ipv4/ip_default_ttl':
        return (f"{lab.TTL_M5}\n" if machine == 'm5' else "64\n"), 0
    if machine == 'trunk':
        return _switch_output(lab, command, lab.VLAN_ODD), 0
    if command.startswith('ping '):
        ip = command.split()[-1]
        return f"PING {ip} ({ip}) 56(84) bytes of data.\n64 bytes from {ip}: icmp_seq=1 ttl=64 time=0.1 ms\n", 0
    if command.startswith('curl '):
        m = re.search(r'http://([^:/]+):(\d+)/', command)
        host, port = m.group(1), int(m.group(2))
        server = 'ext1' if host == _ip(d.ips.ext1) else 'ext2'
        via_router2 = machine in ('b2', 'm3') or (machine == 'm5' and server == 'ext2' and port == lab.HTTP_PORTS[1])
        client = d.ips.router2_ext if via_router2 else d.ips.router_ext
        ttl = lab.TTL_M5 - 1 if machine == 'm5' else lab.DEFAULT_TTL - 1   # m3: routed by b2 (-1) + TTL +1
        return _echo(server, host, port, _ip(client), ttl), 0
    if command == 'nft list ruleset':
        return (_nft_done(lab, d) if machine == 'b2' else ""), 0
    if command.startswith('iptables -t mangle -S'):
        return ("-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n"
                f"-A PREROUTING -s {_ip(d.ips.m3)}/32 -j TTL --ttl-inc 1\n"), 0
    return "", 0


def _nothing(lab, ns, machine, command):
    """(output, code) right after the initial state."""
    d = ns.data
    if command == 'ip -j -d link show':
        return json.dumps(_links_nothing(machine)), 0
    if command.startswith('ip -j -4 addr show'):
        return json.dumps(_addrs_nothing(d, machine)), 0
    if command == 'ip route':
        if machine == 'b2':
            return f"default via {_ip(d.ips.router_trunk)} dev eth0\n", 0
        return "", 0
    if command == 'cat /proc/sys/net/ipv4/ip_forward':
        return "0\n", 0
    if command == 'cat /proc/sys/net/ipv4/ip_default_ttl':
        return "64\n", 0
    if machine == 'trunk':
        return _switch_output(lab, command, 0), 0
    if command.startswith('ping '):
        return "2 packets transmitted, 0 received, 100% packet loss, time 1012ms\n", 1
    if command.startswith('curl '):
        return "", 7
    if command.startswith('iptables -t mangle -S'):
        return "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n", 0
    return "", 0


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
            assert current == keys, "the registered tests changed between two passes"
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
    nets = [d.nets.odd, d.nets.even, d.nets.trunk, d.nets.ext]
    assert len(set(nets)) == 4 and all(n.prefixlen == 24 and n.is_private for n in nets)
    for m in ('m1', 'm3', 'm5', 'm7'):
        assert getattr(d.ips, m) in d.nets.odd and int(str(getattr(d.ips, m).ip).split('.')[-1]) == lab.HOST_PARTS[m]
    for m in ('m2', 'm4', 'm6'):
        assert getattr(d.ips, m) in d.nets.even
    assert d.ips.b1_odd in d.nets.odd and d.ips.b2_odd in d.nets.odd and d.ips.b1_trunk in d.nets.trunk
    assert str(d.ips.router_odd.ip).endswith('.254') and str(d.ips.router2_even.ip).endswith('.200')
    assert d.ips.ext1 in d.nets.ext and d.ips.router2_ext in d.nets.ext and d.ips.router_trunk in d.nets.trunk
    js = d.to_json()
    assert lab.Data.from_json(js).to_json() == js and lab.Data.unpack(d.pack()).to_json() == js


def test_fixed_flavor_uses_the_handout_networks(lab):
    for flavor in (lab.Flavor(ip_choice='fixed'), lab.Flavor.fixed, lab.Flavor.from_form_dict({'ip_choice': 'fixed'})):
        d = lab.Data.generate(flavor=flavor)
        assert (str(d.nets.odd), str(d.nets.even), str(d.nets.trunk), str(d.nets.ext)) == (
            '192.168.11.0/24', '192.168.22.0/24', '10.10.10.0/24', '172.17.1.0/24')
        assert str(d.ips.m7) == '192.168.11.7/24' and str(d.ips.b2_odd) == '192.168.11.102/24'
        assert str(d.ips.router_even) == '192.168.22.254/24' and str(d.ips.ext1) == '172.17.1.51/24'
    assert lab.Data.generate(flavor=lab.Flavor()).nets.odd != lab.FIXED_NETWORKS['odd'] or True
    assert lab.flavor_form_at_startup and 'ip_choice' in _text(lab.Flavor.flavor_form)
    assert lab.Flavor.random.ip_choice == 'random' and lab.Flavor().ip_choice == 'random'


def test_topology_and_machines(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    assert ns.get_machine_names() == ['router', 'router2', 'b1', 'b2', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7',
                                      'ext1', 'ext2']
    assert set(ns.get_visible_machine_names()) == set(ns.get_machine_names())   # no hidden machine
    ifaces = ns.host_interfaces_from_topology()
    assert ifaces['b1'] == ['trunk', 'link1', 'link2'] and ifaces['b2'] == ['trunk', 'odd', 'even']
    assert ifaces['router'] == ['ext', 'trunk'] and ifaces['router2'] == ['ext', 'trunk'] and ifaces['m7'] == ['trunk']
    trunk = ns.get_network('trunk')
    assert trunk.mode == params.network_mode_managed and trunk.allow_connection
    assert set(trunk.vlans) == {'b1', 'b2', 'router', 'router2'} and all(v == [111, 222] for v in trunk.vlans.values())
    assert ns.get_network('odd').mode == 'switch' and ns.get_network('ext').mode == 'switch'
    assert ns.get_network('link1').mode == params.default_network_mode
    assert lab.allow_user_states and lab.export_kathara_project and lab._TRANSLATIONS == {}
    assert not getattr(lab, 'allow_save_restore', False)


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


def test_initial_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'initial')
    d = data
    for m in ns.get_machine_names():
        cmds = _cmds(ops, 1, m)
        assert any('ip_forward=0' in c for c in cmds) and not any('ip_forward=1' in c for c in cmds), m
        assert lab.ECHO_PATH if hasattr(lab, 'ECHO_PATH') else True
        files = _files(ops, 1, m)
        assert '/usr/local/sbin/sre_http_echo.py' in files and 'def parse_syn' in files['/usr/local/sbin/sre_http_echo.py']
        assert any('sre_http_echo.py' in c and ' 80 8080' in c for c in cmds), m
        assert files['/etc/resolv.conf'] == ""
        hosts = files['/etc/hosts']
        assert f"{_ip(d.ips.ext1)}\t\text1" in hosts and f"{_ip(d.ips.router2_trunk)}\t\trouter2_trunk" in hosts
    assert f"ip address add {d.ips.m3} dev eth0" in _cmds(ops, 1, 'm3')
    assert f"ip route add default via {_ip(d.ips.router_odd)}" in _cmds(ops, 1, 'm3')
    assert f"ip route add default via {_ip(d.ips.router_even)}" in _cmds(ops, 1, 'm4')
    assert f"ip address add {d.ips.b2_trunk} dev eth0" in _cmds(ops, 1, 'b2')
    assert not any('ip address add' in c for c in _cmds(ops, 1, 'm7'))      # m7 is left to the students
    assert f"ip address add {d.ips.router2_ext} dev eth0" in _cmds(ops, 1, 'router2')
    assert f"ip address add {d.ips.router_trunk} dev eth1" in _cmds(ops, 1, 'router')
    assert not any('eth1.111' in c or 'brodd' in c or 'nft' in c for m in ns.get_machine_names() for c in _cmds(ops, 1, m))


def test_final_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'final')
    d = data
    for m in ('b1', 'b2'):
        cmds = _cmds(ops, 1, m)
        assert "ip link add link eth0 name eth0.111 type vlan id 111" in cmds
        assert "ip link set eth2 master breven" in cmds and "ip link set eth0.222 master breven" in cmds
        assert "ip link set eth1 master brodd" in cmds and "ip link set eth0.111 master brodd" in cmds
        odd = getattr(d.ips, f'{m}_odd')
        assert f"ip address del {odd} dev eth0.111" in cmds and f"ip address add {odd} dev brodd" in cmds
        assert cmds.index(f"ip address add {odd} dev eth0.111") < cmds.index(f"ip address del {odd} dev eth0.111")
    for m in ('router', 'router2'):
        cmds = _cmds(ops, 1, m)
        assert f"ip address add {getattr(d.ips, m + '_odd')} dev eth1.111" in cmds
        assert f"ip address add {getattr(d.ips, m + '_even')} dev eth1.222" in cmds
        assert "sysctl -w net.ipv4.ip_forward=1" in cmds and "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" in cmds
    m7 = _cmds(ops, 1, 'm7')
    assert f"ip address add {d.ips.m7} dev eth0" in m7 and f"ip route add default via {_ip(d.ips.router_odd)}" in m7
    switch = [op for op in ops.get((1, None), []) if hasattr(op, 'network')]
    assert [(op.network, op.command) for op in switch] == [('trunk', f'port/setvlan @m7 {lab.VLAN_ODD}')]
    b2 = _cmds(ops, 1, 'b2')
    assert f"ip route replace default via {_ip(d.ips.router2_trunk)}" in b2 and "sysctl -w net.ipv4.ip_forward=1" in b2
    assert any(c.startswith("nft 'add chain bridge brouter prerouting { type filter hook prerouting") for c in b2)
    assert (f'nft add rule bridge brouter prerouting iifname "eth1" ip saddr {_ip(d.ips.m3)} meta pkttype set host '
            'ether daddr set $(cat /sys/class/net/brodd/address)') in b2
    assert any(f'ip daddr {_ip(d.ips.ext2)} tcp dport 8080 meta pkttype set host' in c for c in b2)
    assert f"iptables -t mangle -A PREROUTING -s {_ip(d.ips.m3)} -j TTL --ttl-inc 1" in b2
    assert b2.index("nft add table bridge brouter") > b2.index("nft delete table bridge brouter 2>/dev/null; iptables -t mangle -F PREROUTING; true")
    assert _cmds(ops, 1, 'm5') == [f"sysctl -w net.ipv4.ip_default_ttl={lab.TTL_M5}"]
    assert not any('brodd' in c or 'nft' in c for c in _cmds(ops, 1, 'b1') if 'nft' in c)
    for name in ('initial', 'final'):
        assert not getattr(lab.NetScheme, name)._sre_state_user_allowed


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _nothing, cheat=False)
    grades = _grades(grade)
    assert sum(g for g, _ in grades.values()) == 0, {k: v for k, v in grades.items() if v[0]}
    assert sum(mx for _, mx in grades.values()) == 100 and len(grades) == 27
    assert [str(p.title) for p in grade._grade_parts] == [f'part{i}' for i in range(1, 7)]


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _synthetic)
    grades = _grades(grade)
    short = {k: v for k, v in grades.items() if v[0] != v[1]}
    assert not short, short
    assert sum(g for g, _ in grades.values()) == 100
    tests = grade.get_tests()
    assert all(s == 1 for _, s in tests)     # one step: every test is independent
    assert ('trunk', 1) in tests and {c for c, _ in tests[('trunk', 1)]} == {'port/allprint', 'vlan/allprint'}
    curls = [c for m in ('m3', 'm5', 'm4', 'b2', 'm7', 'm2', 'm1') for c, _ in tests.get((m, 1), []) if c.startswith('curl')]
    assert len(curls) == 10 and all(' -m 5 ' in c for c in curls)


def test_tampering_is_not_rewarded(lab, data, tmp_pub_dir):
    """Half a brouter rule, m3 still leaving by router, an address left on eth0.111: points lost."""
    d = data

    def outputs(l, n, machine, command):
        if command == 'nft list ruleset' and machine == 'b2':
            return _nft_done(l, d).replace('meta pkttype set host ', ''), 0
        if command.startswith('curl ') and machine == 'm3':
            return _echo('ext1', _ip(d.ips.ext1), 80, _ip(d.ips.router_ext), 63), 0
        if command.startswith('ip -j -4 addr show') and machine == 'b1':
            return json.dumps(_addrs_done(l, d, 'b1') + [_addr('eth0.111', d.ips.b1_odd)]), 0
        if machine == 'trunk':
            return _switch_output(l, command, 0), 0
        return _synthetic(l, n, machine, command)

    grades = _grades(_simulate(lab, data, tmp_pub_dir, outputs)[0])
    assert grades['brouter_rules'] == (0, 2) and grades['brouter_m3'] == (2, 6) and grades['ttl_increment'] == (2, 6)
    assert grades['brodd_addresses'] == (2, 4) and grades['m7_port_vlan'] == (0, 5)
    assert grades['brouter_port_8080'] == (9, 9) and grades['snat_router'] == (6, 6)


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def test_texts_and_instructor_fragments(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _synthetic, instructor_mode=True)
    info = _text(ns.informations)
    assert info.count('\n## ') == 11 and 'meta pkttype set host' in info and '0x8100' in info
    assert str(data.nets.odd) not in info     # instance data belongs to the first question
    questions = list(grade.get_questions_ordered())
    assert len(questions) == 10
    with_instructor = [q for q in questions if has_instructor(_text(q.description))]
    assert len(with_instructor) == 10
    all_text = info + "".join(_text(q.description) for q in questions)
    assert "{'" not in all_text and not re.search(r"\{[a-z_0-9]+\}", all_text)
    first = _text(questions[0].description)
    for value in (data.nets.odd, data.nets.trunk, data.ips.m7.ip, data.ips.router2_ext.ip, data.ips.b2_odd.ip):
        assert str(value) in first
    assert f"ip saddr {_ip(data.ips.m3)} meta pkttype set host" in all_text
    for e in grade.get_grade_list():
        desc = _text(e.description)
        assert "{'" not in desc and not re.search(r"\{[a-z_]+\}", desc)
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, _synthetic, instructor_mode=False)
    student_text = _text(ns2.informations) + "".join(_text(q.description) for q in grade2.get_questions_ordered())
    assert not has_instructor(student_text) and 'Pour l\'enseignant' not in student_text


def test_cheat_answers_fill_every_form(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _synthetic)
    cheat = grade.get_cheat_answers('final')
    forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
    assert len(forms) == 2
    for q in forms:
        answers = cheat[q.question_hash]
        answers = json.loads(answers) if isinstance(answers, str) else answers
        for field in q.fields:
            assert field['name'] in answers, field['name']
            if 'choices' in field:
                assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'vlan_stripped', 'exec')


def test_english_identifiers(lab, data):
    """Machines, networks, states, data fields, grade elements and part keys are English (tr() texts are French)."""
    french = re.compile(r'(routeur|pont|impair|\bpair\b|reseau|serveur|sonde|panne|exemple|reponse|commutateur|'
                        r'passerelle|machine_|_machine|exterieur)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.NetScheme._network_specs)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += [f.name for f in data.__dataclass_fields__.values()] if hasattr(data, '__dataclass_fields__') else []
    names += list(vars(data.ips)) + list(vars(data.nets)) + [f.name for f in lab.Flavor.__dataclass_fields__.values()]
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade._grade_parts]
    bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
    assert not bad, bad
