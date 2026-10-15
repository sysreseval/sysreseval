"""Offline tests of the bridge / STP lab (lab/sre/_DRAFT_misc/bridge.py): data generation for
both flavors (fixed MAC addresses), topology, the ops of the states, the two-pass grading
contract with synthetic outputs (nothing done: 0, everything done: 100, tampering not
rewarded), instructor texts, English identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of
the real tools (ip -j -d link with the STP fields, bridge -j fdb, nft list ruleset, ping).
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
from bridging import normalize_mac  # noqa: E402

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'bridge.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('bridge_lab_under_test', _LAB_PATH)
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


def _mac(obj):
    return normalize_mac(obj)


# ---------------------------------------------------------------------------
# synthetic outputs
# ---------------------------------------------------------------------------


def _bridge_id(priority, mac):
    """As iproute2 prints it: hexadecimal priority, octets without their leading zero."""
    return f"{priority:04x}." + ":".join(part.lstrip('0') or '0' for part in mac.split(':'))


def _link(name, kind=None, master=None, up=True, mac="02:00:00:00:00:01", info_data=None, slave=None):
    link = {"ifindex": 1, "ifname": name, "flags": ["BROADCAST", "MULTICAST"] + (["UP", "LOWER_UP"] if up else []),
            "mtu": 1500, "link_type": "ether", "address": mac}
    if master:
        link["master"] = master
    linkinfo = {}
    if kind:
        linkinfo["info_kind"] = kind
        if info_data is not None:
            linkinfo["info_data"] = info_data
    if slave is not None:
        linkinfo["info_slave_kind"] = "bridge"
        linkinfo["info_slave_data"] = slave
    if linkinfo:
        link["linkinfo"] = linkinfo
    return link


def _bridge_data(mac, stp=1, priority=0, root_priority=0, root_mac=None, root_port=0, ageing=3000):
    root_mac = mac if root_mac is None else root_mac
    return {"forward_delay": 1500, "hello_time": 200, "max_age": 2000, "ageing_time": ageing, "stp_state": stp,
            "priority": priority, "vlan_filtering": 0, "bridge_id": _bridge_id(priority, mac),
            "root_id": _bridge_id(root_priority, root_mac), "root_port": root_port, "root_path_cost": 0 if root_port == 0 else 2,
            "topology_change": 0}


def _port_data(no, state, bridge_id, root_id):
    return {"state": state, "priority": 32, "cost": 2, "id": f"0x80{no:02x}", "no": f"0x{no:x}",
            "designated_port": 0x8000 + no, "designated_cost": 0, "bridge_id": bridge_id, "root_id": root_id}


def _links_b1(d, stp=True, root=True, ports=('eth0', 'eth1'), ageing=3000, states=('forwarding', 'forwarding')):
    br_mac = min(_mac(d.macs.b1_eth0), _mac(d.macs.b1_eth1))
    b2_mac = min(_mac(d.macs.b2_eth0), _mac(d.macs.b2_eth1))
    if root:
        info = _bridge_data(br_mac, stp=int(stp), priority=0, root_priority=0, root_mac=br_mac, ageing=ageing)
    else:
        info = _bridge_data(br_mac, stp=int(stp), priority=32768, root_priority=4096, root_mac=b2_mac, root_port=1, ageing=ageing)
    links = [_link('lo', 'loopback'), _link('br0', 'bridge', mac=br_mac, info_data=info)]
    for i, (name, mac) in enumerate((('eth0', _mac(d.macs.b1_eth0)), ('eth1', _mac(d.macs.b1_eth1)))):
        if name in ports:
            links.append(_link(name, 'tun', master='br0', mac=mac,
                               slave=_port_data(i + 1, states[i], info['bridge_id'], info['root_id'])))
        else:
            links.append(_link(name, 'tun', mac=mac))
    return links


def _links_stp(d, machine, priority, root_machine, root_priority, blocked=None, stp=True):
    """The bridge br0 of *machine* (b2 or b3) in the STP segment: root id of *root_machine*,
    *blocked* port blocking, the other forwarding."""
    own = min(_mac(getattr(d.macs, machine + '_eth0')), _mac(getattr(d.macs, machine + '_eth1')))
    root = min(_mac(getattr(d.macs, root_machine + '_eth0')), _mac(getattr(d.macs, root_machine + '_eth1')))
    is_root = root_machine == machine
    info = _bridge_data(own, stp=int(stp), priority=priority, root_priority=root_priority, root_mac=root,
                        root_port=0 if is_root else 1, ageing=30000)
    links = [_link('lo', 'loopback'), _link('br0', 'bridge', mac=own, info_data=info)]
    for i, name in enumerate(('eth0', 'eth1')):
        state = 'blocking' if name == blocked else 'forwarding'
        links.append(_link(name, 'tun', master='br0', mac=_mac(getattr(d.macs, f'{machine}_{name}')),
                           slave=_port_data(i + 1, state, info['bridge_id'], info['root_id'])))
    return links


def _stp_links_done(lab, d, machine):
    """After `final`: the first root keeps the default priority and blocks eth1, the other one is
    the root with the lowered priority."""
    first_root, final_root = lab.stp_roots(d)
    if machine == final_root:
        return _links_stp(d, machine, lab.ROOT_PRIORITY, final_root, lab.ROOT_PRIORITY)
    return _links_stp(d, machine, lab.DEFAULT_PRIORITY, final_root, lab.ROOT_PRIORITY, blocked='eth1')


def _links_nothing(d, machine):
    if machine in ('b1', 'b2', 'b3'):
        key = machine + '_eth'
        return [_link('lo', 'loopback'), _link('eth0', 'tun', up=False, mac=_mac(getattr(d.macs, key + '0'))),
                _link('eth1', 'tun', up=False, mac=_mac(getattr(d.macs, key + '1')))]
    return [_link('lo', 'loopback'), _link('eth0', 'tun')]


def _fdb(d, entries):
    """bridge -j fdb show br br0: the permanent entries of the ports plus the learned ones."""
    out = []
    for port, mac in (('eth0', d.macs.b1_eth0), ('eth1', d.macs.b1_eth1)):
        out.append({"mac": _mac(mac), "ifname": port, "master": "br0", "flags": [], "state": "permanent"})
        out.append({"mac": _mac(mac), "ifname": port, "vlan": 1, "master": "br0", "flags": [], "state": "permanent"})
    for mac, port in entries:
        out.append({"mac": _mac(mac), "ifname": port, "master": "br0", "flags": [], "state": ""})
    return json.dumps(out)


def _addr(name, *addresses):
    return {"ifindex": 1, "ifname": name, "flags": ["UP"],
            "addr_info": [{"family": "inet", "local": str(a).split('/')[0], "prefixlen": int(str(a).split('/')[1]),
                           "scope": "global", "label": name} for a in addresses]}


def _nft_done(lab, d):
    return f"""table ip nat {{
	chain POSTROUTING {{
		type nat hook postrouting priority srcnat; policy accept;
	}}
}}
table bridge {lab.FILTER_TABLE} {{
	chain {lab.FILTER_CHAIN} {{
		type filter hook forward priority filter; policy accept;
		ether saddr {_mac(d.macs.m2)} ether daddr {_mac(d.macs.gw_lan)} counter packets 4 bytes 392 drop
	}}
}}
"""


def _ping_ok(ip):
    return f"PING {ip} ({ip}) 56(84) bytes of data.\n64 bytes from {ip}: icmp_seq=1 ttl=64 time=0.3 ms\n", 0


def _ping_ko(ip):
    return f"PING {ip} ({ip}) 56(84) bytes of data.\n\n--- {ip} ping statistics ---\n2 packets transmitted, 0 received, 100% packet loss, time 1012ms\n", 1


def _synthetic(lab, ns, machine, command):
    """(output, code) of *command* on *machine* in a project where everything is done."""
    d = ns.data
    if command == 'ip -j -d link show':
        if machine == 'b1':
            return json.dumps(_links_b1(d)), 0
        if machine in lab.STP_BRIDGES:
            return json.dumps(_stp_links_done(lab, d, machine)), 0
        return json.dumps(_links_nothing(d, machine)), 0
    if command.startswith('bridge -j fdb show br'):
        return _fdb(d, [(d.macs.m1, 'eth0'), (d.macs.gw_lan, 'eth0'), (d.macs.m2, 'eth1'), (d.macs.m3, 'eth1')]), 0
    if command.startswith('ip -j -4 addr show'):
        if machine == 'b1':
            return json.dumps([_addr('lo'), _addr('eth0'), _addr('eth1'), _addr('br0', d.ips.b1)]), 0
        return json.dumps([_addr('eth0', getattr(d.ips, machine, d.ips.ext1))]), 0
    if command == 'ip route':
        if machine == 'b1':
            return f"default via {_ip(d.ips.gw_lan)} dev br0\n{d.nets.lan} dev br0 proto kernel scope link src {_ip(d.ips.b1)}\n", 0
        return "", 0
    if command == 'nft list ruleset':
        return (_nft_done(lab, d) if machine == 'b1' else ""), 0
    if lab.PING in command:
        ip = command.split()[-1]
        if machine == 'm2' and ip == _ip(d.ips.ext1):
            return _ping_ko(ip)
        return _ping_ok(ip)
    return "", 0


def _nothing(lab, ns, machine, command):
    """(output, code) right after the initial state."""
    d = ns.data
    if command == 'ip -j -d link show':
        return json.dumps(_links_nothing(d, machine)), 0
    if command.startswith('bridge -j fdb show br'):
        return "", 1
    if command.startswith('ip -j -4 addr show'):
        if machine == 'b1':
            return json.dumps([_addr('lo'), _addr('eth0'), _addr('eth1')]), 0
        return json.dumps([_addr('eth0', getattr(d.ips, machine, d.ips.ext1))]), 0
    if command == 'ip route':
        return "", 0
    if command == 'nft list ruleset':
        return "", 0
    if lab.PING in command:
        ip = command.split()[-1]
        side = {'m1': 's1', 'gw': 's1', 'm2': 's2', 'm3': 's2', 'm4': 's3'}
        dest_side = {_ip(d.ips.m1): 's1', _ip(d.ips.gw_lan): 's1', _ip(d.ips.ext1): 's1', _ip(d.ips.m2): 's2',
                     _ip(d.ips.m3): 's2', _ip(d.ips.m4): 's3'}
        if machine in side and ip in dest_side and side[machine] == dest_side[ip]:
            return _ping_ok(ip)
        return _ping_ko(ip)
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
    nets = (d.nets.lan, d.nets.ext)
    assert len(set(nets)) == 2 and all(n.prefixlen == 24 and n.is_private for n in nets)
    assert set(vars(d.nets)) == {'lan', 'ext'}
    for key in ('m1', 'm2', 'm3', 'm4', 'b1', 'gw_lan'):
        assert getattr(d.ips, key) in d.nets.lan and int(_ip(getattr(d.ips, key)).split('.')[-1]) == lab.HOST_PARTS[key]
    assert d.ips.gw_ext in d.nets.ext and d.ips.ext1 in d.nets.ext and _ip(d.ips.b1).endswith('.110')
    assert _ip(d.ips.m4).endswith('.4') and not hasattr(d.ips, 'm5')
    macs = [_mac(getattr(d.macs, key)) for key in sorted(set(lab.MAC_KEYS.values()))]
    assert len(macs) == 11 and len(set(macs)) == 11
    assert all(m.startswith('02:53:52:') and int(m[:2], 16) % 2 == 0 for m in macs)   # unicast, locally administered
    assert lab.bridge_mac(d) == min(_mac(d.macs.b1_eth0), _mac(d.macs.b1_eth1))
    first_root, final_root = lab.stp_roots(d)
    assert {first_root, final_root} == {'b2', 'b3'} and lab.bridge_mac(d, first_root) < lab.bridge_mac(d, final_root)
    js = d.to_json()
    assert lab.Data.from_json(js).to_json() == js and lab.Data.unpack(d.pack()).to_json() == js
    assert _mac(lab.Data.from_json(js).macs.m3) == _mac(d.macs.m3)


def test_b1_gets_the_highest_macs(lab):
    """b1 is on s1 with b2 and b3: a student turning its STP on must not make it the root, so its
    two MACs are the highest of the instance (equal priorities: the lowest bridge MAC wins)."""
    others = [key for key in set(lab.MAC_KEYS.values()) if key not in lab.B1_MAC_KEYS]
    assert set(lab.B1_MAC_KEYS) == {'b1_eth0', 'b1_eth1'} and len(others) == 9
    lowest_b1 = set()
    for _ in range(8):
        d = lab.Data.generate()
        assert min(int(d.macs.b1_eth0), int(d.macs.b1_eth1)) > max(int(getattr(d.macs, key)) for key in others)
        assert set(lab.stp_roots(d)) == {'b2', 'b3'}
        lowest_b1.add('eth0' if int(d.macs.b1_eth0) < int(d.macs.b1_eth1) else 'eth1')
        d2 = lab.Data.from_json(d.to_json())
        assert int(d2.macs.b1_eth0) == int(d.macs.b1_eth0) and lab.bridge_mac(d2) == lab.bridge_mac(d)
    assert lowest_b1 == {'eth0', 'eth1'}      # which port gives br0 its MAC stays random


def test_fixed_flavor_uses_the_handout_network(lab):
    for flavor in (lab.Flavor(ip_choice='fixed'), lab.Flavor.fixed, lab.Flavor.from_form_dict({'ip_choice': 'fixed'})):
        d = lab.Data.generate(flavor=flavor)
        assert (str(d.nets.lan), str(d.nets.ext)) == ('192.168.1.0/24', '10.10.10.0/24')
        assert str(d.ips.m4) == '192.168.1.4/24'
        assert str(d.ips.b1) == '192.168.1.110/24' and str(d.ips.gw_lan) == '192.168.1.254/24'
        assert str(d.ips.ext1) == '10.10.10.51/24' and str(d.ips.m2) == '192.168.1.2/24'
    assert lab.flavor_form_at_startup and 'ip_choice' in _text(lab.Flavor.flavor_form)
    assert lab.Flavor.random.ip_choice == 'random' and lab.Flavor().ip_choice == 'random'


def test_topology_and_machines(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    assert set(ns.get_machine_names()) == {'b1', 'b2', 'b3', 'gw', 'm1', 'm2', 'm3', 'm4', 'ext1'}
    assert set(ns.get_visible_machine_names()) == set(ns.get_machine_names())   # no hidden machine
    ifaces = ns.host_interfaces_from_topology()
    assert ifaces['b1'] == ['s1', 's2'] and sorted(ifaces['b2']) == ['s1', 's3'] and sorted(ifaces['b3']) == ['s1', 's3']
    assert ifaces['gw'] == ['s1', 'ext'] and ifaces['m4'] == ['s3'] and ifaces['m1'] == ['s1']
    assert set(lab._TOPOLOGY) == {'s1', 's2', 'ext', 's3'}
    for net in ('s1', 's2', 'ext', 's3'):
        assert ns.get_network(net).mode == 'switch'
    assert all(ns.get_machine(m).allow_connection for m in ('b1', 'b2', 'b3'))
    topology = ns._topology
    assert topology['s1']['b1'] == (0, data.macs.b1_eth0) and topology['s2']['b1'] == (1, data.macs.b1_eth1)
    assert topology['s2']['m3'] == (0, data.macs.m3) and topology['ext'] == {'gw': 1, 'ext1': 0}
    # eth0 of b2 / b3 on s3 (the m4 side), eth1 on s1: the non-root bridge blocks its eth1
    assert topology['s3']['b3'] == (0, data.macs.b3_eth0) and topology['s1']['b2'] == (1, data.macs.b2_eth1)
    assert topology['s1']['b3'] == (1, data.macs.b3_eth1) and topology['s3']['m4'] == (0, data.macs.m4)
    states = [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    assert not any(getattr(lab.NetScheme, name)._sre_state_user_allowed for name in states)   # nothing to apply
    adapters = {(a.machine.name, a.network.name): a for a in ns.get_net_adapters()} if hasattr(ns, 'get_net_adapters') else {}
    if adapters:
        assert str(adapters[('m3', 's2')].mac).lower().replace('-', ':') == _mac(data.macs.m3)
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
        forward = 'ip_forward=1' if m == 'gw' else 'ip_forward=0'
        assert any(forward in c for c in cmds), m
        files = _files(ops, 1, m)
        assert files['/etc/resolv.conf'] == ""
        hosts = files['/etc/hosts']
        assert f"{_ip(d.ips.ext1)}\t\text1.lab\text1" in hosts and f"{_ip(d.ips.b1)}\t\tb1.lab\tb1" in hosts
        assert f"{_ip(d.ips.gw_lan)}\t\tgw.lab\tgw" in hosts and f"127.0.1.1\t{m}" in hosts
    for m in ('m1', 'm2', 'm3', 'm4'):
        assert f"ip address add {getattr(d.ips, m)} dev eth0" in _cmds(ops, 1, m)
        assert f"ip route add default via {_ip(d.ips.gw_lan)}" in _cmds(ops, 1, m)
    assert f"ip address add {d.ips.gw_lan} dev eth0" in _cmds(ops, 1, 'gw')
    assert any(f"ip address add {d.ips.gw_ext} dev eth1" in c for c in _cmds(ops, 1, 'gw'))
    assert f"ip route add default via {_ip(d.ips.gw_ext)}" in _cmds(ops, 1, 'ext1')
    hosts = _files(ops, 1, 'm4')['/etc/hosts']
    assert f"{_ip(d.ips.m4)}\t\tm4.lab\tm4" in hosts and 'm5' not in hosts
    for m in ('b1', 'b2', 'b3'):
        assert "ip link set eth0 down; ip link set eth1 down" in _cmds(ops, 1, m)
        assert not any('br0' in c or 'nft' in c or 'ip address add' in c for c in _cmds(ops, 1, m))
    for m in ('b2', 'b3'):
        for dev in ('eth0', 'eth1'):
            assert f"tc qdisc replace dev {dev} root tbf rate {lab.STORM_CAP_RATE} burst 32kbit latency 50ms" in _cmds(ops, 1, m)
    assert lab.STORM_CAP_RATE == '1mbit'     # measured live: 3 000 to 4 000 frames/s per machine during a storm, host load < 2
    assert not any('tc qdisc' in c for c in _cmds(ops, 1, 'b1'))
    # the echo servers (HTTP 80 / 8080, UDP 530 / 630) on every machine but the bridges
    assert set(lab.SERVER_MACHINES) == set(ns.get_machine_names()) - {'b1', 'b2', 'b3'}
    for m in lab.SERVER_MACHINES:
        script = _files(ops, 1, m)['/usr/local/sbin/sre_server_echo.py']
        assert 'def serve_udp' in script and 'def parse_syn' in script
        assert any(c.endswith(f"sre_server_echo.py {m} 80 8080 udp:530 udp:630'") for c in _cmds(ops, 1, m)), m
    for m in ('b1', 'b2', 'b3'):
        assert '/usr/local/sbin/sre_server_echo.py' not in _files(ops, 1, m)
        assert not any('sre_server_echo' in c for c in _cmds(ops, 1, m))


def test_final_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'final')
    d = data
    b1 = _cmds(ops, 1, 'b1')
    assert b1[0].startswith("ip link del br0 2>/dev/null; nft delete table bridge filter 2>/dev/null")
    for c in ("ip link set eth0 up", "ip link set eth1 up", "ip link add br0 type bridge", "ip link set eth0 master br0",
              "ip link set eth1 master br0", "ip link set br0 up", "ip link set br0 type bridge ageing_time 3000",
              f"ip address add {d.ips.b1} dev br0", f"ip route replace default via {_ip(d.ips.gw_lan)}"):
        assert c in b1, c
    assert not any('stp_state' in c or 'type bridge priority' in c for c in b1)   # b1 never runs STP
    assert any(c.startswith("nft 'add chain bridge filter forward { type filter hook forward") for c in b1)
    assert f"nft add rule bridge filter forward ether saddr {_mac(d.macs.m2)} ether daddr {_mac(d.macs.gw_lan)} drop" in b1
    first_root, final_root = lab.stp_roots(d)
    for m in ('b2', 'b3'):
        cmds = _cmds(ops, 1, m)
        assert cmds[0] == "ip link del br0 2>/dev/null; true"
        assert cmds[1:7] == ["ip link set eth0 up", "ip link set eth1 up", "ip link add br0 type bridge stp_state 1",
                             "ip link set eth0 master br0", "ip link set eth1 master br0", "ip link set br0 up"]
    assert _cmds(ops, 1, final_root)[-1] == f"ip link set br0 type bridge priority {lab.ROOT_PRIORITY}"
    assert len(_cmds(ops, 1, first_root)) == 7
    for name in ('initial', 'final'):
        assert not getattr(lab.NetScheme, name)._sre_state_user_allowed


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _nothing, cheat=False)
    grades = _grades(grade)
    assert sum(g for g, _ in grades.values()) == 0, {k: v for k, v in grades.items() if v[0]}
    assert sum(mx for _, mx in grades.values()) == 100 and len(grades) == 24
    assert [str(p.title) for p in grade._grade_parts] == [f'part{i}' for i in range(1, 7)]


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _synthetic)
    grades = _grades(grade)
    short = {k: v for k, v in grades.items() if v[0] != v[1]}
    assert not short, short
    assert sum(g for g, _ in grades.values()) == 100
    tests = grade.get_tests()
    assert grade.max_step == 2
    fdb = [c for c, _ in tests[('b1', 2)]]
    assert fdb == ['bridge -j fdb show br br0']              # the MAC table is read after the pings
    pings = [(m, c) for (m, s), cmds in tests.items() for c, _ in cmds if lab.PING in c]
    assert len(pings) == 12 and all(s == 1 for (m, s) in tests if m != 'b1' or s == 1)
    assert ('m2', f"{lab.PING} {_ip(ns.data.ips.ext1)}") in pings
    for src, dest in (('m4', ns.data.ips.m1), ('m1', ns.data.ips.m4), ('m4', ns.data.ips.ext1)):
        assert (src, f"ip neigh flush all; {lab.PING} {_ip(dest)}") in pings     # part 6: stale switch entries
    assert not any('flush' in c for m, c in pings if m not in ('m1', 'm4'))


def test_tampering_is_not_rewarded(lab, data, tmp_pub_dir):
    """The root never changed (both bridges at the default priority), a drop rule in another hook
    or about m3, the address on eth0: the right elements lose their points, nothing else."""
    d = data
    first_root, final_root = lab.stp_roots(d)

    def outputs(l, n, machine, command):
        if command == 'ip -j -d link show' and machine == first_root:
            return json.dumps(_links_stp(d, machine, l.DEFAULT_PRIORITY, first_root, l.DEFAULT_PRIORITY)), 0
        if command == 'ip -j -d link show' and machine == final_root:
            return json.dumps(_links_stp(d, machine, l.DEFAULT_PRIORITY, first_root, l.DEFAULT_PRIORITY, blocked='eth1')), 0
        if command == 'nft list ruleset' and machine == 'b1':
            text = _nft_done(l, d).replace('type filter hook forward', 'type filter hook input')
            return text.replace(_mac(d.macs.m2), _mac(d.macs.m3)), 0
        if command.startswith('ip -j -4 addr show') and machine == 'b1':
            return json.dumps([_addr('lo'), _addr('eth0', d.ips.b1), _addr('eth1'), _addr('br0')]), 0
        return _synthetic(l, n, machine, command)

    grades = _grades(_simulate(lab, data, tmp_pub_dir, outputs)[0])
    assert grades['stp_bridges'] == (4, 4) and grades['stp_connectivity'] == (4, 4)
    assert grades['new_root'] == (0, 7) and grades['old_root_blocks'] == (0, 5) and grades['q_blocked_port'] == (0, 3)
    assert grades['q_root_election'] == (3, 3) and grades['q_bpdu'] == (4, 4)
    assert grades['filter_rule'] == (0, 4) and grades['bridge_address'] == (0, 4)
    assert grades['filter_m2_blocked'] == (5, 5) and grades['bridged_connectivity'] == (6, 6)
    assert grades['ageing_time'] == (4, 4) and grades['fdb_learned'] == (5, 5)


def test_blocked_port_is_graded_against_the_live_state(lab, data, tmp_pub_dir):
    """A student who enslaved eth1 first on the new root sees eth0 of the old root blocking: the
    answer eth0 is right for them, eth1 (the cheat answer) is not."""
    d = data
    first_root, final_root = lab.stp_roots(d)

    def outputs(l, n, machine, command):
        if command == 'ip -j -d link show' and machine == first_root:
            return json.dumps(_links_stp(d, machine, l.DEFAULT_PRIORITY, final_root, l.ROOT_PRIORITY, blocked='eth0')), 0
        return _synthetic(l, n, machine, command)

    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    assert _grades(grade)['q_blocked_port'] == (0, 3) and _grades(grade)['old_root_blocks'] == (5, 5)
    q8 = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)][-1]
    answers = json.loads(grade._answers[q8.question_hash])
    answers['blocked_port'] = f"{first_root}_eth0"
    grade._answers[q8.question_hash] = json.dumps(answers)
    grade.reset_before_grade()
    grade.grade()
    assert _grades(grade)['q_blocked_port'] == (3, 3)


def test_partial_bridge_and_stp_off(lab, data, tmp_pub_dir):
    d = data

    def outputs(l, n, machine, command):
        if command == 'ip -j -d link show' and machine == 'b1':
            return json.dumps(_links_b1(d, stp=False, root=True, ports=('eth0',), ageing=30000, states=('forwarding', None))), 0
        if command == 'ip -j -d link show' and machine in ('b2', 'b3'):
            return json.dumps(_links_nothing(d, machine)), 0
        if l.PING in command and (machine == 'm4' or command.endswith(_ip(d.ips.m4))):
            return _ping_ko(command.split()[-1])
        return _synthetic(l, n, machine, command)

    grades = _grades(_simulate(lab, data, tmp_pub_dir, outputs)[0])
    assert grades['bridge_ports'] == (2, 4) and grades['ageing_time'] == (0, 4)
    for title in ('stp_bridges', 'stp_connectivity', 'new_root', 'old_root_blocks', 'q_blocked_port'):
        assert grades[title][0] == 0, title


def test_rule_by_ip_is_accepted(lab, data, tmp_pub_dir):
    d = data

    def outputs(l, n, machine, command):
        if command == 'nft list ruleset' and machine == 'b1':
            return f"""table bridge f {{
	chain fw {{
		type filter hook forward priority 0; policy accept;
		ip saddr {_ip(d.ips.m2)} ip daddr != {d.nets.lan} drop
	}}
}}
""", 0
        return _synthetic(l, n, machine, command)

    assert _grades(_simulate(lab, data, tmp_pub_dir, outputs)[0])['filter_rule'] == (4, 4)


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def test_texts_and_instructor_fragments(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _synthetic, instructor_mode=True)
    info = _text(ns.informations)
    assert info.count('\n## ') == 8 and 'ageing_time 3000' in info and '01:80:c2:00:00:00' in info
    assert str(data.nets.lan) not in info     # instance data belongs to the first question
    # the course is numbered by the lib/informations.py markers, resolved by save_lab_info()
    from SRE.informations import resolve_informations, resolve_text
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved)
    assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 9)]
    assert [s.tag for s in numbering.sections('fr')] == ['recap', 'transparent-bridge', 'linux-bridges', 'observing',
                                                         'filtering', 'stp', 'cheatsheet', 'plan']
    assert '## <a id="linux-bridges"></a>3. Les ponts sous Linux' in course and '- [6. Boucles, redondance et STP](#stp)' in course
    assert '@@' not in course
    questions = list(grade.get_questions_ordered())
    resolved_questions = [_text(resolve_text(q.description, numbering)) for q in questions]
    assert all('@@ref' not in q and '@@sec' not in q for q in resolved_questions)
    assert 'section 3 des Informations' in resolved_questions[2] and 'section 3 des Informations' in resolved_questions[5]
    assert 'section 5 des' in resolved_questions[6] and 'section 6 des Informations' in resolved_questions[8]
    assert len(questions) == 9
    with_instructor = [q for q in questions if has_instructor(_text(q.description))]
    assert len(with_instructor) == 9
    all_text = info + "".join(_text(q.description) for q in questions)
    assert "{'" not in all_text and not re.search(r"\{[a-z_0-9]+\}", all_text)
    first = _text(questions[0].description)
    for value in (data.nets.lan, data.nets.ext, data.ips.m2.ip, data.ips.b1.ip, data.ips.gw_ext.ip, data.ips.m4.ip):
        assert str(value) in first
    assert not re.search(r"\b(m5|lan2|s4)\b", all_text)       # the former independent segment
    for mac in (data.macs.m3, data.macs.gw_lan, data.macs.b3_eth1):
        assert _mac(mac) in first                      # for the instructor only
    assert f"ether saddr {_mac(data.macs.m2)} ether daddr {_mac(data.macs.gw_lan)} drop" in all_text
    first_root, final_root = lab.stp_roots(data)
    assert f"1000.{lab.bridge_mac(data, final_root)}" in all_text and f"8000.{lab.bridge_mac(data, first_root)}.8001" in all_text
    assert 'tc qdisc' in first and 'redundancy' not in all_text
    assert 'nc -u -w 1 m2 530' in course and 'curl http://m2:8080/' in course and 'ss -tulnp' in course
    assert 'section 4 des' in resolved_questions[0] and 'ports 530 et 630' in first
    for e in grade.get_grade_list():
        desc = _text(e.description)
        assert "{'" not in desc and not re.search(r"\{[a-z_]+\}", desc)
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, _synthetic, instructor_mode=False)
    student_text = _text(ns2.informations) + "".join(_text(q.description) for q in grade2.get_questions_ordered())
    assert not has_instructor(student_text) and 'Pour l\'enseignant' not in student_text
    for mac in (data.macs.m3, data.macs.gw_lan, data.macs.b1_eth0, data.macs.b2_eth0, data.macs.b3_eth1):
        assert _mac(mac) not in student_text           # the students read the MACs on the machines
    assert lab.stp_roots(data)[0] not in re.findall(r"racine est \*\*`(b[23])`", student_text)


def test_cheat_answers_fill_every_form(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _synthetic)
    cheat = grade.get_cheat_answers('final')
    forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
    assert len(forms) == 6
    for q in forms:
        answers = cheat[q.question_hash]
        answers = json.loads(answers) if isinstance(answers, str) else answers
        for field in q.fields:
            assert field['name'] in answers, field['name']
            if 'choices' in field:
                assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])
            elif 'regex' in field:
                assert re.fullmatch(field['regex'], answers[field['name']]), (field['name'], answers[field['name']])


def test_priority_answers(lab):
    assert lab._is_priority('4096', 4096) and lab._is_priority('0x1000', 4096) and lab._is_priority('1000', 4096)
    assert not lab._is_priority('4095', 4096) and not lab._is_priority('', 4096) and not lab._is_priority('abcd', 4096)
    assert lab._is_priority('32768', 32768) and lab._is_priority('8000', 32768)
    assert lab._same_mac('02-53-52-0A-0B-0C', '02:53:52:0a:0b:0c') and not lab._same_mac('', '')
    assert lab._float_in('0,35', 0, 1000) and lab._float_in(' 2 ms', 1.99, 2.01) and not lab._float_in('x', 0, 1)


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'bridge_stripped', 'exec')


def test_english_identifiers(lab, data):
    """Machines, networks, states, data fields, grade elements and part keys are English (tr() texts are French)."""
    french = re.compile(r'(routeur|pont|reseau|serveur|sonde|panne|exemple|reponse|commutateur|passerelle|'
                        r'machine_|_machine|exterieur|filtre|racine)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.NetScheme._network_specs)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += list(vars(data.ips)) + list(vars(data.nets)) + list(vars(data.macs)) + list(lab.STP_BRIDGES)
    names += [f.name for f in lab.Flavor.__dataclass_fields__.values()]
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade._grade_parts]
    for q in grade.get_questions_ordered():
        names += [f['name'] for f in getattr(q, 'fields', None) or []]
    bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
    assert not bad, bad
