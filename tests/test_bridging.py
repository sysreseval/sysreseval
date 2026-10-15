"""Tests for lib/bridging.py (fixtures captured on 2026-10-09 in the running VLAN
lab after its `final` state: sysreseval/base:1.30, iproute2 6.19, nftables 1.0.6, iptables 1.8.9
nft, Linux 6.12; tests/mock_data/vlan/)."""
import json
import sys
from ipaddress import IPv4Interface
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from switch import get_switch_ports  # noqa: E402
from bridging import (  # noqa: E402
    MANGLE_RULES_CMD, addresses_of, bridge_ports, broute_rules_for, get_broute_rules, get_ip_links, get_mangle_rules,
    get_sysctl_int, interface_of_address, link_address, link_master, link_up, links_by_name, parse_broute_rules,
    parse_ip_addr_json, parse_ip_links_json, parse_iptables_save, rule_diverts, ttl_rules, vlan_links,
)

MOCK = Path(__file__).parent / 'mock_data' / 'vlan'
BRODD_MAC = "1a:0a:93:41:14:f3"


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    """Grade mock whose grade.test(machine, command, ...) and test_switch(network, command, ...)
    dispatch by command."""
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 1))

    grade.test.side_effect = _test
    grade.test_switch.side_effect = _test
    return grade


# ---------------------------------------------------------------------------
# ip link / ip addr
# ---------------------------------------------------------------------------


def test_vlan_links_and_bridges_of_b2():
    links = parse_ip_links_json(fixture('ip_link_b2.json'))
    assert set(links_by_name(links)) == {'lo', 'eth0', 'eth0.111', 'eth0.222', 'eth1', 'eth2', 'brodd', 'breven'}
    assert vlan_links(links) == {'eth0.111': {'id': 111, 'link': 'eth0', 'up': True, 'master': 'brodd'},
                                 'eth0.222': {'id': 222, 'link': 'eth0', 'up': True, 'master': 'breven'}}
    assert bridge_ports(links) == {'breven': ['eth0.222', 'eth2'], 'brodd': ['eth0.111', 'eth1']}
    assert link_master(links, 'eth1') == 'brodd' and link_master(links, 'eth0') is None and link_master(links, 'x') is None
    assert link_up(links, 'brodd') and not link_up(links, 'nope')
    assert link_address(links, 'brodd') == BRODD_MAC and link_address(links, 'nope') == ''


def test_links_of_a_router_and_of_a_plain_host():
    router = parse_ip_links_json(fixture('ip_link_router.json'))
    assert {name: info['id'] for name, info in vlan_links(router).items()} == {'eth1.111': 111, 'eth1.222': 222}
    assert all(info['master'] is None and info['link'] == 'eth1' for info in vlan_links(router).values())
    assert bridge_ports(router) == {}
    m7 = parse_ip_links_json(fixture('ip_link_m7.json'))
    assert vlan_links(m7) == {} and bridge_ports(m7) == {} and link_up(m7, 'eth0')
    assert vlan_links(parse_ip_links_json("garbage")) == {}


def test_get_ip_links_wrapper():
    grade = make_grade({"ip -j -d link show": (fixture('ip_link_m7.json'), 0)})
    assert [l['ifname'] for l in get_ip_links(grade, 'm7')] == ['lo', 'eth0']
    assert get_ip_links(make_grade({}), 'm7') == []


def test_addresses_of_b2_and_router():
    addrs = parse_ip_addr_json(fixture('ip_addr_b2.json'))
    assert addresses_of(addrs, 'brodd') == ['192.168.100.102/24'] and addresses_of(addrs, 'eth0') == ['10.144.153.102/24']
    assert addresses_of(addrs, 'eth0.111') == [] and interface_of_address(addrs, '192.168.100.102') == 'brodd'
    router = parse_ip_addr_json(fixture('ip_addr_router.json'))
    assert interface_of_address(router, IPv4Interface('192.168.100.254/24')) == 'eth1.111'
    assert interface_of_address(router, '10.194.28.254') == 'eth1.222'


# ---------------------------------------------------------------------------
# nftables bridge family
# ---------------------------------------------------------------------------


def test_parse_broute_rules_of_the_lab():
    rules = parse_broute_rules(fixture('nft_ruleset_b2.txt'))
    assert len(rules) == 2    # the ip nat (Docker) and ip mangle (iptables) tables are ignored
    m3, web = rules
    assert (m3['table'], m3['chain'], m3['hook'], m3['iif']) == ('brouter', 'prerouting', 'prerouting', 'eth1')
    assert m3['saddr'] == '192.168.100.3' and m3['daddr'] is None and m3['dport'] is None and m3['l4proto'] is None
    assert m3['pkttype_host'] and m3['daddr_mac'] == BRODD_MAC and not m3['broute'] and rule_diverts(m3)
    assert web['daddr'] == '10.193.51.52' and web['l4proto'] == 'tcp' and web['dport'] == 8080 and web['saddr'] is None
    assert web['text'].startswith('iifname "eth1" ip daddr 10.193.51.52 tcp dport 8080')
    assert parse_broute_rules(fixture('nft_ruleset_router.txt')) == []
    assert parse_broute_rules("") == [] and parse_broute_rules(None) == []


def test_broute_rules_for():
    rules = parse_broute_rules(fixture('nft_ruleset_b2.txt'))
    assert broute_rules_for(rules, src='192.168.100.3') == [rules[0]]
    assert broute_rules_for(rules, src=IPv4Interface('192.168.100.3/24')) == [rules[0]]
    assert broute_rules_for(rules, src='192.168.100.5') == []
    assert broute_rules_for(rules, dst='10.193.51.52', dport=8080) == [rules[1]]
    assert broute_rules_for(rules, dst='10.193.51.52', dport=80) == []
    assert broute_rules_for(rules, dst='10.193.51.51') == []
    assert len(broute_rules_for(rules)) == 2


def test_broute_rule_variants():
    text = """table bridge br {
	chain pre {
		type filter hook prerouting priority -300; policy accept;
		iif "eth1" ip saddr 192.168.100.0/24 meta broute set 1
		ip saddr 192.168.100.3 meta pkttype set host
		ip saddr 192.168.100.3 ether daddr set 1A:0A:93:41:14:F3
		ip saddr 192.168.100.9 counter accept
	}
}
"""
    rules = parse_broute_rules(text)
    assert [r['saddr'] for r in rules] == ['192.168.100.0/24', '192.168.100.3', '192.168.100.3']
    assert rules[0]['broute'] and rules[0]['iif'] == 'eth1' and rule_diverts(rules[0])
    assert not rule_diverts(rules[1]) and not rule_diverts(rules[2]) and rules[2]['daddr_mac'] == BRODD_MAC
    assert broute_rules_for(rules, src='192.168.100.42') == [rules[0]]      # the prefix covers it
    assert broute_rules_for(rules, src='192.168.100.3') == [rules[0]]
    assert len(broute_rules_for(rules, src='192.168.100.3', diverting=False)) == 3


def test_get_broute_rules_wrapper():
    grade = make_grade({"nft list ruleset": (fixture('nft_ruleset_b2.txt'), 0)})
    assert [r['dport'] for r in get_broute_rules(grade, 'b2')] == [None, 8080]
    assert get_broute_rules(make_grade({}), 'b2') == []


# ---------------------------------------------------------------------------
# iptables mangle
# ---------------------------------------------------------------------------


def test_parse_iptables_save_and_ttl_rules():
    rules = parse_iptables_save(fixture('iptables_mangle_b2.txt'))
    assert len(rules) == 1 and rules[0]['chain'] == 'PREROUTING' and rules[0]['src'] == '192.168.100.3/32'
    assert rules[0]['target'] == 'TTL' and rules[0]['args'] == ['--ttl-inc', '1']
    ttl = ttl_rules(rules)
    assert len(ttl) == 1 and (ttl[0]['op'], ttl[0]['value']) == ('inc', 1)
    more = parse_iptables_save("-A FORWARD -i eth1 -o eth0 -p tcp -m tcp --dport 8080 -j TTL --ttl-set 64\n"
                               "-A PREROUTING ! -s 10.0.0.0/8 -j ACCEPT\n")
    assert more[0]['in'] == 'eth1' and more[0]['out'] == 'eth0' and more[0]['proto'] == 'tcp'
    assert more[0]['args'] == ['-m', 'tcp', '--dport', '8080', '--ttl-set', '64']
    assert ttl_rules(more)[0]['op'] == 'set' and ttl_rules(more)[0]['value'] == 64
    assert more[1]['src'] == '10.0.0.0/8' and more[1]['target'] == 'ACCEPT' and ttl_rules(more[1:]) == []
    assert parse_iptables_save("") == []


def test_get_mangle_rules_wrapper():
    grade = make_grade({MANGLE_RULES_CMD: (fixture('iptables_mangle_b2.txt'), 0)})
    assert ttl_rules(get_mangle_rules(grade, 'b2'))[0]['value'] == 1
    assert get_mangle_rules(make_grade({}), 'b2') == []


# ---------------------------------------------------------------------------
# /proc/sys and the switch of the lab
# ---------------------------------------------------------------------------


def test_get_sysctl_int():
    grade = make_grade({"cat /proc/sys/net/ipv4/ip_default_ttl": ("90\n", 0), "cat /proc/sys/net/ipv4/ip_forward": ("x", 0)})
    assert get_sysctl_int(grade, 'm5', 'net.ipv4.ip_default_ttl') == 90
    assert get_sysctl_int(grade, 'm5', 'net.ipv4.ip_forward') is None
    assert get_sysctl_int(grade, 'm5', 'net.ipv4.conf.all.rp_filter') is None


def test_switch_fixtures_of_the_lab():
    grade = make_grade({"port/allprint": (fixture('port_allprint.txt'), 0), "vlan/allprint": (fixture('vlan_allprint.txt'), 0)})
    ports = get_switch_ports(grade, 'trunk')
    assert ports['m7'] == {'port': 5, 'interface': 'eth0', 'vlan': 111, 'tagged_vlans': []}
    assert ports['b1'] == {'port': 2, 'interface': 'eth0', 'vlan': 0, 'tagged_vlans': [111, 222]}
    assert ports['router2'] == {'port': 4, 'interface': 'eth1', 'vlan': 0, 'tagged_vlans': [111, 222]}


def test_tcpdump_fixtures_show_the_tag_on_eth0_only():
    tagged, sub = fixture('tcpdump_e_eth0_tagged.txt'), fixture('tcpdump_e_eth0_111.txt')
    assert 'ethertype 802.1Q (0x8100), length 102: vlan 111, p 0, ethertype IPv4 (0x0800)' in tagged
    assert '802.1Q' not in sub and 'ethertype IPv4 (0x0800), length 98' in sub


# ---------------------------------------------------------------------------
# bridges and STP (ip -j -d link), fdb, nft bridge family filtering
# ---------------------------------------------------------------------------

from bridging import (  # noqa: E402
    bridge_info, drop_rules_for, fdb_cmd, fdb_port_of, get_bridge_rules, get_fdb, learned_fdb_entries, normalize_mac,
    parse_bridge_id, parse_bridge_rules, parse_fdb_json, port_states,
)

_STP_LINKS = [
    {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP"], "link_type": "loopback", "address": "00:00:00:00:00:00"},
    {"ifindex": 5, "ifname": "br0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "link_type": "ether",
     "address": "02:53:52:0a:0b:0c",
     "linkinfo": {"info_kind": "bridge", "info_data": {
         "forward_delay": 1500, "hello_time": 200, "max_age": 2000, "ageing_time": 3000, "stp_state": 1,
         "priority": 32768, "bridge_id": "8000.2:53:52:a:b:c", "root_id": "1000.2:53:52:1:2:3", "root_port": 1,
         "root_path_cost": 2, "topology_change": 0}}},
    {"ifindex": 2, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "master": "br0",
     "link_type": "ether", "address": "02:53:52:0a:0b:0c",
     "linkinfo": {"info_kind": "tun", "info_slave_kind": "bridge", "info_slave_data": {
         "state": "forwarding", "priority": 32, "cost": 2, "id": "0x8001", "no": "0x1", "designated_port": 32769,
         "designated_cost": 0, "bridge_id": "1000.2:53:52:1:2:3", "root_id": "1000.2:53:52:1:2:3"}}},
    {"ifindex": 3, "ifname": "eth1", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "master": "br0",
     "link_type": "ether", "address": "02:53:52:0d:0e:0f",
     "linkinfo": {"info_kind": "tun", "info_slave_kind": "bridge", "info_slave_data": {
         "state": "blocking", "priority": 32, "cost": 2, "id": "0x8002", "no": "0x2", "designated_port": 32770,
         "designated_cost": 0, "bridge_id": "1000.2:53:52:1:2:3", "root_id": "1000.2:53:52:1:2:3"}}},
]

_FDB = json.dumps([
    {"mac": "02:53:52:0a:0b:0c", "ifname": "eth0", "master": "br0", "flags": [], "state": "permanent"},
    {"mac": "02:53:52:0a:0b:0c", "ifname": "eth0", "vlan": 1, "master": "br0", "flags": [], "state": "permanent"},
    {"mac": "02:53:52:00:00:01", "ifname": "eth0", "master": "br0", "flags": [], "state": ""},
    {"mac": "02:53:52:00:00:03", "ifname": "eth1", "master": "br0", "flags": [], "state": ""},
    {"mac": "02:53:52:00:00:09", "ifname": "eth1", "master": "br0", "flags": [], "state": "stale"},
    {"mac": "33:33:00:00:00:01", "ifname": "eth0", "flags": ["self"], "state": "permanent"},
])

_FILTER_RULESET = """table ip nat {
	chain OUTPUT {
		type nat hook output priority -100; policy accept;
		ip daddr 127.0.0.11 counter packets 0 bytes 0 jump DOCKER_OUTPUT
	}
}
table bridge filter {
	chain forward {
		type filter hook forward priority filter; policy accept;
		ether saddr 02:53:52:00:00:02 ether daddr 02:53:52:00:00:fe counter packets 4 bytes 392 drop
		ip saddr 192.168.1.2 ip daddr != 192.168.1.0/24 drop
		iifname "eth1" ip saddr 192.168.1.0/24 tcp dport 80 accept
		ether saddr 02:53:52:00:00:03 reject with icmp type admin-prohibited
	}
	chain input {
		type filter hook input priority filter; policy accept;
		ip saddr 192.168.1.2 drop
	}
}
"""


def test_normalize_mac_and_bridge_id():
    assert normalize_mac('02-53-52-0A-0B-0C') == '02:53:52:0a:0b:0c' and normalize_mac('2:53:52:a:b:c') == '02:53:52:0a:0b:0c'
    assert normalize_mac('') == '' and normalize_mac('02:53:52') == '' and normalize_mac(None) == ''
    assert parse_bridge_id('8000.1a:a:93:41:14:f3') == (32768, '1a:0a:93:41:14:f3')
    assert parse_bridge_id('1000.02:53:52:aa:bb:cc') == (4096, '02:53:52:aa:bb:cc')
    assert parse_bridge_id('0000.02:53:52:aa:bb:cc') == (0, '02:53:52:aa:bb:cc')
    assert parse_bridge_id('') == (None, '') and parse_bridge_id('8000') == (None, '') and parse_bridge_id(None) == (None, '')


def test_bridge_info_of_a_non_root_stp_bridge():
    info = bridge_info(_STP_LINKS, 'br0')
    assert info['stp'] and info['priority'] == 32768 and info['address'] == '02:53:52:0a:0b:0c' and info['up']
    assert info['bridge_id'] == (32768, '02:53:52:0a:0b:0c') and info['root_id'] == (4096, '02:53:52:01:02:03')
    assert not info['is_root'] and info['root_port'] == 'eth0' and info['root_path_cost'] == 2
    assert (info['ageing_time'], info['hello_time'], info['forward_delay'], info['max_age']) == (30.0, 2.0, 15.0, 20.0)
    assert port_states(info) == {'eth0': 'forwarding', 'eth1': 'blocking'}
    assert info['ports']['eth1']['no'] == 2 and info['ports']['eth1']['designated_bridge'] == (4096, '02:53:52:01:02:03')
    assert info['ports']['eth0']['cost'] == 2 and info['ports']['eth0']['up']
    assert bridge_info(_STP_LINKS, 'eth0') is None and bridge_info(_STP_LINKS, 'nope') is None and port_states(None) == {}


def test_bridge_info_of_the_vlan_fixture():
    info = bridge_info(parse_ip_links_json(fixture('ip_link_b2.json')), 'brodd')
    assert not info['stp'] and info['is_root'] and info['root_port'] is None and info['ageing_time'] == 300.0
    assert info['bridge_id'] == (32768, BRODD_MAC) and set(info['ports']) == {'eth1', 'eth0.111'}
    assert port_states(info) == {'eth1': 'forwarding', 'eth0.111': 'forwarding'}


def test_parse_fdb_json_and_fdb_port_of():
    entries = parse_fdb_json(_FDB)
    assert len(entries) == 6 and entries[1]['vlan'] == 1 and entries[0]['vlan'] is None
    learned = learned_fdb_entries(entries)
    assert [e['mac'] for e in learned] == ['02:53:52:00:00:01', '02:53:52:00:00:03', '02:53:52:00:00:09']
    assert fdb_port_of(entries, '02:53:52:00:00:01') == 'eth0' and fdb_port_of(entries, '02-53-52-00-00-03') == 'eth1'
    assert fdb_port_of(entries, '02:53:52:0a:0b:0c') is None            # permanent: the port's own address
    assert fdb_port_of(entries, '02:53:52:0a:0b:0c', learned_only=False) == 'eth0'
    assert fdb_port_of(entries, '02:53:52:00:00:42') is None
    assert parse_fdb_json('') == [] and parse_fdb_json('garbage') == [] and parse_fdb_json('{}') == []
    assert fdb_cmd('br0') == 'bridge -j fdb show br br0'


def test_get_fdb_wrapper():
    grade = make_grade({"bridge -j fdb show br br0": (_FDB, 0)})
    assert fdb_port_of(get_fdb(grade, 'b1', 'br0'), '02:53:52:00:00:03') == 'eth1'
    assert get_fdb(make_grade({}), 'b1', 'br0') == []


def test_parse_bridge_rules_and_drop_rules_for():
    rules = parse_bridge_rules(_FILTER_RULESET)
    assert [r['chain'] for r in rules] == ['forward'] * 4 + ['input']
    mac, ip, web, rej, inp = rules
    assert (mac['hook'], mac['verdict'], mac['ether_saddr'], mac['ether_daddr']) == (
        'forward', 'drop', '02:53:52:00:00:02', '02:53:52:00:00:fe')
    assert ip['saddr'] == '192.168.1.2' and not ip['saddr_neg'] and ip['daddr'] == '192.168.1.0/24' and ip['daddr_neg']
    assert web['iif'] == 'eth1' and web['verdict'] == 'accept' and web['l4proto'] == 'tcp' and web['dport'] == 80
    assert rej['verdict'] == 'reject' and inp['hook'] == 'input' and inp['verdict'] == 'drop'
    assert not any(r['pkttype_host'] or r['daddr_mac'] or r['broute'] for r in rules)
    assert drop_rules_for(rules, mac='02:53:52:00:00:02') == [mac]
    assert drop_rules_for(rules, ip='192.168.1.2') == [ip, inp]
    assert drop_rules_for(rules, ip='192.168.1.2', hook='forward') == [ip]
    assert drop_rules_for(rules, mac='02:53:52:00:00:02', ip='192.168.1.2') == [mac, ip, inp]
    assert drop_rules_for(rules, ip='192.168.1.7') == []            # the negated daddr prefix does not count
    assert drop_rules_for(rules, mac='02:53:52:00:00:03') == []     # a reject is not a drop
    assert len(drop_rules_for(rules)) == 3
    assert parse_bridge_rules('') == [] and parse_bridge_rules(None) == []


def test_parse_bridge_rules_keeps_the_broute_projection():
    rules = parse_bridge_rules(fixture('nft_ruleset_b2.txt'))
    assert len(rules) == 2 and rules[0]['pkttype_host'] and rules[0]['daddr_mac'] == BRODD_MAC and rules[0]['verdict'] is None
    projected = parse_broute_rules(fixture('nft_ruleset_b2.txt'))
    assert set(projected[0]) == {'table', 'chain', 'hook', 'iif', 'saddr', 'daddr', 'l4proto', 'dport', 'pkttype_host',
                                 'daddr_mac', 'broute', 'text'}
    assert all(projected[i][k] == rules[i][k] for i in range(2) for k in projected[i])


def test_get_bridge_rules_wrapper():
    grade = make_grade({"nft list ruleset": (_FILTER_RULESET, 0)})
    assert len(get_bridge_rules(grade, 'b1')) == 5 and get_bridge_rules(make_grade({}), 'b1') == []


# ---------------------------------------------------------------------------
# fixtures captured in the bridge lab (tests/mock_data/bridge/, 2026-10-11, base:1.30 images)
# ---------------------------------------------------------------------------

from bridging import parse_tcpdump_stp  # noqa: E402

BRIDGE_MOCK = Path(__file__).parent / 'mock_data' / 'bridge'
B1_MAC, B2_MAC = '02:53:52:b6:8b:b7', '02:53:52:60:ea:b6'          # the lowest port MAC of each bridge
M1_MAC, M2_MAC, M3_MAC, GW_MAC = '02:53:52:8e:3d:24', '02:53:52:69:6c:6a', '02:53:52:25:e0:1a', '02:53:52:2c:49:cf'


def bridge_fixture(name):
    return (BRIDGE_MOCK / name).read_text()


def test_bridge_lab_fixture_stp_off():
    info = bridge_info(parse_ip_links_json(bridge_fixture('ip_link_b1.json')), 'br0')
    assert not info['stp'] and info['is_root'] and info['root_port'] is None and info['address'] == B1_MAC
    assert info['bridge_id'] == (32768, B1_MAC) and info['bridge_id_text'] == '8000.2:53:52:b6:8b:b7'
    assert (info['ageing_time'], info['hello_time'], info['forward_delay'], info['max_age']) == (300.0, 2.0, 15.0, 20.0)
    assert port_states(info) == {'eth0': 'forwarding', 'eth1': 'forwarding'}
    assert 'ageing_time 30000 stp_state 0' in bridge_fixture('ip_link_br0.txt')     # centiseconds in the text too


def test_bridge_lab_fixture_b1_with_b2_as_root():
    """STP just enabled on b1 while b2 (priority 4096) is the root: eth0 is the root port, eth1 blocks,
    and the kernel has lowered the ageing time to 2 x forward_delay for the topology change."""
    info = bridge_info(parse_ip_links_json(bridge_fixture('ip_link_b1_stp.json')), 'br0')
    assert info['stp'] and not info['is_root'] and info['priority'] == 32768
    assert info['root_id'] == (4096, B2_MAC) and info['root_port'] == 'eth0' and info['root_path_cost'] == 2
    assert port_states(info) == {'eth0': 'forwarding', 'eth1': 'blocking'}
    assert info['ports']['eth1']['designated_bridge'] == (4096, B2_MAC) and info['ports']['eth1']['no'] == 2
    assert info['ageing_time'] == 30.0
    b2 = bridge_info(parse_ip_links_json(bridge_fixture('ip_link_b2_root.json')), 'br0')
    assert b2['is_root'] and b2['priority'] == 4096 and port_states(b2)['eth1'] in ('learning', 'forwarding')


def test_bridge_lab_fixture_final_state():
    b1 = bridge_info(parse_ip_links_json(bridge_fixture('ip_link_b1_final.json')), 'br0')
    b2 = bridge_info(parse_ip_links_json(bridge_fixture('ip_link_b2.json')), 'br0')
    assert b1['stp'] and b1['is_root'] and b1['priority'] == 0 and b1['bridge_id'] == (0, B1_MAC)
    assert port_states(b1) == {'eth0': 'forwarding', 'eth1': 'forwarding'} and b1['ageing_time'] == 30.0
    assert b2['stp'] and not b2['is_root'] and b2['root_id'] == b1['bridge_id'] and b2['root_port'] == 'eth0'
    assert port_states(b2) == {'eth0': 'forwarding', 'eth1': 'blocking'}
    links = json.loads(bridge_fixture('bridge_link_b2.json'))
    assert {l['ifname']: l['state'] for l in links} == port_states(b2)


def test_bridge_lab_fixture_fdb():
    entries = parse_fdb_json(bridge_fixture('fdb_b1.json'))
    assert fdb_port_of(entries, M1_MAC) == 'eth0' and fdb_port_of(entries, M2_MAC) == 'eth1'
    assert fdb_port_of(entries, B1_MAC) is None and fdb_port_of(entries, B1_MAC, learned_only=False) == 'eth0'
    assert fdb_port_of(entries, '33:33:00:00:00:01') is None       # a `self permanent` multicast entry
    assert [e['mac'] for e in learned_fdb_entries(entries)] == [M1_MAC, M2_MAC]
    permanent = [e for e in entries if e['state'] == 'permanent' and e['master'] == 'br0']
    assert sorted((e['mac'], e['vlan'] or 0) for e in permanent) == [(B1_MAC, 0), (B1_MAC, 1),
                                                                     ('02:53:52:f0:02:e1', 0), ('02:53:52:f0:02:e1', 1)]
    final = parse_fdb_json(bridge_fixture('fdb_b1_final.json'))
    assert {e['mac']: e['ifname'] for e in learned_fdb_entries(final)} == {
        M1_MAC: 'eth0', GW_MAC: 'eth0', M2_MAC: 'eth1', M3_MAC: 'eth1'}


def test_bridge_lab_fixture_nft_filter():
    rules = parse_bridge_rules(bridge_fixture('nft_ruleset_b1.txt'))
    assert len(rules) == 1                                           # Docker's ip nat table is ignored
    rule = rules[0]
    assert (rule['table'], rule['chain'], rule['hook'], rule['verdict']) == ('filter', 'forward', 'forward', 'drop')
    assert rule['ether_saddr'] == M2_MAC and rule['ether_daddr'] == GW_MAC     # nft prints daddr first
    assert drop_rules_for(rules, mac=M2_MAC, hook='forward') == rules and drop_rules_for(rules, mac=GW_MAC) == rules
    assert drop_rules_for(rules, mac=M3_MAC) == [] and drop_rules_for(rules, ip='192.168.1.2') == []


def test_parse_tcpdump_stp():
    frames = parse_tcpdump_stp(bridge_fixture('tcpdump_stp_v.txt'))
    assert len(frames) == 2 and all(f['type'] == 'Config' and f['flags'] == 'Topology change' for f in frames)
    f = frames[0]
    assert f['bridge_id'] == (4096, B2_MAC) and f['port_id'] == 0x8001 and f['length'] == 35
    assert f['root_id'] == (4096, B2_MAC) and f['root_path_cost'] == 0
    assert (f['message_age'], f['max_age'], f['hello_time'], f['forward_delay']) == (0.0, 20.0, 2.0, 15.0)
    short = parse_tcpdump_stp(bridge_fixture('tcpdump_stp.txt'))
    assert len(short) == 2 and short[0]['bridge_id'] == (4096, B2_MAC) and short[0]['max_age'] is None
    none = parse_tcpdump_stp("12:00:00.000000 STP 802.1d, Config, Flags [none], bridge-id 8000.02:53:52:b6:8b:b7.8002, length 35\n")
    assert none[0]['flags'] == 'none' and none[0]['port_id'] == 0x8002
    assert parse_tcpdump_stp('') == [] and parse_tcpdump_stp(None) == []
