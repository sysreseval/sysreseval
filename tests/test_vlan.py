"""Tests for lib/vlan.py and lib/http_echo.py (fixtures captured on 2026-10-09 in the running VLAN
lab after its `final` state: sysreseval/base:1.30, iproute2 6.19, nftables 1.0.6, iptables 1.8.9
nft, Linux 6.12; tests/mock_data/vlan/)."""
import socket
import struct
import sys
from ipaddress import IPv4Interface
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import http_echo  # noqa: E402
from switch import get_switch_ports  # noqa: E402
from vlan import (  # noqa: E402
    ECHO_PATH, ECHO_PID_FILE, MANGLE_RULES_CMD, addresses_of, bridge_ports, broute_rules_for, echo_start_cmd,
    get_broute_rules, get_http_echo, get_ip_links, get_mangle_rules, get_sysctl_int, http_echo_cmd,
    interface_of_address, link_address, link_master, link_up, links_by_name, parse_broute_rules, parse_http_echo,
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
# the echo server: frames and pages
# ---------------------------------------------------------------------------


def _frame(src="192.168.100.3", dst="10.193.51.51", sport=40000, dport=80, flags=0x02, ttl=63, tags=(),
           proto=socket.IPPROTO_TCP, frag=0, ethertype=0x0800, truncate=None):
    eth = bytes.fromhex("1a0a934114f3") + bytes.fromhex("967a72c800e8")
    for tag in tags:
        eth += struct.pack('!HH', 0x8100, tag)
    eth += struct.pack('!H', ethertype)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1234, frag, ttl, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 5 << 4, flags, 64240, 0, 0)
    frame = eth + ip + tcp
    return frame[:truncate] if truncate else frame


def test_parse_syn_plain_and_tagged():
    assert http_echo.parse_syn(_frame()) == ("192.168.100.3", 40000, 80, 63)
    assert http_echo.parse_syn(_frame(tags=(111,), ttl=89, dport=8080)) == ("192.168.100.3", 40000, 8080, 89)
    assert http_echo.parse_syn(_frame(tags=(222, 111))) == ("192.168.100.3", 40000, 80, 63)   # QinQ
    assert http_echo.parse_syn(_frame(), ports={80, 8080}) is not None
    assert http_echo.parse_syn(_frame(dport=443), ports={80, 8080}) is None


def test_parse_syn_rejects_other_frames():
    assert http_echo.parse_syn(_frame(flags=0x12)) is None          # SYN+ACK
    assert http_echo.parse_syn(_frame(flags=0x10)) is None          # ACK
    assert http_echo.parse_syn(_frame(proto=socket.IPPROTO_UDP)) is None
    assert http_echo.parse_syn(_frame(ethertype=0x0806)) is None    # ARP
    assert http_echo.parse_syn(_frame(frag=0x0010)) is None         # later fragment
    assert http_echo.parse_syn(_frame(truncate=40)) is None
    assert http_echo.parse_syn(b"") is None


def test_parse_http_echo_page():
    page = parse_http_echo(fixture('echo_m3_ext1.txt'))
    assert page == {'server': 'ext1', 'server_ip': '10.193.51.51', 'server_port': '80', 'client_ip': '10.193.51.200',
                    'client_port': '52198', 'ttl': 63}
    assert parse_http_echo("SERVER=ext2\nCLIENT_IP=10.0.0.1\nTTL=?\n")['ttl'] is None
    assert parse_http_echo("")['client_ip'] == "" and parse_http_echo(None)['ttl'] is None


def test_echo_commands():
    assert http_echo_cmd(IPv4Interface("10.193.51.52/24"), 8080) == "curl -s -m 5 http://10.193.51.52:8080/"
    assert http_echo_cmd("ext1") == "curl -s -m 5 http://ext1:80/"
    cmd = echo_start_cmd("ext1")
    assert ECHO_PID_FILE in cmd and f"python3 {ECHO_PATH} ext1 80 8080'" in cmd
    assert echo_start_cmd("m 1", (8000,)).endswith("python3 /usr/local/sbin/sre_http_echo.py 'm 1' 8000'")


def test_get_http_echo_wrapper():
    grade = make_grade({"curl -s -m 5 http://10.193.51.51:80/": (fixture('echo_m3_ext1.txt'), 0),
                        "curl -s -m 5 http://10.193.51.52:8080/": ("", 7)})
    assert get_http_echo(grade, 'm3', "10.193.51.51")['client_ip'] == "10.193.51.200"
    assert get_http_echo(grade, 'm5', "10.193.51.52", 8080)['client_ip'] == ""
    grade.test.assert_any_call('m3', "curl -s -m 5 http://10.193.51.51:80/", step=1, timeout=10, allow_error=True)


def test_install_http_echo_script_is_self_contained():
    source = (Path(__file__).parent.parent / 'lib' / 'http_echo.py').read_text()
    assert source.startswith("#!/usr/bin/env python3") and "if __name__ == '__main__':" in source
    assert all(f"import {mod}" in source for mod in ('socket', 'struct', 'threading'))
    assert 'from SRE' not in source and 'import vlan' not in source


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
