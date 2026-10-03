"""Tests for lib/pmtu.py — path MTU discovery helpers of the MTU labs.

Fixtures in tests/mock_data/pmtu were captured on 2026-10-02 in a sysreseval/base:1.28
container (iputils 20221126, iproute2 6.19, nftables 1.0.6) on a Debian 13 / Linux 6.12 host.
"""
import sys
from ipaddress import IPv4Interface, IPv6Interface
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

import pmtu  # noqa: E402

FIXTURES = Path(__file__).parent / 'mock_data' / 'pmtu'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


# ---------------------------------------------------------------------------
# arithmetic and commands
# ---------------------------------------------------------------------------

def test_sizes():
    assert pmtu.max_ping_payload(1500) == 1472
    assert pmtu.max_ping_payload(1500, ipv6=True) == 1452
    assert pmtu.max_ping_payload(1400) == 1372
    assert pmtu.mss_for(1500) == 1460
    assert pmtu.mss_for(1500, ipv6=True) == 1440
    assert pmtu.mss_for(1400, ipv6=True) == 1340
    assert pmtu.GRE_OVERHEAD == 24 and pmtu.SIT_OVERHEAD == 20 and pmtu.IPV6_MIN_MTU == 1280


def test_pmtu_ping_cmd():
    assert pmtu.pmtu_ping_cmd('10.0.0.1', 1372) == "ping -4 -n -M do -s 1372 -c 1 -w 2 10.0.0.1"
    assert pmtu.pmtu_ping_cmd('fd00::1', 1352, ipv6=True, count=2, deadline=3, interval=0.3) == \
        "ping -6 -n -M do -s 1352 -c 2 -i 0.3 -w 3 fd00::1"


# ---------------------------------------------------------------------------
# ping outputs
# ---------------------------------------------------------------------------

def test_parse_ping_too_long_v4():
    r = pmtu.parse_ping_errors(load('ping_too_long_v4.txt'))
    assert r == {'sent': 1, 'received': 0, 'frag_needed_mtu': None, 'too_long_mtu': 1400, 'packet_too_big_mtu': None}


def test_parse_ping_too_long_v6():
    r = pmtu.parse_ping_errors(load('ping_too_long_v6.txt'))
    assert r['too_long_mtu'] == 1400 and r['received'] == 0 and r['frag_needed_mtu'] is None


def test_parse_ping_frag_needed():
    r = pmtu.parse_ping_errors(load('ping_frag_needed_v4.txt'))
    assert r["frag_needed_mtu"] == 1460 and r["too_long_mtu"] is None and r["received"] == 0


def test_parse_ping_packet_too_big():
    r = pmtu.parse_ping_errors(load('ping_ptb_v6.txt'))
    assert r['packet_too_big_mtu'] == 1420 and r['received'] == 0


def test_parse_ping_ok_and_empty():
    r = pmtu.parse_ping_errors(load('ping_ok_v4.txt'))
    assert r['sent'] == 1 and r['received'] == 1
    assert all(r[k] is None for k in ('frag_needed_mtu', 'too_long_mtu', 'packet_too_big_mtu'))
    assert pmtu.ping_received(load('ping_ok_v4.txt')) == 1
    assert pmtu.parse_ping_errors('') == {'sent': None, 'received': None, 'frag_needed_mtu': None,
                                          'too_long_mtu': None, 'packet_too_big_mtu': None}
    assert pmtu.ping_received(None) == 0


# ---------------------------------------------------------------------------
# ip -j -d link
# ---------------------------------------------------------------------------

def test_ip_link_json_cmd():
    assert pmtu.ip_link_json_cmd('gre1') == "ip -j -d link show gre1"
    assert pmtu.ip_link_json_cmd() == "ip -j -d link show"


def test_tunnel_info_gre():
    info = pmtu.tunnel_info(pmtu.parse_ip_link_json(load('ip_link_gre1.json')))
    assert info == {'kind': 'gre', 'mtu': 1296, 'local': '10.9.9.1', 'remote': '10.9.9.2', 'pmtudisc': True, 'up': True}


def test_tunnel_info_sit():
    info = pmtu.tunnel_info(pmtu.parse_ip_link_json(load('ip_link_sit1.json')))
    assert info['kind'] == 'sit' and info['mtu'] == 1480 and info['remote'] == '10.9.9.2'


def test_tunnel_info_absent():
    assert pmtu.parse_ip_link_json('') == {}
    assert pmtu.parse_ip_link_json('Device "gre1" does not exist.') == {}
    info = pmtu.tunnel_info({})
    assert info == {'kind': None, 'mtu': None, 'local': None, 'remote': None, 'pmtudisc': None, 'up': None}


def test_iface_mtus():
    out = '[{"ifname":"lo","mtu":65536},{"ifname":"eth0","mtu":1400},{"ifname":"eth1","mtu":1500}]'
    assert pmtu.iface_mtus(out) == {'lo': 65536, 'eth0': 1400, 'eth1': 1500}
    assert pmtu.iface_mtus('') == {}
    assert pmtu.iface_mtus(load('ip_link_gre1.json')) == {'gre1': 1296}


# ---------------------------------------------------------------------------
# nftables texts
# ---------------------------------------------------------------------------

def test_nft_drop_pmtu_errors_all():
    text = pmtu.nft_drop_pmtu_errors('trou_noir', ipv6=False)
    assert text.startswith("table inet trou_noir {\n    chain output {\n        type filter hook output priority filter; policy accept;\n")
    assert "        icmp type destination-unreachable icmp code frag-needed drop\n" in text
    assert "icmpv6" not in text
    assert text.endswith("    }\n}\n")


def test_nft_drop_pmtu_errors_probes():
    text = pmtu.nft_drop_pmtu_errors('sondes', daddr4=[IPv4Interface('10.1.1.5/24'), '10.2.2.5'],
                                     daddr6=[IPv6Interface('fd00:1::fe/64'), 'fd00:2::fe'])
    assert "ip daddr { 10.1.1.5, 10.2.2.5 } icmp type destination-unreachable icmp code frag-needed drop" in text
    assert "ip6 daddr { fd00:1::fe, fd00:2::fe } icmpv6 type packet-too-big drop" in text


def test_nft_mss_clamp():
    text = pmtu.nft_mss_clamp('mss_clamp', mss4=1360, mss6=1340)
    assert "type filter hook forward priority mangle; policy accept;" in text
    assert "meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1360" in text
    assert "meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1340" in text
    only4 = pmtu.nft_mss_clamp('x', mss4=1360)
    assert "ipv6" not in only4


def test_mss_clamp_rules_inet():
    rules = pmtu.mss_clamp_rules(load('nft_clamp_inet.txt'))
    assert rules == [
        {'family': 4, 'value': 1360, 'hook': 'forward', 'table': 'mss_clamp'},
        {'family': 6, 'value': 1340, 'hook': 'forward', 'table': 'mss_clamp'},
        {'family': None, 'value': 'rt mtu', 'hook': 'forward', 'table': 'mss_clamp'},
    ]


def test_mss_clamp_rules_ip_tables():
    rules = pmtu.mss_clamp_rules(load('nft_clamp_ip.txt'))
    assert [(r['family'], r['value'], r['hook']) for r in rules] == [
        (4, 1300, 'input'), (4, 1360, 'forward'), (6, 'rt mtu', 'forward')]
    assert pmtu.mss_clamp_rules('') == []


def test_mss_clamped():
    rules = pmtu.mss_clamp_rules(load('nft_clamp_inet.txt'))
    assert pmtu.mss_clamped(rules, 4, 1360)
    assert pmtu.mss_clamped(rules, 6, 1340)
    assert not pmtu.mss_clamped(rules, 6, 1300)          # 1340 > 1300 and rt mtu not trusted
    assert pmtu.mss_clamped(rules, 6, 1300, rt_mtu_ok=True)
    rules_ip = pmtu.mss_clamp_rules(load('nft_clamp_ip.txt'))
    assert not pmtu.mss_clamped(rules_ip, 4, 1300)       # the only small enough rule is in the input hook
    assert pmtu.mss_clamped(rules_ip, 4, 1360)
    assert not pmtu.mss_clamped(rules_ip, 6, 1340)
    assert pmtu.mss_clamped(rules_ip, 6, 1340, rt_mtu_ok=True)
