"""Tests for lib/traceroute.py — helpers of the traceroute lab.

Fixtures in tests/mock_data/traceroute were captured on 2026-10-17 in the containers of the lab
(sysreseval/base:1.30: iputils 20221126, traceroute 2.1.2, tcpdump 4.99, on a Linux 6.12 host),
except ping_ttl_exceeded_names.txt, tools_left.txt and tools_none.txt, written by hand (the UDP
trace of island C — tcpdump_udp_trace.txt, tcpdump_udp_trace_v.txt, tshark_udp_trace.txt,
nft_ttlfw_counter.txt — was captured the same day: nc -M 1..7 from m2, tcpdump 4.99, tshark 4.0).
"""
import sys
from ipaddress import IPv4Interface
from pathlib import Path
from types import SimpleNamespace
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

import traceroute  # noqa: E402

FIXTURES = Path(__file__).parent / 'mock_data' / 'traceroute'

CYCLE = ['r1', 'r2', 'r3']


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


# ---------------------------------------------------------------------------
# topology and arithmetic
# ---------------------------------------------------------------------------

def test_link_name():
    assert traceroute.link_name(1, 2) == 'c12' and traceroute.link_name(9, 8) == 'c89'
    assert traceroute.link_name(4, 5, 'd') == 'd45'


def test_hop_at():
    assert [traceroute.hop_at(t, CYCLE) for t in (1, 2, 3, 4, 10, 11, 64, 65, 66)] == \
        ['r1', 'r2', 'r3', 'r1', 'r1', 'r2', 'r1', 'r2', 'r3']


def test_loop_passages():
    r2 = traceroute.loop_passages(64, 3, 1)
    assert r2[:3] == [63, 60, 57] and r2[-1] == 3 and len(r2) == 21
    r1 = traceroute.loop_passages(64, 3, 0)
    assert len(r1) == 22 and r1[0] == 64 and r1[-1] == 1
    r3 = traceroute.loop_passages(64, 3, 2)
    assert len(r3) == 21 and r3[0] == 62 and r3[-1] == 2
    assert traceroute.loop_passages(1, 3, 1) == [] and traceroute.loop_passages(2, 3, 1) == [1]


def test_reply_ttl_and_min_ttl():
    assert traceroute.reply_ttl(2) == 62 and traceroute.reply_ttl(6, default_ttl=128) == 122
    assert traceroute.min_ttl_to_reach(3) == 4


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def test_ping_ttl_cmd():
    assert traceroute.ping_ttl_cmd('203.0.113.77', 5) == "ping -4 -n -t 5 -c 1 -W 1 -w 2 203.0.113.77"
    assert traceroute.ping_ttl_cmd('10.0.0.1') == "ping -4 -n -c 1 -W 1 -w 2 10.0.0.1"
    assert traceroute.ping_ttl_cmd('10.0.0.1', record_route=True, count=2, wait=2, deadline=9) == \
        "ping -4 -n -R -c 2 -W 2 -w 9 10.0.0.1"


def test_traceroute_cmd():
    assert traceroute.traceroute_cmd('172.20.5.9') == "traceroute -4 -n -q 1 -w 1 -m 6 172.20.5.9"
    assert traceroute.traceroute_cmd('172.20.5.9', method='icmp', max_hops=8) == \
        "traceroute -4 -n -q 1 -w 1 -m 8 -I 172.20.5.9"
    assert traceroute.traceroute_cmd('srv', method='tcp', port=80, queries=3, wait=2, first=2) == \
        "traceroute -4 -n -q 3 -w 2 -m 6 -T -p 80 -f 2 srv"
    with pytest.raises(ValueError):
        traceroute.traceroute_cmd('srv', method='sctp')


def test_nc_udp_cmd():
    assert traceroute.nc_udp_cmd('10.5.0.9') == "printf x | nc -u -w 1 10.5.0.9 33434"
    assert traceroute.nc_udp_cmd('target2', port=33435, wait=2, ttl=3) == "printf x | nc -u -w 2 -M 3 target2 33435"


def test_remove_tools_cmd():
    cmd = traceroute.remove_tools_cmd()
    assert cmd.startswith("for n in traceroute traceroute6 tcptraceroute lft traceproto; do update-alternatives --remove-all")
    assert "rm -rf /usr/bin/*traceroute* /usr/sbin/*traceroute*" in cmd
    assert "/usr/bin/nping /usr/bin/busybox /usr/bin/tracert6;" in cmd
    for tool in traceroute.TRACE_TOOLS:
        assert f" {tool}" in cmd
    assert cmd.endswith('&& echo "LEFT $n"; done; echo DONE')
    assert traceroute.tools_left(load('tools_left.txt')) == ['nmap', 'nping']
    assert traceroute.tools_left(load('tools_none.txt')) == [] and traceroute.tools_left('') == []


# ---------------------------------------------------------------------------
# ping outputs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('name, source', [('ping_ttl_exceeded.txt', '192.168.226.9'),
                                          ('ping_ttl_exceeded_names.txt', '192.168.30.1')])
def test_parse_ping_ttl_exceeded(name, source):
    r = traceroute.parse_ping(load(name))
    assert (r['sent'], r['received']) == (1, 0)
    assert r['from'] == source and r['error'] == 'Time to live exceeded'
    assert r['errors'] == [{'from': source, 'seq': 1, 'message': 'Time to live exceeded'}]
    assert r['replies'] == [] and r['reply_ttl'] is None and r['rr'] == []
    assert traceroute.error_from(load(name)) == source
    assert traceroute.error_from(load(name), 'Destination') is None


def test_parse_ping_reply():
    r = traceroute.parse_ping(load('ping_reply.txt'))
    assert (r['sent'], r['received'], r['reply_ttl']) == (1, 1, 56)
    assert r['replies'] == [{'from': '192.168.197.81', 'seq': 1, 'ttl': 56}]
    assert r['from'] is None and r['error'] is None


def test_parse_ping_record_route():
    # inj → r1 → r2 → r3 → srv and back by r3 → r1: nine slots, the destination twice
    r = traceroute.parse_ping(load('ping_rr.txt'))
    assert r['reply_ttl'] == 62
    assert r['rr'] == ['10.236.119.85', '172.23.67.41', '192.168.202.150', '192.168.65.254', '192.168.65.46',
                       '192.168.65.46', '192.168.235.151', '10.236.119.174', '10.236.119.85']
    # without -n the originator is printed "m1 (address)"
    r = traceroute.parse_ping(load('ping_rr_names.txt'))
    assert r['reply_ttl'] == 56 and len(r['rr']) == 9
    assert r['rr'][0] == '192.168.226.55' and r['rr'][-1] == '192.168.197.25'


def test_parse_ping_errors():
    r = traceroute.parse_ping(load('ping_net_unreachable.txt'))
    assert r['sent'] is None and r['from'] is None and r['error'] == 'Network is unreachable'
    r = traceroute.parse_ping(load('ping_dest_net_unreachable.txt'))
    assert r['from'] == '10.236.119.174' and r['error'] == 'Destination Net Unreachable'
    assert traceroute.error_from(load('ping_dest_net_unreachable.txt')) is None
    r = traceroute.parse_ping(load('ping_timeout.txt'))
    assert (r['sent'], r['received'], r['from'], r['error'], r['reply_ttl']) == (1, 0, None, None, None)
    assert traceroute.parse_ping('')['sent'] is None


# ---------------------------------------------------------------------------
# traceroute outputs
# ---------------------------------------------------------------------------

#: the loop of island B as traceroute shows it: r1 on lan3, r2 on l23, r3 on l31 (exit interfaces)
LOOP = ['10.236.119.174', '192.168.202.150', '192.168.235.151']
SRV = '192.168.65.46'


def test_parse_traceroute_udp_drop():
    hops = traceroute.parse_traceroute(load('traceroute_udp_drop.txt'))
    assert traceroute.traceroute_path(hops) == LOOP + [None] * 5
    assert [h['hop'] for h in hops] == list(range(1, 9))
    assert hops[3] == {'hop': 4, 'addr': None, 'addrs': [], 'flags': [], 'timeouts': 1}


def test_parse_traceroute_reject_icmp_tcp():
    hops = traceroute.parse_traceroute(load('traceroute_udp_reject.txt'))
    assert traceroute.traceroute_path(hops) == LOOP + [SRV]
    assert hops[3]['flags'] == ['!X'] and hops[2]['flags'] == []
    for name in ('traceroute_icmp.txt', 'traceroute_tcp.txt'):
        hops = traceroute.parse_traceroute(load(name))
        assert traceroute.traceroute_path(hops) == LOOP + [SRV]
        assert all(h['flags'] == [] and h['timeouts'] == 0 for h in hops)


def test_parse_traceroute_silent_hop_and_loop():
    hops = traceroute.parse_traceroute(load('traceroute_silent_hop.txt'))
    assert traceroute.traceroute_path(hops) == [LOOP[0], None, LOOP[2], SRV]
    hops = traceroute.parse_traceroute(load('traceroute_loop.txt'))
    assert len(hops) == 12
    assert traceroute.traceroute_path(hops) == LOOP * 4


def test_parse_traceroute_three_probes():
    hops = traceroute.parse_traceroute(load('traceroute_q3_names.txt'))      # names from /etc/hosts
    assert traceroute.traceroute_path(hops) == LOOP * 2
    assert all(h['timeouts'] == 0 and h['flags'] == [] for h in hops) and hops[0]['addrs'] == [LOOP[0]]
    hops = traceroute.parse_traceroute(load('traceroute_reject_q3.txt'))
    assert hops[3]['flags'] == ['!X', '!X', '!X'] and hops[3]['addrs'] == [SRV]
    hops = traceroute.parse_traceroute(load('traceroute_silent_q3.txt'))
    assert hops[1]['timeouts'] == 3 and hops[1]['addr'] is None and hops[3]['addr'] == SRV
    assert traceroute.parse_traceroute('') == []


# ---------------------------------------------------------------------------
# tcpdump, nftables
# ---------------------------------------------------------------------------

def test_parse_tcpdump_ttls():
    ttls = traceroute.parse_tcpdump_ttls(load('tcpdump_loop_r2.txt'))
    assert ttls == list(range(63, 2, -3)) and len(ttls) == 21
    assert ttls == traceroute.loop_passages(64, 3, 1)
    # the quoted header inside a time-exceeded message (indented line) is not a packet
    assert traceroute.parse_tcpdump_ttls(load('tcpdump_m1_time_exceeded.txt')) == [2, 63]
    assert traceroute.parse_tcpdump_ttls('') == []


#: the six routers of island C in the capture run (fw first) and target2
HOPS_C = ['192.168.241.56', '192.168.187.2', '10.242.117.219', '10.64.163.175', '10.132.27.63', '10.25.217.181']
TARGET2 = '10.86.81.159'


@pytest.mark.parametrize('name', ['tcpdump_udp_trace.txt', 'tshark_udp_trace.txt'])
def test_parse_icmp_capture_udp_trace(name):
    messages = traceroute.parse_icmp_capture(load(name))
    assert [m['kind'] for m in messages] == ['time-exceeded'] * 6 + ['port-unreachable']
    assert traceroute.capture_sources(messages) == HOPS_C
    assert traceroute.capture_sources(messages, 'port-unreachable') == [TARGET2]
    assert all(m['dst'] == '192.168.241.64' for m in messages)


def test_parse_icmp_capture_verbose_tcpdump():
    # tcpdump -v: the UDP header quoted inside each error is not a packet
    messages = traceroute.parse_icmp_capture(load('tcpdump_udp_trace_v.txt'))
    assert [(m['src'], m['kind']) for m in messages] == [(HOPS_C[1], 'time-exceeded'), (TARGET2, 'port-unreachable')]
    assert messages[1]['text'] == f'{TARGET2} udp port 33434 unreachable'
    assert traceroute.parse_tcpdump_ttls(load('tcpdump_udp_trace_v.txt')) == [63, 58]
    # the echo request quoted inside a time exceeded message is not a packet either
    messages = traceroute.parse_icmp_capture(load('tcpdump_m1_time_exceeded.txt'))
    assert [(m['src'], m['kind']) for m in messages] == [('192.168.226.55', 'echo-request'), ('172.26.62.250', 'time-exceeded')]
    assert traceroute.parse_icmp_capture('') == []


def test_nft_ttl_firewall_and_counter():
    text = traceroute.nft_ttl_firewall('ttlfw', 12)
    assert text.startswith("table ip ttlfw {\n    chain prerouting {\n        type filter hook prerouting priority raw; policy accept;\n")
    assert '        iifname "eth0" icmp type echo-request ip ttl lt 12 drop\n' in text
    assert '        iifname "eth0" icmp type echo-request ip hdrlength gt 5 drop\n' in text
    assert '        iifname "eth0" ip ttl lt 8 counter comment "probes"\n' in text
    assert 'iifname "eth1" ip ttl lt 10 counter comment "udp"' in traceroute.nft_ttl_firewall(
        't', 20, iif='eth1', probe_ttl_limit=10, comment='udp')
    listing = load('nft_ttlfw_counter.txt')      # nft prints "ip ttl < 8" for the "lt 8" rule
    assert 'ip ttl < 12 drop' in listing and 'ip hdrlength > 5 drop' in listing
    assert traceroute.nft_counter_packets(listing, 'probes') == 22
    assert traceroute.nft_counter_packets(listing) == 22
    assert traceroute.nft_counter_packets(listing, 'other') is None
    assert traceroute.nft_counter_packets('table ip ttlfw {\n}\n', 'probes') is None
    assert traceroute.nft_counter_packets('', 'probes') is None


def test_nft_texts():
    silent = traceroute.nft_drop_icmp_types('silent')
    assert silent.startswith("table ip silent {\n    chain output {\n        type filter hook output priority filter; policy accept;\n")
    assert "        icmp type time-exceeded drop\n" in silent
    drop = traceroute.nft_udp_policy('fw')
    assert "type filter hook input priority filter" in drop and "        meta l4proto udp drop\n" in drop
    reject = traceroute.nft_udp_policy('fw', 'reject')
    assert "        meta l4proto udp reject with icmp type admin-prohibited\n" in reject
    with pytest.raises(ValueError):
        traceroute.nft_udp_policy('fw', 'accept')


# ---------------------------------------------------------------------------
# scoring of a typed path
# ---------------------------------------------------------------------------

IPS = {
    'gw_lan1': IPv4Interface('192.168.30.1/24'), 'gw_core0': IPv4Interface('10.1.0.1/24'),
    'h1_core0': IPv4Interface('10.1.0.2/24'), 'h1_c13': IPv4Interface('10.2.0.1/24'),
    'h3_c13': IPv4Interface('10.2.0.2/24'), 'h3_c38': IPv4Interface('10.3.0.1/24'),
    'h8_c38': IPv4Interface('10.3.0.2/24'), 'h8_c89': IPv4Interface('10.4.0.1/24'),
    'h9_c89': IPv4Interface('10.4.0.2/24'), 'h9_tlan': IPv4Interface('10.5.0.1/24'),
    'target': IPv4Interface('10.5.0.9/24'), 'm1': IPv4Interface('192.168.30.7/24'),
}
EXPECTED = ['gw', 'h1', 'h3', 'h8', 'h9']


def test_address_owner():
    assert traceroute.address_owner('10.3.0.2', IPS) == 'h8' and traceroute.address_owner('10.5.0.9', IPS) == 'target'
    assert traceroute.address_owner(' (10.1.0.1) ', IPS) == 'gw' and traceroute.address_owner('10.1.0.1/24', IPS) == 'gw'
    assert traceroute.address_owner('10.9.9.9', IPS) is None and traceroute.address_owner('gw', IPS) is None
    assert traceroute.address_owner('192.168.30.7', SimpleNamespace(**IPS)) == 'm1'


def test_parse_path_answer():
    assert traceroute.parse_path_answer("192.168.30.1, 10.1.0.2 -> * ; 10.3.0.2\n10.4.0.2") == \
        ['192.168.30.1', '10.1.0.2', '*', '10.3.0.2', '10.4.0.2']
    assert traceroute.parse_path_answer("1: 192.168.30.1 2: ? 3: 10.3.0.1") == ['192.168.30.1', '*', '10.3.0.1']
    assert traceroute.parse_path_answer('') == [] and traceroute.parse_path_answer(None) == []


def test_score_path():
    ingress = ['192.168.30.1', '10.1.0.2', '10.2.0.2', '10.3.0.2', '10.4.0.2']
    assert traceroute.score_path(ingress, EXPECTED, IPS, silent_index=2) == (5, 0)
    egress = ['10.1.0.1', '10.2.0.1', '10.3.0.1', '10.4.0.1', '10.5.0.1']        # ping -R addresses
    assert traceroute.score_path(egress, EXPECTED, IPS, silent_index=2) == (5, 0)
    with_star = ['192.168.30.1', '10.1.0.2', '*', '10.3.0.2', '10.4.0.2']
    assert traceroute.score_path(with_star, EXPECTED, IPS, silent_index=2) == (5, 0)
    assert traceroute.score_path(with_star, EXPECTED, IPS, silent_index=3) == (4, 0)
    assert traceroute.score_path(with_star, EXPECTED, IPS) == (4, 0)
    assert traceroute.score_path(ingress + ['10.5.0.9'], EXPECTED, IPS, silent_index=2) == (5, 1)
    shifted = ['10.1.0.2', '10.2.0.2', '10.3.0.2', '10.4.0.2']
    assert traceroute.score_path(shifted, EXPECTED, IPS, silent_index=2) == (0, 0)
    assert traceroute.score_path([], EXPECTED, IPS) == (0, 0)
    assert traceroute.score_path(['*'] * 5, EXPECTED, IPS, silent_index=2) == (1, 0)


# ---------------------------------------------------------------------------
# wrappers
# ---------------------------------------------------------------------------

def test_wrappers():
    grade = MagicMock()
    grade.test.return_value = (load('ping_ttl_exceeded.txt'), 1)
    r = traceroute.ping_ttl(grade, 'inj', '10.60.0.2', ttl=3, step=2)
    assert r['from'] == '192.168.226.9'
    grade.test.assert_called_once_with('inj', "ping -4 -n -t 3 -c 1 -W 1 -w 2 10.60.0.2", step=2, allow_error=True)
    grade.test.reset_mock()
    grade.test.return_value = (load('traceroute_tcp.txt'), 0)
    hops = traceroute.traceroute_run(grade, 'inj', SRV, method='tcp')
    assert traceroute.traceroute_path(hops)[-1] == SRV
    grade.test.assert_called_once_with('inj', f"traceroute -4 -n -q 1 -w 1 -m 6 -T {SRV}", step=1, timeout=16,
                                       allow_error=True)
