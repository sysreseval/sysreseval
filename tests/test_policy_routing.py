"""Tests for lib/policy_routing.py.  The fixtures of tests/mock_data/policy_routing were captured on
2026-11-18 in the running policy routing lab (iproute2 6.19, nftables 1.0.6, Linux 6.12), the
reference solution applied by hand: a source rule towards a named table (r1), a table per uplink
(r2), a fwmark rule (r3, r4), a weighted multipath default route, the same through a nexthop
group, and the untouched route (r5), two VRFs with their `unreachable` default routes and a leak
(r6), the 64 pages of the spread probe (pc5) and the pings of the VRF isolation (red1, blue1)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import tc  # noqa: E402
from bridging import parse_ip_links_json  # noqa: E402
from policy_routing import (  # noqa: E402
    FULL_MASK, MAIN_TABLE, ROUTE_TABLES_CMD, default_nexthops, default_route, fwmark_rules, get_route_tables,
    leaves_by, parse_route_tables, parse_spread, route_nexthops, rule_selects_mark, spread_cmd, tables_of_mark,
    vrf_devices, vrf_of_port,
)
from traceroute import parse_ping  # noqa: E402
from wireguard import parse_ip_rules  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'policy_routing'

ISP1, ISP2 = "198.19.177.1", "198.19.217.1"


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def tables(name: str):
    return parse_route_tables(fixture(name))


def rules(name: str):
    return parse_ip_rules(fixture(name))


# ---------------------------------------------------------------------------
# routes of every table
# ---------------------------------------------------------------------------


class TestRouteTables:
    def test_tables_of_a_source_rule_with_a_named_table(self):
        t = tables('route_tables_r1_named.json')
        assert set(t) == {'isp2', MAIN_TABLE, 'local'}
        assert [r['dst'] for r in t['isp2']] == ['default', '172.22.20.0/24', '192.168.173.0/24']
        assert default_nexthops(t['isp2']) == [{'gateway': ISP2, 'dev': 'eth2', 'weight': 1}]
        assert default_nexthops(t[MAIN_TABLE]) == [{'gateway': ISP1, 'dev': 'eth1', 'weight': 1}]

    def test_one_numbered_table_per_uplink(self):
        t = tables('route_tables_r2.json')
        assert {'101', '102'} <= set(t)
        assert leaves_by(t['101'], 'eth1') and not leaves_by(t['101'], 'eth2')
        assert leaves_by(t['102'], 'eth2') and not leaves_by(t['102'], 'eth1')

    def test_untouched_router(self):
        t = tables('route_tables_r5_untouched.json')
        assert set(t) == {MAIN_TABLE, 'local'}
        assert leaves_by(t[MAIN_TABLE], 'eth1')

    @pytest.mark.parametrize('name', ['route_tables_r5_multipath.json', 'route_tables_r5_nhid.json'])
    def test_weighted_multipath_default_route(self, name):
        main = tables(name)[MAIN_TABLE]
        assert default_nexthops(main) == [{'gateway': ISP1, 'dev': 'eth1', 'weight': 3},
                                          {'gateway': ISP2, 'dev': 'eth2', 'weight': 1}]
        assert not leaves_by(main, 'eth1') and not leaves_by(main, 'eth2')

    def test_nexthop_group_is_named_in_the_route(self):
        assert default_route(tables('route_tables_r5_nhid.json')[MAIN_TABLE])['nhid'] == 10

    def test_unreachable_default_route_of_a_vrf_table(self):
        t = tables('route_tables_r6_vrf.json')
        assert {'10', '20'} <= set(t)
        for table in ('10', '20'):
            assert default_route(t[table])['type'] == 'unreachable'
            assert default_nexthops(t[table]) == []
            assert not leaves_by(t[table], 'eth4')
        # the leak: the management network in the table of the blue VRF only
        assert any(r['dst'] == '10.56.195.0/24' and r['dev'] == 'eth4' for r in t['10'])
        assert not any(r['dst'] == '10.56.195.0/24' for r in t['20'])
        assert any(r.get('dev') == 'vrf-blue' for r in t[MAIN_TABLE])

    def test_no_default_route(self):
        assert default_route([]) is None and default_nexthops([]) == [] and not leaves_by([], 'eth1')
        assert default_route(None) is None

    def test_lowest_metric_wins(self):
        routes = [{'dst': 'default', 'gateway': '10.0.0.2', 'dev': 'eth2', 'metric': 200},
                  {'dst': 'default', 'gateway': '10.0.0.1', 'dev': 'eth1', 'metric': 100}]
        assert default_nexthops(routes) == [{'gateway': '10.0.0.1', 'dev': 'eth1', 'weight': 1}]

    def test_route_nexthops_shapes(self):
        assert route_nexthops(None) == []
        assert route_nexthops({'dst': 'default', 'type': 'blackhole'}) == []
        assert route_nexthops({'dst': '10.0.0.0/24', 'dev': 'eth0'}) == [{'gateway': '', 'dev': 'eth0', 'weight': 1}]

    @pytest.mark.parametrize('text', ['', 'not json', '{}', '[1, 2]'])
    def test_unparsable(self, text):
        assert parse_route_tables(text) == {}

    def test_get_route_tables(self):
        grade = MagicMock()
        grade.test.return_value = (fixture('route_tables_r2.json'), 0)
        assert '102' in get_route_tables(grade, 'r2')
        assert grade.test.call_args.args == ('r2', ROUTE_TABLES_CMD)
        assert grade.test.call_args.kwargs == {'step': 1, 'allow_error': True}
        grade.test.return_value = ('', 1)
        assert get_route_tables(grade, 'r2') == {}


# ---------------------------------------------------------------------------
# rules selecting a mark
# ---------------------------------------------------------------------------


class TestFwmarkRules:
    @pytest.mark.parametrize('name', ['rule_r3_fwmark.json', 'rule_r4_fwmark.json'])
    def test_fwmark_rule(self, name):
        assert fwmark_rules(rules(name)) == [{'mark': 2, 'mask': FULL_MASK, 'table': '102', 'priority': 1000}]
        assert tables_of_mark(rules(name), 2) == ['102']
        assert tables_of_mark(rules(name), 3) == []

    @pytest.mark.parametrize('name', ['rule_untouched.json', 'rule_r1_source_named.json', 'rule_r2_addresses.json',
                                      'rule_r6_l3mdev.json'])
    def test_no_fwmark_rule(self, name):
        assert fwmark_rules(rules(name)) == []

    def test_mask_in_the_value_or_in_its_own_key(self):
        in_value = fwmark_rules([{'priority': 5, 'fwmark': '0x2/0xff', 'table': 'isp2'}])
        own_key = fwmark_rules([{'priority': 5, 'fwmark': '0x2', 'fwmask': '0xff', 'table': 'isp2'}])
        assert in_value == own_key == [{'mark': 2, 'mask': 0xff, 'table': 'isp2', 'priority': 5}]
        assert rule_selects_mark(in_value[0], 0x102) and not rule_selects_mark(in_value[0], 3)

    def test_negated_or_tableless_rules_are_left_out(self):
        # wg-quick: `not from all fwmark 0xca6c lookup 51820`
        assert fwmark_rules([{'priority': 1, 'not': None, 'fwmark': '0xca6c', 'table': '51820'}]) == []
        assert fwmark_rules([{'priority': 1, 'fwmark': '0x2', 'action': 'blackhole'}]) == []
        assert fwmark_rules([{'priority': 1, 'fwmark': 'junk', 'table': '102'}]) == []
        assert fwmark_rules(None) == []

    def test_tables_by_priority(self):
        some = [{'priority': 2000, 'fwmark': '0x2', 'table': 'late'}, {'priority': 100, 'fwmark': '0x2', 'table': 'early'}]
        assert tables_of_mark(some, 2) == ['early', 'late']


class TestNftMarks:
    """What tc.nft_mark_rules reads in the rulesets of the lab (the reference solution of r3 with
    its output chain, plus the rules saving the mark in conntrack; the connmark of r4)."""

    def test_r3_constant_marks_by_hook(self):
        marks = tc.nft_mark_rules(tc.parse_nft_json(fixture('nft_r3_marks.json')))
        constant = {(m['hook'], m['mark'], m['dport']) for m in marks if m['mark'] is not None}
        assert constant == {('prerouting', 2, 8080), ('output', 2, 8080)}

    def test_r4_mark_restored_from_conntrack_has_no_constant(self):
        marks = tc.nft_mark_rules(tc.parse_nft_json(fixture('nft_r4_connmark.json')))
        assert [(m['hook'], m['mark']) for m in marks] == [('prerouting', None)]


# ---------------------------------------------------------------------------
# VRF devices
# ---------------------------------------------------------------------------


class TestVrfDevices:
    def test_two_vrfs(self):
        devices = vrf_devices(parse_ip_links_json(fixture('links_r6_vrf.json')))
        assert devices == {'vrf-blue': {'table': 10, 'up': True, 'ports': ['eth0', 'eth1']},
                           'vrf-red': {'table': 20, 'up': True, 'ports': ['eth2', 'eth3']}}
        assert vrf_of_port(devices, 'eth1') == 'vrf-blue' and vrf_of_port(devices, 'eth3') == 'vrf-red'
        assert vrf_of_port(devices, 'eth4') is None and vrf_of_port(devices, 'nope') is None

    def test_no_vrf(self):
        assert vrf_devices(parse_ip_links_json(fixture('links_r1.json'))) == {}
        assert vrf_devices([]) == {}

    def test_a_bridge_is_not_a_vrf(self):
        links = [{'ifname': 'br0', 'flags': ['UP'], 'linkinfo': {'info_kind': 'bridge'}},
                 {'ifname': 'eth0', 'flags': ['UP'], 'master': 'br0'},
                 {'ifname': 'vrf-x', 'flags': [], 'linkinfo': {'info_kind': 'vrf', 'info_data': {'table': 7}}}]
        assert vrf_devices(links) == {'vrf-x': {'table': 7, 'up': False, 'ports': []}}


# ---------------------------------------------------------------------------
# the spread probe
# ---------------------------------------------------------------------------


class TestSpread:
    def test_command(self):
        assert spread_cmd('198.18.199.1', 64) == \
            "seq 1 64 | xargs -P 8 -I {} curl -s -m 3 http://198.18.199.{}:80/"
        assert spread_cmd('10.0.0.200/24', 4, port=8080, parallel=2, timeout=5) == \
            "seq 200 203 | xargs -P 2 -I {} curl -s -m 5 http://10.0.0.{}:8080/"

    @pytest.mark.parametrize('first, count', [('10.0.0.200', 60), ('10.0.0.1', 0)])
    def test_command_refuses_to_leave_the_prefix(self, first, count):
        with pytest.raises(ValueError):
            spread_cmd(first, count)

    def test_multipath_spread(self):
        spread = parse_spread(fixture('spread_pc5_multipath.txt'))
        assert spread['servers'] == {f"198.18.199.{i}" for i in range(1, 65)}
        assert spread['clients'] == {'198.19.177.15': 47, '198.19.217.15': 17}

    def test_single_uplink(self):
        spread = parse_spread(fixture('spread_pc5_untouched.txt'))
        assert len(spread['servers']) == 64 and spread['clients'] == {'198.19.177.15': 64}

    @pytest.mark.parametrize('text', ['', None, 'curl: (28) Operation timed out\n'])
    def test_nothing_answered(self, text):
        assert parse_spread(text) == {'servers': set(), 'clients': {}}


# ---------------------------------------------------------------------------
# the pings of the VRF isolation, read with traceroute.parse_ping
# ---------------------------------------------------------------------------


class TestIsolationPings:
    def test_unreachable_default_answers_host_unreachable(self):
        ping = parse_ping(fixture('ping_red1_unreachable.txt'))
        assert ping['received'] == 0 and ping['from'] == '172.28.126.1'
        assert ping['error'] == 'Destination Host Unreachable'

    @pytest.mark.parametrize('name', ['ping_red1_silent.txt', 'ping_red1_no_gateway.txt'])
    def test_silence_without_it(self, name):
        ping = parse_ping(fixture(name))
        assert ping['received'] == 0 and ping['from'] is None and ping['error'] is None

    def test_leak_answers(self):
        assert parse_ping(fixture('ping_blue1_leak.txt'))['received'] == 1
