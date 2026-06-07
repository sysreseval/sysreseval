"""Tests for lib/ips.py — IPv4Addresses, IPv4Networks, random_ipv4networks,
random_ipv4s, random_ipv4s_with_range."""
import sys
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from netaddr import EUI

from ips import (
    IPv4Addresses,
    IPv4Networks,
    random_ipv4networks,
    random_ipv4s,
    random_ipv4s_with_range,
    random_mac_address,
)


# ---------------------------------------------------------------------------
# IPv4Addresses
# ---------------------------------------------------------------------------

class TestIPv4Addresses:
    def test_set_and_get(self):
        ips = IPv4Addresses()
        ips.router = IPv4Interface('10.0.0.1/24')
        assert ips.router == IPv4Interface('10.0.0.1/24')

    def test_rejects_non_interface(self):
        ips = IPv4Addresses()
        with pytest.raises(TypeError):
            ips.bad = IPv4Address('10.0.0.1')

    def test_rejects_string(self):
        ips = IPv4Addresses()
        with pytest.raises(TypeError):
            ips.bad = '10.0.0.1/24'

    def test_rejects_network(self):
        ips = IPv4Addresses()
        with pytest.raises(TypeError):
            ips.bad = IPv4Network('10.0.0.0/24')

    def test_multiple_attributes(self):
        ips = IPv4Addresses()
        ips.a = IPv4Interface('1.2.3.4/8')
        ips.b = IPv4Interface('5.6.7.8/16')
        assert len(ips.__dict__) == 2

    # dict round-trip
    def test_to_dict_values_are_strings(self):
        ips = IPv4Addresses()
        ips.x = IPv4Interface('192.168.1.1/24')
        assert ips.to_dict() == {'x': '192.168.1.1/24'}

    def test_from_dict_round_trip(self):
        ips = IPv4Addresses()
        ips.x = IPv4Interface('192.168.1.1/24')
        ips.y = IPv4Interface('10.0.0.1/8')
        restored = IPv4Addresses.from_dict(ips.to_dict())
        assert restored.x == ips.x
        assert restored.y == ips.y

    def test_from_dict_empty(self):
        obj = IPv4Addresses.from_dict({})
        assert obj.__dict__ == {}

    # JSON round-trip
    def test_json_round_trip(self):
        ips = IPv4Addresses()
        ips.gw = IPv4Interface('172.16.0.1/12')
        assert IPv4Addresses.from_json(ips.to_json()).gw == ips.gw

    def test_to_json_is_valid_json(self):
        import json
        ips = IPv4Addresses()
        ips.a = IPv4Interface('1.1.1.1/32')
        obj = json.loads(ips.to_json())
        assert obj == {'a': '1.1.1.1/32'}

    # msgpack round-trip
    def test_msgpack_round_trip(self):
        ips = IPv4Addresses()
        ips.gw = IPv4Interface('10.1.2.3/24')
        blob = ips.pack()
        assert isinstance(blob, bytes)
        restored = IPv4Addresses.unpack(blob)
        assert restored.gw == ips.gw


# ---------------------------------------------------------------------------
# IPv4Networks
# ---------------------------------------------------------------------------

class TestIPv4Networks:
    def test_set_and_get(self):
        nets = IPv4Networks()
        nets.lan = IPv4Network('10.0.0.0/24')
        assert nets.lan == IPv4Network('10.0.0.0/24')

    def test_rejects_interface(self):
        nets = IPv4Networks()
        with pytest.raises(TypeError):
            nets.bad = IPv4Interface('10.0.0.1/24')

    def test_rejects_string(self):
        nets = IPv4Networks()
        with pytest.raises(TypeError):
            nets.bad = '10.0.0.0/24'

    def test_rejects_address(self):
        nets = IPv4Networks()
        with pytest.raises(TypeError):
            nets.bad = IPv4Address('10.0.0.1')

    def test_multiple_attributes(self):
        nets = IPv4Networks()
        nets.lan = IPv4Network('10.0.0.0/24')
        nets.mgmt = IPv4Network('172.16.0.0/16')
        assert len(nets.__dict__) == 2

    # dict round-trip
    def test_to_dict_values_are_strings(self):
        nets = IPv4Networks()
        nets.lan = IPv4Network('192.168.0.0/24')
        assert nets.to_dict() == {'lan': '192.168.0.0/24'}

    def test_from_dict_round_trip(self):
        nets = IPv4Networks()
        nets.lan  = IPv4Network('10.0.0.0/24')
        nets.mgmt = IPv4Network('172.16.0.0/12')
        restored = IPv4Networks.from_dict(nets.to_dict())
        assert restored.lan  == nets.lan
        assert restored.mgmt == nets.mgmt

    def test_from_dict_empty(self):
        obj = IPv4Networks.from_dict({})
        assert obj.__dict__ == {}

    # JSON round-trip
    def test_json_round_trip(self):
        nets = IPv4Networks()
        nets.wan = IPv4Network('8.8.8.0/24')
        assert IPv4Networks.from_json(nets.to_json()).wan == nets.wan

    # msgpack round-trip
    def test_msgpack_round_trip(self):
        nets = IPv4Networks()
        nets.lan = IPv4Network('192.168.1.0/24')
        blob = nets.pack()
        assert isinstance(blob, bytes)
        restored = IPv4Networks.unpack(blob)
        assert restored.lan == nets.lan


# ---------------------------------------------------------------------------
# random_ipv4networks
# ---------------------------------------------------------------------------

_PRIVATE = [
    IPv4Network('10.0.0.0/8'),
    IPv4Network('172.16.0.0/12'),
    IPv4Network('192.168.0.0/16'),
]


class TestRandomIPv4Networks:
    def test_single_int_mask_returns_one(self):
        result = random_ipv4networks(24)
        assert len(result) == 1
        assert isinstance(result[0], IPv4Network)
        assert result[0].prefixlen == 24

    def test_list_of_masks_returns_one_per_mask(self):
        result = random_ipv4networks([24, 16, 8])
        assert len(result) == 3
        assert [n.prefixlen for n in result] == [24, 16, 8]

    def test_results_are_disjoint(self):
        for _ in range(10):
            nets = random_ipv4networks([24, 24, 24])
            for i, a in enumerate(nets):
                for b in nets[i+1:]:
                    assert not a.overlaps(b)

    def test_from_network_constrains_results(self):
        container = IPv4Network('10.0.0.0/22')  # 4 /24s
        for _ in range(5):
            nets = random_ipv4networks([24, 24], from_network=container)
            for n in nets:
                assert n.subnet_of(container)

    def test_exclude_not_overlapped(self):
        excluded = IPv4Network('10.0.1.0/24')
        container = IPv4Network('10.0.0.0/22')  # 4 /24s: .0, .1, .2, .3
        for _ in range(5):
            nets = random_ipv4networks([24], from_network=container, exclude=[excluded])
            assert not nets[0].overlaps(excluded)

    def test_from_private_network_stays_private(self):
        for _ in range(20):
            nets = random_ipv4networks([24], from_private_network=True)
            assert any(nets[0].subnet_of(p) for p in _PRIVATE)

    def test_multiple_private_networks_disjoint(self):
        for _ in range(10):
            nets = random_ipv4networks([24, 24, 24], from_private_network=True)
            for i, a in enumerate(nets):
                for b in nets[i+1:]:
                    assert not a.overlaps(b)

    def test_impossible_raises(self):
        # /24 does not fit inside a /25
        with pytest.raises(ValueError):
            random_ipv4networks([24], from_network=IPv4Network('10.0.0.0/25'))

    def test_exclude_all_raises(self):
        # Only one /24 in 10.0.0.0/24; exclude it → nothing left
        with pytest.raises(ValueError):
            random_ipv4networks([24], from_network=IPv4Network('10.0.0.0/24'),
                                 exclude=[IPv4Network('10.0.0.0/24')])

    def test_reproducible_with_seed(self):
        import random as _r
        _r.seed(99)
        r1 = random_ipv4networks([24, 16], from_private_network=True)
        _r.seed(99)
        r2 = random_ipv4networks([24, 16], from_private_network=True)
        assert r1 == r2


# ---------------------------------------------------------------------------
# random_ipv4s
# ---------------------------------------------------------------------------

class TestRandomIPv4s:
    def test_returns_n_addresses(self):
        net = IPv4Network('10.0.0.0/24')
        assert len(random_ipv4s(net, 5)) == 5

    def test_default_n_is_1(self):
        net = IPv4Network('10.0.0.0/24')
        assert len(random_ipv4s(net)) == 1

    def test_all_ipv4interface(self):
        net = IPv4Network('10.0.0.0/24')
        for ip in random_ipv4s(net, 10):
            assert isinstance(ip, IPv4Interface)

    def test_all_in_network(self):
        net = IPv4Network('10.0.0.0/24')
        for ip in random_ipv4s(net, 20):
            assert ip in net

    def test_prefixlen_matches(self):
        net = IPv4Network('192.168.5.0/28')
        for ip in random_ipv4s(net, 5):
            assert ip.network.prefixlen == 28

    def test_all_distinct(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s(net, 50)
        assert len(set(result)) == 50

    def test_exclude_ips_not_returned(self):
        net = IPv4Network('10.0.0.0/24')
        excluded = [IPv4Interface('10.0.0.1/24'), IPv4Interface('10.0.0.2/24')]
        for _ in range(20):
            result = random_ipv4s(net, 10, exclude_ips=excluded)
            for ip in result:
                assert ip not in excluded

    def test_exclude_nets_not_returned(self):
        net = IPv4Network('10.0.0.0/24')
        excluded_net = IPv4Network('10.0.0.128/25')
        for _ in range(5):
            result = random_ipv4s(net, 10, exclude_nets=[excluded_net])
            for ip in result:
                assert ip not in excluded_net

    def test_not_enough_raises(self):
        # /30 has 2 usable host addresses; asking for 5 should fail
        net = IPv4Network('10.0.0.0/30')
        with pytest.raises(ValueError, match="Not enough"):
            random_ipv4s(net, 5)

    def test_slash30_no_network_or_broadcast(self):
        # /30: only offsets 1 and 2 are valid hosts
        net = IPv4Network('10.0.0.0/30')
        network_addr = IPv4Interface('10.0.0.0/30')
        broadcast_addr = IPv4Interface('10.0.0.3/30')
        for _ in range(20):
            result = random_ipv4s(net, 2)
            assert network_addr not in result
            assert broadcast_addr not in result

    def test_slash28_no_network_or_broadcast(self):
        net = IPv4Network('10.0.1.0/28')  # 16 addresses, .0 and .15 are reserved
        network_addr = IPv4Interface('10.0.1.0/28')
        broadcast_addr = IPv4Interface('10.0.1.15/28')
        for _ in range(10):
            result = random_ipv4s(net, 10)
            assert network_addr not in result
            assert broadcast_addr not in result

    def test_slash31_both_addresses_usable(self):
        # /31 (RFC 3021): no reserved addresses, both should be reachable
        net = IPv4Network('10.0.0.0/31')
        result = random_ipv4s(net, 2)
        assert len(result) == 2

    def test_slash32_single_address(self):
        net = IPv4Network('10.0.0.1/32')
        result = random_ipv4s(net, 1)
        assert result == [IPv4Interface('10.0.0.1/32')]

    def test_n_zero_returns_empty(self):
        net = IPv4Network('10.0.0.0/24')
        assert random_ipv4s(net, 0) == []

    def test_reproducible_with_seed(self):
        import random as _r
        net = IPv4Network('10.0.0.0/24')
        _r.seed(7)
        r1 = random_ipv4s(net, 5)
        _r.seed(7)
        r2 = random_ipv4s(net, 5)
        assert r1 == r2


# ---------------------------------------------------------------------------
# random_ipv4s_with_range (helper)
# ---------------------------------------------------------------------------

def addr(iface: IPv4Interface) -> int:
    """Integer value of the host address in an IPv4Interface."""
    return int(iface.ip)


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------

class TestReturnStructure:
    def test_returns_n_plus_2(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=5, n=3)
        assert len(result) == 5

    def test_default_n_returns_3(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=5)
        assert len(result) == 3

    def test_all_are_ipv4interface(self):
        net = IPv4Network('10.0.0.0/24')
        for ip in random_ipv4s_with_range(net, gap=4, n=2):
            assert isinstance(ip, IPv4Interface)

    def test_all_in_network(self):
        net = IPv4Network('10.0.0.0/24')
        for ip in random_ipv4s_with_range(net, gap=4, n=5):
            assert ip in net

    def test_prefixlen_matches_network(self):
        net = IPv4Network('192.168.1.0/28')
        for ip in random_ipv4s_with_range(net, gap=3, n=2):
            assert ip.network.prefixlen == 28

    def test_all_distinct(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=4, n=10)
        assert len(set(result)) == len(result)


# ---------------------------------------------------------------------------
# ip1 / ip2 contract
# ---------------------------------------------------------------------------

class TestIp1Ip2Contract:
    def test_ip1_less_than_ip2(self):
        net = IPv4Network('10.0.0.0/24')
        for _ in range(20):
            ip1, ip2, *_ = random_ipv4s_with_range(net, gap=5, n=1)
            assert addr(ip1) < addr(ip2)

    def test_exact_gap(self):
        net = IPv4Network('10.0.0.0/24')
        for gap in (1, 2, 5, 10, 50):
            ip1, ip2, *_ = random_ipv4s_with_range(net, gap=gap, n=1)
            assert addr(ip2) - addr(ip1) == gap

    def test_gap_1_means_adjacent(self):
        net = IPv4Network('10.0.0.0/24')
        for _ in range(10):
            ip1, ip2, *_ = random_ipv4s_with_range(net, gap=1, n=0)
            assert addr(ip2) - addr(ip1) == 1


# ---------------------------------------------------------------------------
# Extras not in the (ip1, ip2) interval
# ---------------------------------------------------------------------------

class TestExtrasOutsideInterval:
    def _check(self, net, gap, n, repeat=5):
        for _ in range(repeat):
            result = random_ipv4s_with_range(net, gap=gap, n=n)
            ip1, ip2 = result[0], result[1]
            lo, hi = addr(ip1), addr(ip2)
            for extra in result[2:]:
                v = addr(extra)
                assert not (lo < v < hi), (
                    f"extra {extra} is inside ({ip1}, {ip2})"
                )

    def test_extras_outside_small_gap(self):
        self._check(IPv4Network('10.0.0.0/24'), gap=3, n=5)

    def test_extras_outside_large_gap(self):
        self._check(IPv4Network('10.0.0.0/24'), gap=100, n=5)

    def test_extras_outside_gap_equal_to_1(self):
        # gap=1: no address strictly between ip1 and ip2, but still check
        self._check(IPv4Network('10.0.0.0/24'), gap=1, n=5)

    def test_n_zero_returns_only_ip1_ip2(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=5, n=0)
        assert len(result) == 2
        ip1, ip2 = result
        assert addr(ip2) - addr(ip1) == 5


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------

class TestExclusions:
    def test_exclude_ips_not_returned(self):
        net = IPv4Network('10.0.0.0/24')
        excluded = [IPv4Interface('10.0.0.5/24'), IPv4Interface('10.0.0.10/24')]
        for _ in range(20):
            result = random_ipv4s_with_range(net, gap=3, n=5, exclude_ips=excluded)
            for ip in result:
                assert ip not in excluded

    def test_exclude_nets_not_returned(self):
        net = IPv4Network('10.0.0.0/24')
        excluded_net = IPv4Network('10.0.0.128/25')
        for _ in range(5):
            result = random_ipv4s_with_range(net, gap=5, n=5, exclude_nets=[excluded_net])
            for ip in result:
                assert ip not in excluded_net


# ---------------------------------------------------------------------------
# Edge cases and errors
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_gap_spans_almost_entire_network(self):
        # /29 = 8 addresses (0..7); gap=6 forces ip1=0, ip2=6 (only possibility)
        net = IPv4Network('10.0.0.0/29')
        ip1, ip2 = random_ipv4s_with_range(net, gap=6, n=0)
        assert addr(ip2) - addr(ip1) == 6

    def test_network_too_small_raises(self):
        # /30 = 4 addresses; gap=4 needs at least 5
        net = IPv4Network('10.0.0.0/30')
        with pytest.raises(ValueError, match="too small"):
            random_ipv4s_with_range(net, gap=4, n=0)

    def test_not_enough_extras_raises(self):
        # /29 = 8 addresses (0..7); gap=6 → ip1=0, ip2=6; forbidden=[0..6] → only 7 free
        # asking for 2 extras but only 1 address (7) is outside the forbidden zone
        net = IPv4Network('10.0.0.0/29')
        with pytest.raises(ValueError):
            random_ipv4s_with_range(net, gap=6, n=2)

    def test_reproducible_with_seed(self):
        import random
        net = IPv4Network('10.0.0.0/24')
        random.seed(42)
        r1 = random_ipv4s_with_range(net, gap=10, n=3)
        random.seed(42)
        r2 = random_ipv4s_with_range(net, gap=10, n=3)
        assert r1 == r2


# ---------------------------------------------------------------------------
# random_ipv4s_with_range — gap as a list
# ---------------------------------------------------------------------------

def _ranges(result, k):
    """Extract [(ip_min, ip_max), ...] for the first k pairs from result."""
    return [(result[2 * i], result[2 * i + 1]) for i in range(k)]


def _extras(result, k):
    """Extract the extra IPs after the k pairs."""
    return result[2 * k:]


class TestGapList:
    """Tests for random_ipv4s_with_range when gap is a list of ints (k > 1)."""

    def test_return_length(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=[5, 10], n=3)
        assert len(result) == 3 + 2 * 2  # n + 2*k

    def test_return_length_three_ranges(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=[3, 5, 7], n=2)
        assert len(result) == 2 + 2 * 3

    def test_all_are_ipv4interface(self):
        net = IPv4Network('10.0.0.0/24')
        for ip in random_ipv4s_with_range(net, gap=[4, 6], n=2):
            assert isinstance(ip, IPv4Interface)

    def test_all_in_network(self):
        net = IPv4Network('10.0.0.0/24')
        for ip in random_ipv4s_with_range(net, gap=[4, 6], n=5):
            assert ip in net

    def test_all_distinct(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=[5, 10], n=8)
        assert len(set(result)) == len(result)

    def test_exact_gaps(self):
        net = IPv4Network('10.0.0.0/24')
        for _ in range(10):
            result = random_ipv4s_with_range(net, gap=[3, 7], n=0)
            (mn1, mx1), (mn2, mx2) = _ranges(result, 2)
            assert addr(mx1) - addr(mn1) == 3
            assert addr(mx2) - addr(mn2) == 7

    def test_ranges_strictly_ordered(self):
        net = IPv4Network('10.0.0.0/24')
        for _ in range(10):
            result = random_ipv4s_with_range(net, gap=[5, 8], n=0)
            (mn1, mx1), (mn2, mx2) = _ranges(result, 2)
            assert addr(mx1) < addr(mn2)

    def test_three_ranges_all_ordered(self):
        net = IPv4Network('10.0.0.0/24')
        for _ in range(10):
            result = random_ipv4s_with_range(net, gap=[3, 5, 4], n=0)
            (mn1, mx1), (mn2, mx2), (mn3, mx3) = _ranges(result, 3)
            assert addr(mx1) < addr(mn2)
            assert addr(mx2) < addr(mn3)

    def test_extras_outside_all_ranges(self):
        net = IPv4Network('10.0.0.0/24')
        for _ in range(5):
            result = random_ipv4s_with_range(net, gap=[5, 10], n=6)
            ranges = _ranges(result, 2)
            for extra in _extras(result, 2):
                v = addr(extra)
                for mn, mx in ranges:
                    assert not (addr(mn) <= v <= addr(mx)), (
                        f"extra {extra} is inside range [{mn}, {mx}]"
                    )

    def test_n_zero_returns_only_pairs(self):
        net = IPv4Network('10.0.0.0/24')
        result = random_ipv4s_with_range(net, gap=[4, 6], n=0)
        assert len(result) == 4

    def test_prefixlen_matches_network(self):
        net = IPv4Network('192.168.1.0/26')
        result = random_ipv4s_with_range(net, gap=[3, 5], n=2)
        for ip in result:
            assert ip.network.prefixlen == 26

    def test_network_too_small_raises(self):
        # /28 = 16 addresses; gaps [8, 8] need at least 8+8+2 = 18
        net = IPv4Network('10.0.0.0/28')
        with pytest.raises(ValueError, match="too small"):
            random_ipv4s_with_range(net, gap=[8, 8], n=0)

    def test_exclude_ips_not_returned(self):
        net = IPv4Network('10.0.0.0/24')
        excluded = [IPv4Interface('10.0.0.5/24'), IPv4Interface('10.0.0.20/24')]
        for _ in range(20):
            result = random_ipv4s_with_range(net, gap=[3, 6], n=4, exclude_ips=excluded)
            for ip in result:
                assert ip not in excluded

    def test_exclude_nets_not_returned(self):
        net = IPv4Network('10.0.0.0/24')
        excluded_net = IPv4Network('10.0.0.192/26')
        for _ in range(5):
            result = random_ipv4s_with_range(net, gap=[4, 8], n=3, exclude_nets=[excluded_net])
            for ip in result:
                assert ip not in excluded_net

    def test_reproducible_with_seed(self):
        import random
        net = IPv4Network('10.0.0.0/24')
        random.seed(99)
        r1 = random_ipv4s_with_range(net, gap=[5, 10], n=3)
        random.seed(99)
        r2 = random_ipv4s_with_range(net, gap=[5, 10], n=3)
        assert r1 == r2

    def test_tight_fit_two_ranges(self):
        # /27 = 32 addresses (0..31); gaps [10, 10] minimum space = 10+10+2 = 22 <= 32
        # Only valid placement: s0 in [0, 9], s1 in [s0+11, 31-10]
        net = IPv4Network('10.0.0.0/27')
        for _ in range(10):
            result = random_ipv4s_with_range(net, gap=[10, 10], n=0)
            (mn1, mx1), (mn2, mx2) = _ranges(result, 2)
            assert addr(mx2) - addr(mn2) == 10
            assert addr(mx1) - addr(mn1) == 10
            assert addr(mx1) < addr(mn2)
            assert addr(mn1) >= int(net.network_address)
            assert addr(mx2) <= int(net.broadcast_address)


# ---------------------------------------------------------------------------
# random_mac_address
# ---------------------------------------------------------------------------

class TestRandomMacAddress:
    def test_returns_n_addresses(self):
        result = random_mac_address(n=5)
        assert len(result) == 5

    def test_default_n_is_1(self):
        result = random_mac_address()
        assert len(result) == 1

    def test_all_eui(self):
        for mac in random_mac_address(n=10):
            assert isinstance(mac, EUI)

    def test_all_distinct(self):
        result = random_mac_address(n=20)
        assert len(set(str(m) for m in result)) == 20

    def test_prefix_colon(self):
        prefix = '00:1a:2b'
        for mac in random_mac_address(prefix=prefix, n=10):
            parts = str(mac).split('-')  # netaddr EUI uses '-' by default
            assert parts[0].lower() == '00'
            assert parts[1].lower() == '1a'
            assert parts[2].lower() == '2b'

    def test_prefix_dash(self):
        prefix = 'aa-bb-cc'
        for mac in random_mac_address(prefix=prefix, n=5):
            parts = str(mac).split('-')
            assert parts[0].lower() == 'aa'
            assert parts[1].lower() == 'bb'
            assert parts[2].lower() == 'cc'

    def test_prefix_one_byte(self):
        for mac in random_mac_address(prefix='de', n=5):
            assert str(mac).split('-')[0].lower() == 'de'

    def test_prefix_full_6_bytes(self):
        prefix = '01:02:03:04:05:06'
        result = random_mac_address(prefix=prefix, n=1)
        assert len(result) == 1
        parts = str(result[0]).split('-')
        assert [p.lower() for p in parts] == ['01', '02', '03', '04', '05', '06']

    def test_prefix_full_6_bytes_n_gt_1_raises(self):
        with pytest.raises(ValueError):
            random_mac_address(prefix='01:02:03:04:05:06', n=2)

    def test_prefix_too_long_raises(self):
        with pytest.raises(ValueError):
            random_mac_address(prefix='01:02:03:04:05:06:07')

    def test_n_zero_returns_empty(self):
        assert random_mac_address(n=0) == []

    def test_reproducible_with_seed(self):
        import random as _r
        _r.seed(123)
        r1 = random_mac_address(n=5)
        _r.seed(123)
        r2 = random_mac_address(n=5)
        assert [str(m) for m in r1] == [str(m) for m in r2]

    def test_reproducible_with_prefix_and_seed(self):
        import random as _r
        _r.seed(55)
        r1 = random_mac_address(prefix='de:ad:be', n=3)
        _r.seed(55)
        r2 = random_mac_address(prefix='de:ad:be', n=3)
        assert [str(m) for m in r1] == [str(m) for m in r2]

    def test_no_prefix_never_multicast(self):
        for mac in random_mac_address(n=50):
            first_byte = int(str(mac).split('-')[0], 16)
            assert first_byte & 1 == 0, f"multicast MAC generated: {mac}"
