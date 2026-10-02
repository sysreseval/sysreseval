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


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------

import random  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from ipaddress import IPv6Address, IPv6Interface, IPv6Network  # noqa: E402

from ips import (  # noqa: E402
    IPv6Addresses,
    IPv6Networks,
    random_ipv6networks,
    random_ipv6s,
    random_ipv6s_with_range,
    random_ips_from_topology,
)

GUA = IPv6Network('2000::/3')
ULA = IPv6Network('fd00::/8')
DOC = IPv6Network('2001:db8::/32')


class TestIPv6Addresses:
    def test_set_get_and_type_check(self):
        ips = IPv6Addresses()
        ips.r = IPv6Interface('2001:db8::1/64')
        assert ips.r == IPv6Interface('2001:db8::1/64')
        for bad in ('2001:db8::1/64', IPv4Interface('10.0.0.1/24'), IPv6Network('2001:db8::/64')):
            with pytest.raises(TypeError, match='expected IPv6Interface'):
                ips.x = bad

    def test_roundtrips(self):
        ips = IPv6Addresses()
        ips.r = IPv6Interface('2001:db8::1/64')
        assert ips.to_dict() == {'r': '2001:db8::1/64'}
        assert IPv6Addresses.from_dict(ips.to_dict()).r == ips.r
        assert IPv6Addresses.from_json(ips.to_json()).r == ips.r
        assert IPv6Addresses.unpack(ips.pack()).r == ips.r

    def test_ipv4_container_unchanged(self):
        ips = IPv4Addresses()
        with pytest.raises(TypeError, match='expected IPv4Interface'):
            ips.r = IPv6Interface('2001:db8::1/64')


class TestIPv6Networks:
    def test_set_get_and_type_check(self):
        nets = IPv6Networks()
        nets.lan = IPv6Network('2001:db8::/64')
        for bad in ('2001:db8::/64', IPv4Network('10.0.0.0/24'), IPv6Interface('2001:db8::1/64')):
            with pytest.raises(TypeError, match='expected IPv6Network'):
                nets.x = bad

    def test_roundtrips(self):
        nets = IPv6Networks()
        nets.lan = IPv6Network('2001:db8::/64')
        assert IPv6Networks.from_dict(nets.to_dict()).lan == nets.lan
        assert IPv6Networks.from_json(nets.to_json()).lan == nets.lan
        assert IPv6Networks.unpack(nets.pack()).lan == nets.lan


class TestRandomIPv6Networks:
    def test_default_is_global_unicast(self):
        for _ in range(20):
            (net,) = random_ipv6networks(64)
            assert isinstance(net, IPv6Network) and net.prefixlen == 64 and net.subnet_of(GUA)

    def test_list_of_masks_disjoint(self):
        nets = random_ipv6networks([64, 48, 56])
        assert [n.prefixlen for n in nets] == [64, 48, 56]
        for i, a in enumerate(nets):
            for b in nets[i + 1:]:
                assert not a.overlaps(b)

    def test_from_network(self):
        for _ in range(20):
            (net,) = random_ipv6networks(64, from_network=DOC)
            assert net.subnet_of(DOC)

    def test_private_is_ula(self):
        for _ in range(20):
            a, b = random_ipv6networks([64, 48], from_private_network=True)
            assert a.subnet_of(ULA) and b.subnet_of(ULA) and not a.overlaps(b)

    def test_private_within_from_network(self):
        (net,) = random_ipv6networks(64, from_network=IPv6Network('fd12::/32'), from_private_network=True)
        assert net.subnet_of(IPv6Network('fd12::/32'))

    def test_exclude(self):
        space = IPv6Network('2001:db8::/46')
        excluded = [IPv6Network('2001:db8::/48'), IPv6Network('2001:db8:1::/48'), IPv6Network('2001:db8:2::/48')]
        for _ in range(10):
            (net,) = random_ipv6networks(48, from_network=space, exclude=excluded)
            assert net == IPv6Network('2001:db8:3::/48')

    def test_exclude_other_family_is_ignored(self):
        (net,) = random_ipv6networks(64, from_network=DOC, exclude=[IPv4Network('10.0.0.0/8')])
        assert net.subnet_of(DOC)

    def test_impossible(self):
        with pytest.raises(ValueError):
            random_ipv6networks(48, from_network=IPv6Network('2001:db8::/56'))
        with pytest.raises(ValueError):
            random_ipv6networks(48, from_network=IPv6Network('2001:db8::/46'),
                                exclude=[IPv6Network('2001:db8::/46')])

    def test_huge_index_space_does_not_overflow(self):
        (net,) = random_ipv6networks([120], from_network=IPv6Network('::/0'))
        assert net.prefixlen == 120

    def test_mask_out_of_range(self):
        with pytest.raises(ValueError, match='out of range'):
            random_ipv6networks(129)
        with pytest.raises(ValueError, match='out of range'):
            random_ipv4networks(33)

    def test_family_guards(self):
        with pytest.raises(ValueError, match='expected an IPv4 network'):
            random_ipv4networks(64, from_network=DOC)
        with pytest.raises(ValueError, match='expected an IPv6 network'):
            random_ipv6networks(24, from_network=IPv4Network('10.0.0.0/8'))

    def test_reproducible_with_seed(self):
        random.seed(7)
        a = random_ipv6networks([64, 64], from_private_network=True)
        random.seed(7)
        assert random_ipv6networks([64, 64], from_private_network=True) == a


class TestRandomIPv6s:
    NET = IPv6Network('2001:db8:1::/64')

    def test_count_type_membership_prefix_distinct(self):
        ips = random_ipv6s(self.NET, 5)
        assert len(ips) == 5 and len(set(ips)) == 5
        for ip in ips:
            assert isinstance(ip, IPv6Interface) and ip.ip in self.NET and ip.network == self.NET

    def test_anycast_offset_zero_never_returned(self):
        small = IPv6Network('2001:db8::/120')
        for _ in range(30):
            assert all(ip.ip != small.network_address for ip in random_ipv6s(small, 10))
        for _ in range(50):
            assert random_ipv6s(self.NET, 1)[0].ip != self.NET.network_address

    def test_slash_126_uses_offsets_1_to_3(self):
        net = IPv6Network('2001:db8::/126')
        got = sorted(random_ipv6s(net, 3), key=lambda i: int(i.ip))
        assert got == [IPv6Interface('2001:db8::1/126'), IPv6Interface('2001:db8::2/126'),
                       IPv6Interface('2001:db8::3/126')]
        with pytest.raises(ValueError, match='Not enough'):
            random_ipv6s(net, 4)

    def test_slash_127_and_128(self):
        assert set(random_ipv6s(IPv6Network('2001:db8::/127'), 2)) == {
            IPv6Interface('2001:db8::/127'), IPv6Interface('2001:db8::1/127')}
        assert random_ipv6s(IPv6Network('2001:db8::1/128'), 1) == [IPv6Interface('2001:db8::1/128')]

    def test_exclusions(self):
        net = IPv6Network('2001:db8::/120')
        ex_ips = [IPv6Interface(f'2001:db8::{i:x}/120') for i in range(1, 200)]
        for _ in range(10):
            ips = random_ipv6s(net, 5, exclude_ips=ex_ips, exclude_nets=[IPv6Network('2001:db8::c8/125')])
            assert all(int(ip.ip) >= 0xd0 for ip in ips)

    def test_zero_and_too_many(self):
        assert random_ipv6s(self.NET, 0) == []
        with pytest.raises(ValueError):
            random_ipv6s(IPv6Network('2001:db8::/126'), 10)

    def test_family_guards(self):
        with pytest.raises(ValueError, match='expected an IPv6 network'):
            random_ipv6s(IPv4Network('10.0.0.0/24'))
        with pytest.raises(ValueError, match='expected an IPv4 network'):
            random_ipv4s(self.NET)

    def test_reproducible_with_seed(self):
        random.seed(11)
        a = random_ipv6s(self.NET, 3)
        random.seed(11)
        assert random_ipv6s(self.NET, 3) == a


class TestRandomIPv6sWithRange:
    @pytest.mark.parametrize('net', [IPv6Network('2001:db8::/64'), IPv6Network('2001:db8::/120')])
    def test_structure(self, net):
        for _ in range(10):
            res = random_ipv6s_with_range(net, 10, 3)
            assert len(res) == 5 and all(isinstance(i, IPv6Interface) for i in res)
            lo, hi = res[0], res[1]
            assert int(hi.ip) - int(lo.ip) == 10
            for extra in res[2:]:
                assert not (int(lo.ip) <= int(extra.ip) <= int(hi.ip))
                assert extra.ip in net

    def test_family_guard(self):
        with pytest.raises(ValueError, match='expected an IPv6 network'):
            random_ipv6s_with_range(IPv4Network('10.0.0.0/24'), 5)


class TestRandomIpsFromTopology:
    TOPO = {'lan': ['r', 'pc'], 'wan': ['r', 'srv']}

    def _data(self):
        from SRE.lib_sre import Data0

        @dataclass(slots=True)
        class _D(Data0):
            x: int = 0

        d = _D()
        d.nets.lan, d.nets.wan = IPv4Network('10.0.0.0/24'), IPv4Network('10.1.0.0/24')
        d.nets6.lan, d.nets6.wan = IPv6Network('fd00:a::/64'), IPv6Network('fd00:b::/64')
        return d

    def test_default_fills_ipv4_only(self):
        d = self._data()
        random_ips_from_topology(d, self.TOPO)
        assert set(d.ips.__dict__) == {'r_lan', 'r_wan', 'pc', 'srv'}
        assert d.ips.pc.network == d.nets.lan and d.ips.r_wan.network == d.nets.wan
        assert d.ips6.__dict__ == {}

    def test_ipv6_fills_both(self):
        d = self._data()
        random_ips_from_topology(d, self.TOPO, ipv6=True)
        assert set(d.ips.__dict__) == {'r_lan', 'r_wan', 'pc', 'srv'}
        assert set(d.ips6.__dict__) == {'r_lan', 'r_wan', 'pc', 'srv'}
        assert isinstance(d.ips6.pc, IPv6Interface) and d.ips6.pc.network == d.nets6.lan
        assert d.ips6.r_lan != d.ips6.pc

    def test_ipv6_only(self):
        d = self._data()
        random_ips_from_topology(d, self.TOPO, ipv4=False, ipv6=True)
        assert d.ips.__dict__ == {} and set(d.ips6.__dict__) == {'r_lan', 'r_wan', 'pc', 'srv'}

    def test_missing_network_raises(self):
        d = self._data()
        del d.nets6.__dict__['wan']
        with pytest.raises(AttributeError, match="nets6 has no network 'wan'"):
            random_ips_from_topology(d, self.TOPO, ipv6=True)
        with pytest.raises(ValueError):
            random_ips_from_topology(d, self.TOPO, ipv4=False, ipv6=False)
