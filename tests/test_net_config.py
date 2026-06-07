"""Tests for lib/net_config.py — all public functions."""
import sys
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

# Make src/ and lib/ importable.
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

# Stub out Kathara before any SRE import so the test suite works without Docker.
for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
# Provide the two names lib_sre imports at module level.
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()

from types import SimpleNamespace

from net_config import (
    eval_net_config,
    get_ip_addresses,
    get_ip_forward,
    get_net_config_entry,
    get_net_config_from_topology,
    get_persistent_net_config_entry,
    get_routes,
    get_sysctl_conf,
    set_ip_forward,
    set_net_config_entry,
    set_persistent_net_config_entry,
    set_persistent_sysctl,
    set_sysctl,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_grade(responses: dict | None = None):
    """Return a mock Grade0-like object.

    responses: {command_string: (output, exit_code)}
    When a command is not found in responses, returns ('', 0).
    """
    grade = MagicMock()

    def _test(machine, cmd, step=1, allow_error=False):
        if responses is None:
            return ('', 0)
        return responses.get(cmd, ('', 0))

    grade.test.side_effect = _test
    return grade


def make_net_scheme():
    ns = MagicMock()
    ns.remount_proc_sys_done = {}
    return ns


# ---------------------------------------------------------------------------
# get_ip_addresses
# ---------------------------------------------------------------------------

IP_A_OUTPUT = """\
1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo
2: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.10/24 scope global eth0
    inet 10.0.0.1/8 scope global eth0
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 172.16.0.2/16 scope global eth1
"""

class TestGetIpAddresses:
    def test_normal_output(self):
        grade = make_grade({'ip a': (IP_A_OUTPUT, 0)})
        result = get_ip_addresses(grade, 'r1')
        assert 'lo' in result
        assert ('127.0.0.1', 8) in result['lo']
        assert ('192.168.1.10', 24) in result['eth0']
        assert ('10.0.0.1', 8) in result['eth0']
        assert ('172.16.0.2', 16) in result['eth1']

    def test_virtual_interface_name_stripped(self):
        grade = make_grade({'ip a': (IP_A_OUTPUT, 0)})
        result = get_ip_addresses(grade, 'r1')
        # eth0@if5 → eth0
        assert 'eth0' in result
        assert 'eth0@if5' not in result

    def test_addresses_sorted_prefix_desc_then_ip_asc(self):
        grade = make_grade({'ip a': (IP_A_OUTPUT, 0)})
        result = get_ip_addresses(grade, 'r1')
        eth0 = result['eth0']
        # /24 > /8, so 192.168.1.10/24 comes first
        assert eth0[0] == ('192.168.1.10', 24)
        assert eth0[1] == ('10.0.0.1', 8)

    def test_non_zero_exit_returns_empty(self):
        grade = make_grade({'ip a': ('some output', 1)})
        assert get_ip_addresses(grade, 'r1') == {}

    def test_empty_output_returns_empty(self):
        grade = make_grade({'ip a': ('', 0)})
        assert get_ip_addresses(grade, 'r1') == {}

    def test_step_forwarded(self):
        grade = make_grade()
        grade.test.side_effect = None
        grade.test.return_value = ('', 0)
        get_ip_addresses(grade, 'r1', step=3)
        grade.test.assert_called_once_with('r1', 'ip a', step=3)


# ---------------------------------------------------------------------------
# get_routes
# ---------------------------------------------------------------------------

IP_ROUTE_OUTPUT = """\
default via 10.0.0.1 dev eth0
192.168.1.0/24 via 10.0.0.2 dev eth0 metric 100
10.0.0.0/8 dev eth0
172.16.0.5 via 10.0.0.3 dev eth0
"""

class TestGetRoutes:
    def test_default_route(self):
        grade = make_grade({'ip route': (IP_ROUTE_OUTPUT, 0)})
        result = get_routes(grade, 'r1')
        assert ('0.0.0.0', 0) in result
        via, dev, metric = result[('0.0.0.0', 0)]
        assert via == '10.0.0.1'
        assert dev == 'eth0'
        assert metric == 0

    def test_network_route_with_metric(self):
        grade = make_grade({'ip route': (IP_ROUTE_OUTPUT, 0)})
        result = get_routes(grade, 'r1')
        via, dev, metric = result[('192.168.1.0', 24)]
        assert via == '10.0.0.2'
        assert metric == 100

    def test_direct_route_no_via(self):
        grade = make_grade({'ip route': (IP_ROUTE_OUTPUT, 0)})
        result = get_routes(grade, 'r1')
        via, dev, metric = result[('10.0.0.0', 8)]
        assert via == ''

    def test_host_route_mask_32(self):
        grade = make_grade({'ip route': (IP_ROUTE_OUTPUT, 0)})
        result = get_routes(grade, 'r1')
        assert ('172.16.0.5', 32) in result

    def test_non_zero_exit_returns_empty(self):
        grade = make_grade({'ip route': ('output', 1)})
        assert get_routes(grade, 'r1') == {}

    def test_empty_output_returns_empty(self):
        grade = make_grade({'ip route': ('', 0)})
        assert get_routes(grade, 'r1') == {}

    def test_step_forwarded(self):
        grade = make_grade()
        grade.test.side_effect = None
        grade.test.return_value = ('', 0)
        get_routes(grade, 'r1', step=2)
        grade.test.assert_called_once_with('r1', 'ip route', step=2)


# ---------------------------------------------------------------------------
# get_sysctl_conf
# ---------------------------------------------------------------------------

SYSCTL_CONF = """\
# comment line
; another comment
net.ipv4.ip_forward = 0
net.ipv6.conf.all.disable_ipv6=1

kernel.hostname = myhost
"""

SYSCTL_D = """\
net.ipv4.ip_forward=1
net.core.rmem_max = 212992
"""

class TestGetSysctlConf:
    def test_basic_parsing(self):
        grade = make_grade({
            'cat /etc/sysctl.conf': (SYSCTL_CONF, 0),
            'cat /etc/sysctl.d/*': ('', 0),
        })
        result = get_sysctl_conf(grade, 'r1')
        assert result['net.ipv4.ip_forward'] == '0'
        assert result['net.ipv6.conf.all.disable_ipv6'] == '1'
        assert result['kernel.hostname'] == 'myhost'

    def test_comments_and_blank_lines_ignored(self):
        grade = make_grade({
            'cat /etc/sysctl.conf': (SYSCTL_CONF, 0),
            'cat /etc/sysctl.d/*': ('', 0),
        })
        result = get_sysctl_conf(grade, 'r1')
        assert '# comment line' not in result
        assert '' not in result

    def test_sysctl_d_overrides_conf(self):
        grade = make_grade({
            'cat /etc/sysctl.conf': (SYSCTL_CONF, 0),
            'cat /etc/sysctl.d/*': (SYSCTL_D, 0),
        })
        result = get_sysctl_conf(grade, 'r1')
        # sysctl.d overrides: ip_forward should now be 1
        assert result['net.ipv4.ip_forward'] == '1'
        assert result['net.core.rmem_max'] == '212992'

    def test_non_zero_on_first_call_returns_empty(self):
        grade = make_grade({
            'cat /etc/sysctl.conf': ('', 1),
            'cat /etc/sysctl.d/*': (SYSCTL_D, 0),
        })
        assert get_sysctl_conf(grade, 'r1') == {}

    def test_non_zero_on_second_call_returns_empty(self):
        grade = make_grade({
            'cat /etc/sysctl.conf': (SYSCTL_CONF, 0),
            'cat /etc/sysctl.d/*': ('', 1),
        })
        assert get_sysctl_conf(grade, 'r1') == {}

    def test_step_forwarded(self):
        grade = make_grade()
        grade.test.side_effect = None
        grade.test.return_value = ('', 0)
        get_sysctl_conf(grade, 'r1', step=4)
        calls = grade.test.call_args_list
        assert all(c.kwargs.get('step') == 4 or c.args[2:] == (4,) for c in calls)


# ---------------------------------------------------------------------------
# get_net_config
# ---------------------------------------------------------------------------

_IP_A_STATIC = """\
1: lo: <LOOPBACK>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST>
    inet 192.168.1.1/24 scope global eth0
3: eth1: <BROADCAST>
    inet 10.0.0.1/24 scope global eth1
"""

_IP_A_DHCP = """\
1: lo: <LOOPBACK>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST>
    inet 192.168.1.50/24 dynamic scope global eth0
"""

_IP_A_NO_ADDR = """\
1: lo: <LOOPBACK>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST>
"""

_IP_LINK_ETH01 = """\
1: lo: <LOOPBACK>
2: eth0: <BROADCAST>
3: eth1: <BROADCAST>
"""

_IP_LINK_ETH0 = """\
1: lo: <LOOPBACK>
2: eth0: <BROADCAST>
"""

_IP_ROUTE_STATIC = """\
default via 192.168.1.254 dev eth0
10.10.0.0/16 via 10.0.0.254 dev eth1
"""


def _make_grade_for_net_config(ip_a, ip_route, ip_link):
    """Build a grade mock whose test() dispatches by command string."""
    def _test(machine, cmd, step=1, allow_error=False):
        if cmd == 'ip a':
            return (ip_a, 0)
        if cmd == 'ip route':
            return (ip_route, 0)
        if cmd == 'ip link show':
            return (ip_link, 0)
        return ('', 0)
    grade = MagicMock()
    grade.test.side_effect = _test
    return grade


class TestGetNetConfig:
    def test_static_interfaces(self):
        grade = _make_grade_for_net_config(_IP_A_STATIC, _IP_ROUTE_STATIC, _IP_LINK_ETH01)
        result = get_net_config_entry(grade, 'r1')
        assert len(result) == 2
        eth0_entry, eth1_entry = result
        assert isinstance(eth0_entry, tuple)
        assert isinstance(eth1_entry, tuple)

    def test_static_interface_addresses(self):
        grade = _make_grade_for_net_config(_IP_A_STATIC, '', _IP_LINK_ETH0)
        result = get_net_config_entry(grade, 'r1')
        ifaces, routes = result[0]
        assert IPv4Interface('192.168.1.1/24') in ifaces

    def test_dhcp_interface(self):
        grade = _make_grade_for_net_config(_IP_A_DHCP, '', _IP_LINK_ETH0)
        result = get_net_config_entry(grade, 'r1')
        assert result[0] == 'dhcp'

    def test_no_address_interface(self):
        grade = _make_grade_for_net_config(_IP_A_NO_ADDR, '', _IP_LINK_ETH0)
        result = get_net_config_entry(grade, 'r1')
        assert result[0] is None

    def test_routes_distributed(self):
        grade = _make_grade_for_net_config(_IP_A_STATIC, _IP_ROUTE_STATIC, _IP_LINK_ETH01)
        result = get_net_config_entry(grade, 'r1')
        # default route goes via 192.168.1.254 which is in eth0's network
        ifaces0, routes0 = result[0]
        route_nets = [str(net) for net, _ in routes0]
        assert '0.0.0.0/0' in route_nets

    def test_ip_link_failure_returns_empty(self):
        def _test(machine, cmd, step=1, allow_error=False):
            if cmd == 'ip link show':
                return ('', 1)
            return ('', 0)
        grade = MagicMock()
        grade.test.side_effect = _test
        assert get_net_config_entry(grade, 'r1') == []

    def test_no_eth_interfaces_returns_empty(self):
        def _test(machine, cmd, step=1, allow_error=False):
            if cmd == 'ip link show':
                return ('1: lo: <LOOPBACK>', 0)
            return ('', 0)
        grade = MagicMock()
        grade.test.side_effect = _test
        assert get_net_config_entry(grade, 'r1') == []


# ---------------------------------------------------------------------------
# get_persistent_net_config
# ---------------------------------------------------------------------------

_INTERFACES_STATIC = """\
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
    post-up ip route add 10.0.0.0/8 via 192.168.1.1
"""

# Same config without any indentation (ifupdown does not require it).
_INTERFACES_STATIC_NO_INDENT = """\
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
address 192.168.1.10/24
gateway 192.168.1.1
post-up ip route add 10.0.0.0/8 via 192.168.1.1
"""

# Mixed: tabs on some lines, spaces on others, nothing on the rest.
_INTERFACES_STATIC_MIXED_INDENT = """\
auto eth0
iface eth0 inet static
\taddress 192.168.1.10/24
  gateway 192.168.1.1
post-up ip route add 10.0.0.0/8 via 192.168.1.1
"""

# Real-world-style unindented with two extra static routes.
_INTERFACES_MULTI_ROUTE_NO_INDENT = """\
auto eth0
iface eth0 inet static
address 14.15.16.18/28
gateway 14.15.16.17
post-up ip route add 140.150.160.168/30 via 14.15.16.19
post-up ip route add 192.168.0.64/30 via 14.15.16.19
"""

_INTERFACES_DHCP = """\
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
"""

_INTERFACES_NETMASK = """\
auto eth0
iface eth0 inet static
    address 192.168.1.10
    netmask 255.255.255.0
"""

_INTERFACES_EXTRA_ADDR = """\
auto eth0
iface eth0 inet static
    address 192.168.1.10/24
    post-up ip addr add 192.168.1.20/24 dev eth0
"""

_INTERFACES_ERRORS = """\
bad_keyword
iface
iface eth0 inet static
    address not-an-ip
    gateway not-an-ip
    post-up ip route add 10.0.0.0/8 via not-an-ip
    post-up ip addr add not-an-ip dev eth0
    unknown_directive value
"""


def _make_grade_for_persistent(interfaces_main, interfaces_d=''):
    def _test(machine, cmd, step=1, allow_error=False):
        if cmd == 'cat /etc/network/interfaces':
            return (interfaces_main, 0) if interfaces_main is not None else ('', 1)
        if cmd == 'cat /etc/network/interfaces.d/*':
            return (interfaces_d, 0) if interfaces_d is not None else ('', 1)
        return ('', 0)
    grade = MagicMock()
    grade.test.side_effect = _test
    return grade


class TestGetPersistentNetConfig:
    def test_static_stanza(self):
        grade = _make_grade_for_persistent(_INTERFACES_STATIC)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert errors == 0
        assert len(result) == 1
        ifaces, routes = result[0]
        assert IPv4Interface('192.168.1.10/24') in ifaces

    def test_static_gateway_as_default_route(self):
        grade = _make_grade_for_persistent(_INTERFACES_STATIC)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        _, routes = result[0]
        default_routes = [(str(n), str(gw)) for n, gw in routes if str(n) == '0.0.0.0/0']
        assert default_routes == [('0.0.0.0/0', '192.168.1.1')]

    def test_static_post_up_route(self):
        grade = _make_grade_for_persistent(_INTERFACES_STATIC)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        _, routes = result[0]
        route_nets = [str(n) for n, _ in routes]
        assert '10.0.0.0/8' in route_nets

    def test_dhcp_stanza(self):
        grade = _make_grade_for_persistent(_INTERFACES_DHCP)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert errors == 0
        assert result[0] == 'dhcp'

    def test_netmask_combined_with_address(self):
        grade = _make_grade_for_persistent(_INTERFACES_NETMASK)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert errors == 0
        ifaces, _ = result[0]
        assert IPv4Interface('192.168.1.10/24') in ifaces

    def test_extra_address_post_up(self):
        grade = _make_grade_for_persistent(_INTERFACES_EXTRA_ADDR)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert errors == 0
        ifaces, _ = result[0]
        assert IPv4Interface('192.168.1.20/24') in ifaces

    def test_error_counting(self):
        grade = _make_grade_for_persistent(_INTERFACES_ERRORS)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert errors > 0

    def test_interfaces_d_merged(self):
        main = ('source /etc/network/interfaces.d/*\n'
                'auto eth0\niface eth0 inet static\n    address 192.168.1.1/24\n')
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent(main, extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert len(result) == 2
        assert result[1] == 'dhcp'

    def test_interfaces_d_ignored_without_source(self):
        main = 'auto eth0\niface eth0 inet static\n    address 192.168.1.1/24\n'
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent(main, extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert len(result) == 1

    def test_interfaces_d_with_source_directory(self):
        main = ('source-directory /etc/network/interfaces.d\n'
                'auto eth0\niface eth0 inet static\n    address 192.168.1.1/24\n')
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent(main, extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert len(result) == 2
        assert result[1] == 'dhcp'

    def test_interfaces_d_source_glob_with_extension(self):
        main = ('source /etc/network/interfaces.d/*.conf\n'
                'auto eth0\niface eth0 inet static\n    address 192.168.1.1/24\n')
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent(main, extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert len(result) == 2
        assert result[1] == 'dhcp'

    def test_interfaces_d_commented_source_ignored(self):
        main = ('# source /etc/network/interfaces.d/*\n'
                'auto eth0\niface eth0 inet static\n    address 192.168.1.1/24\n')
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent(main, extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert len(result) == 1

    def test_interfaces_d_unrelated_source_ignored(self):
        main = ('source /etc/other/interfaces\n'
                'auto eth0\niface eth0 inet static\n    address 192.168.1.1/24\n')
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent(main, extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert len(result) == 1

    def test_interfaces_d_indented_source_honored(self):
        main = ('   source /etc/network/interfaces.d/*\n'
                'auto eth0\niface eth0 inet static\n    address 192.168.1.1/24\n')
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent(main, extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert len(result) == 2
        assert result[1] == 'dhcp'

    def test_interfaces_d_empty_main_no_source(self):
        # Main file is empty/missing — interfaces.d alone should not be parsed.
        extra = 'auto eth1\niface eth1 inet dhcp\n'
        grade = _make_grade_for_persistent('', extra)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert result == []

    def test_auto_without_stanza_returns_none(self):
        src = 'auto eth0\n'
        grade = _make_grade_for_persistent(src)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert result[0] is None

    def test_both_files_fail_returns_empty(self):
        grade = _make_grade_for_persistent(None, None)
        result, errors = get_persistent_net_config_entry(grade, 'r1')
        assert result == []
        assert errors == 0


# ---------------------------------------------------------------------------
# get_persistent_net_config — error cases
# ---------------------------------------------------------------------------

def _perr(src, interfaces_d=''):
    """Shorthand: run get_persistent_net_config and return (result, errors)."""
    return get_persistent_net_config_entry(_make_grade_for_persistent(src, interfaces_d), 'r1')


class TestGetPersistentNetConfigErrors:

    # ---- misspelled / unknown directives -----------------------------------

    def test_misspelled_address(self):
        src = 'iface eth0 inet static\n    adress 192.168.1.1/24\n'
        _, errors = _perr(src)
        assert errors >= 1          # 'adress' is unknown → error

    def test_misspelled_gateway(self):
        src = 'iface eth0 inet static\n    address 192.168.1.1/24\n    gatway 192.168.1.254\n'
        _, errors = _perr(src)
        assert errors >= 1          # 'gatway' is unknown → error

    def test_misspelled_netmask(self):
        src = 'iface eth0 inet static\n    address 192.168.1.1\n    nettmask 255.255.255.0\n'
        _, errors = _perr(src)
        assert errors >= 1          # 'nettmask' is unknown → error

    def test_unknown_top_level_keyword(self):
        src = 'badkeyword eth0\niface eth0 inet static\n    address 192.168.1.1/24\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_unknown_stanza_directive(self):
        src = 'iface eth0 inet static\n    address 192.168.1.1/24\n    foobar value\n'
        _, errors = _perr(src)
        assert errors >= 1

    # ---- invalid IP / network values ---------------------------------------

    def test_invalid_address_value(self):
        src = 'iface eth0 inet static\n    address not-an-ip\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_address_out_of_range(self):
        src = 'iface eth0 inet static\n    address 300.1.2.3/24\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_invalid_gateway_value(self):
        src = 'iface eth0 inet static\n    address 192.168.1.1/24\n    gateway bad-gw\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_invalid_post_up_route_network(self):
        src = (
            'iface eth0 inet static\n'
            '    address 192.168.1.1/24\n'
            '    post-up ip route add notanet/24 via 192.168.1.254\n'
        )
        _, errors = _perr(src)
        assert errors >= 1

    def test_invalid_post_up_route_gateway(self):
        src = (
            'iface eth0 inet static\n'
            '    address 192.168.1.1/24\n'
            '    post-up ip route add 10.0.0.0/8 via notanip\n'
        )
        _, errors = _perr(src)
        assert errors >= 1

    def test_invalid_post_up_addr_add(self):
        src = (
            'iface eth0 inet static\n'
            '    address 192.168.1.1/24\n'
            '    post-up ip addr add notanip/24 dev eth0\n'
        )
        _, errors = _perr(src)
        assert errors >= 1

    # ---- missing values (bare directive with no argument) ------------------

    def test_address_keyword_alone(self):
        src = 'iface eth0 inet static\n    address\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_gateway_keyword_alone(self):
        src = 'iface eth0 inet static\n    address 192.168.1.1/24\n    gateway\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_netmask_keyword_alone(self):
        src = 'iface eth0 inet static\n    address 192.168.1.1\n    netmask\n'
        _, errors = _perr(src)
        assert errors >= 1

    # ---- incomplete iface line ---------------------------------------------

    def test_iface_line_too_short(self):
        # Missing method field
        src = 'iface eth0 inet\n    address 192.168.1.1/24\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_iface_line_only_name(self):
        src = 'iface eth0\n    address 192.168.1.1/24\n'
        _, errors = _perr(src)
        assert errors >= 1

    # ---- netmask forgotten (bare IP without prefix and no netmask) ---------

    def test_address_without_prefix_and_no_netmask_gives_none_entry(self):
        # No prefix, no netmask → primary has no prefix but netmask is None
        # The address is stored but without a valid prefix → result entry is
        # built with IPv4Interface('192.168.1.1') which defaults to /32.
        src = 'auto eth0\niface eth0 inet static\n    address 192.168.1.1\n'
        result, errors = _perr(src)
        # No error counted (not a parse error), but the prefix is /32 (bare IP default)
        assert errors == 0
        ifaces, _ = result[0]
        assert ifaces[0].network.prefixlen == 32

    def test_address_without_prefix_but_valid_netmask_resolves(self):
        src = 'auto eth0\niface eth0 inet static\n    address 192.168.1.10\n    netmask 255.255.0.0\n'
        result, errors = _perr(src)
        assert errors == 0
        ifaces, _ = result[0]
        assert ifaces[0].network.prefixlen == 16

    def test_address_without_prefix_invalid_netmask(self):
        src = 'auto eth0\niface eth0 inet static\n    address 192.168.1.10\n    netmask 999.999.999.999\n'
        _, errors = _perr(src)
        assert errors >= 1

    # ---- multiple errors accumulate ----------------------------------------

    def test_multiple_errors_accumulate(self):
        src = (
            'iface eth0 inet static\n'
            '    adress 1.2.3.4/24\n'       # misspelled address → 1 error
            '    gatway 1.2.3.1\n'           # misspelled gateway → 1 error
            '    nettmask 255.255.255.0\n'   # misspelled netmask → 1 error
        )
        _, errors = _perr(src)
        assert errors >= 3

    def test_invalid_address_does_not_suppress_other_errors(self):
        src = (
            'iface eth0 inet static\n'
            '    address bad-ip\n'           # error 1
            '    gateway also-bad\n'         # error 2
        )
        _, errors = _perr(src)
        assert errors >= 2

    # ---- errors do not bleed across stanzas --------------------------------

    def test_error_in_one_stanza_does_not_affect_other(self):
        src = (
            'iface eth0 inet static\n'
            '    address bad-ip\n'
            'iface eth1 inet static\n'
            '    address 10.0.0.1/8\n'
        )
        result, errors = _perr(src)
        assert errors >= 1
        # eth1 should still be parsed correctly
        eth1 = next((e for e in result if isinstance(e, tuple)), None)
        assert eth1 is not None
        ifaces, _ = eth1
        assert IPv4Interface('10.0.0.1/8') in ifaces

    # ---- directives inside loopback/dhcp stanzas are silently ignored ------

    def test_unknown_directive_in_loopback_not_counted(self):
        src = (
            'iface lo inet loopback\n'
            '    foobar value\n'             # inside loopback → ignored
            'iface eth0 inet static\n'
            '    address 192.168.1.1/24\n'
        )
        _, errors = _perr(src)
        assert errors == 0

    def test_unknown_directive_in_dhcp_not_counted(self):
        src = (
            'iface eth0 inet dhcp\n'
            '    foobar value\n'             # inside dhcp → ignored
        )
        _, errors = _perr(src)
        assert errors == 0

    # ---- unknown directive outside any stanza is still an error ------------

    def test_unknown_top_level_before_any_stanza_is_error(self):
        # 'badkeyword' before any iface line: not inside any stanza → error
        src = 'badkeyword eth0\niface eth0 inet static\n    address 1.2.3.4/24\n'
        _, errors = _perr(src)
        assert errors >= 1


# ---------------------------------------------------------------------------
# get_persistent_net_config — indentation-independent parsing
# ---------------------------------------------------------------------------

class TestGetPersistentNetConfigIndentation:
    """Verify that option lines within a stanza work with any indentation."""

    def test_no_indent_address_parsed(self):
        result, errors = _perr(_INTERFACES_STATIC_NO_INDENT)
        assert errors == 0
        ifaces, _ = result[0]
        assert IPv4Interface('192.168.1.10/24') in ifaces

    def test_no_indent_gateway_parsed(self):
        result, errors = _perr(_INTERFACES_STATIC_NO_INDENT)
        assert errors == 0
        _, routes = result[0]
        default_routes = [(str(n), str(gw)) for n, gw in routes if str(n) == '0.0.0.0/0']
        assert default_routes == [('0.0.0.0/0', '192.168.1.1')]

    def test_no_indent_post_up_route_parsed(self):
        result, errors = _perr(_INTERFACES_STATIC_NO_INDENT)
        assert errors == 0
        _, routes = result[0]
        assert '10.0.0.0/8' in [str(n) for n, _ in routes]

    def test_no_indent_matches_indented(self):
        result_indent, errors_indent = _perr(_INTERFACES_STATIC)
        result_no_indent, errors_no_indent = _perr(_INTERFACES_STATIC_NO_INDENT)
        assert errors_indent == errors_no_indent == 0
        # Same addresses and routes regardless of indentation
        ifaces_i, routes_i = result_indent[0]
        ifaces_n, routes_n = result_no_indent[0]
        assert set(str(x) for x in ifaces_i) == set(str(x) for x in ifaces_n)
        assert set((str(n), str(gw)) for n, gw in routes_i) == \
               set((str(n), str(gw)) for n, gw in routes_n)

    def test_mixed_indent_parsed(self):
        # Tabs on some lines, spaces on others, nothing on the rest
        result, errors = _perr(_INTERFACES_STATIC_MIXED_INDENT)
        assert errors == 0
        ifaces, routes = result[0]
        assert IPv4Interface('192.168.1.10/24') in ifaces
        assert any(str(n) == '0.0.0.0/0' for n, _ in routes)
        assert any(str(n) == '10.0.0.0/8' for n, _ in routes)

    def test_multi_route_no_indent(self):
        # The exact format from the bug report
        result, errors = _perr(_INTERFACES_MULTI_ROUTE_NO_INDENT)
        assert errors == 0
        ifaces, routes = result[0]
        assert IPv4Interface('14.15.16.18/28') in ifaces
        route_nets = [str(n) for n, _ in routes]
        assert '0.0.0.0/0' in route_nets
        assert '140.150.160.168/30' in route_nets
        assert '192.168.0.64/30' in route_nets

    def test_no_indent_loopback_options_ignored(self):
        # Non-indented lines inside a loopback stanza should still be ignored
        src = (
            'iface lo inet loopback\n'
            'foobar value\n'                 # no indent, inside loopback → ignored
            'iface eth0 inet static\n'
            'address 10.0.0.1/24\n'
        )
        result, errors = _perr(src)
        assert errors == 0
        ifaces, _ = result[0]
        assert IPv4Interface('10.0.0.1/24') in ifaces

    def test_no_indent_dhcp_options_ignored(self):
        src = (
            'iface eth0 inet dhcp\n'
            'foobar value\n'                 # no indent, inside dhcp → ignored
        )
        _, errors = _perr(src)
        assert errors == 0

    def test_no_indent_misspelled_directive_still_errors(self):
        src = 'iface eth0 inet static\nadress 192.168.1.1/24\n'
        _, errors = _perr(src)
        assert errors >= 1

    def test_no_indent_invalid_ip_still_errors(self):
        src = 'iface eth0 inet static\naddress not-an-ip\n'
        _, errors = _perr(src)
        assert errors >= 1


# ---------------------------------------------------------------------------
# eval_net_config
# ---------------------------------------------------------------------------

class TestEvalNetConfig:
    def _make(self, ips=('192.168.1.1/24',), routes=()):
        ifaces = [IPv4Interface(ip) for ip in ips]
        r = [(IPv4Network(n, strict=False), IPv4Address(gw)) for n, gw in routes]
        return [(ifaces, r)]

    def test_all_correct(self):
        nc = self._make(ips=('192.168.1.1/24',), routes=(('0.0.0.0/0', '192.168.1.254'),))
        res = eval_net_config(MagicMock(), nc, current=nc)
        assert res.ips == 1
        assert res.default_route == 1
        assert res.ips_expected == 1
        assert res.default_route_expected == 1

    def test_missing_ip(self):
        expected = self._make(ips=('192.168.1.1/24', '10.0.0.1/8'))
        current = self._make(ips=('192.168.1.1/24',))
        res = eval_net_config(MagicMock(), expected, current=current)
        assert res.ips == 1
        assert res.ips_expected == 2

    def test_wrong_route_counted(self):
        expected = self._make(routes=(('10.0.0.0/8', '192.168.1.1'),))
        current = self._make(routes=(('10.0.0.0/8', '192.168.1.1'), ('172.16.0.0/12', '192.168.1.1')))
        res = eval_net_config(MagicMock(), expected, current=current)
        assert res.other_routes == 1
        assert res.wrong_routes == 1

    def test_dhcp_matching(self):
        expected = ['dhcp', 'dhcp']
        current = ['dhcp', None]
        res = eval_net_config(MagicMock(), expected, current=current)
        assert res.dhcp_interfaces == 1
        assert res.dhcp_interfaces_expected == 2

    def test_none_interfaces_expected(self):
        expected = [None, None]
        current = [None, None]
        res = eval_net_config(MagicMock(), expected, current=current)
        assert res.none_interfaces_expected == 2

    def test_calls_get_net_config_when_current_none(self):
        nc = self._make()

        def _test(machine, cmd, step=1, allow_error=False):
            if cmd == 'ip link show':
                return ('2: eth0: <BROADCAST>', 0)
            if cmd == 'ip a':
                return ('2: eth0: <BROADCAST>\n    inet 192.168.1.1/24 scope global eth0\n', 0)
            return ('', 0)

        grade = MagicMock()
        grade.test.side_effect = _test
        # Should not raise even when current=None
        res = eval_net_config(grade, nc, machine_name='r1', current=None)
        assert isinstance(res.ips, int)

    def test_raises_when_both_current_and_machine_name_none(self):
        with pytest.raises(ValueError):
            eval_net_config(MagicMock(), [], current=None, machine_name=None)


# ---------------------------------------------------------------------------
# set_persistent_net_config
# ---------------------------------------------------------------------------

class TestSetPersistentNetConfig:
    def test_static_entry(self):
        ns = make_net_scheme()
        nc = [([IPv4Interface('192.168.1.1/24')],
               [(IPv4Network('0.0.0.0/0'), IPv4Address('192.168.1.254'))])]
        set_persistent_net_config_entry(ns, 'r1', nc)
        ns.file.assert_called_once()
        content = ns.file.call_args[0][2]
        assert 'iface eth0 inet static' in content
        assert 'address 192.168.1.1/24' in content
        assert 'gateway 192.168.1.254' in content

    def test_dhcp_entry(self):
        ns = make_net_scheme()
        set_persistent_net_config_entry(ns, 'r1', ['dhcp'])
        content = ns.file.call_args[0][2]
        assert 'iface eth0 inet dhcp' in content

    def test_none_entry_skipped(self):
        ns = make_net_scheme()
        set_persistent_net_config_entry(ns, 'r1', [None])
        content = ns.file.call_args[0][2]
        assert 'eth0' not in content

    def test_extra_addresses_as_post_up(self):
        ns = make_net_scheme()
        nc = [([IPv4Interface('192.168.1.1/24'), IPv4Interface('192.168.1.2/24')], [])]
        set_persistent_net_config_entry(ns, 'r1', nc)
        content = ns.file.call_args[0][2]
        assert 'post-up ip addr add 192.168.1.2/24 dev eth0' in content

    def test_non_default_route_as_post_up(self):
        ns = make_net_scheme()
        nc = [([IPv4Interface('192.168.1.1/24')],
               [(IPv4Network('10.0.0.0/8'), IPv4Address('192.168.1.254'))])]
        set_persistent_net_config_entry(ns, 'r1', nc)
        content = ns.file.call_args[0][2]
        assert 'post-up ip route add 10.0.0.0/8 via 192.168.1.254' in content

    def test_interface_numbering(self):
        ns = make_net_scheme()
        nc = [
            ([IPv4Interface('192.168.1.1/24')], []),
            'dhcp',
        ]
        set_persistent_net_config_entry(ns, 'r1', nc)
        content = ns.file.call_args[0][2]
        assert 'iface eth0 inet static' in content
        assert 'iface eth1 inet dhcp' in content


# ---------------------------------------------------------------------------
# set_net_config
# ---------------------------------------------------------------------------

class TestSetNetConfig:
    def test_static_cmds(self):
        ns = make_net_scheme()
        nc = [([IPv4Interface('192.168.1.1/24')],
               [(IPv4Network('0.0.0.0/0'), IPv4Address('192.168.1.254'))])]
        set_net_config_entry(ns, 'r1', nc)
        cmds = [c.args[1] for c in ns.cmd.call_args_list]
        assert 'ip link set eth0 up' in cmds
        assert 'ip addr add 192.168.1.1/24 dev eth0' in cmds
        assert 'ip route add 0.0.0.0/0 via 192.168.1.254' in cmds

    def test_dhcp_cmds(self):
        ns = make_net_scheme()
        set_net_config_entry(ns, 'r1', ['dhcp'])
        cmds = [c.args[1] for c in ns.cmd.call_args_list]
        assert 'ip link set eth0 up' in cmds
        assert 'dhclient eth0' in cmds

    def test_none_entry_skipped(self):
        ns = make_net_scheme()
        set_net_config_entry(ns, 'r1', [None])
        ns.cmd.assert_not_called()

    def test_interface_numbering(self):
        ns = make_net_scheme()
        nc = [None, ([IPv4Interface('10.0.0.1/8')], [])]
        set_net_config_entry(ns, 'r1', nc)
        cmds = [c.args[1] for c in ns.cmd.call_args_list]
        assert 'ip link set eth1 up' in cmds
        assert not any('eth0' in c for c in cmds)


# ---------------------------------------------------------------------------
# set_persistent_sysctl
# ---------------------------------------------------------------------------

class TestSetPersistentSysctl:
    def test_writes_conf_and_applies(self):
        ns = make_net_scheme()
        set_persistent_sysctl(ns, 'r1', {'net.ipv4.ip_forward': 1})
        cmds = [c.args[1] for c in ns.cmd.call_args_list]
        assert any('net.ipv4.ip_forward=1' in c for c in cmds)
        assert 'sysctl -p' in cmds
        assert 'mount -o rw,remount /proc/sys' in cmds

    def test_empty_config_no_cmds(self):
        ns = make_net_scheme()
        set_persistent_sysctl(ns, 'r1', {})
        ns.cmd.assert_not_called()

    def test_multiple_entries(self):
        ns = make_net_scheme()
        set_persistent_sysctl(ns, 'r1', {'a': 1, 'b': 2})
        cmds = [c.args[1] for c in ns.cmd.call_args_list]
        assert any('a=1' in c for c in cmds)
        assert any('b=2' in c for c in cmds)


# ---------------------------------------------------------------------------
# set_sysctl
# ---------------------------------------------------------------------------

class TestSetSysctl:
    def test_applies_with_mount(self):
        ns = make_net_scheme()
        set_sysctl(ns, 'r1', {'net.ipv4.ip_forward': 1})
        cmds = [c.args[1] for c in ns.cmd.call_args_list]
        assert 'mount -o rw,remount /proc/sys' in cmds
        assert 'sysctl -w net.ipv4.ip_forward=1' in cmds

    def test_empty_config_no_cmds(self):
        ns = make_net_scheme()
        set_sysctl(ns, 'r1', {})
        ns.cmd.assert_not_called()


# ---------------------------------------------------------------------------
# set_ip_forward
# ---------------------------------------------------------------------------

class TestSetIpForward:
    def test_enable(self):
        ns = make_net_scheme()
        set_ip_forward(ns, 'r1', True)
        ns.cmd.assert_called_with('r1', 'sysctl -w net.ipv4.ip_forward=1', step=1)
        assert ns.cmd.call_args_list[0] == call('r1', 'mount -o rw,remount /proc/sys')

    def test_disable(self):
        ns = make_net_scheme()
        set_ip_forward(ns, 'r1', False)
        ns.cmd.assert_called_with('r1', 'sysctl -w net.ipv4.ip_forward=0', step=1)
        assert ns.cmd.call_args_list[0] == call('r1', 'mount -o rw,remount /proc/sys')

    def test_custom_step(self):
        ns = make_net_scheme()
        set_ip_forward(ns, 'r1', True, step=3)
        ns.cmd.assert_called_with('r1', 'sysctl -w net.ipv4.ip_forward=1', step=3)
        assert ns.cmd.call_args_list[0] == call('r1', 'mount -o rw,remount /proc/sys')


# ---------------------------------------------------------------------------
# get_ip_forward
# ---------------------------------------------------------------------------

class TestGetIpForward:
    def test_returns_true_when_1(self):
        grade = make_grade({'cat /proc/sys/net/ipv4/ip_forward': ('1\n', 0)})
        assert get_ip_forward(grade, 'r1') is True

    def test_returns_false_when_0(self):
        grade = make_grade({'cat /proc/sys/net/ipv4/ip_forward': ('0\n', 0)})
        assert get_ip_forward(grade, 'r1') is False

    def test_returns_false_on_error(self):
        grade = make_grade({'cat /proc/sys/net/ipv4/ip_forward': ('', 1)})
        assert get_ip_forward(grade, 'r1') is False

    def test_step_forwarded(self):
        grade = make_grade()
        grade.test.side_effect = None
        grade.test.return_value = ('1', 0)
        get_ip_forward(grade, 'r1', step=5)
        grade.test.assert_called_once_with('r1', 'cat /proc/sys/net/ipv4/ip_forward', step=5)


# ---------------------------------------------------------------------------
# get_net_config_from_topology
# ---------------------------------------------------------------------------

def make_topology_net_scheme(ips: dict, nets: dict, topology: dict):
    """Return a minimal net_scheme mock for get_net_config_from_topology."""
    ns = MagicMock()
    ns.get_topology.return_value = topology
    ns.data = SimpleNamespace(
        ips=SimpleNamespace(**{k: IPv4Interface(v) for k, v in ips.items()}),
        nets=SimpleNamespace(**{k: IPv4Network(v) for k, v in nets.items()}),
    )
    return ns


def _all_routes(nc):
    """Return {net_str: gw_str} for all routes across every interface in a NetConfig."""
    result = {}
    for entry in nc:
        if isinstance(entry, tuple):
            _, routes = entry
            for net, gw in routes:
                result[str(net)] = str(gw)
    return result


# --- shared topology fixtures ---

_STAR_TOPOLOGY = {
    'lan': ['pc1', 'pc2', 'router'],
    'wan': ['router', 'server'],
}
_STAR_IPS = {
    'pc1':        '10.0.0.1/24',
    'pc2':        '10.0.0.2/24',
    'router_lan': '10.0.0.254/24',
    'router_wan': '10.1.0.254/24',
    'server':     '10.1.0.1/24',
}
_STAR_NETS = {'lan': '10.0.0.0/24', 'wan': '10.1.0.0/24'}

# pc1 — lan1 — r1 — mid — r2 — lan2 — pc2
_CHAIN_TOPOLOGY = {
    'lan1': ['pc1', 'r1'],
    'mid':  ['r1', 'r2'],
    'lan2': ['r2', 'pc2'],
}
_CHAIN_IPS = {
    'pc1':     '10.0.1.1/24',
    'r1_lan1': '10.0.1.254/24',
    'r1_mid':  '10.0.2.1/24',
    'r2_mid':  '10.0.2.254/24',
    'r2_lan2': '10.0.3.1/24',
    'pc2':     '10.0.3.2/24',
}
_CHAIN_NETS = {'lan1': '10.0.1.0/24', 'mid': '10.0.2.0/24', 'lan2': '10.0.3.0/24'}


class TestGetNetConfigFromTopology:

    # --- return structure ---

    def test_all_machines_returned(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        assert set(result.keys()) == {'pc1', 'pc2', 'router', 'server'}

    def test_each_value_is_list(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        for machine, nc in result.items():
            assert isinstance(nc, list), f"{machine}: expected list, got {type(nc)}"

    def test_single_net_machine_has_one_entry(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        assert len(result['pc1']) == 1
        assert result['pc1'][0] is not None

    def test_multinet_machine_has_two_entries(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        assert len(result['router']) == 2

    # --- topology=None delegates to net_scheme.get_topology() ---

    def test_topology_none_uses_get_topology(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns)
        ns.get_topology.assert_called_once()
        assert set(result.keys()) == {'pc1', 'pc2', 'router', 'server'}

    # --- eth index assignment ---

    def test_explicit_iface_index_honored(self):
        topology = {'lan': {'pc1': 2, 'router': 0}, 'wan': {'router': 1}}
        ips = {
            'pc1':        '10.0.0.1/24',
            'router_lan': '10.0.0.254/24',
            'router_wan': '10.1.0.254/24',
        }
        ns = make_topology_net_scheme(ips, _STAR_NETS, topology)
        result = get_net_config_from_topology(ns, topology)
        # pc1 declared at eth2 → list length 3, first two slots None
        assert len(result['pc1']) == 3
        assert result['pc1'][0] is None
        assert result['pc1'][1] is None
        assert result['pc1'][2] is not None

    def test_tuple_iface_spec_index_honored(self):
        topology = {'lan': {'pc1': (1, None), 'router': (0, None)}}
        ips = {'pc1': '10.0.0.1/24', 'router': '10.0.0.254/24'}
        ns = make_topology_net_scheme(ips, {'lan': '10.0.0.0/24'}, topology)
        result = get_net_config_from_topology(ns, topology)
        assert len(result['pc1']) == 2
        assert result['pc1'][0] is None
        assert result['pc1'][1] is not None

    def test_dict_topology_none_iface_auto_assigned(self):
        topology = {'lan': {'pc1': None, 'router': None}, 'wan': {'router': None}}
        ips = {
            'pc1':        '10.0.0.1/24',
            'router_lan': '10.0.0.254/24',
            'router_wan': '10.1.0.254/24',
        }
        ns = make_topology_net_scheme(ips, _STAR_NETS, topology)
        result = get_net_config_from_topology(ns, topology)
        assert len(result['pc1']) == 1
        assert len(result['router']) == 2

    # --- IP addresses ---

    def test_single_net_machine_ip(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        ifaces, _ = result['pc1'][0]
        assert IPv4Interface('10.0.0.1/24') in ifaces

    def test_multinet_machine_ip_per_iface(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        # router: eth0=lan (first in topology), eth1=wan
        ifaces_eth0, _ = result['router'][0]
        ifaces_eth1, _ = result['router'][1]
        assert IPv4Interface('10.0.0.254/24') in ifaces_eth0
        assert IPv4Interface('10.1.0.254/24') in ifaces_eth1

    # --- routing: star topology ---

    def test_pc_has_route_to_remote_net(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        routes = _all_routes(result['pc1'])
        assert '10.1.0.0/24' in routes

    def test_pc_route_next_hop_is_router_lan_ip(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        routes = _all_routes(result['pc1'])
        assert routes['10.1.0.0/24'] == '10.0.0.254'

    def test_router_directly_connected_no_specific_routes(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        for entry in result['router']:
            if isinstance(entry, tuple):
                _, routes = entry
                non_default = [r for r in routes if str(r[0]) != '0.0.0.0/0']
                assert non_default == []

    def test_server_has_route_to_lan(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY)
        routes = _all_routes(result['server'])
        assert routes.get('10.0.0.0/24') == '10.1.0.254'

    def test_single_network_no_routes(self):
        topology = {'lan': ['pc1', 'pc2']}
        ips = {'pc1': '10.0.0.1/24', 'pc2': '10.0.0.2/24'}
        ns = make_topology_net_scheme(ips, {'lan': '10.0.0.0/24'}, topology)
        result = get_net_config_from_topology(ns, topology)
        for machine in ('pc1', 'pc2'):
            _, routes = result[machine][0]
            assert routes == []

    # --- routing: chain topology (multi-hop BFS) ---

    def test_chain_pc1_direct_hop_to_mid(self):
        ns = make_topology_net_scheme(_CHAIN_IPS, _CHAIN_NETS, _CHAIN_TOPOLOGY)
        result = get_net_config_from_topology(ns, _CHAIN_TOPOLOGY)
        routes = _all_routes(result['pc1'])
        assert routes.get('10.0.2.0/24') == '10.0.1.254'   # via r1_lan1

    def test_chain_pc1_multi_hop_first_hop_for_lan2(self):
        ns = make_topology_net_scheme(_CHAIN_IPS, _CHAIN_NETS, _CHAIN_TOPOLOGY)
        result = get_net_config_from_topology(ns, _CHAIN_TOPOLOGY)
        routes = _all_routes(result['pc1'])
        # lan2 is two hops away; first hop is still r1
        assert routes.get('10.0.3.0/24') == '10.0.1.254'

    def test_chain_r1_route_to_lan2_via_r2(self):
        ns = make_topology_net_scheme(_CHAIN_IPS, _CHAIN_NETS, _CHAIN_TOPOLOGY)
        result = get_net_config_from_topology(ns, _CHAIN_TOPOLOGY)
        routes = _all_routes(result['r1'])
        assert routes.get('10.0.3.0/24') == '10.0.2.254'   # via r2_mid

    def test_chain_r1_lan2_route_on_mid_interface(self):
        ns = make_topology_net_scheme(_CHAIN_IPS, _CHAIN_NETS, _CHAIN_TOPOLOGY)
        result = get_net_config_from_topology(ns, _CHAIN_TOPOLOGY)
        # r1: eth0=lan1, eth1=mid; lan2 route must be on eth1
        _, routes_eth1 = result['r1'][1]
        assert any(str(net) == '10.0.3.0/24' for net, _ in routes_eth1)

    def test_chain_r1_lan2_route_not_on_lan1_interface(self):
        ns = make_topology_net_scheme(_CHAIN_IPS, _CHAIN_NETS, _CHAIN_TOPOLOGY)
        result = get_net_config_from_topology(ns, _CHAIN_TOPOLOGY)
        _, routes_eth0 = result['r1'][0]
        assert all(str(net) != '10.0.3.0/24' for net, _ in routes_eth0)

    def test_chain_r2_route_to_lan1_via_r1_mid(self):
        ns = make_topology_net_scheme(_CHAIN_IPS, _CHAIN_NETS, _CHAIN_TOPOLOGY)
        result = get_net_config_from_topology(ns, _CHAIN_TOPOLOGY)
        routes = _all_routes(result['r2'])
        assert routes.get('10.0.1.0/24') == '10.0.2.1'    # via r1_mid

    # --- route deduplication ---

    def test_redundant_specific_route_removed_when_default_same_hop(self):
        # Star topology: pc1's specific route to wan goes via router_lan (same as default).
        # After deduplication only 0.0.0.0/0 should remain.
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway='router')
        routes = _all_routes(result['pc1'])
        assert set(routes.keys()) == {'0.0.0.0/0'}

    def test_specific_route_kept_when_different_hop_from_default(self):
        # Two routers on the same LAN: router1 is gateway, router2 reaches wan2.
        # pc1's route to wan2 (via router2) must survive even though a default (via
        # router1) exists, because they have different next-hops.
        topology = {
            'lan':  ['pc1', 'router1', 'router2'],
            'wan1': ['router1'],
            'wan2': ['router2'],
        }
        ips = {
            'pc1':         '10.0.0.1/24',
            'router1_lan': '10.0.0.254/24',
            'router1_wan1':'10.1.0.254/24',
            'router2_lan': '10.0.0.253/24',
            'router2_wan2':'10.2.0.254/24',
        }
        nets = {
            'lan':  '10.0.0.0/24',
            'wan1': '10.1.0.0/24',
            'wan2': '10.2.0.0/24',
        }
        ns = make_topology_net_scheme(ips, nets, topology)
        result = get_net_config_from_topology(ns, topology, gateway='router1')
        routes = _all_routes(result['pc1'])
        # default via router1, wan2 via router2 — both needed
        assert '0.0.0.0/0' in routes
        assert '10.2.0.0/24' in routes
        assert routes['10.2.0.0/24'] == '10.0.0.253'
        # wan1 via router1 is redundant (covered by default via same hop)
        assert '10.1.0.0/24' not in routes

    def test_gateway_machine_keeps_specific_routes_to_internal_nets(self):
        # Chain: r1 is gateway; it still needs a specific route to lan2 so that
        # intra-lab traffic is not sent out via the external default route (different hop).
        ns = make_topology_net_scheme(_CHAIN_IPS, _CHAIN_NETS, _CHAIN_TOPOLOGY)
        result = get_net_config_from_topology(ns, _CHAIN_TOPOLOGY, gateway='r1')
        routes = _all_routes(result['r1'])
        assert '10.0.3.0/24' in routes   # specific route to lan2 (via r2, different hop)
        assert '0.0.0.0/0' in routes     # plus external default

    # --- gateway=None: no default route ---

    def test_no_gateway_no_default_route(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway=None)
        for machine, nc in result.items():
            routes = _all_routes(nc)
            assert '0.0.0.0/0' not in routes, f"{machine} has unexpected default route"

    # --- gateway set: default routes ---

    def test_gateway_end_host_gets_default_route(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway='router')
        assert '0.0.0.0/0' in _all_routes(result['pc1'])

    def test_gateway_end_host_default_route_via_router(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway='router')
        assert _all_routes(result['pc1'])['0.0.0.0/0'] == '10.0.0.254'

    def test_gateway_server_default_route_via_router_wan(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway='router')
        assert _all_routes(result['server']).get('0.0.0.0/0') == '10.1.0.254'

    def test_gateway_itself_gets_default_route(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway='router')
        assert '0.0.0.0/0' in _all_routes(result['router'])

    def test_gateway_default_route_uses_default_route_param_ipv4address(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        dr = IPv4Address('192.0.2.1')
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway='router', default_route=dr)
        assert _all_routes(result['router']).get('0.0.0.0/0') == '192.0.2.1'

    def test_gateway_default_route_uses_ip_from_ipv4interface(self):
        ns = make_topology_net_scheme(_STAR_IPS, _STAR_NETS, _STAR_TOPOLOGY)
        dr = IPv4Interface('172.17.0.1/24')
        result = get_net_config_from_topology(ns, _STAR_TOPOLOGY, gateway='router', default_route=dr)
        # Must use .ip (172.17.0.1), not the full interface string
        assert _all_routes(result['router']).get('0.0.0.0/0') == '172.17.0.1'

