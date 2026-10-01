"""Tests for lib/dhcp.py — DhcpParameters, DhcpSubnet, set_dhcp_server, get_dhcp_server."""
import sys
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

# Make lib/ and src/ importable without Docker.
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()

from dhcp import (DhcpParameters, DhcpSubnet, _parse_dhcpd_interfaces,
                  check_running_dhcp_server, get_dhcp_server, set_dhcp_server)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_net_scheme():
    return MagicMock()


def make_grade(isc_content=None, dhcpd_content=None,
               isc_code=0, dhcpd_code=0):
    """Return a mock Grade0 whose .test() returns canned file contents."""
    grade = MagicMock()

    def _test(machine, cmd, step=1, allow_error=False):
        if cmd == 'cat /etc/default/isc-dhcp-server':
            return (isc_content or '', isc_code)
        if cmd == 'cat /etc/dhcp/dhcpd.conf':
            return (dhcpd_content or '', dhcpd_code)
        return ('', 0)

    grade.test.side_effect = _test
    return grade


def capture_files(params: DhcpParameters, step=1) -> dict[str, str]:
    """Run set_dhcp_server and return {path: content} for every file() call."""
    ns = make_net_scheme()
    set_dhcp_server(ns, 'srv', params, step=step)
    return {c.args[1]: c.args[2] for c in ns.file.call_args_list}


def minimal_params(**kwargs) -> DhcpParameters:
    """A valid DhcpParameters with one simple subnet; override fields via kwargs."""
    subnet = DhcpSubnet(
        subnet=IPv4Network('10.0.0.0/24'),
        range_start=IPv4Address('10.0.0.10'),
        range_end=IPv4Address('10.0.0.50'),
    )
    p = DhcpParameters(interfaces_v4=['eth0'], subnets=[subnet])
    for k, v in kwargs.items():
        setattr(p, k, v)
    return p


# ---------------------------------------------------------------------------
# DhcpSubnet / DhcpParameters — dataclass basics
# ---------------------------------------------------------------------------

class TestDataclasses:
    def test_dhcp_subnet_required_fields(self):
        s = DhcpSubnet(
            subnet=IPv4Network('192.168.1.0/24'),
            range_start=IPv4Address('192.168.1.10'),
            range_end=IPv4Address('192.168.1.100'),
        )
        assert s.subnet == IPv4Network('192.168.1.0/24')
        assert s.routers == []
        assert s.dns_servers == []
        assert s.domain_name is None
        assert s.broadcast_address is None
        assert s.default_lease_time is None
        assert s.max_lease_time is None
        assert s.fixed_addresses == {}

    def test_dhcp_parameters_defaults(self):
        p = DhcpParameters(interfaces_v4=['eth0'])
        assert p.authoritative is True
        assert p.default_lease_time is None
        assert p.max_lease_time is None
        assert p.ddns_update_style == 'none'
        assert p.subnets == []

    def test_independent_default_factories(self):
        s1 = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                        range_start=IPv4Address('10.0.0.1'),
                        range_end=IPv4Address('10.0.0.10'))
        s2 = DhcpSubnet(subnet=IPv4Network('10.0.1.0/24'),
                        range_start=IPv4Address('10.0.1.1'),
                        range_end=IPv4Address('10.0.1.10'))
        s1.routers.append(IPv4Address('10.0.0.1'))
        assert s2.routers == []


# ---------------------------------------------------------------------------
# set_dhcp_server — /etc/default/isc-dhcp-server
# ---------------------------------------------------------------------------

class TestSetDhcpServerDefaultFile:
    def test_writes_default_file(self):
        files = capture_files(minimal_params())
        assert '/etc/default/isc-dhcp-server' in files

    def test_single_interface(self):
        files = capture_files(minimal_params())
        assert 'INTERFACESv4="eth0"' in files['/etc/default/isc-dhcp-server']

    def test_multiple_interfaces(self):
        p = DhcpParameters(interfaces_v4=['eth0', 'eth1'], subnets=[])
        files = capture_files(p)
        assert 'INTERFACESv4="eth0 eth1"' in files['/etc/default/isc-dhcp-server']

    def test_ipv6_interfaces_empty(self):
        files = capture_files(minimal_params())
        assert 'INTERFACESv6=""' in files['/etc/default/isc-dhcp-server']


# ---------------------------------------------------------------------------
# set_dhcp_server — /etc/dhcp/dhcpd.conf global section
# ---------------------------------------------------------------------------

class TestSetDhcpServerConf:
    def test_writes_conf_file(self):
        files = capture_files(minimal_params())
        assert '/etc/dhcp/dhcpd.conf' in files

    def test_authoritative(self):
        conf = capture_files(minimal_params(authoritative=True))['/etc/dhcp/dhcpd.conf']
        assert 'authoritative;' in conf
        assert 'not authoritative' not in conf

    def test_not_authoritative(self):
        conf = capture_files(minimal_params(authoritative=False))['/etc/dhcp/dhcpd.conf']
        assert 'not authoritative;' in conf

    def test_default_lease_time(self):
        conf = capture_files(minimal_params(default_lease_time=300))['/etc/dhcp/dhcpd.conf']
        assert 'default-lease-time 300;' in conf

    def test_max_lease_time(self):
        conf = capture_files(minimal_params(max_lease_time=3600))['/etc/dhcp/dhcpd.conf']
        assert 'max-lease-time 3600;' in conf

    def test_no_default_lease_time_when_none(self):
        conf = capture_files(minimal_params())['/etc/dhcp/dhcpd.conf']
        assert 'default-lease-time' not in conf

    def test_no_max_lease_time_when_none(self):
        conf = capture_files(minimal_params())['/etc/dhcp/dhcpd.conf']
        assert 'max-lease-time' not in conf

    def test_ddns_update_style(self):
        conf = capture_files(minimal_params(ddns_update_style='interim'))['/etc/dhcp/dhcpd.conf']
        assert 'ddns-update-style interim;' in conf


# ---------------------------------------------------------------------------
# set_dhcp_server — subnet block
# ---------------------------------------------------------------------------

class TestSetDhcpServerSubnet:
    def _conf(self, **subnet_kwargs) -> str:
        s = DhcpSubnet(
            subnet=IPv4Network('10.0.0.0/24'),
            range_start=IPv4Address('10.0.0.10'),
            range_end=IPv4Address('10.0.0.50'),
            **subnet_kwargs,
        )
        return capture_files(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))['/etc/dhcp/dhcpd.conf']

    def test_subnet_declaration(self):
        conf = self._conf()
        assert 'subnet 10.0.0.0 netmask 255.255.255.0 {' in conf

    def test_range(self):
        conf = self._conf()
        assert 'range 10.0.0.10 10.0.0.50;' in conf

    def test_option_routers(self):
        conf = self._conf(routers=[IPv4Address('10.0.0.1')])
        assert 'option routers 10.0.0.1;' in conf

    def test_option_routers_multiple(self):
        conf = self._conf(routers=[IPv4Address('10.0.0.1'), IPv4Address('10.0.0.2')])
        assert 'option routers 10.0.0.1, 10.0.0.2;' in conf

    def test_option_dns_servers(self):
        conf = self._conf(dns_servers=[IPv4Address('8.8.8.8'), IPv4Address('8.8.4.4')])
        assert 'option domain-name-servers 8.8.8.8, 8.8.4.4;' in conf

    def test_option_domain_name(self):
        conf = self._conf(domain_name='example.com')
        assert 'option domain-name "example.com";' in conf

    def test_no_domain_name_when_none(self):
        conf = self._conf()
        assert 'domain-name' not in conf

    def test_option_broadcast_address(self):
        conf = self._conf(broadcast_address=IPv4Address('10.0.0.255'))
        assert 'option broadcast-address 10.0.0.255;' in conf

    def test_no_broadcast_when_none(self):
        conf = self._conf()
        assert 'broadcast-address' not in conf

    def test_subnet_default_lease_override(self):
        conf = self._conf(default_lease_time=120)
        assert '    default-lease-time 120;' in conf

    def test_subnet_max_lease_override(self):
        conf = self._conf(max_lease_time=1800)
        assert '    max-lease-time 1800;' in conf

    def test_no_subnet_lease_when_none(self):
        conf = self._conf()
        lines = [l.strip() for l in conf.splitlines() if 'lease-time' in l]
        # Only the two global lines should appear
        assert all(not l.startswith('default-lease-time') and
                   not l.startswith('max-lease-time') or
                   not l.startswith('    ')
                   for l in lines)

    def test_fixed_address_host_block(self):
        conf = self._conf(fixed_addresses={'aa:bb:cc:dd:ee:ff': '10.0.0.5'})
        assert 'hardware ethernet aa:bb:cc:dd:ee:ff;' in conf
        assert 'fixed-address 10.0.0.5;' in conf

    def test_no_routers_line_when_empty(self):
        conf = self._conf()
        assert 'option routers' not in conf

    def test_multiple_subnets(self):
        s1 = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                        range_start=IPv4Address('10.0.0.10'),
                        range_end=IPv4Address('10.0.0.50'))
        s2 = DhcpSubnet(subnet=IPv4Network('192.168.1.0/24'),
                        range_start=IPv4Address('192.168.1.10'),
                        range_end=IPv4Address('192.168.1.100'))
        conf = capture_files(DhcpParameters(interfaces_v4=['eth0'], subnets=[s1, s2]))['/etc/dhcp/dhcpd.conf']
        assert 'subnet 10.0.0.0' in conf
        assert 'subnet 192.168.1.0' in conf


# ---------------------------------------------------------------------------
# set_dhcp_server — systemctl commands and step parameter
# ---------------------------------------------------------------------------

class TestSetDhcpServerCommands:
    def test_enable_and_restart_called(self):
        ns = make_net_scheme()
        set_dhcp_server(ns, 'srv', minimal_params())
        cmds = [c.args[1] for c in ns.cmd.call_args_list]
        assert 'systemctl enable isc-dhcp-server' in cmds
        assert 'systemctl restart isc-dhcp-server' in cmds

    def test_step_forwarded_to_file(self):
        ns = make_net_scheme()
        set_dhcp_server(ns, 'srv', minimal_params(), step=3)
        for c in ns.file.call_args_list:
            assert c.kwargs.get('step', c.args[3] if len(c.args) > 3 else None) == 3

    def test_step_forwarded_to_cmd(self):
        ns = make_net_scheme()
        set_dhcp_server(ns, 'srv', minimal_params(), step=3)
        for c in ns.cmd.call_args_list:
            assert c.kwargs.get('step', c.args[2] if len(c.args) > 2 else None) == 3

    def test_machine_name_forwarded(self):
        ns = make_net_scheme()
        set_dhcp_server(ns, 'myserver', minimal_params())
        for c in ns.file.call_args_list:
            assert c.args[0] == 'myserver'
        for c in ns.cmd.call_args_list:
            assert c.args[0] == 'myserver'


# ---------------------------------------------------------------------------
# get_dhcp_server
# ---------------------------------------------------------------------------

_ISC_DEFAULT = 'INTERFACESv4="eth0"\nINTERFACESv6=""\n'

_DHCPD_MINIMAL = """\
ddns-update-style none;
authoritative;
default-lease-time 600;
max-lease-time 7200;

subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.10 10.0.0.50;
}
"""

_DHCPD_FULL = """\
ddns-update-style none;
authoritative;
default-lease-time 300;
max-lease-time 3600;

subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.10 10.0.0.100;
    option routers 10.0.0.1;
    option domain-name-servers 8.8.8.8, 8.8.4.4;
    option domain-name "lab.example.com";
    option broadcast-address 10.0.0.255;
    host aa-bb-cc-dd-ee-ff {
        hardware ethernet aa:bb:cc:dd:ee:ff;
        fixed-address 10.0.0.5;
    }
}
"""


class TestGetDhcpServerErrors:
    def test_missing_default_file_returns_none(self):
        grade = make_grade(isc_code=1, dhcpd_content=_DHCPD_MINIMAL)
        params, errors = get_dhcp_server(grade, 'srv')
        assert params is None
        assert errors == 1

    def test_dhcpd_conf_parse_errors_counted(self):
        bad_conf = 'this is not valid dhcp config {\n'
        grade = make_grade(isc_content=_ISC_DEFAULT, dhcpd_content=bad_conf)
        params, errors = get_dhcp_server(grade, 'srv')
        assert errors > 0

    def test_no_errors_on_valid_conf(self):
        grade = make_grade(isc_content=_ISC_DEFAULT, dhcpd_content=_DHCPD_MINIMAL)
        params, errors = get_dhcp_server(grade, 'srv')
        assert errors == 0


class TestGetDhcpServerGlobalParams:
    def _get(self, dhcpd=_DHCPD_MINIMAL, isc=_ISC_DEFAULT):
        grade = make_grade(isc_content=isc, dhcpd_content=dhcpd)
        params, _ = get_dhcp_server(grade, 'srv')
        return params

    def test_interfaces_parsed(self):
        assert self._get().interfaces_v4 == ['eth0']

    def test_multiple_interfaces_parsed(self):
        isc = 'INTERFACESv4="eth0 eth1"\nINTERFACESv6=""\n'
        assert self._get(isc=isc).interfaces_v4 == ['eth0', 'eth1']

    def test_authoritative_true(self):
        assert self._get().authoritative is True

    def test_not_authoritative(self):
        conf = _DHCPD_MINIMAL.replace('authoritative;', 'not authoritative;')
        assert self._get(dhcpd=conf).authoritative is False

    def test_default_lease_time(self):
        assert self._get().default_lease_time == 600

    def test_max_lease_time(self):
        assert self._get().max_lease_time == 7200

    def test_default_lease_time_absent_is_none(self):
        conf = _DHCPD_MINIMAL.replace('default-lease-time 600;\n', '')
        assert self._get(dhcpd=conf).default_lease_time is None

    def test_max_lease_time_absent_is_none(self):
        conf = _DHCPD_MINIMAL.replace('max-lease-time 7200;\n', '')
        assert self._get(dhcpd=conf).max_lease_time is None

    def test_ddns_update_style(self):
        assert self._get().ddns_update_style == 'none'


class TestGetDhcpServerSubnet:
    def _subnet(self, dhcpd=_DHCPD_MINIMAL):
        grade = make_grade(isc_content=_ISC_DEFAULT, dhcpd_content=dhcpd)
        params, _ = get_dhcp_server(grade, 'srv')
        return params.subnets[0]

    def test_one_subnet_parsed(self):
        grade = make_grade(isc_content=_ISC_DEFAULT, dhcpd_content=_DHCPD_MINIMAL)
        params, _ = get_dhcp_server(grade, 'srv')
        assert len(params.subnets) == 1

    def test_subnet_network(self):
        assert self._subnet().subnet == IPv4Network('10.0.0.0/24')

    def test_range_start(self):
        assert self._subnet().range_start == IPv4Address('10.0.0.10')

    def test_range_end(self):
        assert self._subnet().range_end == IPv4Address('10.0.0.50')

    def test_routers(self):
        s = self._subnet(dhcpd=_DHCPD_FULL)
        assert s.routers == [IPv4Address('10.0.0.1')]

    def test_dns_servers(self):
        s = self._subnet(dhcpd=_DHCPD_FULL)
        assert s.dns_servers == [IPv4Address('8.8.8.8'), IPv4Address('8.8.4.4')]

    def test_domain_name(self):
        assert self._subnet(dhcpd=_DHCPD_FULL).domain_name == 'lab.example.com'

    def test_broadcast_address(self):
        assert self._subnet(dhcpd=_DHCPD_FULL).broadcast_address == IPv4Address('10.0.0.255')

    def test_fixed_addresses(self):
        s = self._subnet(dhcpd=_DHCPD_FULL)
        assert s.fixed_addresses == {'aa:bb:cc:dd:ee:ff': '10.0.0.5'}

    def test_no_routers_when_absent(self):
        assert self._subnet().routers == []

    def test_no_fixed_addresses_when_absent(self):
        assert self._subnet().fixed_addresses == {}

    def test_subnet_lease_override_when_different(self):
        conf = """\
default-lease-time 600;
max-lease-time 7200;
subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.10 10.0.0.50;
    default-lease-time 120;
    max-lease-time 1800;
}
"""
        s = self._subnet(dhcpd=conf)
        assert s.default_lease_time == 120
        assert s.max_lease_time == 1800

    def test_subnet_lease_none_when_same_as_global(self):
        # Effective params equal global → no per-subnet override needed
        conf = """\
default-lease-time 600;
max-lease-time 7200;
subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.10 10.0.0.50;
    default-lease-time 600;
    max-lease-time 7200;
}
"""
        s = self._subnet(dhcpd=conf)
        assert s.default_lease_time is None
        assert s.max_lease_time is None

    def test_subnet_lease_when_no_global(self):
        # No global lease times: subnet-level values become overrides (not None)
        conf = """\
subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.10 10.0.0.50;
    default-lease-time 300;
    max-lease-time 1800;
}
"""
        s = self._subnet(dhcpd=conf)
        assert s.default_lease_time == 300
        assert s.max_lease_time == 1800

    def test_multiple_subnets(self):
        conf = """\
subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.10 10.0.0.50;
}
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.10 192.168.1.100;
}
"""
        grade = make_grade(isc_content=_ISC_DEFAULT, dhcpd_content=conf)
        params, _ = get_dhcp_server(grade, 'srv')
        nets = {s.subnet for s in params.subnets}
        assert IPv4Network('10.0.0.0/24') in nets
        assert IPv4Network('192.168.1.0/24') in nets


# ---------------------------------------------------------------------------
# Round-trip: set then get
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def _round_trip(self, params: DhcpParameters):
        """Write config via set_dhcp_server, then parse it back via get_dhcp_server."""
        ns = make_net_scheme()
        set_dhcp_server(ns, 'srv', params)
        files = {c.args[1]: c.args[2] for c in ns.file.call_args_list}
        isc = files['/etc/default/isc-dhcp-server']
        conf = files['/etc/dhcp/dhcpd.conf']
        grade = make_grade(isc_content=isc, dhcpd_content=conf)
        result, errors = get_dhcp_server(grade, 'srv')
        return result, errors

    def test_no_errors_on_round_trip(self):
        _, errors = self._round_trip(minimal_params())
        assert errors == 0

    def test_interfaces_survive(self):
        p = DhcpParameters(interfaces_v4=['eth0', 'eth1'], subnets=[])
        result, _ = self._round_trip(p)
        assert result.interfaces_v4 == ['eth0', 'eth1']

    def test_authoritative_survives(self):
        result, _ = self._round_trip(minimal_params(authoritative=False))
        assert result.authoritative is False

    def test_lease_times_survive(self):
        p = minimal_params(default_lease_time=300, max_lease_time=3600)
        result, _ = self._round_trip(p)
        assert result.default_lease_time == 300
        assert result.max_lease_time == 3600

    def test_subnet_range_survives(self):
        s = DhcpSubnet(subnet=IPv4Network('10.1.2.0/24'),
                       range_start=IPv4Address('10.1.2.20'),
                       range_end=IPv4Address('10.1.2.80'))
        result, _ = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        rs = result.subnets[0]
        assert rs.subnet == IPv4Network('10.1.2.0/24')
        assert rs.range_start == IPv4Address('10.1.2.20')
        assert rs.range_end == IPv4Address('10.1.2.80')

    def test_routers_survive(self):
        s = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'),
                       routers=[IPv4Address('10.0.0.1')])
        result, _ = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        assert result.subnets[0].routers == [IPv4Address('10.0.0.1')]

    def test_dns_servers_survive(self):
        s = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'),
                       dns_servers=[IPv4Address('8.8.8.8'), IPv4Address('1.1.1.1')])
        result, _ = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        assert result.subnets[0].dns_servers == [IPv4Address('8.8.8.8'), IPv4Address('1.1.1.1')]

    def test_domain_name_survives(self):
        s = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'),
                       domain_name='tp.local')
        result, _ = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        assert result.subnets[0].domain_name == 'tp.local'

    def test_broadcast_survives(self):
        s = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'),
                       broadcast_address=IPv4Address('10.0.0.255'))
        result, _ = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        assert result.subnets[0].broadcast_address == IPv4Address('10.0.0.255')

    def test_fixed_addresses_survive(self):
        s = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'),
                       fixed_addresses={'de:ad:be:ef:00:01': '10.0.0.3'})
        result, _ = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        assert result.subnets[0].fixed_addresses == {'de:ad:be:ef:00:01': '10.0.0.3'}

    def test_subnet_lease_override_survives(self):
        s = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'),
                       default_lease_time=120,
                       max_lease_time=900)
        result, _ = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        rs = result.subnets[0]
        assert rs.default_lease_time == 120
        assert rs.max_lease_time == 900

    def test_none_global_lease_times_survive(self):
        # Default (None) global lease times: no global lines written, no errors
        p = DhcpParameters(interfaces_v4=['eth0'], subnets=[
            DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'))
        ])
        result, errors = self._round_trip(p)
        assert errors == 0
        assert result.default_lease_time is None
        assert result.max_lease_time is None

    def test_subnet_only_lease_times_round_trip(self):
        # Global is None, subnet defines its own lease times
        s = DhcpSubnet(subnet=IPv4Network('10.0.0.0/24'),
                       range_start=IPv4Address('10.0.0.10'),
                       range_end=IPv4Address('10.0.0.50'),
                       default_lease_time=300,
                       max_lease_time=1800)
        result, errors = self._round_trip(DhcpParameters(interfaces_v4=['eth0'], subnets=[s]))
        assert errors == 0
        assert result.subnets[0].default_lease_time == 300
        assert result.subnets[0].max_lease_time == 1800


# ---------------------------------------------------------------------------
# _parse_dhcpd_interfaces
# ---------------------------------------------------------------------------

def _cmdline(*args):
    """Format a dhcpd argv as newline-separated tokens, as produced by tr '\\000' '\\n'."""
    return '\n'.join(['/usr/sbin/dhcpd'] + list(args))


class TestParseDhcpdInterfaces:
    def test_single_interface(self):
        assert _parse_dhcpd_interfaces(_cmdline('-4', '-q',
                                                '-cf', '/etc/dhcp/dhcpd.conf',
                                                'eth0')) == ['eth0']

    def test_two_interfaces(self):
        assert _parse_dhcpd_interfaces(_cmdline('-4', '-q',
                                                '-cf', '/etc/dhcp/dhcpd.conf',
                                                'eth0', 'eth1')) == ['eth0', 'eth1']

    def test_no_interface_returns_wildcard(self):
        assert _parse_dhcpd_interfaces(_cmdline('-4', '-q',
                                                '-cf', '/etc/dhcp/dhcpd.conf',
                                                '-pf', '/run/dhcp-server/dhcpd.pid',
                                                '-lf', '/var/lib/dhcp/dhcpd.leases',
                                                )) == ['*']

    def test_empty_output_returns_wildcard(self):
        assert _parse_dhcpd_interfaces('') == ['*']

    def test_all_value_flags_skipped(self):
        # Every flag that takes a value argument must not swallow an interface name.
        cmdline = _cmdline(
            '-cf', '/etc/dhcp/dhcpd.conf',
            '-lf', '/var/lib/dhcp/dhcpd.leases',
            '-pf', '/run/dhcp-server/dhcpd.pid',
            '-tf', '/tmp/trace',
            '-sf', '/usr/lib/dhcp/dhclient-script',
            '-user', 'dhcpd',
            '-group', 'dhcpd',
            '-chroot', '/var/lib/dhcpd',
            '-port', '67',
            'eth0',
        )
        assert _parse_dhcpd_interfaces(cmdline) == ['eth0']

    def test_executable_not_included(self):
        result = _parse_dhcpd_interfaces(_cmdline('eth0'))
        assert '/usr/sbin/dhcpd' not in result
        assert result == ['eth0']

    def test_flags_without_value_skipped(self):
        assert _parse_dhcpd_interfaces(_cmdline('-4', '-6', '-q', '-d', '-f', '-t',
                                                '-T', 'eth0')) == ['eth0']

    def test_interface_names_preserved_order(self):
        result = _parse_dhcpd_interfaces(_cmdline('ens3', 'ens4', 'eth0'))
        assert result == ['ens3', 'ens4', 'eth0']


# ---------------------------------------------------------------------------
# check_running_dhcp_server
# ---------------------------------------------------------------------------

def make_running_grade(active=True, cmdline=''):
    """Return a mock Grade0 for check_running_dhcp_server tests."""
    grade = MagicMock()
    is_active_code = 0 if active else 1

    def _test(machine, cmd, step=1, allow_error=False):
        if cmd == 'systemctl is-active isc-dhcp-server':
            return ('active' if active else 'inactive', is_active_code)
        if 'pidof' in cmd:
            return (cmdline, 0)
        return ('', 0)

    grade.test.side_effect = _test
    return grade


class TestCheckRunningDhcpServer:
    def test_not_running_returns_false_empty(self):
        grade = make_running_grade(active=False)
        running, interfaces = check_running_dhcp_server(grade, 'srv')
        assert running is False
        assert interfaces == []

    def test_running_returns_true(self):
        grade = make_running_grade(active=True,
                                   cmdline=_cmdline('-4', '-cf', '/etc/dhcp/dhcpd.conf', 'eth0'))
        running, _ = check_running_dhcp_server(grade, 'srv')
        assert running is True

    def test_running_single_interface(self):
        grade = make_running_grade(cmdline=_cmdline('-4', '-cf', '/etc/dhcp/dhcpd.conf', 'eth0'))
        _, interfaces = check_running_dhcp_server(grade, 'srv')
        assert interfaces == ['eth0']

    def test_running_multiple_interfaces(self):
        grade = make_running_grade(
            cmdline=_cmdline('-4', '-cf', '/etc/dhcp/dhcpd.conf', 'eth0', 'eth1'))
        _, interfaces = check_running_dhcp_server(grade, 'srv')
        assert interfaces == ['eth0', 'eth1']

    def test_running_no_interfaces_returns_wildcard(self):
        # dhcpd started without explicit interface args → listens on all
        grade = make_running_grade(cmdline=_cmdline('-4', '-cf', '/etc/dhcp/dhcpd.conf'))
        _, interfaces = check_running_dhcp_server(grade, 'srv')
        assert interfaces == ['*']

    def test_running_empty_cmdline_returns_wildcard(self):
        # pidof returned nothing (process disappeared between is-active and cmdline read)
        grade = make_running_grade(cmdline='')
        _, interfaces = check_running_dhcp_server(grade, 'srv')
        assert interfaces == ['*']

    def test_not_running_skips_cmdline_call(self):
        grade = make_running_grade(active=False)
        check_running_dhcp_server(grade, 'srv')
        # Only the is-active call should have been made
        cmds = [call.args[1] for call in grade.test.call_args_list]
        assert all('systemctl' in c for c in cmds)
        assert not any('pidof' in c for c in cmds)

    def test_machine_name_forwarded(self):
        grade = make_running_grade(active=False)
        check_running_dhcp_server(grade, 'myrouter')
        assert grade.test.call_args_list[0].args[0] == 'myrouter'

# ---------------------------------------------------------------------------
# Probe, relay, failover and client leases
# Fixtures in tests/mock_data/dhcp were captured on ISC DHCP 4.4.3-P1 (lab dhcp.py,
# state `final`: two servers, relay on r1, failover pool on lan2).
# ---------------------------------------------------------------------------

import base64
import json
import struct

import dhcp_probe
from dhcp import (DHCP_PROBE_PATH, DhcpRelayParameters, _parse_dhcpd_cmdlines, _parse_dhcrelay_cmdline,
                  check_running_dhcp_relay, dhcp_probe as run_dhcp_probe, dhcp_probe_command,
                  dhcp_probe_query, get_dhclient_leases, get_dhcp_failover_state, get_dhcpd_interfaces,
                  install_dhcp_probe, parse_dhclient_leases, parse_dhcp_probe, parse_dhcpd_failover_state,
                  set_dhcp_relay)

FIXTURES = Path(__file__).parent / 'mock_data' / 'dhcp'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def make_output_grade(output='', code=0):
    """Mock Grade0 whose .test() returns the same canned output for every command."""
    grade = MagicMock()
    grade.test.return_value = (output, code)
    return grade


class TestProbeFrames:
    SRC = '02:53:52:00:00:aa'
    CHADDR = '02:53:52:00:00:01'

    def _bootp(self, frame: bytes) -> bytes:
        return frame[14 + 20 + 8:]

    def _options(self, frame: bytes) -> dict[int, bytes]:
        opts, raw, i = {}, self._bootp(frame)[240:], 0
        while raw[i] != 255:
            opts[raw[i]] = raw[i + 2:i + 2 + raw[i + 1]]
            i += 2 + raw[i + 1]
        return opts

    def test_discover_is_broadcast_from_the_interface_mac(self):
        frame = dhcp_probe.build_request(self.SRC, self.CHADDR, 0x1234)
        assert frame[0:6] == b'\xff' * 6
        assert frame[6:12] == bytes.fromhex('0253520000aa')
        assert frame[12:14] == b'\x08\x00'
        assert frame[14 + 12:14 + 16] == bytes(4) and frame[14 + 16:14 + 20] == b'\xff' * 4
        assert struct.unpack('!HH', frame[34:38]) == (68, 67)

    def test_bootp_header(self):
        bootp = self._bootp(dhcp_probe.build_request(self.SRC, self.CHADDR, 0xdeadbeef, secs=7))
        op, htype, hlen, hops, xid, secs, flags = struct.unpack('!BBBBIHH', bootp[:12])
        assert (op, htype, hlen, hops, xid, secs) == (1, 1, 6, 0, 0xdeadbeef, 7)
        assert flags == dhcp_probe.FLAG_BROADCAST
        assert bootp[28:34] == bytes.fromhex('025352000001')  # chaddr differs from the Ethernet source
        assert len(bootp) >= dhcp_probe.BOOTP_MIN_LEN

    def test_checksums_are_valid(self):
        frame = dhcp_probe.build_request(self.SRC, self.CHADDR, 1)
        assert dhcp_probe._checksum(frame[14:34]) == 0
        udp_len = struct.unpack('!H', frame[38:40])[0]
        pseudo = frame[26:34] + struct.pack('!BBH', 0, 17, udp_len)
        assert dhcp_probe._checksum(pseudo + frame[34:]) == 0

    def test_discover_options(self):
        opts = self._options(dhcp_probe.build_request(self.SRC, self.CHADDR, 1, hostname='sonde', lease=4000000))
        assert opts[53] == b'\x01'
        assert opts[12] == b'sonde'
        assert struct.unpack('!I', opts[51])[0] == 4000000
        assert set(opts[55]) >= {1, 3, 6, 15, 51, 54}
        assert 50 not in opts

    def test_init_reboot_request(self):
        opts = self._options(dhcp_probe.build_request(self.SRC, self.CHADDR, 1, msg_type='request',
                                                      requested='192.0.2.77'))
        assert opts[53] == b'\x03'
        assert opts[50] == bytes([192, 0, 2, 77])
        assert 54 not in opts  # no server identifier: INIT-REBOOT, nothing can be committed

    def _reply_frame(self, xid=0x1234, options=b''):
        bootp = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 2, 1, 6, 1, xid, 0, 0x8000,
                            bytes(4), bytes([10, 0, 0, 50]), bytes(4), bytes([10, 0, 0, 254]),
                            bytes.fromhex('025352000001'), b'', b'')
        bootp += dhcp_probe.BOOTP_MAGIC + options + b'\xff'
        udp = struct.pack('!HHHH', 67, 68, 8 + len(bootp), 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp) + len(bootp), 0, 0, 64, 17, 0,
                         bytes([10, 0, 0, 254]), b'\xff' * 4)
        return b'\xff' * 6 + bytes.fromhex('aabbccddeeff') + b'\x08\x00' + ip + udp + bootp

    def test_parse_reply(self):
        options = (bytes([53, 1, 2]) + bytes([54, 4, 192, 168, 1, 10]) + bytes([51, 4]) + struct.pack('!I', 600)
                   + bytes([1, 4, 255, 255, 255, 0]) + bytes([3, 4, 10, 0, 0, 254])
                   + bytes([6, 8, 10, 9, 9, 9, 10, 8, 8, 8]) + bytes([15, 6]) + b'tp.lan')
        reply = dhcp_probe.parse_reply(self._reply_frame(options=options))
        assert reply['msg_type'] == 'OFFER'
        assert reply['xid'] == 0x1234
        assert reply['yiaddr'] == '10.0.0.50'
        assert reply['giaddr'] == '10.0.0.254'
        assert reply['server_id'] == '192.168.1.10'
        assert reply['src_ip'] == '10.0.0.254'
        assert reply['src_mac'] == 'aa:bb:cc:dd:ee:ff'
        assert reply['lease_time'] == 600
        assert reply['subnet_mask'] == '255.255.255.0'
        assert reply['routers'] == ['10.0.0.254']
        assert reply['dns_servers'] == ['10.9.9.9', '10.8.8.8']
        assert reply['domain_name'] == 'tp.lan'

    def test_parse_reply_ignores_requests_and_garbage(self):
        assert dhcp_probe.parse_reply(dhcp_probe.build_request(self.SRC, self.CHADDR, 1)) is None
        assert dhcp_probe.parse_reply(b'') is None
        assert dhcp_probe.parse_reply(b'\x00' * 400) is None
        assert dhcp_probe.parse_reply(self._reply_frame()[:100]) is None

    def test_main_always_prints_json(self, capsys):
        assert dhcp_probe.main(['dhcp_probe.py', 'not base64 json']) == 0
        document = json.loads(capsys.readouterr().out)
        assert document['replies'] == {} and document['errors']


class TestProbeCommand:
    def test_command_is_deterministic_and_shell_safe(self):
        spec = {'interfaces': {'eth0': [dhcp_probe_query('dyn', '02-53-52-AA-BB-CC')]}}
        cmd = dhcp_probe_command(spec)
        assert cmd == dhcp_probe_command({'interfaces': {'eth0': [dhcp_probe_query('dyn', '02:53:52:aa:bb:cc')]}})
        assert cmd.startswith(f'python3 {DHCP_PROBE_PATH} ')
        encoded = cmd.split()[-1]
        assert all(c.isalnum() or c in '-_=' for c in encoded)  # no quote, no ':' first, no '@@@'
        assert json.loads(base64.urlsafe_b64decode(encoded)) == spec

    def test_query_fields(self):
        q = dhcp_probe_query('nak', '02:53:52:00:00:01', msg_type='request', requested=IPv4Address('192.0.2.77'))
        assert q == {'id': 'nak', 'type': 'request', 'chaddr': '02:53:52:00:00:01', 'requested': '192.0.2.77'}
        q = dhcp_probe_query('max', '02:53:52:00:00:01', lease=4000000, late=True, hostname='sonde')
        assert q['lease'] == 4000000 and q['late'] is True and q['hostname'] == 'sonde'

    def test_install_copies_the_script(self):
        ns = make_net_scheme()
        install_dhcp_probe(ns, 'sonde')
        (machine, path, content), kwargs = ns.file.call_args
        assert (machine, path) == ('sonde', DHCP_PROBE_PATH)
        assert 'def build_request' in content and kwargs['permissions'] == 0o755

    def test_dhcp_probe_registers_one_test(self):
        grade = make_output_grade(load('probe_final.json'))
        spec = {'interfaces': {'eth0': [dhcp_probe_query('dyn', '02:53:52:a5:fe:4c')]}}
        result = run_dhcp_probe(grade, 'sonde', spec)
        grade.test.assert_called_once_with('sonde', dhcp_probe_command(spec), step=1, timeout=30, allow_error=True)
        assert result['eth0']['dyn']


class TestParseDhcpProbe:
    SRV1, SRV2 = IPv4Address('192.168.11.54'), IPv4Address('192.168.11.23')

    def test_empty_or_malformed_output(self):
        assert parse_dhcp_probe('') == {}
        assert parse_dhcp_probe('Traceback (most recent call last):') == {}
        assert parse_dhcp_probe('{"errors": []}') == {}
        assert parse_dhcp_probe('{"replies": {"eth0": {"dyn": "x"}}}') == {'eth0': {'dyn': []}}

    def test_two_servers_on_lan1(self):
        replies = parse_dhcp_probe(load('probe_final.json'))['eth0']['dyn']
        direct = {r.server_id: r for r in replies if r.giaddr is None}
        assert set(direct) == {self.SRV1, self.SRV2}
        offer = direct[self.SRV1]
        assert offer.msg_type == 'OFFER'
        assert offer.yiaddr == IPv4Address('192.168.11.162')
        assert offer.subnet_mask == IPv4Address('255.255.255.0')
        assert offer.routers == [IPv4Address('192.168.11.115')]
        assert offer.dns_servers == [IPv4Address('172.18.202.184')]
        assert offer.domain_name == 'tp-dhcp.lan'
        assert offer.lease_time == 600
        assert direct[self.SRV2].yiaddr == IPv4Address('192.168.11.209')

    def test_relay_duplicates_on_the_server_lan(self):
        # dhcrelay -i eth1 -i eth2 also relays the lan1 broadcasts: same offers with giaddr set.
        replies = parse_dhcp_probe(load('probe_final.json'))['eth0']['dyn']
        relayed = [r for r in replies if r.giaddr is not None]
        assert relayed and {r.giaddr for r in relayed} == {IPv4Address('192.168.11.115')}
        assert {r.yiaddr for r in replies if r.server_id == self.SRV1} == {IPv4Address('192.168.11.162')}

    def test_reservation_offered_by_both_servers(self):
        replies = parse_dhcp_probe(load('probe_final.json'))['eth0']['fixed']
        assert {r.server_id for r in replies} == {self.SRV1, self.SRV2}
        assert {r.yiaddr for r in replies} == {IPv4Address('192.168.11.139')}

    def test_max_lease_time(self):
        replies = parse_dhcp_probe(load('probe_final.json'))['eth0']['max']
        assert {r.lease_time for r in replies} == {7200}

    def test_nak_from_authoritative_servers(self):
        replies = parse_dhcp_probe(load('probe_final.json'))['eth0']['nak']
        assert {r.msg_type for r in replies} == {'NAK'}
        assert {r.server_id for r in replies} == {self.SRV1, self.SRV2}
        assert all(r.yiaddr is None for r in replies)

    def test_relayed_network(self):
        replies = parse_dhcp_probe(load('probe_final.json'))['eth1']['dyn']
        assert {r.giaddr for r in replies} == {IPv4Address('172.18.14.49')}
        assert {r.src_ip for r in replies} == {IPv4Address('172.18.14.49')}  # sent by the relay
        assert {r.server_id for r in replies} == {self.SRV1, self.SRV2}      # failover peers, secs > 3
        assert {r.lease_time for r in replies} == {90}                       # first lease = MCLT
        assert len({r.yiaddr for r in replies}) == 2


class TestDhcpRelay:
    def test_set_dhcp_relay(self):
        ns = make_net_scheme()
        set_dhcp_relay(ns, 'r1', DhcpRelayParameters(
            servers=[IPv4Address('192.168.11.54'), '192.168.11.23'], interfaces=['eth1', 'eth2']))
        (machine, path, content), _ = ns.file.call_args
        assert (machine, path) == ('r1', '/etc/default/isc-dhcp-relay')
        assert content == 'SERVERS="192.168.11.54 192.168.11.23"\nINTERFACES="eth1 eth2"\nOPTIONS=""\n'
        assert ns.cmd.call_args_list[-1] == call('r1', 'systemctl restart isc-dhcp-relay', step=1)

    def test_set_dhcp_relay_options(self):
        ns = make_net_scheme()
        set_dhcp_relay(ns, 'r1', DhcpRelayParameters(servers=['10.0.0.1'], options='-id eth2 -iu eth1'), step=2)
        (_machine, _path, content), kwargs = ns.file.call_args
        assert 'INTERFACES=""\nOPTIONS="-id eth2 -iu eth1"\n' in content
        assert kwargs['step'] == 2

    def test_parse_cmdline_captured(self):
        parsed = _parse_dhcrelay_cmdline(load('dhcrelay_cmdline_final.txt'))
        assert parsed == {'servers': ['192.168.11.54', '192.168.11.23'], 'interfaces': ['eth1', 'eth2'],
                          'upstream': [], 'downstream': []}

    def test_parse_cmdline_directions(self):
        parsed = _parse_dhcrelay_cmdline('/usr/sbin/dhcrelay -q -id eth2 -iu eth1 192.168.11.54')
        assert parsed == {'servers': ['192.168.11.54'], 'interfaces': [], 'upstream': ['eth1'],
                          'downstream': ['eth2']}

    def test_parse_cmdline_value_flags_and_all_interfaces(self):
        parsed = _parse_dhcrelay_cmdline('/usr/sbin/dhcrelay -q -m append -c 5 10.0.0.1 10.0.0.2')
        assert parsed == {'servers': ['10.0.0.1', '10.0.0.2'], 'interfaces': [], 'upstream': [], 'downstream': []}

    def test_not_running(self):
        assert _parse_dhcrelay_cmdline('') is None
        assert _parse_dhcrelay_cmdline('sh: 1: cannot open /proc//cmdline: No such file') is None
        running, args = check_running_dhcp_relay(make_output_grade('', 1), 'r1')
        assert running is False and args['servers'] == []

    def test_running(self):
        running, args = check_running_dhcp_relay(make_output_grade(load('dhcrelay_cmdline_final.txt')), 'r1')
        assert running is True and args['interfaces'] == ['eth1', 'eth2']


class TestDhcpdCmdlines:
    def test_captured(self):
        assert _parse_dhcpd_cmdlines(load('dhcpd_cmdlines_srv1_final.txt')) == ['eth0']

    def test_not_running(self):
        assert _parse_dhcpd_cmdlines('') is None
        assert _parse_dhcpd_cmdlines('sh: 1: pidof: not found\n') is None
        assert get_dhcpd_interfaces(make_output_grade(''), 'srv1') is None

    def test_no_interface_means_all(self):
        # started with an empty INTERFACESv4: the unit is "failed" but dhcpd -4 runs on every interface
        assert _parse_dhcpd_cmdlines('/usr/sbin/dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf \n') == ['*']

    def test_ipv6_process_is_ignored(self):
        output = ('/usr/sbin/dhcpd -6 -q -cf /etc/dhcp/dhcpd6.conf eth0 \n'
                  '/usr/sbin/dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf eth0 eth1 \n')
        assert _parse_dhcpd_cmdlines(output) == ['eth0', 'eth1']
        assert _parse_dhcpd_cmdlines('/usr/sbin/dhcpd -6 -q -cf /etc/dhcp/dhcpd6.conf eth0 \n') is None


class TestFailoverState:
    def test_last_block_wins(self):
        for name in ('failover_srv1_final.txt', 'failover_srv2_final.txt'):
            assert parse_dhcpd_failover_state(load(name)) == {
                'lan2': {'my_state': 'normal', 'partner_state': 'normal'}}

    def test_full_leases_file_syntax(self):
        text = ('lease 10.0.0.5 {\n  binding state free;\n}\n'
                'failover peer "a" state {\n  my state communications-interrupted at 3 2026/09/30 14:50:24;\n'
                '  partner state normal at 3 2026/09/30 14:50:24;\n  mclt 90;\n}\n'
                'failover peer "b" state {\n  my state partner-down at 3 2026/09/30 14:50:24;\n}\n')
        assert parse_dhcpd_failover_state(text) == {
            'a': {'my_state': 'communications-interrupted', 'partner_state': 'normal'},
            'b': {'my_state': 'partner-down'}}

    def test_no_failover(self):
        assert parse_dhcpd_failover_state('') == {}
        assert get_dhcp_failover_state(make_output_grade('', 1), 'srv1') == {}


class TestDhclientLeases:
    def test_first_lease(self):
        leases = parse_dhclient_leases(load('dhclient_m3_first_lease.leases'))
        assert len(leases) == 1
        lease = leases[0]
        assert lease['interface'] == 'eth0'
        assert lease['fixed-address'] == '172.18.14.152'
        assert lease['routers'] == '172.18.14.49'
        assert lease['dhcp-lease-time'] == '90'
        assert lease['dhcp-server-identifier'] == '192.168.11.23'
        assert lease['domain-name'] == 'tp-dhcp.lan'
        assert lease['expire'].startswith('3 2026/09/30')

    def test_renewed_lease_is_last(self):
        leases = parse_dhclient_leases(load('dhclient_m3_renewed.leases'))
        assert [l['dhcp-lease-time'] for l in leases] == ['90', '600']

    def test_empty(self):
        assert parse_dhclient_leases('') == []
        assert get_dhclient_leases(make_output_grade('', 1), 'm3') == []
