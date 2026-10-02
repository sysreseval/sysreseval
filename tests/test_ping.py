"""Tests for lib/ping.py — eval_ping resolution of sources/destinations, IPv4 and IPv6."""
import sys
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
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
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()

from ping import eval_ping

NC = {
    'm1': [([IPv4Interface('10.0.0.1/24'), IPv6Interface('fd00:1::1/64')], [])],
    'r1': [([IPv4Interface('10.0.0.254/24'), IPv6Interface('fd00:1::fe/64')], []),
           ([IPv4Interface('10.1.0.254/24'), IPv6Interface('fd00:2::fe/64')], [])],
    'v6only': [([IPv6Interface('fd00:1::9/64')], [])],
    'dyn': ['dhcp'],
}

PING_OK = "PING 10.0.0.254 (10.0.0.254) 56(84) bytes of data.\n64 bytes from 10.0.0.254: icmp_seq=1 ttl=64 time=0.1 ms\n"
PING_KO = "PING 10.0.0.254 (10.0.0.254) 56(84) bytes of data.\n\n--- 10.0.0.254 ping statistics ---\n1 packets transmitted, 0 received\n"


def make_grade(responses=None, net_config=NC):
    grade = MagicMock()
    calls = []

    def _test(machine, cmd, step=1, allow_error=False, **kw):
        calls.append((machine, cmd, step, allow_error))
        return (responses or {}).get(cmd, ('', 0))

    grade.test.side_effect = _test
    grade.calls = calls
    grade.net_scheme.net_config = net_config
    return grade


def _command(grade):
    assert len(grade.calls) == 1
    return grade.calls[0]


class TestDestinationResolution:
    @pytest.mark.parametrize('dest', ['10.0.0.254', IPv4Address('10.0.0.254'), IPv4Interface('10.0.0.254/24')])
    def test_ipv4_literal_used_directly(self, dest):
        g = make_grade(net_config=None)  # a literal needs no net_config for dest ...
        g.net_scheme.net_config = {'m1': NC['m1']}  # ... but src still does
        eval_ping(g, 'm1', dest)
        assert _command(g) == ('m1', 'ping -c 1 -w 1 10.0.0.254', 1, False)

    @pytest.mark.parametrize('dest', ['fd00:1::fe', IPv6Address('fd00:1::fe'), IPv6Interface('fd00:1::fe/64')])
    def test_ipv6_literal_is_not_split_as_machine_iface(self, dest):
        g = make_grade()
        eval_ping(g, 'm1', dest)
        assert _command(g) == ('m1', 'ping -c 1 -w 1 fd00:1::fe', 1, False)

    def test_machine_iface_default_ipv4(self):
        g = make_grade()
        eval_ping(g, 'm1', 'r1:eth1')
        assert _command(g)[1] == 'ping -c 1 -w 1 10.1.0.254'

    def test_machine_iface_numeric(self):
        g = make_grade()
        eval_ping(g, 'm1', 'r1:1')
        assert _command(g)[1] == 'ping -c 1 -w 1 10.1.0.254'

    def test_machine_iface_ipv6(self):
        g = make_grade()
        eval_ping(g, 'm1', 'r1:eth1', ipv6=True)
        assert _command(g)[1] == 'ping -c 1 -w 1 fd00:2::fe'

    def test_machine_name_default_ipv4(self):
        g = make_grade()
        eval_ping(g, 'm1', 'r1')
        assert _command(g)[1] == 'ping -c 1 -w 1 10.0.0.254'

    def test_machine_name_ipv6(self):
        g = make_grade()
        eval_ping(g, 'm1', 'r1', ipv6=True)
        assert _command(g)[1] == 'ping -c 1 -w 1 fd00:1::fe'

    def test_v6only_machine_needs_ipv6_flag(self):
        g = make_grade()
        with pytest.raises(ValueError, match='no IPv4 address'):
            eval_ping(g, 'm1', 'v6only')
        g = make_grade()
        eval_ping(g, 'm1', 'v6only', ipv6=True)
        assert _command(g)[1] == 'ping -c 1 -w 1 fd00:1::9'

    def test_unknown_machine(self):
        with pytest.raises(ValueError, match="not found"):
            eval_ping(make_grade(), 'm1', 'nobody')

    def test_iface_index_out_of_range(self):
        with pytest.raises(ValueError, match="out of range"):
            eval_ping(make_grade(), 'm1', 'r1:eth5')

    def test_dhcp_interface_has_no_static_address(self):
        with pytest.raises(ValueError, match="no static address"):
            eval_ping(make_grade(), 'm1', 'dyn')

    def test_explicit_net_config_wins(self):
        g = make_grade(net_config={'x': [([IPv4Interface('192.168.0.1/24')], [])]})
        eval_ping(g, 'x', 'x', net_config={'x': [([IPv4Interface('192.168.0.1/24')], [])]})
        assert _command(g) == ('x', 'ping -c 1 -w 1 192.168.0.1', 1, False)

    def test_missing_net_config(self):
        g = make_grade(net_config=None)
        with pytest.raises(ValueError, match='net_config is required'):
            eval_ping(g, 'm1', 'r1')


class TestSourceResolution:
    @pytest.mark.parametrize('src', ['10.0.0.1', IPv4Address('10.0.0.1'), 'fd00:1::1', IPv6Address('fd00:1::1'),
                                     IPv6Interface('fd00:1::1/64'), 'm1', 'm1:eth0', 'm1:0'])
    def test_source_forms_resolve_to_m1(self, src):
        g = make_grade()
        eval_ping(g, src, '10.0.0.254')
        assert _command(g)[0] == 'm1'

    def test_unknown_source_ip(self):
        with pytest.raises(ValueError, match='No machine with IP'):
            eval_ping(make_grade(), '10.9.9.9', '10.0.0.254')

    def test_unknown_source_machine(self):
        with pytest.raises(ValueError, match="not found"):
            eval_ping(make_grade(), 'ghost:eth0', '10.0.0.254')


class TestCommandAndResult:
    def test_success_and_failure(self):
        g = make_grade({'ping -c 1 -w 1 10.0.0.254': (PING_OK, 0)})
        assert eval_ping(g, 'm1', 'r1') is True
        g = make_grade({'ping -c 1 -w 1 10.0.0.254': (PING_KO, 1)})
        assert eval_ping(g, 'm1', 'r1') is False

    def test_count_deadline_step_forwarded(self):
        g = make_grade()
        eval_ping(g, 'm1', 'r1', step=3, count=3, deadline=5)
        assert _command(g) == ('m1', 'ping -c 3 -w 5 10.0.0.254', 3, False)

    def test_allow_error_forwarded(self):
        g = make_grade()
        eval_ping(g, 'm1', 'r1', allow_error=True)
        assert _command(g)[3] is True
