"""Tests for lib/mpls.py: the kernel side of MPLS (fixtures in tests/mock_data/mpls, captured in the
MPLS lab, lab/sre/_DRAFT_misc/mpls.py, on Debian 13 / iproute2 7.3.0 / Linux 6.12)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from mpls import (  # noqa: E402
    MPLS_COUNTERS_CMD, get_kernel_mpls_routes, get_mpls_counters, get_mpls_sysctls, mpls_counter_delta,
    mpls_route_is_pop, mpls_route_is_swap, parse_kernel_mpls_routes, parse_labels, parse_mpls_counters,
    parse_mpls_sysctls, trigger_mpls_modules_cmd,
)

FIXTURES = Path(__file__).parent / 'mock_data' / 'mpls'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def make_grade(output: str, code: int = 0):
    grade = MagicMock()
    grade.test.return_value = (output, code)
    return grade


class TestSysctls:
    def test_after_the_static_lsp(self):
        s = parse_mpls_sysctls(load('sysctl_st_p_final.txt'))
        assert s == {'input': {'eth0': 1, 'eth1': 1, 'lo': 0}, 'default_ttl': 255, 'ip_ttl_propagate': 1,
                     'platform_labels': 1000}

    def test_defaults_and_fault(self):
        assert parse_mpls_sysctls(load('sysctl_st_p_initial.txt'))['platform_labels'] == 0
        fault = parse_mpls_sysctls(load('sysctl_fix_p1_initial.txt'))
        assert fault['input'] == {'eth0': 0, 'eth1': 1, 'lo': 0} and fault['platform_labels'] == 100000

    def test_modules_missing(self):
        # no /proc/sys/net/mpls: grep fails, every key is missing
        assert parse_mpls_sysctls('') == {'input': {}}
        assert get_mpls_sysctls(make_grade('grep: /proc/sys/net/mpls: No such file or directory\n', 2),
                                'r1') == {'input': {}}


class TestKernelMplsRoutes:
    def test_swap_and_php(self):
        routes = parse_kernel_mpls_routes(load('ilm_st_p_final.json'))
        assert routes == {381: {'protocol': None, 'nexthops': [{'out_labels': [409], 'via': '10.161.16.6', 'dev': 'eth1'}]},
                          509: {'protocol': None, 'nexthops': [{'out_labels': [], 'via': '10.161.16.1', 'dev': 'eth0'}]}}
        assert mpls_route_is_swap(routes, 381, [409], '10.161.16.6') and mpls_route_is_swap(routes, 381, 409)
        assert not mpls_route_is_swap(routes, 381, [410]) and not mpls_route_is_swap(routes, 381, [409], '10.0.0.1')
        assert mpls_route_is_pop(routes, 509, via='10.161.16.1') and not mpls_route_is_pop(routes, 381)

    def test_local_pop(self):
        routes = parse_kernel_mpls_routes(load('ilm_st_pe2_final.json'))
        assert routes[409]['nexthops'] == [{'out_labels': [], 'via': None, 'dev': 'lo'}]
        assert mpls_route_is_pop(routes, 409, dev='lo') and not mpls_route_is_pop(routes, 409, dev='eth0')

    def test_routes_of_the_daemons(self):
        ldp = parse_kernel_mpls_routes(load('ilm_ldp_p1_final.json'))
        assert sorted(ldp) == [16, 17, 18, 19, 20] and ldp[18]['protocol'] == 'ldp'
        assert mpls_route_is_swap(ldp, 18, [19]) and mpls_route_is_pop(ldp, 19)
        sr = parse_kernel_mpls_routes(load('ilm_sr_r4_final.json'))
        assert mpls_route_is_pop(sr, 17040, dev='lo') and mpls_route_is_swap(sr, 17021, [50021])

    def test_empty_and_garbage(self):
        assert parse_kernel_mpls_routes(load('ilm_st_p_initial.json')) == {}
        assert parse_kernel_mpls_routes('') == {} and parse_kernel_mpls_routes('{}') == {}
        assert get_kernel_mpls_routes(make_grade('', 1), 'r1') == {}

    def test_multipath_and_stack(self):
        text = ('[{"dst":"100","nexthops":[{"to":"200/300","via":{"family":"inet","host":"10.0.0.2"},"dev":"eth1"},'
                '{"via":{"family":"inet","host":"10.0.0.6"},"dev":"eth2"}]}]')
        routes = parse_kernel_mpls_routes(text)
        assert routes[100]['nexthops'][0]['out_labels'] == [200, 300]
        assert mpls_route_is_swap(routes, 100, [200, 300]) and mpls_route_is_pop(routes, 100, via='10.0.0.6')


class TestCounters:
    def test_parse(self):
        c = parse_mpls_counters(load('afstats_st_p_final.json'))
        assert set(c) == {'lo', 'eth0', 'eth1'}
        assert c['eth0']['rx_packets'] == 36 and c['eth0']['rx_errors'] == 1 and c['eth0']['tx_packets'] == 0
        assert c['eth1']['tx_packets'] == 35 and c['eth1']['rx_noroute'] == 0

    def test_delta(self):
        before = parse_mpls_counters(load('afstats_st_p_initial.json'))
        after = parse_mpls_counters(load('afstats_st_p_final.json'))
        assert mpls_counter_delta(before, after, 'eth0') == 36
        assert mpls_counter_delta(before, after, 'eth1', key='tx_packets') == 35
        assert mpls_counter_delta(after, before, 'eth0') == 0
        assert mpls_counter_delta({}, after, 'eth0') == 0 and mpls_counter_delta(before, after, 'eth9') == 0

    def test_get_registers_one_command_per_step(self):
        grade = make_grade(load('afstats_st_p_final.json'))
        assert get_mpls_counters(grade, 'st_p', step=3)['eth0']['rx_packets'] == 36
        assert grade.test.call_args[0][1] == MPLS_COUNTERS_CMD and grade.test.call_args[1]['step'] == 3
        assert parse_mpls_counters('') == {}


class TestHelpers:
    @pytest.mark.parametrize('text, labels', [('381', [381]), ('16003/16005', [16003, 16005]), ('', []), (None, [])])
    def test_parse_labels(self, text, labels):
        assert parse_labels(text) == labels

    def test_trigger_command(self):
        cmd = trigger_mpls_modules_cmd(wait_tenths=7)
        assert cmd.startswith('ip route add 198.51.100.255/32 encap mpls 16 dev lo')
        assert 'ip route del 198.51.100.255/32' in cmd and '-lt 7' in cmd
        assert cmd.endswith('test -e /proc/sys/net/mpls/platform_labels')
