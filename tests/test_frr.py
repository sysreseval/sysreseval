"""Tests for lib/frr.py — OSPF and BGP parsers (fixtures in tests/mock_data/frr are real FRR 9.1.3 captures)."""
import json
import sys
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

from frr import get_ospf_interfaces


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_grade(cmd_output: str, exit_code: int = 0):
    grade = MagicMock()
    grade.test.return_value = (cmd_output, exit_code)
    return grade


OSPF_TWO_IFACES = """\
eth0 is up
  ifindex 13, MTU 1500 bytes, BW 10000 Mbit <UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>
  Internet Address 10.150.180.224/28, Broadcast 10.150.180.239, Area 0.0.0.0
  MTU mismatch detection: enabled
  Router ID 10.150.180.224, Network Type BROADCAST, Cost: 10
  Transmit Delay is 1 sec, State Backup, Priority 1
  Designated Router (ID) 172.23.52.228 Interface Address 10.150.180.230/28
  Backup Designated Router (ID) 10.150.180.224, Interface Address 10.150.180.224
  Multicast group memberships: OSPFAllRouters OSPFDesignatedRouters
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
    Hello due in 9.090s
  Neighbor Count is 1, Adjacent neighbor count is 1
  Graceful Restart hello delay: 10s
  LSA retransmissions: 1
eth1 is up
  ifindex 21, MTU 1500 bytes, BW 10000 Mbit <UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>
  Internet Address 10.106.40.105/28, Broadcast 10.106.40.111, Area 0.0.0.0
  MTU mismatch detection: enabled
  Router ID 10.150.180.224, Network Type BROADCAST, Cost: 10
  Transmit Delay is 1 sec, State Backup, Priority 1
  Designated Router (ID) 172.23.52.231 Interface Address 10.106.40.107/28
  Backup Designated Router (ID) 10.150.180.224, Interface Address 10.106.40.105
  Multicast group memberships: OSPFAllRouters OSPFDesignatedRouters
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
    Hello due in 9.090s
  Neighbor Count is 1, Adjacent neighbor count is 1
  Graceful Restart hello delay: 10s
  LSA retransmissions: 2
"""


# ---------------------------------------------------------------------------
# Basic parsing — two interfaces
# ---------------------------------------------------------------------------

class TestTwoInterfaces:
    def setup_method(self):
        self.result = get_ospf_interfaces(make_grade(OSPF_TWO_IFACES), 'r1')

    def test_returns_two_interfaces(self):
        assert set(self.result.keys()) == {'eth0', 'eth1'}

    def test_state_up(self):
        assert self.result['eth0']['state'] == 'up'
        assert self.result['eth1']['state'] == 'up'

    def test_internet_address(self):
        assert self.result['eth0']['internet_address'] == '10.150.180.224/28'
        assert self.result['eth1']['internet_address'] == '10.106.40.105/28'

    def test_broadcast(self):
        assert self.result['eth0']['broadcast'] == '10.150.180.239'
        assert self.result['eth1']['broadcast'] == '10.106.40.111'

    def test_area(self):
        assert self.result['eth0']['area'] == '0.0.0.0'
        assert self.result['eth1']['area'] == '0.0.0.0'

    def test_router_id(self):
        assert self.result['eth0']['router_id'] == '10.150.180.224'

    def test_network_type(self):
        assert self.result['eth0']['network_type'] == 'BROADCAST'

    def test_cost(self):
        assert self.result['eth0']['cost'] == 10
        assert self.result['eth1']['cost'] == 10

    def test_ospf_state(self):
        assert self.result['eth0']['ospf_state'] == 'Backup'
        assert self.result['eth1']['ospf_state'] == 'Backup'

    def test_priority(self):
        assert self.result['eth0']['priority'] == 1
        assert self.result['eth1']['priority'] == 1

    def test_timers(self):
        assert self.result['eth0']['hello_interval'] == 10
        assert self.result['eth0']['dead_interval'] == 40
        assert self.result['eth0']['retransmit_interval'] == 5

    def test_neighbor_counts(self):
        assert self.result['eth0']['neighbor_count'] == 1
        assert self.result['eth0']['adjacent_neighbor_count'] == 1
        assert self.result['eth1']['neighbor_count'] == 1
        assert self.result['eth1']['adjacent_neighbor_count'] == 1

    def test_dr(self):
        assert self.result['eth0']['dr_id'] == '172.23.52.228'
        assert self.result['eth0']['dr_address'] == '10.150.180.230/28'
        assert self.result['eth1']['dr_id'] == '172.23.52.231'
        assert self.result['eth1']['dr_address'] == '10.106.40.107/28'

    def test_bdr(self):
        assert self.result['eth0']['bdr_id'] == '10.150.180.224'
        assert self.result['eth0']['bdr_address'] == '10.150.180.224'
        assert self.result['eth1']['bdr_id'] == '10.150.180.224'
        assert self.result['eth1']['bdr_address'] == '10.106.40.105'

    def test_cost_is_int(self):
        assert isinstance(self.result['eth0']['cost'], int)

    def test_priority_is_int(self):
        assert isinstance(self.result['eth0']['priority'], int)

    def test_intervals_are_int(self):
        assert isinstance(self.result['eth0']['hello_interval'], int)
        assert isinstance(self.result['eth0']['dead_interval'], int)
        assert isinstance(self.result['eth0']['retransmit_interval'], int)

    def test_neighbor_counts_are_int(self):
        assert isinstance(self.result['eth0']['neighbor_count'], int)
        assert isinstance(self.result['eth0']['adjacent_neighbor_count'], int)

    def test_interfaces_are_independent(self):
        # modifying eth0 dict must not affect eth1
        self.result['eth0']['cost'] = 999
        assert self.result['eth1']['cost'] == 10


# ---------------------------------------------------------------------------
# DR state
# ---------------------------------------------------------------------------

OSPF_DR_STATE = """\
eth0 is up
  Internet Address 192.168.1.1/24, Broadcast 192.168.1.255, Area 0.0.0.1
  Router ID 192.168.1.1, Network Type BROADCAST, Cost: 1
  Transmit Delay is 1 sec, State DR, Priority 10
  Designated Router (ID) 192.168.1.1 Interface Address 192.168.1.1/24
  Backup Designated Router (ID) 192.168.1.2, Interface Address 192.168.1.2
  Timer intervals configured, Hello 5s, Dead 20s, Wait 20s, Retransmit 5
  Neighbor Count is 2, Adjacent neighbor count is 2
"""


def test_dr_ospf_state():
    result = get_ospf_interfaces(make_grade(OSPF_DR_STATE), 'r1')
    assert result['eth0']['ospf_state'] == 'DR'


def test_dr_priority():
    result = get_ospf_interfaces(make_grade(OSPF_DR_STATE), 'r1')
    assert result['eth0']['priority'] == 10


def test_dr_dr_fields():
    result = get_ospf_interfaces(make_grade(OSPF_DR_STATE), 'r1')
    assert result['eth0']['dr_id'] == '192.168.1.1'
    assert result['eth0']['dr_address'] == '192.168.1.1/24'


def test_dr_neighbor_count():
    result = get_ospf_interfaces(make_grade(OSPF_DR_STATE), 'r1')
    assert result['eth0']['neighbor_count'] == 2
    assert result['eth0']['adjacent_neighbor_count'] == 2


def test_dr_hello_interval():
    result = get_ospf_interfaces(make_grade(OSPF_DR_STATE), 'r1')
    assert result['eth0']['hello_interval'] == 5
    assert result['eth0']['dead_interval'] == 20


# ---------------------------------------------------------------------------
# Interface down
# ---------------------------------------------------------------------------

OSPF_IFACE_DOWN = """\
eth0 is down
  Internet Address 10.0.0.1/24, Broadcast 10.0.0.255, Area 0.0.0.0
  Router ID 10.0.0.1, Network Type BROADCAST, Cost: 10
  Transmit Delay is 1 sec, State DROther, Priority 0
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
  Neighbor Count is 0, Adjacent neighbor count is 0
"""


def test_interface_down_state():
    result = get_ospf_interfaces(make_grade(OSPF_IFACE_DOWN), 'r1')
    assert result['eth0']['state'] == 'down'


def test_interface_down_neighbor_count_zero():
    result = get_ospf_interfaces(make_grade(OSPF_IFACE_DOWN), 'r1')
    assert result['eth0']['neighbor_count'] == 0


def test_interface_down_dr_none():
    result = get_ospf_interfaces(make_grade(OSPF_IFACE_DOWN), 'r1')
    assert result['eth0']['dr_id'] is None
    assert result['eth0']['dr_address'] is None


def test_dROther_state():
    result = get_ospf_interfaces(make_grade(OSPF_IFACE_DOWN), 'r1')
    assert result['eth0']['ospf_state'] == 'DROther'


# ---------------------------------------------------------------------------
# Error / empty output cases
# ---------------------------------------------------------------------------

def test_nonzero_exit_code_returns_empty():
    grade = make_grade('some output', exit_code=1)
    assert get_ospf_interfaces(grade, 'r1') == {}


def test_empty_output_returns_empty():
    assert get_ospf_interfaces(make_grade(''), 'r1') == {}


def test_no_ospf_running_returns_empty():
    assert get_ospf_interfaces(make_grade('OSPF Routing Process not enabled'), 'r1') == {}


# ---------------------------------------------------------------------------
# grade.test() call arguments
# ---------------------------------------------------------------------------

def test_calls_correct_command():
    grade = make_grade(OSPF_TWO_IFACES)
    get_ospf_interfaces(grade, 'r1', step=3)
    grade.test.assert_called_once_with('r1', 'vtysh -c "show ip ospf interface"', step=3)


# ===========================================================================
# New parsers — fixtures captured on FRR 9.1.3 (tests/mock_data/frr)
# ===========================================================================

import json as _json

from frr import (
    parse_ospf_interfaces, parse_ospf_neighbors, parse_ospf_info, parse_ospf_routes,
    parse_kernel_routes, parse_frr_config, get_ospf_neighbors, get_ospf_info, get_ospf_routes,
    get_kernel_routes, get_frr_running_config, find_neighbor, neighbor_is_full, router_id_map,
    kernel_route_gateways, is_ospf_protocol, normalize_area, expected_auto_cost,
    is_bgp_protocol, BGP_ROUTE_PROTOCOLS, as_list_from_string,
    parse_bgp_summary, get_bgp_summary, parse_bgp_neighbor, get_bgp_neighbor,
    parse_bgp_routes, get_bgp_routes, bgp_best_path, bgp_paths, parse_bgp_prefix, get_bgp_prefix,
    parse_bgp_advertised_routes, get_bgp_advertised_routes,
)

FIXTURES = Path(__file__).parent / 'mock_data' / 'frr'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


# ---------------------------------------------------------------------------
# show ip ospf interface — new fields
# ---------------------------------------------------------------------------

class TestInterfacesReal:
    def test_r4_final(self):
        r = parse_ospf_interfaces(load('interfaces_r4_final.txt'))
        assert set(r) == {'eth0', 'eth1', 'eth2', 'eth3'}
        assert r['eth0']['passive'] is True
        assert r['eth0']['bandwidth'] == 10000
        assert r['eth0']['mtu'] == 1500
        assert r['eth0']['bdr_id'] is None  # "No backup designated router on this network"
        assert r['eth1']['cost'] == 492
        assert r['eth1']['passive'] is False
        assert r['eth2']['hello_interval'] == 2
        assert r['eth2']['dead_interval'] == 8
        assert r['eth3']['area'] == '0.0.0.2'
        assert r['eth3']['ospf_state'] == 'Backup'
        assert r['eth3']['dr_id'] == '6.6.6.6'
        assert r['eth3']['bdr_id'] == '4.4.4.4'
        assert all(v['ospf_enabled'] for v in r.values())

    def test_r1_initial(self):
        r = parse_ospf_interfaces(load('interfaces_r1_initial.txt'))
        assert r['eth0']['passive'] is True and r['eth0']['cost'] == 10
        assert r['eth0']['dr_id'] == '1.1.1.1' and r['eth0']['bdr_id'] is None
        assert r['eth1']['ospf_state'] == 'Backup' and r['eth1']['dr_id'] == '192.168.169.81'
        assert r['eth2']['neighbor_count'] == 0

    def test_ospf_not_running(self):
        assert parse_ospf_interfaces(load('interfaces_r3_none.txt')) == {}

    def test_interface_without_ospf(self):
        text = ("eth3 is up\n"
                "  ifindex 9, MTU 1500 bytes, BW 10000 Mbit <UP,BROADCAST,RUNNING,MULTICAST>\n"
                "  OSPF not enabled on this interface\n")
        r = parse_ospf_interfaces(text)
        assert r['eth3']['ospf_enabled'] is False
        assert r['eth3']['area'] is None
        assert r['eth3']['bandwidth'] == 10000

    def test_point_to_point_address_line(self):
        text = ("eth1 is up\n"
                "  Internet Address 10.0.0.1/30, Area 0.0.0.0\n"
                "  Router ID 1.1.1.1, Network Type POINTOPOINT, Cost: 10\n")
        r = parse_ospf_interfaces(text)
        assert r['eth1']['internet_address'] == '10.0.0.1/30'
        assert r['eth1']['area'] == '0.0.0.0'
        assert r['eth1']['network_type'] == 'POINTOPOINT'

    def test_allow_error_kwarg(self):
        grade = make_grade(load('interfaces_r4_final.txt'))
        get_ospf_interfaces(grade, 'r4', step=2, allow_error=True)
        grade.test.assert_called_once_with('r4', 'vtysh -c "show ip ospf interface"', step=2, allow_error=True)


# ---------------------------------------------------------------------------
# show ip ospf neighbor
# ---------------------------------------------------------------------------

class TestNeighbors:
    def test_real(self):
        n = parse_ospf_neighbors(load('neighbors_r1_final.txt'))
        assert [x['neighbor_id'] for x in n] == ['3.3.3.3', '192.168.169.81', '4.4.4.4']
        assert n[0] == {
            'neighbor_id': '3.3.3.3', 'priority': 100, 'state': 'Full', 'role': 'DR',
            'up_time': '1m12s', 'dead_time': '32.730s', 'address': '192.168.142.154',
            'interface': 'eth1', 'local_address': '192.168.142.196',
        }
        assert n[1]['priority'] == 0 and n[1]['role'] == 'DROther'
        assert n[2]['interface'] == 'eth2'

    def test_without_up_time_column(self):
        text = ("Neighbor ID     Pri State           Dead Time Address         Interface            RXmtL RqstL DBsmL\n"
                "10.0.0.2          1 Full/DR           36.245s 10.0.12.2       eth0:10.0.12.1           0     0     0\n"
                "10.0.0.9          1 2-Way/DROther     30.100s 10.0.12.9       eth0:10.0.12.1           0     0     0\n")
        n = parse_ospf_neighbors(text)
        assert len(n) == 2
        assert n[0]['up_time'] is None
        assert n[0]['dead_time'] == '36.245s'
        assert n[0]['address'] == '10.0.12.2'
        assert n[0]['interface'] == 'eth0' and n[0]['local_address'] == '10.0.12.1'
        assert n[1]['state'] == '2-Way' and n[1]['role'] == 'DROther'

    def test_point_to_point_role(self):
        text = "1.1.1.1           1 Full/-          1m00s             35.000s 10.0.0.1        eth1:10.0.0.2    0     0     0\n"
        n = parse_ospf_neighbors(text)
        assert n[0]['state'] == 'Full' and n[0]['role'] == '-'

    def test_not_running(self):
        assert parse_ospf_neighbors(load('neighbors_r3_none.txt')) == []
        assert parse_ospf_neighbors('') == []

    def test_find_and_full(self):
        n = parse_ospf_neighbors(load('neighbors_r1_final.txt'))
        assert find_neighbor(n, interface='eth2')['neighbor_id'] == '4.4.4.4'
        assert find_neighbor(n, neighbor_id='3.3.3.3', interface='eth1') is not None
        assert find_neighbor(n, neighbor_id='3.3.3.3', interface='eth2') is None
        assert neighbor_is_full(n, neighbor_id='192.168.169.81')
        assert not neighbor_is_full(n, neighbor_id='9.9.9.9')
        assert neighbor_is_full(n, address='172.18.219.189')

    def test_get_calls_test(self):
        grade = make_grade(load('neighbors_r1_final.txt'))
        assert len(get_ospf_neighbors(grade, 'r1', allow_error=True)) == 3
        grade.test.assert_called_once_with('r1', 'vtysh -c "show ip ospf neighbor"', step=1, allow_error=True)
        assert get_ospf_neighbors(make_grade('x', exit_code=1), 'r1') == []


# ---------------------------------------------------------------------------
# show ip ospf
# ---------------------------------------------------------------------------

class TestInfo:
    def test_asbr(self):
        i = parse_ospf_info(load('info_r1_final.txt'))
        assert i['router_id'] == '1.1.1.1'
        assert i['asbr'] is True and i['abr'] is False
        a = i['areas']['0.0.0.0']
        assert a['type'] == 'backbone'
        assert (a['interfaces'], a['active_interfaces'], a['full_neighbors']) == (3, 3, 3)
        assert a['authentication'] == 'no'

    def test_abr_stub_no_summary(self):
        i = parse_ospf_info(load('info_r3_final.txt'))
        assert i['abr'] is True and i['asbr'] is False
        assert set(i['areas']) == {'0.0.0.0', '0.0.0.1'}
        assert i['areas']['0.0.0.1']['type'] == 'stub'
        assert i['areas']['0.0.0.1']['no_summary'] is True
        assert i['areas']['0.0.0.0']['no_summary'] is False

    def test_normal_area(self):
        i = parse_ospf_info(load('info_r4_final.txt'))
        assert i['areas']['0.0.0.2']['type'] == 'normal'
        assert i['areas']['0.0.0.2']['full_neighbors'] == 1

    def test_stub(self):
        i = parse_ospf_info(load('info_r5_final.txt'))
        assert i['router_id'] == '5.5.5.5'
        assert i['areas']['0.0.0.1']['type'] == 'stub'
        assert i['areas']['0.0.0.1']['no_summary'] is False
        assert i['abr'] is False

    def test_not_running(self):
        assert parse_ospf_info('') == {}
        assert parse_ospf_info('% OSPF is not enabled in vrf default\n') == {}
        assert get_ospf_info(make_grade(''), 'r3') == {}

    def test_router_id_map(self):
        grade = MagicMock()

        def _test(machine, command, **kwargs):
            return ({'r1': load('info_r1_final.txt'), 'r5': load('info_r5_final.txt')}.get(machine, ''), 0)

        grade.test.side_effect = _test
        assert router_id_map(grade, ['r1', 'r3', 'r5']) == {'1.1.1.1': 'r1', '5.5.5.5': 'r5'}


# ---------------------------------------------------------------------------
# show ip ospf route
# ---------------------------------------------------------------------------

class TestOspfRoutes:
    def test_abr_table(self):
        r = parse_ospf_routes(load('routes_r4_final.txt'))
        d = r['10.137.0.0/22']
        assert d['kind'] == 'D' and d['type'] == 'IA' and d['discard'] is True and d['cost'] is None
        e = r['203.0.113.0/24']
        assert (e['kind'], e['type'], e['cost'], e['ext_cost'], e['tag']) == ('N', 'E2', 200, 20, 0)
        assert e['nexthops'] == [('192.168.169.81', 'eth2')]
        assert r['0.0.0.0/0']['type'] == 'E2' and r['0.0.0.0/0']['ext_cost'] == 10
        assert r['10.137.2.0/30']['nexthops'] == [(None, 'eth3')]
        assert r['172.16.241.0/24']['type'] == 'IA' and r['172.16.241.0/24']['area'] == '0.0.0.0'
        assert r['1.1.1.1']['kind'] == 'R' and r['1.1.1.1']['asbr'] is True and r['1.1.1.1']['abr'] is False
        assert r['3.3.3.3']['abr'] is True

    def test_router_entry_with_ia_after_id(self):
        r = parse_ospf_routes(load('routes_r7_final.txt'))
        assert r['1.1.1.1'] == {
            'kind': 'R', 'type': 'IA', 'cost': 400, 'ext_cost': None, 'tag': None, 'area': '0.0.0.2',
            'abr': False, 'asbr': True, 'discard': False, 'nexthops': [('10.137.2.5', 'eth1')],
        }
        # regression: the "R 1.1.1.1 IA [400]" line must not leak its next hop into the previous entry
        assert r['192.168.169.80/30']['nexthops'] == [('10.137.2.5', 'eth1')]
        assert r['203.0.113.0/24']['type'] == 'E2' and r['203.0.113.0/24']['cost'] == 400

    def test_stub_default(self):
        r = parse_ospf_routes(load('routes_r5_final.txt'))
        assert r['0.0.0.0/0']['type'] == 'IA'
        assert r['0.0.0.0/0']['nexthops'] == [('172.25.145.122', 'eth1')]
        assert '203.0.113.0/24' not in r

    def test_not_running(self):
        assert parse_ospf_routes(load('routes_r3_none.txt')) == {}
        assert get_ospf_routes(make_grade('', 0), 'r3') == {}

    def test_get_calls_test(self):
        grade = make_grade(load('routes_r5_final.txt'))
        get_ospf_routes(grade, 'r5', step=3)
        grade.test.assert_called_once_with('r5', 'vtysh -c "show ip ospf route"', step=3)


# ---------------------------------------------------------------------------
# ip -j route
# ---------------------------------------------------------------------------

class TestKernelRoutes:
    def test_real(self):
        r = parse_kernel_routes(load('iproute_r1_final.json'))
        assert r['0.0.0.0/0']['protocol'] == 'static'
        assert r['10.139.140.0/22'] == {'protocol': 'ospf', 'metric': 20, 'scope': None,
                                       'nexthops': [('172.22.40.54', 'eth1')], 'labels': [[]], 'type': 'unicast'}
        assert r['192.168.226.0/24']['protocol'] == 'kernel'
        assert r['192.168.226.0/24']['nexthops'] == [(None, 'eth0')]
        assert r['192.168.226.0/24']['scope'] == 'link'

    def test_gateways_helper(self):
        r = parse_kernel_routes(load('iproute_r1_final.json'))
        assert kernel_route_gateways(r, '10.139.140.0/22') == ['172.22.40.54']
        assert kernel_route_gateways(r, '203.0.113.0/24') == []  # static, not OSPF
        assert kernel_route_gateways(r, '203.0.113.0/24', ospf_only=False) == ['192.168.89.221']
        assert kernel_route_gateways(r, '1.2.3.0/24') == []

    def test_ecmp_and_host_route(self):
        text = _json.dumps([
            {"dst": "10.4.0.0/24", "nhid": 30, "protocol": "ospf", "metric": 30, "flags": [],
             "nexthops": [{"gateway": "10.0.13.1", "dev": "eth0", "weight": 1, "flags": []},
                          {"gateway": "10.0.13.2", "dev": "eth0", "weight": 1, "flags": []}]},
            {"dst": "10.9.9.9", "gateway": "10.0.13.1", "dev": "eth0", "protocol": "188", "metric": 20, "flags": []},
            {"dst": "default", "gateway": "10.0.0.1", "dev": "eth1", "protocol": "boot", "flags": []},
        ])
        r = parse_kernel_routes(text)
        assert r['10.4.0.0/24']['nexthops'] == [('10.0.13.1', 'eth0'), ('10.0.13.2', 'eth0')]
        assert kernel_route_gateways(r, '10.4.0.0/24') == ['10.0.13.1', '10.0.13.2']
        assert r['10.9.9.9/32']['protocol'] == '188' and is_ospf_protocol(r['10.9.9.9/32']['protocol'])
        assert r['0.0.0.0/0']['metric'] == 0 and not is_ospf_protocol('boot')

    def test_stub_router_default_is_ospf(self):
        r = parse_kernel_routes(load('iproute_r5_final.json'))
        assert is_ospf_protocol(r['0.0.0.0/0']['protocol'])
        assert '203.0.113.0/24' not in r

    def test_garbage(self):
        assert parse_kernel_routes('not json') == {}
        assert parse_kernel_routes('{"a": 1}') == {}
        assert get_kernel_routes(make_grade('[]', 1), 'r1') == {}

    def test_get_calls_test(self):
        grade = make_grade('[]')
        get_kernel_routes(grade, 'r1', allow_error=True)
        grade.test.assert_called_once_with('r1', 'ip -j route', step=1, allow_error=True)


# ---------------------------------------------------------------------------
# show running-config
# ---------------------------------------------------------------------------

class TestFrrConfig:
    def test_asbr_config(self):
        c = parse_frr_config(load('config_r1_final.txt'))
        assert c['hostname'] == 'r1'
        assert ('203.0.113.0/24', '192.168.89.221') in c['static_routes']
        ro = c['router_ospf']
        assert ro['present'] and ro['router_id'] == '1.1.1.1'
        assert ro['redistribute'] == ['static']
        assert ro['default_information_originate'] is True and ro['default_information_always'] is False
        assert ro['auto_cost_reference_bandwidth'] == 200000
        assert ('192.168.226.0/24', '0.0.0.0') in ro['networks']
        assert c['interfaces']['eth0']['passive'] is True
        assert c['interfaces']['eth1']['priority'] == 50
        eth2 = c['interfaces']['eth2']
        assert eth2['authentication'] == 'message-digest'
        assert eth2['message_digest_keys'] == {1: 'ABmckuuvDo18'}
        assert eth2['cost'] == 535

    def test_abr_stub_config(self):
        c = parse_frr_config(load('config_r3_final.txt'))
        a = c['router_ospf']['areas']['0.0.0.1']
        assert a['stub'] is True and a['no_summary'] is True and a['nssa'] is False
        assert c['interfaces']['eth0']['bandwidth'] == 1000
        assert c['interfaces']['eth0']['priority'] == 100
        assert ('10.15.50.108/30', '0.0.0.1') in c['router_ospf']['networks']

    def test_range_and_timers(self):
        c = parse_frr_config(load('config_r4_final.txt'))
        assert c['router_ospf']['areas']['0.0.0.2']['ranges'] == ['10.139.140.0/22']
        assert c['router_ospf']['areas']['0.0.0.2']['stub'] is False
        assert c['interfaces']['eth2']['hello_interval'] == 2
        assert c['interfaces']['eth2']['dead_interval'] == 8

    def test_no_ospf(self):
        c = parse_frr_config(load('config_r3_initial.txt'))
        assert c['router_ospf']['present'] is False
        assert c['interfaces'] == {}
        assert get_frr_running_config(make_grade(''), 'r3') == {}

    def test_legacy_syntax(self):
        text = ("router ospf\n"
                " ospf router-id 9.9.9.9\n"
                " passive-interface eth0\n"
                " passive-interface default\n"
                " network 10.1.0.0/24 area 1\n"
                " area 1 stub\n"
                " area 0 authentication message-digest\n"
                " area 2 range 10.2.0.0/22 not-advertise\n"
                " default-information originate always metric 5\n"
                " redistribute connected metric-type 1\n"
                "!\n"
                "interface eth3\n"
                " ip ospf area 2\n"
                " ip ospf network point-to-point\n"
                " ip ospf dead-interval 8\n"
                " ip ospf authentication\n"
                " ip ospf authentication-key secret\n"
                " no ip ospf passive\n"
                "!\n")
        c = parse_frr_config(text)
        ro = c['router_ospf']
        assert ro['router_id'] == '9.9.9.9'
        assert ro['passive_interfaces'] == ['eth0'] and ro['passive_default'] is True
        assert ro['networks'] == [('10.1.0.0/24', '0.0.0.1')]
        assert ro['areas']['0.0.0.1']['stub'] is True and ro['areas']['0.0.0.1']['no_summary'] is False
        assert ro['areas']['0.0.0.0']['authentication'] == 'message-digest'
        assert ro['areas']['0.0.0.2']['ranges'] == ['10.2.0.0/22']
        assert ro['default_information_originate'] and ro['default_information_always']
        assert ro['redistribute'] == ['connected']
        eth3 = c['interfaces']['eth3']
        assert eth3['area'] == '0.0.0.2'
        assert eth3['network_type'] == 'point-to-point'
        assert eth3['dead_interval'] == 8
        assert eth3['authentication'] == 'simple' and eth3['authentication_key'] == 'secret'
        assert eth3['passive'] is False

    def test_normalize_area(self):
        assert normalize_area('1') == '0.0.0.1'
        assert normalize_area(' 10 ') == '0.0.0.10'
        assert normalize_area('0.0.0.2') == '0.0.0.2'
        assert normalize_area(256) == '0.0.1.0'


# ---------------------------------------------------------------------------
# cost helper
# ---------------------------------------------------------------------------

def test_expected_auto_cost():
    assert expected_auto_cost(100000, 10000) == 10      # FRR defaults on a veth
    assert expected_auto_cost(1000000, 10000) == 100
    assert expected_auto_cost(1000000, 1000) == 1000
    assert expected_auto_cost(100000, 10000000) == 1    # never below 1
    assert expected_auto_cost(4294967, 1) == 65535      # clamped
    assert expected_auto_cost(100000, 0) == 10          # unknown bandwidth: FRR default cost


# ---------------------------------------------------------------------------
# BGP — json output
# ---------------------------------------------------------------------------

def load_json(name: str) -> dict:
    return json.loads(load(name))


class TestBgpSummary:
    def test_probe(self):
        s = parse_bgp_summary(load_json('bgp_summary_probe.json'))
        assert s['router_id'] == '10.9.9.1' and s['as'] == 65001
        assert set(s['peers']) == {'10.1.1.2', '10.9.9.3'}
        ebgp = s['peers']['10.1.1.2']
        assert ebgp['remote_as'] == 65100 and ebgp['state'] == 'Active' and ebgp['established'] is False
        assert ebgp['policy_blocked'] is True      # eBGP peer without policy (RFC 8212)
        assert ebgp['description'] == 'ISP-A' and ebgp['pfx_rcd'] == 0
        ibgp = s['peers']['10.9.9.3']
        assert ibgp['policy_blocked'] is False and ibgp['state'] == 'Connect' and ibgp['description'] is None

    def test_wrapped_output(self):
        s = parse_bgp_summary({'ipv4Unicast': load_json('bgp_summary_probe.json')})
        assert s['as'] == 65001 and len(s['peers']) == 2

    def test_established_peer(self):
        data = {'routerId': '1.1.1.1', 'as': 65001,
                'peers': {'10.0.0.2': {'remoteAs': 65200, 'state': 'Established', 'peerState': 'OK',
                                       'pfxRcd': 3, 'pfxSnt': 1, 'peerUptime': '00:01:02'}}}
        p = parse_bgp_summary(data)['peers']['10.0.0.2']
        assert p['established'] is True and p['pfx_rcd'] == 3 and p['pfx_snt'] == 1 and p['uptime'] == '00:01:02'

    def test_empty_shapes(self):
        assert parse_bgp_summary({}) == {}
        assert parse_bgp_summary(None) == {}
        assert parse_bgp_summary({'ipv4Unicast': {}}) == {}
        assert get_bgp_summary(make_grade(''), 'r1') == {}
        assert get_bgp_summary(make_grade('% No BGP process is configured'), 'r1') == {}
        assert get_bgp_summary(make_grade('{}', 1), 'r1') == {}

    def test_calls_json_command(self):
        grade = make_grade(load('bgp_summary_probe.json'))
        get_bgp_summary(grade, 'r3', step=2, allow_error=True)
        grade.test.assert_called_once_with('r3', 'vtysh -c "show bgp ipv4 unicast summary json"', step=2,
                                           allow_error=True)


class TestBgpRoutes:
    def test_probe(self):
        r = parse_bgp_routes(load_json('bgp_routes_probe.json'))
        assert set(r) == {'10.9.9.1/32', '10.20.0.0/22'}
        local = r['10.9.9.1/32'][0]
        assert local['valid'] is True and local['best'] is True and local['reason'] == 'First path received'
        assert local['weight'] == 32768 and local['aspath'] == '' and local['as_list'] == []
        assert local['local'] is True and local['nexthop'] == '0.0.0.0' and local['origin'] == 'IGP'
        # `network 10.20.0.0/22` without a matching route (bgp network import-check): not valid
        pending = r['10.20.0.0/22'][0]
        assert pending['valid'] is False and pending['best'] is False and pending['reason'] is None

    def test_received_paths(self):
        data = {'routes': {'203.0.113.0/24': [
            {'valid': True, 'bestpath': True, 'selectionReason': 'Local Pref', 'pathFrom': 'internal',
             'locPrf': 200, 'metric': 0, 'weight': 0, 'peerId': '10.0.7.3', 'path': '65200 65000', 'origin': 'IGP',
             'nexthops': [{'ip': '10.0.7.3', 'afi': 'ipv4', 'used': True}]},
            {'valid': True, 'pathFrom': 'external', 'metric': 0, 'weight': 0, 'peerId': '10.1.1.2',
             'path': '65100 65000', 'origin': 'IGP', 'nexthops': [{'ip': '10.1.1.2', 'afi': 'ipv4', 'used': True}]},
        ]}}
        r = parse_bgp_routes(data)
        best = bgp_best_path(r, '203.0.113.0/24')
        assert best['nexthop'] == '10.0.7.3' and best['locprf'] == 200 and best['path_from'] == 'internal'
        assert best['as_list'] == [65200, 65000] and best['reason'] == 'Local Pref'
        other = [p for p in r['203.0.113.0/24'] if not p['best']][0]
        assert other['locprf'] is None and other['peer'] == '10.1.1.2' and other['local'] is False
        assert bgp_paths(r, '203.0.113.0/24', first_as=65100) == [other]
        assert bgp_paths(r, '203.0.113.0/24', ends_with=[65000]) == r['203.0.113.0/24']
        assert bgp_paths(r, '203.0.113.0/24', peer='10.0.7.3', path_from='internal') == [best]
        assert bgp_paths(r, '203.0.113.0/24', nexthop='1.2.3.4') == []
        assert bgp_paths(r, '10.0.0.0/8') == [] and bgp_best_path(r, '10.0.0.0/8') == {}

    def test_empty_shapes(self):
        assert parse_bgp_routes({}) == {} and parse_bgp_routes({'routes': None}) == {}
        assert get_bgp_routes(make_grade(''), 'r1') == {}
        assert get_bgp_routes(make_grade('not json'), 'r1') == {}
        assert bgp_best_path({}, '10.0.0.0/8') == {}


class TestBgpPrefix:
    def test_probe(self):
        p = parse_bgp_prefix(load_json('bgp_prefix_probe.json'))
        assert p['prefix'] == '10.9.9.1/32' and len(p['paths']) == 1
        path = p['paths'][0]
        assert path['aspath'] == '' and path['local'] is True and path['best'] is True
        assert path['reason'] == 'First path received' and path['accessible'] is True
        assert path['peer'] == '0.0.0.0' and path['peer_router_id'] == '10.9.9.1'
        assert path['originator_id'] is None and path['cluster_list'] == [] and path['communities'] == []

    def test_reflected_path_with_community(self):
        data = {'prefix': '192.168.137.0/24', 'paths': [{
            'aspath': {'string': '65100', 'segments': [{'type': 'as-sequence', 'list': [65100]}], 'length': 1},
            'origin': 'IGP', 'metric': 0, 'locPrf': 100, 'weight': 0, 'valid': True,
            'community': {'string': '65001:300', 'list': ['65001:300']},
            'originatorId': '10.0.7.1', 'clusterList': {'list': ['10.0.7.2']},
            'bestpath': {'overall': True, 'selectionReason': 'First path received'},
            'nexthops': [{'ip': '10.0.7.1', 'afi': 'ipv4', 'metric': 20, 'accessible': True, 'used': True}],
            'peer': {'peerId': '10.0.7.2', 'routerId': '10.0.7.2', 'type': 'internal'}}]}
        path = parse_bgp_prefix(data)['paths'][0]
        assert path['as_list'] == [65100] and path['communities'] == ['65001:300']
        assert path['originator_id'] == '10.0.7.1' and path['cluster_list'] == ['10.0.7.2']
        assert path['path_from'] == 'internal' and path['nexthop'] == '10.0.7.1' and path['locprf'] == 100

    def test_empty_shapes(self):
        assert parse_bgp_prefix({}) == {'prefix': None, 'paths': []}
        assert get_bgp_prefix(make_grade('% Network not in table'), 'r1', '10.0.0.0/8') == {'prefix': None, 'paths': []}
        grade = make_grade('')
        get_bgp_prefix(grade, 'r3', '10.0.0.0/8', allow_error=True)
        grade.test.assert_called_once_with('r3', 'vtysh -c "show bgp ipv4 unicast 10.0.0.0/8 json"', step=1,
                                           allow_error=True)


class TestBgpNeighbor:
    def test_established_neighbor(self):
        data = {'10.0.3.2': {
            'remoteAs': 65200, 'localAs': 65001, 'nbrExternalLink': True, 'nbrDesc': 'ISP-B',
            'remoteRouterId': '200.200.200.200', 'localRouterId': '10.0.7.3', 'bgpState': 'Established',
            'bgpTimerHoldTimeMsecs': 30000, 'bgpTimerKeepAliveIntervalMsecs': 10000,
            'bgpTimerConfiguredHoldTimeMsecs': 30000, 'bgpTimerConfiguredKeepAliveIntervalMsecs': 10000,
            'hostLocal': '10.0.3.1', 'hostForeign': '10.0.3.2',
            'addressFamilyInfo': {'ipv4Unicast': {
                'routeMapForIncomingAdvertisements': 'LP-IN', 'routeMapForOutgoingAdvertisements': 'TO-ISPB',
                'acceptedPrefixCounter': 3, 'sentPrefixCounter': 2, 'commAttriSentToNbr': 'extendedAndStandard'}}}}
        n = parse_bgp_neighbor(data, '10.0.3.2')
        assert n['peer'] == '10.0.3.2' and n['remote_as'] == 65200 and n['established'] is True
        assert n['link'] == 'external' and n['description'] == 'ISP-B'
        assert n['hold_time'] == 30 and n['keepalive'] == 10 and n['configured_hold_time'] == 30
        assert n['local_host'] == '10.0.3.1' and n['foreign_host'] == '10.0.3.2'
        assert n['route_map_in'] == 'LP-IN' and n['route_map_out'] == 'TO-ISPB'
        assert n['accepted_prefixes'] == 3 and n['sent_prefixes'] == 2
        assert n['route_reflector_client'] is False and n['next_hop_self'] is False and n['default_originate'] is False
        assert n['send_community'] is True
        assert parse_bgp_neighbor(data)['peer'] == '10.0.3.2'      # first (only) entry when peer is omitted

    def test_rr_client_flags(self):
        data = {'10.0.7.1': {'remoteAs': 65001, 'localAs': 65001, 'nbrInternalLink': True, 'bgpState': 'Established',
                             'updateSource': 'lo',
                             'addressFamilyInfo': {'ipv4Unicast': {'routeReflectorClient': True,
                                                                   'routerAlwaysNextHop': True,
                                                                   'defaultSent': True}}}}
        n = parse_bgp_neighbor(data, '10.0.7.1')
        assert n['link'] == 'internal' and n['update_source'] == 'lo'
        assert n['route_reflector_client'] is True and n['next_hop_self'] is True and n['default_originate'] is True

    def test_empty_shapes(self):
        assert parse_bgp_neighbor({}) == {}
        assert parse_bgp_neighbor({'bgpNoSuchNeighbor': True}) == {}
        assert parse_bgp_neighbor({'10.0.0.1': {'remoteAs': 1}}, '10.0.0.2') == {}
        assert get_bgp_neighbor(make_grade(''), 'r1', '10.0.0.1') == {}
        grade = make_grade('{}')
        get_bgp_neighbor(grade, 'r2', '10.0.7.1', step=3)
        grade.test.assert_called_once_with('r2', 'vtysh -c "show bgp neighbors 10.0.7.1 json"', step=3)


class TestBgpAdvertised:
    def test_advertised(self):
        data = {'bgpTableVersion': 12, 'bgpLocalRouterId': '10.0.7.1', 'defaultLocPrf': 100, 'localAS': 65001,
                'advertisedRoutes': {
                    '10.0.4.0/22': {'addrPrefix': '10.0.4.0', 'prefixLen': 22, 'network': '10.0.4.0/22',
                                    'nextHop': '10.1.1.1', 'weight': 32768, 'path': '65001 65001',
                                    'bgpOriginCode': 'i', 'appliedStatusSymbols': {'*': True, '>': True}},
                    '172.26.245.0/24': {'nextHop': '10.1.1.1', 'metric': 0, 'locPrf': 100, 'weight': 0,
                                        'path': '65001 65001 65300', 'bgpOriginCode': 'i'}},
                'totalPrefixCounter': 2, 'filteredPrefixCounter': 0}
        a = parse_bgp_advertised_routes(data)
        assert set(a) == {'10.0.4.0/22', '172.26.245.0/24'}
        assert a['10.0.4.0/22']['as_list'] == [65001, 65001] and a['10.0.4.0/22']['origin'] == 'i'
        assert a['172.26.245.0/24']['as_list'] == [65001, 65001, 65300] and a['172.26.245.0/24']['locprf'] == 100
        assert a['10.0.4.0/22']['nexthop'] == '10.1.1.1'

    def test_empty_shapes(self):
        assert parse_bgp_advertised_routes({}) == {} and parse_bgp_advertised_routes({'advertisedRoutes': None}) == {}
        assert get_bgp_advertised_routes(make_grade(''), 'r1', '10.1.1.2') == {}
        grade = make_grade('{"advertisedRoutes": {}}')
        get_bgp_advertised_routes(grade, 'r1', '10.1.1.2', allow_error=True)
        grade.test.assert_called_once_with(
            'r1', 'vtysh -c "show bgp ipv4 unicast neighbors 10.1.1.2 advertised-routes json"', step=1, allow_error=True)


class TestBgpMisc:
    def test_is_bgp_protocol(self):
        assert is_bgp_protocol('bgp') and is_bgp_protocol(186) and not is_bgp_protocol('ospf')
        assert BGP_ROUTE_PROTOCOLS == ('bgp', '186')

    def test_as_list_from_string(self):
        assert as_list_from_string('65100 65000') == [65100, 65000]
        assert as_list_from_string('') == [] and as_list_from_string(None) == []
        assert as_list_from_string('65001 {65100,65200}') == [65001, 65100, 65200]

    def test_kernel_route_gateways_protocols(self):
        routes = {'203.0.113.0/24': {'protocol': 'bgp', 'metric': 20, 'scope': None, 'nexthops': [('10.0.1.2', 'eth1')]},
                  '10.0.5.0/24': {'protocol': 'ospf', 'metric': 20, 'scope': None, 'nexthops': [('10.0.1.2', 'eth1')]}}
        assert kernel_route_gateways(routes, '203.0.113.0/24') == []                       # ospf only by default
        assert kernel_route_gateways(routes, '203.0.113.0/24', protocols=BGP_ROUTE_PROTOCOLS) == ['10.0.1.2']
        assert kernel_route_gateways(routes, '10.0.5.0/24', protocols=BGP_ROUTE_PROTOCOLS) == []
        assert kernel_route_gateways(routes, '203.0.113.0/24', ospf_only=False) == ['10.0.1.2']


class TestFrrConfigBgp:
    def test_probe_config(self):
        c = parse_frr_config(load('config_bgp_probe.txt'))
        rb = c['router_bgp']
        assert rb['present'] and rb['as'] == 65001 and rb['router_id'] is None
        assert rb['ebgp_requires_policy'] is True and rb['network_import_check'] is True
        assert rb['networks'] == ['10.9.9.1/32', '10.20.0.0/22']
        ispa = rb['neighbors']['10.1.1.2']
        assert ispa['remote_as'] == 65100 and ispa['description'] == 'ISP-A' and ispa['timers'] == (10, 30)
        assert ispa['default_originate'] is True and ispa['route_map_out'] == 'OUT' and ispa['route_map_in'] is None
        rr = rb['neighbors']['10.9.9.3']
        assert rr['remote_as'] == 65001 and rr['update_source'] == 'lo'
        assert rr['route_reflector_client'] is True and rr['next_hop_self'] is True
        assert c['prefix_lists'] == {'P': [{'seq': 5, 'action': 'permit', 'prefix': '10.20.0.0/22', 'ge': None, 'le': None}]}
        assert c['route_maps'] == {'OUT': [{'seq': 10, 'action': 'permit', 'match': ['ip address prefix-list P'],
                                            'set': ['as-path prepend 65001 65001']}]}
        assert c['as_path_lists'] == {'CUST': [(5, 'permit', '^65300$')]}
        assert c['interfaces']['lo']['addresses'] == ['10.9.9.1/32']
        assert c['router_ospf']['present'] is False

    def test_flags_and_lists(self):
        text = ("ip route 10.0.4.0/22 blackhole\n"
                "router bgp 65001\n"
                " bgp router-id 10.0.7.3\n"
                " no bgp ebgp-requires-policy\n"
                " no bgp network import-check\n"
                " bgp bestpath compare-routerid\n"
                " bgp cluster-id 9.9.9.9\n"
                " timers bgp 20 60\n"
                " neighbor 10.0.3.2 remote-as 65200\n"
                " neighbor 10.0.3.2 password s3cret\n"
                " neighbor 10.0.3.2 ebgp-multihop 2\n"
                " neighbor 10.0.3.2 shutdown\n"
                " neighbor 10.0.5.1 remote-as 65300\n"
                " !\n"
                " address-family ipv4 unicast\n"
                "  network 10.0.4.0/22\n"
                "  aggregate-address 10.0.0.0/16 summary-only\n"
                "  redistribute connected\n"
                "  neighbor 10.0.3.2 prefix-list MINE out\n"
                "  neighbor 10.0.3.2 filter-list CUST in\n"
                "  neighbor 10.0.5.1 default-originate route-map DEF\n"
                "  neighbor 10.0.5.1 soft-reconfiguration inbound\n"
                "  no neighbor 10.0.5.1 send-community\n"
                " exit-address-family\n"
                "exit\n"
                "!\n"
                "ip prefix-list MINE seq 5 permit 10.0.4.0/22\n"
                "ip prefix-list MINE seq 10 permit 10.0.0.0/8 ge 24 le 24\n"
                "ip prefix-list ANY permit 0.0.0.0/0 le 32\n"
                "!\n"
                "bgp community-list standard CUST seq 5 permit 65001:300\n"
                "!\n"
                "route-map DEF permit 10\n"
                " match ip address prefix-list MINE\n"
                " set local-preference 200\n"
                " set community 65001:300\n"
                "exit\n"
                "route-map DEF deny 20\n"
                "exit\n")
        c = parse_frr_config(text)
        assert ('10.0.4.0/22', 'blackhole') in c['static_routes']
        rb = c['router_bgp']
        assert rb['router_id'] == '10.0.7.3' and rb['ebgp_requires_policy'] is False
        assert rb['network_import_check'] is False and rb['bestpath'] == ['compare-routerid']
        assert rb['cluster_id'] == '9.9.9.9' and rb['timers'] == (20, 60)
        assert rb['networks'] == ['10.0.4.0/22'] and rb['redistribute'] == ['connected']
        assert rb['aggregate_addresses'] == [('10.0.0.0/16', ['summary-only'])]
        n = rb['neighbors']['10.0.3.2']
        assert n['password'] == 's3cret' and n['ebgp_multihop'] == 2 and n['shutdown'] is True
        assert n['prefix_list_out'] == 'MINE' and n['filter_list_in'] == 'CUST'
        cust = rb['neighbors']['10.0.5.1']
        assert cust['default_originate'] is True and cust['default_originate_route_map'] == 'DEF'
        assert cust['soft_reconfiguration'] is True and cust['send_community'] is False
        assert c['prefix_lists']['MINE'][1] == {'seq': 10, 'action': 'permit', 'prefix': '10.0.0.0/8', 'ge': 24, 'le': 24}
        assert c['prefix_lists']['ANY'] == [{'seq': None, 'action': 'permit', 'prefix': '0.0.0.0/0', 'ge': None, 'le': 32}]
        assert c['community_lists'] == {'CUST': [(5, 'permit', '65001:300')]}
        assert [e['action'] for e in c['route_maps']['DEF']] == ['permit', 'deny']
        assert c['route_maps']['DEF'][0]['set'] == ['local-preference 200', 'community 65001:300']

    def test_no_bgp(self):
        c = parse_frr_config(load('config_r3_initial.txt'))
        assert c['router_bgp']['present'] is False and c['router_bgp']['neighbors'] == {}
        assert c['prefix_lists'] == {} and c['route_maps'] == {}


class TestBgpRealCaptures:
    """Real FRR 9.1.3 captures from lab/em/s4/bgp.py (initial state, r3 without policy, final state)."""

    def test_policy_blocked_peer(self):
        s = parse_bgp_summary(load_json('bgp_summary_r3_policy.json'))
        p = s['peers']['172.18.192.126']
        assert s['router_id'] == '172.18.95.3' and s['as'] == 65001
        assert p['established'] is True and p['policy_blocked'] is True and p['pfx_rcd'] == 0 and p['pfx_snt'] == 0
        assert '(Policy)' in load('show_ip_bgp_summary_r3_policy.txt')

    def test_isp_sees_unconfigured_peer_active(self):
        s = parse_bgp_summary(load_json('bgp_summary_ispb_initial.json'))
        r3 = s['peers']['172.18.192.125']
        assert r3['state'] == 'Active' and r3['established'] is False and r3['policy_blocked'] is False
        assert s['peers']['172.20.249.157']['established'] and s['peers']['172.20.249.157']['pfx_rcd'] == 3

    def test_no_bgp_outputs(self):
        assert parse_bgp_summary(json.loads(load('bgp_summary_r4_nobgp.txt').split('exit=')[0])) == {}
        assert parse_bgp_routes(json.loads(load('bgp_routes_r4_nobgp.txt').split('exit=')[0])) == {}
        assert parse_bgp_neighbor(json.loads(load('bgp_neighbor_r1_unknown.txt').split('exit=')[0])) == {}
        assert parse_bgp_prefix(json.loads(load('bgp_prefix_r1_unknown.txt').split('exit=')[0])) == {'prefix': None, 'paths': []}
        assert get_bgp_summary(make_grade(load('bgp_summary_r4_nobgp.txt').split('exit=')[0]), 'r4') == {}

    def test_import_check_pending_network(self):
        r = parse_bgp_routes(load_json('bgp_routes_r3_importcheck.json'))
        p = r['172.18.92.0/22'][0]
        assert p['valid'] is False and p['best'] is False and p['local'] is True and p['weight'] == 32768

    def test_neighbor_ebgp_with_timers_and_policies(self):
        n = parse_bgp_neighbor(load_json('bgp_neighbor_r3_ispb_final.json'), '172.18.192.126')
        assert n['established'] and n['link'] == 'external' and n['remote_as'] == 65200 and n['description'] == 'ISP-B'
        assert n['hold_time'] == 45 and n['keepalive'] == 15 and n['configured_hold_time'] == 45
        assert n['local_host'] == '172.18.192.125' and n['foreign_host'] == '172.18.192.126' and n['update_source'] is None
        assert n['route_map_in'] == 'LP-IN' and n['route_map_out'] == 'TO-ISPB'
        assert n['accepted_prefixes'] == 3 and n['sent_prefixes'] == 2 and n['send_community'] is True
        assert n['route_reflector_client'] is False and n['next_hop_self'] is False and n['default_originate'] is False

    def test_neighbor_ibgp_flags(self):
        rr = parse_bgp_neighbor(load_json('bgp_neighbor_r2_lo1_final.json'), '172.18.95.1')
        assert rr['link'] == 'internal' and rr['update_source'] == 'lo' and rr['route_reflector_client'] is True
        assert rr['local_host'] == '172.18.95.2' and rr['foreign_host'] == '172.18.95.1' and rr['hold_time'] == 180
        nhs = parse_bgp_neighbor(load_json('bgp_neighbor_r1_lo2_final.json'), '172.18.95.2')
        assert nhs['next_hop_self'] is True and nhs['route_reflector_client'] is False
        cust = parse_bgp_neighbor(load_json('bgp_neighbor_r3_r4_final.json'), '192.168.162.33')
        assert cust['remote_as'] == 65300 and cust['default_originate'] is True
        assert cust['route_map_in'] == 'FROM-R4' and cust['route_map_out'] == 'TO-R4'
        assert parse_bgp_neighbor(load_json('bgp_neighbor_r1_ispa_initial.json'))['remote_router_id'] == '100.100.100.100'

    def test_routes_local_pref_and_tie_breaks(self):
        r1 = parse_bgp_routes(load_json('bgp_routes_r1_final.json'))
        web = bgp_best_path(r1, '203.0.113.0/24')
        assert web['nexthop'] == '172.18.95.3' and web['locprf'] == 200 and web['reason'] == 'Local Pref'
        assert web['path_from'] == 'internal' and web['as_list'] == [65200, 65000] and web['peer'] == '172.18.95.2'
        assert bgp_paths(r1, '203.0.113.0/24', path_from='external')[0]['as_list'] == [65100, 65000]
        assert bgp_best_path(r1, '10.223.94.0/24')['reason'] == 'AS Path'
        assert bgp_best_path(r1, '192.168.195.0/24')['path_from'] == 'external'
        r2 = parse_bgp_routes(load_json('bgp_routes_r2_final.json'))
        assert [(p['best'], p['nexthop']) for p in r2['172.18.92.0/22']] == [(False, '172.18.95.3'), (True, '172.18.95.1')]
        assert bgp_best_path(r2, '172.18.92.0/22')['reason'] == 'Router ID'
        inet = parse_bgp_routes(load_json('bgp_routes_inet_final.json'))
        assert bgp_best_path(inet, '172.18.92.0/22')['as_list'] == [65200, 65001]
        assert bgp_paths(inet, '172.18.92.0/22', first_as=65100)[0]['as_list'] == [65100, 65200, 65001]
        ispa = parse_bgp_routes(load_json('bgp_routes_ispa_final.json'))
        assert bgp_paths(ispa, '172.18.92.0/22', peer='172.26.133.29')[0]['as_list'] == [65001, 65001, 65001]
        assert bgp_paths(ispa, '10.223.94.0/24', first_as=65001) == []       # no transit leak after filtering
        assert bgp_paths(ispa, '10.148.200.0/24', ends_with=[65001, 65300])   # customer prefix propagated

    def test_prefix_reflected_and_community(self):
        p = parse_bgp_prefix(load_json('bgp_prefix_r3_neta_final.json'))
        assert p['prefix'] == '192.168.195.0/24'
        best = [x for x in p['paths'] if x['best']][0]
        assert best['nexthop'] == '172.18.95.1' and best['originator_id'] == '172.18.95.1'
        assert best['cluster_list'] == ['172.18.95.2'] and best['path_from'] == 'internal' and best['peer'] == '172.18.95.2'
        assert best['reason'] == 'AS Path' and best['accessible'] is True and best['locprf'] == 100
        other = [x for x in p['paths'] if not x['best']][0]
        assert other['originator_id'] is None and other['cluster_list'] == [] and other['as_list'] == [65200, 65100]
        net4 = parse_bgp_prefix(load_json('bgp_prefix_ispa_net4_final.json'))
        assert all(x['communities'] == ['65001:538'] for x in net4['paths'])
        assert [x['as_list'] for x in net4['paths'] if x['best']] == [[65200, 65001, 65300]]

    def test_advertised_routes(self):
        a = parse_bgp_advertised_routes(load_json('bgp_advertised_r1_ispa_final.json'))
        assert set(a) == {'10.148.200.0/24', '172.18.92.0/22'}
        assert a['172.18.92.0/22']['as_list'] == [65001, 65001]              # prepend applied
        assert a['10.148.200.0/24']['as_list'] == [65001, 65001, 65300]
        # before filtering, r1 even sends ISP A's own routes back to it
        assert len(parse_bgp_advertised_routes(load_json('bgp_advertised_r1_ispa_initial.json'))) == 4
        # the default of default-originate is counted but not listed
        d = load_json('bgp_advertised_r3_r4_final.json')
        assert parse_bgp_advertised_routes(d) == {} and d['totalPrefixCounter'] == 1

    def test_kernel_bgp_routes(self):
        r2 = parse_kernel_routes(load('iproute_bgp_r2_final.json'))
        assert is_bgp_protocol(r2['203.0.113.0/24']['protocol'])
        assert kernel_route_gateways(r2, '203.0.113.0/24', protocols=BGP_ROUTE_PROTOCOLS) == ['172.18.94.6']
        assert kernel_route_gateways(r2, '203.0.113.0/24') == []                       # not an OSPF route
        assert sorted(kernel_route_gateways(r2, '172.18.92.0/22', protocols=BGP_ROUTE_PROTOCOLS)) == ['172.18.94.1', '172.18.94.6']
        r4 = parse_kernel_routes(load('iproute_bgp_r4_final.json'))
        assert r4['0.0.0.0/0']['protocol'] == 'bgp' and r4['0.0.0.0/0']['nexthops'] == [('192.168.162.34', 'eth1')]

    def test_running_configs(self):
        c = parse_frr_config(load('config_bgp_r3_final.txt'))
        rb = c['router_bgp']
        assert rb['as'] == 65001 and rb['router_id'] == '172.18.95.3' and rb['ebgp_requires_policy'] is False
        assert rb['networks'] == ['172.18.92.0/22'] and ('172.18.92.0/22', 'blackhole') in c['static_routes']
        ispb = rb['neighbors']['172.18.192.126']
        assert ispb['remote_as'] == 65200 and ispb['timers'] == (15, 45) and ispb['password'] == 'G1IgAnV3EL0H'
        assert ispb['route_map_in'] == 'LP-IN' and ispb['route_map_out'] == 'TO-ISPB'
        assert rb['neighbors']['172.18.95.2']['next_hop_self'] is True and rb['neighbors']['172.18.95.2']['update_source'] == 'lo'
        r4 = rb['neighbors']['192.168.162.33']
        assert r4['default_originate'] is True and r4['route_map_out'] == 'TO-R4' and r4['route_map_in'] == 'FROM-R4'
        assert c['route_maps']['LP-IN'][0]['set'] == ['local-preference 200']
        assert c['route_maps']['LP-IN'][1] == {'seq': 20, 'action': 'permit', 'match': [], 'set': []}
        assert c['route_maps']['FROM-R4'][0]['set'] == ['community 65001:538']
        assert c['prefix_lists']['DEFAULT-ONLY'] == [{'seq': 5, 'action': 'permit', 'prefix': '0.0.0.0/0', 'ge': None, 'le': None}]
        r2 = parse_frr_config(load('config_bgp_r2_final.txt'))
        assert {p: n['route_reflector_client'] for p, n in r2['router_bgp']['neighbors'].items()} == {'172.18.95.1': True, '172.18.95.3': True}
        assert r2['router_ospf']['present'] and r2['interfaces']['lo']['addresses'] == ['172.18.95.2/32']
        assert r2['interfaces']['lo']['passive'] is True   # `passive-interface lo` rewritten by FRR
        policy = parse_frr_config(load('config_bgp_r3_policy.txt'))['router_bgp']
        assert policy['ebgp_requires_policy'] is True and policy['neighbors']['172.18.192.126']['remote_as'] == 65200


# ===========================================================================
# RIP — `show ip rip` and `show ip rip status`
#
# The rip_*.txt, iproute_rip_* and ip6route_rip_* fixtures were captured on FRR 9.1.3 in one
# running instance of lab/sre/_DRAFT_misc/rip.py (2026-11-11): `initial` (r1 and r2 only),
# `part2` (RIP typed by hand on the four routers with `network ethN`: the rogue speaker of
# lan3, 10.62.3.54, is believed) and `final` (the reference solution applied on top).
# ===========================================================================

from frr import (  # noqa: E402
    RIP_ROUTE_PROTOCOLS, RIPNG_ROUTE_PROTOCOLS, RIP_INFINITY, is_rip_protocol, is_ripng_protocol,
    parse_rip_routes, get_rip_routes, rip_route_metric, rip_route_sources, parse_rip_status, get_rip_status,
)


class TestRipProtocols:
    def test_names_and_numbers(self):
        assert RIP_ROUTE_PROTOCOLS == ('rip', '189') and RIPNG_ROUTE_PROTOCOLS == ('ripng', '190')
        assert is_rip_protocol('rip') and is_rip_protocol(189) and not is_rip_protocol('ospf')
        assert is_ripng_protocol('ripng') and is_ripng_protocol('190') and not is_ripng_protocol('rip')

    def test_kernel_route_gateways_needs_the_protocols(self):
        routes = parse_kernel_routes(load('iproute_rip_r1_final.json'))
        assert routes['10.62.3.0/24']['protocol'] == 'rip' and routes['10.62.3.0/24']['metric'] == 20
        assert kernel_route_gateways(routes, '10.62.3.0/24') == []           # OSPF only by default
        # `allow-ecmp`: both next hops of the ring are in the kernel
        assert kernel_route_gateways(routes, '10.62.3.0/24', protocols=RIP_ROUTE_PROTOCOLS) == [
            '10.62.12.2', '10.62.14.1']
        assert kernel_route_gateways(routes, '10.62.2.0/24', protocols=RIP_ROUTE_PROTOCOLS) == ['10.62.12.2']
        assert kernel_route_gateways(routes, '0.0.0.0/0', protocols=RIP_ROUTE_PROTOCOLS) == ['10.62.14.1']
        assert kernel_route_gateways(routes, '10.62.12.0/30', protocols=RIP_ROUTE_PROTOCOLS) == []   # connected

    def test_kernel_ripng_routes(self):
        routes = json.loads(load('ip6route_rip_r1_final.json'))
        protocols = {r['dst']: r['protocol'] for r in routes}
        assert is_ripng_protocol(protocols['fde4:1c40:8968:2::/64']) and is_ripng_protocol(protocols['fde4:1c40:8968:3::/64'])
        assert protocols['fde4:1c40:8968:1::/64'] == 'kernel'
        gateways = [r['gateway'] for r in routes if is_ripng_protocol(r['protocol'])]
        assert gateways and all(g.startswith('fe80::') for g in gateways)   # link-local next hops


class TestRipRoutes:
    def test_r1_final(self):
        r = parse_rip_routes(load('rip_routes_r1_final.txt'))
        assert set(r) == {'0.0.0.0/0', '10.62.1.0/24', '10.62.2.0/24', '10.62.3.0/24', '10.62.12.0/30',
                          '10.62.13.0/30', '10.62.14.0/30', '10.62.23.0/30', '10.62.34.0/30', '10.62.83.0/24'}
        assert r['10.62.1.0/24'] == [{'code': 'C', 'sub_code': 'i', 'nexthop': None, 'metric': 1, 'source': None,
                                      'external': None, 'tag': 0, 'time': None}]
        assert r['10.62.2.0/24'] == [{'code': 'R', 'sub_code': 'n', 'nexthop': '10.62.12.2', 'metric': 2,
                                      'source': '10.62.12.2', 'external': None, 'tag': 0, 'time': '00:11'}]
        # ECMP (`allow-ecmp`): one row per path
        assert [(p['nexthop'], p['metric']) for p in r['10.62.3.0/24']] == [('10.62.14.1', 3), ('10.62.12.2', 3)]
        assert rip_route_sources(r, '10.62.3.0/24') == ['10.62.14.1', '10.62.12.2']
        assert rip_route_metric(r, '10.62.3.0/24') == 3 and rip_route_metric(r, '0.0.0.0/0') == 2
        assert rip_route_metric(r, '10.62.83.0/24', learned=True) == 4
        assert rip_route_metric(r, '10.62.1.0/24', learned=True) is None
        assert rip_route_metric(r, '10.62.1.0/24', learned=False) == 1
        assert rip_route_metric(r, '10.99.0.0/24') is None and rip_route_sources(r, '10.99.0.0/24') == []

    def test_r1_initial(self):
        r = parse_rip_routes(load('rip_routes_r1_initial.txt'))
        assert set(r) == {'10.62.2.0/24', '10.62.12.0/30'}
        assert r['10.62.2.0/24'][0]['time'] == '02:55'                       # the 180 s timeout counting down

    def test_r3_final(self):
        r = parse_rip_routes(load('rip_routes_r3_final.txt'))
        static = r['10.62.83.0/24'][0]
        # a redistributed route has metric 1 in the router's own table: `metric M` is for its updates
        assert (static['code'], static['sub_code'], static['nexthop'], static['metric']) == ('S', 'r', '10.62.3.111', 1)
        assert static['source'] is None and static['time'] is None
        assert rip_route_sources(r, '10.62.1.0/24') == ['10.62.23.2', '10.62.34.2']
        assert '172.30.55.0/24' not in r                                     # the rogue speaker is ignored

    def test_r3_part2_believes_the_rogue_speaker(self):
        r = parse_rip_routes(load('rip_routes_r3_part2.txt'))
        ghost = r['172.30.55.0/24'][0]
        assert (ghost['code'], ghost['sub_code'], ghost['metric']) == ('R', 'n', 2)
        assert ghost['nexthop'] == ghost['source'] == '10.62.3.54'
        assert rip_route_sources(r, '172.30.55.0/24') == ['10.62.3.54']

    def test_r4_originates_the_default_route(self):
        r = parse_rip_routes(load('rip_routes_r4_final.txt'))
        assert r['0.0.0.0/0'] == [{'code': 'R', 'sub_code': 'd', 'nexthop': None, 'metric': 1, 'source': None,
                                   'external': None, 'tag': 0, 'time': None}]
        assert rip_route_metric(r, '10.62.83.0/24', learned=True) == 3       # announced with `metric 2`

    def test_garbage_collection(self):
        """A route in garbage collection is still listed, with metric 16 and no reachable source."""
        r = parse_rip_routes(
            "R(n) 192.168.77.0/24    10.57.3.66           16 10.57.3.66        0 00:07\n")
        assert r['192.168.77.0/24'][0]['metric'] == RIP_INFINITY
        assert rip_route_sources(r, '192.168.77.0/24') == [] and rip_route_metric(r, '192.168.77.0/24') == 16

    def test_other_rows(self):
        text = (
            "     Network            Next Hop         Metric From            Tag Time\n"
            "R(d) 0.0.0.0/0          0.0.0.0               1 self              0\n"
            "K(r) 172.20.0.0/16      10.57.14.2            1 self (kernel:20)  0\n"
            "R(s) 10.80.0.0/24       0.0.0.0               1 self              0\n"
            "C(r) 10.57.3.0/24       0.0.0.0               1 self              0\n"
            "R(n) 10.57.9.0/24       10.57.12.2           16 10.57.12.2       12 01:58\n"
            "R(n) 10.57.8.0/24       10.57.12.2            4 10.57.12.2        0 02:51:07\n"
        )
        r = parse_rip_routes(text)
        assert r['0.0.0.0/0'][0]['sub_code'] == 'd' and r['0.0.0.0/0'][0]['source'] is None
        kernel = r['172.20.0.0/16'][0]
        assert (kernel['code'], kernel['sub_code'], kernel['external'], kernel['source']) == ('K', 'r', 'kernel:20', None)
        assert r['10.80.0.0/24'][0]['sub_code'] == 's' and r['10.57.3.0/24'][0]['code'] == 'C'
        assert r['10.57.9.0/24'][0]['metric'] == 16 and r['10.57.9.0/24'][0]['tag'] == 12
        assert r['10.57.8.0/24'][0]['time'] == '02:51:07'

    def test_not_running_and_placeholder(self):
        assert parse_rip_routes(load('rip_routes_r3_none.txt')) == {}
        assert parse_rip_routes('') == {} and parse_rip_routes(None) == {}

    def test_get(self):
        grade = make_grade(load('rip_routes_r1_final.txt'))
        assert '10.62.2.0/24' in get_rip_routes(grade, 'r1', allow_error=True)
        grade.test.assert_called_once_with('r1', 'vtysh -c "show ip rip"', step=1, allow_error=True)
        assert get_rip_routes(make_grade('', 0), 'r1') == {}
        assert get_rip_routes(make_grade(load('rip_routes_r1_final.txt'), 1), 'r1') == {}


class TestRipStatus:
    def test_r1_final(self):
        s = parse_rip_status(load('rip_status_r1_final.txt'))
        assert (s['update'], s['timeout'], s['garbage']) == (5, 15, 10)
        assert s['default_metric'] == 1 and s['redistribute'] == [] and s['distance'] == 120
        assert s['send_version'] == '2' and s['receive_version'] == '2'
        assert s['interfaces'] == {
            'eth0': {'send': '2', 'receive': '2', 'key_chain': None},
            'eth1': {'send': '2', 'receive': '2', 'key_chain': 'RIPKEYS'},
            'eth2': {'send': '2', 'receive': '2', 'key_chain': 'RIPKEYS'},
            'eth3': {'send': '2', 'receive': '2', 'key_chain': 'RIPKEYS'},
        }
        # the prefixes of the reference solution, then the interface names typed by hand before
        assert s['networks'] == ['10.62.1.0/24', '10.62.12.0/30', '10.62.13.0/30', '10.62.14.0/30',
                                 'eth0', 'eth2', 'eth3']
        assert s['passive_interfaces'] == ['eth0']
        assert set(s['sources']) == {'10.62.12.2', '10.62.13.1', '10.62.14.1'}
        # one packet of each neighbour was refused while authentication was being set up
        assert s['sources']['10.62.12.2'] == {'bad_packets': 1, 'bad_routes': 0, 'distance': 120,
                                              'last_update': '00:00:03'}

    def test_r3_final(self):
        s = parse_rip_status(load('rip_status_r3_final.txt'))
        assert s['redistribute'] == ['static'] and s['passive_interfaces'] == ['eth0']
        assert s['interfaces']['eth0'] == {'send': '2', 'receive': 'none', 'key_chain': None}
        assert s['interfaces']['eth1'] == {'send': '2', 'receive': '2', 'key_chain': 'RIPKEYS'}
        assert s['sources']['10.62.3.54']['bad_packets'] == 34          # the rogue speaker, refused

    def test_r3_part2(self):
        s = parse_rip_status(load('rip_status_r3_part2.txt'))
        assert s['networks'] == ['eth0', 'eth1', 'eth2', 'eth3'] and s['passive_interfaces'] == []
        assert s['sources']['10.62.3.54'] == {'bad_packets': 0, 'bad_routes': 0, 'distance': 120,
                                              'last_update': '00:00:02'}     # believed
        assert all(i['key_chain'] is None for i in s['interfaces'].values())

    def test_r2_initial(self):
        s = parse_rip_status(load('rip_status_r2_initial.txt'))
        assert (s['update'], s['timeout'], s['garbage']) == (30, 180, 120)
        assert s['passive_interfaces'] == [] and set(s['interfaces']) == {'eth0', 'eth1'}
        assert s['networks'] == ['10.62.2.0/24', '10.62.12.0/30']
        # r1 has nothing to tell r2 (split horizon): it never shows as a source
        assert s['sources'] == {}

    def test_versions_and_filters(self):
        text = (
            'Routing Protocol is "rip"\n'
            '  Sending updates every 30 seconds with +/-50%, next due in 4 seconds\n'
            '  Timeout after 180 seconds, garbage collect after 120 seconds\n'
            '  Outgoing update filter list for all interface is not set\n'
            '    eth2 filtered by (prefix-list) NO-GHOST\n'
            '  Incoming update filter list for all interface is not set\n'
            '  Default redistribution metric is 3\n'
            '  Redistributing: connected static\n'
            '  Default version control: send version 2, receive any version \n'
            '    Interface        Send  Recv   Key-chain\n'
            '    eth0             1 2   1 2    \n'
            '    eth1             none  2      K1\n'
            '  Routing for Networks:\n'
            '    eth0\n'
            '    10.0.0.0/8\n'
            '    10.57.12.9\n'
            '  Routing Information Sources:\n'
            '    Gateway          BadPackets BadRoutes  Distance Last Update\n'
            '  Distance: (default is 100)\n'
            '    Address           Distance  List\n'
            '    10.57.2.0/24           90  \n'
        )
        s = parse_rip_status(text)
        assert s['receive_version'] == '1 2' and s['default_metric'] == 3
        assert s['redistribute'] == ['connected', 'static'] and s['distance'] == 100
        assert s['interfaces'] == {'eth0': {'send': '1 2', 'receive': '1 2', 'key_chain': None},
                                   'eth1': {'send': 'none', 'receive': '2', 'key_chain': 'K1'}}
        assert s['networks'] == ['eth0', '10.0.0.0/8', '10.57.12.9'] and s['sources'] == {}

    def test_not_running_and_placeholder(self):
        assert load('rip_status_r3_none.txt') == "% RIP instance not found\n"
        assert parse_rip_status(load('rip_status_r3_none.txt')) == {}
        assert parse_rip_status('') == {} and parse_rip_status(None) == {}

    def test_get(self):
        grade = make_grade(load('rip_status_r1_final.txt'))
        assert get_rip_status(grade, 'r1', allow_error=True)['update'] == 5
        grade.test.assert_called_once_with('r1', 'vtysh -c "show ip rip status"', step=1, allow_error=True)
        assert get_rip_status(make_grade('', 0), 'r1') == {}


# ---------------------------------------------------------------------------
# PIM / IGMP / MSDP / MLD (pimd, pim6d) — captured in the multicast lab (lab/sre/_DRAFT_misc/multicast.py)
# ---------------------------------------------------------------------------

from frr import (  # noqa: E402
    PIM_REGISTER_INTERFACES, get_igmp_groups, get_igmp_interfaces, get_mld_groups, get_mld_interfaces, get_mroutes,
    get_msdp_peers, get_msdp_sa, get_pim_group_type, get_pim_interfaces, get_pim_neighbors, get_pim_rp_info,
    igmp_enabled, parse_frr_config, parse_igmp_groups, parse_igmp_interfaces, parse_igmp_sources, parse_mroutes,
    parse_msdp_peers, parse_msdp_sa, parse_pim_group_type, parse_pim_interfaces, parse_pim_neighbors,
    parse_pim_rp_info, parse_pim_upstream, pim_neighbor_on, prefix_list_permits, rp_for_group,
)


class TestPimInterfacesNeighbors:
    def test_interfaces_leave_pimreg_out(self):
        interfaces = parse_pim_interfaces(load_json('pim_interface_asm_r3.json'))
        assert set(interfaces) == {'eth0', 'eth1', 'eth2'}
        assert not set(interfaces) & set(PIM_REGISTER_INTERFACES)
        assert interfaces['eth0'] == {'address': '10.106.34.2', 'up': True, 'neighbors': 1, 'dr': '10.106.34.2',
                                      'dr_local': True}
        assert interfaces['eth2']['neighbors'] == 0

    def test_ipv6_interfaces(self):
        interfaces = parse_pim_interfaces(load_json('pim6_interface_v6_r2.json'))
        assert 'pim6reg' not in interfaces and interfaces['eth0']['address'].startswith('fe80::')

    def test_neighbors(self):
        neighbors = parse_pim_neighbors(load_json('pim_neighbor_asm_r3.json'))
        assert neighbors == {'eth0': ['10.106.34.1'], 'eth1': ['10.106.33.1']}
        assert pim_neighbor_on(neighbors, 'eth0') and pim_neighbor_on(neighbors, 'eth1', '10.106.33.1')
        assert not pim_neighbor_on(neighbors, 'eth1', '10.106.33.9') and not pim_neighbor_on(neighbors, 'eth2')

    def test_ipv6_neighbors_are_link_local(self):
        neighbors = parse_pim_neighbors(load_json('pim6_neighbor_v6_r2.json'))
        assert neighbors == {'eth0': ['fe80::9045:f2ff:feb4:161a']}

    def test_get_commands(self):
        grade = make_grade(load('pim_neighbor_asm_r3.json'))
        assert get_pim_neighbors(grade, 'asm_r3', allow_error=True)['eth1'] == ['10.106.33.1']
        grade.test.assert_called_once_with('asm_r3', 'vtysh -c "show ip pim neighbor json"', step=1, allow_error=True)
        grade = make_grade(load('pim6_interface_v6_r2.json'))
        get_pim_interfaces(grade, 'v6_r2', ipv6=True)
        grade.test.assert_called_once_with('v6_r2', 'vtysh -c "show ipv6 pim interface json"', step=1)

    @pytest.mark.parametrize('output, code', [('', 0), ('{\n}\n', 0), ('% PIM not enabled', 1)])
    def test_empty(self, output, code):
        assert get_pim_neighbors(make_grade(output, code), 'r') == {}
        assert get_pim_interfaces(make_grade(output, code), 'r') == {}


class TestPimRpAndGroupType:
    def test_rp_info(self):
        rp_info = parse_pim_rp_info(load_json('pim_rp_info_asm_r3.json'))
        assert rp_info == [{'rp': '10.106.99.2', 'group': '239.0.0.0/8', 'source': 'Static', 'group_type': 'ASM',
                            'iface': 'eth0', 'i_am_rp': False}]
        assert parse_pim_rp_info(load_json('pim_rp_info_asm_r2.json'))[0]['i_am_rp'] is True

    def test_rp_for_group(self):
        rp_info = parse_pim_rp_info(load_json('pim_rp_info_asm_r3.json'))
        assert rp_for_group(rp_info, '239.5.5.6')['rp'] == '10.106.99.2'
        assert rp_for_group(rp_info, '232.1.1.1') is None and rp_for_group(rp_info, 'garbage') is None
        both = rp_info + [{'rp': '10.0.0.1', 'group': '239.5.0.0/16', 'source': 'Static', 'group_type': 'ASM',
                           'iface': 'eth1', 'i_am_rp': False}]
        assert rp_for_group(both, '239.5.5.6')['rp'] == '10.0.0.1'      # the longest prefix

    def test_wrong_rp_of_the_fix_site(self):
        rp_info = parse_pim_rp_info(load_json('pim_rp_info_fix_r2_broken.json'))
        assert rp_for_group(rp_info, '239.1.1.1')['rp'] == '10.106.72.2'

    def test_group_type(self):
        assert parse_pim_group_type(load_json('pim_group_type_ssm.json')) == 'SSM'
        assert parse_pim_group_type({}) is None and parse_pim_group_type([]) is None
        grade = make_grade(load('pim_group_type_ssm.json'))
        assert get_pim_group_type(grade, 'ssm_r1', '239.232.9.9', allow_error=True) == 'SSM'
        grade.test.assert_called_once_with('ssm_r1', 'vtysh -c "show ip pim group-type 239.232.9.9 json"', step=1,
                                           allow_error=True)

    def test_get_rp_info(self):
        assert get_pim_rp_info(make_grade(load('pim_rp_info_asm_r1.json')), 'asm_r1')[0]['iface'] == 'eth1'


class TestMroutesUpstream:
    def test_shared_tree_only(self):
        mroutes = parse_mroutes(load_json('pim_mroute_asm_r3_star.json'))
        assert mroutes == {('*', '239.5.5.6'): {'iif': 'eth0', 'oil': ['eth2'], 'flags': 'SC', 'installed': True}}

    def test_after_the_spt_switchover(self):
        mroutes = parse_mroutes(load_json('pim_mroute_asm_r3.json'))
        assert mroutes[('10.106.31.159', '239.5.5.6')]['iif'] == 'eth1'
        assert mroutes[('*', '239.5.5.6')]['iif'] == 'eth0'

    def test_first_hop_router(self):
        mroutes = parse_mroutes(load_json('pim_mroute_asm_r1.json'))
        assert mroutes[('10.106.31.159', '239.5.5.6')] == {'iif': 'eth0', 'oil': ['eth1', 'eth2'], 'flags': 'SFT',
                                                           'installed': True}

    def test_ipv6(self):
        mroutes = parse_mroutes(load_json('pim6_mroute_v6_r2.json'))
        assert mroutes[('fd39:deb4:cd32:61::f97', 'ff3e::1:2345')]['oil'] == ['eth1']

    def test_upstream(self):
        upstream = parse_pim_upstream(load_json('pim_upstream_asm_r3.json'))
        assert upstream[('*', '239.5.5.6')] == {'join_state': 'Joined', 'reg_state': 'RegNoInfo', 'iif': 'eth0',
                                                'rpf': '10.106.99.2', 'spt': False}
        assert upstream[('10.106.31.159', '239.5.5.6')]['iif'] == 'eth1'

    def test_get_mroutes(self):
        grade = make_grade(load('pim6_mroute_v6_r2.json'))
        assert len(get_mroutes(grade, 'v6_r2', step=3, ipv6=True)) == 1
        grade.test.assert_called_once_with('v6_r2', 'vtysh -c "show ipv6 mroute json"', step=3)
        assert get_mroutes(make_grade('{\n}\n'), 'r') == {}


class TestIgmp:
    def test_detail_querier_and_timers(self):
        interfaces = parse_igmp_interfaces(load_json('igmp_interface_detail_igmp_r1.json'))
        eth0 = interfaces['eth0']
        assert eth0['querier'] is True and eth0['querier_ip'] == '10.106.10.35' and eth0['version'] == 3
        assert eth0['query_interval'] == 40.0 and eth0['query_response_interval'] == 10.0
        assert eth0['last_member_interval'] == 2.0 and eth0['robustness'] == 2
        assert igmp_enabled(interfaces, 'eth0') and not igmp_enabled(interfaces, 'eth1')

    def test_the_other_router_is_not_querier(self):
        before = parse_igmp_interfaces(load_json('igmp_interface_detail_igmp_r2_before.json'))['eth0']
        after = parse_igmp_interfaces(load_json('igmp_interface_detail_igmp_r2_after.json'))['eth0']
        assert before['querier'] is True
        assert after['querier'] is False and after['querier_ip'] == '10.106.10.35'

    def test_short_form_and_mtrace_only(self):
        interfaces = parse_igmp_interfaces(load_json('igmp_interface_asm_r3.json'))
        assert interfaces['eth0']['mtrace_only'] and not igmp_enabled(interfaces, 'eth0')
        assert igmp_enabled(interfaces, 'eth2') and interfaces['eth2']['querier'] is True
        assert interfaces['eth2']['query_interval'] is None

    def test_nothing_configured(self):
        assert parse_igmp_interfaces(load_json('igmp_interface_detail_none.json')) == {}

    def test_groups_versions(self):
        groups = parse_igmp_groups(load_json('igmp_groups_igmp_r1.json'))['eth0']
        assert groups['239.3.3.1']['version'] == 3 and groups['239.3.3.1']['mode'] == 'EXCLUDE'
        assert groups['239.3.3.2']['version'] == 2 and groups['239.3.3.2']['mode'] is None
        assert groups['239.3.3.1']['uptime'] == 11.0

    def test_sources(self):
        assert parse_igmp_sources(load_json('igmp_sources_ssm_r2.json')) == {
            'eth1': {'239.232.9.9': ['10.106.41.139'], '232.9.9.9': ['10.106.41.139']}}
        assert parse_igmp_sources(load_json('igmp_sources_asm_r3.json')) == {}          # EXCLUDE {}: source '*'

    def test_get(self):
        grade = make_grade(load('igmp_interface_detail_igmp_r1.json'))
        assert get_igmp_interfaces(grade, 'igmp_r1', allow_error=True)['eth0']['querier']
        grade.test.assert_called_once_with('igmp_r1', 'vtysh -c "show ip igmp interface detail json"', step=1,
                                           allow_error=True)
        grade = make_grade(load('igmp_groups_ssm_r2.json'))
        assert set(get_igmp_groups(grade, 'ssm_r2', step=3)['eth1']) == {'239.232.9.9', '232.9.9.9'}


class TestMld:
    def test_interface_in_a_vrf_wrapper(self):
        interfaces = parse_igmp_interfaces(load_json('mld_interface_v6_r2.json'))
        assert interfaces['eth1']['version'] == 2 and interfaces['eth1']['querier'] is True
        assert interfaces['eth1']['query_interval'] == 125.0 and interfaces['eth1']['last_member_interval'] == 1.0

    def test_groups(self):
        groups = parse_igmp_groups(load_json('mld_groups_v6_r2.json'))['eth1']
        assert 'ff3e::1:2345' in groups and 'ff02::16' in groups and groups['ff3e::1:2345']['version'] == 2

    def test_get(self):
        grade = make_grade(load('mld_interface_v6_r2.json'))
        assert igmp_enabled(get_mld_interfaces(grade, 'v6_r2'), 'eth1')
        grade.test.assert_called_once_with('v6_r2', 'vtysh -c "show ipv6 mld interface json"', step=1)
        assert 'ff3e::1:2345' in get_mld_groups(make_grade(load('mld_groups_v6_r2.json')), 'v6_r2')['eth1']


class TestMsdp:
    def test_peers(self):
        assert parse_msdp_peers(load_json('msdp_peer_r2.json')) == {
            '10.106.99.51': {'state': 'established', 'established': True, 'local': '10.106.99.52', 'sa_count': 2}}
        assert parse_msdp_peers(load_json('msdp_peer_none.json')) == {}
        listening = parse_msdp_peers({'10.1.1.1': {'peer': '10.1.1.1', 'local': '10.1.1.2', 'state': 'listen'}})
        assert listening['10.1.1.1']['established'] is False

    def test_sa_cache(self):
        sa = parse_msdp_sa(load_json('msdp_sa_r2.json'))
        assert sa[('10.106.51.117', '239.7.7.7')] == {'rp': '10.106.99.51', 'local': False, 'spt': True}
        local = parse_msdp_sa(load_json('msdp_sa_r1.json'))
        assert local[('10.106.51.117', '239.7.7.7')] == {'rp': None, 'local': True, 'spt': False}

    def test_get(self):
        grade = make_grade(load('msdp_sa_r2.json'))
        assert len(get_msdp_sa(grade, 'msdp_r2', step=3, allow_error=True)) == 2
        grade.test.assert_called_once_with('msdp_r2', 'vtysh -c "show ip msdp sa json"', step=3, allow_error=True)
        assert get_msdp_peers(make_grade('', 1), 'msdp_r1') == {}


class TestPimRunningConfig:
    def test_boundary_and_prefix_list(self):
        config = parse_frr_config(load('pim_running_config_msdp_r1.txt'))
        assert config['interfaces']['eth1']['multicast_boundary'] == 'ORG-SCOPE'
        assert config['interfaces']['eth1']['pim'] is True and config['interfaces']['eth0']['igmp'] is False
        assert config['interfaces']['eth0']['multicast_boundary'] is None
        plists = config['prefix_lists']
        assert prefix_list_permits(plists, 'ORG-SCOPE', '239.193.1.1') is False
        assert prefix_list_permits(plists, 'ORG-SCOPE', '239.7.7.7') is True
        assert prefix_list_permits(plists, 'ORG-SCOPE', '10.0.0.1') is False          # implicit deny
        assert prefix_list_permits(plists, 'NOPE', '239.7.7.7') is None

    @pytest.mark.parametrize('entries, prefix, expected', [
        ([{'seq': 10, 'action': 'permit', 'prefix': '239.0.0.0/8', 'ge': None, 'le': None}], '239.0.0.0/8', True),
        ([{'seq': 10, 'action': 'permit', 'prefix': '239.0.0.0/8', 'ge': None, 'le': None}], '239.1.1.1', False),
        ([{'seq': 10, 'action': 'permit', 'prefix': '239.0.0.0/8', 'ge': 24, 'le': None}], '239.1.1.1', True),
        ([{'seq': 10, 'action': 'permit', 'prefix': '239.0.0.0/8', 'ge': 24, 'le': 24}], '239.1.1.1', False),
        ([{'seq': 20, 'action': 'permit', 'prefix': '224.0.0.0/4', 'ge': None, 'le': 32},
          {'seq': 5, 'action': 'deny', 'prefix': '239.192.0.0/14', 'ge': None, 'le': 32}], '239.192.0.1', False),
    ])
    def test_prefix_list_semantics(self, entries, prefix, expected):
        assert prefix_list_permits({'P': entries}, 'P', prefix) is expected


# ---------------------------------------------------------------------------
# OSPFv3 and BGP over IPv6 — fixtures ospf6_* / bgp6_* / config_ospf6_* / ip6route_* captured on
# FRR 9.1.3 (routing-frr:1.34) in an IPv6-only probe: p1 (area 0, ASBR, auth on eth1) — p2 (ABR,
# area 1 stub with a /60 range) — p3 (area 1, BGP unnumbered to p4), p1–p2 in eBGP, p5 (auth)
# ---------------------------------------------------------------------------

from frr import (  # noqa: E402
    OSPF6_PATH_TYPES, bgp_neighbor_activated, get_bgp_routes, get_bgp_summary, get_kernel_routes,
    get_ospf6_border_routers, get_ospf6_info, get_ospf6_interfaces, get_ospf6_neighbors, get_ospf6_routes,
    neighbor_is_full, parse_bgp_advertised_routes, parse_bgp_neighbor, parse_bgp_prefix, parse_bgp_routes,
    parse_bgp_summary, parse_frr_config, parse_kernel_routes, parse_ospf6_border_routers, parse_ospf6_info,
    parse_ospf6_interfaces, parse_ospf6_neighbors, parse_ospf6_routes, prefix_list_permits,
)

P6 = '3fff:550:5cfb'


class TestOspf6Info:
    def test_abr_with_stub_area(self):
        info = parse_ospf6_info(load_json('ospf6_info_p2.json'))
        assert info['router_id'] == '2.2.2.2' and info['abr'] is True
        assert set(info['areas']) == {'0.0.0.0', '0.0.0.1'}          # typed "0" / "1", normalised
        assert info['areas']['0.0.0.1']['stub'] is True and info['areas']['0.0.0.0']['stub'] is False
        assert info['areas']['0.0.0.1']['interfaces'] == ['eth1']

    def test_internal_router(self):
        info = parse_ospf6_info(load_json('ospf6_info_p3.json'))
        assert info['router_id'] == '3.3.3.3' and info['abr'] is False
        assert info['areas']['0.0.0.1']['interfaces'] == ['eth0', 'eth2', 'eth3']

    def test_not_running(self):
        # without ospf6d the json commands print nothing (exit 0)
        assert parse_ospf6_info({}) == {}
        assert get_ospf6_info(make_grade('', 0), 'p4') == {}
        assert get_ospf6_neighbors(make_grade('', 0), 'p4') == []
        assert get_ospf6_interfaces(make_grade('', 0), 'p4') == {}
        assert get_ospf6_routes(make_grade('', 0), 'p4') == {}
        assert get_ospf6_border_routers(make_grade('% OSPFv3 instance not found\n', 0), 'p4') == {}

    def test_wrapper_runs_json_command(self):
        grade = make_grade(load('ospf6_info_p2.json'))
        assert get_ospf6_info(grade, 'p2')['router_id'] == '2.2.2.2'
        assert grade.test.call_args[0][1] == 'vtysh -c "show ipv6 ospf6 json"'


class TestOspf6Neighbors:
    def test_full_neighbors(self):
        neighbors = parse_ospf6_neighbors(load_json('ospf6_neighbor_p2.json'))
        assert [(n['neighbor_id'], n['interface'], n['state']) for n in neighbors] == [
            ('1.1.1.1', 'eth0', 'Full'), ('3.3.3.3', 'eth1', 'Full')]
        assert neighbors[0]['role'] == 'BDR' and neighbors[0]['interface_state'] == 'DR'
        assert neighbor_is_full(neighbors, neighbor_id='3.3.3.3', interface='eth1')
        assert not neighbor_is_full(neighbors, neighbor_id='3.3.3.3', interface='eth0')

    def test_twoway_while_waiting(self):
        data = {'neighbors': [{'neighborId': '1.1.1.1', 'priority': 1, 'deadTime': '00:00:34', 'state': 'Twoway',
                               'ifState': 'DROther', 'duration': '00:00:15', 'interfaceName': 'eth0',
                               'interfaceState': 'Waiting'}]}
        neighbors = parse_ospf6_neighbors(data)
        assert neighbors[0]['state'] == 'Twoway' and not neighbor_is_full(neighbors, neighbor_id='1.1.1.1')


class TestOspf6Interfaces:
    def test_passive_and_disabled(self):
        interfaces = parse_ospf6_interfaces(load_json('ospf6_interface_p3.json'))
        assert interfaces['eth2']['enabled'] and interfaces['eth2']['passive'] is True
        assert interfaces['eth2']['area'] == '0.0.0.1' and interfaces['eth2']['cost'] == 10
        assert interfaces['eth0']['passive'] is False and interfaces['eth0']['state'] == 'DR'
        assert interfaces['eth0']['mtu'] == 1500 and interfaces['eth0']['mtu_ignore'] is False
        assert f'{P6}:23::3/64' in interfaces['eth0']['addresses']
        # eth1 (the unnumbered BGP link) is not in OSPFv3
        assert interfaces['eth1']['enabled'] is False and interfaces['eth1']['area'] is None

    def test_authentication_trailer(self):
        interfaces = parse_ospf6_interfaces(load_json('ospf6_interface_p1.json'))
        assert interfaces['eth1']['auth_type'] == 'manualkey'
        assert interfaces['eth0']['auth_type'] == 'NULL'


class TestOspf6Routes:
    def test_stub_area_gets_a_default(self):
        routes = parse_ospf6_routes(load_json('ospf6_route_p3.json'))
        assert routes['::/0']['type'] == 'inter-area' and routes['::/0']['code'] == 'IE'
        assert routes['::/0']['nexthops'][0][0].startswith('fe80::')
        assert routes[f'{P6}:130::/64']['type'] == 'intra-area'
        assert routes[f'{P6}:130::/64']['nexthops'] == [(None, 'eth2')]       # connected: '::'
        assert not any(r['type'].startswith('external') for r in routes.values())

    def test_range_and_externals(self):
        backbone = parse_ospf6_routes(load_json('ospf6_route_p1.json'))
        assert backbone[f'{P6}:130::/60']['type'] == 'inter-area'
        assert f'{P6}:130::/64' not in backbone and f'{P6}:131::/64' not in backbone
        abr = parse_ospf6_routes(load_json('ospf6_route_p2.json'))
        assert abr[f'{P6}:e0::/64']['type'] == 'external-2'
        assert set(OSPF6_PATH_TYPES.values()) >= {r['type'] for r in abr.values()}


class TestOspf6BorderRouters:
    def test_bits(self):
        seen_from_backbone = parse_ospf6_border_routers(load('ospf6_border_routers_p1.txt'))
        assert seen_from_backbone['1.1.1.1']['asbr'] and not seen_from_backbone['1.1.1.1']['abr']
        assert seen_from_backbone['2.2.2.2']['abr'] and not seen_from_backbone['2.2.2.2']['asbr']
        on_abr = parse_ospf6_border_routers(load('ospf6_border_routers_p2.txt'))
        assert on_abr['2.2.2.2']['areas'] == ['0.0.0.0', '0.0.0.1']
        in_stub = parse_ospf6_border_routers(load('ospf6_border_routers_p3.txt'))
        assert set(in_stub) == {'2.2.2.2'}                                    # the ASBR is not seen


class TestKernelRoutes6:
    def test_ipv6_default_and_host_routes(self):
        routes = parse_kernel_routes(load('ip6route_ospf6_p3.json'), ipv6=True)
        assert routes['::/0']['protocol'] == 'ospf'
        assert routes[f'{P6}:ff::3/128']['protocol'] == 'kernel'
        assert routes['fe80::/64']['nexthops'] == [(None, 'eth0')]            # first entry wins

    def test_wrapper(self):
        grade = make_grade(load('ip6route_bgp6_p2.json'))
        routes = get_kernel_routes(grade, 'p2', ipv6=True)
        assert grade.test.call_args[0][1] == 'ip -j -6 route'
        assert routes[f'{P6}:e0::/64']['protocol'] == 'bgp'
        assert routes[f'{P6}:e0::/64']['nexthops'][0][0].startswith('fe80::')


class TestBgpIpv6:
    def test_summary_policy_and_unnumbered(self):
        summary = parse_bgp_summary(load_json('bgp6_summary_p2.json'))
        assert summary['as'] == 65002 and summary['peers'][f'{P6}:12::1']['established']
        assert summary['peers'][f'{P6}:12::1']['id_type'] == 'ipv6'
        unnumbered = parse_bgp_summary(load_json('bgp6_summary_p3_unnumbered.json'))
        assert unnumbered['peers']['eth1']['id_type'] == 'interface'
        assert unnumbered['peers']['eth1']['remote_as'] == 65004 and unnumbered['peers']['eth1']['pfx_rcd'] == 1

    def test_summary_wrapper_of_show_bgp_summary(self):
        wrapped = {'ipv6Unicast': load_json('bgp6_summary_p2.json')}
        assert parse_bgp_summary(wrapped)['router_id'] == '2.2.2.2'

    def test_afi_keyword(self):
        grade = make_grade(load('bgp6_summary_p2.json'))
        get_bgp_summary(grade, 'p2', afi='ipv6')
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp ipv6 unicast summary json"'
        grade = make_grade(load('bgp6_routes_p2.json'))
        assert f'{P6}:e0::/64' in get_bgp_routes(grade, 'p2', afi='ipv6')
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp ipv6 unicast json"'
        with pytest.raises(ValueError):
            get_bgp_routes(make_grade('{}'), 'p2', afi='ipv5')

    def test_two_next_hops(self):
        path = parse_bgp_routes(load_json('bgp6_routes_p2.json'))[f'{P6}:e0::/64'][0]
        assert path['nexthop_global'] == f'{P6}:12::1'
        assert path['nexthop_link_local'].startswith('fe80::') and path['nexthop'] == path['nexthop_link_local']
        assert path['as_list'] == [65001] and path['path_from'] == 'external'
        detail = parse_bgp_prefix(load_json('bgp6_prefix_p2.json'))['paths'][0]
        assert detail['nexthop_global'] == f'{P6}:12::1' and detail['accessible'] is True

    def test_unnumbered_next_hop(self):
        path = parse_bgp_routes(load_json('bgp6_routes_p3_unnumbered.json'))[f'{P6}:ff::4/128'][0]
        assert path['peer'].startswith('fe80::') and path['nexthop_global'].startswith('fe80::')

    def test_advertised_routes_next_hop_global(self):
        adv = parse_bgp_advertised_routes(load_json('bgp6_advertised_p1.json'))
        assert adv[f'{P6}::/48']['nexthop'] == '::' and adv[f'{P6}:130::/60']['as_list'] == [65002]

    def test_neighbor_ipv6_family(self):
        data = load_json('bgp6_neighbor_p1.json')
        n = parse_bgp_neighbor(data, peer=f'{P6}:12::2', afi='ipv6')
        assert n['established'] and n['accepted_prefixes'] == 1 and n['route_map_in'] == 'ALL'
        assert n['nexthop_global'] == f'{P6}:12::1' and n['nexthop_local'].startswith('fe80::')
        assert parse_bgp_neighbor(data, peer=f'{P6}:12::2')['af'] == {}       # not active in IPv4
        unnumbered = parse_bgp_neighbor(load_json('bgp6_neighbor_p3_eth1.json'), peer='eth1', afi='ipv6')
        assert unnumbered['established'] and unnumbered['foreign_host'].startswith('fe80::')


class TestFrrConfigIpv6:
    def test_ospf6_interfaces_and_router(self):
        c = parse_frr_config(load('config_ospf6_p1.txt'))
        assert c['static_routes6'] == [(f'{P6}::/48', 'blackhole')] and c['static_routes'] == []
        assert c['interfaces']['eth0']['ospf6']['area'] == '0.0.0.0'
        assert c['interfaces']['eth1']['ospf6']['authentication'] == {'key_id': 7, 'hash_algo': 'hmac-sha-256',
                                                                     'key': 'S3cretKey'}
        r6 = c['router_ospf6']
        assert r6['present'] and r6['router_id'] == '1.1.1.1' and r6['redistribute'] == ['connected']
        assert r6['default_information_originate'] and r6['default_information_always']
        assert c['router_ospf']['present'] is False

    def test_stub_range_passive(self):
        abr = parse_frr_config(load('config_ospf6_p2.txt'))['router_ospf6']
        assert abr['areas']['0.0.0.1']['stub'] and abr['areas']['0.0.0.1']['ranges'] == [f'{P6}:130::/60']
        p3 = parse_frr_config(load('config_ospf6_p3.txt'))
        assert p3['interfaces']['eth2']['ospf6']['passive'] is True
        assert p3['interfaces']['eth0']['ospf6']['passive'] is None

    def test_bgp_address_families(self):
        rb = parse_frr_config(load('config_ospf6_p1.txt'))['router_bgp']
        assert rb['default_ipv4_unicast'] is False
        v6 = rb['address_families']['ipv6 unicast']
        assert v6['neighbors'][f'{P6}:12::2'] == {'activate': True, 'route_map_in': 'ALL', 'route_map_out': 'ALL'}
        assert v6['networks'] == [f'{P6}::/48', f'{P6}:e0::/64']
        assert bgp_neighbor_activated(rb, f'{P6}:12::2', 'ipv6')
        assert not bgp_neighbor_activated(rb, f'{P6}:12::2', 'ipv4')
        assert not bgp_neighbor_activated(rb, f'{P6}:12::9', 'ipv6')

    def test_unnumbered_neighbor(self):
        rb = parse_frr_config(load('config_ospf6_p3.txt'))['router_bgp']
        assert rb['neighbors']['eth1']['interface'] is True and rb['neighbors']['eth1']['remote_as'] == 'external'
        assert bgp_neighbor_activated(rb, 'eth1', 'ipv6')

    def test_ipv4_family_by_default_and_negation(self):
        text = ("router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 2001:db8::2 remote-as 65003\n"
                " address-family ipv4 unicast\n  no neighbor 2001:db8::2 activate\n exit-address-family\n"
                " address-family ipv6 unicast\n  neighbor 2001:db8::2 activate\n"
                "  neighbor 2001:db8::2 next-hop-self\n exit-address-family\nexit\n"
                "ipv6 prefix-list IN6 seq 5 deny fc00::/7 le 128\nipv6 prefix-list IN6 seq 10 permit 2000::/3 le 48\n")
        c = parse_frr_config(text)
        rb = c['router_bgp']
        assert bgp_neighbor_activated(rb, '10.0.0.2', 'ipv4') and not bgp_neighbor_activated(rb, '10.0.0.2', 'ipv6')
        assert not bgp_neighbor_activated(rb, '2001:db8::2', 'ipv4') and bgp_neighbor_activated(rb, '2001:db8::2', 'ipv6')
        assert rb['address_families']['ipv6 unicast']['neighbors']['2001:db8::2']['next_hop_self'] is True
        assert 'next_hop_self' not in rb['address_families']['ipv4 unicast']['neighbors']['2001:db8::2']
        assert c['prefix_lists'] == {}
        assert prefix_list_permits(c['prefix_lists6'], 'IN6', 'fd12:3456::/48') is False
        assert prefix_list_permits(c['prefix_lists6'], 'IN6', '3fff:550::/48') is True
        assert prefix_list_permits(c['prefix_lists6'], 'IN6', '3fff:550:1:2::/64') is False


class TestIpv6LabCaptures:
    """Captured in the solved OSPFv3 + BGP-IPv6 lab (instance 3fff:fef::/32, final state, FRR 9.1.3)."""

    def test_ibgp_path_has_one_global_next_hop(self):
        path = parse_bgp_routes(load_json('bgp6_routes_ib_r3_nhs.json'))['3fff:fef:410::/48'][0]
        # next-hop-self over loopbacks: only the global next hop, no link-local
        assert path['path_from'] == 'internal' and path['valid']
        assert path['nexthop_global'] == '3fff:fef:400:ff::1' == path['nexthop']
        assert path['nexthop_link_local'] is None

    def test_ibgp_neighbor_between_loopbacks(self):
        n = parse_bgp_neighbor(load_json('bgp6_neighbor_ib_r3_lo1.json'), peer='3fff:fef:400:ff::1', afi='ipv6')
        assert n['established'] and n['link'] == 'internal' and n['af']
        assert (n['local_host'], n['foreign_host']) == ('3fff:fef:400:ff::3', '3fff:fef:400:ff::1')

    def test_local_preference_and_filters(self):
        routes = parse_bgp_routes(load_json('bgp6_routes_po_r1_policy.json'))
        assert set(routes) == {'3fff:fef:500::/48', '3fff:fef:510::/48', '3fff:fef:520::/48', '3fff:fef:530::/48'}
        best = [p for p in routes['3fff:fef:530::/48'] if p['best']]
        assert len(best) == 1 and best[0]['locprf'] == 200 and best[0]['peer'] == '3fff:fef:510:c1::1'
        assert best[0]['as_list'] == [65110, 65110, 65000]

    def test_prepend_seen_from_the_internet(self):
        paths = parse_bgp_routes(load_json('bgp6_routes_po_inet_prepend.json'))['3fff:fef:500::/48']
        via_b = next(p for p in paths if p['peer'] == '3fff:fef:530:b::1')
        assert via_b['as_list'] == [65120, 65030, 65030, 65030] and not via_b['best']
        assert next(p for p in paths if p['best'])['peer'] == '3fff:fef:530:a::1'

    def test_advertised_only_own_prefix(self):
        adv = parse_bgp_advertised_routes(load_json('bgp6_advertised_po_r1_ispb.json'))
        assert list(adv) == ['3fff:fef:500::/48'] and adv['3fff:fef:500::/48']['as_list'] == [65030, 65030]

    def test_policy_running_config(self):
        c = parse_frr_config(load('config_bgp6_po_r1_policy.txt'))
        assert c['prefix_lists'] == {} and set(c['prefix_lists6']) == {'BOGONS', 'MINE'}
        assert prefix_list_permits(c['prefix_lists6'], 'BOGONS', '2001:db8:3bad::/48') is False
        assert prefix_list_permits(c['prefix_lists6'], 'BOGONS', '3fff:fef:530::/48') is True
        assert c['route_maps']['ISPB-OUT'][0]['set'] == ['as-path prepend 65030 65030']
        assert c['route_maps']['ISPA-IN'][0]['match'] == ['ipv6 address prefix-list BOGONS']
        v6 = c['router_bgp']['address_families']['ipv6 unicast']['neighbors']
        assert v6['3fff:fef:520:c1::1']['route_map_out'] == 'ISPB-OUT'
        ib_r1 = parse_frr_config(load('config_bgp6_ib_r1.txt'))
        assert ib_r1['interfaces']['lo']['ospf6']['area'] == '0.0.0.0'
        assert ib_r1['interfaces']['eth1']['ospf6']['network_type'] == 'point-to-point'
        v6 = ib_r1['router_bgp']['address_families']['ipv6 unicast']['neighbors']
        assert v6['3fff:fef:400:ff::3'] == {'activate': True, 'next_hop_self': True}
        assert ib_r1['router_bgp']['neighbors']['3fff:fef:400:ff::3']['update_source'] == 'lo'

    def test_stub_default_in_the_kernel_and_fixed_router_id(self):
        routes = parse_kernel_routes(load('ip6route_ospf6_o2_r1_stub.json'), ipv6=True)
        assert routes['::/0']['protocol'] == 'ospf' and routes['::/0']['nexthops'][0][0].startswith('fe80::')
        assert parse_ospf6_info(load_json('ospf6_info_fix_r2_fixed.json'))['router_id'] == '6.0.0.2'


# ---------------------------------------------------------------------------
# MPLS: LDP, label table, segment routing in OSPF, RIB with labels and backups
# (FRR 10.3, captured in the solved and in the untouched MPLS lab: lab/sre/_DRAFT_misc/mpls.py)
# ---------------------------------------------------------------------------

from frr import (  # noqa: E402
    MPLS_IMPLICIT_NULL, get_frr_routes, get_ldp_bindings, get_ldp_neighbors, get_mpls_table, get_ospf_sr_database,
    kernel_route_labels, ldp_session_up, mpls_label_value, parse_frr_routes, parse_ldp_bindings,
    parse_ldp_discovery, parse_ldp_neighbors, parse_mpls_table, parse_ospf_sr_database,
)

MPLS_FIXTURES = Path(__file__).parent / 'mock_data' / 'mpls'


class TestMplsLabelValue:
    @pytest.mark.parametrize('text, value', [('16', 16), (16, 16), ('imp-null', 3), ('implicit-null', 3),
                                             ('exp-null', 0), ('-', None), ('', None), (None, None)])
    def test_values(self, text, value):
        assert mpls_label_value(text) == value
        assert MPLS_IMPLICIT_NULL == 3


class TestLdp:
    def test_neighbors(self):
        n = parse_ldp_neighbors(load_json('ldp_neighbor_p1.json'))
        assert set(n) == {'10.161.47.1', '10.161.47.3'}
        assert n['10.161.47.1'] == {'state': 'OPERATIONAL', 'operational': True, 'transport_address': '10.161.47.1',
                                    'uptime': '00:08:15'}
        assert ldp_session_up(n, '10.161.47.3') and not ldp_session_up(n, '10.161.47.4')

    def test_no_ldp(self):
        # ldpd running without configuration: an empty object; a transport address out of
        # reach: an adjacency without session
        assert parse_ldp_neighbors(load_json('ldp_neighbor_none.json')) == {}
        assert parse_ldp_neighbors(load_json('ldp_neighbor_fix_p2_initial.json')) == {}
        assert parse_ldp_discovery(load_json('ldp_discovery_fix_p2_initial.json')) == {'eth1': ['10.24.79.4']}
        assert get_ldp_bindings(make_grade(load('ldp_binding_none.txt')), 'ldp_p1') == {}

    def test_discovery(self):
        assert parse_ldp_discovery(load_json('ldp_discovery_p1.json')) == {'eth0': ['10.161.47.1'],
                                                                             'eth1': ['10.161.47.3']}
        data = {'adjacencies': [{'neighborId': '1.1.1.1', 'type': 'targeted', 'peer': '1.1.1.1'}]}
        assert parse_ldp_discovery(data) == {'targeted': ['1.1.1.1']}

    def test_bindings_with_the_allocation_filter(self):
        b = parse_ldp_bindings(load_json('ldp_binding_p1_filtered.json'))
        # loopbacks and host networks only: no /30 link
        assert set(b) == {'10.161.33.0/24', '10.161.34.0/24', '10.161.47.1/32', '10.161.47.2/32', '10.161.47.3/32',
                          '10.161.47.4/32'}
        assert b['10.161.47.4/32'] == {'local': 20, 'remote': {'10.161.47.1': 19, '10.161.47.3': 20},
                                       'in_use': '10.161.47.3'}
        # its own loopback: implicit-null locally; the next hop of pe1's loopback announces implicit-null
        assert b['10.161.47.2/32']['local'] == 3 and b['10.161.47.2/32']['in_use'] is None
        assert b['10.161.47.1/32']['remote']['10.161.47.1'] == 3

    def test_bindings_without_filter_include_the_links(self):
        b = parse_ldp_bindings(load_json('ldp_binding_fix_p2.json'))
        assert {'10.161.64.0/30', '10.161.64.4/30', '10.161.64.8/30'} <= set(b)
        assert len(b) == 9

    def test_get_helpers_use_vtysh_json(self):
        grade = make_grade(load('ldp_neighbor_p1.json'))
        assert set(get_ldp_neighbors(grade, 'ldp_p1')) == {'10.161.47.1', '10.161.47.3'}
        assert grade.test.call_args[0][1] == 'vtysh -c "show mpls ldp neighbor json"'


class TestMplsTable:
    def test_ldp_entries(self):
        t = parse_mpls_table(load_json('mpls_table_ldp_p1.json'))
        assert sorted(t) == [16, 17, 18, 19, 20]
        assert t[18] == {'installed': True, 'nexthops': [{'type': 'LDP', 'out_labels': [19], 'nexthop': '10.161.32.6',
                                                          'interface': 'eth1', 'installed': True}]}
        assert t[16]['nexthops'][0]['out_labels'] == [3]

    def test_sr_entries_and_empty_table(self):
        t = parse_mpls_table(load_json('mpls_table_sr_r2.json'))
        assert t[17040]['nexthops'][0]['type'] == 'SR (OSPF)' and t[17040]['nexthops'][0]['out_labels'] == [50040]
        assert parse_mpls_table(load_json('mpls_table_none.json')) == {}
        assert get_mpls_table(make_grade('', 1), 'ldp_p1') == {}


class TestOspfSegmentRouting:
    def test_database(self):
        db = parse_ospf_sr_database(load_json('ospf_sr_sr_r2.json'))
        assert set(db) == {'10.161.63.1', '10.161.63.2', '10.161.63.3', '10.161.63.4'}
        # sr_r3 has its own SRGB; the labels towards sr_r4 use the SRGB of the next hop
        assert db['10.161.63.3']['srgb'] == (50000, 8000) and db['10.161.63.4']['srgb'] == (17000, 8000)
        assert db['10.161.63.4']['srlb'] == (15000, 1000)
        r4 = db['10.161.63.4']['prefixes']['10.161.63.4/32']
        assert r4['index'] == 40 and r4['input_label'] == 17040
        assert r4['routes'] == [{'out_label': 50040, 'interface': 'eth1', 'nexthop': '10.161.48.6'}]
        # the router that answers lists itself, without input label
        assert db['10.161.63.2']['prefixes']['10.161.63.2/32']['index'] == 21

    def test_disabled(self):
        assert get_ospf_sr_database(make_grade(load('ospf_sr_disabled.txt')), 'sr_r2') == {}


class TestFrrRoutes:
    def test_ti_lfa_backup(self):
        routes = parse_frr_routes(load_json('route_tl_r1_tilfa.json'))
        r3 = routes['10.161.95.3/32']
        assert r3['protocol'] == 'ospf' and r3['selected'] and r3['installed']
        assert r3['nexthops'] == [{'ip': '10.161.80.2', 'interface': 'eth0', 'labels': [16003], 'active': True,
                                   'fib': True}]
        assert r3['backups'] == [{'ip': '10.161.80.14', 'interface': 'eth1', 'labels': [15003, 16003], 'active': True,
                                  'fib': False}]
        assert [p for p, r in routes.items() if r['backups']] == ['10.161.95.3/32']

    def test_no_backup_before(self):
        routes = parse_frr_routes(load_json('route_tl_r1_initial.json'))
        assert routes['10.161.95.3/32']['backups'] == [] if '10.161.95.3/32' in routes else True
        assert all(not r['backups'] for r in routes.values())

    def test_vrf_command(self):
        grade = make_grade('{}')
        assert get_frr_routes(grade, 'pe1', vrf='CUST_A') == {}
        assert grade.test.call_args[0][1] == 'vtysh -c "show ip route vrf CUST_A json"'


class TestKernelRouteLabels:
    def test_encap_labels(self):
        routes = parse_kernel_routes((MPLS_FIXTURES / 'iproute_ldp_pe1_final.json').read_text())
        assert kernel_route_labels(routes, '10.161.34.0/24') == [[18]]
        assert kernel_route_labels(routes, '10.161.47.2/32') == [[]]
        assert kernel_route_labels(routes, '192.0.2.0/24') == []
        assert routes['10.161.47.4/32']['nexthops'] == [('10.161.32.2', 'eth1')]
        st = parse_kernel_routes((MPLS_FIXTURES / 'iproute_st_pe1_final.json').read_text())
        assert st['10.161.18.0/24']['labels'] == [[381]] and st['10.161.18.0/24']['protocol'] == ''

    def test_label_stack_and_multipath(self):
        data = [{'dst': '10.0.0.0/24', 'encap': {'encap_type': 'mpls', 'dst': '16003/16005'}, 'gateway': '10.1.0.2',
                 'dev': 'eth1'},
                {'dst': '10.0.1.0/24', 'nexthops': [
                    {'encap': {'encap_type': 'mpls', 'dst': '20'}, 'gateway': '10.1.0.2', 'dev': 'eth1'},
                    {'gateway': '10.1.0.6', 'dev': 'eth2'}]}]
        routes = parse_kernel_routes(json.dumps(data))
        assert routes['10.0.0.0/24']['labels'] == [[16003, 16005]]
        assert routes['10.0.1.0/24']['labels'] == [[20], []]


class TestFrrConfigMpls:
    def test_mpls_ldp_block(self):
        c = parse_frr_config(load('config_mpls_ldp_p1.txt'))
        assert c['mpls_ldp'] == {'present': True, 'router_id': '10.161.47.2', 'transport_address': '10.161.47.2',
                                 'interfaces': ['eth0', 'eth1'], 'label_allocate': 'for LDP-FEC',
                                 'label_advertise': [], 'explicit_null': False}
        assert [e['prefix'] for e in c['access_lists']['LDP-FEC']] == ['10.161.47.0/24', '10.161.33.0/24',
                                                                       '10.161.34.0/24']
        assert c['access_lists']['LDP-FEC'][0] == {'seq': 5, 'action': 'permit', 'prefix': '10.161.47.0/24',
                                                   'exact': False}
        # the interface statements of OSPF are still read
        assert c['interfaces']['eth0']['network_type'] == 'point-to-point'

    def test_fault_and_other_forms(self):
        c = parse_frr_config(load('config_mpls_fix_pe2_initial.txt'))
        assert c['mpls_ldp']['interfaces'] == ['eth1'] and 'lo' not in c['interfaces']
        text = ("mpls ldp\n router-id 1.1.1.1\n !\n address-family ipv4\n  label local allocate host-routes\n"
                "  label local advertise explicit-null\n  interface eth1\n  exit\n exit-address-family\n !\n"
                " address-family ipv6\n  discovery transport-address ::1\n  interface eth2\n  exit\n"
                " exit-address-family\nexit\n")
        ldp = parse_frr_config(text)['mpls_ldp']
        assert ldp['label_allocate'] == 'host-routes' and ldp['explicit_null'] is True
        assert ldp['interfaces'] == ['eth1'] and ldp['transport_address'] is None

    def test_segment_routing_and_ti_lfa(self):
        sr = parse_frr_config(load('config_mpls_sr_r4.txt'))['router_ospf']
        assert sr['capability_opaque'] is True and sr['ti_lfa'] is None
        assert sr['segment_routing'] == {'enabled': True, 'srgb': (17000, 24999), 'srlb': None, 'node_msd': None,
                                         'prefixes': {'10.161.63.4/32': {'index': 40, 'no_php': True,
                                                                          'explicit_null': False}}}
        tl = parse_frr_config(load('config_mpls_tl_r1.txt'))['router_ospf']
        assert tl['ti_lfa'] == 'node' and tl['segment_routing']['srgb'] is None
        text = ("router ospf\n fast-reroute ti-lfa\n segment-routing global-block 16000 23999 local-block 5000 5999\n"
                " segment-routing node-msd 8\nexit\n")
        ro = parse_frr_config(text)['router_ospf']
        assert ro['ti_lfa'] == 'link' and ro['segment_routing']['srgb'] == (16000, 23999)
        assert ro['segment_routing']['srlb'] == (5000, 5999) and ro['segment_routing']['node_msd'] == 8


# ---------------------------------------------------------------------------
# BGP/MPLS L3VPN: the VPNv4 family, the instances of the VRFs (FRR 10.3, captured in the solved and
# in the untouched MPLS VPN lab: lab/sre/_DRAFT_misc/mpls-vpn.py)
# ---------------------------------------------------------------------------

from frr import bgp_neighbor_activated, get_bgp_vpn_routes, get_bgp_vpn_summary, parse_bgp_vpn_routes  # noqa: E402
from policy_routing import vrf_devices, vrf_of_port  # noqa: E402


class TestBgpVpn:
    def test_vpnv4_table_by_rd(self):
        routes = parse_bgp_vpn_routes(load_json('bgp_vpn_l3_pe2.json'))
        # the two customers announce the same prefixes, kept apart by their RD
        assert set(routes) == {'65000:18', '65000:35'}
        for rd in routes:
            assert set(routes[rd]) == {'192.168.16.0/24', '192.168.17.0/24'}
            remote = routes[rd]['192.168.16.0/24'][0]
            assert remote['path_from'] == 'internal' and remote['nexthop'] == '10.133.31.1' and remote['best']
            assert routes[rd]['192.168.17.0/24'][0]['path_from'] == 'external'

    def test_no_bgp(self):
        assert parse_bgp_vpn_routes(load_json('bgp_vpn_none.json')) == {}
        assert get_bgp_vpn_routes(make_grade(load('bgp_vpn_none.json')), 'pe1') == {}

    def test_summaries(self):
        s = parse_bgp_summary(load_json('bgp_vpn_summary_l3_pe1.json'))
        assert s['peers']['10.133.31.3']['established'] and s['peers']['10.133.31.3']['pfx_rcd'] == 2
        # a neighbour not activated in the family: no peer in the summary of the family
        assert parse_bgp_summary(load_json('bgp_vpn_summary_not_activated.json')) == {}
        grade = make_grade(load('bgp_vpn_summary_l3_pe1.json'))
        assert get_bgp_vpn_summary(grade, 'l3_pe1')['as'] == 65000
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp ipv4 vpn summary json"'

    def test_vrf_instance_commands(self):
        s = parse_bgp_summary(load_json('bgp_vrf_summary_ce_pe1.json'))
        assert s['peers']['172.18.0.2']['remote_as'] == 65101 and s['peers']['172.18.0.2']['established']
        grade = make_grade('{}')
        get_bgp_summary(grade, 'ce_pe1', vrf='CUST_C')
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp vrf CUST_C ipv4 unicast summary json"'
        get_bgp_routes(grade, 'ce_pe1', vrf='CUST_C')
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp vrf CUST_C ipv4 unicast json"'
        get_bgp_routes(grade, 'ce_pe1')
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp ipv4 unicast json"'
        get_kernel_routes(grade, 'pe1', vrf='CUST_A')
        assert grade.test.call_args[0][1] == 'ip -j route show vrf CUST_A'

    def test_as_override_seen_by_the_ce(self):
        routes = parse_bgp_routes(load_json('bgp_routes_ce_c2_override.json'))
        remote = [p for p in routes['172.18.122.0/24'] if p['best']]
        assert remote[0]['as_list'] == [65000, 65000]
        # its own network comes back from the PE (not best): the AS of the customer was replaced
        own = routes['172.18.29.0/24']
        assert [p['as_list'] for p in own] == [[], [65000, 65000]] and own[0]['best']

    def test_label_stacks_of_a_vrf(self):
        rib = parse_frr_routes(load_json('route_vrf_l3_pe1_a.json'))
        remote = rib['192.168.17.0/24']
        assert remote['protocol'] == 'bgp' and [n['labels'] for n in remote['nexthops']] == [[145], [16, 145]]
        kernel = parse_kernel_routes(load('iproute_vrf_l3_pe1_a.json'))
        assert kernel['192.168.17.0/24']['labels'] == [[16, 145]]
        # no LDP: the VPN label alone, which the P router does not know
        no_ldp = parse_kernel_routes(load('iproute_vrf_sv_pe1_no_ldp.json'))
        assert kernel_route_labels(no_ldp, '172.22.2.0/24') == [[16]]

    def test_vrf_devices(self):
        devices = vrf_devices(json.loads(load('links_vrf_l3_pe1.json')))
        assert devices == {'CUST_A': {'table': 10, 'up': True, 'ports': ['eth0']},
                           'CUST_B': {'table': 20, 'up': True, 'ports': ['eth1']}}
        fault = vrf_devices(json.loads(load('links_vrf_fix_pe2_initial.json')))
        assert fault['CUST_A']['ports'] == [] and vrf_of_port(fault, 'eth0') is None


class TestFrrConfigVpn:
    def test_vrf_instances(self):
        c = parse_frr_config(load('config_vpn_ex_pe1.txt'))
        # the VRF instances stay out of the main instance
        assert c['router_bgp']['as'] == 65000 and list(c['router_bgp']['neighbors']) == ['10.133.63.2']
        assert bgp_neighbor_activated(c['router_bgp'], '10.133.63.2', 'ipv4 vpn')
        assert not bgp_neighbor_activated(c['router_bgp'], '10.133.63.2', 'ipv4')
        assert set(c['router_bgp_vrfs']) == {'CUST_A', 'CUST_B'}
        a = c['router_bgp_vrfs']['CUST_A']
        assert a['as'] == 65000 and a['router_id'] == '10.133.63.1' and a['redistribute'] == ['connected']
        assert a['vpn'] == {'rd': '65000:35', 'rt_import': ['65000:35', '65000:65'], 'rt_export': ['65000:35'],
                            'label': 'auto', 'export_vpn': True, 'import_vpn': True, 'route_map_export': None,
                            'route_map_import': None}

    def test_vrf_neighbor_and_rt_both(self):
        c = parse_frr_config(load('config_vpn_ce_pe1.txt'))
        vrf = c['router_bgp_vrfs']['CUST_C']
        assert vrf['vpn']['rt_import'] == vrf['vpn']['rt_export'] == ['65000:45']
        n = vrf['neighbors']['172.18.0.2']
        assert n['remote_as'] == 65101 and n['route_map_in'] == 'ALL' and n['route_map_out'] == 'ALL'
        assert '172.18.0.2' not in c['router_bgp']['neighbors']

    def test_the_faults(self):
        pe1 = parse_frr_config(load('config_vpn_fix_pe1_initial.txt'))
        assert pe1['router_bgp_vrfs']['CUST_A']['vpn']['label'] is None
        pe2 = parse_frr_config(load('config_vpn_fix_pe2_initial.txt'))
        peer = list(pe2['router_bgp']['neighbors'])[0]
        assert not bgp_neighbor_activated(pe2['router_bgp'], peer, 'ipv4 vpn')
        assert pe2['router_bgp_vrfs']['CUST_A']['vpn']['rt_import'] == ['65000:57']

    def test_negations(self):
        text = ("router bgp 65000 vrf X\n address-family ipv4 unicast\n  rt vpn both 1:1\n  rt vpn import 1:1 2:2\n"
                "  no rt vpn import 2:2\n  label vpn export 100\n  no export vpn\n exit-address-family\nexit\n")
        vpn = parse_frr_config(text)['router_bgp_vrfs']['X']['vpn']
        assert vpn['rt_import'] == ['1:1'] and vpn['rt_export'] == ['1:1'] and vpn['label'] == '100'
        assert vpn['export_vpn'] is False and vpn['rd'] is None


# ---------------------------------------------------------------------------
# IS-IS and BFD (FRR 10.3 captures of an IS-IS probe on Debian 13: isis_*, bfd_*, config_isis_*,
# iproute_isis_*, ip6route_isis_*, route_isis_*)
# ---------------------------------------------------------------------------

from frr import (  # noqa: E402
    ISIS_DEFAULT_SRGB, bfd_detection_time, bfd_profile_value, get_bfd_peers, get_isis_database,
    get_isis_interfaces, get_isis_neighbors, get_isis_routes, is_isis_protocol, isis_adjacencies,
    isis_adjacency_levels, isis_adjacency_up, isis_interface_value, isis_lsp_node, isis_lsps_of, isis_net,
    isis_srgb, isis_system_id_from_ipv4, normalize_system_id, parse_bfd_peers, parse_isis_database,
    parse_isis_interfaces, parse_isis_neighbors, parse_isis_net, parse_isis_routes, _json_with_duplicates,
)


def load_isis(name: str):
    return _json_with_duplicates(load(name))


class TestIsisNames:
    @pytest.mark.parametrize('address, sysid', [('10.0.31.2', '0100.0003.1002'), ('10.99.255.1', '0100.9925.5001'),
                                                ('192.168.1.254/32', '1921.6800.1254')])
    def test_system_id_from_ipv4(self, address, sysid):
        assert isis_system_id_from_ipv4(address) == sysid

    def test_net(self):
        assert isis_net('49.0001', '0100.0003.1002') == '49.0001.0100.0003.1002.00'
        assert parse_isis_net('49.0001.0100.0003.1002.00') == {'area': '49.0001', 'system_id': '0100.0003.1002',
                                                               'nsel': '00'}
        assert parse_isis_net('49.0001.0100.0003.1002') is None
        assert parse_isis_net(' 49.ABCD.0100.0003.1002.00 ')['area'] == '49.abcd'
        assert parse_isis_net('49.0001.0002.0100.0003.1002.00')['area'] == '49.0001.0002'
        assert parse_isis_net(None) is None

    @pytest.mark.parametrize('text, sysid', [('0100.0003.1002', '0100.0003.1002'), ('010000031002', '0100.0003.1002'),
                                             ('0100.00031002 ', '0100.0003.1002'), ('ABCD.0000.0001', 'abcd.0000.0001'),
                                             ('0100.0003.100', None), ('', None), (None, None), ('0100.0003.10g2', None)])
    def test_normalize_system_id(self, text, sysid):
        assert normalize_system_id(text) == sysid

    def test_lsp_node(self):
        assert isis_lsp_node('r3.4d-00') == ('r3', '4d', '00')
        assert isis_lsp_node('lan_r3.00-01') == ('lan_r3', '00', '01')
        assert isis_lsp_node('0100.9925.5005.42-00') == ('0100.9925.5005', '42', '00')
        assert isis_lsp_node('nonsense') is None

    def test_protocol(self):
        assert is_isis_protocol('isis') and is_isis_protocol(187) and not is_isis_protocol('ospf')


class TestIsisNeighbors:
    def test_detail_lan_and_p2p(self):
        n = parse_isis_neighbors(load('isis_neighbor_detail_lan.txt'))
        assert [(x['name'], x['interface'], x['level']) for x in n] == [
            ('a', 'eth0', 2), ('c', 'eth1', 2), ('c', 'eth2', 2), ('e', 'eth2', 2)]
        a = n[0]
        assert a['up'] and a['state'] == 'Up' and a['holdtime'] == 19 and a['circuit_type'] == 'L2'
        assert a['speaks'] == ['IPv4', 'IPv6'] and a['topologies'] == ['standard', 'ipv6-unicast']
        assert a['areas'] == ['49.0001'] and a['ipv4'] == ['10.99.1.1']
        assert a['ipv6'] == ['fe80::f877:1dff:fe7b:4a86'] and a['ipv6_global'] == ['fd99:1::1']
        assert a['lan_id'] is None and a['is_dis'] is None and a['bfd'] is None
        dis = n[2]
        assert dis['lan_id'] == 'c.4d' and dis['priority'] == 100 and dis['is_dis'] is True
        assert n[3]['priority'] == 64 and n[3]['is_dis'] is False
        assert n[1]['holdtime'] == 2   # hello 1 s x 3 on that link

    def test_detail_both_levels_and_bfd(self):
        n = parse_isis_neighbors(load('isis_neighbor_detail_l1l2.txt'))
        assert [(x['name'], x['level'], x['circuit_type']) for x in n] == [('b', 3, 'L1L2'), ('d', 3, 'L1L2')]
        assert n[1]['ipv4'] == ['10.99.4.2'] and n[1]['areas'] == ['49.0001']
        b = parse_isis_neighbors(load('isis_neighbor_detail_bfd.txt'))
        assert len(b) == 1 and b[0]['bfd'] == 'Up' and b[0]['ipv4'] == ['10.99.4.2']

    def test_plain_table(self):
        n = parse_isis_neighbors(load('isis_neighbor_lan_l1l2.txt'))
        assert len(n) == 6 and n[2] == {'name': 'c', 'interface': 'eth2', 'level': 1, 'state': 'Up', 'up': True,
                                        'holdtime': 28, 'snpa': '9e00.c1c1.0b8b'}
        levels = parse_isis_neighbors(load('isis_neighbor_levels.txt'))
        assert [(x['name'], x['level']) for x in levels] == [('b', 1), ('d', 3)]

    def test_adjacency_filters(self):
        n = parse_isis_neighbors(load('isis_neighbor_lan_l1l2.txt'))
        # the two adjacencies of a broadcast circuit (one per level) count together
        assert isis_adjacency_up(n, 'c', 'eth2', level=3) and isis_adjacency_levels(n, 'c', 'eth2') == 3
        assert isis_adjacency_up(n, 'a', level=1) and isis_adjacency_up(n, 'a', level=2)
        assert not isis_adjacency_up(n, 'a', 'eth1') and not isis_adjacency_up(n, 'z')
        assert isis_adjacency_up(n, ['z', 'e'], 'eth2', level=2)
        levels = parse_isis_neighbors(load('isis_neighbor_levels.txt'))
        assert isis_adjacency_levels(levels, 'b') == 1 and not isis_adjacency_up(levels, 'b', level=2)
        down = [dict(levels[0], state='Initializing', up=False)]
        assert not isis_adjacency_up(down, 'b') and isis_adjacencies(down, 'b', up=False)

    def test_placeholder_and_errors(self):
        assert parse_isis_neighbors('') == [] and parse_isis_neighbors(None) == []
        assert get_isis_neighbors(make_grade('', 1), 'r1') == []
        assert get_isis_neighbors(make_grade(load('isis_neighbor_detail_bfd.txt')), 'r1')[0]['name'] == 'd'


class TestIsisInterfaces:
    def test_l1l2_lan_p2p_loopback(self):
        i = parse_isis_interfaces(load_isis('isis_interface_detail_l1l2.json'))
        assert set(i) == {'eth0', 'eth1', 'eth2', 'lo'}
        assert i['eth0']['type'] == 'p2p' and i['eth0']['level'] == 3 and not i['eth0']['passive']
        assert i['eth0']['levels'][1] == {'metric': 10, 'hello_interval': 3, 'hello_multiplier': 10, 'padding': True,
                                          'csnp_interval': 10, 'neighbors': 1, 'priority': None, 'is_dis': None}
        assert i['eth2']['type'] == 'lan' and i['eth2']['levels'][2]['priority'] == 64
        assert i['eth2']['levels'][2]['is_dis'] is False and i['eth2']['circuit_id'] == '0x50'
        assert i['lo']['passive'] and i['lo']['type'] == 'loopback' and i['lo']['ipv4'] == ['10.99.255.2/32']
        assert i['eth0']['ipv6'] == ['fd99:1::2/64'] and i['eth0']['ipv6_link_local'][0].startswith('fe80::')

    def test_dis_and_timers(self):
        i = parse_isis_interfaces(load_isis('isis_interface_detail_dis.json'))
        assert i['eth2']['levels'][2]['is_dis'] is True and i['eth2']['levels'][2]['priority'] == 100
        assert set(i['eth2']['levels']) == {2} and i['eth2']['level'] == 2
        assert i['eth0']['levels'][2]['hello_interval'] == 1 and i['eth0']['levels'][2]['hello_multiplier'] == 3
        h = parse_isis_interfaces(load_isis('isis_interface_detail_hello.json'))
        assert h['eth1']['levels'][2]['hello_multiplier'] == 3 and h['eth0']['levels'][2]['hello_multiplier'] == 10

    def test_empty(self):
        assert parse_isis_interfaces(None) == {} and parse_isis_interfaces({}) == {}
        assert get_isis_interfaces(make_grade('', 1), 'r1') == {}
        assert get_isis_interfaces(make_grade(load('isis_interface_detail_dis.json')), 'r1')['eth2']['type'] == 'lan'


class TestIsisDatabase:
    def test_levels_att_pseudonode(self):
        db = parse_isis_database(load_isis('isis_database_detail_l1l2.json'))
        assert set(db) == {1, 2}
        a = db[1]['a.00-00']
        assert a['node'] == 'a' and not a['pseudonode'] and a['att'] and not a['ol'] and a['areas'] == ['49.0001']
        assert a['seq'] == 2 and a['hostname'] == 'a' and a['router_id'] == '10.99.255.1' and a['protocols'] == ['IPv4']
        assert {r['id']: r['metric'] for r in a['is_reach']} == {'0100.9925.5002.00': 10, '0100.9925.5004.00': 10}
        assert [r['prefix'] for r in a['ip_reach']] == ['10.99.1.0/24', '10.99.4.0/24', '10.99.7.0/24', '10.99.255.1/32']
        assert db[1]['b.00-00']['own'] and not a['own']
        pn = db[1]['e.42-00']
        assert pn['pseudonode'] and pn['node'] == 'e'
        assert [x['node'] for x in isis_lsps_of(db, 1, 'e', pseudonode=True)] == ['e']
        assert len(isis_lsps_of(db, 2, ['a', 'b'], pseudonode=False)) == 2

    def test_overload_and_dis(self):
        db = parse_isis_database(load_isis('isis_database_detail_overload.json'))
        assert db[2]['e.00-00']['ol'] and not db[2]['c.00-00']['ol']
        assert db[2]['c.4d-00']['pseudonode'] and {r['metric'] for r in db[2]['c.4d-00']['is_reach']} == {0}
        external = [r['prefix'] for r in db[2]['a.00-00']['ip_reach']]
        assert '0.0.0.0/0' in external and '203.0.113.0/24' in external

    def test_multi_topology(self):
        a = parse_isis_database(load_isis('isis_database_detail_mt.json'))[2]['a.00-00']
        assert a['topologies'] == [0, 2] and a['protocols'] == ['IPv4', 'IPv6']
        assert [(r['id'], r['mt']) for r in a['is_reach']] == [
            ('0100.9925.5002.00', None), ('0100.9925.5004.00', None), ('0100.9925.5002.00', 'ipv6-unicast')]
        assert [(r['prefix'], r['mt']) for r in a['ipv6_reach']][0] == ('fd99:1::/64', 'ipv6-unicast')

    def test_segment_routing(self):
        db = parse_isis_database(load_isis('isis_database_detail_sr.json'))[2]
        assert db['c.00-00']['srgb'] == (30000, 8000) and db['a.00-00']['srgb'] == (16000, 8000)
        assert db['a.00-00']['srlb'] == (15000, 1000)
        sids = {r['prefix']: r['sid'] for r in db['d.00-00']['ip_reach'] if r['sid']}
        assert sids == {'10.99.255.4/32': {'index': 4, 'no_php': True, 'explicit_null': False}}
        assert db['a.00-00']['is_reach'][0]['adj_sids']

    def test_duplicate_keys_become_lists(self):
        data = _json_with_duplicates('{"areas": [{"area": {"name": "CORE"}, "levels": [{"id": 1, "lsps": [{"lsp": '
                                     '{"id": "x.00-00"}, "attPOl": "0/0/0", "areaAddr": "49.0001", '
                                     '"areaAddr": "49.0002"}]}]}]}')
        assert parse_isis_database(data)[1]['x.00-00']['areas'] == ['49.0001', '49.0002']

    def test_empty(self):
        assert parse_isis_database(None) == {} and parse_isis_database({'areas': []}) == {}
        assert get_isis_database(make_grade('% isis not running', 0), 'r1') == {}


class TestIsisRoutes:
    def test_ecmp_and_levels(self):
        rt = parse_isis_routes(load_isis('isis_route_l1l2.json'))
        assert set(rt) == {1, 2}
        assert rt[2]['10.99.255.3/32'] == {'metric': 30, 'nexthops': [('10.99.1.2', 'eth0'), ('10.99.4.2', 'eth1')],
                                           'labels': [None, None]}
        assert rt[1]['10.99.7.0/24'] == {'metric': 0, 'nexthops': [], 'labels': []}
        assert rt[2]['10.99.8.0/24']['nexthops'] == [('10.99.4.2', 'eth1')]

    def test_ipv6(self):
        data = load_isis('isis_route_mt.json')
        rt6 = parse_isis_routes(data, ipv6=True)
        assert rt6[2]['fd99:8::/64'] == {'metric': 40, 'nexthops': [('fe80::e0c3:acff:fe6e:1cae', 'eth0')],
                                         'labels': [None]}
        assert '10.99.8.0/24' in parse_isis_routes(data)[2] and rt6.get(1) == {}

    def test_empty(self):
        assert parse_isis_routes(None) == {} and get_isis_routes(make_grade('', 1), 'r1') == {}


class TestIsisKernelRoutes:
    def test_isis_routes(self):
        k = parse_kernel_routes(load('iproute_isis_ecmp.json'))
        isis = {p for p, v in k.items() if is_isis_protocol(v['protocol'])}
        assert '10.99.8.0/24' in isis and k['10.99.255.3/32']['nexthops'] == [('10.99.1.2', 'eth0'),
                                                                             ('10.99.4.2', 'eth1')]
        assert kernel_route_gateways(k, '10.99.8.0/24', protocols=('isis', '187')) == ['10.99.4.2']
        k6 = parse_kernel_routes(load('ip6route_isis_mt.json'), ipv6=True)
        assert is_isis_protocol(k6['fd99:8::/64']['protocol'])


class TestBfdPeers:
    def test_up(self):
        p = parse_bfd_peers(load_isis('bfd_peers_up.json'))
        assert list(p) == ['10.99.4.2']
        s = p['10.99.4.2']
        assert s['up'] and s['interface'] == 'eth1' and s['local'] == '10.99.4.1' and not s['multihop']
        assert (s['receive_interval'], s['transmit_interval'], s['detect_multiplier']) == (100, 100, 3)
        assert bfd_detection_time(s) == 300
        assert bfd_detection_time(dict(s, remote_transmit_interval=250, remote_detect_multiplier=4)) == 1000

    def test_none(self):
        assert parse_bfd_peers(load_isis('bfd_peers_none.json')) == {} and parse_bfd_peers(None) == {}
        assert get_bfd_peers(make_grade('', 1), 'r1') == {} and bfd_detection_time({}) is None


class TestFrrConfigIsis:
    def test_router_and_interfaces(self):
        c = parse_frr_config(load('config_isis_sr_bfd.txt'))
        ri = c['router_isis']
        assert ri['present'] and ri['name'] == 'CORE' and ri['nets'] == ['49.0001.0100.9925.5001.00']
        assert ri['is_type'] == 'level-2-only' and ri['topologies'] == ['ipv6-unicast'] and not ri['overload']
        assert ri['redistribute'] == [('ipv4', 'static', 'level-2')]
        assert ri['default_information'] == [{'afi': 'ipv4', 'level': 'level-2', 'always': False}]
        assert ri['segment_routing']['prefixes'] == {'10.99.255.1/32': {'index': 1, 'no_php': False,
                                                                        'explicit_null': False}}
        assert isis_srgb(ri) == ISIS_DEFAULT_SRGB == (16000, 23999)
        eth1 = c['interfaces']['eth1']['isis']
        assert eth1['ipv4'] == 'CORE' and eth1['ipv6'] is None and eth1['network_type'] == 'point-to-point'
        assert eth1['bfd'] and eth1['bfd_profile'] == 'FAST' and eth1['fast_reroute'] == {'level-2': 'node'}
        assert c['interfaces']['lo']['isis']['passive'] and c['interfaces']['eth0']['isis']['ipv6'] == 'CORE'
        fast = c['bfd']['profiles']['FAST']
        assert fast == {'transmit_interval': 100, 'receive_interval': 100}
        assert bfd_profile_value(fast, 'detect_multiplier') == 3 and bfd_profile_value(fast, 'receive_interval') == 100
        assert bfd_profile_value(None, 'receive_interval') is None
        assert c['static_routes'] == [('0.0.0.0/0', '10.99.7.2'), ('203.0.113.0/24', '10.99.7.2')]

    def test_passwords_and_timers(self):
        c = parse_frr_config(load('config_isis_auth.txt'))
        assert c['router_isis']['domain_password'] == {'type': 'md5', 'key': 'DomKey2'}
        assert c['router_isis']['area_password'] is None
        assert c['interfaces']['eth0']['isis']['password'] == {'type': 'md5', 'key': 'HelloKey1'}
        eth1 = c['interfaces']['eth1']['isis']
        assert isis_interface_value(eth1, 'hello_interval', 2) == 1 and isis_interface_value(eth1, 'hello_multiplier', 1) == 3
        assert isis_interface_value(c['interfaces']['eth2']['isis'], 'hello_interval', 2) is None

    def test_srgb_and_no_php(self):
        c = parse_frr_config(load('config_isis_srgb.txt'))['router_isis']
        assert isis_srgb(c) == (30000, 37999) and c['segment_routing']['prefixes']['10.99.255.3/32']['index'] == 3
        d = parse_frr_config(load('config_isis_sr_nophp.txt'))['router_isis']
        assert d['segment_routing']['prefixes']['10.99.255.4/32']['no_php'] and isis_srgb(d) == (16000, 23999)
        assert isis_srgb(parse_frr_config('router isis X\n net 49.0001.0000.0000.0001.00\nexit\n')['router_isis']) is None

    def test_levels_metrics_overload(self):
        # statements as FRR 10.3 writes them (seen in the probe), gathered in one configuration
        text = ("interface eth0\n ip router isis CORE\n isis circuit-type level-1\n isis metric 200\n"
                " isis priority 100 level-2\n isis password clear Secret\nexit\n"
                "interface eth1\n ip router isis CORE\n isis metric 30 level-1\n isis hello-interval 1 level-2\n"
                " no isis passive\nexit\n"
                "router isis CORE\n is-type level-1\n net 49.0001.0100.0003.1002.00\n net 49.0002.0100.0003.1002.00\n"
                " metric-style narrow\n set-overload-bit\n area-password md5 AreaKey\n no hostname dynamic\n"
                " lsp-gen-interval 2\n log-adjacency-changes\nexit\n")
        c = parse_frr_config(text)
        ri = c['router_isis']
        assert ri['is_type'] == 'level-1' and ri['metric_style'] == 'narrow' and ri['overload']
        assert ri['nets'] == ['49.0001.0100.0003.1002.00', '49.0002.0100.0003.1002.00']
        assert ri['area_password'] == {'type': 'md5', 'key': 'AreaKey'} and not ri['hostname_dynamic']
        assert ri['lsp_gen_interval'] == 2 and ri['log_adjacency_changes']
        e0 = c['interfaces']['eth0']['isis']
        assert e0['circuit_type'] == 'level-1' and e0['metric'] == {'all': 200} and e0['priority'] == {'level-2': 100}
        assert isis_interface_value(e0, 'metric', 1) == 200 and isis_interface_value(e0, 'priority', 1) is None
        assert e0['password'] == {'type': 'clear', 'key': 'Secret'}
        e1 = c['interfaces']['eth1']['isis']
        assert isis_interface_value(e1, 'metric', 1) == 30 and isis_interface_value(e1, 'metric', 2) is None
        assert e1['hello_interval'] == {'level-2': 1} and e1['passive'] is False

    def test_negations(self):
        text = ("interface eth0\n ip router isis CORE\n no ip router isis CORE\n isis bfd\n no isis bfd\nexit\n"
                "router isis CORE\n net 49.0001.0000.0000.0001.00\n no net 49.0001.0000.0000.0001.00\n"
                " set-overload-bit\n no set-overload-bit\n topology ipv6-unicast\n no topology ipv6-unicast\nexit\n")
        c = parse_frr_config(text)
        assert c['interfaces']['eth0']['isis']['ipv4'] is None and not c['interfaces']['eth0']['isis']['bfd']
        assert c['router_isis']['nets'] == [] and not c['router_isis']['overload']
        assert c['router_isis']['topologies'] == []

    def test_no_isis(self):
        c = parse_frr_config(load('config_isis_srgb.txt').replace('router isis', 'router ospf'))
        assert not c['router_isis']['present'] and c['bfd'] == {'profiles': {}}


# ---------------------------------------------------------------------------
# EVPN (FRR 10.3 captures of a VXLAN / EVPN probe on Debian 13: evpn_*, bgp_evpn_vni_*, config_evpn_*,
# bgp_vpn_gw_*, iproute_vrf_gw_*, iproute_vrf_irb_*, mroute_vxlan; and of the solved labs:
# tests/mock_data/vxlan/lab1_*, lab2_*)
# ---------------------------------------------------------------------------

from frr import (  # noqa: E402
    evpn_family, evpn_routes, get_bgp_evpn_routes, get_bgp_evpn_summary, get_bgp_evpn_vni, get_evpn_arp_cache,
    get_evpn_macs, get_evpn_rmacs, get_evpn_vnis, get_vrf_vnis, parse_bgp_evpn_routes, parse_bgp_evpn_vni,
    parse_evpn_arp_cache, parse_evpn_macs, parse_evpn_prefix, parse_evpn_rmacs, parse_evpn_vnis, parse_mroutes,
    parse_vrf_vnis, parse_bgp_vpn_routes, bgp_neighbor_activated,
)

VXLAN_FIXTURES = Path(__file__).parent / 'mock_data' / 'vxlan'


def load_evpn(name: str):
    return json.loads(load(name))


def load_vxlan(name: str) -> str:
    return (VXLAN_FIXTURES / name).read_text()


class TestEvpnPrefix:
    @pytest.mark.parametrize('prefix, expected', [
        ('[2]:[0]:[48]:[6E:F5:66:0b:a1:15]', {'type': 2, 'eth_tag': 0, 'mac': '6e:f5:66:0b:a1:15', 'ip': None}),
        ('[2]:[0]:[48]:[96:ce:35:e9:9b:49]:[32]:[192.168.20.15]',
         {'type': 2, 'eth_tag': 0, 'mac': '96:ce:35:e9:9b:49', 'ip': '192.168.20.15'}),
        ('[3]:[0]:[32]:[10.255.0.11]', {'type': 3, 'eth_tag': 0, 'vtep': '10.255.0.11'}),
        ('[5]:[0]:[24]:[203.0.113.0]', {'type': 5, 'eth_tag': 0, 'network': '203.0.113.0/24'}),
        ('[4]:[03:44:38:39:ff:ff:01:00:00:01]:[32]:[10.0.0.1]', {'type': 4, 'eth_tag': None,
                                                                 'fields': ['03:44:38:39:ff:ff:01:00:00:01', '32', '10.0.0.1']}),
        ('rd', {}), (None, {}), ('[x]:[0]', {}),
    ])
    def test_prefixes(self, prefix, expected):
        assert parse_evpn_prefix(prefix) == expected


class TestEvpnRoutes:
    def test_layer2_fabric(self):
        routes = parse_bgp_evpn_routes(load_evpn('evpn_route_detail_l2.json'))
        assert len(routes) == 10 and sum(r['local'] for r in routes) == 4
        # the type-3 routes build the flood list: one per VNI and VTEP, with ingress replication
        type3 = evpn_routes(routes, route_type=3, vtep='10.255.0.12')
        assert sorted(r['rts'][0] for r in type3) == ['65000:100', '65000:200']
        assert all(r['pmsi'] == 'Ingress Replication' and r['nexthop'] == '10.255.0.12' for r in type3)
        remote_mac = evpn_routes(routes, route_type=2, mac='FE:91:FB:2E:62:6A')
        assert remote_mac[0]['rd'] == '10.255.0.12:2' and remote_mac[0]['vnis'] == [100] and not remote_mac[0]['local']
        assert remote_mac[0]['peer'] == '10.255.0.1'     # reflected by the spine
        assert evpn_routes(routes, route_type=3, local=True, rt='65000:200')[0]['vtep'] == '10.255.0.11'

    def test_symmetric_irb(self):
        routes = parse_bgp_evpn_routes(load_evpn('evpn_route_detail_irb.json'))
        macip = evpn_routes(routes, route_type=2, ip='192.168.20.15')
        assert len(macip) == 1
        r = macip[0]
        # a MAC+IP route carries the L2VNI and the L3VNI, two RTs and the router MAC of its VTEP
        assert r['vnis'] == [200, 4000] and r['rts'] == ['65000:200', '65000:4000']
        assert r['router_mac'] == 'fa:97:32:8e:06:48' and r['nexthop'] == '10.255.0.12'
        assert len(evpn_routes(routes, route_type=2, mac='96:ce:35:e9:9b:49', ip=False)) == 1
        type5 = evpn_routes(routes, route_type=5)
        assert [(x['network'], x['nexthop'], x['vnis']) for x in type5] == [('203.0.113.0/24', '10.255.0.20', [4000])]

    def test_brief_form_has_no_vni(self):
        routes = parse_bgp_evpn_routes(load_evpn('evpn_route_brief_irb.json'))
        r = evpn_routes(routes, route_type=2, ip='192.168.20.15')[0]
        assert r['vnis'] == [] and r['rts'] == ['65000:200', '65000:4000'] and r['best']
        assert sum(x['local'] for x in routes) == 6       # peerId "(unspec)"

    def test_gateway_reoriginates_vpn_routes(self):
        routes = parse_bgp_evpn_routes(load_evpn('evpn_route_detail_gw.json'))
        vpn = evpn_routes(routes, route_type=5, network='172.16.9.0/24', nexthop='10.255.0.20')
        assert vpn and vpn[0]['vnis'] == [4000] and '65000:4000' in vpn[0]['rts']

    def test_ebgp_between_data_centres(self):
        routes = parse_bgp_evpn_routes(load_evpn('evpn_route_detail_dci.json'))
        # the automatic RTs differ (AS:VNI), the route is installed all the same
        assert evpn_routes(routes, route_type=3, vtep='10.255.0.32')[0]['rts'] == ['65102:300']
        assert evpn_routes(routes, route_type=3, local=True)[0]['rts'] == ['65101:300']
        lab = parse_bgp_evpn_routes(json.loads(load_vxlan('lab2_route_st_dc1.json')))
        assert len(evpn_routes(lab, route_type=3)) == 2 and len(evpn_routes(lab, route_type=2)) == 2

    def test_empty_and_invalid(self):
        assert parse_bgp_evpn_routes({}) == [] and parse_bgp_evpn_routes([]) == []
        # bgpd with BGP but no EVPN prints invalid json
        assert get_bgp_evpn_routes(make_grade('{ ,"numPrefix":0,"numPaths":0}'), 'pe1') == []
        grade = make_grade(load('evpn_route_detail_l2.json'))
        assert len(get_bgp_evpn_routes(grade, 'l1', step=2)) == 10
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp l2vpn evpn route detail json"'

    def test_filters(self):
        routes = parse_bgp_evpn_routes(load_evpn('evpn_route_detail_irb.json'))
        not_best = dict(routes[0], best=False)
        assert evpn_routes([not_best]) == [] and evpn_routes([not_best], best_only=False) == [not_best]
        assert evpn_routes(routes, route_type=2, ip='192.168.99.1') == []
        assert evpn_routes(routes, route_type=5, network='203.0.113.0/24', nexthop='10.255.0.11') == []


class TestEvpnVnis:
    def test_detail_layer2(self):
        vnis = parse_evpn_vnis(load_evpn('evpn_vni_detail_l2.json'))
        assert set(vnis) == {100, 200}
        assert vnis[100]['remote_vteps'] == ['10.255.0.12', '10.255.0.13'] and vnis[100]['flood']['10.255.0.12'] == 'HER'
        assert vnis[100]['svi'] == 'br100' and vnis[100]['vtep_ip'] == '10.255.0.11' and vnis[100]['mcast_group'] is None
        assert vnis[200]['type'] == 'L2' and vnis[200]['vrf'] == 'default'

    def test_detail_irb_and_border(self):
        vnis = parse_evpn_vnis(load_evpn('evpn_vni_detail_irb.json'))
        l3 = vnis[4000]
        assert (l3['type'], l3['vrf'], l3['state'], l3['svi'], l3['vxlan_if']) == ('L3', 'TENANT', 'Up', 'br4000', 'vxlan4000')
        assert l3['router_mac'] == 'ce:d2:6c:17:61:1f' and l3['l2_vnis'] == [100, 200] and l3['remote_vteps'] == []
        assert vnis[100]['vrf'] == 'TENANT'
        border = parse_evpn_vnis(load_evpn('evpn_vni_detail_border.json'))
        assert list(border) == [4000] and border[4000]['l2_vnis'] == []

    def test_brief_form_and_empty(self):
        vnis = parse_evpn_vnis(load_evpn('evpn_vni_irb.json'))
        assert vnis[100]['remote_vteps'] == ['10.255.0.12', '10.255.0.13'] and vnis[4000]['type'] == 'L3'
        assert parse_evpn_vnis({}) == {} and parse_evpn_vnis(None) == {}

    def test_wrapper_reads_a_list(self):
        grade = make_grade(load('evpn_vni_detail_irb.json'))
        assert set(get_evpn_vnis(grade, 'l1')) == {100, 200, 4000}
        assert grade.test.call_args[0][1] == 'vtysh -c "show evpn vni detail json"'
        assert get_evpn_vnis(make_grade('{}'), 'p') == {}
        lab = parse_evpn_vnis(json.loads(load_vxlan('lab1_vni_l2_leaf2.json')))
        assert len(lab) == 2 and all(len(v['remote_vteps']) == 1 for v in lab.values())


class TestEvpnTables:
    def test_macs(self):
        macs = parse_evpn_macs(load_evpn('evpn_mac_leaf.json'))
        assert macs[100]['6e:f5:66:0b:a1:15'] == {'type': 'local', 'intf': 'eth1', 'remote_vtep': None}
        assert macs[100]['fe:91:fb:2e:62:6a']['remote_vtep'] == '10.255.0.12'
        grade = make_grade(load('evpn_mac_leaf.json'))
        assert set(get_evpn_macs(grade, 'l1')) == {100, 200}
        assert grade.test.call_args[0][1] == 'vtysh -c "show evpn mac vni all json"'

    def test_arp_cache(self):
        arp = parse_evpn_arp_cache(load_evpn('evpn_arpcache_irb.json'))
        assert arp[200]['192.168.20.15'] == {'type': 'remote', 'state': 'active', 'mac': '96:ce:35:e9:9b:49',
                                             'remote_vtep': '10.255.0.12'}
        # a STALE neighbour of the leaf: local, inactive (its MAC+IP route is withdrawn)
        assert arp[100]['192.168.10.13']['state'] == 'inactive'
        assert get_evpn_arp_cache(make_grade(load('evpn_arpcache_irb.json')), 'l1')[200]['192.168.20.14']['type'] == 'local'

    def test_l3vni_tables(self):
        assert parse_vrf_vnis(load_evpn('evpn_vrf_vni_irb.json')) == {
            'TENANT': {'vni': 4000, 'vxlan_if': 'vxlan4000', 'svi': 'br4000', 'state': 'Up',
                       'router_mac': 'ce:d2:6c:17:61:1f'}}
        assert parse_vrf_vnis({'vrfs': []}) == {}
        assert parse_evpn_rmacs(load_evpn('evpn_rmac_irb.json')) == {
            4000: {'fa:97:32:8e:06:48': '10.255.0.12', 'c2:3b:56:81:89:a8': '10.255.0.20'}}
        grade = make_grade(load('evpn_vrf_vni_irb.json'))
        assert get_vrf_vnis(grade, 'l1')['TENANT']['vni'] == 4000
        assert grade.test.call_args[0][1] == 'vtysh -c "show vrf vni json"'
        assert get_evpn_rmacs(make_grade(load('evpn_rmac_irb.json')), 'l1')[4000]

    def test_bgp_vni_route_targets(self):
        info = parse_bgp_evpn_vni(load_evpn('bgp_evpn_vni_irb.json'))
        assert info['advertise_all_vni'] and info['flooding'] == 'Head-end replication'
        # automatic RD = router-id:index (not the VNI), automatic RT = AS:VNI
        assert info['vnis'][100] == {'type': 'L2', 'rd': '10.255.0.11:2', 'import_rts': ['65000:100'],
                                     'export_rts': ['65000:100'], 'rmac': None}
        assert info['vnis'][4000]['type'] == 'L3' and info['vnis'][4000]['rmac'] == 'ce:d2:6c:17:61:1f'
        manual = parse_bgp_evpn_vni(load_evpn('bgp_evpn_vni_manual.json'))
        assert manual['vnis'][300]['rd'] == '10.255.0.31:300' and manual['vnis'][300]['import_rts'] == ['65102:300']
        assert parse_bgp_evpn_vni({}) == {}
        assert get_bgp_evpn_vni(make_grade(load('bgp_evpn_vni_irb.json')), 'l1')['vnis'][200]['rd'] == '10.255.0.11:3'

    def test_multicast_underlay_mroutes(self):
        routes = parse_mroutes(load_evpn('mroute_vxlan.json'))
        star = routes[('*', '239.1.1.5')]
        assert star['oil'] == ['eth0', 'eth1', 'eth2'] and star['iif'] == 'lo'
        assert any(src == '10.0.1.2' for src, _g in routes)
        lab = parse_mroutes(json.loads(load_vxlan('lab1_mroute_mc_r.json')))
        assert {flags for flags in (e['flags'] for e in lab.values())} == {'SC', 'SFT'}


class TestEvpnSummary:
    def test_spine_and_leaf(self):
        s = parse_bgp_summary(load_evpn('evpn_summary_spine.json'))
        assert sorted(s['peers']) == ['10.255.0.11', '10.255.0.12', '10.255.0.13']
        assert all(p['established'] and not p['policy_blocked'] for p in s['peers'].values())
        grade = make_grade(load('evpn_summary_leaf.json'))
        assert get_bgp_evpn_summary(grade, 'l1')['peers']['10.255.0.1']['pfx_rcd'] == 6
        assert grade.test.call_args[0][1] == 'vtysh -c "show bgp l2vpn evpn summary json"'

    def test_rfc8212_applies_to_evpn(self):
        p = parse_bgp_summary(load_evpn('evpn_summary_policy.json'))['peers']['10.255.0.32']
        assert p['established'] and p['policy_blocked'] and p['remote_as'] == 65102
        assert get_bgp_evpn_summary(make_grade('{}'), 'p') == {}


class TestFrrConfigEvpn:
    def test_spine_route_reflector(self):
        rb = parse_frr_config(load('config_evpn_spine.txt'))['router_bgp']
        assert not rb['default_ipv4_unicast']
        af = evpn_family(rb)
        assert all(bgp_neighbor_activated(rb, p, 'l2vpn evpn') for p in ('10.255.0.11', '10.255.0.12', '10.255.0.13'))
        assert not bgp_neighbor_activated(rb, '10.255.0.11', 'ipv4')
        assert all(af['neighbors'][p]['route_reflector_client'] for p in af['neighbors'])
        assert not af['advertise_all_vni']

    def test_leaf_and_irb(self):
        c = parse_frr_config(load('config_evpn_leaf.txt'))
        assert evpn_family(c['router_bgp'])['advertise_all_vni'] and c['vrfs'] == {}
        irb = parse_frr_config(load('config_evpn_irb_leaf.txt'))
        assert irb['vrfs'] == {'TENANT': {'vni': 4000}}
        # the VRF instance of a leaf without type-5
        assert not evpn_family(irb['router_bgp_vrfs']['TENANT'])['advertise_ipv4_unicast']
        border = parse_frr_config(load('config_evpn_irb_border.txt'))
        tenant = border['router_bgp_vrfs']['TENANT']
        assert evpn_family(tenant)['advertise_ipv4_unicast'] and tenant['redistribute'] == ['connected']

    def test_vni_block_and_autort(self):
        rb = parse_frr_config(load('config_evpn_vni.txt'))['router_bgp']
        af = evpn_family(rb)
        assert af['vnis'] == {300: {'rd': '10.255.0.31:300', 'rt_import': ['65102:300'], 'rt_export': []}}
        assert af['autort_rfc8365'] and af['advertise_all_vni']
        assert af['neighbors']['10.255.0.32']['route_map_out'] == 'ALL'
        assert bgp_neighbor_activated(rb, '10.255.0.32', 'l2vpn evpn')

    def test_gateway_vrf(self):
        c = parse_frr_config(load('config_evpn_gw.txt'))
        tenant = c['router_bgp_vrfs']['TENANT']
        assert tenant['vpn'] == {'rd': '65000:201', 'rt_import': ['65000:200'], 'rt_export': ['65000:200'],
                                 'label': 'auto', 'export_vpn': True, 'import_vpn': True,
                                 'route_map_export': 'VPN-OUT', 'route_map_import': None}
        assert evpn_family(tenant)['advertise_ipv4_unicast']
        assert bgp_neighbor_activated(c['router_bgp'], '10.255.0.23', 'ipv4 vpn')
        assert c['prefix_lists']['NO-HOST'][0] == {'seq': 5, 'action': 'deny', 'prefix': '0.0.0.0/0', 'ge': 32,
                                                   'le': None}

    def test_statements_and_negations(self):
        text = ("vrf T\n vni 5000\nexit-vrf\nvrf U\n vni 6000\n no vni 6000\nexit-vrf\n"
                "router bgp 65000\n address-family l2vpn evpn\n advertise-all-vni\n no advertise-all-vni\n"
                "  vni 10\n   rd 1.1.1.1:10\n   route-target import 65000:10 65000:11\n   route-target both 65000:12\n"
                "   no route-target import 65000:11\n  exit-vni\n  vni 20\n  exit-vni\n  no vni 20\n"
                "  advertise-svi-ip\n  advertise-default-gw\n exit-address-family\nexit\n"
                "router bgp 65000 vrf T\n address-family l2vpn evpn\n  rd 1.1.1.1:5000\n"
                "  route-target import 65000:5000\n  advertise ipv4 unicast\n exit-address-family\nexit\n")
        c = parse_frr_config(text)
        assert c['vrfs'] == {'T': {'vni': 5000}, 'U': {'vni': None}}
        af = evpn_family(c['router_bgp'])
        assert not af['advertise_all_vni'] and af['advertise_svi_ip'] and af['advertise_default_gw']
        assert af['vnis'] == {10: {'rd': '1.1.1.1:10', 'rt_import': ['65000:10', '65000:12'], 'rt_export': ['65000:12']}}
        vrf = evpn_family(c['router_bgp_vrfs']['T'])
        assert vrf['rd'] == '1.1.1.1:5000' and vrf['rt_import'] == ['65000:5000'] and vrf['advertise_ipv4_unicast']
        assert evpn_family({})['vnis'] == {} and evpn_family(None)['advertise_all_vni'] is False

    def test_lab_captures(self):
        spine = evpn_family(parse_frr_config(load_vxlan('lab1_config_fix_spine.txt'))['router_bgp'])
        assert sum(bool(n.get('route_reflector_client')) for n in spine['neighbors'].values()) == 2
        assert evpn_family(parse_frr_config(load_vxlan('lab1_config_fix_leaf2.txt'))['router_bgp'])['advertise_all_vni']
        dc1 = parse_frr_config(load_vxlan('lab2_config_fix_dc1.txt'))['router_bgp']
        assert any(n['ebgp_multihop'] == 5 for n in dc1['neighbors'].values())
        dc2 = parse_frr_config(load_vxlan('lab2_config_fix_dc2.txt'))['router_bgp']
        evpn_neighbors = evpn_family(dc2)['neighbors']
        assert len(evpn_neighbors) == 1 and list(evpn_neighbors.values())[0]['route_map_out'] == 'ALL'
        # the PE-CE neighbour of the VTEP is only active in IPv4 unicast
        pe = [p for p in dc2['neighbors'] if p not in evpn_neighbors][0]
        assert bgp_neighbor_activated(dc2, pe, 'ipv4') and not bgp_neighbor_activated(dc2, pe, 'l2vpn evpn')


class TestGatewayTables:
    def test_vpn_routes_with_and_without_host_routes(self):
        hosts = parse_bgp_vpn_routes(load_evpn('bgp_vpn_gw_hosts_pe2.json'))
        dc = hosts['65000:201']
        assert {'192.168.10.0/24', '192.168.10.11/32', '192.168.20.15/32'} <= set(dc)
        filtered = parse_bgp_vpn_routes(load_evpn('bgp_vpn_gw_pe2.json'))['65000:201']
        assert not [p for p in filtered if p.endswith('/32')] and '192.168.20.0/24' in filtered

    def test_kernel_routes_of_the_gateway_and_the_leaf(self):
        border = parse_kernel_routes(load('iproute_vrf_gw_border.json'))
        # towards the remote site: MPLS (transport + VPN); towards the data centre: the L3VNI bridge
        assert border['172.16.9.0/24']['labels'] == [[16, 80]]
        assert border['192.168.10.11/32']['nexthops'] == [('10.255.0.11', 'br4000')]
        leaf = parse_kernel_routes(load('iproute_vrf_irb_leaf.json'))
        assert leaf['192.168.20.15/32']['nexthops'] == [('10.255.0.12', 'br4000')]
        assert leaf['203.0.113.0/24']['nexthops'] == [('10.255.0.20', 'br4000')]


# ---------------------------------------------------------------------------
# BGP operations (RPKI, maximum-prefix, GTSM, confederations, dampening, BFD, graceful shutdown):
# fixtures captured on FRR 10.3 + stayrtr in a probe lab (s15, 2026-11-23; tests/mock_data/frr/bgpops_*)
# ---------------------------------------------------------------------------

from frr import (  # noqa: E402
    BGP_DAMPENING_DEFAULTS, confed_as_list_from_string, get_bgp_dampened_paths, get_bgp_dampening_parameters,
    get_bgp_flap_statistics, get_rpki_cache_connection, get_rpki_prefix_table, parse_bgp_dampening_parameters,
    parse_bgp_dampening_paths, parse_rpki_cache_connection, parse_rpki_prefix_table, rpki_origin_state,
)


class TestRpki:
    def test_cache_connection(self):
        c = parse_rpki_cache_connection(load_json('bgpops_rpki_connection.json'))
        assert c['connected'] is True and c['error'] is None
        assert c['connections'] == [{'mode': 'tcp', 'host': '10.0.99.2', 'port': 3323, 'preference': 1,
                                     'state': 'connected'}]

    def test_no_connection(self):
        c = parse_rpki_cache_connection({"error": "No connection to RPKI cache server."})
        assert c == {'connected': False, 'error': "No connection to RPKI cache server.", 'connections': []}
        assert parse_rpki_cache_connection(None)['connected'] is False
        assert get_rpki_cache_connection(make_grade('% Unknown command: show rpki cache-connection json', 1),
                                         'r1')['connected'] is False

    def test_prefix_table(self):
        vrps = parse_rpki_prefix_table(load_json('bgpops_rpki_prefix_table.json'))
        assert {'prefix': '172.16.4.0/22', 'max_length': 22, 'asn': 65002} in vrps
        assert {'prefix': '172.16.2.0/24', 'max_length': 24, 'asn': 65099} in vrps
        assert parse_rpki_prefix_table({"error": "No Connection to RPKI cache server."}) == []

    def test_calls(self):
        grade = make_grade(load('bgpops_rpki_prefix_table.json'))
        assert get_rpki_prefix_table(grade, 'r1', step=2)
        grade.test.assert_called_once_with('r1', 'vtysh -c "show rpki prefix-table json"', step=2, allow_error=True)

    def test_origin_validation(self):
        vrps = [{'prefix': '172.16.4.0/22', 'max_length': 22, 'asn': 65002},
                {'prefix': '172.16.2.0/24', 'max_length': 24, 'asn': 65099},
                {'prefix': '172.16.2.0/24', 'max_length': 24, 'asn': 65002}]
        assert rpki_origin_state(vrps, '172.16.4.0/22', 65002) == 'valid'
        assert rpki_origin_state(vrps, '172.16.4.0/24', 65002) == 'invalid'    # longer than maxLength
        assert rpki_origin_state(vrps, '172.16.4.0/22', 65003) == 'invalid'    # wrong origin
        assert rpki_origin_state(vrps, '172.16.2.0/24', 65002) == 'valid'      # one VRP of two matches
        assert rpki_origin_state(vrps, '172.16.3.0/24', 65002) == 'notfound'

    def test_route_states(self):
        routes = parse_bgp_routes(load_json('bgpops_routes_rpki.json'))
        assert bgp_best_path(routes, '172.16.1.0/24')['rpki'] == 'valid'
        assert bgp_best_path(routes, '172.16.3.0/24')['rpki'] == 'notfound'
        assert bgp_best_path(routes, '172.16.1.0/24')['locprf'] == 200     # match rpki valid -> local-pref 200
        assert '172.16.4.0/24' not in routes                                # match rpki invalid -> deny
        one = parse_bgp_prefix(load_json('bgpops_prefix_rpki_notfound.json'))
        assert one['paths'][0]['rpki'] == 'notfound'
        # the whole table and one prefix name the states differently
        assert parse_bgp_routes({'routes': {'p': [{'rpkiInvalid': True}]}})['p'][0]['rpki'] == 'invalid'
        assert parse_bgp_prefix({'paths': [{'rpkiValidationState': 'invalid'}]})['paths'][0]['rpki'] == 'invalid'
        assert parse_bgp_prefix({'paths': [{}]})['paths'][0]['rpki'] is None

    def test_config(self):
        cfg = parse_frr_config(load('config_bgpops_r1.txt'))
        assert cfg['rpki'] == {'present': True, 'polling_period': None, 'retry_interval': None,
                               'expire_interval': None,
                               'cache_servers': [{'mode': 'tcp', 'host': '10.0.99.2', 'port': 3323, 'preference': 1}]}
        rm = cfg['route_maps']['RPKI-IN']
        assert ('deny', ['rpki invalid']) in [(e['action'], e['match']) for e in rm]
        assert parse_frr_config("rpki\n rpki polling_period 60\n rpki cache 10.0.0.1 323 preference 2\nexit\n")[
            'rpki']['cache_servers'][0]['port'] == 323
        assert parse_frr_config("router bgp 1\n")['rpki']['present'] is False


class TestMaximumPrefix:
    def test_summary_pfxct(self):
        s = parse_bgp_summary(load_json('bgpops_summary_pfxct.json'))
        p = s['peers']['10.0.13.2']
        assert p['state'] == 'Idle (PfxCt)' and p['established'] is False and p['prefix_limit_exceeded'] is True
        assert s['peers']['10.0.14.2']['prefix_limit_exceeded'] is False and s['dampening_enabled'] is True

    def test_neighbor(self):
        n = parse_bgp_neighbor(load_json('bgpops_neighbor_pfxct.json'), peer='10.0.13.2')
        assert n['max_prefix'] == 1 and n['max_prefix_threshold'] == 75 and n['max_prefix_exceeded'] is True
        assert n['last_notification'] == 'Cease/Maximum Number of Prefixes Reached'
        assert n['max_prefix_restart'] is None and n['max_prefix_warning_only'] is False
        r = parse_bgp_neighbor(load_json('bgpops_neighbor_maxpfx_restart.json'), peer='10.0.14.2')
        assert (r['max_prefix'], r['max_prefix_threshold'], r['max_prefix_restart']) == (10, 60, 5)
        assert r['max_prefix_exceeded'] is False

    def test_config(self):
        n = parse_frr_config(load('config_bgpops_r1.txt'))['router_bgp']['neighbors']
        assert n['10.0.13.2']['maximum_prefix'] == {'limit': 1, 'threshold': None, 'warning_only': False,
                                                    'restart': None, 'force': False}
        assert n['10.0.14.2']['maximum_prefix'] == {'limit': 10, 'threshold': 60, 'warning_only': False,
                                                    'restart': 5, 'force': False}
        cfg = parse_frr_config("router bgp 1\n neighbor 10.0.0.2 remote-as 2\n address-family ipv4 unicast\n"
                               "  neighbor 10.0.0.2 maximum-prefix 4 50 warning-only\n"
                               "  neighbor 10.0.0.2 maximum-prefix-out 3\n exit-address-family\nexit\n")['router_bgp']
        assert cfg['neighbors']['10.0.0.2']['maximum_prefix']['warning_only'] is True
        assert cfg['neighbors']['10.0.0.2']['maximum_prefix_out'] == 3
        assert cfg['address_families']['ipv4 unicast']['neighbors']['10.0.0.2']['maximum_prefix']['limit'] == 4


class TestGtsmBfdGracefulShutdown:
    def test_config(self):
        rb = parse_frr_config("router bgp 1\n neighbor 10.0.0.2 remote-as 2\n neighbor 10.0.0.2 ttl-security hops 2\n"
                              " neighbor 10.0.0.2 bfd\n neighbor 10.0.0.2 bfd profile fast\n"
                              " neighbor 10.0.0.2 graceful-shutdown\n bgp graceful-shutdown\nexit\n")['router_bgp']
        n = rb['neighbors']['10.0.0.2']
        assert n['ttl_security'] == 2 and n['ebgp_multihop'] is None
        assert n['bfd'] is True and n['bfd_profile'] == 'fast' and n['graceful_shutdown'] is True
        assert rb['graceful_shutdown'] is True
        cfg = parse_frr_config(load('config_bgpops_r1.txt'))
        assert cfg['router_bgp']['neighbors']['10.0.14.2']['bfd_profile'] == 'fast'
        assert cfg['bfd']['profiles']['fast']

    def test_bfd_neighbor(self):
        n = parse_bgp_neighbor(load_json('bgpops_neighbor_bfd.json'), peer='10.0.14.2')
        assert n['bfd_status'] == 'Up'
        assert parse_bfd_peers(load_json('bgpops_bfd_peers.json'))

    def test_graceful_shutdown_community(self):
        p = parse_bgp_prefix(load_json('bgpops_prefix_gshut.json'))['paths'][0]
        assert p['communities'] == ['gracefulShutdown'] and p['locprf'] == 0


class TestConfederation:
    def test_as_path(self):
        assert confed_as_list_from_string('(65101 65102) 64500') == [65101, 65102]
        assert confed_as_list_from_string('65100 65002') == []
        assert as_list_from_string('(65102) 65002') == [65102, 65002]

    def test_paths(self):
        inside = parse_bgp_prefix(load_json('bgpops_prefix_confed.json'))['paths'][0]
        assert inside['confed_as_list'] == [65102] and inside['path_from'] == 'confed-external'
        assert inside['locprf'] == 150      # LOCAL_PREF crosses the member-AS boundary
        outside = parse_bgp_routes(load_json('bgpops_routes_external_of_confed.json'))
        assert bgp_best_path(outside, '172.16.20.0/24')['as_list'] == [65100]
        assert bgp_best_path(outside, '172.16.20.0/24')['confed_as_list'] == []
        local_as = parse_bgp_prefix(load_json('bgpops_prefix_local_as.json'))['paths'][0]
        assert local_as['communities'] == ['localAs']

    def test_neighbor_and_config(self):
        n = parse_bgp_neighbor(load_json('bgpops_neighbor_confed.json'), peer='10.0.13.2')
        assert n['link'] == 'confed-external' and n['remote_as'] == 65102 and n['local_as'] == 65101
        rb = parse_frr_config(load('config_bgpops_r1.txt'))['router_bgp']
        assert rb['as'] == 65101 and rb['confederation_identifier'] == 65100 and rb['confederation_peers'] == [65102]
        rb = parse_frr_config("router bgp 1\n bgp confederation peers 2 3\n no bgp confederation peers 2\nexit\n")[
            'router_bgp']
        assert rb['confederation_peers'] == [3]


class TestMultipathAndDampening:
    def test_multipath_flags_and_config(self):
        routes = parse_bgp_routes(load_json('bgpops_routes_damped.json'))
        assert bgp_paths(routes, '172.16.40.0/24')[0]['multipath'] is True
        rb = parse_frr_config("router bgp 1\n bgp bestpath as-path multipath-relax\n address-family ipv4 unicast\n"
                              "  maximum-paths 4\n  maximum-paths ibgp 2\n exit-address-family\nexit\n")['router_bgp']
        assert 'as-path multipath-relax' in rb['bestpath']
        assert (rb['maximum_paths'], rb['maximum_paths_ibgp']) == (4, 2)
        assert rb['address_families']['ipv4 unicast']['maximum_paths'] == 4

    def test_dampening_outputs(self):
        assert parse_bgp_dampening_parameters(load_json('bgpops_dampening_parameters.json')) == {
            'half_life': 10, 'reuse': 800, 'suppress': 2500, 'max_suppress': 40, 'max_penalty': 12800}
        assert parse_bgp_dampening_parameters({}) == {}
        damped = parse_bgp_dampening_paths(load_json('bgpops_dampened_paths.json'))
        assert damped['172.16.40.0/24'][0]['damped'] is True and damped['172.16.40.0/24'][0]['peer'] == '10.0.14.2'
        flaps = parse_bgp_dampening_paths(load_json('bgpops_flap_statistics.json'))
        assert flaps['172.16.40.0/24'][0]['flaps'] >= 4
        p = parse_bgp_prefix(load_json('bgpops_prefix_damped.json'))['paths'][0]
        assert p['damped'] is True and p['dampening_penalty'] > 2500
        assert bgp_paths(parse_bgp_routes(load_json('bgpops_routes_damped.json')), '172.16.40.0/24')[0]['damped']

    def test_dampening_calls(self):
        for fn, cmd in ((get_bgp_dampening_parameters, 'parameters'), (get_bgp_dampened_paths, 'dampened-paths'),
                        (get_bgp_flap_statistics, 'flap-statistics')):
            grade = make_grade('{}')
            fn(grade, 'r1')
            grade.test.assert_called_once_with('r1', f'vtysh -c "show bgp ipv4 unicast dampening {cmd} json"',
                                               step=1, allow_error=True)

    def test_dampening_config(self):
        rb = parse_frr_config(load('config_bgpops_r1.txt'))['router_bgp']
        assert rb['dampening'] == (10, 800, 2500, 40)
        assert rb['address_families']['ipv4 unicast']['dampening'] == (10, 800, 2500, 40)
        bare = parse_frr_config("router bgp 1\n address-family ipv4 unicast\n  bgp dampening\n"
                                " exit-address-family\nexit\n")['router_bgp']
        assert bare['dampening'] == BGP_DAMPENING_DEFAULTS == (15, 750, 2000, 60)
        assert parse_frr_config("router bgp 1\n")['router_bgp']['dampening'] is None


def test_kernel_route_type():
    routes = parse_kernel_routes(json.dumps([
        {"type": "blackhole", "dst": "192.0.2.1", "protocol": "static", "metric": 20, "flags": []},
        {"dst": "172.16.9.9", "gateway": "192.0.2.66", "dev": "discard0", "protocol": "bgp", "metric": 20}]))
    assert routes['192.0.2.1/32']['type'] == 'blackhole' and routes['192.0.2.1/32']['nexthops'] == [(None, None)]
    assert routes['172.16.9.9/32']['type'] == 'unicast'
    assert routes['172.16.9.9/32']['nexthops'] == [('192.0.2.66', 'discard0')]


# ---------------------------------------------------------------------------
# show ip ospf database external json (the anycast lab; captured on FRR 10.3, s15, 2026-11-23:
# two instances announcing the service address as type 2 externals, metrics 40 and 380)
# ---------------------------------------------------------------------------

from frr import get_ospf_external_lsas, get_ospf_nssa_lsas, parse_ospf_external_lsas  # noqa: E402


class TestOspfExternalLsas:
    def test_anycast_capture(self):
        lsas = parse_ospf_external_lsas(json.loads(load('ospf_external_anycast_prim.json')))
        assert set(lsas) == {('172.30.89.53/32', '10.30.33.2'), ('172.30.89.53/32', '10.30.34.2')}
        primary = lsas[('172.30.89.53/32', '10.30.33.2')]
        assert (primary['prefix'], primary['adv_router']) == ('172.30.89.53/32', '10.30.33.2')
        assert (primary['metric_type'], primary['metric'], primary['forward'], primary['tag']) == (2, 40, '0.0.0.0', 0)
        assert lsas[('172.30.89.53/32', '10.30.34.2')]['metric'] == 380

    def test_type_1_and_mask_forms(self):
        def one(mask, mtype):
            data = {'asExternalLinkStates': [{'linkStateId': '10.1.0.0', 'advertisingRouter': '1.1.1.1',
                                              'networkMask': mask, 'metricType': mtype, 'metric': 5}]}
            (entry,) = parse_ospf_external_lsas(data).values()
            return entry['prefix'], entry['metric_type']
        assert one('255.255.0.0', 'E1') == ('10.1.0.0/16', 1)
        assert one('/16', 'E2 (Larger than any link state path)') == ('10.1.0.0/16', 2)
        assert one(16, 'E1') == ('10.1.0.0/16', 1)

    def test_nothing(self):
        assert parse_ospf_external_lsas({}) == {}
        assert parse_ospf_external_lsas(None) == {}
        assert parse_ospf_external_lsas({'routerId': '10.0.0.1', 'asExternalLinkStates': []}) == {}

    def test_wrapper(self):
        grade = MagicMock()
        grade.test.return_value = (load('ospf_external_anycast_prim.json'), 0)
        lsas = get_ospf_external_lsas(grade, 'r2')
        grade.test.assert_called_once_with('r2', 'vtysh -c "show ip ospf database external json"', step=1,
                                           allow_error=True)
        assert len(lsas) == 2
        grade.test.return_value = ('', 0)
        assert get_ospf_external_lsas(grade, 'r2') == {}


class TestOspfNssaLsas:
    """``show ip ospf database nssa-external json`` captured in the redistribution lab (FRR 10.3, the
    nssa site solved): the ABR holds the two type 7 LSAs of the ASBR, the backbone router none."""

    def test_abr_capture(self):
        lsas = parse_ospf_external_lsas(json.loads(load('ospf_nssa_external_redist_abr.json')))
        assert set(lsas) == {('10.213.113.0/24', '10.213.255.22'), ('10.213.114.0/24', '10.213.255.22')}
        entry = lsas[('10.213.113.0/24', '10.213.255.22')]
        assert (entry['metric_type'], entry['metric'], entry['forward'], entry['tag']) == (2, 20, '10.213.112.6', 0)

    def test_backbone_router_has_none(self):
        assert parse_ospf_external_lsas(json.loads(load('ospf_nssa_external_redist_core.json'))) == {}

    def test_wrapper(self):
        grade = MagicMock()
        grade.test.return_value = (load('ospf_nssa_external_redist_abr.json'), 0)
        lsas = get_ospf_nssa_lsas(grade, 'nssa_abr')
        grade.test.assert_called_once_with('nssa_abr', 'vtysh -c "show ip ospf database nssa-external json"',
                                           step=1, allow_error=True)
        assert len(lsas) == 2
        grade.test.return_value = ('', 0)
        assert get_ospf_nssa_lsas(grade, 'nssa_abr') == {}


class TestBgpPrefixNoExport:
    def test_community_of_a_local_node(self):
        """`show bgp ipv4 unicast PREFIX json` of the operator that receives a route marked no-export
        (the anycast lab, FRR 10.3): the community list holds ``noExport``."""
        result = parse_bgp_prefix(json.loads(load('bgp_prefix_anycast_noexport.json')))
        assert result['prefix'] == '198.18.123.0/24'
        local = [p for p in result['paths'] if p['as_list'] == [64736]]
        assert len(local) == 1 and local[0]['communities'] == ['noExport'] and local[0]['best']
        assert sorted(p['as_list'] for p in result['paths'] if p['communities'] == []) == [[65010, 64736],
                                                                                          [65020, 65010, 64736]]
