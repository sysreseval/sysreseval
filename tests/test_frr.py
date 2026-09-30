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
                                       'nexthops': [('172.22.40.54', 'eth1')]}
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
