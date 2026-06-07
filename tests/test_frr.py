"""Tests for lib/frr.py — get_ospf_interfaces."""
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
