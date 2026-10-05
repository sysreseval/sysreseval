"""Tests for lib/switch.py — grading helpers of the managed switches.

Fixtures in tests/mock_data/switch are the port and VLAN tables of a VDE switch 2.3.3 behind
the Kathara network plugin (samples of the test suite of the Kathara fork, switch-mode feature).
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

import switch  # noqa: E402

FIXTURES = Path(__file__).parent / 'mock_data' / 'switch'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


PORTS = load('port_allprint.txt')
VLANS = load('vlan_allprint.txt')


class FakeGrade:
    """Grade stand-in: test_switch() answers from canned (output, code) results."""

    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    def test_switch(self, network, command, step=1, allow_error=False):
        self.calls.append((network, command, step, allow_error))
        return self.results.get(command, ('', 0))


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------

def test_parse_vlans():
    assert switch.parse_switch_vlans(VLANS) == {
        0: {'untagged': [1, 5], 'tagged': []},
        10: {'untagged': [2], 'tagged': [1]},
        20: {'untagged': [3], 'tagged': [1]},
    }


def test_parse_vlans_empty():
    assert switch.parse_switch_vlans('') == {}
    assert switch.parse_switch_vlans(None) == {}


def test_parse_ports():
    ports = switch.parse_switch_ports(PORTS, VLANS)
    assert sorted(ports) == [1, 2, 3, 5]
    assert ports[1] == {'vlan': 0, 'tagged_vlans': [10, 20], 'active': True,
                        'endpoints': ['kathara r1:eth0'], 'machine': 'r1', 'interface': 'eth0'}
    assert ports[2]['vlan'] == 10 and ports[2]['machine'] == 'pc2' and ports[2]['tagged_vlans'] == []


def test_parse_ports_inactive_port_has_no_machine():
    port = switch.parse_switch_ports(PORTS, VLANS)[3]
    assert port == {'vlan': 20, 'tagged_vlans': [], 'active': False, 'endpoints': [],
                    'machine': None, 'interface': None}


def test_parse_ports_unlabelled_and_external_endpoints():
    port = switch.parse_switch_ports(PORTS, VLANS)[5]
    assert port['endpoints'] == ['kathara', 'vde_ext: eth1']
    assert port['machine'] is None


def test_parse_ports_without_vlan_table():
    ports = switch.parse_switch_ports(PORTS)
    assert ports[1]['tagged_vlans'] == []
    assert ports[2]['vlan'] == 10


def test_parse_ports_empty():
    assert switch.parse_switch_ports('') == {}
    assert switch.parse_switch_ports(None, None) == {}


def test_ports_by_machine():
    assert switch.ports_by_machine(switch.parse_switch_ports(PORTS, VLANS)) == {
        'r1': {'port': 1, 'interface': 'eth0', 'vlan': 0, 'tagged_vlans': [10, 20]},
        'pc2': {'port': 2, 'interface': 'eth0', 'vlan': 10, 'tagged_vlans': []},
    }


# ---------------------------------------------------------------------------
# grade helpers
# ---------------------------------------------------------------------------

def test_get_switch_ports():
    grade = FakeGrade({'port/allprint': (PORTS, 0), 'vlan/allprint': (VLANS, 0)})
    ports = switch.get_switch_ports(grade, 'lan', step=2, allow_error=True)
    assert ports['pc2'] == {'port': 2, 'interface': 'eth0', 'vlan': 10, 'tagged_vlans': []}
    assert ports['r1']['tagged_vlans'] == [10, 20]
    assert grade.calls == [('lan', 'port/allprint', 2, True), ('lan', 'vlan/allprint', 2, True)]


def test_get_switch_ports_registers_both_tests_on_the_first_pass():
    grade = FakeGrade()  # placeholders ('', 0): nothing has run yet
    assert switch.get_switch_ports(grade, 'lan') == {}
    assert [c[1] for c in grade.calls] == ['port/allprint', 'vlan/allprint']


def test_get_switch_ports_console_failure():
    grade = FakeGrade({'port/allprint': ('unreachable', -2), 'vlan/allprint': ('unreachable', -2)})
    assert switch.get_switch_ports(grade, 'lan') == {}
    assert len(grade.calls) == 2


def test_get_switch_ports_without_vlan_table():
    grade = FakeGrade({'port/allprint': (PORTS, 0), 'vlan/allprint': ('unreachable', -2)})
    assert switch.get_switch_ports(grade, 'lan')['r1'] == {'port': 1, 'interface': 'eth0', 'vlan': 0,
                                                           'tagged_vlans': []}


def test_get_switch_vlans():
    grade = FakeGrade({'vlan/allprint': (VLANS, 0)})
    assert switch.get_switch_vlans(grade, 'lan')[10] == {'untagged': [2], 'tagged': [1]}
    assert switch.get_switch_vlans(FakeGrade({'vlan/allprint': ('x', 22)}), 'lan') == {}
