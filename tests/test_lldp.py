"""Tests for lib/lldp.py.

Fixtures of tests/mock_data/lldp/: ``lldpcli -f json0 show neighbors details`` captured on 2026-11-21
on s17 (lldpd 1.0.18, Debian 13 images, Kathara VDE links) in a probe lab: no neighbour, one
neighbour with a local port ID, a description and a management address, a switch seeing a bond
slave (link aggregation TLV) and two hosts, and a host behind a port carrying a VLAN.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from lldp import LLDP_NEIGHBORS_CMD, get_lldp_neighbors, lldp_neighbor, parse_lldp_neighbors  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'lldp'


def neighbors(name: str):
    return parse_lldp_neighbors((MOCK / f'lldp_json0_{name}.json').read_text())


def test_no_neighbor():
    assert neighbors('none') == []


def test_one_neighbor():
    [n] = neighbors('one')
    assert n['interface'] == 'eth0' and n['via'] == 'LLDP'
    assert (n['chassis_id_type'], n['chassis_id']) == ('mac', '3e:db:c1:51:e2:de')
    assert n['chassis_name'] == 'dc2-core-a' and n['descr'] == 'Core switch rack B7'
    assert n['mgmt_ips'] == ['192.0.2.2']
    assert n['capabilities'] == {'Bridge': True, 'Router': True, 'Wlan': False, 'Station': False}
    assert (n['port_id_type'], n['port_id'], n['port_descr']) == ('local', 'Gi1/0/17', 'to server c')
    assert n['ttl'] == 120 and n['aggregation'] is None and n['vlans'] == []


def test_switch_sees_a_bond_slave():
    found = neighbors('switch')
    assert [n['interface'] for n in found] == ['eth0', 'eth2', 'eth3']
    slave = lldp_neighbor(found, interface='eth0')
    assert slave['chassis_name'] == 'a' and slave['descr'] == 'web server rack B7'
    assert slave['aggregation'] == 4                       # ifindex of the bond of 'a'
    assert slave['port_id_type'] == 'mac' and slave['port_descr'] == 'eth0'
    assert slave['mgmt_ips'] == ['10.77.0.1']
    assert lldp_neighbor(found, interface='eth2')['aggregation'] is None


def test_vlan_tlv():
    [n] = neighbors('vlan')
    assert n['vlans'] == [{'id': 42, 'pvid': False, 'name': 'vlan42'}]
    assert n['port_descr'] == 'eth3'


def test_lldp_neighbor_lookup():
    found = neighbors('switch')
    assert lldp_neighbor(found, name='c')['interface'] == 'eth2'
    assert lldp_neighbor(found, interface='eth3', name='v')['chassis_name'] == 'v'
    assert lldp_neighbor(found, interface='eth3', name='c') is None
    assert lldp_neighbor(found, name='zz') is None
    fqdn = [dict(found[0], chassis_name='a.example.org')]
    assert lldp_neighbor(fqdn, name='a') is fqdn[0]
    assert lldp_neighbor([dict(found[0], chassis_name='ab')], name='a') is None


def test_unreadable_and_reader():
    assert parse_lldp_neighbors('') == [] and parse_lldp_neighbors('not json') == []
    assert parse_lldp_neighbors('[]') == [] and parse_lldp_neighbors('{"lldp": [{}]}') == []
    grade = MagicMock()
    text = (MOCK / 'lldp_json0_one.json').read_text()
    grade.test.side_effect = lambda m, command, step=1, **kw: (text, 0) if command == LLDP_NEIGHBORS_CMD else ('', 1)
    assert get_lldp_neighbors(grade, 'm')[0]['chassis_name'] == 'dc2-core-a'
    grade.test.side_effect = lambda m, command, step=1, **kw: ('unable to connect to socket', 1)
    assert get_lldp_neighbors(grade, 'm') == []
