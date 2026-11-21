"""Tests for lib/bonding.py.

Fixtures of tests/mock_data/bonding/, captured on 2026-11-21 on s17 (Debian 13 images, Linux 6.12,
Kathara VDE links) in a probe lab: an 802.3ad server and the bond of a Linux switch (aggregated, then
one member set down at the server end only), a balance-xor server facing an 802.3ad switch (no
partner), an 802.3ad bond whose ``min_links`` is not reached (no carrier), the bond between two
switches (a port of an STP bridge) and an active-backup bond with ARP monitoring.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from bonding import (  # noqa: E402
    bond_info, bond_slaves, get_bond_info, get_proc_bonding, get_tx_packets, hping_flows_cmd, lacp_aggregated,
    lacp_partner_is, packets_delta, parse_proc_bonding, parse_tx_packets, tx_packets_cmd,
)
from bridging import parse_ip_links_json  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'bonding'
SRV_MAC = "7a:50:db:c9:36:0f"      # bond0 of the server = its first slave, eth1
SW_MAC = "3e:db:c1:51:e2:de"       # bond1 of the switch


def links(name: str):
    return parse_ip_links_json((MOCK / name).read_text())


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    grade = MagicMock()
    grade.test.side_effect = lambda machine_name, command, step=1, **kwargs: responses.get(command, ('', 1))
    return grade


class TestBondInfo:
    def test_lacp_server(self):
        info = bond_info(links('ip_link_lacp_srv.json'), 'bond0')
        assert info['mode'] == '802.3ad'
        assert info['address'] == SRV_MAC
        assert info['up'] and info['carrier']
        assert (info['miimon'], info['lacp_rate'], info['xmit_hash_policy']) == (100, 'fast', 'layer3+4')
        assert info['lacp_active'] is True and info['min_links'] == 0
        assert (info['aggregator'], info['num_ports'], info['actor_key'], info['partner_key']) == (1, 2, 15, 15)
        assert info['partner_mac'] == SW_MAC
        assert info['actor_sys_prio'] == 65535
        assert bond_slaves(info) == ['eth0', 'eth1']
        eth0 = info['slaves']['eth0']
        assert eth0['state'] == 'ACTIVE' and eth0['mii_status'] == 'UP' and eth0['up']
        assert eth0['aggregator_id'] == 1 and eth0['actor_state'] == 63 and eth0['partner_state'] == 63
        assert eth0['actor_state_str'] == ['active', 'short_timeout', 'aggregating', 'in_sync', 'collecting',
                                           'distributing']
        assert eth0['perm_hwaddr'] == "f2:0f:b0:1b:92:a1"

    def test_lacp_aggregated_both_ends(self):
        srv = bond_info(links('ip_link_lacp_srv.json'), 'bond0')
        sw = bond_info(links('ip_link_lacp_sw.json'), 'bond1')
        assert lacp_aggregated(srv) == ['eth0', 'eth1'] and lacp_aggregated(sw) == ['eth0', 'eth1']
        assert lacp_partner_is(srv, [sw['address']]) and lacp_partner_is(sw, [srv['address'].upper()])
        assert not lacp_partner_is(srv, [srv['address']])

    def test_one_member_down_at_the_far_end(self):
        """eth1 set down on the server only: the switch keeps its carrier, LACP takes it out."""
        sw = bond_info(links('ip_link_lacp_sw_one_down.json'), 'bond1')
        assert sw['slaves']['eth1']['up'] and sw['slaves']['eth1']['mii_status'] == 'UP'
        assert sw['num_ports'] == 1 and sw['slaves']['eth1']['aggregator_id'] == 2
        assert lacp_aggregated(sw) == ['eth0']

    def test_static_bond_has_no_aggregator(self):
        info = bond_info(links('ip_link_fix_srv_balance_xor.json'), 'bond0')
        assert info['mode'] == 'balance-xor' and info['partner_mac'] == '' and info['aggregator'] is None
        assert bond_slaves(info) == ['eth0', 'eth1'] and lacp_aggregated(info) == []
        assert not lacp_partner_is(info, [SW_MAC])

    def test_min_links_not_reached(self):
        info = bond_info(links('ip_link_fix_sw_min_links.json'), 'bond1')
        assert info['min_links'] == 3 and info['up'] and not info['carrier']
        # LACP still aggregates both ports: lacp_aggregated() does not look at the carrier
        assert lacp_aggregated(info) == ['eth0', 'eth1']

    def test_bond_between_switches_is_a_bridge_port(self):
        all_links = links('ip_link_isl_sw1.json')
        info = bond_info(all_links, 'bond0')
        assert bond_slaves(info) == ['eth1', 'eth2'] and lacp_aggregated(info) == ['eth1', 'eth2']
        assert info['partner_mac'] == "a2:22:04:51:81:f1"
        bond_link = [link for link in all_links if link['ifname'] == 'bond0'][0]
        assert bond_link['master'] == 'br0'

    def test_active_backup_with_arp_monitoring(self):
        info = bond_info(links('ip_link_ab_srv_arp.json'), 'bond0')
        assert info['mode'] == 'active-backup'
        assert (info['primary'], info['active_slave']) == ('eth0', 'eth0')
        assert info['miimon'] == 0 and info['arp_interval'] == 1000 and info['arp_ip_target'] == ['10.78.0.1']
        assert info['slaves']['eth0']['state'] == 'ACTIVE' and info['slaves']['eth1']['state'] == 'BACKUP'
        assert lacp_aggregated(info) == []

    def test_missing_or_not_a_bond(self):
        all_links = links('ip_link_lacp_srv.json')
        assert bond_info(all_links, 'bond7') is None
        assert bond_info(all_links, 'eth0') is None
        assert bond_info([], 'bond0') is None
        assert bond_slaves(None) == [] and lacp_aggregated(None) == [] and not lacp_partner_is(None, [SW_MAC])

    def test_get_bond_info(self):
        from pmtu import ip_link_json_cmd
        grade = make_grade({ip_link_json_cmd(): (fixture('ip_link_lacp_srv.json'), 0)})
        assert get_bond_info(grade, 'lacp_srv')['partner_mac'] == SW_MAC
        assert get_bond_info(make_grade({}), 'lacp_srv') is None


class TestProcBonding:
    def test_lacp_server(self):
        p = parse_proc_bonding(fixture('proc_bonding_lacp_srv.txt'))
        assert p['mode'] == 'IEEE 802.3ad Dynamic link aggregation'
        assert (p['xmit_hash_policy'], p['lacp_rate'], p['miimon'], p['min_links']) == ('layer3+4', 'fast', 100, 0)
        assert p['system_priority'] == 65535 and p['system_mac'] == SRV_MAC
        assert p['aggregator'] == {'id': 1, 'num_ports': 2, 'actor_key': 15, 'partner_key': 15, 'partner_mac': SW_MAC}
        eth0 = p['slaves']['eth0']
        assert eth0['aggregator_id'] == 1 and eth0['speed'] == '10000 Mbps' and eth0['duplex'] == 'full'
        assert eth0['actor'] == {'system_priority': 65535, 'system_mac': SRV_MAC, 'key': 15, 'port_priority': 255,
                                 'port_number': 2, 'port_state': 63}
        assert eth0['partner']['system_mac'] == SW_MAC and eth0['partner']['port_number'] == 1

    def test_switch_facing_a_static_server(self):
        """balance-xor on the server: no LACPDU, no partner, each port alone in an aggregator."""
        p = parse_proc_bonding(fixture('proc_bonding_fix_sw_static_peer.txt'))
        assert p['aggregator']['num_ports'] == 1 and p['aggregator']['partner_mac'] == ''
        assert {s['aggregator_id'] for s in p['slaves'].values()} == {1, 2}
        assert all(s['partner']['system_mac'] == '' and s['partner']['port_state'] == 0 for s in p['slaves'].values())

    def test_active_backup(self):
        p = parse_proc_bonding(fixture('proc_bonding_ab_srv_arp.txt'))
        assert p['mode'] == 'fault-tolerance (active-backup)'
        assert (p['primary'], p['active_slave'], p['miimon'], p['arp_interval']) == ('eth0', 'eth0', 0, 1000)
        assert p['arp_ip_target'] == ['10.78.0.1'] and 'aggregator' not in p
        assert p['slaves']['eth0']['link_failure_count'] == 4

    def test_one_member_down(self):
        p = parse_proc_bonding(fixture('proc_bonding_lacp_sw_one_down.txt'))
        assert p['aggregator']['num_ports'] == 1
        assert p['slaves']['eth1']['aggregator_id'] != p['aggregator']['id']

    def test_empty_and_reader(self):
        assert parse_proc_bonding('') == {}
        grade = make_grade({"cat /proc/net/bonding/bond0": (fixture('proc_bonding_lacp_srv.txt'), 0)})
        assert get_proc_bonding(grade, 'm')['aggregator']['num_ports'] == 2
        assert get_proc_bonding(make_grade({}), 'm') == {}


class TestCounters:
    def test_tx_packets(self):
        cmd = tx_packets_cmd(['eth0', 'eth1', 'eth9'])
        assert 'eth0 eth1 eth9' in cmd and 'tx_packets' in cmd
        assert parse_tx_packets("eth0 120\neth1 98\neth9 -\n") == {'eth0': 120, 'eth1': 98, 'eth9': None}
        grade = make_grade({cmd: ("eth0 120\neth1 98\neth9 -\n", 0)})
        before = get_tx_packets(grade, 'm', ['eth0', 'eth1', 'eth9'])
        after = {'eth0': 153, 'eth1': 98, 'eth9': None}
        assert packets_delta(before, after) == {'eth0': 33, 'eth1': 0, 'eth9': None}
        assert get_tx_packets(make_grade({}), 'm', ['eth0']) == {'eth0': None}

    def test_hping_flows_cmd(self):
        assert hping_flows_cmd("10.0.0.20") == ("hping3 --udp -s 33000 -k -p ++20000 -c 64 -i u2000 10.0.0.20 "
                                                ">/dev/null 2>&1; true")


def test_lacpdu_capture_matches_the_bond_values():
    """The LACPDU decoded by tcpdump carries what /proc/net/bonding shows (course figures)."""
    text = fixture('tcpdump_lacpdu.txt')
    assert '01:80:c2:00:00:02' in text and 'Slow Protocols (0x8809)' in text
    assert 'System Priority 65535, Key 15' in text and 'Port Priority 255' in text
    assert 'State Flags [Activity, Timeout, Aggregation, Synchronization, Collecting, Distributing]' in text
