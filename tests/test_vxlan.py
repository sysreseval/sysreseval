"""Tests for lib/vxlan.py: the kernel side of VXLAN (fixtures in tests/mock_data/vxlan, captured on Debian 13 /
iproute2 7.3.0 / Linux 6.12 in a probe lab and in the solved VXLAN / EVPN labs)."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from vxlan import (  # noqa: E402
    BRIDGE_PORTS_CMD, FDB_ALL_CMD, FLOOD_MAC, FLUSH_PMTU_CMD, FRAG_CREATES_CMD, VXLAN_OVERHEAD, VXLAN_PORT,
    bridge_cmds, bridge_port_flags, df_ping_cmd, flood_cmds, flood_list, frag_delta, get_bridge_port_flags,
    get_fdb_all, get_frag_creates, get_vxlan_fdb, l3vni_cmds, link_mtu, parse_fdb_json, parse_frag_creates,
    remote_macs, vxlan_cmds, vxlan_devices, vxlan_fdb_cmd, vxlan_of_vni, vrf_cmds,
)

FIXTURES = Path(__file__).parent / 'mock_data' / 'vxlan'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def load_json(name: str):
    return json.loads(load(name))


def make_grade(output: str, code: int = 0):
    grade = MagicMock()
    grade.test.return_value = (output, code)
    return grade


class TestDevices:
    def test_evpn_leaf(self):
        devices = vxlan_devices(load_json('links_evpn_leaf.json'))
        assert set(devices) == {'vxlan100', 'vxlan200'}
        d = devices['vxlan100']
        assert (d['vni'], d['local'], d['port'], d['learning'], d['master'], d['mtu']) == \
            (100, '10.255.0.11', VXLAN_PORT, False, 'br100', 1500)
        assert d['group'] is None and d['dev'] is None and d['ttl'] == 0 and d['up'] and not d['neigh_suppress']
        assert vxlan_of_vni(devices, 200) == 'vxlan200' and vxlan_of_vni(devices, 300) is None

    def test_irb_leaf_arp_suppression_and_l3vni(self):
        devices = vxlan_devices(load_json('links_irb_leaf.json'))
        assert devices['vxlan100']['neigh_suppress'] and devices['vxlan200']['neigh_suppress']
        assert devices['vxlan4000']['master'] == 'br4000' and not devices['vxlan4000']['neigh_suppress']
        links = load_json('links_irb_leaf.json')
        # the SVIs are in the VRF, with the anycast gateway MAC
        from bridging import link_address, link_master
        assert link_master(links, 'br100') == 'TENANT' and link_master(links, 'br4000') == 'TENANT'
        assert link_address(links, 'br100') == '00:00:5e:00:01:01'

    def test_multicast_group(self):
        d = vxlan_devices(load_json('links_mcast_vtep.json'))['vxlan500']
        # dev eth0: the MTU is that of eth0 minus 50; no local: the address of eth0
        assert (d['group'], d['dev'], d['ttl'], d['mtu'], d['local']) == ('239.1.1.5', 'eth0', 5, 1450, '10.0.1.2')
        assert d['learning']

    def test_student_device_of_the_static_part(self):
        devices = vxlan_devices(load_json('lab1_links_st_vtep1.json'))
        assert list(devices) == ['vxlan8505'] and devices['vxlan8505']['learning']
        assert link_mtu(load_json('lab1_links_st_vtep1.json'), 'eth0') == 1600
        assert link_mtu(load_json('lab1_links_st_vtep1.json'), 'eth9') is None

    def test_no_device(self):
        assert vxlan_devices([]) == {} and vxlan_devices([{'ifname': 'eth0', 'linkinfo': {}}, 'junk']) == {}


class TestFdb:
    def test_static_head_end_replication_and_learning(self):
        entries = parse_fdb_json(load('fdb_static_vtep.json'))
        assert flood_list(entries, 'vxlan100') == ['10.255.0.12', '10.255.0.13']
        # learned from the traffic: a bridge entry and a self entry with the remote VTEP
        assert remote_macs(entries, 'vxlan100') == {'1a:31:13:00:3e:68': '10.255.0.13',
                                                    'fe:91:fb:2e:62:6a': '10.255.0.12'}
        assert remote_macs(entries, 'vxlan100', extern_only=True) == {}
        assert entries[0]['dst'] is None and entries[4]['dst'] == '10.255.0.12'

    def test_installed_by_evpn(self):
        entries = parse_fdb_json(load('fdb_evpn_leaf.json'))
        assert flood_list(entries, 'vxlan100') == ['10.255.0.12', '10.255.0.13']
        assert remote_macs(entries, 'vxlan100', extern_only=True) == {'1a:31:13:00:3e:68': '10.255.0.13',
                                                                      'fe:91:fb:2e:62:6a': '10.255.0.12'}
        # with ifname (bridge fdb show br X): another device has nothing
        assert flood_list(entries, 'vxlan200') == [] and remote_macs(entries, 'vxlan200') == {}

    def test_multicast_flood_entry(self):
        entries = parse_fdb_json(load('fdb_mcast_vtep.json'))
        assert flood_list(entries, 'vxlan500') == ['239.1.1.5']
        assert remote_macs(entries, 'vxlan500') == {'9a:99:54:2a:78:f0': '10.0.2.2', '52:ff:9e:e3:7e:ff': '10.0.3.2'}

    def test_whole_table_of_a_student_vtep(self):
        entries = parse_fdb_json(load('lab1_fdb_all_st_vtep1.json'))
        assert flood_list(entries, 'vxlan8505') == ['10.7.31.12', '10.7.31.13']
        assert set(remote_macs(entries, 'vxlan8505').values()) == {'10.7.31.12', '10.7.31.13'}

    def test_l3vni_router_macs(self):
        entries = parse_fdb_json(load('fdb_l3vni_leaf.json'))
        assert flood_list(entries, 'vxlan4000') == []
        assert remote_macs(entries, 'vxlan4000', extern_only=True) == {'fa:97:32:8e:06:48': '10.255.0.12',
                                                                       'c2:3b:56:81:89:a8': '10.255.0.20'}

    def test_wrappers(self):
        grade = make_grade(load('fdb_static_vtep.json'))
        assert flood_list(get_vxlan_fdb(grade, 'st_vtep1', 'vxlan100'), 'vxlan100') == ['10.255.0.12', '10.255.0.13']
        assert grade.test.call_args[0][1] == vxlan_fdb_cmd('vxlan100') == 'bridge -j fdb show dev vxlan100'
        grade = make_grade(load('lab1_fdb_all_st_vtep1.json'))
        assert len(get_fdb_all(grade, 'st_vtep1', step=2)) > 5
        assert grade.test.call_args[0][1] == FDB_ALL_CMD and grade.test.call_args[1]['step'] == 2
        assert get_fdb_all(make_grade('', 1), 'x') == [] and get_vxlan_fdb(make_grade('', -1), 'x', 'v') == []


class TestBridgePorts:
    def test_neigh_suppress(self):
        ports = bridge_port_flags(load('bridge_link_irb_leaf.json'))
        assert ports['vxlan100']['neigh_suppress'] and not ports['eth1']['neigh_suppress']
        assert ports['eth1']['master'] == 'br100' and ports['vxlan100']['state'] == 'forwarding'
        assert bridge_port_flags('') == {} and bridge_port_flags('garbage') == {}

    def test_wrapper(self):
        grade = make_grade(load('lab1_bridge_link_irb_leaf2.json'))
        ports = get_bridge_port_flags(grade, 'irb_leaf2')
        assert grade.test.call_args[0][1] == BRIDGE_PORTS_CMD
        # the two layer-2 VNIs of irb_leaf2 suppress ARP, its L3VNI does not
        suppress = sorted(p['neigh_suppress'] for name, p in ports.items() if name.startswith('vxlan'))
        assert suppress == [False, True, True]


class TestMtuProbes:
    def test_frag_creates(self):
        assert parse_frag_creates(load('lab1_nstat_st_r.txt')) == 0
        assert parse_frag_creates("#kernel\nIpFragCreates                   12                 0.0\n") == 12
        assert parse_frag_creates('') is None
        grade = make_grade(load('lab2_nstat_st_pe1.txt'))
        assert get_frag_creates(grade, 'st_pe1', step=3) == 0
        assert grade.test.call_args[0][1] == FRAG_CREATES_CMD == 'nstat -az IpFragCreates'
        assert frag_delta(0, 12) == 12 and frag_delta(None, 3) is None and frag_delta(3, None) is None

    def test_df_ping_flushes_the_pmtu_cache_first(self):
        cmd = df_ping_cmd('192.168.1.12')
        assert cmd.startswith(FLUSH_PMTU_CMD) and 'mount -o rw,remount /proc/sys' in cmd
        assert cmd.endswith('-M do -s 1472 192.168.1.12') and 'ip route flush cache' in cmd
        assert VXLAN_OVERHEAD == 50


class TestStateCommands:
    def test_vxlan_cmds(self):
        assert vxlan_cmds('vxlan100', 100, local='10.0.0.1') == [
            'ip link add vxlan100 type vxlan id 100 local 10.0.0.1 dstport 4789', 'ip link set vxlan100 up']
        assert vxlan_cmds('v', 5, local='1.1.1.1', learning=False, mtu=1500)[0].endswith('nolearning')
        assert vxlan_cmds('v', 5, group='239.1.1.5', dev='eth0', ttl=5)[0] == \
            'ip link add v type vxlan id 5 group 239.1.1.5 dev eth0 ttl 5 dstport 4789'

    def test_bridge_flood_l3vni(self):
        cmds = bridge_cmds('br100', ['eth1', 'vxlan100'], address='192.168.1.1/24', mac='02:00:5e:00:00:01', vrf='T',
                           neigh_suppress=['vxlan100'])
        assert cmds[0] == 'ip link add br100 type bridge' and cmds[-1] == 'ip link set br100 up'
        assert 'ip link set br100 address 02:00:5e:00:00:01' in cmds and 'ip link set br100 master T' in cmds
        assert 'ip link set vxlan100 type bridge_slave neigh_suppress on' in cmds
        assert flood_cmds('v', ['10.0.0.2']) == [f'bridge fdb append {FLOOD_MAC} dev v dst 10.0.0.2']
        assert vrf_cmds('T', 100) == ['ip link add T type vrf table 100', 'ip link set T up']
        l3 = l3vni_cmds('T', 100, 4000, '10.0.0.1')
        assert l3[:2] == vrf_cmds('T', 100) and 'ip link set br4000 master T' in l3
        assert 'ip link add vxlan4000 type vxlan id 4000 local 10.0.0.1 dstport 4789 nolearning' in l3
        assert not any('type vrf' in c for c in l3vni_cmds('T', 100, 4000, '10.0.0.1', create_vrf=False))
