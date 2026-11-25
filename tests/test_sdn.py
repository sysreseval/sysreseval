"""Tests of lib/sdn.py (Open vSwitch / OpenFlow helpers of the SDN lab).

The fixtures of tests/mock_data/sdn/ are outputs captured on s17 (2026-11-24, Open vSwitch 3.5.0, OS-Ken
3.0.1, iperf3 3.18), extracted from the real evaluations of tests/mock_data/sdn/lab/ (``ovs_state_*``,
``flows_*``, ``meters_*``, ``trace_*``, ``iperf_udp_final.json``) or run by hand (``ofctl_show_sw2.txt``).
Those of tests/mock_data/sdn/ovs/ come from the evaluations of the Open vSwitch lab
(tests/mock_data/openvswitch/lab/, s17, 2026-11-25, image netdev13:1.36), but ``*_tor2_no_partner.txt``, run
by hand on its switch tor2 before the other end had its bond.
"""
import json
import shlex
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import sdn  # noqa: E402
from tc import parse_iperf3  # noqa: E402

_MOCK = _REPO / 'tests' / 'mock_data' / 'sdn'


def _fixture(name: str) -> str:
    return (_MOCK / name).read_text()


class TestStateSide:
    def test_ovs_start(self):
        cmd = sdn.ovs_start_cmd()
        # the module autoload first, then ovs-ctl, then a wait that fails if ovs-vsctl never answers
        assert cmd.index('ovs-dpctl show') < cmd.index('ovs-ctl --system-id=random start')
        assert cmd.rstrip().endswith('ovs-vsctl --timeout=2 show >/dev/null')
        assert '@@@' not in cmd

    def test_bridge_cmd_secure_before_ports(self):
        cmd = sdn.ovs_bridge_cmd('br0', [('eth1', 17), ('eth0', None)], fail_mode='secure', dpid=0xa1,
                                 controller='tcp:192.0.2.1:6653', tags={'eth1': 120})
        words = cmd.split(' -- ')
        assert words[0] == 'ovs-vsctl --timeout=5 --may-exist add-br br0'
        assert words[1] == 'set bridge br0 protocols=OpenFlow13 fail-mode=secure other-config:datapath-id=00000000000000a1'
        assert words[2] == 'set-controller br0 tcp:192.0.2.1:6653'
        assert words[3:] == ['--may-exist add-port br0 eth1', 'set interface eth1 ofport_request=17',
                             'set port eth1 tag=120', '--may-exist add-port br0 eth0']

    def test_bridge_cmd_minimal(self):
        assert sdn.ovs_bridge_cmd('br0', protocols=None) == 'ovs-vsctl --timeout=5 --may-exist add-br br0'

    def test_osken_start(self):
        cmd = sdn.osken_start_cmd(['os_ken.app.ofctl_rest'], env={'OFCTL_REST_PORT': 8081})
        assert 'setsid -f env OFCTL_REST_PORT=8081 osken-manager --log-file /var/log/osken-manager.log ' \
               '--pid-file /run/osken-manager.pid os_ken.app.ofctl_rest' in cmd
        assert "grep -q ':6653 '" in cmd
        assert 'kill $(cat /run/osken-manager.pid)' in cmd
        assert 'ss -ltnH' not in sdn.osken_start_cmd(['x'], wait_port=None)

    def test_rest_cmd(self):
        body = {'dpid': 161, 'priority': 100, 'match': {'in_port': 1}, 'actions': [{'type': 'OUTPUT', 'port': 2}]}
        cmd = sdn.rest_cmd('10.0.0.1/24', 'flowentry/add', body)
        words = shlex.split(cmd)
        assert words[:5] == ['curl', '-s', '-m', '5', '-X'] and words[5] == 'POST'
        assert json.loads(words[7]) == body and words[8] == 'http://10.0.0.1:8080/stats/flowentry/add'
        assert sdn.rest_cmd('ctl', 'switches') == 'curl -s -m 5 http://ctl:8080/stats/switches'
        assert sdn.rest_cmd('ctl', 'flowentry/clear/161', method='DELETE') == \
            'curl -s -m 5 -X DELETE http://ctl:8080/stats/flowentry/clear/161'

    def test_dpid_text(self):
        assert sdn.dpid_text(161) == '00000000000000a1'


class TestOvsHelpersStateSide:
    """The helpers of the Open vSwitch lab (lab/sre/_DRAFT_misc/openvswitch.py)."""

    def test_bond(self):
        cmd = sdn.ovs_bond_cmd('br0', 'bond0', ['eth0', 'eth1'], other_config={'lacp-system-id': '02:1a:00:00:00:01'})
        assert cmd.split(' -- ') == [
            'ovs-vsctl --timeout=5 --may-exist add-bond br0 bond0 eth0 eth1',
            'set port bond0 bond_mode=balance-tcp lacp=active other_config:lacp-system-id=02:1a:00:00:00:01 '
            'other_config:lacp-time=fast']
        assert sdn.ovs_bond_cmd('br0', 'b', ['a', 'c'], bond_mode=None, lacp=None, lacp_time=None) == \
            'ovs-vsctl --timeout=5 --may-exist add-bond br0 b a c'

    def test_tunnel(self):
        cmd = sdn.ovs_tunnel_cmd('br-int', 'vx', 'vxlan', '198.51.100.2/24', 5000, tag=12)
        assert cmd.split(' -- ') == ['ovs-vsctl --timeout=5 --may-exist add-port br-int vx',
                                     'set interface vx type=vxlan options:key=5000 options:remote_ip=198.51.100.2',
                                     'set port vx tag=12']
        assert 'options:key' not in sdn.ovs_tunnel_cmd('br0', 'g', 'gre', '192.0.2.1')

    def test_internal_port(self):
        assert sdn.ovs_internal_port_cmd('br0', 'gw', tag=7).split(' -- ') == [
            'ovs-vsctl --timeout=5 --may-exist add-port br0 gw', 'set interface gw type=internal', 'set port gw tag=7']

    def test_mirror(self):
        cmd = sdn.ovs_mirror_cmd('br0', 'span', ['eth0', 'eth1'], 'eth2')
        assert cmd.split(' -- ') == [
            'ovs-vsctl --timeout=5', '--id=@p0 get port eth0', '--id=@p1 get port eth1', '--id=@out get port eth2',
            '--id=@m create mirror name=span select_src_port=@p0,@p1 select_dst_port=@p0,@p1 output_port=@out',
            'set bridge br0 mirrors=@m']

    def test_policing_and_qos(self):
        assert sdn.ovs_policing_cmd('eth3', 2000, 200) == \
            'ovs-vsctl --timeout=5 set interface eth3 ingress_policing_rate=2000 ingress_policing_burst=200'
        cmd = sdn.ovs_qos_cmd('eth4', 30_000_000, {1: 7_000_000, 0: 30_000_000})
        assert cmd.split(' -- ') == [
            'ovs-vsctl --timeout=5', 'set port eth4 qos=@qos',
            '--id=@qos create qos type=linux-htb other_config:max-rate=30000000 queues:0=@q0 queues:1=@q1',
            '--id=@q0 create queue other_config:max-rate=30000000', '--id=@q1 create queue other_config:max-rate=7000000']

    def test_capture(self):
        start = sdn.capture_start_cmd('span', bpf='icmp', seconds=20)
        assert start.startswith('rm -f /tmp/sre-span.pcap /tmp/sre-span.pid; setsid -f sh -c ')
        assert 'exec timeout 20 tcpdump -n -U -i eth0 -w /tmp/sre-span.pcap icmp' in start
        assert start.endswith('test -s /tmp/sre-span.pid') and '@@@' not in start
        read = sdn.capture_read_cmd('span', 'icmp')
        assert 'kill $(cat /tmp/sre-span.pid)' in read and read.endswith('tcpdump -n -r /tmp/sre-span.pcap icmp 2>/dev/null')


class TestOvsState:
    def test_connected_secure_bridge(self):
        state = sdn.parse_ovs_state(_fixture('ovs_state_sw3_final.txt'))
        assert state.running and list(state.bridges) == ['br0']
        br = state.bridge()
        assert br is state.bridge('br0') and br.fail_mode == 'secure' and br.protocols == ['OpenFlow13']
        assert sorted(br.port_names()) == ['eth1', 'eth2']
        assert len(br.controllers) == 1
        c = br.controller()
        assert c.is_connected and c.target.startswith('tcp:') and c.target.endswith(':6653')
        assert br.controller(c.target) is c and br.controller('tcp:192.0.2.1:6653') is None
        assert len(br.datapath_id) == 16 and br.dpid == int(br.datapath_id, 16)
        assert state.bridge_of('eth1') is br and state.port_of('eth2').interfaces == ['eth2']
        assert isinstance(state.ofport('eth1'), int) and state.ofport('br0') == 65534
        assert state.interfaces['br0'].type == 'internal'

    def test_tags_and_ofports(self):
        state = sdn.parse_ovs_state(_fixture('ovs_state_sw2_final.txt'))
        br = state.bridge('br0')
        assert br.fail_mode == 'secure' and br.controllers == []
        ofports = {name: state.ofport(name) for name in ('eth0', 'eth1', 'eth2', 'eth3')}
        assert all(5 <= p < 49 for p in ofports.values()) and len(set(ofports.values())) == 4
        assert all(br.port(p).tag is None for p in ('eth0', 'eth1', 'eth2', 'eth3'))

    def test_no_bridge(self):
        state = sdn.parse_ovs_state(_fixture('ovs_state_sw1_initial.txt'))
        assert state.running and state.bridges == {} and state.bridge() is None
        assert state.bridge_of('eth0') is None and state.port_of('eth0') is None and state.ofport('eth0') is None

    def test_not_running(self):
        text = ("ovs-vsctl: unix:/var/run/openvswitch/db.sock: database connection failed (No such file or directory)\n"
                + "==SRE-SDN==\n") * 3 + "ovs-vsctl: database connection failed\n"
        assert not sdn.parse_ovs_state(text).running
        assert not sdn.parse_ovs_state('').running

    def test_decoding(self):
        assert sdn._ovs_value(['map', [['a', 'b']]]) == {'a': 'b'}
        assert sdn._ovs_value(['set', [['uuid', 'u1'], ['uuid', 'u2']]]) == ['u1', 'u2']
        assert sdn._optional([]) is None and sdn._optional([5]) == 5 and sdn._optional(7) == 7
        assert sdn.parse_ovs_table('not json') == []

    def test_state_cmd(self):
        cmd = sdn.ovs_state_cmd()
        assert cmd.count('--format=json list') == 4 and cmd.count('==SRE-SDN==') == 3 and '@@@' not in cmd


class TestFlows:
    def test_learning_switch(self):
        flows = sdn.parse_flows(_fixture('flows_sw3_final.txt'))
        assert len(flows) == 3
        miss = sdn.table_miss(flows)
        assert miss is flows[2] and miss.outputs() == ['CONTROLLER'] and miss.n_packets == 3
        learned = flows[0]
        assert learned.priority == 1 and learned.idle_timeout == 300 and learned.table == 0
        assert learned.match['in_port'] == '2' and 'dl_src' in learned.match and 'dl_dst' in learned.match
        assert learned.outputs() == ['1'] and not learned.drops
        assert learned.fields()['eth_src'] == learned.match['dl_src']

    def test_meter_instruction(self):
        flows = sdn.parse_flows(_fixture('flows_sw4a_final.txt'))
        metered = [f for f in flows if f.meter_ids()]
        assert len(metered) == 1 and metered[0].meter_ids() == [1] and metered[0].actions[0] == 'meter:1'
        assert all(f.priority == 100 for f in flows) and sdn.table_miss(flows) is None

    def test_empty_table(self):
        assert sdn.parse_flows(_fixture('flows_sw4a_initial.txt')) == []

    def test_line_forms(self):
        f = sdn.parse_flow_line(' cookie=0x2a, duration=1.050s, table=1, n_packets=4, n_bytes=392, '
                                'hard_timeout=30, priority=500,tcp,in_port=1,nw_dst=10.9.0.3,tp_dst=80 '
                                'actions=ct(commit,zone=1),output:2')
        assert f.cookie == 42 and f.table == 1 and f.hard_timeout == 30 and f.priority == 500
        assert f.match == {'tcp': None, 'in_port': '1', 'nw_dst': '10.9.0.3', 'tp_dst': '80'}
        assert f.actions == ['ct(commit,zone=1)', 'output:2'] and f.outputs() == ['2']
        assert f.fields() == {'eth_type': 0x0800, 'ip_proto': 6, 'in_port': '1', 'ipv4_dst': '10.9.0.3', 'tp_dst': '80'}
        default = sdn.parse_flow_line(' cookie=0x0, duration=2s, table=0, n_packets=0, n_bytes=0, arp actions=NORMAL')
        assert default.priority == sdn.DEFAULT_PRIORITY and default.outputs() == ['NORMAL']
        drop = sdn.parse_flow_line(' cookie=0x0, table=0, priority=0 actions=drop')
        assert drop.drops and drop.is_table_miss
        assert sdn.parse_flow_line('OFPST_FLOW reply (OF1.3) (xid=0x2):') is None
        assert sdn.flows_cmd() == 'ovs-ofctl -O OpenFlow13 --no-names dump-flows br0'


class TestTraceMetersShow:
    def test_trace(self):
        drop = sdn.parse_trace(_fixture('trace_drop_final.txt'))
        assert drop.dropped and not drop.forwarded
        forward = sdn.parse_trace(_fixture('trace_forward_allow_all.txt'))
        assert forward.forwarded and not forward.dropped and forward.datapath_actions == '2'
        error = sdn.parse_trace('Bad openflow flow syntax: ...: prerequisites not met for setting tp_src\n'
                                'ovs-appctl: ovs-vswitchd: server returned an error\n')
        assert not error.dropped and not error.forwarded

    def test_trace_flow(self):
        udp = sdn.trace_flow(in_port=7, proto='udp', eth_src='02:00:00:00:00:01', eth_dst='02:00:00:00:00:02',
                             ip_src='192.0.2.1', ip_dst='192.0.2.2', dport=9999)
        # tp_src / tp_dst after udp are refused by ofproto/trace of OVS 3.5
        assert udp == ('in_port=7,udp,dl_src=02:00:00:00:00:01,dl_dst=02:00:00:00:00:02,nw_src=192.0.2.1,'
                       'nw_dst=192.0.2.2,udp_src=40000,udp_dst=9999')
        icmp = sdn.trace_flow(in_port=3, proto='icmp', eth_src='a', eth_dst='b', ip_src='1.1.1.1', ip_dst='2.2.2.2')
        assert icmp.endswith('icmp_type=8,icmp_code=0')
        arp = sdn.trace_flow(in_port=3, proto='arp', eth_src='a', eth_dst='ff:ff:ff:ff:ff:ff', ip_src='1.1.1.1',
                             ip_dst='2.2.2.2')
        assert arp == 'in_port=3,arp,dl_src=a,dl_dst=ff:ff:ff:ff:ff:ff,arp_spa=1.1.1.1,arp_tpa=2.2.2.2,arp_op=1'
        assert sdn.trace_cmd('br0', udp) == f"ovs-appctl ofproto/trace br0 {udp}"

    def test_meters(self):
        meters = sdn.parse_meters(_fixture('meters_sw4a_final.txt'))
        assert list(meters) == [1]
        assert meters[1].flags == ['kbps'] and meters[1].bands == [{'type': 'drop', 'rate': 5500}]
        assert sdn.parse_meters(_fixture('meters_sw4a_initial.txt')) == {}
        two = sdn.parse_meters('meter=2 pktps burst stats bands=\ntype=drop rate=100 burst_size=10\n'
                               'meter=3 kbps bands=type=dscp_remark rate=50 prec_level=1\n')
        assert two[2].flags == ['pktps', 'burst', 'stats'] and two[2].bands[0]['burst_size'] == 10
        assert two[3].bands == [{'type': 'dscp_remark', 'rate': 50, 'prec_level': 1}]

    def test_ofctl_show(self):
        show = sdn.parse_ofctl_show(_fixture('ofctl_show_sw2.txt'))
        assert show['dpid'] == '0000ba6cdc4e784e'
        assert set(show['ports']) == {'eth0', 'eth1', 'eth2', 'eth3', 'br0'} and show['ports']['br0'] == 'LOCAL'
        assert all(isinstance(n, int) for name, n in show['ports'].items() if name != 'br0')

    def test_iperf_udp(self):
        result = parse_iperf3(_fixture('iperf_udp_final.json'))
        # 16 500 kbit/s sent through a meter of 5 500 kbit/s: the receiver's figure, below 1.5 times the rate
        assert result['error'] is None and 0.5 * 5500 <= result['bps'] / 1000 <= 1.5 * 5500


class TestAnswers:
    def test_hex_dpid(self):
        for answer in ('00000000000000a1', '0xa1', 'A1', '00:00:00:00:00:00:00:a1', ' a1 ', 'dpid:00000000000000a1'):
            assert sdn.normalize_dpid(answer) == 0xa1, answer
        for answer in ('', 'xyz', '1' * 17, None):
            assert sdn.normalize_dpid(answer) is None, answer

    def test_decimal_dpid(self):
        assert sdn.normalize_decimal_dpid(' 6947 ') == 6947
        assert sdn.normalize_decimal_dpid('0x1b23') is None and sdn.normalize_decimal_dpid(None) is None


# ---------------------------------------------------------------------------
# the Open vSwitch lab: full OVSDB state, bonds, LACP, conntrack, traces with ct, captures
# ---------------------------------------------------------------------------


def _ovs(name: str) -> str:
    return (_MOCK / 'ovs' / name).read_text()


class TestFullOvsState:
    def test_mirror_qos_policing(self):
        state = sdn.parse_ovs_state(_ovs('ovs_state_sw5_final_full.txt'), sdn.OVS_TABLES_FULL)
        bridge = state.bridge('br0')
        assert [(m.name, m.select_src_ports, m.select_dst_ports, m.output_port, m.select_all) for m in bridge.mirrors] == \
            [('span', ['eth0'], ['eth0'], 'eth2', False)]
        qos = state.port_of('eth4').qos
        assert qos.type == 'linux-htb' and qos.other_config == {'max-rate': '30000000'}
        assert {n: q.other_config for n, q in qos.queues.items()} == {0: {'max-rate': '30000000'},
                                                                      1: {'max-rate': '7000000'}}
        assert state.port_of('eth0').qos is None
        eth3 = state.interfaces['eth3']
        assert (eth3.ingress_policing_rate, eth3.ingress_policing_burst) == (2000, 200)
        assert state.interfaces['eth0'].ingress_policing_rate == 0 and state.ofport('eth3') == 17

    def test_default_tables_ignore_the_others(self):
        """The first four chunks are the default tables: the SDN lab's parse still works on a full state."""
        state = sdn.parse_ovs_state(_ovs('ovs_state_sw5_final_full.txt'))
        assert state.running and state.bridge('br0').mirrors == [] and state.port_of('eth4').qos is None
        assert state.ofport('eth3') == 17
        assert sdn.ovs_state_cmd() == sdn.ovs_state_cmd(sdn.OVS_TABLES)
        assert sdn.ovs_state_cmd(sdn.OVS_TABLES_FULL).endswith('list Mirror; echo ==SRE-SDN==; '
                                                               'ovs-vsctl --timeout=3 --format=json list QoS; '
                                                               'echo ==SRE-SDN==; ovs-vsctl --timeout=3 --format=json list Queue')

    def test_tunnels(self):
        state = sdn.parse_ovs_state(_ovs('ovs_state_hv3a_final.txt'))
        vx = state.interfaces['vxlan-red']
        assert vx.type == 'vxlan' and vx.options == {'key': '94068', 'remote_ip': '192.168.171.173'}
        assert vx.status.get('tunnel_egress_iface') == 'eth0'
        assert state.interfaces['geneve-blue'].options['key'] == '57426'
        assert [p.name for p in state.ports_of_type('vxlan')] == ['vxlan-red']
        assert state.port_of('vxlan-red').tag == 789 and state.bridge_of('vxlan-red').name == 'br-int'

    def test_bond_port(self):
        state = sdn.parse_ovs_state(_ovs('ovs_state_hv2_final.txt'))
        bond = state.bridge('br0').port('bond0')
        assert sorted(bond.interfaces) == ['eth0', 'eth1'] and bond.bond_mode == 'balance-tcp'
        assert bond.lacp == 'active' and bond.other_config == {'lacp-time': 'fast'}
        assert state.bridge('br0').port('eth2').bond_mode is None


class TestBondLacp:
    def test_negotiated(self):
        bonds = sdn.parse_bond_show(_ovs('bond_show_hv2_final.txt'))
        bond = bonds['bond0']
        assert bond.bond_mode == 'balance-tcp' and bond.lacp_status == 'negotiated'
        assert bond.enabled_members() == ['eth0', 'eth1'] and sum(m.active for m in bond.members.values()) == 1
        lacp = sdn.parse_lacp_show(_ovs('lacp_show_hv2_final.txt'))['bond0']
        assert lacp.negotiated and lacp.status == ['active', 'negotiated'] and lacp.lacp_time == 'fast'
        assert lacp.sys_priority == 65534 and lacp.partner_sys_ids() == ['02:1a:17:2e:f7:9a']
        assert all(m.aggregated and m.states == ['current', 'attached'] for m in lacp.members.values())

    def test_slb(self):
        bond = sdn.parse_bond_show(_ovs('bond_show_hv2_slb.txt'))['bond0']
        assert bond.bond_mode == 'balance-slb' and bond.lacp_status == 'negotiated'

    def test_no_partner(self):
        bond = sdn.parse_bond_show(_ovs('bond_show_tor2_no_partner.txt'))['bond0']
        assert bond.lacp_status == 'configured' and bond.enabled_members() == []
        assert not any(m.may_enable for m in bond.members.values())
        lacp = sdn.parse_lacp_show(_ovs('lacp_show_tor2_no_partner.txt'))['bond0']
        assert not lacp.negotiated and lacp.sys_id == '02:1a:17:2e:f7:9a'
        assert lacp.partner_sys_ids() == ['00:00:00:00:00:00']
        assert all(m.states == ['defaulted', 'detached'] and not m.aggregated and m.partner_state == []
                   for m in lacp.members.values())

    def test_empty(self):
        assert sdn.parse_bond_show('') == {} and sdn.parse_lacp_show('ovs-appctl: no such bond') == {}


class TestConntrackTraceCapture:
    def test_conntrack(self):
        entries = sdn.parse_conntrack(_ovs('conntrack_fw4_final.txt'))
        assert [e.proto for e in entries] == ['icmp', 'tcp']
        tcp = entries[1]
        assert tcp.state == 'TIME_WAIT' and tcp.zone == 0 and tcp.reply['sport'] == '80'
        assert tcp.matches(src='172.31.149.252', dst='172.31.149.119', dport=80, sport='45684')
        assert not tcp.matches(src='172.31.149.252', dport=80, sport=1)
        assert entries[0].orig == {'src': '172.31.149.252', 'dst': '172.31.149.119', 'id': '133', 'type': '8',
                                   'code': '0'}
        zone = sdn.parse_conntrack('udp,orig=(src=1.1.1.1,dst=2.2.2.2,sport=1,dport=2),reply=(src=2.2.2.2,'
                                   'dst=1.1.1.1,sport=2,dport=1),zone=5')
        assert zone[0].zone == 5 and zone[0].state == ''

    def test_trace_after_recirculation(self):
        """With ct(), a trace has a 'Datapath actions:' line per pass: the last one is the verdict."""
        stateful = sdn.parse_trace(_ovs('trace_fw4_synack_final.txt'))
        assert stateful.dropped and stateful.text.count('Datapath actions:') == 2
        assert sdn.parse_trace(_ovs('trace_fw4_synack_stateless.txt')).forwarded

    def test_trace_options(self):
        flow = sdn.trace_flow(in_port=45, proto='tcp', eth_src='02:00:00:00:00:02', eth_dst='02:00:00:00:00:01',
                              ip_src='192.0.2.2', ip_dst='192.0.2.1', sport=80, dport=40000, tcp_flags=0x012)
        assert flow.endswith(',tcp_src=80,tcp_dst=40000,tcp_flags=0x012')
        assert sdn.trace_cmd('br0', 'in_port=1,ip') == "ovs-appctl ofproto/trace br0 in_port=1,ip"
        assert sdn.trace_cmd('br0', 'in_port=1,ip', ['trk,new', 'trk,est']) == \
            "ovs-appctl ofproto/trace br0 in_port=1,ip --ct-next trk,new --ct-next trk,est"

    def test_capture(self):
        text = _ovs('capture_ids5_final.txt')
        assert sdn.count_icmp_echo(text) == 8
        assert sdn.count_icmp_echo(text, '192.168.222.84', '192.168.222.6') == 8
        assert sdn.count_icmp_echo(text, '192.168.222.84', '192.168.222.7') == 0
        assert sdn.count_icmp_echo('') == 0

    def test_set_queue_flow(self):
        flows = sdn.parse_flows(_ovs('flows_sw5_final.txt'))
        queued = flows[0]
        assert queued.actions == ['set_queue:1', 'NORMAL'] and queued.outputs() == ['NORMAL']
        assert queued.fields()['ipv4_src'] == '192.168.222.84' and queued.priority == 100
