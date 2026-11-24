"""Tests of lib/sdn.py (Open vSwitch / OpenFlow helpers of the SDN lab).

The fixtures of tests/mock_data/sdn/ are outputs captured on s17 (2026-11-24, Open vSwitch 3.5.0, OS-Ken
3.0.1, iperf3 3.18), extracted from the real evaluations of tests/mock_data/sdn/lab/ (``ovs_state_*``,
``flows_*``, ``meters_*``, ``trace_*``, ``iperf_udp_final.json``) or run by hand (``ofctl_show_sw2.txt``).
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
