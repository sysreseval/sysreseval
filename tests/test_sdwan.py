"""Tests of lib/sdwan.py (the grading helpers of the SD-WAN lab) and lib/sdwan_agent.py (its edge agent).

The fixtures of tests/mock_data/sdwan/ were extracted from the real evaluations of
tests/mock_data/sdwan/lab/ (s17, 2026-11-24, nftables 1.1.3 on routing-frr:1.35): the hub's counter table
(``counters_final_step1.txt`` / ``counters_final_step3.txt``, before and after the healthy probes of the
final project) and the agent status of edge6 (``agent_status_final.json``, ``agent_status_none.json``).
"""
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import sdwan  # noqa: E402
import sdwan_agent as agent  # noqa: E402

_MOCK = _REPO / 'tests' / 'mock_data' / 'sdwan'


def _fixture(name: str) -> str:
    return (_MOCK / name).read_text()


POLICY = {
    "version": 3,
    "paths": {"mpls": {"device": "wg-mpls", "probe": "172.30.0.1"},
              "inet": {"device": "wg-inet", "probe": "172.31.0.1"}},
    "sla_classes": {"realtime": {"max_latency_ms": 150, "max_loss_pct": 5, "max_jitter_ms": 30}},
    "applications": [
        {"name": "voice", "match": {"proto": "udp", "dports": [5060, "16384-32767"]}, "sla_class": "realtime",
         "paths": ["mpls", "inet"]},
        {"name": "video", "match": {"dscp": "af41"}, "sla_class": "realtime", "paths": ["inet", "mpls"]},
        {"name": "backup", "match": {"proto": "tcp", "dports": [873], "dst": ["10.1.2.7/24"]}, "paths": ["inet"]},
    ],
}


class TestCounters:
    def test_ruleset(self):
        text = sdwan.counter_ruleset({'pc1': '10.1.1.10', 'pc2': '10.1.2.10'}, ef_port=41000)
        assert text.startswith('table inet sre_count\ndelete table inet sre_count\n')
        assert 'type filter hook prerouting priority raw; policy accept;' in text
        rules = [line.strip() for line in text.splitlines() if 'counter comment' in line]
        assert len(rules) == 2 * 2 * len(sdwan.APPS)
        assert ('iifname "wg-mpls" ip saddr 10.1.1.10 ip dscp ef udp dport 41000 counter comment "pc1|mpls|ef"'
                in rules)
        assert 'iifname "wg-inet" ip saddr 10.1.2.10 tcp dport 8443 counter comment "pc2|inet|erp"' in rules
        assert '@@@' not in text

    def test_parse_and_delta(self):
        before = sdwan.parse_counters(_fixture('counters_final_step1.txt'))
        after = sdwan.parse_counters(_fixture('counters_final_step3.txt'))
        assert len(before) == len(after) == 6 * 2 * len(sdwan.APPS)
        # the final project, healthy transports: voice and the ERP of pc3 over MPLS, the rest over Internet
        for app in ('sip', 'ef', 'erp'):
            assert sdwan.carried_by(sdwan.tunnel_delta(before, after, 'pc3', app), 'mpls'), app
        for app in ('web', 'bulk', 'udp'):
            assert sdwan.carried_by(sdwan.tunnel_delta(before, after, 'pc3', app), 'inet'), app
        assert sdwan.carried_by(sdwan.tunnel_delta(before, after, 'pc6', 'bulk'), 'inet')
        assert not sdwan.carried_by(sdwan.tunnel_delta(before, after, 'pc6', 'bulk'), 'mpls')
        # a TCP probe is counted twice: the SYN, then the RST of the host after the SYN-ACK of dc
        delta = sdwan.tunnel_delta(before, after, 'pc3', 'erp')
        assert delta['mpls'] >= 2 * sdwan.PROBE_COUNT - 2 and delta['inet'] == 0

    def test_carried_by(self):
        assert sdwan.carried_by({'mpls': 20, 'inet': 0}, 'mpls')
        assert sdwan.carried_by({'mpls': 15, 'inet': 3}, 'mpls')
        assert not sdwan.carried_by({'mpls': 14, 'inet': 0}, 'mpls')
        assert not sdwan.carried_by({'mpls': 20, 'inet': 4}, 'mpls')
        assert not sdwan.carried_by({'mpls': None, 'inet': 0}, 'mpls')
        assert not sdwan.carried_by({'mpls': 20, 'inet': None}, 'mpls')
        assert sdwan.tunnel_delta({}, {}, 'pc1', 'sip') == {'mpls': None, 'inet': None}

    def test_parse_garbage(self):
        assert sdwan.parse_counters('') == {} and sdwan.parse_counters('Error: No such file or directory') == {}
        assert sdwan.parse_counters('{"nftables": [{"rule": {"comment": "x", "expr": []}}]}') == {}


class TestCommands:
    def test_probes(self):
        assert sdwan.probe_cmd('sip', '10.0.0.10/24') == \
            'hping3 --udp -p 5060 -c 20 -i u10000 -q 10.0.0.10 >/dev/null 2>&1; true'
        # hping3 reads the TOS in hexadecimal without 0x
        assert '--udp -p 41000 -o b8 ' in sdwan.probe_cmd('ef', '10.0.0.10', ef_port=41000)
        assert '-o' not in sdwan.probe_cmd('udp', '10.0.0.10', ef_port=41000)
        assert '-S -p 873 ' in sdwan.probe_cmd('bulk', '10.0.0.10') and '-S -p 8443 ' in sdwan.probe_cmd('erp', 'x')
        assert sdwan.probe_cmd('icmp', '10.0.0.10', count=5).startswith('ping -n -q -c 5 ')
        with pytest.raises(KeyError):
            sdwan.probe_cmd('ftp', '10.0.0.10')

    def test_impairments(self):
        assert sdwan.brownout_cmd('eth5', 250) == 'tc qdisc replace dev eth5 root netem delay 250ms'
        assert sdwan.restore_cmd('eth5') == 'tc qdisc del dev eth5 root 2>/dev/null; true'

    def test_policy_json(self):
        text = sdwan.policy_json({'mpls': ('wg-mpls', '172.30.0.1')}, {'rt': {'max_latency_ms': 100}},
                                 [{'name': 'voice', 'match': {'proto': 'udp', 'dports': [5060]}, 'sla_class': 'rt',
                                   'paths': ['mpls']}], version=4)
        doc = json.loads(text)
        policy, errors = agent.validate_policy(doc)
        assert errors == [] and policy['version'] == 4 and policy['paths']['mpls']['device'] == 'wg-mpls'


class TestAgentStatus:
    def test_with_policy(self):
        status = sdwan.parse_agent_status(_fixture('agent_status_final.json'))
        assert status['policy']['version'] == 1 and status['fetch']['status'] == 'ok'
        assert {a['name']: a['path'] for a in status['applications']} == {'voice': 'mpls', 'bulk': 'inet'}
        assert set(status['paths']) == {'mpls', 'inet'} and status['refused'] is None

    def test_without_policy(self):
        status = sdwan.parse_agent_status(_fixture('agent_status_none.json'))
        assert status['policy'] is None and status['fetch']['status'] == 'not found'
        assert status['applications'] == [] and status['paths'] == {}

    def test_no_status(self):
        assert sdwan.parse_agent_status('no status: is sdwan-agent running? (sdwan-agent start)') == {}
        assert sdwan.parse_agent_status('') == {}


class TestAgentPolicy:
    def test_valid(self):
        policy, errors = agent.validate_policy(POLICY)
        assert errors == []
        assert policy['hold_down_s'] == agent.DEFAULT_HOLD_DOWN
        assert policy['applications'][1]['match'] == {'dscp': 34}
        assert policy['applications'][2]['match']['dst'] == ['10.1.2.0/24']
        assert policy['applications'][0]['match']['dports'] == ['5060', '16384-32767']

    @pytest.mark.parametrize('change, message', [
        (lambda p: p.pop('version'), 'version'),
        (lambda p: p.update(version=-1), 'version'),
        (lambda p: p.update(extra=1), 'unknown keys: extra'),
        (lambda p: p['paths']['mpls'].update(probe='not-an-ip'), 'paths.mpls.probe'),
        (lambda p: p['paths']['mpls'].update(device='a very long interface name'), 'paths.mpls.device'),
        (lambda p: p['sla_classes']['realtime'].update(max_loss_pct=150), 'max_loss_pct'),
        (lambda p: p['sla_classes']['realtime'].update(latency=3), 'unknown keys latency'),
        (lambda p: p['applications'][0].update(sla_class='gold'), "unknown class 'gold'"),
        (lambda p: p['applications'][0].update(paths=['lte']), 'applications[0].paths'),
        (lambda p: p['applications'][0].update(paths=['mpls', 'mpls']), 'applications[0].paths'),
        (lambda p: p['applications'][0]['match'].update(dports=[70000]), 'is not a port'),
        (lambda p: p['applications'][0]['match'].update(dports=['20-10']), 'is not a port'),
        (lambda p: p['applications'][1]['match'].update(dports=[80]), 'needs "proto"'),
        (lambda p: p['applications'][1]['match'].update(dscp='gold'), 'is not a DSCP value'),
        (lambda p: p['applications'][1].update(name='voice'), 'unique name'),
        (lambda p: p['applications'][2]['match'].update(dst=['10.1.2.0/33']), 'not an IPv4 network'),
        (lambda p: p['applications'][2].update(match={}), 'non-empty object'),
    ])
    def test_errors(self, change, message):
        doc = json.loads(json.dumps(POLICY))
        change(doc)
        policy, errors = agent.validate_policy(doc)
        assert policy is None and any(message in e for e in errors), errors

    def test_not_an_object(self):
        assert agent.validate_policy([]) == (None, ['the policy must be a JSON object'])

    def test_nft(self):
        policy, _ = agent.validate_policy(POLICY)
        assert agent.nft_rule(policy['applications'][0], 0x101) == \
            'udp dport { 5060, 16384-32767 } meta mark set 0x101 accept comment "voice"'
        assert agent.nft_rule(policy['applications'][1], 0x102) == 'ip dscp 34 meta mark set 0x102 accept comment "video"'
        assert agent.nft_rule(policy['applications'][2], 0x103) == \
            'ip daddr { 10.1.2.0/24 } tcp dport { 873 } meta mark set 0x103 accept comment "backup"'
        assert agent.nft_rule({'name': 'p', 'match': {'proto': 'icmp'}}, 0x104) == \
            'meta l4proto icmp meta mark set 0x104 accept comment "p"'
        text = agent.nft_ruleset(policy)
        assert text.startswith('table inet sdwan\ndelete table inet sdwan\ntable inet sdwan {\n')
        assert text.count('meta mark set') == 3 and 'hook prerouting priority mangle' in text


class TestAgentDecisions:
    def test_metrics(self):
        assert agent.metrics([1.0, 3.0, None, 2.0, None]) == {'alive': True, 'latency_ms': 2.0, 'loss_pct': 40.0,
                                                              'jitter_ms': 1.5}
        assert agent.metrics([None, None]) == {'alive': False, 'latency_ms': None, 'loss_pct': 100.0,
                                               'jitter_ms': None}
        assert agent.metrics([])['alive'] is False

    def test_meets(self):
        sla = {'max_latency_ms': 150.0, 'max_loss_pct': 5.0, 'max_jitter_ms': 30.0}
        assert agent.meets(agent.metrics([1, 1, 1, 1, 1]), sla)
        # the brownout of the lab: three of five probes at 251 ms → mean 151 ms
        assert not agent.meets(agent.metrics([1, 1, 251, 251, 251]), {'max_latency_ms': 150.0})
        assert agent.meets(agent.metrics([1, 1, 1, 251, 251]), {'max_latency_ms': 150.0})
        assert not agent.meets(agent.metrics([1, None, 1, 1, 1]), sla)           # 20 % lost
        assert not agent.meets(agent.metrics([1, 100, 1, 100, 1]), sla)          # jitter 99 ms
        assert agent.meets(agent.metrics([500]), None) and not agent.meets(agent.metrics([None]), None)

    def test_choose_with_hysteresis(self):
        app = {'paths': ['mpls', 'inet']}
        sla = {'max_latency_ms': 150.0}
        good, bad = agent.metrics([1] * 5), agent.metrics([251] * 5)
        assert agent.choose(app, sla, {'mpls': good, 'inet': good}, None, {}, 100.0, 5) == 'mpls'
        # MPLS degraded: leave at once
        assert agent.choose(app, sla, {'mpls': bad, 'inet': good}, 'mpls', {}, 100.0, 5) == 'inet'
        # MPLS good again for 3 s only: stay; for 5 s: come back
        assert agent.choose(app, sla, {'mpls': good, 'inet': good}, 'inet', {'mpls': 97.0}, 100.0, 5) == 'inet'
        assert agent.choose(app, sla, {'mpls': good, 'inet': good}, 'inet', {'mpls': 95.0}, 100.0, 5) == 'mpls'
        # both out of the SLA: the lowest latency; both dead: stay
        worse = agent.metrics([400] * 5)
        assert agent.choose(app, sla, {'mpls': worse, 'inet': bad}, 'mpls', {}, 100.0, 5) == 'inet'
        dead = agent.metrics([None] * 5)
        assert agent.choose(app, sla, {'mpls': dead, 'inet': dead}, 'inet', {}, 100.0, 5) == 'inet'
        # the current path failing: no hold-down to leave it for the preferred one
        assert agent.choose(app, sla, {'mpls': good, 'inet': dead}, 'inet', {}, 100.0, 5) == 'mpls'

    def test_cli_check(self, tmp_path, capsys):
        f = tmp_path / 'p.json'
        f.write_text(json.dumps(POLICY))
        assert agent.main(['check', str(f)]) == 0
        out = capsys.readouterr().out
        assert out.startswith('valid: version 3, 3 applications') and 'chain classify' in out
        f.write_text('{"version": 1}')
        assert agent.main(['check', str(f)]) == 1
        assert 'error: paths' in capsys.readouterr().out
