"""Tests of lib/ntp.py (chronyc parsers, probe specs, state helpers) and lib/ntp_probe.py (NTP packets,
the fake server and the client, run on localhost).

The fixtures of tests/mock_data/ntp/ are the outputs the NTP lab's grader read on s17 (chrony 4.6.1,
Debian 13, 2026-11-23): ``snapshot_<machine>_<untouched|final>.txt`` (the ``snapshot_cmd()`` of
each machine) and ``probe_check_<untouched|final>.txt`` (``ntp_probe.py check``).
"""
import json
import shlex
import socket
import sys
import threading
from ipaddress import IPv4Interface
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import ntp  # noqa: E402
import ntp_probe  # noqa: E402

MOCK = _REPO / 'tests' / 'mock_data' / 'ntp'


def _fixture(name: str) -> str:
    return (MOCK / name).read_text()


# ---------------------------------------------------------------------------
# chronyc parsers
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_server_with_a_falseticker(self):
        snap = ntp.parse_snapshot(_fixture('snapshot_border_final.txt'))
        assert snap.running
        assert snap.tracking.synced and snap.tracking.address == '198.19.199.246' and snap.tracking.stratum == 2
        assert snap.tracking.refid == 'C613C7F6' == ntp.refid_of('198.19.199.246')
        assert [(s.state, s.address, s.stratum, s.reach) for s in snap.sources] == [
            ('-', '198.19.199.91', 2, 7), ('*', '198.19.199.246', 1, 7), ('x', '198.19.199.16', 2, 7),
            ('?', '198.19.199.71', 0, 0)]
        assert snap.selected().address == '198.19.199.246' and snap.synced_to('198.19.199.246')
        assert snap.source('198.19.199.16').offset == pytest.approx(75, abs=0.01)
        assert {a.mode for a in snap.authdata} == {'-'}
        assert snap.config == []   # no config section asked

    def test_reach_is_octal(self):
        snap = ntp.parse_snapshot(_fixture('snapshot_ts1_final.txt'))
        assert snap.source('192.168.151.248').reach == 0o37 == 31

    def test_configuration_of_chronyd_p(self):
        snap = ntp.parse_snapshot(_fixture('snapshot_ts1_final.txt'))
        assert snap.directives('local') == [['local', 'stratum', '10', 'orphan']]
        assert [w[1] for w in snap.directives('allow')] == ['192.168.151.0/24', '192.168.52.0/24']
        assert snap.directives('server') == [['server', 'gps.corp.lan', 'iburst']]
        assert snap.directives('pool') == []

    def test_symmetric_key_and_nts(self):
        cam = ntp.parse_snapshot(_fixture('snapshot_cam1_final.txt'))
        auth = cam.auth('10.100.46.204')
        assert (auth.mode, auth.keyid, auth.key_length, auth.cookies) == ('SK', 51, 256, 0)
        assert cam.synced_to(IPv4Interface('10.100.46.204/24')) and cam.tracking.stratum == 3
        web = ntp.parse_snapshot(_fixture('snapshot_web1_final.txt'))
        auth = web.auth('192.168.221.1')
        assert (auth.mode, auth.keyid, auth.cookies) == ('NTS', 1, 8)

    def test_chronyd_not_running(self):
        snap = ntp.parse_snapshot(_fixture('snapshot_legacy_untouched.txt'))
        assert not snap.running and snap.tracking is None and snap.sources == [] and snap.authdata == []
        assert not snap.synced_to('192.168.151.248') and snap.selected() is None

    def test_running_without_source(self):
        snap = ntp.parse_snapshot(_fixture('snapshot_pc1_untouched.txt'))
        assert snap.running and snap.tracking is not None and not snap.tracking.synced
        assert snap.tracking.leap == ntp.NOT_SYNCHRONISED and snap.tracking.refid == '00000000'
        assert snap.sources == [] and snap.selected() is None

    def test_local_reference_is_synchronised_without_address(self):
        t = ntp.parse_tracking('7F7F0101,,10,1795445935.120169811,0.0,0.0,0.0,0.000,0.000,0.000,0.0,0.0,0.0,Normal')
        assert t.synced and t.address == '' and t.stratum == 10 and t.refid == ntp.LOCAL_REFID

    def test_garbage(self):
        assert ntp.parse_snapshot('') == ntp.ChronySnapshot()
        assert ntp.parse_tracking('506 Cannot talk to daemon') is None
        assert ntp.parse_sources('506 Cannot talk to daemon\n') == []
        assert ntp.parse_config('# comment\n\nServer x\n! include\n') == []

    def test_the_command_never_holds_the_exetests_separator(self):
        # exetests.py splits the commands of a batch on "@@@"
        assert '@@@' not in ntp.snapshot_cmd() and '@@@' not in ntp.snapshot_cmd(config=False)
        assert 'chronyd -p' in ntp.snapshot_cmd() and 'chronyd -p' not in ntp.snapshot_cmd(config=False)


class TestProbeCheck:
    def test_final(self):
        res = ntp.parse_probe_check(_fixture('probe_check_final.txt'))
        assert res['ts2_key']['synced'] and not res['ts2_badkey']['synced'] and res['ts3_nts']['synced']
        assert ntp.answered(res['ts1_lan'], synchronised=True) and ntp.answered(res['ts1_srv'])
        assert not ntp.answered(res['ts1_dmz'])
        assert res['border_burst'] == {'answered': 13, 'sent': 30}
        assert res['ts1_lan']['refid'] == '192.168.151.248' and res['ts1_lan']['stratum'] == 2

    def test_untouched(self):
        res = ntp.parse_probe_check(_fixture('probe_check_untouched.txt'))
        assert not any(ntp.answered(res[k]) for k in ('ts1_lan', 'ts1_srv', 'ts1_dmz', 'border_wan'))
        assert not any(res[k]['synced'] for k in ('ts2_key', 'ts2_badkey', 'ts3_nts'))
        assert res['border_burst']['answered'] == 0

    def test_answered(self):
        assert not ntp.answered(None) and not ntp.answered({}) and not ntp.answered({'answered': False})
        assert ntp.answered({'answered': True, 'leap': 3})
        assert not ntp.answered({'answered': True, 'leap': 3}, synchronised=True)
        assert ntp.answered({'answered': True, 'leap': 3}, synchronised=False)

    def test_parse_takes_the_last_json_line(self):
        assert ntp.parse_probe_check('Traceback\n{"a": {"answered": false}}\n') == {'a': {'answered': False}}
        assert ntp.parse_probe_check('') == {} and ntp.parse_probe_check('{broken') == {}

    def test_specs(self):
        ip = IPv4Interface('10.0.0.1/24')
        assert ntp.query_spec('q', ip, source=IPv4Interface('10.0.0.9/24')) == {
            'id': 'q', 'kind': 'query', 'server': '10.0.0.1', 'source': '10.0.0.9', 'timeout': 2.0}
        assert ntp.burst_spec('b', '10.0.0.1')['count'] == 30 and 'source' not in ntp.burst_spec('b', '10.0.0.1')
        assert ntp.chrony_spec('c', ['server x iburst'], timeout=8) == {
            'id': 'c', 'kind': 'chrony', 'directives': ['server x iburst'], 'timeout': 8}
        cmd = ntp.ntp_probe_check_cmd([ntp.query_spec('q', ip)])
        words = shlex.split(cmd)
        assert words[:3] == ['python3', ntp.NTP_PROBE_PATH, 'check'] and json.loads(words[3])[0]['id'] == 'q'


class TestStateHelpers:
    def test_base_configuration(self):
        conf = ntp.base_chrony_conf()
        assert 'pool' not in conf and 'confdir /etc/chrony/conf.d' in conf and 'keyfile /etc/chrony/chrony.keys' in conf
        assert ntp.base_chrony_conf('a\nb').startswith('# a\n# b\n')

    def test_daemon_options(self):
        assert f'DAEMON_OPTS="{ntp.DAEMON_OPTS}"' in ntp.daemon_defaults()
        assert ' -x ' in f' {ntp.DAEMON_OPTS} ' and ntp.CHRONY_LOG in ntp.DAEMON_OPTS
        assert ntp.DRIFT_SEED.split() == ['0.000000', '1.000000']

    def test_fake_server_command(self):
        personas = [ntp.persona(IPv4Interface('198.18.0.5/24'), offset=-97, stratum=2, refid='203.0.113.4')]
        assert personas[0]['address'] == '198.18.0.5' and personas[0]['offset'] == -97.0
        cmd = ntp.fake_server_cmd(personas)
        assert ntp.FAKE_PID_FILE in cmd and 'nohup setsid python3' in cmd
        quoted = cmd.split(' serve ', 1)[1].split(' >/dev/null')[0]
        assert json.loads(shlex.split(quoted)[0]) == personas

    def test_lines(self):
        assert ntp.server_line(IPv4Interface('10.1.2.3/24'), 'iburst', '', 'key 5') == 'server 10.1.2.3 iburst key 5'
        assert ntp.key_line(7, 'ab12') == '7 SHA256 HEX:AB12'
        assert ntp.refid_of('10.1.2.3') == '0A010203'


# ---------------------------------------------------------------------------
# lib/ntp_probe.py
# ---------------------------------------------------------------------------


class TestPackets:
    def test_timestamps(self):
        t = 1795445935.25
        assert ntp_probe.from_ntp(ntp_probe.to_ntp(t)) == pytest.approx(t, abs=1e-6)
        assert ntp_probe.to_ntp(0) >> 32 == ntp_probe.NTP_DELTA
        assert ntp_probe.from_short(ntp_probe.to_short(0.0153)) == pytest.approx(0.0153, abs=2e-5)

    def test_offset_and_delay_of_the_course(self):
        # T1 10:00:00.000, T2 .040, T3 .043, T4 .033: delta 30 ms, theta 25 ms
        offset, delay = ntp_probe.offset_delay(0.0, 0.040, 0.043, 0.033)
        assert offset == pytest.approx(0.025) and delay == pytest.approx(0.030)

    def test_refids(self):
        assert ntp_probe.refid_bytes('GPS', 1) == b'GPS\0'
        assert ntp_probe.refid_bytes('10.1.2.3', 2) == bytes([10, 1, 2, 3])
        assert ntp_probe.refid_text(b'GPS\0', 1) == 'GPS' and ntp_probe.refid_text(bytes([10, 1, 2, 3]), 3) == '10.1.2.3'
        assert ntp_probe.refid_text(b'INIT', 16) == 'INIT'

    def test_response_echoes_the_transmit_timestamp(self):
        request = ntp_probe.build_request(0x1234567890ABCDEF)
        assert ntp_probe.parse_packet(request)['mode'] == ntp_probe.MODE_CLIENT
        persona = {'offset': 100.0, 'stratum': 2, 'refid': '192.0.2.7', 'precision': -21, 'root_delay': 0.012,
                   'root_dispersion': 0.02}
        answer = ntp_probe.parse_packet(ntp_probe.build_response(request, 1795445935.0, persona))
        assert answer['orig'] == 0x1234567890ABCDEF and answer['mode'] == ntp_probe.MODE_SERVER
        assert (answer['stratum'], answer['refid'], answer['precision'], answer['leap']) == (2, '192.0.2.7', -21, 0)
        assert ntp_probe.from_ntp(answer['recv']) == pytest.approx(1795445935.0 + 100.0, abs=1e-6)
        unsync = ntp_probe.parse_packet(ntp_probe.build_response(request, 1795445935.0,
                                                                 {'leap': 3, 'stratum': 16, 'refid': 'INIT'}))
        assert unsync['leap'] == 3 and unsync['ref'] == 0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture(scope='module')
def fake_server():
    """Two personalities of the fake server on 127.0.0.1 (a falseticker, an unsynchronised one)."""
    false_port, unsync_port = _free_port(), _free_port()
    personas = [{'address': '127.0.0.1', 'port': false_port, 'offset': 42.5, 'stratum': 2, 'refid': '10.1.2.3',
                 'precision': -21},
                {'address': '127.0.0.1', 'port': unsync_port, 'leap': 3, 'stratum': 16, 'refid': 'INIT'}]
    threading.Thread(target=ntp_probe.serve, args=(personas,), daemon=True).start()
    return false_port, unsync_port


class TestRoundTrip:
    def test_query(self, fake_server):
        false_port, unsync_port = fake_server
        answer = ntp_probe.query('127.0.0.1', port=false_port)
        assert answer['answered'] and answer['offset'] == pytest.approx(42.5, abs=0.05)
        assert answer['delay'] < 0.5 and answer['refid'] == '10.1.2.3' and answer['precision'] == -21
        unsync = ntp_probe.query('127.0.0.1', port=unsync_port)
        assert unsync['answered'] and unsync['leap'] == 3 and unsync['stratum'] == 16

    def test_no_answer(self):
        assert ntp_probe.query('127.0.0.1', port=_free_port(), timeout=0.3) == {'answered': False}

    def test_burst(self, fake_server):
        assert ntp_probe.burst('127.0.0.1', port=fake_server[0], count=10, interval=0.01, wait=0.5) == {
            'sent': 10, 'answered': 10}

    def test_check_runs_the_probes_concurrently(self, fake_server):
        results = ntp_probe.run_check([
            {'id': 'q', 'kind': 'query', 'server': '127.0.0.1', 'port': fake_server[0]},
            {'id': 'b', 'kind': 'burst', 'server': '127.0.0.1', 'port': fake_server[0], 'count': 5, 'interval': 0.01,
             'wait': 0.3},
            {'id': 'odd', 'kind': 'nothing'},
        ])
        assert results['q']['answered'] and results['b'] == {'sent': 5, 'answered': 5}
        assert 'error' in results['odd']

    def test_chronyd_synced_pattern(self):
        out = "2026-11-23T14:53:15Z System clock wrong by -0.000026 seconds (ignored)\n"
        assert float(ntp_probe.CHRONY_SYNCED.search(out).group(1)) == pytest.approx(-0.000026)
        assert ntp_probe.CHRONY_SYNCED.search("No suitable source for synchronisation") is None
