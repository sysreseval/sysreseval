"""Tests for lib/voip.py and lib/sip_probe.py (the VoIP lab: Asterisk 22 / chan_pjsip, baresip).

The fixtures of tests/mock_data/voip/ were captured live on 2026-11-11 (z04, sysreseval/voip:1.32 =
Asterisk 22.12.0 compiled in images/voip/Dockerfile): the Asterisk console outputs of a PBX holding
the reference configuration of lab/sre/_DRAFT_misc2/voip.py (``pjsip_show_*``, ``dialplan_show_*``,
``rtp_show_settings``, ``voicemail_*``, each followed by the ``===RC`` marker of
``voip.asterisk_rx_cmd``), the contacts of the running lab once solved (``pjsip_show_contacts_nat``:
the NAT phones registered with the box's public address), and the outputs of the probe against
that PBX (``run_office.json`` = ``sip_probe.py run``, ``kick_office.json`` = ``kick``,
``daemon_log_office.jsonl`` = the log of the persistent phones).

The end-to-end tests run the probe on loopback: a caller agent against the phones of a daemon
(no PBX in between), and against a fake registrar written here (UDP, digest checked
independently) and a fake TLS registrar.
"""
import base64
import hashlib
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

import sip_probe as probe  # noqa: E402
import voip  # noqa: E402
from voip import (  # noqa: E402
    PROBE_PATH, TONES, ScenarioResult, asterisk_rx, asterisk_rx_cmd, asterisk_start_cmd, baresip_start_cmd,
    call_scenario, codec_list, console_output, contacts_of, daemon_account, daemon_calls, daemon_log_cmd,
    daemon_spec, dialplan_applications, encode_spec, find_calls, flag, get_contacts, get_dialplan, get_endpoint,
    get_phone_calls, get_voicemail_messages, install_sip_probe, parse_contacts, parse_daemon_log, parse_dialplan,
    parse_identifies, parse_kick, parse_parameters, parse_probe_run, parse_rtp_settings, parse_transports,
    parse_voicemail_messages, register_scenario, render_baresip_account, render_baresip_config, run_spec,
    sip_daemon_cmd, sip_kick, sip_kick_cmd, sip_probe, sip_run_cmd, start_sip_daemon, voicemail_cleanup_cmd,
    voicemail_dump_cmd,
)

FIXTURES = Path(__file__).parent / 'mock_data' / 'voip'


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def console(name: str) -> str:
    return console_output(fixture(name))


def make_grade(responses: dict | None = None):
    """Grade mock dispatching on (machine, command); ('', 0) = the placeholder of a registration pass."""
    grade = MagicMock()
    responses = responses or {}

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get((machine_name, command), ('', 0))

    grade.test.side_effect = _test
    return grade


def spec_of(command: str) -> dict:
    """The spec of a probe command line (the word after the sub-command)."""
    words = command.split()
    return json.loads(base64.urlsafe_b64decode(words[words.index(PROBE_PATH) + 2]))


def one_line(command: str) -> bool:
    return '\n' not in command and '@@@' not in command


# ---------------------------------------------------------------------------
# sip_probe.py: audio, RTP, SIP messages, digest, SDP
# ---------------------------------------------------------------------------

class TestG711:
    def test_known_codes(self):
        assert probe.lin2alaw(0) == 0xD5 and probe.lin2ulaw(0) == 0xFF
        assert probe.ALAW_DECODE[0xD5] == 8 and probe.ULAW_DECODE[0xFF] == 0

    @pytest.mark.parametrize('sample', [-32768, -12345, -1000, -100, -1, 0, 1, 100, 1000, 12345, 32767])
    def test_round_trip(self, sample):
        for encode, table in ((probe.lin2alaw, probe.ALAW_DECODE), (probe.lin2ulaw, probe.ULAW_DECODE)):
            assert abs(table[encode(sample)] - sample) <= max(16, abs(sample) * 0.07)

    def test_monotonic(self):
        for table, encode in ((probe.ALAW_DECODE, probe.lin2alaw), (probe.ULAW_DECODE, probe.lin2ulaw)):
            values = [table[encode(s)] for s in range(-32000, 32001, 250)]
            assert values == sorted(values)


class TestTones:
    @staticmethod
    def feed(detector, tone, packets=60):
        for _ in range(packets):
            detector.feed([probe.ALAW_DECODE[byte] for byte in tone.next_payload()])

    def test_detects_its_frequency(self):
        detector = probe.ToneDetector(TONES)
        self.feed(detector, probe.Tone(640, 'PCMA'))
        result = detector.result()
        assert result['tones'] == {'640': result['windows']} and result['windows'] == 4

    def test_neighbours_are_told_apart(self):
        for freq in (560, 640, 720):
            detector = probe.ToneDetector(TONES)
            self.feed(detector, probe.Tone(freq, 'PCMU', ptime=30), packets=40)
            assert list(detector.result()['tones']) == [str(freq)]

    def test_silence_and_noise(self):
        detector = probe.ToneDetector(TONES)
        detector.feed([0] * 4000)
        detector.feed([((n * 7919) % 2001) - 1000 for n in range(4000)])  # broadband
        result = detector.result()
        assert result['silent'] == 2 and result['other'] == 2 and result['tones'] == {}

    def test_packet_size_follows_ptime(self):
        assert len(probe.Tone(400, ptime=20).next_payload()) == 160
        assert len(probe.Tone(400, ptime=40).next_payload()) == 320


class TestRtp:
    def test_round_trip(self):
        packet = probe.rtp_packet(8, 65535, 2 ** 32 - 1, 0x1234, b'\xd5' * 160, marker=True)
        assert probe.parse_rtp(packet) == (8, True, 65535, 2 ** 32 - 1, 0x1234, b'\xd5' * 160)

    def test_extension_and_padding(self):
        header = bytearray(probe.rtp_packet(0, 1, 2, 3, b''))
        header[0] |= 0x10 | 0x20  # extension + padding
        packet = bytes(header) + b'\xbe\xde\x00\x01' + b'\x00' * 4 + b'audio' + b'\x00\x00\x03'
        assert probe.parse_rtp(packet)[5] == b'audio'

    def test_not_rtp(self):
        assert probe.parse_rtp(b'short') is None and probe.parse_rtp(b'\x00' * 20) is None

    def test_dtmf(self):
        payload = probe.dtmf_payload(probe.DTMF_EVENTS['#'], 1280, end=True)
        assert probe.parse_dtmf(payload) == (11, True, 1280) and probe.DTMF_DIGITS[11] == '#'


REGISTER = (
    "REGISTER sip:10.0.0.2 SIP/2.0\r\n"
    "v: SIP/2.0/UDP 10.0.0.5:5071;branch=z9hG4bKabc;rport\r\n"
    "f: <sip:1003@10.0.0.2>;tag=t1\r\n"
    "t: <sip:1003@10.0.0.2>\r\n"
    "i: call1@10.0.0.5\r\n"
    "CSeq: 2 REGISTER\r\n"
    "m: <sip:1003@10.0.0.5:5071>\r\n"
    "User-Agent: phone\r\n"
    "  model 2\r\n"
    "l: 0\r\n\r\n")


class TestSipMessages:
    def test_parse_request_with_compact_and_folded_headers(self):
        message = probe.parse_message(REGISTER.encode())
        assert message.is_request and message.method == 'REGISTER' and message.uri == 'sip:10.0.0.2'
        assert message.get('call-id') == 'call1@10.0.0.5' and message.get('contact') == '<sip:1003@10.0.0.5:5071>'
        assert message.get('user-agent') == 'phone model 2'
        assert message.cseq() == (2, 'REGISTER') and message.branch() == 'z9hG4bKabc'

    def test_parse_response(self):
        message = probe.parse_message(b"SIP/2.0 486 Busy Here\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
        assert not message.is_request and message.status == 486 and message.reason == 'Busy Here'

    def test_encode_sets_the_length(self):
        message = probe.SipMessage(status=200, reason='OK', headers=[('Content-Length', '99')], body='v=0\r\n')
        data = message.encode()
        assert data.count(b'Content-Length') == 1 and b'Content-Length: 5\r\n\r\nv=0\r\n' in data
        assert probe.parse_message(data).body == 'v=0\r\n'

    def test_garbage(self):
        assert probe.parse_message(b'\x00\x01 hello') is None and probe.parse_message(b'') is None

    @pytest.mark.parametrize('value, expected', [
        ('"Alice Martin" <sip:1001@pbx.corp.tp;transport=tls>;tag=abc',
         ('Alice Martin', 'sip:1001@pbx.corp.tp;transport=tls', '1001', 'pbx.corp.tp', None, 'abc')),
        ('<sip:1006@192.168.1.4:5071>', ('', 'sip:1006@192.168.1.4:5071', '1006', '192.168.1.4', 5071, '')),
        ('Bob <sip:2001@10.0.0.9>', ('Bob', 'sip:2001@10.0.0.9', '2001', '10.0.0.9', None, '')),
        ('sip:10.0.0.9:5060;tag=x', ('', 'sip:10.0.0.9:5060', '', '10.0.0.9', 5060, 'x')),
    ])
    def test_name_addr(self, value, expected):
        parts = probe.parse_name_addr(value)
        assert (parts['display'], parts['uri'], parts['user'], parts['host'], parts['port'], parts['tag']) == expected


class TestDigest:
    CHALLENGE = ('Digest realm="testrealm@host.com", qop="auth,auth-int", '
                 'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')

    def test_rfc2617_example(self):
        challenge = probe.parse_challenge(self.CHALLENGE)
        value = probe.digest_authorization(challenge, 'GET', '/dir/index.html', 'Mufasa', 'Circle Of Life',
                                           cnonce='0a4f113b')
        assert 'response="6629fae49393a05397450978507c4ef1"' in value
        assert 'qop=auth' in value and 'nc=00000001' in value and 'opaque="5ccc069c403ebaf9f0171e9517f40e41"' in value

    def test_without_qop(self):
        challenge = probe.parse_challenge('Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"')
        value = probe.digest_authorization(challenge, 'GET', '/dir/index.html', 'Mufasa', 'Circle Of Life')
        assert 'response="670fd8c2df070c60b045671b8b24ff02"' in value and 'qop' not in value

    def test_pick_challenge(self):
        values = ['Basic realm="x"', 'Digest realm="a", nonce="n", algorithm=SHA-512-256',
                  'Digest realm="a", nonce="n", algorithm=SHA-256', 'Digest realm="a", nonce="n"']
        assert probe.pick_challenge(values)['algorithm'] == 'SHA-256'
        assert probe.pick_challenge(values[:2]) is None
        assert probe.pick_challenge(['Digest realm="asterisk",nonce="1/2",opaque="o",algorithm=MD5,qop="auth"'])[
            'nonce'] == '1/2'


ASTERISK_ANSWER = (
    "v=0\r\no=- 1803 1805 IN IP4 10.0.0.2\r\ns=Asterisk\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\n"
    "m=audio 16154 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\na=ptime:20\r\na=maxptime:150\r\na=sendrecv\r\n")


class TestSdp:
    def test_parse_an_answer(self):
        sdp = probe.parse_sdp(ASTERISK_ANSWER)
        assert (sdp['address'], sdp['port'], sdp['profile'], sdp['payloads']) == ('10.0.0.2', 16154, 'RTP/AVP', [8, 101])
        assert sdp['ptime'] == 20 and sdp['telephone_event'] == 101 and sdp['crypto'] == []
        assert probe.pick_codec(sdp) == 'PCMA'

    def test_round_trip_with_srtp(self):
        offer = probe.build_sdp('10.0.0.5', 40000, ['PCMU', 'GSM', 'PCMA'], ptime=30, srtp_key=b'k' * 30)
        sdp = probe.parse_sdp(offer)
        assert sdp['profile'] == 'RTP/SAVP' and sdp['payloads'] == [0, 3, 8, 101] and sdp['ptime'] == 30
        assert sdp['crypto'][0].startswith('1 AES_CM_128_HMAC_SHA1_80 inline:')
        assert sdp['codecs'] == {'0': 'PCMU/8000', '3': 'GSM/8000', '8': 'PCMA/8000', '101': 'telephone-event/8000'}

    def test_media_address_wins_over_the_session_one(self):
        sdp = probe.parse_sdp("v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP4 2.2.2.2\r\n")
        assert sdp['address'] == '2.2.2.2' and sdp['codecs'] == {'0': 'PCMU/8000'}

    def test_no_audio(self):
        assert probe.parse_sdp('') == {} and probe.parse_sdp("v=0\r\nm=video 5000 RTP/AVP 96\r\n") == {}
        assert probe.pick_codec({'payloads': [3, 9]}) is None


# ---------------------------------------------------------------------------
# sip_probe.py end to end, on loopback
# ---------------------------------------------------------------------------

class FakeDaemon:
    """What a Phone needs of its daemon, the log kept in memory."""
    local_ip = '127.0.0.1'
    listen = list(TONES)

    def __init__(self):
        self.stopped = threading.Event()
        self.entries = []

    def log(self, entry):
        self.entries.append({'t': time.time(), **entry})

    def write_status(self):
        pass


@pytest.fixture
def phones():
    daemon = FakeDaemon()
    made = {}

    def make(user, mode='answer', tone=None, codecs=None):
        account = {'user': user, 'password': 'x', 'server': '127.0.0.1', 'port': 9, 'mode': mode, 'tone': tone,
                   'max_call': 20}
        if codecs:
            account['codecs'] = codecs
        made[user] = probe.Phone(daemon, account)
        return made[user]

    yield daemon, make
    daemon.stopped.set()
    for phone in made.values():
        phone.agent.close()


def call_to(phone, scenario_id, **more):
    """A call scenario towards *phone* directly (its agent plays the PBX's role)."""
    return {'id': scenario_id, 'kind': 'call', 'server': '127.0.0.1', 'port': phone.agent.local_port,
            'user': '1004', 'password': 'pw', **more}


def wait_entries(daemon, count, timeout=5.0):
    end = time.time() + timeout
    while len(daemon.entries) < count and time.time() < end:
        time.sleep(0.05)
    return daemon.entries


class TestCalls:
    def test_answered_call_tones_both_ways_and_digits(self, phones):
        daemon, make = phones
        callee = make('1003', tone=640)
        run = probe.run({'local_ip': '127.0.0.1', 'listen': list(TONES), 'deadline': 20, 'tracks': [[
            call_to(callee, 'call', to='1003', tone=960, duration=1.5, display='Probe',
                    codecs=['PCMU', 'GSM', 'PCMA'], dtmf=[{'at': 0.3, 'digits': '7#'}])]]})
        result = run['results']['call']
        assert run['errors'] == [] and result['status'] == 200 and result['answered'] and result['bye'] == 'sent'
        assert result['provisional'] == [100, 180] and result['sdp']['payloads'] == [0, 101]
        assert 640 in result['rtp']['heard'] and result['rtp']['sources']
        entry = wait_entries(daemon, 1)[0]
        assert (entry['action'], entry['from_user'], entry['from_display'], entry['ruri_user']) == (
            'answered', '1004', 'Probe', '1003')
        assert entry['end'] == 'received' and 960 in entry['rtp']['heard'] and entry['rtp']['digits'] == '7#'
        assert entry['offer']['payloads'] == [0, 3, 8, 101]

    def test_busy_refused_and_unanswered(self, phones):
        daemon, make = phones
        busy, gsm_only, absent = make('1004', mode='busy'), make('1005', tone=400), make('1009', mode='none')
        run = probe.run({'local_ip': '127.0.0.1', 'deadline': 20, 'tracks': [
            [call_to(busy, 'busy', to='1004')],
            [call_to(gsm_only, 'refused', to='1005', codecs=['GSM'])],
            [call_to(absent, 'absent', to='1009')]]})
        results = run['results']
        assert results['busy']['status'] == 486 and not results['busy']['answered']
        assert results['refused']['status'] == 488 and results['absent']['status'] == 486
        actions = {entry['user']: entry['action'] for entry in wait_entries(daemon, 2)}
        assert actions == {'1004': 'busy', '1005': 'refused'}

    def test_deadline(self):
        start = time.time()
        run = probe.run({'local_ip': '127.0.0.1', 'deadline': 1, 'tracks': [[
            {'id': 'long', 'kind': 'sleep', 'seconds': 30}, {'id': 'next', 'kind': 'sleep', 'seconds': 1}]]})
        assert time.time() - start < 6 and run['errors'] == ['deadline reached']
        assert run['results']['next'] == {'error': 'deadline'} and 'long' in run['results']

    def test_main_prints_one_document(self, capsys):
        spec = run_spec('127.0.0.1', [[{'id': 'nap', 'kind': 'sleep', 'seconds': 0.1}]])
        assert probe.main(['sre_sip_probe.py', 'run', encode_spec(spec)]) == 0
        document = json.loads(capsys.readouterr().out)
        assert document['errors'] == [] and document['results']['nap']['error'] is None
        assert probe.main(['sre_sip_probe.py', 'run', 'not-base64!']) == 0
        assert json.loads(capsys.readouterr().out)['results'] == {}
        assert probe.main(['sre_sip_probe.py', 'nothing']) == 2

    def test_kick_without_daemon(self, tmp_path, capsys):
        assert probe.command_kick(str(tmp_path / 'status'), str(tmp_path / 'pid'), timeout=0.2) == 0
        assert json.loads(capsys.readouterr().out)['alive'] is False


class FakeRegistrar(threading.Thread):
    """A UDP registrar on loopback: 401 with a digest challenge (qop=auth), 200 when the answer
    matches *passwords*; the digest is computed here, independently of the probe."""

    REALM, NONCE = 'sre', 'n0nce'

    def __init__(self, passwords):
        super().__init__(daemon=True)
        self.passwords = passwords
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.bindings = {}
        self.requests = []
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            try:
                data, source = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            request = probe.parse_message(data)
            if request is not None and request.is_request:
                self.requests.append(request)
                self.handle(request, source)

    def reply(self, request, status, reason, source, headers=()):
        lines = [('Via', via) for via in request.get_all('via')]
        lines += [('From', request.get('from')), ('To', request.get('to') + ';tag=reg'),
                  ('Call-ID', request.get('call-id')), ('CSeq', request.get('cseq')), *headers]
        self.sock.sendto(probe.SipMessage(status=status, reason=reason, headers=lines).encode(), source)

    def valid(self, request, user):
        params = probe.parse_challenge(request.get('authorization'))
        if user not in self.passwords or params.get('username') != user:
            return False

        def md5(text):
            return hashlib.md5(text.encode()).hexdigest()

        ha1 = md5(f"{user}:{self.REALM}:{self.passwords[user]}")
        ha2 = md5(f"REGISTER:{params['uri']}")
        return params.get('response') == md5(f"{ha1}:{self.NONCE}:{params['nc']}:{params['cnonce']}:auth:{ha2}")

    def handle(self, request, source):
        user = probe.parse_name_addr(request.get('to'))['user']
        if not request.get('authorization') or not self.valid(request, user):
            self.reply(request, 401, 'Unauthorized', source, [
                ('WWW-Authenticate', f'Digest realm="{self.REALM}",nonce="{self.NONCE}",algorithm=MD5,qop="auth"')])
            return
        contact, expires = request.get('contact'), request.get('expires')
        if contact:
            if expires == '0':
                self.bindings.pop(user, None)
            else:
                self.bindings[user] = contact
        headers = [('Contact', f'{self.bindings[user]};expires={expires}')] if user in self.bindings else []
        self.reply(request, 200, 'OK', source, headers)


@pytest.fixture
def registrar():
    server = FakeRegistrar({'1003': 'secret3'})
    server.start()
    yield server
    server.stop.set()
    server.join(2)


class TestRegister:
    def test_query_bad_password_and_binding(self, registrar):
        tracks = [[register_scenario('query', '127.0.0.1', 1003, 'secret3', port=registrar.port),
                   register_scenario('bad', '127.0.0.1', 1003, 'wrong', port=registrar.port),
                   register_scenario('unknown', '127.0.0.1', 1099, 'x', port=registrar.port),
                   register_scenario('bind', '127.0.0.1', 1003, 'secret3', contact=True, expires=45,
                                     port=registrar.port)]]
        results = probe.run(run_spec('127.0.0.1', tracks, deadline=20))['results']
        query, bad, unknown, bind = (results[name] for name in ('query', 'bad', 'unknown', 'bind'))
        assert query['status'] == 200 and query['challenged'] and query['realm'] == 'sre' and query['qop'] == 'auth'
        assert query['contacts'] == [] and bad['status'] == 401 and unknown['status'] == 401
        assert bind['status'] == 200 and bind['expires'] == 45 and bind['unregistered'] == 200
        assert registrar.bindings == {}  # the binding was removed at the end
        assert not [r for r in registrar.requests if r.get('authorization') and not r.get('contact')
                    and r.get('expires')]  # a query carries neither Contact nor Expires

    def test_phone_registers_and_reports(self, registrar):
        daemon = FakeDaemon()
        phone = probe.Phone(daemon, {'user': '1003', 'password': 'secret3', 'server': '127.0.0.1',
                                     'port': registrar.port, 'mode': 'busy', 'expires': 60})
        try:
            phone.start()
            end = time.time() + 5
            while not phone.status['registered'] and time.time() < end:
                time.sleep(0.05)
            assert phone.status['registered'] and phone.status['expires'] == 60
            assert daemon.entries[0]['event'] == 'register' and daemon.entries[0]['status'] == 200
            assert registrar.bindings['1003'] == f'<sip:1003@127.0.0.1:{phone.agent.local_port}>'
        finally:
            daemon.stopped.set()
            phone.kick.set()
            phone.agent.close()


class FakeTlsRegistrar(threading.Thread):
    """A SIP-over-TLS server answering 200 to every REGISTER."""

    def __init__(self, cert_file, key_file):
        super().__init__(daemon=True)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_file, key_file)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.handshakes = 0
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.serve, args=(connection,), daemon=True).start()

    def serve(self, connection):
        try:
            with self.context.wrap_socket(connection, server_side=True) as tls:
                self.handshakes += 1
                buffer = b''
                while True:
                    chunk = tls.recv(65535)
                    if not chunk:
                        return
                    buffer += chunk
                    while b'\r\n\r\n' in buffer:
                        head, buffer = buffer.split(b'\r\n\r\n', 1)
                        request = probe.parse_message(head + b'\r\n\r\n')
                        lines = [('Via', v) for v in request.get_all('via')]
                        lines += [(k, request.get(k)) for k in ('From', 'To', 'Call-ID', 'CSeq')]
                        tls.sendall(probe.SipMessage(status=200, reason='OK', headers=lines).encode())
        except (ssl.SSLError, OSError):
            return


class TestTls:
    def test_verified_and_refused_names(self, tmp_path):
        tls = pytest.importorskip('tls')
        ca_cert, ca_key = tls.generate_ca_pem('Test CA')
        cert, key = tls.generate_server_cert_pem(ca_cert, ca_key, 'pbx.test')
        (tmp_path / 'ca.pem').write_text(ca_cert)
        (tmp_path / 'cert.pem').write_text(cert)
        (tmp_path / 'key.pem').write_text(key)
        server = FakeTlsRegistrar(str(tmp_path / 'cert.pem'), str(tmp_path / 'key.pem'))
        server.start()
        try:
            common = dict(port=server.port, transport='tls', ca_file=str(tmp_path / 'ca.pem'))
            results = probe.run(run_spec('127.0.0.1', [[
                register_scenario('good', '127.0.0.1', 1007, 'x', contact=True, server_name='pbx.test', **common),
                register_scenario('wrong_name', '127.0.0.1', 1007, 'x', server_name='other.test', **common),
            ]], deadline=20))['results']
        finally:
            server.stop.set()
        good, wrong = results['good'], results['wrong_name']
        assert good['status'] == 200 and good['unregistered'] == 200
        assert good['tls']['verified'] and good['tls']['version'].startswith('TLS')
        assert wrong['status'] is None and wrong['tls']['verified'] is False and 'other.test' in wrong['tls']['error']


# ---------------------------------------------------------------------------
# voip.py: probe commands and results
# ---------------------------------------------------------------------------

class TestSpecs:
    def test_accounts_and_specs(self):
        account = daemon_account(1003, 'pw', '10.0.0.2', 5071, tone=640, rtp_port=40000,
                                 calls=daemon_calls(334, every=25, codec='PCMU', ptime=40))
        assert account == {'user': '1003', 'password': 'pw', 'server': '10.0.0.2', 'port': 5060, 'sip_port': 5071,
                           'mode': 'answer', 'expires': 120, 'retry': 10, 'max_call': 120, 'tone': 640,
                           'rtp_port': 40000, 'calls': {'number': '334', 'every': 25, 'duration': 5,
                                                        'codec': 'PCMU', 'ptime': 40}}
        spec = daemon_spec('10.0.0.5', [account])
        assert spec['local_ip'] == '10.0.0.5' and spec['listen'] == list(TONES) and spec['accounts'] == [account]

    def test_scenarios_omit_the_defaults(self):
        assert register_scenario('r', '10.0.0.2', 1003, 'pw') == {
            'id': 'r', 'kind': 'register', 'server': '10.0.0.2', 'port': 5060, 'user': '1003', 'password': 'pw',
            'expires': 60, 'unregister': True}
        scenario = call_scenario('c', '10.0.0.2', 1004, 'pw', 600, tone=1040, port=5061, transport='tls',
                                 ca_file='/ca.pem', server_name='pbx.test', srtp=True)
        assert scenario['to'] == '600' and scenario['srtp'] and scenario['transport'] == 'tls'
        assert 'display' not in scenario and 'dtmf' not in scenario and 'voicemail' not in scenario

    def test_command_lines(self):
        spec = run_spec('10.0.0.5', [[call_scenario('c', '10.0.0.2', 1004, 'pw', 1003, tone=960)]], deadline=30)
        for command in (sip_run_cmd(spec), sip_daemon_cmd(spec), sip_kick_cmd(), daemon_log_cmd(),
                        asterisk_start_cmd(), asterisk_rx_cmd('pjsip show endpoint 1003'), voicemail_dump_cmd(1004),
                        voicemail_cleanup_cmd(1004, 1003), baresip_start_cmd()):
            assert one_line(command), command
        assert spec_of(sip_run_cmd(spec)) == spec and spec_of(sip_daemon_cmd(spec, ensure=True)) == spec
        assert sip_daemon_cmd(spec, ensure=True).split()[2] == 'ensure'
        assert sip_run_cmd(spec) == sip_run_cmd(json.loads(json.dumps(spec)))  # canonical: stable across passes

    def test_install_and_start(self):
        net_scheme = MagicMock()
        start_sip_daemon(net_scheme, 'probe', daemon_spec('10.0.0.5', []), step=3)
        args, kwargs = net_scheme.file.call_args
        assert args[:2] == ('probe', PROBE_PATH) and args[2].startswith('#!/usr/bin/env python3')
        assert kwargs == {'permissions': 0o755, 'step': 3}
        command = net_scheme.cmd.call_args[0][1]
        assert ' daemon ' in command and net_scheme.cmd.call_args[1] == {'step': 3}
        net_scheme.reset_mock()
        install_sip_probe(net_scheme, 'probe')
        assert net_scheme.file.call_count == 1 and net_scheme.cmd.call_count == 0


class TestResults:
    def test_probe_run_fixture(self):
        run = parse_probe_run(fixture('run_office.json'))
        assert run.errors == [] and set(run) >= {'reg_ok', 'reg_bad', 'internal', 'echo', 'foreign', 'voicemail'}
        assert run['reg_ok'].status == 200 and run['reg_bad'].status == 401 and run['reg_ok'].realm == 'asterisk'
        internal = run['internal']
        assert internal.answered and internal.hears(480) and not internal.hears(640)
        assert internal.payloads == [8, 101] and internal.tos_values == {184}
        assert internal.source_hosts() == {'10.250.77.10'} == internal.source_hosts(tail=True)
        assert 16000 <= internal.media_port <= 16198 and not internal.reinvites
        assert run['foreign'].status == 488 and run['foreign'].refused and not run['internal'].refused
        assert run['unknown_number'].status == 404 and run['voicemail'].pound
        assert run['echo'].hears(720) and run['ivr1'].hears(480)

    def test_absent_and_placeholder(self):
        run = parse_probe_run(fixture('run_office.json'))
        absent = run['not-run']
        assert not absent.ran and not absent.refused and not absent.answered and absent.heard == []
        assert parse_probe_run('') == {} and parse_probe_run('Traceback (most recent call last):\n') == {}
        assert parse_probe_run('{"results": "nope"}') == {}

    def test_probe_wrapper(self):
        spec = run_spec('10.0.0.5', [[register_scenario('r', '10.0.0.2', 1003, 'pw')]])
        grade = make_grade({('probe', sip_run_cmd(spec)): ('noise\n' + fixture('run_office.json'), 0)})
        assert sip_probe(grade, 'probe', spec, step=2)['reg_ok'].status == 200
        grade.test.assert_called_once_with('probe', sip_run_cmd(spec), step=2, timeout=60, allow_error=True)
        assert sip_probe(make_grade(), 'probe', spec) == {}

    def test_kick(self):
        status = parse_kick(fixture('kick_office.json'))
        assert status.ran and status.alive and status.registered(1003) and status.registered('1004')
        assert not status.registered(1001) and status.status(1003) == 200
        stale = parse_kick(json.dumps({'alive': True, 'kicked': 100.0,
                                       'phones': {'1003': {'registered': True, 'status': 200, 't': 99.0}}}))
        assert not stale.registered(1003)  # registered before the request: not refreshed
        assert not parse_kick('').ran and not parse_kick('').registered(1003)
        spec = daemon_spec('10.0.0.5', [])
        grade = make_grade()
        sip_kick(grade, 'probe', spec)
        command = grade.test.call_args[0][1]
        assert ' ensure ' in command and command.endswith(sip_kick_cmd()) and one_line(command)

    def test_daemon_log(self):
        calls = parse_daemon_log(fixture('daemon_log_office.jsonl') + '\n===END\nnot json\n{"event": "start"}\n')
        assert [(c.user, c.action, c.from_user) for c in calls] == [
            ('1004', 'busy', '1003'), ('1003', 'answered', '1004'), ('1004', 'busy', '1003'), ('1003', 'answered', '1004')]
        answered = calls[1]
        assert answered.from_display == 'Dominique Petit' and answered.hears(640)
        assert answered.source_hosts() == {'10.250.77.10'} and answered.tos_values == {184}
        assert len(find_calls(calls, user=1003, action='answered')) == 2
        assert [c.heard for c in find_calls(calls, user='1003', heard=880)] == [[880]]
        assert find_calls(calls, user=1004, from_user=1003, since=calls[2].t) == [calls[2]]
        assert find_calls(calls, until=calls[0].t) == [calls[0]]
        grade = make_grade({('probe', daemon_log_cmd()): (fixture('daemon_log_office.jsonl'), 0)})
        assert len(get_phone_calls(grade, 'probe', step=3)) == 4 and get_phone_calls(make_grade(), 'probe') == []
        # the phones write a call once it is over: the reader waits a little
        assert daemon_log_cmd().startswith('sleep 2; tail -n 400 ') and not daemon_log_cmd(wait=0).startswith('sleep')


# ---------------------------------------------------------------------------
# voip.py: the Asterisk console
# ---------------------------------------------------------------------------

class TestConsole:
    def test_marker(self):
        assert console_output('text\n===RC 0\n') == 'text\n'
        assert console_output('Unable to connect to remote asterisk\n===RC 1\n') == ''
        assert console_output('') == '' and console_output('no marker') == ''

    def test_endpoint(self):
        endpoint = parse_parameters(console('pjsip_show_endpoint_1003.txt'))
        assert len(endpoint) > 100 and endpoint['context'] == 'internal' and endpoint['callerid'] == '"Camille Durand" <1003>'
        assert codec_list(endpoint) == ['alaw'] and not flag(endpoint, 'direct_media') and flag(endpoint, 'force_rport')
        assert endpoint['tos_audio'] == '184' and endpoint['mailboxes'] == '1003@default'
        assert parse_parameters(console('pjsip_show_endpoint_1007.txt'))['media_encryption'] == 'sdes'
        trunk = parse_parameters(console('pjsip_show_endpoint_site_b.txt'))
        assert (trunk['auth'], trunk['outbound_auth'], trunk['context']) == ('site-b-in', 'site-b-out', 'from-site-b')
        assert parse_parameters(console('pjsip_show_endpoint_missing.txt')) == {}

    def test_aor_and_codecs(self):
        aor = parse_parameters(console('pjsip_show_aor_1003.txt'))
        assert aor['max_contacts'] == '1' and flag(aor, 'remove_existing') and aor['qualify_frequency'] == '0'
        assert codec_list({'allow': '(ulaw|alaw|gsm)'}) == ['ulaw', 'alaw', 'gsm'] and codec_list({}) == []

    def test_contacts(self):
        contacts = parse_contacts(console('pjsip_show_contacts.txt'))
        assert [(c.aor, c.user, c.host, c.port) for c in contacts] == [
            ('1003', '1003', '10.250.77.20', 5071), ('1004', '1004', '10.250.77.20', 5072),
            ('site-b', '', '10.250.77.30', 5060)]
        nat = parse_contacts(console('pjsip_show_contacts_nat.txt'))
        # the URIs are cut at the width of the column: the host always comes out whole
        assert {c.aor: c.host for c in nat}['1006'] == '10.130.247.36' == contacts_of(nat, 1005)[0].host
        assert contacts_of(nat, '1001')[0].host == '10.158.92.155' and contacts_of(nat, 1099) == []
        assert {c.aor: c.status for c in nat}['1006'] == 'Avail'

    def test_transports_identifies_rtp(self):
        assert parse_transports(console('pjsip_show_transports.txt')) == [
            {'id': 'transport-tls', 'type': 'tls', 'cos': 0, 'tos': 0, 'bind': '0.0.0.0:5061'},
            {'id': 'transport-udp', 'type': 'udp', 'cos': 0, 'tos': 0, 'bind': '0.0.0.0:5060'}]
        assert parse_identifies(console('pjsip_show_identifies.txt')) == [
            {'name': 'site-b', 'endpoint': 'site-b', 'matches': ['10.250.77.30/32']}]
        assert parse_rtp_settings(console('rtp_show_settings.txt')) == {'port_start': 16000, 'port_end': 16198}
        assert parse_rtp_settings('') == {}

    def test_dialplan(self):
        internal = parse_dialplan(console('dialplan_show_internal.txt'))
        assert set(internal) == {'_1XXX', '_2XXX', '500', '600'}
        assert dialplan_applications(internal, '_1XXX') == ['dial', 'voicemail', 'hangup']
        assert internal['_1XXX'][1].arguments == '${EXTEN}@default,${IF($["${DIALSTATUS}" = "BUSY"]?b:u)}'
        assert internal['500'][0].arguments == 'ivr,s,1' and dialplan_applications(internal, '700') == []
        ivr = parse_dialplan(console('dialplan_show_ivr.txt'))
        assert ivr['s'][1].label == 'menu' and ivr['s'][1].application == 'Background'
        assert [s.priority for s in ivr['s']] == [1, 2, 3] and dialplan_applications(ivr, 'i') == ['playback', 'goto']
        assert parse_dialplan(console('dialplan_show_missing.txt')) == {}

    def test_voicemail(self):
        messages = parse_voicemail_messages(fixture('voicemail_messages.txt'))
        assert len(messages) == 1
        message = messages[0]
        assert (message.mailbox, message.caller, message.duration) == ('1004', '1003', 3)
        assert message.origtime == 1794432280 and message.file.endswith('/default/1004/INBOX/msg0000.txt')
        unnamed = parse_voicemail_messages('===MSG /x/msg0001.txt\n[message]\ncallerid=1003\nduration=2\n===END\n')
        assert unnamed[0].caller == '1003' and unnamed[0].origtime == 0
        assert parse_voicemail_messages('===END\n') == []

    @pytest.mark.skipif(sys.platform == 'win32', reason='POSIX shell')
    def test_voicemail_cleanup_removes_the_callers_messages_only(self, tmp_path):
        inbox = tmp_path / 'default' / '1004' / 'INBOX'
        inbox.mkdir(parents=True)
        callers = {'msg0000': '"Camille Durand" <1003>', 'msg0001': '1003', 'msg0002': '"Alice" <1001>',
                   'msg0003': '10031', 'msg0004': '"X" <10031>'}
        for name, callerid in callers.items():
            (inbox / f'{name}.txt').write_text(f'[message]\ncallerid={callerid}\nduration=3\n')
            (inbox / f'{name}.wav').write_bytes(b'RIFF')
        command = voicemail_cleanup_cmd(1004, 1003).replace(voip.VOICEMAIL_SPOOL, str(tmp_path))
        subprocess.run(['sh', '-c', command], check=True)
        assert sorted(p.name for p in inbox.iterdir()) == [
            'msg0002.txt', 'msg0002.wav', 'msg0003.txt', 'msg0003.wav', 'msg0004.txt', 'msg0004.wav']

    def test_wrappers_and_placeholders(self):
        command = asterisk_rx_cmd('pjsip show endpoint 1003')
        grade = make_grade({
            ('pbx', command): (fixture('pjsip_show_endpoint_1003.txt'), 0),
            ('pbx', asterisk_rx_cmd('pjsip show contacts')): (fixture('pjsip_show_contacts.txt'), 0),
            ('pbx', asterisk_rx_cmd('dialplan show ivr')): (fixture('dialplan_show_ivr.txt'), 0),
            ('pbx', voicemail_dump_cmd(1004)): (fixture('voicemail_messages.txt'), 0),
        })
        assert get_endpoint(grade, 'pbx', 1003)['context'] == 'internal'
        assert len(get_contacts(grade, 'pbx', step=3)) == 3 and set(get_dialplan(grade, 'pbx', 'ivr')) >= {'s', 'i'}
        assert get_voicemail_messages(grade, 'pbx', 1004)[0].caller == '1003'
        empty = make_grade()
        assert get_endpoint(empty, 'pbx', 1003) == {} and get_contacts(empty, 'pbx') == []
        assert get_dialplan(empty, 'pbx', 'internal') == {} and asterisk_rx(empty, 'pbx', 'core show uptime') == ''
        assert get_voicemail_messages(empty, 'pbx', 1004) == []


class TestBaresip:
    def test_config(self):
        config = render_baresip_config(tone=480, recordings='/shared/phone2', ca_file='/etc/ssl/ca.pem', srtp=True)
        lines = dict(line.split(None, 1) for line in config.splitlines() if line and not line.startswith('#')
                     and not line.startswith('module'))
        assert lines['audio_source'] == 'ausine,480' and lines['audio_player'] == 'none'
        assert lines['ausrc_srate'] == '48000' and lines['ausrc_channels'] == '2'  # what ausine requires
        assert lines['snd_path'] == '/shared/phone2' and lines['sip_cafile'] == '/etc/ssl/ca.pem'
        assert 'module\t\t\tsndfile.so' in config and 'module\t\t\tsrtp.so' in config
        assert 'alsa' not in config and 'sip_cafile' not in render_baresip_config()

    def test_account(self):
        assert render_baresip_account(1001, '10.0.0.2', 'pw') == '<sip:1001@10.0.0.2>;auth_pass=pw;regint=120\n'
        assert render_baresip_account(1007, 'pbx.corp.tp:5061', 'pw', transport='tls', mediaenc='srtp-mand') == (
            '<sip:1007@pbx.corp.tp:5061;transport=tls>;auth_pass=pw;regint=120;mediaenc=srtp-mand\n')
