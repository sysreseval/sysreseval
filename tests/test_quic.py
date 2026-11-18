"""Tests for lib/quic.py (the helpers of the QUIC lab) and the pure parts of lib/quic_probe.py
(quic-client).

The fixtures of tests/mock_data/quic/ are the outputs of the grader's own commands, taken from
the archives of two real evaluations of the lab (tests/mock_data/quic/lab/initial.zst: a fresh
project, solved.zst: the reference solution) on 2026-11-18 (images base13 / init13 1.33: nginx
1.30.6 from nginx.org with OpenSSL 3.5.7, curl 8.14.1, aioquic 1.2.0, tshark 4.4.19, BIND 9.20);
facts.json holds the addresses and the random values of that instance."""
import json
import socket
import struct
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import quic  # noqa: E402
import quic_probe as qp  # noqa: E402
from dns import parse_dig  # noqa: E402
from http_proxy import parse_reply  # noqa: E402
from openvpn import listener_process, parse_ss_listeners  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'quic'
FACTS = json.loads((MOCK / 'facts.json').read_text())


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def client_result(name: str) -> dict:
    return quic.parse_quic_client(fixture(f"quic_client_{name}.json").replace("\n", " "))


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


class TestStateSide:
    def test_install_quic_client(self):
        ns = MagicMock()
        quic.install_quic_client(ns, 'probe', step=2)
        args, kwargs = ns.file.call_args
        assert args[0] == 'probe' and args[1] == quic.CLIENT_PATH
        assert args[2].startswith('#!/usr/bin/python3') and 'def main(' in args[2]
        assert kwargs == {'permissions': 0o755, 'step': 2}

    def test_render_nginx_h3_server_default(self):
        conf = quic.render_nginx_h3_server('www.x.tp', '/c.crt', '/c.key', '/var/www/x')
        for line in ("listen 443 quic reuseport;", "listen 443 ssl;", "http2 on;", "http3 on;",
                     "server_name www.x.tp;", "ssl_certificate /c.crt;", "ssl_certificate_key /c.key;",
                     "add_header Alt-Svc 'h3=\":443\"; ma=86400' always;", "root /var/www/x;"):
            assert line in conf, line
        for absent in ("quic_retry", "quic_host_key", "ssl_early_data", "log_format", "Early-Data"):
            assert absent not in conf
        assert conf.count('{') == conf.count('}') == 1

    def test_render_nginx_h3_server_tuned(self):
        conf = quic.render_nginx_h3_server(
            'cdn.x.tp', '/c.crt', '/c.key', '/var/www/c', quic_ports=[8443], tcp=False, max_streams=77,
            keepalive_timeout=33, quic_retry=True, quic_host_key='/etc/nginx/k', early_data=True,
            early_data_header=True, access_log='/var/log/a.log', log_format=True,
            locations=[("= /order", ["if ($ssl_early_data) { return 425; }", 'return 200 "ok\\n";'])])
        assert conf.startswith(f"log_format {quic.ACCESS_LOG_FORMAT_NAME} ")
        for line in ("listen 8443 quic reuseport;", "http3_max_concurrent_streams 77;", "keepalive_timeout 33s;",
                     "quic_retry on;", "quic_host_key /etc/nginx/k;", "ssl_early_data on;",
                     f"access_log /var/log/a.log {quic.ACCESS_LOG_FORMAT_NAME};",
                     "add_header Early-Data $ssl_early_data always;", "location = /order {",
                     "if ($ssl_early_data) { return 425; }"):
            assert line in conf, line
        assert "listen 443 ssl;" not in conf
        assert quic.nginx_directive_values(conf, 'quic_host_key') == [['/etc/nginx/k']]

    def test_render_caddyfile(self):
        text = quic.render_caddyfile('https://www.x.tp:8444', '/etc/caddy/c.crt', '/etc/caddy/c.key', '/var/www/x')
        assert "auto_https off" in text and "https://www.x.tp:8444 {" in text
        assert "tls /etc/caddy/c.crt /etc/caddy/c.key" in text and "root * /var/www/x" in text

    def test_render_fw_ruleset(self):
        closed, opened = quic.render_fw_ruleset(), quic.render_fw_ruleset(quic=True)
        assert closed == fixture('nftables_initial.conf') and opened == fixture('nftables_quic.conf')
        assert "udp dport 443" not in closed and 'iifname "eth1" oifname "eth0" udp dport 443 accept' in opened
        assert 'masquerade random' in closed and 'policy drop' in closed


# ---------------------------------------------------------------------------
# quic-client from the grader
# ---------------------------------------------------------------------------


class TestQuicClientCommand:
    def test_cmd(self):
        cmd = quic.quic_client_cmd('migrate', ['https://cdn.quic.tp/'], '192.0.2.5/24', 443, timeout=6,
                                   connections=5, step_timeout=2, zero_rtt=False, token=None)
        assert cmd == ("/usr/local/bin/quic-client migrate --json --timeout 6 --connect 192.0.2.5:443 "
                       "--connections 5 --step-timeout 2 https://cdn.quic.tp/ 2>/dev/null")
        assert "--zero-rtt" in quic.quic_client_cmd('get', ['https://x/'], zero_rtt=True)
        assert "--connect" not in quic.quic_client_cmd('get', ['https://x/'])
        assert "--connect 192.0.2.5 " in quic.quic_client_cmd('get', ['https://x/'], '192.0.2.5')

    def test_parse(self):
        assert quic.parse_quic_client('') == {}
        assert quic.parse_quic_client('garbage\n{not json') == {}
        assert quic.parse_quic_client('noise\n{"command": "get", "retry": true}\n') == {'command': 'get', 'retry': True}

    def test_run_budget(self):
        grade = MagicMock()
        grade.test.return_value = ('{"command": "migrate", "migrated": 5}', 0)
        result = quic.run_quic_client(grade, 'probe', 'migrate', ['https://x/'], '192.0.2.5', 443, step=2,
                                      timeout=6, connections=5, step_timeout=2)
        assert result['migrated'] == 5
        args, kwargs = grade.test.call_args
        assert args[0] == 'probe' and kwargs['step'] == 2 and kwargs['allow_error'] is True
        assert kwargs['timeout'] == 6 * 4 + 10 + 5 * 4

    def test_migrate_fixtures(self):
        failing, working = client_result('migrate_initial'), client_result('migrate_final')
        assert working['migrated'] == 5 and len(working['connections']) == 5
        assert all(c['path_challenges_received'] >= 1 for c in working['connections'])
        assert failing['migrated'] < 5
        assert any(s['error'] == 'TimeoutError' for c in failing['connections'] for s in c['steps'])

    def test_get_fixtures(self):
        before, after = client_result('get_initial'), client_result('get_final')
        assert before['retry'] is False and after['retry'] is True
        for r in (before, after):
            assert r['alpn'] == 'h3' and r['version'] == '0x00000001'
            assert quic.response_of(r, '/')['status'] == 200
        assert quic.response_of(after, '/missing') == {}

    def test_resume_fixtures(self):
        before, after = client_result('resume_initial'), client_result('resume_final')
        assert before['second']['session_resumed'] is True and before['second']['early_data_accepted'] is False
        assert quic.response_header(quic.response_of(before['second'], '/'), 'early-data') == ''
        assert quic.response_of(before['second'], '/order')['status'] == 200
        second = after['second']
        assert second['early_data_accepted'] is True and second['retry'] is False   # NEW_TOKEN: no Retry
        assert quic.response_header(quic.response_of(second, '/'), 'Early-Data') == '1'
        assert quic.response_of(second, '/order')['status'] == 425
        assert quic.response_of(after['first'], '/order')['status'] == 200
        assert after['first']['retry'] is True and after['token_received'] is True


# ---------------------------------------------------------------------------
# Alt-Svc, curl
# ---------------------------------------------------------------------------


class TestAltSvc:
    @pytest.mark.parametrize('value, expected', [
        ('h3=":443"; ma=86400', [{'alpn': 'h3', 'host': '', 'port': 443, 'ma': 86400}]),
        ('h3=":8444"; ma=2592000, h3-29=":8444"', [{'alpn': 'h3', 'host': '', 'port': 8444, 'ma': 2592000},
                                                   {'alpn': 'h3-29', 'host': '', 'port': 8444, 'ma': None}]),
        ('h2="alt.example.tp:443"', [{'alpn': 'h2', 'host': 'alt.example.tp', 'port': 443, 'ma': None}]),
        ('clear', []), ('', []), ('garbage', []),
    ])
    def test_parse(self, value, expected):
        assert quic.parse_alt_svc(value) == expected

    def test_offers(self):
        assert quic.alt_svc_offers('h3=":443"; ma=86400')
        assert not quic.alt_svc_offers('h3=":8443"; ma=86400')
        assert not quic.alt_svc_offers('h2=":443"')
        assert not quic.alt_svc_offers('h3="other.tp:443"')

    def test_curl_fixtures(self):
        h3, h2 = parse_reply(fixture('curl_h3_web.txt')), parse_reply(fixture('curl_h2_web.txt'))
        assert h3.ok and h3.http_version == '3' and FACTS['web_token'] in h3.body
        assert h2.ok and h2.http_version == '2' and quic.alt_svc_offers(h2.header('alt-svc'))
        timeout = parse_reply(fixture('curl_h3_timeout.txt'), 28)
        assert timeout.code is None and timeout.http_version == ''


# ---------------------------------------------------------------------------
# nginx, access log, sockets
# ---------------------------------------------------------------------------


class TestNginx:
    def test_strip_comments(self):
        assert quic.strip_comments("a 1; # c\n# whole\nb '#x';") == "a 1; \n\nb '#x';"

    def test_directives_tuned(self):
        dump = fixture('nginx_T_edge_tuned.txt')
        assert quic.nginx_test_ok(dump)
        assert quic.nginx_directive_values(dump, 'quic_bpf') == [['on']]
        assert quic.nginx_directive_values(dump, 'quic_retry') == [['on']]
        assert quic.nginx_directive_values(dump, 'quic_host_key') == [['/etc/nginx/quic_host.key']]
        assert quic.nginx_directive_values(dump, 'ssl_early_data') == [['on']]
        assert ['4'] in quic.nginx_directive_values(dump, 'worker_processes')

    def test_directives_default(self):
        dump = fixture('nginx_T_edge_default.txt')
        for name in ('quic_bpf', 'quic_retry', 'quic_host_key', 'ssl_early_data'):
            assert quic.nginx_directive_values(dump, name) == [], name
        assert quic.nginx_directive_values("# quic_bpf on;\nhttp { }", 'quic_bpf') == []
        assert not quic.nginx_test_ok("nginx: [emerg] unknown directive")

    def test_files_status_cmd(self):
        cmd = quic.nginx_files_status_cmd('quic_host_key', '/etc/nginx/quic_host.key')
        assert cmd.startswith("for f in $(nginx -T 2>/dev/null | sed -n -E 's/^[[:space:]]*quic_host_key")
        assert "/etc/nginx/quic_host.key; do" in cmd and '\n' not in cmd
        assert quic.parse_file_status(fixture('host_key_status.txt')) == {'/etc/nginx/quic_host.key': (80, 0o600)}
        assert quic.parse_file_status(fixture('host_key_status_missing.txt')) == {'/etc/nginx/quic_host.key': None}

    def test_access_log(self):
        entries = quic.parse_access_log(fixture('news_access.log') + "a line in another format\n")
        assert entries and all(set(e) == {'remote', 'time', 'protocol', 'status', 'method', 'path'} for e in entries)
        mine = quic.requests_from(entries, FACTS['client'] + '/24', protocol='HTTP/3.0', path='/h3-secret.txt',
                                  status=200)
        assert mine and mine[0]['method'] == 'GET'
        assert quic.requests_from(entries, FACTS['client'], protocol='HTTP/1.1') == []
        assert quic.requests_from(entries, '192.0.2.250') == []
        assert {e['protocol'] for e in entries} >= {'HTTP/2.0', 'HTTP/3.0'}

    def test_udp_listeners(self):
        listeners = parse_ss_listeners(fixture('ss_ulnp_web.txt'))
        assert listener_process(listeners, 443) == 'nginx' and listener_process(listeners, 8444) == 'caddy'


# ---------------------------------------------------------------------------
# captures
# ---------------------------------------------------------------------------


class TestCaptures:
    def test_cmd(self):
        cmd = quic.tshark_quic_cmd('/shared/q.pcapng', '/shared/q.keys')
        for piece in ("tshark -n -r /shared/q.pcapng -c 4000 -d udp.port==443,quic",
                      "-o tls.keylog_file:/shared/q.keys", "-Y 'quic && udp.port == 443'", "-E separator=/t",
                      "-e http3.headers.path", "2>/dev/null"):
            assert piece in cmd, piece
        assert "keylog" not in quic.tshark_quic_cmd('/shared/q.pcapng')

    def test_plain_capture(self):
        rows = quic.parse_tshark_rows(fixture('tshark_plain.txt'))
        assert rows and all(len(r) == len(quic.TSHARK_FIELDS) for r in rows)
        summary = quic.capture_summary(rows, FACTS['client'], FACTS['ref'])
        assert summary.packets == len(rows)
        assert summary.long_types.get('initial', 0) >= 2 and summary.long_types.get('handshake', 0) >= 1
        assert summary.short_packets > 0 and not summary.decrypted

    def test_decrypted_capture(self):
        summary = quic.capture_summary(quic.parse_tshark_rows(fixture('tshark_keylog.txt')), FACTS['client'],
                                       FACTS['ref'])
        assert summary.decrypted
        assert ('GET', '/') in summary.requests and ('GET', '/h3-secret.txt') in summary.requests
        assert '200' in summary.statuses
        # the unidirectional streams nginx opens: control (0) and QPACK decoder (3), no encoder
        assert {int(t, 16) for t in summary.uni_stream_types} == {0, 3}

    def test_other_hosts_ignored(self):
        rows = quic.parse_tshark_rows(fixture('tshark_keylog.txt'))
        assert quic.capture_summary(rows, FACTS['client'], FACTS['web']).packets == 0
        assert quic.capture_summary(rows, FACTS['client'], FACTS['ref'], port=8443).packets == 0
        assert quic.parse_tshark_rows("garbage\n\n") == []

    def test_file_status(self):
        files = quic.parse_file_status(fixture('file_status.txt'))
        assert files['/shared/quic.pcapng'][0] > 1000 and files['/shared/quic.keys'][1] == 0o644
        assert quic.parse_file_status(fixture('file_status_missing.txt')) == {'/shared/quic.pcapng': None,
                                                                            '/shared/quic.keys': None}
        cmd = quic.file_status_cmd('/a b', '/c')
        assert cmd.startswith("for f in '/a b' /c; do") and '\n' not in cmd

    def test_keylog_labels(self):
        text = ("# comment\nCLIENT_HANDSHAKE_TRAFFIC_SECRET aa01 bb02\nSERVER_TRAFFIC_SECRET_0 aa01 cc03\n"
                "CLIENT_TRAFFIC_SECRET_0 aa01 dd04\nCLIENT_TRAFFIC_SECRET_0 ff00 ee05\nbroken line\n")
        assert quic.keylog_labels(text) == {'CLIENT_HANDSHAKE_TRAFFIC_SECRET': 1, 'SERVER_TRAFFIC_SECRET_0': 1,
                                            'CLIENT_TRAFFIC_SECRET_0': 2}


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


class TestHttpsRecord:
    @pytest.mark.parametrize('rdata, expected', [
        ('1 . alpn="h3,h2"', {'priority': 1, 'target': '.', 'params': {'alpn': 'h3,h2'}, 'alpn': ['h3', 'h2']}),
        ('1 . alpn="h3,h2" port=443 ipv4hint=192.0.2.1',
         {'priority': 1, 'target': '.', 'params': {'alpn': 'h3,h2', 'port': '443', 'ipv4hint': '192.0.2.1'},
          'alpn': ['h3', 'h2']}),
        ('0 www.news.tp.', {'priority': 0, 'target': 'www.news.tp.', 'params': {}, 'alpn': []}),
        ('1 . alpn=h2 no-default-alpn', {'priority': 1, 'target': '.', 'params': {'alpn': 'h2', 'no-default-alpn': ''},
                                         'alpn': ['h2']}),
    ])
    def test_parse(self, rdata, expected):
        assert quic.parse_https_rr(rdata) == expected

    @pytest.mark.parametrize('rdata', ['', 'x . alpn=h3', '1', '1 . alpn="unterminated'])
    def test_invalid(self, rdata):
        assert quic.parse_https_rr(rdata) is None

    def test_dig_fixtures(self):
        answer = parse_dig(fixture('dig_https.txt'))
        assert answer.has_flag('aa')
        rrs = [quic.parse_https_rr(r) for r in answer.rdata('HTTPS')]
        assert rrs == [{'priority': 1, 'target': '.', 'params': {'alpn': 'h3,h2'}, 'alpn': ['h3', 'h2']}]
        assert parse_dig(fixture('dig_https_none.txt')).rdata('HTTPS') == []


# ---------------------------------------------------------------------------
# quic-client: the parts that need no aioquic
# ---------------------------------------------------------------------------


class TestQuicProbePure:
    @pytest.mark.parametrize('value, expected', [
        (None, (None, 443)), ('192.0.2.1', ('192.0.2.1', 443)), ('192.0.2.1:8443', ('192.0.2.1', 8443)),
        ('[2001:db8::1]:8443', ('2001:db8::1', 8443)), ('[2001:db8::1]', ('2001:db8::1', 443)),
        ('2001:db8::1', ('2001:db8::1', 443)),
    ])
    def test_parse_connect(self, value, expected):
        assert qp.parse_connect(value, 443) == expected

    def test_parse_header(self):
        assert qp.parse_header('X-Test:  a: b ') == ('x-test', 'a: b')
        with pytest.raises(ValueError):
            qp.parse_header('no colon')

    def test_vn_probe(self):
        packet = qp.build_vn_probe(b'\x01' * 8, b'\x02' * 8)
        assert len(packet) == qp.MIN_INITIAL_SIZE
        assert packet[0] & 0xC0 == 0xC0 and struct.unpack('!I', packet[1:5])[0] == qp.GREASE_VERSION
        assert packet[5] == 8 and packet[6:14] == b'\x01' * 8 and packet[14] == 8 and packet[15:23] == b'\x02' * 8

    def test_parse_vn(self):
        vn = bytes([0x80 | 0x2a]) + b'\x00\x00\x00\x00' + bytes([8]) + b'\x02' * 8 + bytes([8]) + b'\x01' * 8 \
            + struct.pack('!II', 1, 0x6B3343CF)
        assert qp.parse_vn(vn) == {'dcid': '02' * 8, 'scid': '01' * 8, 'versions': ['0x00000001', '0x6b3343cf']}
        assert qp.parse_vn(b'\x40' + b'\x00' * 20) is None                   # short header
        assert qp.parse_vn(b'\xc0\x00\x00\x00\x01' + b'\x00' * 10) is None   # a version-1 long header
        assert qp.parse_vn(b'\x80\x00') is None

    def test_version_name(self):
        assert qp.version_name(1).startswith('QUIC v1') and qp.version_name(0x6B3343CF).startswith('QUIC v2')
        assert qp.version_name(0x1A2A3A4A) == '0x1a2a3a4a' and qp.version_name(None) == '?'

    def test_vn_against_a_fake_server(self, capsys):
        """`quic-client vn` against a UDP server that answers like nginx (QUIC v1 only)."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0))
        port = server.getsockname()[1]

        def answer():
            data, addr = server.recvfrom(2048)
            dlen = data[5]
            dcid = data[6:6 + dlen]
            slen = data[6 + dlen]
            scid = data[7 + dlen:7 + dlen + slen]
            server.sendto(b'\x80\x00\x00\x00\x00' + bytes([len(scid)]) + scid + bytes([len(dcid)]) + dcid
                          + struct.pack('!I', 1), addr)

        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        try:
            assert qp.main(['vn', '127.0.0.1', str(port), '--json']) == 0
        finally:
            thread.join(2)
            server.close()
        result = json.loads(capsys.readouterr().out)
        assert result['answer']['versions'] == ['0x00000001']
        assert result['answer']['dcid'] == result['scid'] and result['answer']['scid'] == result['dcid']

    def test_vn_timeout(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        try:
            result = qp.run_vn('127.0.0.1', sock.getsockname()[1], 0.3)
        finally:
            sock.close()
        assert result['answer'] is None and result['error'] == 'timeout'
