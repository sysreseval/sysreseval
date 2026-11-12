"""Tests of lib/rsyslog.py and lib/syslog_probe.py: the parsers on outputs captured live in
tests/mock_data/rsyslog/ (z04, 2026-11-12: rsyslog 8.2302, logrotate 3.21 of Debian 12), the
shell pieces of the commands run for real (the awk of the logrotate sandbox, the bounded wait of
the reader), the probe against local UDP / TCP / TLS servers, the renderers and the histories."""
import base64
import json
import socket
import ssl
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import rsyslog as rs  # noqa: E402
import syslog_probe  # noqa: E402

DATA = _REPO / 'tests' / 'mock_data' / 'rsyslog'
LOGROTATE_REMOTE = """/var/log/remote/*/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
"""


def fixture(name):
    return (DATA / name).read_text()


def make_grade(responses: dict):
    grade = MagicMock()
    grade.test.side_effect = lambda machine, command, step=1, **kwargs: responses.get(command, ('', 0))
    return grade


# ---------------------------------------------------------------------------
# markers
# ---------------------------------------------------------------------------


class TestMarkers:
    def test_pri(self):
        assert rs.syslog_pri("local3", "warning") == 156 and rs.syslog_pri("local7", "info") == 190
        assert rs.syslog_pri("auth", "err") == 35

    def test_marker_forms(self):
        assert rs.marker_text("tok", "udp") == "sreprobe.tok.udp.{epoch}"
        assert rs.shell_marker("tok", "fwd_web1") == "sreprobe.tok.fwd_web1.$(date +%s)"

    def test_collected_lines(self):
        lines = rs.parse_marked_lines(fixture('collect_logsrv_probe.txt'), 'tok1')
        assert rs.where(lines, 'udp') == {'/var/log/remote/sw-3fa1/sre-probe.log'}
        assert rs.where(lines, 'udp_other') == {'/var/log/remote/sw-3fa1/sre-other.log'}
        assert rs.where(lines, 'tcp') == {'/var/log/remote/fw-9c20/sre-probe.log'}
        assert rs.where(lines, 'tls_web1') == rs.where(lines, 'tls_app1') == {'/var/log/remote/ap-71be/sre-probe.log'}
        assert rs.where(lines, 'tls_rogue') == set() and rs.where(lines, 'tls_nocert') == set()
        assert {l.epoch for l in lines} == {1794449008}
        assert rs.parse_marked_lines(fixture('collect_logsrv_probe.txt'), 'other') == []

    def test_fresh(self):
        lines = rs.parse_marked_lines(fixture('collect_logsrv_probe.txt'), 'tok1')
        assert len(rs.fresh(lines, 1794449009)) == len(lines)        # 2 s of slack
        assert rs.fresh(lines, 1794449011) == [] and rs.fresh(lines, None) == []
        assert rs.parse_t0("T0=1794449000\n") == 1794449000 and rs.parse_t0("") is None

    def test_local_rules(self):
        lines = rs.parse_marked_lines(fixture('collect_app1_local.txt'), 'tok1')
        assert rs.where(lines, 'p1_info') == {'/var/log/shop/shop.log'}
        assert rs.where(lines, 'p1_err') == {'/var/log/shop/shop.log', '/var/log/shop/alert.log'}
        assert rs.where(lines, 'p1_control') == {'/var/log/syslog'}

    def test_line_without_path_and_access_log(self):
        line = ('127.0.0.1 - - [12/Nov/2026:02:03:49 +0000] "GET /sreprobe.tok1.imfile_web1.1794449029 HTTP/1.1" '
                '404 153 "-" "curl/7.88.1"')
        (marked,) = rs.parse_marked_lines(line, 'tok1')
        assert (marked.path, marked.msg_id, marked.epoch) == ('', 'imfile_web1', 1794449029)


# ---------------------------------------------------------------------------
# sockets, configuration, logrotate, probe output
# ---------------------------------------------------------------------------


class TestParsers:
    def test_established(self):
        assert rs.parse_established(fixture('ss_established_plain_tls.txt')) == [(514, '172.18.0.3'), (6514, '172.18.0.4')]
        assert rs.parse_established(fixture('ss_established_tls.txt')) == [(6514, '172.18.0.4'), (6514, '172.18.0.3')]
        assert rs.parse_established("") == []

    def test_configuration_checks(self):
        tls = rs.render_forward_conf("logsrv.corp.lan", 6514, tls={"ca": "/c", "cert": "/w", "key": "/k"})
        lines = rs.active_config_lines("# comment\n" + tls + "\n===RC 0\n")
        assert rs.has_disk_queue(lines) and rs.has_name_auth(lines, "logsrv.corp.lan")
        assert not rs.has_name_auth(lines, "other.lan")
        assert rs.has_disk_queue(["*.* @@logsrv:514", "$ActionQueueFileName fwd", "$ActionResumeRetryCount -1"])
        assert not rs.has_disk_queue(['action(type="omfwd" target="logsrv" port="514" protocol="tcp")'])
        plain = rs.active_config_lines(rs.render_forward_conf("logsrv.corp.lan"))
        assert rs.has_disk_queue(plain) and not rs.has_name_auth(plain, "logsrv.corp.lan")

    def test_logrotate_conf(self):
        (block,) = rs.parse_logrotate_conf(LOGROTATE_REMOTE)
        assert block.patterns == ['/var/log/remote/*/*.log'] and block.value('rotate') == '14'
        assert block.has('daily') and block.has('compress') and 'rsyslog-rotate' in block.scripts['postrotate']
        assert rs.glob_covers('/var/log/remote/*/*.log', '/var/log/remote/web1/sre-probe.log')
        assert not rs.glob_covers('/var/log/remote/*.log', '/var/log/remote/web1/sre-probe.log')
        assert rs.block_for([block], '/var/log/remote/app1/x.log') is block
        two = rs.parse_logrotate_conf("/var/log/a.log\n/var/log/b.log\n{\n weekly\n rotate 4\n}\n/x/*.log { daily }\n")
        assert two[0].patterns == ['/var/log/a.log', '/var/log/b.log'] and two[0].value('rotate') == '4'
        assert two[1].patterns == ['/x/*.log']

    def test_logrotate_debug(self):
        ok = rs.parse_logrotate_debug(fixture('logrotate_debug_ok.txt'))
        assert ok == {"ran": True, "rc": 0, "errors": [], "patterns": ['/var/log/remote/*/*.log']}
        error = rs.parse_logrotate_debug(fixture('logrotate_debug_error.txt'))
        assert error["rc"] == 1 and error["errors"][0] == '/tmp/bad.conf:3 argument expected after rotate count'
        assert not rs.parse_logrotate_debug('')["ran"]

    def test_probe_output(self):
        results = rs.parse_syslog_probe(fixture('probe_first.txt'))
        assert results['udp']['sent'] and results['tls_app1']['handshake'] and results['tls_app1']['verified']
        assert results['tls_app1']['tls_version'] == 'TLSv1.3'
        assert not results['tls_badname']['verified']                 # sent again without checking
        assert rs.parse_syslog_probe('') == {} and rs.parse_syslog_probe('x\n===RC 1\n') == {}

    def test_rotated(self):
        after = rs.parse_marked_lines(fixture('rotated_after_hup.txt'), 'tok1')
        assert rs.where(after, 'udp') == {'/var/log/remote/sw-3fa1/sre-probe.log.1'}
        assert rs.where(after, 'after_rotate') == {'/var/log/remote/sw-3fa1/sre-probe.log'}
        without = rs.parse_marked_lines(fixture('rotated_without_hup.txt'), 'tok1')
        assert rs.where(without, 'after_nohup') == {'/var/log/remote/sw-3fa1/sre-probe.log.1'}


# ---------------------------------------------------------------------------
# shell pieces, run for real
# ---------------------------------------------------------------------------


def _sandbox_conf(tmp_path, source_text, name='remote'):
    """What the awk of logrotate_sandbox_cmd makes of *source_text* (logrotate not run)."""
    source = tmp_path / name
    if source_text is not None:
        source.write_text(source_text)
    command = rs.logrotate_sandbox_cmd(str(source), str(tmp_path / 'ghost'))
    awk_part = command.split("; ", 2)[2].split(f" > {rs.SANDBOX_CONF}")[0]
    out = subprocess.run(["sh", "-c", f"d={tmp_path / 'ghost'}; {awk_part}"], capture_output=True, text=True, timeout=10)
    return out.stdout


class TestShell:
    def test_sandbox_one_line_header(self, tmp_path):
        text = _sandbox_conf(tmp_path, LOGROTATE_REMOTE)
        (block,) = rs.parse_logrotate_conf(text)
        assert block.patterns == [f"{tmp_path}/ghost/*.log"] and block.value('rotate') == '14'
        assert 'rsyslog-rotate' in block.scripts['postrotate']

    def test_sandbox_never_widens_the_rotation(self, tmp_path):
        # a header on two lines: the first pattern line must not survive
        text = _sandbox_conf(tmp_path, "# remote logs\n/var/log/remote/*/*.log\n{\n  daily\n  rotate 7\n}\n/var/log/x.log {\n weekly\n}\n")
        assert "/var/log/remote/*/*.log" not in text and "/var/log/x.log" not in text
        (block,) = rs.parse_logrotate_conf(text)
        assert block.patterns == [f"{tmp_path}/ghost/*.log"] and block.value('rotate') == '7'
        assert _sandbox_conf(tmp_path, None, name='absent') == ""                      # no file, nothing to rotate

    def test_collect_waits_then_reads(self, tmp_path):
        remote = tmp_path / 'remote' / 'h'
        remote.mkdir(parents=True)
        (remote / 'a.log').write_text("x sreprobe.tok.udp.1794449008\ny sreprobe.tok.tcp.1794449008\n")
        command = rs.collect_cmd('tok', [str(tmp_path / 'remote')], str(tmp_path / 'remote'), expected=2, max_wait=5)
        out = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=20).stdout
        lines = rs.parse_marked_lines(out, 'tok')
        assert {l.msg_id for l in lines} == {'udp', 'tcp'} and out.endswith("===RC 0\n")
        assert all(l.path.endswith('/h/a.log') for l in lines)


# ---------------------------------------------------------------------------
# lib/syslog_probe.py against local servers
# ---------------------------------------------------------------------------


def _ca_and_server(tmp_path):
    sys.path.insert(0, str(_REPO / 'src'))
    import tls
    ca_cert, ca_key = tls.generate_ca_pem("CA test")
    cert, key = tls.generate_server_cert_pem(ca_cert, ca_key, "logsrv.corp.lan")
    client_cert, client_key = tls.generate_server_cert_pem(ca_cert, ca_key, "web1.corp.lan")
    for name, text in (("ca.crt", ca_cert), ("srv.crt", cert), ("srv.key", key), ("cli.crt", client_cert),
                       ("cli.key", client_key)):
        (tmp_path / name).write_text(text)
    return tmp_path


class _Collector:
    """UDP, TCP and TLS listeners on loopback ports, keeping what they receive."""

    def __init__(self, tmp_path):
        self.received = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.tcp = socket.create_server(("127.0.0.1", 0))
        self.tls_sock = socket.create_server(("127.0.0.1", 0))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tmp_path / "srv.crt", tmp_path / "srv.key")
        # no client verification here: OpenSSL (unlike the GnuTLS of rsyslog) refuses a client
        # certificate whose extended key usage is serverAuth only; refusing peers is rsyslog's job
        self.context = context
        for target in (self._udp, self._tcp, self._tls):
            threading.Thread(target=target, daemon=True).start()

    def ports(self):
        return self.udp.getsockname()[1], self.tcp.getsockname()[1], self.tls_sock.getsockname()[1]

    def _udp(self):
        while True:
            data, _ = self.udp.recvfrom(4096)
            self.received.append(("udp", data.decode()))

    def _tcp(self):
        while True:
            conn, _ = self.tcp.accept()
            with conn:
                self.received.append(("tcp", conn.recv(4096).decode()))

    def _tls(self):
        while True:
            conn, _ = self.tls_sock.accept()
            try:
                with self.context.wrap_socket(conn, server_side=True) as s:
                    self.received.append(("tls", s.recv(4096).decode()))
            except (ssl.SSLError, OSError):
                conn.close()


class TestSyslogProbe:
    def test_frame(self):
        frame = syslog_probe.frame({"pri": 134, "hostname": "sw-3fa1", "tag": "sre-probe",
                                    "text": "sreprobe.t.udp.{epoch}"}, 1794449008.5)
        assert frame.startswith(b"<134>") and frame.endswith(b" sw-3fa1 sre-probe: sreprobe.t.udp.1794449008")

    def test_three_transports(self, tmp_path):
        certs = _ca_and_server(tmp_path)
        collector = _Collector(certs)
        udp, tcp, tls_port = collector.ports()
        tls_member = {"ca": str(certs / "ca.crt"), "cert": str(certs / "cli.crt"), "key": str(certs / "cli.key"),
                      "server_name": "logsrv.corp.lan"}
        messages = [rs.syslog_message("udp", "127.0.0.1", "tok", port=udp, hostname="sw-1"),
                    rs.syslog_message("tcp", "127.0.0.1", "tok", proto="tcp", port=tcp, hostname="fw-2"),
                    rs.syslog_message("tls_member", "127.0.0.1", "tok", proto="tls", port=tls_port, hostname="ap-3",
                                      tls=tls_member),
                    rs.syslog_message("tls_badname", "127.0.0.1", "tok", proto="tls", port=tls_port, hostname="ap-3",
                                      tls=dict(tls_member, server_name="wrong.corp.lan")),
                    rs.syslog_message("tls_nocert", "127.0.0.1", "tok", proto="tls", port=tls_port, hostname="ap-3",
                                      tls={"ca": str(certs / "ca.crt"), "server_name": "logsrv.corp.lan"}),
                    rs.syslog_message("closed", "127.0.0.1", "tok", proto="tcp", port=1, hostname="x")]
        command = rs.syslog_probe_cmd(messages, timeout=2)
        spec = command.split()[2]
        answer = syslog_probe.run(syslog_probe.decode_spec(spec))
        results = rs.parse_syslog_probe(json.dumps(answer) + "\n===RC 0\n")
        assert results['udp']['sent'] and results['tcp']['sent']
        assert results['tls_member']['handshake'] and results['tls_member']['verified'] and results['tls_member']['sent']
        assert results['tls_badname']['sent'] and results['tls_badname']['verified'] is False
        assert results['tls_nocert']['sent'] and results['tls_nocert']['handshake']
        assert results['closed']['error'] and not results['closed']['sent']
        import time
        for _ in range(50):
            if len(collector.received) >= 5:
                break
            time.sleep(0.1)
        texts = " ".join(t for _, t in collector.received)
        for msg_id in ('udp', 'tcp', 'tls_member', 'tls_badname', 'tls_nocert'):
            assert f"sreprobe.tok.{msg_id}.{answer['time']}" in texts

    def test_bad_spec(self):
        out = subprocess.run([sys.executable, str(_REPO / 'lib' / 'syslog_probe.py'), '!!'],
                             capture_output=True, text=True, timeout=20)
        assert 'bad spec' in json.loads(out.stdout)['error']


# ---------------------------------------------------------------------------
# renderers, histories, commands, wrappers
# ---------------------------------------------------------------------------


class TestRenderers:
    def test_collector(self):
        text = rs.render_collector_conf(tls={"ca": "/c", "cert": "/s", "key": "/k", "peers": ["web1.corp.lan", "app1.corp.lan"]})
        assert 'input(type="imtcp" port="6514" ruleset="remote"' in text
        assert 'permittedPeer=["web1.corp.lan","app1.corp.lan"]' in text
        assert '/var/log/remote/%HOSTNAME:::secpath-replace%/%PROGRAMNAME:::secpath-replace%.log' in text
        assert '6514' not in rs.render_collector_conf()

    def test_forward_imfile_rules_logrotate(self):
        assert 'port="514"' in rs.render_forward_conf("logsrv.corp.lan") and 'global(' not in rs.render_forward_conf("x")
        assert rs.render_imfile_conf("/var/log/nginx/access.log", "nginx-access:").endswith(
            'if $syslogtag == "nginx-access:" then stop\n')
        rules = rs.render_facility_rules("local3", "/var/log/shop/shop.log", "/var/log/shop/alert.log")
        assert rules.startswith('if $syslogfacility-text == "local3" then {') and "stop" in rules
        (block,) = rs.parse_logrotate_conf(rs.render_logrotate("/var/log/remote/*/*.log", 21))
        assert block.value('rotate') == '21' and block.has('daily') and block.has('compress')

    def test_shop(self):
        script = rs.render_shopd("local4", "/opt/shop/log/audit.log")
        assert script.startswith("#!/bin/bash") and "-p local4.warning" in script
        assert "ExecStart=/usr/local/sbin/shopd" in rs.render_shopd_unit("/usr/local/sbin/shopd")


class TestHistories:
    def test_bruteforce_and_scan(self):
        start, end = datetime(2026, 11, 10, 6, 0), datetime(2026, 11, 10, 6, 40)
        lines = rs.ssh_bruteforce_lines("203.0.113.7", 120, start, end, "app1", 7)
        assert len(lines) == 120 and rs.failed_by_ip("\n".join(lines)) == {"203.0.113.7": 120}
        assert lines == rs.ssh_bruteforce_lines("203.0.113.7", 120, start, end, "app1", 7)
        scan = rs.http_scan_lines("198.51.100.9", 50, start, end, 3)
        assert rs.requests_by_ip("\n".join(scan)) == {"198.51.100.9": 50}

    def test_merge_by_time(self):
        merged = rs.merge_by_time("Nov 10 05:00:00 h a\nNov 10 07:00:00 h c\n", ["Nov 10 06:00:00 h b"])
        assert [l[-1] for l in merged.splitlines()] == ["a", "b", "c"]
        clf = rs.merge_by_time('1 - - [10/Nov/2026:07:00:00 +0000] "c"\n', ['2 - - [10/Nov/2026:06:00:00 +0000] "b"'], clf=True)
        assert clf.splitlines()[0].startswith("2 ")


class TestCommands:
    def test_single_line(self):
        commands = [rs.t0_cmd(), rs.logger_cmd("t", "p1_info", "local3.info"), rs.append_marker_cmd("/a", "t", "x", "AUDIT "),
                    rs.http_marker_cmd("t", "x"), rs.collect_cmd("t", ["/var/log/remote"], "/var/log/remote", 11, 8),
                    rs.established_cmd(), rs.config_dump_cmd(), rs.config_check_cmd(), rs.cat_cmd(rs.LOGROTATE_FILE),
                    rs.logrotate_debug_cmd(), rs.logrotate_sandbox_cmd(rs.LOGROTATE_FILE, "/var/log/remote/sw-1"),
                    rs.rotated_cmd("/var/log/remote/sw-1", "t"), rs.syslog_probe_cmd([rs.syslog_message("u", "h", "t")])]
        for command in commands:
            assert "\n" not in command and "@@@" not in command
        spec = rs.syslog_probe_cmd([rs.syslog_message("u", "10.0.0.1", "t")]).split()[2]
        assert json.loads(base64.urlsafe_b64decode(spec + "=="))["messages"][0]["text"] == "sreprobe.t.u.{epoch}"

    def test_wrappers(self):
        grade = make_grade({rs.t0_cmd(): ("T0=1794449000\n", 0),
                            rs.established_cmd(): (fixture('ss_established_tls.txt'), 0),
                            rs.cat_cmd(rs.LOGROTATE_FILE): (LOGROTATE_REMOTE + "===RC 0\n", 0),
                            rs.logrotate_debug_cmd(): (fixture('logrotate_debug_ok.txt'), 0)})
        assert rs.get_t0(grade, 'logsrv') == 1794449000
        assert rs.get_established(grade, 'logsrv') == [(6514, '172.18.0.4'), (6514, '172.18.0.3')]
        assert rs.parse_logrotate_conf(rs.get_file(grade, 'logsrv', rs.LOGROTATE_FILE))[0].value('rotate') == '14'
        assert rs.get_logrotate_debug(grade, 'logsrv')["rc"] == 0
        empty = make_grade({})
        assert rs.get_t0(empty, 'x') is None and rs.get_file(empty, 'x', '/f') is None
        assert rs.collect_lines(empty, 'x', 't', ['/var/log']) == [] and rs.get_active_config(empty, 'x') == []
        assert rs.syslog_probe(empty, 'probe', []) == {}
