"""Tests of lib/fail2ban.py, lib/intranet_app.py and the ``--bind`` option of lib/login_probe.py.

The ``fail2ban-client`` outputs of tests/mock_data/fail2ban/ were captured live on s17 (2026-11-23,
fail2ban 1.1.0 of Debian 13) in the Suricata / fail2ban lab.
"""
import json
import shlex
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import fail2ban  # noqa: E402
import intranet_app  # noqa: E402
import login_probe  # noqa: E402

_MOCK = _REPO / 'tests' / 'mock_data' / 'fail2ban'


class TestParsers:
    def test_jails(self):
        assert fail2ban.parse_jails((_MOCK / 'status.txt').read_text()) == ['intranet', 'sshd']
        assert fail2ban.parse_jails("Status\n|- Number of jail:\t0\n`- Jail list:\t\n") == []
        assert fail2ban.parse_jails("") == []

    def test_jail_status(self):
        status = fail2ban.parse_jail_status((_MOCK / 'status_sshd_banned.txt').read_text())
        assert status['exists'] and status['currently_banned'] == len(status['banned']) >= 1
        assert status['total_failed'] >= status['currently_failed'] >= 0
        empty = fail2ban.parse_jail_status("")
        assert empty == {'exists': False, 'currently_failed': None, 'total_failed': None,
                         'currently_banned': None, 'banned': []}

    def test_ignoreip_and_seconds(self):
        assert fail2ban.parse_ignoreip("No IP address/network is ignored\n") == []
        text = "These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n|- ::1\n`- 10.5.0.0/24\n"
        assert fail2ban.parse_ignoreip(text) == ['127.0.0.0/8', '10.5.0.0/24']
        assert fail2ban.parse_seconds("3600") == 3600 and fail2ban.parse_seconds("600.0") == 600
        assert fail2ban.parse_seconds(None) is None and fail2ban.parse_seconds("1h") is None

    def test_tcp_open(self):
        cmd = fail2ban.tcp_open_cmd('10.1.1.10', 22, '198.18.1.5', tag='_x')
        assert 'nc -z -w 3 -s 198.18.1.5 10.1.1.10 22' in cmd and 'OPEN_x' in cmd and 'CLOSED_x' in cmd
        assert fail2ban.parse_tcp_open("foo\nOPEN_x\n", "_x") is True
        assert fail2ban.parse_tcp_open("CLOSED_x\n", "_x") is False
        assert fail2ban.parse_tcp_open("OPEN_y\n", "_x") is None


class TestCommands:
    def test_ssh_failures(self):
        cmd = fail2ban.ssh_failures_cmd('10.1.1.10', 'student', "it's wrong", 4, '198.18.1.5')
        assert cmd.startswith('for i in $(seq 4); do python3 /usr/local/sbin/sre_login_probe.py --timeout 12 '
                              '--bind 198.18.1.5 ssh 10.1.1.10 student ')
        assert shlex.quote("it's wrong") in cmd
        assert '--bind' not in fail2ban.ssh_failures_cmd('h', 'u', 'p', 2)

    def test_http_logins(self):
        cmd = fail2ban.http_logins_cmd('http://intranet/login', 'x from=198.18.1.9', 'nope', 4, '198.18.1.8')
        assert "--interface 198.18.1.8" in cmd and "--data-urlencode user='x from=198.18.1.9'" in cmd
        assert cmd.endswith('; done; echo') and "-w '%{http_code} '" in cmd

    def test_unban_and_jail(self):
        assert fail2ban.unban_cmd(['1.2.3.4', '5.6.7.8']) == "fail2ban-client unban 1.2.3.4 5.6.7.8 >/dev/null 2>&1; true"
        assert fail2ban.render_jail('web', port='http', maxretry=3) == "[web]\nenabled = true\nport = http\nmaxretry = 3\n"


@pytest.fixture
def app(tmp_path):
    users = tmp_path / 'users.json'
    users.write_text(json.dumps({'demo': 'secret'}))
    log = tmp_path / 'log' / 'auth.log'
    log.parent.mkdir()
    server = ThreadingHTTPServer(('127.0.0.1', 0), intranet_app.make_handler({'demo': 'secret'}, str(log)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", log
    server.shutdown()
    server.server_close()


def _post(url, **fields):
    data = urllib.parse.urlencode(fields).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class TestIntranetApp:
    def test_clean_user(self):
        assert intranet_app.clean_user("a\nb\x00c") == "a?b?c"
        assert len(intranet_app.clean_user("x" * 100)) == 64
        assert intranet_app.clean_user("x from=10.0.0.1") == "x from=10.0.0.1"

    def test_logins_and_health(self, app):
        url, log = app
        assert _post(url + "/login", user="demo", password="secret") == (200, "Bienvenue demo\n")
        assert _post(url + "/login", user="x from=10.9.9.9", password="no")[0] == 401
        assert _post(url + "/login", user="evil\n2026-01-01 00:00:00 FAILED login user=a from=1.2.3.4",
                     password="no")[0] == 401
        with urllib.request.urlopen(url + "/health", timeout=5) as r:
            assert r.read() == b"OK\n"
        with urllib.request.urlopen(url + "/", timeout=5) as r:
            assert b'action="/login"' in r.read()
        assert _post(url + "/other", user="a")[0] == 404
        lines = log.read_text().splitlines()
        assert len(lines) == 4
        assert lines[0].endswith(" OK login user=demo from=127.0.0.1")
        assert lines[1].endswith(" FAILED login user=x from=10.9.9.9 from=127.0.0.1")
        # a newline in the user name never forges a line
        assert lines[2].endswith(" from=127.0.0.1") and "user=evil?2026-01-01" in lines[2]
        assert lines[3].endswith(" INFO health check from=127.0.0.1")
        assert all(len(line.split(" ", 2)[1]) == 8 for line in lines)


class TestLoginProbeBind:
    def test_bind_adds_ssh_b(self, monkeypatch, capsys):
        seen = {}

        def fake_run(argv, password, timeout):
            seen['argv'] = argv
            return "Permission denied\r\n", 255, True, False

        monkeypatch.setattr(login_probe, 'run', fake_run)
        assert login_probe.main(['--bind', '198.18.1.5', '--timeout', '3', 'ssh', 'h', 'u', 'p']) == 1
        argv = seen['argv']
        assert argv[argv.index('-b') + 1] == '198.18.1.5' and argv[-2] == 'u@h'
        result = json.loads(capsys.readouterr().out)
        assert result['ok'] is False and result['prompted'] is True
        assert login_probe.main(['ssh', 'h', 'u', 'p']) == 1
        assert '-b' not in seen['argv']
