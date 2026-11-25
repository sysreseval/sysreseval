"""Tests of lib/cowrie.py (the Cowrie helpers of the network security monitoring lab) and of the
``--command`` option of lib/login_probe.py.

The events and the login_probe outputs below come from Cowrie 3.1.8 (image sretest/nsm13:1.36, s16,
2026-11-25), reached by an OpenSSH 10.0 client.
"""
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src'))

import cowrie  # noqa: E402
import login_probe  # noqa: E402

EVENTS = """\
{"eventid":"cowrie.session.connect","src_ip":"198.18.120.202","src_port":60844,"dst_ip":"172.31.19.25","dst_port":2222,"session":"a696bc630c26","protocol":"ssh","message":"New connection","sensor":"hp-dmz-42","timestamp":"2026-11-25T19:52:10.123456Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4","message":"Remote SSH version","sensor":"hp-dmz-42","timestamp":"2026-11-25T19:52:10.200000Z","src_ip":"198.18.120.202","session":"a696bc630c26"}
{"eventid":"cowrie.login.success","username":"root","password":"123456","message":"login attempt [root/123456] succeeded","sensor":"hp-dmz-42","timestamp":"2026-11-25T19:52:11.000000Z","src_ip":"198.18.120.202","session":"a696bc630c26"}
{"eventid":"cowrie.login.failed","username":"root","password":"qwerty","message":"login attempt [root/qwerty] failed","sensor":"hp-dmz-42","timestamp":"2026-11-25T19:52:12.000000Z","src_ip":"198.18.120.202","session":"518a91163fd6"}
{"eventid":"cowrie.login.failed","username":"pi","password":"raspberry","message":"login attempt [pi/raspberry] failed","sensor":"hp-dmz-42","timestamp":"2026-11-25T18:00:00.000000Z","src_ip":"198.18.120.202","session":"6a5c0d558e10"}
{"eventid":"cowrie.login.failed","username":"guest","password":"guest","sensor":"hp-dmz-42","timestamp":"2026-11-25T19:52:13.000000Z","src_ip":"203.0.113.5","session":"73401464b3f4"}
not json
"""
SESSION_OK = ('{"ok": true, "login": "", "home": "", "home_exists": null, "prompted": true, "exit": 0, '
              '"timeout": false, "output": "\\rroot@172.31.19.25\'s password: \\r\\nSRE_LOGIN_OK\\r\\nerp-03\\r\\n'
              '5.10.0-25-amd64\\r\\n"}')
SESSION_REFUSED = ('{"ok": false, "login": "", "home": "", "home_exists": null, "prompted": true, "exit": 255, '
                   '"timeout": false, "output": "\\rroot@172.31.19.25\'s password: \\r\\nroot@172.31.19.25: '
                   'Permission denied (publickey,password).\\r\\r\\n"}')


class TestState:
    def test_cfg(self):
        text = cowrie.render_cowrie_cfg({"honeypot": {"hostname": "erp-03", "sensor_name": "hp-dmz-42"},
                                         "ssh": {"version": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3"}})
        assert text == ("[honeypot]\nhostname = erp-03\nsensor_name = hp-dmz-42\n\n"
                        "[ssh]\nversion = SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\n")

    def test_userdb(self):
        assert cowrie.render_userdb([("root", "123456"), ("root", "!*"), ("pi", "*")]) == \
            "root:x:123456\nroot:x:!*\npi:x:*\n"

    def test_generated_events_read_back(self):
        events = [cowrie.cowrie_event("cowrie.session.connect", 1795600000.25, "abcdef012345", "192.0.2.7",
                                      "hp-prod-01", src_port=40000, dst_port=2222),
                  cowrie.cowrie_event("cowrie.login.failed", 1795600001.5, "abcdef012345", "192.0.2.7",
                                      "hp-prod-01", username="root", password="x")]
        parsed = cowrie.parse_events(cowrie.render_events(events))
        assert parsed[0]["timestamp"] == "2026-11-25T09:46:40.250000Z"
        assert cowrie.event_epoch(parsed[0]) == 1795600000.25
        assert parsed[1]["eventid"] == "cowrie.login.failed" and parsed[1]["sensor"] == "hp-prod-01"
        assert cowrie.login_results(parsed) == {("root", "x"): "failed"}


class TestEvents:
    def test_command(self):
        assert cowrie.events_cmd(["198.18.120.202"]) == \
            "grep -F -e '\"198.18.120.202\"' /opt/cowrie/var/log/cowrie/cowrie.json 2>/dev/null | tail -n 300"

    def test_parse_and_since(self):
        events = cowrie.parse_events(EVENTS)
        assert len(events) == 6
        t0 = cowrie.event_epoch(events[0])
        recent = cowrie.events_since(events, t0, src="198.18.120.202")
        assert [e["eventid"] for e in recent] == ["cowrie.session.connect", "cowrie.client.version",
                                                  "cowrie.login.success", "cowrie.login.failed"]
        assert cowrie.events_since(events, None) == []
        assert cowrie.login_results(recent) == {("root", "123456"): "success", ("root", "qwerty"): "failed"}
        assert {e["sensor"] for e in recent} == {"hp-dmz-42"}

    def test_epoch_forms(self):
        assert cowrie.event_epoch({"timestamp": 1795600000}) == 1795600000.0
        assert cowrie.event_epoch({"timestamp": "garbage"}) is None
        assert cowrie.event_epoch({}) is None


class TestBannersAndProcesses:
    def test_banner(self):
        cmd = cowrie.banner_cmd("172.31.19.25", 22, "p22", "198.18.120.202")
        assert "nc -w 4 -s 198.18.120.202 172.31.19.25 22 </dev/null" in cmd and " -N " not in cmd
        assert cmd.startswith('echo "SRE-BANNER-p22=$(timeout 6 nc ')
        out = "SRE-BANNER-p22=SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\nSRE-BANNER-wan=\n"
        assert cowrie.parse_banner(out, "p22") == "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3"
        assert cowrie.parse_banner(out, "wan") == "" and cowrie.parse_banner(out, "other") == ""
        assert "-s " not in cowrie.banner_cmd("h", 22222, "lan")

    def test_owners(self):
        out = ("cowrie   /opt/cowrie/cowrie-env/bin/python3 /opt/cowrie/cowrie-env/bin/twistd --umask=0022 "
               "--pidfile var/run/cowrie.pid --logger cowrie.python.logfile.logger -n cowrie\n")
        assert cowrie.parse_owners(out) == ["cowrie"]
        assert cowrie.parse_owners("") == []

    def test_session_output(self):
        ok, output = cowrie.session_output(SESSION_OK)
        assert ok and cowrie.output_lines_after_mark(output) == ["erp-03", "5.10.0-25-amd64"]
        ok, output = cowrie.session_output(SESSION_REFUSED)
        assert not ok and cowrie.output_lines_after_mark(output) == []
        assert cowrie.session_output("") == (False, "")


class TestLoginProbeCommand:
    def test_command_replaces_the_session_script(self, monkeypatch, capsys):
        seen = {}

        def fake_run(argv, password, timeout):
            seen['argv'] = argv
            return "\r\nSRE_LOGIN_OK\r\nerp-03\r\n", 0, True, False

        monkeypatch.setattr(login_probe, 'run', fake_run)
        assert login_probe.main(['--bind', '198.18.1.5', '--command', 'hostname; uname -r', 'ssh', 'h', 'u', 'p']) == 0
        assert seen['argv'][-1] == "echo SRE_LOGIN_OK; hostname; uname -r" and seen['argv'][-2] == "u@h"
        result = json.loads(capsys.readouterr().out)
        assert result['ok'] is True and result['login'] == "" and "erp-03" in result['output']

    def test_without_command(self, monkeypatch, capsys):
        seen = {}
        monkeypatch.setattr(login_probe, 'run', lambda argv, pw, timeout: (seen.update(argv=argv), ("", 255, True, False))[1])
        login_probe.main(['ssh', 'h', 'u', 'p'])
        assert seen['argv'][-1] == login_probe.SESSION_SCRIPT
        capsys.readouterr()
