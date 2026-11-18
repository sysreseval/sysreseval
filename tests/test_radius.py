"""Tests for lib/radius.py (fixtures captured on FreeRADIUS / freeradius-utils 3.2.1, Debian 12, in the
sysreseval/aaa containers of the AAA lab on 2026-11-18: tests/mock_data/aaa/)."""
import shlex
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from radius import (  # noqa: E402
    LDAP_AUTH_TYPE, LOCALHOST_SECRET, PRISTINE_DIR, TOTP_CHECK, TOTP_SPLIT, Raw, ShellExpr, attrs_shell_word,
    auth_attrs, config_check_cmd, detail_cmd, get_detail_records, ldap_group_policy, normalize_station_id,
    parse_detail, parse_radclient, rad_value, radclient_cmd, radius_request, random_base32_secret, render_client,
    render_default_site, render_eap_module, render_huntgroup, render_ldap_module, render_users_entry, reset_cmd,
    split_rc, totp_shell,
)

MOCK = Path(__file__).parent / 'mock_data' / 'aaa'


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 1))

    grade.test.side_effect = _test
    return grade


# ---------------------------------------------------------------------------
# radclient
# ---------------------------------------------------------------------------


def test_parse_accept_without_attributes():
    r = parse_radclient(fixture('sw_pap_alice.txt'))
    assert r.ran and r.exit_code == 0 and r.sent and r.accepted and not r.rejected and r.attrs == {}


def test_parse_reply_message():
    r = parse_radclient(fixture('sw_bob.txt'))
    assert r.accepted and r.attr('Reply-Message') == "Bonjour bob, session dd83b5"
    assert r.attr('reply-message') == r.attr('Reply-Message')       # case-insensitive


def test_parse_reject_and_no_reply():
    r = parse_radclient(fixture('sw_alice_wrong.txt'))
    assert r.rejected and r.exit_code == 1 and not r.no_reply
    r = parse_radclient(fixture('probe_alice_unknown_client.txt'))
    assert r.no_reply and r.code is None and not r.accepted and not r.rejected and r.exit_code == 1


def test_parse_tagged_tunnel_attributes():
    r = parse_radclient(fixture('radius_hugo.txt'))
    assert r.accepted
    assert r.attr('Tunnel-Type') == 'VLAN' and r.attr('Tunnel-Medium-Type') == 'IEEE-802'
    assert r.attr('Tunnel-Private-Group-Id') == '197' and r.attr('Session-Timeout') == '5400'
    # the attributes of the request (the Sent block) are not those of the answer
    assert r.attr('User-Name') is None


def test_placeholder_is_not_an_answer():
    r = parse_radclient('')
    assert not r.ran and not r.accepted and r.exit_code is None
    assert split_rc("x\n===RC 3\n") == ("x", 3) and split_rc("x") == ("x", None)


def test_attrs_shell_word_quoting():
    word = attrs_shell_word([("User-Name", "alice"), ("User-Password", 'a"b$c'), ("Message-Authenticator", 0)])
    # what the shell gives radclient
    out = subprocess.run(["sh", "-c", f"printf %s {word}"], capture_output=True, text=True).stdout
    assert out == 'User-Name = "alice", User-Password = "a\\"b$c", Message-Authenticator = 0'


def test_attrs_shell_word_shell_expression():
    word = attrs_shell_word([("User-Password", ("pw", ShellExpr("$(echo 123456)")))])
    out = subprocess.run(["sh", "-c", f"printf %s {word}"], capture_output=True, text=True).stdout
    assert out == 'User-Password = "pw123456"'


def test_radclient_cmd_and_auth_attrs():
    cmd = radclient_cmd("radius.corp.lan", "S3cr$t", auth_attrs("alice", "pw"))
    assert "| radclient -x -r 1 -t 2 radius.corp.lan auth 'S3cr$t' 2>&1; echo \"===RC $?\"" in cmd
    assert cmd.startswith('echo "User-Name = \\"alice\\", User-Password = \\"pw\\", Message-Authenticator = 0"')
    chap = auth_attrs("alice", "pw", chap=True, extra=[("NAS-IP-Address", "10.0.0.1")])
    assert chap == [("User-Name", "alice"), ("CHAP-Password", "pw"), ("NAS-IP-Address", "10.0.0.1"),
                    ("Message-Authenticator", 0)]
    assert "\n" not in cmd


def test_totp_shell():
    assert totp_shell("JBSWY3DPEHPK3PXP") == "$(oathtool --totp -b JBSWY3DPEHPK3PXP)"
    assert totp_shell("ABC", "now + 10 minutes") == "$(oathtool --totp -b -N 'now + 10 minutes' ABC)"
    secret = random_base32_secret()
    assert len(secret) == 16 and set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def test_radius_request_wrapper():
    cmd = radclient_cmd("127.0.0.1", LOCALHOST_SECRET, auth_attrs("emma", "x"))
    grade = make_grade({cmd: (fixture('radius_emma.txt'), 0)})
    r = radius_request(grade, 'radius', '127.0.0.1', LOCALHOST_SECRET, auth_attrs("emma", "x"))
    assert r.accepted and r.attr('Tunnel-Private-Group-Id') == '91'
    assert not radius_request(grade, 'radius', '127.0.0.1', LOCALHOST_SECRET, auth_attrs("ines", "x")).ran


# ---------------------------------------------------------------------------
# accounting
# ---------------------------------------------------------------------------


def test_parse_detail():
    records = parse_detail(fixture('nac_detail.txt'))
    kinds = [r['acct-status-type'] for r in records]
    assert 'Accounting-On' in kinds and 'Start' in kinds
    starts = [r for r in records if r['acct-status-type'] == 'Start']
    jdoe = next(r for r in starts if r.get('user-name') == 'jdoe')
    assert jdoe['nas-identifier'] == 'sw' and normalize_station_id(jdoe['calling-station-id']) == '02:53:52:80:9a:35'
    assert jdoe['date'].startswith('Wed Nov 18')
    grade = make_grade({detail_cmd(): (fixture('nac_detail.txt'), 0)})
    assert len(get_detail_records(grade, 'nac')) == len(records)


def test_normalize_station_id():
    assert normalize_station_id("02-53-52-6E-19-29") == "02:53:52:6e:19:29"
    assert normalize_station_id("0253.526e.1929") == "02:53:52:6e:19:29"
    assert normalize_station_id("DA-38-4F-D5-82-B1:") == "da:38:4f:d5:82:b1"
    assert normalize_station_id("nope") == ""


def test_config_check_fixture():
    out, code = split_rc(fixture('radius_config_check.txt'))
    assert code == 0 and "Configuration appears to be OK" in out
    assert config_check_cmd().startswith("freeradius -XC")


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def test_render_client():
    text = render_client('sw', '192.0.2.2', 'secret')
    assert text == "\nclient sw {\n\tipaddr = 192.0.2.2\n\tsecret = secret\n\tshortname = sw\n}\n"


def test_render_users_entry():
    assert render_users_entry("alice", [("Cleartext-Password", ":=", "pw")]) == 'alice\tCleartext-Password := "pw"\n\n'
    text = render_users_entry("bob", [("Cleartext-Password", ":=", "pw")],
                              [("Reply-Message", ":=", "Hi"), ("Session-Timeout", ":=", 60)])
    assert text == 'bob\tCleartext-Password := "pw"\n\tReply-Message := "Hi",\n\tSession-Timeout := 60\n\n'
    text = render_users_entry("DEFAULT", [("Huntgroup-Name", "==", "devices"), ("Auth-Type", ":=", Raw("Reject"))],
                              fall_through=True)
    assert text == 'DEFAULT\tHuntgroup-Name == "devices", Auth-Type := Reject\n\tFall-Through = Yes\n\n'
    assert rad_value(True) == "yes" and rad_value('a"b') == '"a\\"b"'


def test_render_huntgroup():
    assert render_huntgroup("devices", [("NAS-IP-Address", "==", "192.0.2.1")]) == "devices\tNAS-IP-Address == 192.0.2.1\n"


def test_render_modules_and_site():
    ldap = render_ldap_module("ldap.corp.lan", "cn=radius,dc=corp,dc=lan", "pw", "dc=corp,dc=lan",
                              "ou=people,dc=corp,dc=lan", "ou=groups,dc=corp,dc=lan")
    assert "server = 'ldap.corp.lan'" in ldap and "membership_filter = \"(|(member=%{control:${..user_dn}})" in ldap
    assert ldap.count("{") == ldap.count("}")
    eap = render_eap_module("/c/s.crt", "/c/s.key", "/c/ca.crt", check_cert_cn="%{User-Name}")
    assert "default_eap_type = peap" in eap and "check_cert_cn = %{User-Name}" in eap
    assert "private_key_password" not in eap and eap.count("{") == eap.count("}")
    policy = ldap_group_policy([("wifi-staff", [("Tunnel-Private-Group-Id", ":=", "10")])])
    assert 'if (LDAP-Group == "wifi-staff")' in policy and "reject" in policy
    plain = render_default_site()
    assert "\t-ldap\n" in plain and "Auth-Type LDAP" not in plain and "totp" not in plain
    full = render_default_site(ldap=True, ldap_policy=policy, totp=True)
    assert LDAP_AUTH_TYPE in full and TOTP_SPLIT in full and TOTP_CHECK in full and "Auth-Type LDAP {" in full
    # the Auth-Type block right after the ldap call, before the group policy (it reads its rcode)
    assert full.index("\tldap\n") < full.index("&Auth-Type := ldap") < full.index("LDAP-Group")
    for text in (plain, full):
        assert text.count("{") == text.count("}")


def test_reset_cmd():
    assert PRISTINE_DIR in reset_cmd() and "rm -rf /etc/freeradius" in reset_cmd()
    assert shlex.split(reset_cmd())     # one parsable shell line
