"""Tests for lib/openldap.py (fixtures captured on slapd / ldap-utils 2.5.13 and nss-pam-ldapd
0.9.12, Debian 12, in sysreseval/base containers on 2026-11-05: tests/mock_data/ldap/)."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from openldap import (  # noqa: E402
    DEFAULT_ACCESS, LDAPI_URI, LdapResult, PAM_MKHOMEDIR_PROFILE, acl_access, acl_for_attribute, check_password,
    config_search_cmd, dn_equal, entries_under, entry_value, entry_values, find_entry, get_slapd_config,
    getent_passwd, has_object_class, ldap_bind, ldap_result, ldapdelete_cmd, ldapmodify_cmd, ldappasswd_cmd,
    ldapsearch_cmd, ldapwhoami_cmd, login_probe, login_probe_cmd, normalize_dn, nslcd_tls, nsswitch_has,
    pam_has, pam_modules, parent_dn, parse_csn, parse_getent_group, parse_getent_passwd, parse_id, parse_ldap_error,
    parse_ldif, parse_listen_ports, parse_login_probe, parse_nslcd_conf, parse_nsswitch, parse_olc_access,
    parse_olc_security, parse_pam_file, parse_s_client, parse_slapd_config, parse_syncrepl, password_hashed,
    rdn_value, render_base_ldif, render_entry_ldif, render_modify_ldif, render_nslcd_conf, render_ou_ldif,
    render_person_ldif, render_posix_group_ldif, render_service_account_ldif, render_slapd_config_ldif,
    render_syncrepl, s_client_cmd, ssha_hash, strip_index, tls_check,
)

MOCK = Path(__file__).parent / 'mock_data' / 'ldap'


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    """Grade mock whose grade.test(machine, command, step=...) dispatches by command."""
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 1))

    grade.test.side_effect = _test
    return grade


# ---------------------------------------------------------------------------
# LDIF
# ---------------------------------------------------------------------------

SEARCH_OUT = """dn: ou=people,dc=nodomain
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=nodomain
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: alice
cn: Alice Martin
sn: Martin
givenName: Alice
uidNumber: 5001
gidNumber: 5000
homeDirectory: /home/alice
loginShell: /bin/bash
userPassword:: e1NTSEF9WnZzazI5V2c1RE9PNmdqTitpL3owUXQ3MjBhSFJQbks=

===RC 0
"""

FULL_SEARCH_OUT = """# extended LDIF
#
# LDAPv3
# base <dc=nodomain> with scope subtree
# filter: (uid=alice)
# requesting: uid uidNumber
#

# alice, people, nodomain
dn: uid=alice,ou=people,dc=nodomain
uid: alice
uidNumber: 5001

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
"""


def test_parse_ldif_entries_values_and_base64():
    entries = parse_ldif(SEARCH_OUT)
    assert [e['dn'] for e in entries] == ['ou=people,dc=nodomain', 'uid=alice,ou=people,dc=nodomain']
    alice = entries[1]
    assert entry_values(alice, 'objectclass') == ['inetOrgPerson', 'posixAccount', 'shadowAccount']
    assert entry_value(alice, 'uidNumber') == '5001'
    assert entry_value(alice, 'userPassword').startswith('{SSHA}')
    assert has_object_class(alice, 'POSIXACCOUNT') and not has_object_class(alice, 'posixGroup')
    assert entry_value(alice, 'missing', 'x') == 'x' and entry_values(None, 'uid') == []


def test_parse_ldif_full_output_skips_comments_and_trailer():
    entries = parse_ldif(FULL_SEARCH_OUT)
    assert len(entries) == 1
    assert entries[0]['attrs'] == {'uid': ['alice'], 'uidNumber': ['5001']}


def test_parse_ldif_continuation_lines():
    text = ("dn: olcDatabase={-1}frontend,cn=config\n"
            "olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external\n"
            " ,cn=auth manage by * break\n")
    e = parse_ldif(text)[0]
    assert entry_value(e, 'olcAccess') == ("{0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external"
                                           ",cn=auth manage by * break")


def test_dn_helpers():
    assert normalize_dn('UID=Alice, ou=People ,dc=corp,dc=lan') == 'uid=alice,ou=people,dc=corp,dc=lan'
    assert dn_equal('uid=alice,ou=people,dc=corp,dc=lan', 'uid=Alice,ou=people, dc=corp,dc=lan')
    assert rdn_value('uid=alice,ou=people,dc=corp,dc=lan') == 'alice'
    assert parent_dn('uid=alice,ou=people,dc=corp,dc=lan') == 'ou=people,dc=corp,dc=lan'
    assert parent_dn('dc=lan') == ''
    entries = parse_ldif(SEARCH_OUT)
    assert find_entry(entries, 'UID=ALICE,ou=people,dc=nodomain') is entries[1]
    assert find_entry(entries, 'uid=bob,ou=people,dc=nodomain') is None
    assert [e['dn'] for e in entries_under(entries, 'ou=people,dc=nodomain')] == ['uid=alice,ou=people,dc=nodomain']


# ---------------------------------------------------------------------------
# results and errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text, expected", [
    ("ldap_bind: Invalid credentials (49)\n", (49, 'Invalid credentials')),
    ("No such object (32)\n", (32, 'No such object')),
    ("ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)\n", (-1, "Can't contact LDAP server")),
    ("ldap_modify: Insufficient access (50)\n\tadditional info: no write access to parent\n", (50, 'Insufficient access')),
    ("ldap_bind: Confidentiality required (13)\n\tadditional info: confidentiality required\n",
     (13, 'Confidentiality required')),
    ("ldap_delete: No such object (32)\n\tmatched DN: ou=people,dc=nodomain\n", (32, 'No such object')),
    ("dn:uid=alice,ou=people,dc=nodomain\n", (None, '')),
    ("", (None, '')),
])
def test_parse_ldap_error(text, expected):
    assert parse_ldap_error(text) == expected


def test_ldap_result_reads_the_rc_marker():
    r = ldap_result(SEARCH_OUT, 0)
    assert r.ran and r.ok and len(r.entries) == 2 and r.exit_code == 0
    r = ldap_result("ldap_bind: Invalid credentials (49)\n===RC 49\n", 0)
    assert r.ran and not r.ok and r.error_code == 49 and r.exit_code == 49
    placeholder = ldap_result('', 0)
    assert not placeholder.ran and not placeholder.ok and placeholder.entries == []
    # an empty answer that ran (nothing printed but the marker)
    r = ldap_result("===RC 0\n", 0)
    assert r.ran and r.ok and r.entries == []


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def test_ldapsearch_cmd_forms():
    cmd = ldapsearch_cmd('ldap://ldap1.corp.lan', 'ou=people,dc=corp,dc=lan', '(uid=*)', ('uid', 'cn'),
                         binddn='uid=bob,ou=people,dc=corp,dc=lan', password='s3cret', scope='one', starttls=True)
    assert cmd.startswith("ldapsearch -LLL -x -D uid=bob,ou=people,dc=corp,dc=lan -w s3cret -ZZ -H ldap://ldap1.corp.lan "
                          "-b ou=people,dc=corp,dc=lan -s one '(uid=*)' uid cn 2>&1; echo \"===RC $?\"")
    assert ldapsearch_cmd(LDAPI_URI, 'cn=config', external=True).startswith(
        "ldapsearch -LLL -Y EXTERNAL -Q -H ldapi:/// -b cn=config '(objectClass=*)'")
    assert "ldapsearch -LLL -x -H ldap://h -b dc=x '(objectClass=*)'" in ldapsearch_cmd('ldap://h', 'dc=x')
    assert config_search_cmd().startswith("ldapsearch -LLL -Y EXTERNAL -Q -H ldapi:/// -b cn=config '(|(objectClass=olcGlobal)")


def test_other_commands():
    assert ldapwhoami_cmd('ldaps://ldap1', 'cn=admin,dc=corp,dc=lan', 'pw') == \
        'ldapwhoami -x -D cn=admin,dc=corp,dc=lan -w pw -H ldaps://ldap1 2>&1; echo "===RC $?"'
    mod = ldapmodify_cmd(LDAPI_URI, "dn: cn=config\nchangetype: modify\n", external=True)
    assert mod.startswith("echo ") and "| base64 -d | ldapmodify -Y EXTERNAL -Q -H ldapi:/// 2>&1" in mod
    assert "\n" not in mod
    assert "| ldapmodify -a -c -x -D a -w b -H ldap://h" in ldapmodify_cmd('ldap://h', 'dn: x\n', 'a', 'b', add=True,
                                                                             cont=True)
    assert ldappasswd_cmd('ldap://h', 'uid=a,dc=x', 'old', 'new') == \
        'ldappasswd -x -D uid=a,dc=x -w old -H ldap://h -s new 2>&1; echo "===RC $?"'
    assert ldappasswd_cmd('ldap://h', 'cn=admin,dc=x', 'pw', 'new', 'uid=a,dc=x', starttls=True).endswith(
        '-ZZ -H ldap://h -s new uid=a,dc=x 2>&1; echo "===RC $?"')
    assert ldapdelete_cmd(LDAPI_URI, 'uid=a,dc=x', 'cn=admin,dc=x', 'pw') == \
        'ldapdelete -x -D cn=admin,dc=x -w pw -H ldapi:/// uid=a,dc=x 2>&1; echo "===RC $?"'
    s = s_client_cmd('ldap1.corp.lan', 636, '/root/ca.crt', 'ldap1.corp.lan')
    assert s.startswith("openssl s_client -connect ldap1.corp.lan:636 -CAfile /root/ca.crt -verify_hostname ldap1.corp.lan "
                        "-servername ldap1.corp.lan </dev/null 2>&1 | grep -E")
    assert s.endswith("; echo ===END")
    assert " -starttls ldap " in s_client_cmd('h', 389, None, None, starttls='ldap')
    assert login_probe_cmd('su', 'alice', 'pw') == \
        "python3 /usr/local/sbin/sre_login_probe.py --timeout 20 --as student su alice pw 2>&1"
    assert login_probe_cmd('ssh', 'alice', "p'w", host='10.0.0.2', timeout=5) == \
        "python3 /usr/local/sbin/sre_login_probe.py --timeout 5 ssh 10.0.0.2 alice 'p'\"'\"'w' 2>&1"
    with pytest.raises(ValueError):
        login_probe_cmd('ssh', 'alice', 'pw')
    with pytest.raises(ValueError):
        login_probe_cmd('telnet', 'alice', 'pw')


# ---------------------------------------------------------------------------
# cn=config
# ---------------------------------------------------------------------------


def test_strip_index_and_olc_access():
    assert strip_index('{0}back_mdb') == 'back_mdb' and strip_index('{-1}frontend') == 'frontend'
    acl = parse_olc_access('{0}to attrs=userPassword by self write by anonymous auth by * none')
    assert acl['what_attrs'] == ['userpassword'] and acl['what_dn'] is None
    assert acl['by'] == [{'who': 'self', 'access': 'write', 'control': None},
                         {'who': 'anonymous', 'access': 'auth', 'control': None},
                         {'who': '*', 'access': 'none', 'control': None}]
    assert acl_access(acl, 'anonymous') == 'auth' and acl_access(acl, 'users') is None
    front = parse_olc_access('to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break')
    assert front['what'] == '*' and front['by'][0]['access'] == 'manage' and front['by'][1]['control'] == 'break'
    sub = parse_olc_access('to dn.subtree="ou=people,dc=corp,dc=lan" attrs=telephoneNumber,mail '
                           'by set="[cn=helpdesk,ou=groups,dc=corp,dc=lan]/memberUid & user/uid" write by users read')
    assert sub['what_dn'] == 'ou=people,dc=corp,dc=lan' and sub['what_dn_style'] == 'subtree'
    assert sub['what_attrs'] == ['telephonenumber', 'mail']
    assert sub['by'][0]['who'] == 'set=[cn=helpdesk,ou=groups,dc=corp,dc=lan]/memberUid & user/uid'
    assert acl_access(sub, 'users') == 'read'
    # an omitted level is none
    assert parse_olc_access('to * by *')['by'] == [{'who': '*', 'access': 'none', 'control': None}]
    acls = [parse_olc_access(a) for a in DEFAULT_ACCESS]
    assert acl_for_attribute(acls, 'userPassword') is acls[0]
    assert acl_for_attribute(acls, 'cn') is acls[2]
    assert acl_for_attribute([], 'cn') is None


def test_olc_security_and_syncrepl():
    assert parse_olc_security('simple_bind=128 ssf=0') == {'simple_bind': 128, 'ssf': 0}
    assert parse_olc_security('{0}tls=1 bogus') == {'tls': 1}
    sr = parse_syncrepl('{0}rid=001 provider=ldap://ldap1.corp.lan bindmethod=simple binddn="cn=replicator,dc=corp,dc=lan"'
                        ' credentials=secret searchbase="dc=corp,dc=lan" type=refreshAndPersist retry="5 +"'
                        ' starttls=critical tls_cacert=/root/ca/ca.crt')
    assert sr['rid'] == '001' and sr['provider'] == 'ldap://ldap1.corp.lan'
    assert sr['binddn'] == 'cn=replicator,dc=corp,dc=lan' and sr['retry'] == '5 +' and sr['starttls'] == 'critical'
    rendered = render_syncrepl(1, 'ldap://ldap1.corp.lan', 'cn=replicator,dc=corp,dc=lan', 'secret', 'dc=corp,dc=lan',
                               starttls='critical', tls_cacert='/root/ca/ca.crt')
    assert parse_syncrepl(rendered) == {k: v for k, v in sr.items()}


def test_parse_slapd_config_fixture():
    cfg = parse_slapd_config(parse_ldif(fixture('config_final.ldif')))
    assert cfg.loglevel == 'stats' and 'back_mdb' in cfg.modules and 'syncprov' in cfg.modules
    assert cfg.tls['olcTLSCertificateKeyFile'] == '/etc/ldap/tls/ldap1.key'
    db = cfg.database('DC=corp, dc=lan')
    assert db['type'] == 'mdb' and db['rootdn'] == 'cn=admin,dc=corp,dc=lan' and db['rootpw_hashed']
    assert db['directory'] == '/var/lib/ldap' and db['security'] == {'simple_bind': 128}
    assert db['overlays'] == ['syncprov'] and db['syncrepl'] == []
    assert db['access'][0]['what_attrs'] == ['userpassword'] and acl_access(db['access'][-1], 'users') == 'read'
    assert 'objectClass eq' in db['indexes']
    cfg2 = parse_slapd_config(parse_ldif(fixture('config_consumer.ldif')))
    db2 = cfg2.database('dc=corp,dc=lan')
    assert db2['syncrepl'][0]['type'] == 'refreshAndPersist' and db2['updateref'] == 'ldap://ldap1.corp.lan'
    assert db2['overlays'] == []
    assert parse_slapd_config([]).database('dc=corp,dc=lan') is None


def test_get_slapd_config_wrapper():
    grade = make_grade({config_search_cmd(): (fixture('config_final.ldif'), 0)})
    cfg = get_slapd_config(grade, 'ldap1')
    assert cfg.database('dc=corp,dc=lan')['suffix'] == 'dc=corp,dc=lan'
    assert get_slapd_config(make_grade({}), 'ldap1').databases == {}


# ---------------------------------------------------------------------------
# passwords
# ---------------------------------------------------------------------------


def test_ssha_hash_and_check():
    h = ssha_hash('secret', salt=b'salt')
    assert h == '{SSHA}' + __import__('base64').b64encode(
        __import__('hashlib').sha1(b'secretsalt').digest() + b'salt').decode()
    assert check_password(h, 'secret') and not check_password(h, 'Secret')
    assert check_password(ssha_hash('x'), 'x')
    # slappasswd -s alicepw, captured
    assert check_password('{SSHA}Zvsk29Wg5DOO6gjN+i/z0Qt720aHRPnK', 'alicepw')
    assert check_password('clear', 'clear') and not check_password('{CRYPT}abc', 'abc')
    assert not check_password('{SSHA}not-base64!', 'x')
    assert password_hashed('{SSHA}abc') and password_hashed('{crypt}$6$x') and password_hashed('{ARGON2}$argon2id$v=19')
    assert not password_hashed('secret') and not password_hashed('')


# ---------------------------------------------------------------------------
# client side
# ---------------------------------------------------------------------------

NSSWITCH = """# /etc/nsswitch.conf
passwd:         files systemd ldap
group:          files systemd ldap
shadow:         files systemd
gshadow:        files
hosts:          files dns [NOTFOUND=return] mdns4
"""


def test_parse_nsswitch():
    conf = parse_nsswitch(NSSWITCH)
    assert conf['passwd'] == ['files', 'systemd', 'ldap'] and conf['hosts'] == ['files', 'dns', 'mdns4']
    assert nsswitch_has(conf, 'passwd') and nsswitch_has(conf, 'GROUP', 'ldap') and not nsswitch_has(conf, 'shadow')
    assert not nsswitch_has(conf, 'netgroup')


NSLCD = """# nslcd.conf
uid nslcd
gid nslcd
uri ldaps://ldap1.corp.lan/
uri ldaps://ldap2.corp.lan/
base dc=corp,dc=lan
binddn cn=nslcd,dc=corp,dc=lan
bindpw s3cret
tls_cacertfile /root/ca.crt
tls_reqcert demand
"""


def test_parse_nslcd_conf_and_tls():
    conf = parse_nslcd_conf(NSLCD)
    assert conf['uri'] == ['ldaps://ldap1.corp.lan/', 'ldaps://ldap2.corp.lan/'] and conf['bindpw'] == ['s3cret']
    info = nslcd_tls(conf)
    assert info['ldaps'] and not info['starttls'] and info['cacert'] == '/root/ca.crt' and info['reqcert'] == 'demand'
    assert info['binddn'] == 'cn=nslcd,dc=corp,dc=lan' and info['base'] == 'dc=corp,dc=lan'
    plain = nslcd_tls(parse_nslcd_conf("uri ldap://ldap1.corp.lan/\nbase dc=corp,dc=lan\nssl start_tls\n"))
    assert plain['starttls'] and not plain['ldaps'] and plain['cacert'] is None and plain['binddn'] is None
    assert nslcd_tls({})['uris'] == [] and nslcd_tls({})['base'] is None
    rendered = render_nslcd_conf('ldaps://ldap1.corp.lan/', 'dc=corp,dc=lan', 'cn=nslcd,dc=corp,dc=lan', 'pw',
                                 cacert='/root/ca.crt', reqcert='demand')
    assert parse_nslcd_conf(rendered)['binddn'] == ['cn=nslcd,dc=corp,dc=lan']
    assert 'ssl start_tls' in render_nslcd_conf('ldap://h/', 'dc=x', starttls=True)


COMMON_AUTH = """#
# /etc/pam.d/common-auth - authentication settings common to all services
#
auth\t[success=2 default=ignore]\tpam_unix.so nullok
auth\t[success=1 default=ignore]\tpam_ldap.so minimum_uid=1000 use_first_pass
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
"""
COMMON_SESSION = """session\t[default=1]\t\t\tpam_permit.so
session\trequisite\t\t\tpam_deny.so
session\trequired\t\t\tpam_permit.so
session\trequired\tpam_mkhomedir.so umask=0077 skel=/etc/skel
session\trequired\tpam_unix.so
session\t[success=ok default=ignore]\tpam_ldap.so minimum_uid=1000
session\toptional\tpam_systemd.so
@include common-password
"""


def test_parse_pam_file():
    lines = parse_pam_file(COMMON_AUTH)
    assert [(l.type, l.control, l.module) for l in lines][:2] == [
        ('auth', '[success=2 default=ignore]', 'pam_unix.so'), ('auth', '[success=1 default=ignore]', 'pam_ldap.so')]
    assert lines[1].args == ['minimum_uid=1000', 'use_first_pass']
    assert pam_has(lines, 'auth', 'pam_ldap.so') and not pam_has(lines, 'account', 'pam_ldap.so')
    session = parse_pam_file(COMMON_SESSION)
    assert pam_modules(session, 'session')[3] == 'pam_mkhomedir.so' and session[-1].type == '@include'
    assert pam_has(session, 'session', 'pam_mkhomedir.so')
    assert parse_pam_file("auth required pam_unix.so \\\n    nullok\n")[0].args == ['nullok']


def test_parse_getent_and_id():
    passwd = parse_getent_passwd("alice:x:5001:5000:Alice Martin:/home/alice:/bin/bash\nbad line\n")
    assert passwd == {'alice': {'uid': 5001, 'gid': 5000, 'gecos': 'Alice Martin', 'home': '/home/alice',
                                'shell': '/bin/bash'}}
    assert parse_getent_group("dev:*:5001:alice,bob\nstaff:*:5000:\n") == {
        'dev': {'gid': 5001, 'members': ['alice', 'bob']}, 'staff': {'gid': 5000, 'members': []}}
    info = parse_id("uid=5001(alice) gid=5000(staff) groups=5000(staff),5001(dev)\n")
    assert info == {'uid': 5001, 'user': 'alice', 'gid': 5000, 'group': 'staff', 'groups': {5000: 'staff', 5001: 'dev'}}
    assert parse_id("id: 'nobody2': no such user\n") is None
    grade = make_grade({"getent passwd alice 2>&1": ("alice:x:5001:5000:Alice Martin:/home/alice:/bin/bash\n", 0)})
    assert getent_passwd(grade, 'm1', 'alice')['uid'] == 5001 and getent_passwd(grade, 'm1', 'bob') is None


def test_parse_listen_ports():
    out = ("State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
           "LISTEN 0      2048         0.0.0.0:389       0.0.0.0:*    users:((\"slapd\",pid=263,fd=8))\n"
           "LISTEN 0      2048            [::]:636          [::]:*    users:((\"slapd\",pid=263,fd=10))\n"
           "LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=47,fd=3))\n"
           "LISTEN 0      4096      127.0.0.11:38651      0.0.0.0:*\n")
    assert parse_listen_ports(out) == {389: 'slapd', 636: 'slapd', 22: 'sshd', 38651: ''}


def test_login_probe_results():
    ok = ('{"ok": true, "login": "alice", "home": "/home/alice", "home_exists": true, "prompted": true, '
          '"exit": 0, "timeout": false, "output": "Password: \\r\\nSRE_LOGIN_OK\\r\\n"}')
    r = parse_login_probe("noise\n" + ok + "\n")
    assert r['ok'] and r['login'] == 'alice' and r['home_exists'] is True
    bad = ('{"ok": false, "login": "", "home": "", "home_exists": null, "prompted": true, "exit": 1, '
           '"timeout": false, "output": "Password: \\r\\nsu: Authentication failure\\r\\n"}')
    assert parse_login_probe(bad)['ok'] is False and parse_login_probe(bad)['home_exists'] is None
    assert parse_login_probe('') is None and parse_login_probe('{broken') is None
    grade = make_grade({login_probe_cmd('su', 'alice', 'pw'): (ok, 0)})
    assert login_probe(grade, 'm1', 'su', 'alice', 'pw')['login'] == 'alice'
    assert login_probe(grade, 'm1', 'ssh', 'alice', 'pw', host='10.0.0.1') is None


def test_parse_s_client():
    out = ("CONNECTED(00000003)\n"
           "subject=CN = ldap1.corp.lan\n"
           "issuer=CN = CA corp.lan\n"
           "Verify return code: 0 (ok)\n===END\n")
    r = parse_s_client(out)
    assert r['connected'] and r['verify_code'] == 0 and r['subject'] == 'CN = ldap1.corp.lan' and r['errors'] == []
    bad = ("CONNECTED(00000003)\nverify error:num=62:hostname mismatch\nsubject=CN = ldap1\n"
           "Verify return code: 62 (hostname mismatch)\n===END\n")
    r = parse_s_client(bad)
    assert r['verify_code'] == 62 and r['errors'] == ['verify error:num=62:hostname mismatch']
    r = parse_s_client("connect: Connection refused\nconnect:errno=111\n===END\n")
    assert not r['connected'] and r['verify_code'] is None
    grade = make_grade({s_client_cmd('ldap1', 636, '/root/ca.crt', 'ldap1'): (out, 0)})
    assert tls_check(grade, 'probe', 'ldap1', 636, '/root/ca.crt', 'ldap1')['ran']
    assert not tls_check(grade, 'probe', 'ldap2', 636, '/root/ca.crt', 'ldap2')['ran']


def test_parse_csn():
    assert parse_csn('20261105001234.567890Z#000000#000#000000') == ('20261105001234', '567890', '000000', '000', '000000')
    assert parse_csn('garbage') is None


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def test_render_entries():
    base = render_base_ldif('dc=corp,dc=lan', 'Corp')
    e = parse_ldif(base)[0]
    assert e['dn'] == 'dc=corp,dc=lan' and entry_value(e, 'dc') == 'corp' and has_object_class(e, 'dcObject')
    ou = parse_ldif(render_ou_ldif('dc=corp,dc=lan', 'people'))[0]
    assert ou['dn'] == 'ou=people,dc=corp,dc=lan' and has_object_class(ou, 'organizationalUnit')
    person = parse_ldif(render_person_ldif('dc=corp,dc=lan', 'amartin', 'Alice', 'Martin', 5001, 5000, '{SSHA}x',
                                           mail='amartin@corp.lan'))[0]
    assert person['dn'] == 'uid=amartin,ou=people,dc=corp,dc=lan'
    assert entry_value(person, 'cn') == 'Alice Martin' and entry_value(person, 'homeDirectory') == '/home/amartin'
    assert entry_value(person, 'uidNumber') == '5001' and entry_value(person, 'mail') == 'amartin@corp.lan'
    group = parse_ldif(render_posix_group_ldif('dc=corp,dc=lan', 'dev', 5001, ['amartin', 'bdubois']))[0]
    assert entry_values(group, 'memberUid') == ['amartin', 'bdubois'] and entry_value(group, 'gidNumber') == '5001'
    svc = parse_ldif(render_service_account_ldif('cn=nslcd,dc=corp,dc=lan', '{SSHA}y', 'nslcd'))[0]
    assert has_object_class(svc, 'simpleSecurityObject') and entry_value(svc, 'cn') == 'nslcd'
    # non-ASCII and leading-space values go base64
    text = render_entry_ldif('cn=x', [('description', 'Gaëlle'), ('o', ' spaced')])
    assert 'description:: ' in text and 'o:: ' in text
    assert entry_value(parse_ldif(text)[0], 'description') == 'Gaëlle'


def test_render_modify_ldif():
    text = render_modify_ldif('uid=a,dc=x', [('replace', 'loginShell', '/bin/sh'), ('add', 'mail', ['a@x', 'b@x']),
                                             ('delete', 'mobile', None)])
    assert text == ("dn: uid=a,dc=x\nchangetype: modify\nreplace: loginShell\nloginShell: /bin/sh\n-\n"
                    "add: mail\nmail: a@x\nmail: b@x\n-\ndelete: mobile\n-\n\n")


def test_render_slapd_config_ldif():
    text = render_slapd_config_ldif('dc=corp,dc=lan', 'cn=admin,dc=corp,dc=lan', '{SSHA}abc')
    entries = parse_ldif(text)
    dns = [e['dn'] for e in entries]
    assert dns == ['cn=config', 'cn=module{0},cn=config', 'cn=schema,cn=config', 'olcDatabase={-1}frontend,cn=config',
                   'olcDatabase={0}config,cn=config', 'olcDatabase={1}mdb,cn=config']
    assert 'include: file:///etc/ldap/schema/nis.ldif' in text
    cfg = parse_slapd_config(entries)
    assert cfg.loglevel == 'stats'
    db = cfg.database('dc=corp,dc=lan')
    assert db['rootdn'] == 'cn=admin,dc=corp,dc=lan' and db['rootpw_hashed'] and db['access_raw'] == list(DEFAULT_ACCESS)
    assert entry_value(entries[0], 'olcLocalSSF') == '128'
    assert 'olcLocalSSF' not in render_slapd_config_ldif('dc=x', 'cn=a,dc=x', '{SSHA}a', local_ssf=None)
    assert 'olcModuleLoad: syncprov' in render_slapd_config_ldif('dc=x', 'cn=a,dc=x', '{SSHA}a', extra_modules=('syncprov',))
    assert PAM_MKHOMEDIR_PROFILE.startswith('Name: ') and 'pam_mkhomedir.so' in PAM_MKHOMEDIR_PROFILE


# ---------------------------------------------------------------------------
# wrappers on captured outputs
# ---------------------------------------------------------------------------


def test_ldap_bind_wrapper():
    cmd_ok = ldapwhoami_cmd('ldap://ldap1', 'uid=alice,ou=people,dc=nodomain', 'alicepw')
    cmd_bad = ldapwhoami_cmd('ldap://ldap1', 'uid=alice,ou=people,dc=nodomain', 'wrong')
    grade = make_grade({cmd_ok: ("dn:uid=alice,ou=people,dc=nodomain\n===RC 0\n", 0),
                        cmd_bad: ("ldap_bind: Invalid credentials (49)\n===RC 49\n", 0)})
    assert ldap_bind(grade, 'probe', 'ldap://ldap1', 'uid=alice,ou=people,dc=nodomain', 'alicepw').ok
    r = ldap_bind(grade, 'probe', 'ldap://ldap1', 'uid=alice,ou=people,dc=nodomain', 'wrong')
    assert r.ran and not r.ok and r.error_code == 49
    assert isinstance(ldap_bind(grade, 'probe', 'ldap://x', 'cn=a', 'b'), LdapResult)
    assert not ldap_bind(grade, 'probe', 'ldap://x', 'cn=a', 'b').ran


def test_tree_fixture_of_the_solution():
    entries = parse_ldif(fixture('tree_final.ldif'))
    people = entries_under(entries, 'ou=people,dc=corp,dc=lan')
    assert len(people) == 4 and all(has_object_class(p, 'posixAccount') for p in people)
    assert all(password_hashed(entry_value(p, 'userPassword')) for p in people)
    groups = entries_under(entries, 'ou=groups,dc=corp,dc=lan')
    assert {rdn_value(g['dn']) for g in groups} == {'staff', 'dev', 'helpdesk'}
    nslcd = find_entry(entries, 'cn=nslcd,dc=corp,dc=lan')
    assert has_object_class(nslcd, 'simpleSecurityObject')


# ---------------------------------------------------------------------------
# the captured outputs of the lab's evaluation (solution applied, and a fresh project)
# ---------------------------------------------------------------------------


def test_live_pam_files_of_the_solution():
    auth = parse_pam_file(fixture('common-auth'))
    assert pam_has(auth, 'auth', 'pam_unix.so') and pam_has(auth, 'auth', 'pam_ldap.so')
    assert [l.control for l in auth if l.module == 'pam_unix.so'] == ['[success=2 default=ignore]']
    account = parse_pam_file(fixture('common-account'))
    assert pam_has(account, 'account', 'pam_ldap.so')
    session = parse_pam_file(fixture('common-session'))
    assert pam_has(session, 'session', 'pam_mkhomedir.so') and pam_has(session, 'session', 'pam_ldap.so')


def test_live_client_files_of_the_solution():
    nss = parse_nsswitch(fixture('nsswitch.conf'))
    assert all(nsswitch_has(nss, db) for db in ('passwd', 'group', 'shadow')) and not nsswitch_has(nss, 'hosts')
    info = nslcd_tls(parse_nslcd_conf(fixture('nslcd.conf')))
    assert info['ldaps'] and info['cacert'] == '/etc/ldap/ca.crt' and info['binddn'] == 'cn=nslcd,dc=corp,dc=lan'
    assert info['base'] == 'dc=corp,dc=lan' and info['reqcert'] == 'demand'
    passwd = parse_getent_passwd(fixture('getent_passwd.txt'))
    assert passwd['cguerin']['uid'] == 5228 and passwd['cguerin']['gid'] == 5200 and passwd['cguerin']['shell'] == '/bin/bash'
    assert parse_getent_group(fixture('getent_group_dev.txt'))['dev'] == {'gid': 5201, 'members': ['nmichel', 'cguerin']}
    assert parse_id(fixture('id.txt'))['groups'] == {5200: 'staff'}
    assert {389, 636} <= set(parse_listen_ports(fixture('ss_tlnp_ldap1.txt')))
    su = parse_login_probe(fixture('login_su.txt'))
    assert su['ok'] and su['login'] == 'nmichel' and su['home_exists'] is True
    ssh = parse_login_probe(fixture('login_ssh.txt'))
    assert ssh['ok'] and ssh['home'] == '/home/nmichel'


def test_live_ldap_results_of_the_solution():
    denied = ldap_result(fixture('anonymous_denied.txt'), 0)
    assert denied.ran and denied.error_code == 32 and denied.entries == []
    clear = ldap_result(fixture('whoami_clear_refused.txt'), 0)
    assert clear.ran and clear.error_code == 13 and not clear.ok and clear.exit_code == 13
    ldaps = ldap_result(fixture('whoami_ldaps.txt'), 0)
    assert ldaps.ok and ldaps.entries[0]['dn'] == 'cn=admin,dc=corp,dc=lan'   # ldapwhoami prints dn:…
    invalid = ldap_result(fixture('whoami_invalid.txt'), 0)
    assert invalid.error_code == 49
    no_write = ldap_result(fixture('user_no_write.txt'), 0)
    assert no_write.error_code == 50 and no_write.exit_code == 50 and not no_write.ok
    phone = ldap_result(fixture('helpdesk_phone.txt'), 0)
    assert phone.ok and phone.entries == []
    read = ldap_result(fixture('user_read.txt'), 0)
    assert read.ok and entry_value(read.entries[0], 'cn') == 'Chloe Guerin'
    hidden = ldap_result(fixture('user_no_password.txt'), 0)
    assert hidden.ok and hidden.entries and entry_values(hidden.entries[0], 'userPassword') == []
    csn = ldap_result(fixture('contextcsn.ldif'), 0)
    assert parse_csn(entry_value(csn.entries[0], 'contextCSN'))[0] == '20261105002157'
    canary = ldap_result(fixture('canary_consumer.ldif'), 0)
    assert entry_value(canary.entries[0], 'description') == '37435ce24518'


def test_live_tls_outputs():
    ok = parse_s_client(fixture('s_client_ldaps.txt'))
    assert ok['connected'] and ok['verify_code'] == 0 and ok['subject'] == 'CN = ldap1.corp.lan'
    assert ok['issuer'] == 'CN = CA corp.lan'
    starttls = parse_s_client(fixture('s_client_starttls.txt'))
    assert starttls['verify_code'] == 0 and starttls['subject'] == 'CN = ldap1.corp.lan'
    # a fresh server: no certificate behind STARTTLS, yet "Verify return code: 0 (ok)" (no subject line)
    notls = parse_s_client(fixture('s_client_starttls_notls.txt'))
    assert notls['subject'] == '' and notls['verify_code'] in (0, None)
    refused = parse_s_client(fixture('s_client_ldaps_refused.txt'))
    assert not refused['connected'] and refused['subject'] == ''


def test_live_fresh_project_outputs():
    assert ldap_result(fixture('anonymous_empty.txt'), 0).entries == []
    tree = ldap_result(fixture('tree_empty.ldif'), 0)
    assert tree.ran and tree.entries == [] and tree.error_code == 32
    refused = ldap_result(fixture('whoami_ldaps_refused.txt'), 0)
    assert refused.ran and not refused.ok and refused.error_code == -1
    unknown = parse_login_probe(fixture('login_su_unknown.txt'))
    assert unknown is not None and not unknown['ok']
