"""Tests for lib/kerberos.py (fixtures captured on MIT krb5 1.20, Debian 12, in the sysreseval/aaa
containers of the AAA lab on 2026-11-18: tests/mock_data/aaa/)."""
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from kerberos import (  # noqa: E402
    create_realm_cmds, get_keytab, get_policy, get_principal, gssapi_ssh, kadmin_cmd, kadmin_local_cmd,
    kinit_cmd, kinit_result, kinit_test, negotiate_curl, parse_getpol, parse_getprinc, parse_http, parse_keytab,
    parse_kinit_error, parse_klist, plain_curl, render_kadm5_acl, render_kdc_conf, render_krb5_conf,
    split_markers,
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


def test_kinit_with_klist():
    r = kinit_result(fixture('probe_kinit_nina.txt'))
    assert r['ran'] and r['ok'] and r['error'] == 'ok' and len(r['then']) == 1
    out, status = r['then'][0]
    assert status == '0'
    klist = parse_klist(out)
    assert klist['principal'] == 'nina@CORP.LAN' and klist['cache'] == 'FILE:/tmp/cc_nina'
    tgt = klist['tickets'][0]
    assert tgt['service'] == 'krbtgt/CORP.LAN@CORP.LAN' and tgt['enctypes'] == ['aes256-cts-hmac-sha1-96'] * 2


def test_kinit_errors():
    assert kinit_result(fixture('probe_kinit_leaver.txt'))['error'] == 'revoked'
    assert kinit_result(fixture('probe_kinit_wrong.txt'))['error'] == 'password'
    assert kinit_result(fixture('probe_kinit_unknown.txt'))['error'] == 'unknown'
    assert kinit_result(fixture('probe_kinit_unreachable.txt'))['error'] == 'unreachable'
    assert parse_kinit_error('') == 'ok' and parse_kinit_error('kinit: something') == 'other'
    assert not kinit_result('')['ran']


def test_kinit_then_ssh_and_http():
    r = kinit_result(fixture('probe_dev2_services.txt'))
    assert r['ok'] and [s for _, s in r['then']] == ['0', '0']
    assert r['then'][0][0].strip() == 'dev2'
    body, code = parse_http(r['then'][1][0])
    assert code == 200 and 'REMOTE_USER=dev2@CORP.LAN' in body
    body, code = parse_http(fixture('probe_plain_curl.txt'))
    assert code == 401 and 'WWW-Authenticate: Negotiate' in body
    assert parse_http('') == ('', None)


def test_cross_realm_kvno():
    r = kinit_result(fixture('probe_researcher.txt'))
    assert r['ok'] and r['then'][0][1] == '0' and 'kvno = 1' in r['then'][0][0]


def test_kinit_cmd_shape():
    cmd = kinit_cmd('dev2', "pa'ss", '/tmp/cc', then=['klist'])
    assert '\n' not in cmd and cmd.startswith('rm -f /tmp/cc; printf')
    assert "if [ $rc -eq 0 ]; then KRB5CCNAME=FILE:/tmp/cc klist 2>&1" in cmd and cmd.endswith('; rm -f /tmp/cc')
    # a skipped command leaves a "none" marker
    assert split_markers("x\n===RC 1\n===RC none\n") == [("x", "1"), ("", None)]
    out = subprocess.run(["sh", "-c", cmd.replace('kinit dev2', 'false')], capture_output=True, text=True).stdout
    assert out.splitlines()[-1] == '===RC none'


def test_service_clients():
    ssh = gssapi_ssh('dev2@srv.corp.lan')
    assert '-o PreferredAuthentications=gssapi-with-mic' in ssh and '-o BatchMode=yes' in ssh
    assert ssh.endswith("dev2@srv.corp.lan 'id -un'")
    assert negotiate_curl('http://srv/p/').startswith('curl -s -m 5 --negotiate -u :')
    assert plain_curl('http://srv/p/').endswith('echo "===RC $?"')


def test_getprinc_and_getpol():
    nina = parse_getprinc(fixture('kdc_getprinc_nina.txt'))
    assert nina['principal'] == 'nina@CORP.LAN' and nina['policy'] == 'staff'
    assert nina['attributes'] == ['REQUIRES_PRE_AUTH'] and nina['max_life'] == '0 days 10:00:00'
    assert nina['keys'] == ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96']
    leaver = parse_getprinc(fixture('kdc_getprinc_leaver.txt'))
    assert 'DISALLOW_ALL_TIX' in leaver['attributes'] and leaver['policy'] is None
    assert parse_getprinc(fixture('kdc_getprinc_missing.txt')) is None
    staff = parse_getpol(fixture('kdc_getpol_staff.txt'))
    assert staff == {'policy': 'staff', 'min_length': 10, 'min_classes': 3, 'history': 1}
    assert parse_getpol(fixture('kdc_getpol_missing.txt')) is None


def test_keytab():
    assert parse_keytab(fixture('srv_keytab_host.txt')) == [(3, 'host/srv.corp.lan@CORP.LAN')] * 2
    assert parse_keytab('klist: No such file or directory') == []


def test_helpdesk_kadmin_outputs():
    assert 'changed' in fixture('probe_helpdesk_cpw.txt')
    for name in ('probe_helpdesk_add.txt', 'probe_helpdesk_admin.txt'):
        out = fixture(name)
        assert 'requires' in out and 'privilege' in out
    assert kadmin_cmd('helpdesk', 'pw', 'cpw dev1') == \
        "kadmin -p helpdesk -w pw -q 'cpw dev1' 2>&1; echo \"===RC $?\""


def test_wrappers():
    grade = make_grade({
        kadmin_local_cmd('getprinc nina'): (fixture('kdc_getprinc_nina.txt'), 0),
        kadmin_local_cmd('getpol staff'): (fixture('kdc_getpol_staff.txt'), 0),
        "klist -k /etc/krb5.keytab 2>&1": (fixture('srv_keytab_host.txt'), 0),
        kinit_cmd('nina', 'pw', '/tmp/cc', ['klist -e']): (fixture('probe_kinit_nina.txt'), 0),
    })
    assert get_principal(grade, 'kdc', 'nina')['policy'] == 'staff'
    assert get_policy(grade, 'kdc', 'staff')['min_length'] == 10
    assert get_keytab(grade, 'srv', '/etc/krb5.keytab')[0][0] == 3
    assert kinit_test(grade, 'probe', 'nina', 'pw', '/tmp/cc', then=['klist -e'])['ok']
    assert get_principal(grade, 'kdc', 'omar') is None


def test_renderers():
    conf = render_krb5_conf('CORP.LAN', {'CORP.LAN': ('kdc.corp.lan', 'kdc.corp.lan'), 'LAB.CORP.LAN': ('kdc2', None)},
                            domain_realm=[('.corp.lan', 'CORP.LAN')])
    assert '\tdefault_realm = CORP.LAN\n' in conf and '\trdns = false\n' in conf
    assert '\t\tadmin_server = kdc.corp.lan\n' in conf and conf.count('admin_server') == 1
    assert '[domain_realm]\n\t.corp.lan = CORP.LAN\n' in conf
    kdc = render_kdc_conf('LAB.CORP.LAN')
    assert '\tLAB.CORP.LAN = {' in kdc and 'supported_enctypes = aes256-cts:normal aes128-cts:normal' in kdc
    assert render_kadm5_acl([('*/admin@CORP.LAN', '*', None), ('helpdesk@CORP.LAN', 'ci', '*@CORP.LAN')]) == \
        "*/admin@CORP.LAN\t*\nhelpdesk@CORP.LAN\tci\t*@CORP.LAN\n"
    cmds = create_realm_cmds('CORP.LAN', 'master')
    assert cmds[-1] == "kdb5_util create -s -r CORP.LAN -P master 2>&1"
