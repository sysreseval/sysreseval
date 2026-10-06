"""Tests for lib/smtp.py and lib/smtp_probe.py (mail labs: Postfix, Dovecot, OpenDKIM, SPF).

Fixtures in tests/mock_data/smtp/ were captured on 2026-10-06 from the SMTP lab
(lab/sre/misc/smtp.py) running on the mail image (images/mail, published as sysreseval/mail:1.30; Debian 12:
Postfix 3.7.11, Dovecot 2.3.19, OpenDKIM 2.11.0, postfix-policyd-spf-python 3.0.4, Python
3.11.2): the test outputs (`sre cat --tests --json`) of one evaluation in the initial state
(`*_initial.*`, nothing configured on mx1) and of one in the `final` state (`*_final.*`, 80/80).
`commands_final.json` keeps the exact grader command of every fixture.
"""
import base64
import json
import socket
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make lib/ and src/ importable without Docker.
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()

import smtp_probe as probe_script  # noqa: E402
from smtp import (  # noqa: E402
    PROBE_HEADER, PROBE_QUERY_HEADER, SMTP_PROBE_PATH, MailqEntry, ProbeResult, body_contains,
    body_text, deferred_to, dkim_txt_record, doveconf_listener, doveconf_value, find_messages,
    generate_dkim_keypair, get_doveconf, get_mailq, get_master_services, get_postconf,
    imap_query, install_smtp_probe, is_bounce, maildir_cleanup_command, maildir_dump_command,
    mynetworks_covers, normalize_text, parse_authentication_results, parse_dkim_signature,
    parse_dkim_txt, parse_doveconf, parse_dsn, parse_maildir_dump, parse_mailq,
    parse_master_services, parse_postconf, parse_received_spf, parse_smtp_probe, parse_spf,
    parse_txt_strings, queue_cleanup_command, received_hops, relayhost_target,
    render_unbound_records, smtp_probe, smtp_probe_command, smtp_query, spf_record_ok,
)
from tls import get_tls_server_certificate  # noqa: E402

FIXTURES = Path(__file__).parent / 'mock_data' / 'smtp'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def make_grade(responses: dict | None = None):
    """Grade mock dispatching on (machine, command); records every call."""
    grade = MagicMock()
    responses = responses or {}

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get((machine_name, command), ('', 0))

    grade.test.side_effect = _test
    return grade


# ---------------------------------------------------------------------------
# Probe spec and results
# ---------------------------------------------------------------------------

class TestProbeSpec:
    def test_smtp_query_builds_a_message_with_the_probe_headers(self):
        q = smtp_query('ext_in', '192.0.2.10', helo='h2.beta.tp', mail_from='h2@beta.tp',
                       rcpt_to=['alice@alpha.tp'], token='abcd', body='hello')
        assert q['kind'] == 'smtp' and q['host'] == '192.0.2.10' and q['port'] == 25
        assert q['rcpt_to'] == ['alice@alpha.tp'] and q['auth'] is None and q['starttls'] is False
        assert q['data']['headers'][PROBE_HEADER] == 'abcd'
        assert q['data']['headers'][PROBE_QUERY_HEADER] == 'ext_in'
        assert q['data']['headers']['Subject'] == '[SRE] ext_in' and q['data']['body'] == 'hello'

    def test_smtp_query_without_send_has_no_data(self):
        q = smtp_query('relay', '192.0.2.10', mail_from='a@b', rcpt_to=['c@d'], send=False,
                       starttls=True, auth=('alice', 'pw'), port=587)
        assert q['data'] is None and q['starttls'] is True and q['auth'] == ['alice', 'pw']
        assert q['port'] == 587

    def test_imap_query_searches_the_token_header(self):
        q = imap_query('imap', '192.0.2.10', 'alice', 'pw', token='abcd', poll=8)
        assert q['kind'] == 'imap' and q['header'] == [PROBE_HEADER, 'abcd'] and q['poll'] == 8
        assert q['port'] == 143 and 'Subject' in q['fetch']

    def test_command_is_stable_and_self_contained(self):
        spec = {'timeout': 5, 'queries': [smtp_query('q', '192.0.2.10', mail_from='a@b', rcpt_to=['c@d'])]}
        cmd = smtp_probe_command(spec)
        assert cmd == smtp_probe_command(json.loads(json.dumps(spec)))
        assert cmd.startswith(f'python3 {SMTP_PROBE_PATH} ')
        decoded = json.loads(base64.urlsafe_b64decode(cmd.split()[-1]))
        assert decoded == spec

    def test_install_copies_the_script(self):
        ns = MagicMock()
        install_smtp_probe(ns, 'h1', step=2)
        ns.file.assert_called_once()
        args, kwargs = ns.file.call_args
        assert args[0] == 'h1' and args[1] == SMTP_PROBE_PATH
        assert args[2].startswith('#!/usr/bin/env python3') and 'def smtp_query' in args[2]
        assert kwargs['permissions'] == 0o755 and kwargs['step'] == 2


class TestParseProbe:
    def test_final_results_of_h2(self):
        r = parse_smtp_probe(load('probe_h2_final.json'))
        assert set(r) == {'ext_in', 'ext_relay', 'ext_alias', 'ext_fwd', 'sub_noauth', 'sub_auth'}
        ext_in = r['ext_in']
        assert ext_in.connected and ext_in.code(ext_in.banner) == 220
        assert ext_in.accepted('alice@alpha.tp') and ext_in.sent and ext_in.queue_id == 'EF831189786'
        assert 'STARTTLS' in ext_in.extensions and ext_in.extensions['SIZE'] == '10240000'
        relay = r['ext_relay']
        assert relay.rcpt_code('sonde@beta.tp') == 454 and not relay.accepted('sonde@beta.tp')
        assert relay.data is None and not relay.sent and relay.queue_id is None
        noauth = r['sub_noauth']
        assert noauth.code(noauth.starttls) == 220 and noauth.tls_version == 'TLSv1.3'
        assert 'AUTH' not in noauth.extensions and noauth.extensions_tls['AUTH'] == 'PLAIN LOGIN'
        assert noauth.rcpt_code('sonde@beta.tp') == 554 and noauth.auth is None
        auth = r['sub_auth']
        assert auth.code(auth.auth) == 235 and auth.sent and auth.accepted('sonde@beta.tp')

    def test_initial_results_record_the_connection_error(self):
        r = parse_smtp_probe(load('probe_h2_initial.json'))
        assert not r['ext_in'].connected and r['ext_in'].banner is None
        assert r['ext_in'].error.startswith('ConnectionRefusedError')
        assert r['ext_in'].code(r['ext_in'].banner) == 0 and not r['ext_in'].sent

    def test_imap_results(self):
        r = parse_smtp_probe(load('probe_imap_final.json'))['imap_alice']
        assert r.logged_in and r.count == 3 and len(r.messages) == 3
        assert r.messages[0]['headers']['Subject'] == ['[SRE] ext_in']
        r0 = parse_smtp_probe(load('probe_imap_initial.json'))['imap_alice']
        assert not r0.logged_in and r0.count is None and 'ConnectionRefused' in r0.error

    def test_garbage_gives_no_result(self):
        assert parse_smtp_probe('') == {}
        assert parse_smtp_probe('not json') == {}
        assert parse_smtp_probe('[1, 2]') == {}
        assert parse_smtp_probe('{"errors": ["x"], "results": {"q": 3}}') == {}

    def test_smtp_probe_registers_one_test(self):
        spec = {'timeout': 5, 'queries': [smtp_query('q', '192.0.2.10')]}
        grade = make_grade({('h2', smtp_probe_command(spec)): (load('probe_h1_final.json'), 0)})
        results = smtp_probe(grade, 'h2', spec, step=2, timeout=60)
        grade.test.assert_called_once_with('h2', smtp_probe_command(spec), step=2, timeout=60, allow_error=True)
        assert results['lan_relay'].queue_id == 'F1C6A189787'

    def test_probe_result_defaults(self):
        r = ProbeResult(query_id='x')
        assert r.rcpt == {} and r.messages == [] and not r.sent and not r.logged_in
        assert r.rcpt_code('a@b') == 0 and ProbeResult.code(None) == 0


# ---------------------------------------------------------------------------
# Postfix
# ---------------------------------------------------------------------------

class TestPostconf:
    def test_parse_final(self):
        pc = parse_postconf(load('postconf_mx1_final.txt'))
        assert pc['myhostname'] == 'mx1.alpha.tp' and pc['mydomain'] == 'alpha.tp'
        assert pc['mydestination'] == 'mx1.alpha.tp, alpha.tp, localhost'
        assert pc['relayhost'] == '' and pc['mailbox_command'] == ''  # empty values kept
        assert pc['home_mailbox'] == 'Maildir/' and pc['smtpd_sasl_path'] == 'private/auth'
        assert pc['non_smtpd_milters'] == 'inet:localhost:8891'  # $smtpd_milters expanded by -x

    def test_parse_initial(self):
        pc = parse_postconf(load('postconf_mx1_initial.txt'))
        assert pc['myhostname'] == 'mx1.localdomain' and pc['home_mailbox'] == ''
        assert pc['mynetworks'] == '127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128'

    def test_get_postconf_fails_closed(self):
        grade = make_grade({('mx1', 'postconf -x myhostname'): ('myhostname = x\n', 0),
                            ('pc1', 'postconf -x myhostname'): ('postconf: fatal', 1)})
        assert get_postconf(grade, 'mx1', ('myhostname',)) == {'myhostname': 'x'}
        assert get_postconf(grade, 'pc1', ('myhostname',)) == {}

    def test_mynetworks_covers(self):
        assert mynetworks_covers('127.0.0.0/8 172.22.188.0/24', '172.22.188.0/24')
        assert mynetworks_covers('127.0.0.0/8, 172.22.0.0/16', '172.22.188.0/24')
        assert not mynetworks_covers('127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128', '172.22.188.0/24')
        assert not mynetworks_covers('172.22.188.5', '172.22.188.0/24')
        assert mynetworks_covers('0.0.0.0/0', '10.0.0.0/24')
        assert not mynetworks_covers('hash:/etc/postfix/networks !172.22.188.0/24', '172.22.188.0/24')
        assert not mynetworks_covers('', '10.0.0.0/24')

    def test_relayhost_target(self):
        assert relayhost_target('[mx1.alpha.tp]') == ('mx1.alpha.tp', None)
        assert relayhost_target('[mx1.alpha.tp]:587') == ('mx1.alpha.tp', 587)
        assert relayhost_target('mx1.alpha.tp:25') == ('mx1.alpha.tp', 25)
        assert relayhost_target(' [192.0.2.10] ') == ('192.0.2.10', None)
        assert relayhost_target('') == ('', None)


class TestMasterServices:
    def test_final_has_submission_with_its_options(self):
        services = parse_master_services(load('master_mx1_final.txt'))
        sub = services['submission/inet']
        assert sub['command'] == 'smtpd' and sub['chroot'] == 'y' and sub['private'] == 'n'
        assert sub['options'] == {
            'syslog_name': 'postfix/submission', 'smtpd_tls_security_level': 'encrypt',
            'smtpd_sasl_auth_enable': 'yes', 'smtpd_relay_restrictions': 'permit_sasl_authenticated,reject',
        }
        assert services['smtp/inet']['command'] == 'smtpd' and services['smtp/unix']['command'] == 'smtp'
        assert services['relay/unix']['options'] == {'syslog_name': 'postfix/$service_name'}
        assert services['maildrop/unix']['args'][:2] == ['flags=DRXhu', 'user=vmail']

    def test_initial_has_no_submission(self):
        services = parse_master_services(load('master_mx1_initial.txt'))
        assert 'submission/inet' not in services and 'smtp/inet' in services

    def test_get_master_services(self):
        grade = make_grade({('mx1', 'postconf -M'): (load('master_mx1_final.txt'), 0)})
        assert 'submission/inet' in get_master_services(grade, 'mx1')
        assert get_master_services(make_grade({('mx1', 'postconf -M'): ('', 1)}), 'mx1') == {}


class TestMailq:
    def test_parse_deferred(self):
        entries = parse_mailq(load('postqueue_j_final.txt'))
        assert len(entries) == 2 and all(isinstance(e, MailqEntry) for e in entries)
        e = entries[0]
        assert e.queue_id == 'AC30E189112' and e.queue_name == 'deferred' and e.sender == 'alice@alpha.tp'
        assert e.recipients == [('x@delta.tp', 'connect to mail.delta.tp[172.22.188.174]:25: Connection refused')]
        assert e.arrival_time == 1791287859 and e.message_size == 431

    def test_deferred_to(self):
        entries = parse_mailq(load('postqueue_j_final.txt'))
        assert len(deferred_to(entries, 'delta.tp')) == 2
        assert deferred_to(entries, 'beta.tp') == []
        entries[0].queue_name = 'active'
        assert len(deferred_to(entries, 'DELTA.TP')) == 1

    def test_empty_and_malformed(self):
        assert parse_mailq('') == [] and parse_mailq('\n\n') == []
        assert parse_mailq('{"queue_name": "x"}\nnot json\n{"queue_id": "A", "recipients": 3}\n')[0].recipients == []

    def test_get_mailq_and_cleanup(self):
        grade = make_grade({('mx1', 'postqueue -j'): (load('postqueue_j_final.txt'), 0)})
        assert get_mailq(grade, 'mx1')[1].queue_id == '4B87F18972A'
        cmd = queue_cleanup_command('probe@alpha.tp')
        assert cmd.startswith('postqueue -j') and 'postsuper -d -' in cmd and "'probe@alpha.tp'" in cmd
        assert cmd.endswith('; true') and '\n' not in cmd


# ---------------------------------------------------------------------------
# Maildir
# ---------------------------------------------------------------------------

class TestMaildirCommands:
    def test_dump_without_wait(self):
        cmd = maildir_dump_command(['/home/alice/Maildir'])
        assert cmd.startswith('for f in $(find /home/alice/Maildir -type f')
        assert "-path '*/new/*' -o -path '*/cur/*'" in cmd and 'base64 -w0' in cmd and '\n' not in cmd
        assert cmd == maildir_dump_command(['/home/alice/Maildir'], token='t', expected=0, max_wait=5)

    def test_dump_with_wait(self):
        cmd = maildir_dump_command(['/home/bob/Maildir', '/home/dave/Maildir'], token='abcd', expected=4, max_wait=10)
        assert cmd.startswith('i=0; while [ $i -lt 10 ] && [ $(grep -rls abcd /home/bob/Maildir/new /home/bob/Maildir/cur'
                              ' /home/dave/Maildir/new /home/dave/Maildir/cur 2>/dev/null | wc -l) -lt 4 ]; do sleep 1;')
        assert 'for f in $(find /home/bob/Maildir /home/dave/Maildir' in cmd

    def test_cleanup(self):
        cmd = maildir_cleanup_command(['/home/alice/Maildir'], "ab'cd")
        assert cmd == "grep -rls 'ab'\"'\"'cd' /home/alice/Maildir 2>/dev/null | xargs -r rm -f; true"


class TestMaildirDump:
    def test_mx1_messages(self):
        msgs = parse_maildir_dump(load('maildir_dump_mx1_final.txt'))
        assert [(m.user, m.folder) for m in msgs] == [('alice', 'new')] * 4
        assert all(m.path.startswith('/home/alice/Maildir/new/') for m in msgs)
        token = msgs[1][PROBE_HEADER]
        assert len(token) == 16
        assert [m[PROBE_QUERY_HEADER] for m in find_messages(msgs, token)] == ['ext_in', 'pc1', 'ext_alias']
        assert len(find_messages(msgs, token, 'pc1')) == 1 and find_messages(msgs, 'other') == []
        assert body_text(find_messages(msgs, token, 'ext_in')[0].message).strip() == 'message de test'

    def test_received_hops(self):
        msgs = parse_maildir_dump(load('maildir_dump_mx1_final.txt'))
        pc1 = [m for m in msgs if m[PROBE_QUERY_HEADER] == 'pc1'][0]
        hops = received_hops(pc1.message)
        assert hops[0] == {'from': 'pc1.alpha.tp', 'from_ip': '172.22.188.231', 'by': 'mx1.alpha.tp',
                           'with': 'ESMTPS', 'id': hops[0]['id'], 'for': 'alice@alpha.tp'}
        assert hops[1]['from'] == '' and hops[1]['by'] == 'pc1.alpha.tp'  # pickup: no "from"

    def test_bounce(self):
        msgs = parse_maildir_dump(load('maildir_dump_mx1_final.txt'))
        dsn = [m for m in msgs if is_bounce(m.message)]
        assert len(dsn) == 1 and not is_bounce(msgs[1].message)
        parsed = parse_dsn(dsn[0].message)
        assert parsed['recipients'] == [{
            'final_recipient': 'inconnu@beta.tp', 'action': 'failed', 'status': '5.1.1',
            'diagnostic_code': 'smtp; 550 5.1.1 <inconnu@beta.tp>: Recipient address rejected: User unknown'
                               ' in local recipient table'}]
        assert parsed['original'] is not None and parsed['original']['To'] == 'inconnu@beta.tp'

    def test_mx2_messages_and_authentication_headers(self):
        msgs = parse_maildir_dump(load('maildir_dump_mx2_final.txt'))
        assert [(m.user, m[PROBE_QUERY_HEADER]) for m in msgs] == [
            ('bob', None), ('dave', 'ext_alias'), ('dave', 'ext_fwd'), ('sonde', 'lan_relay'), ('sonde', 'sub_auth')]
        bob = msgs[0].message
        assert parse_received_spf(bob['Received-SPF'])['result'] == 'fail'
        assert received_hops(bob)[0]['from_ip'] == '172.22.188.231'
        relay = msgs[3].message
        spf = parse_received_spf(relay['Received-SPF'])
        assert spf == {'result': 'pass', 'comment': 'mailfrom', 'identity': 'mailfrom',
                       'client-ip': '172.22.188.18', 'helo': 'mx1.alpha.tp',
                       'envelope-from': 'h1@alpha.tp', 'receiver': 'beta.tp'}
        assert parse_received_spf(msgs[1].message['Received-SPF'])['result'] == 'none'
        sig = parse_dkim_signature(relay['DKIM-Signature'])
        assert sig['v'] == '1' and sig['a'] == 'rsa-sha256' and sig['d'] == 'alpha.tp' and sig['s'] == 'tp'
        assert sig['h'] == 'From:To:Date:Subject:From' and ' ' not in sig['b'] and sig['c'] == 'relaxed/simple'
        ar = parse_authentication_results(relay['Authentication-Results'])
        assert ar['authserv_id'] == 'mx2.beta.tp' and ar['results'] == {'dkim': 'pass', 'dkim-atps': 'neutral'}
        assert ar['properties']['dkim']['header.d'] == 'alpha.tp' and ar['properties']['dkim']['header.s'] == 'tp'
        hops = received_hops(msgs[4].message)
        assert hops[1]['with'] == 'ESMTPSA' and hops[0]['with'] == 'ESMTPS'

    def test_body_contains_ignores_case_and_punctuation(self):
        msgs = parse_maildir_dump(load('maildir_dump_mx2_final.txt'))
        words = body_text(msgs[0].message).split()
        assert body_contains(msgs[0].message, ', '.join(w.upper() for w in words) + '!')
        assert not body_contains(msgs[0].message, 'absent words here')
        assert not body_contains(msgs[0].message, '')
        assert normalize_text("  Été, c'est  FINI. ") == 'été c est fini'

    def test_garbage_entries_are_skipped(self):
        out = '===SRE-MAIL /home/a/Maildir/new/1\nnot base64!\n===SRE-MAIL /home/b/Maildir/cur/2\n' \
              + base64.b64encode(b'Subject: ok\n\nbody\n').decode() + '\n'
        msgs = parse_maildir_dump(out)
        assert [(m.user, m.folder, m['Subject']) for m in msgs] == [('b', 'cur', 'ok')]
        assert parse_maildir_dump('') == [] and parse_maildir_dump('===SRE-MAIL /x\n') == []

    def test_parse_authentication_results_without_result(self):
        assert parse_authentication_results('mx2.beta.tp; none') == {'authserv_id': 'mx2.beta.tp', 'results': {}, 'properties': {}}
        assert parse_authentication_results('')['authserv_id'] == ''


# ---------------------------------------------------------------------------
# Dovecot
# ---------------------------------------------------------------------------

class TestDoveconf:
    def test_parse_final(self):
        conf = parse_doveconf(load('doveconf_mx1_final.txt'))
        assert conf['mail_location'] == 'maildir:~/Maildir' and conf['protocols'] == 'imap'
        assert conf['passdb'] == {'driver': 'pam'} and conf['listen'] == '*'
        assert conf['namespace inbox']['mailbox Drafts'] == {'special_use': '\\Drafts'}
        assert doveconf_listener(conf, '/var/spool/postfix/private/auth') == {'group': 'postfix', 'mode': '0660', 'user': 'postfix'}
        assert doveconf_listener(conf, '/run/dovecot/auth') is None
        assert doveconf_value(conf, 'mail_location') == 'maildir:~/Maildir' and doveconf_value(conf, 'missing') == ''

    def test_quotes_and_merging(self):
        conf = parse_doveconf('# comment\nprotocols = " imap"\nservice auth {\n  a = 1\n}\nservice auth {\n  b = 2\n}\n}\n')
        assert doveconf_value(conf, 'protocols') == 'imap' and conf['service auth'] == {'a': '1', 'b': '2'}

    def test_get_doveconf(self):
        grade = make_grade({('mx1', 'doveconf -n'): (load('doveconf_mx1_final.txt'), 0), ('mx2', 'doveconf -n'): ('error', 89)})
        assert get_doveconf(grade, 'mx1')['protocols'] == 'imap' and get_doveconf(grade, 'mx2') == {}


# ---------------------------------------------------------------------------
# DNS: unbound records, SPF, DKIM
# ---------------------------------------------------------------------------

class TestDnsRecords:
    def test_render_unbound_records(self):
        text = render_unbound_records([
            ('alpha.tp', 'MX', '10 mx1.alpha.tp.'), ('mx1.alpha.tp.', 'A', '192.0.2.10'),
            ('192.0.2.10', 'PTR', 'mx1.alpha.tp'), ('alpha.tp', 'TXT', 'v=spf1 mx -all'),
            ('k._domainkey.alpha.tp', 'txt', 'v=DKIM1; p=' + 'A' * 300),
        ])
        lines = text.splitlines()
        assert lines[0] == '    local-data: "alpha.tp. IN MX 10 mx1.alpha.tp."'
        assert lines[1] == '    local-data: "mx1.alpha.tp. IN A 192.0.2.10"'
        assert lines[2] == '    local-data-ptr: "192.0.2.10 mx1.alpha.tp."'
        assert lines[3] == """    local-data: 'alpha.tp. IN TXT "v=spf1 mx -all"'"""
        assert lines[4].startswith("""    local-data: 'k._domainkey.alpha.tp. IN TXT "v=DKIM1; p=AAA""")
        assert lines[4].count('"') == 4 and len(lines[4].split('" "')[0].split('"')[1]) == 255
        assert render_unbound_records([]) == '' and text.endswith('\n')

    def test_parse_txt_strings(self):
        assert parse_txt_strings(load('dig_txt_spf_final.txt')) == ['v=spf1 mx -all']
        (dkim,) = parse_txt_strings(load('dig_txt_dkim_final.txt'))
        assert dkim.startswith('v=DKIM1; k=rsa; p=MIIBIjAN') and '" "' not in dkim and len(dkim) > 400
        assert parse_txt_strings('') == [] and parse_txt_strings('"a\\"b" "c"\n"d"\n') == ['a"bc', 'd']

    def test_parse_spf(self):
        assert parse_spf('v=spf1 mx a:mx1.alpha.tp ip4:192.0.2.0/24 include:other.tp redirect=x.tp ~all') == {
            'version': 'spf1', 'terms': [('+', 'mx', None), ('+', 'a', 'mx1.alpha.tp'), ('+', 'ip4', '192.0.2.0/24'),
                                         ('+', 'include', 'other.tp'), ('+', 'redirect=', 'x.tp'), ('~', 'all', None)]}
        assert parse_spf('V=SPF1 -all')['terms'] == [('-', 'all', None)]
        assert parse_spf('v=spf2 mx') is None and parse_spf('') is None

    def test_spf_record_ok(self):
        assert spf_record_ok('v=spf1 mx -all', mx_ip='192.0.2.10') == {'valid': True, 'authorizes_mx': True, 'all': '-'}
        assert spf_record_ok('v=spf1 ip4:192.0.2.0/24 ~all', mx_ip='192.0.2.10') == {'valid': True, 'authorizes_mx': True, 'all': '~'}
        assert spf_record_ok('v=spf1 a:mx1.alpha.tp. -all', mx_name='mx1.alpha.tp')['authorizes_mx']
        assert not spf_record_ok('v=spf1 ip4:198.51.100.0/24 -all', mx_ip='192.0.2.10')['authorizes_mx']
        assert not spf_record_ok('v=spf1 -mx -all', mx_ip='192.0.2.10')['authorizes_mx']
        assert spf_record_ok('v=spf1 mx', mx_ip='192.0.2.10')['all'] is None
        assert spf_record_ok('mx -all') == {'valid': False, 'authorizes_mx': False, 'all': None}

    def test_dkim_txt(self):
        (record,) = parse_txt_strings(load('dig_txt_dkim_final.txt'))
        tags = parse_dkim_txt(record)
        assert tags['v'] == 'DKIM1' and tags['k'] == 'rsa' and tags['p'].startswith('MIIBIjAN')
        assert base64.b64decode(tags['p'])  # the key is valid base64
        assert parse_dkim_txt('v=DKIM1; p=AB CD') == {'v': 'DKIM1', 'p': 'ABCD'}
        assert dkim_txt_record('ABC') == 'v=DKIM1; k=rsa; p=ABC'

    def test_generate_dkim_keypair(self):
        pytest.importorskip('cryptography')
        private_pem, public_b64 = generate_dkim_keypair(1024)
        assert private_pem.startswith('-----BEGIN PRIVATE KEY-----')  # PKCS#8, as opendkim-genkey
        assert base64.b64decode(public_b64)[:5] == b'\x30\x81\x9f\x30\x0d'  # DER SubjectPublicKeyInfo (1024-bit)
        assert parse_dkim_txt(dkim_txt_record(public_b64))['p'] == public_b64


# ---------------------------------------------------------------------------
# The probe script itself (against a loopback fake SMTP server)
# ---------------------------------------------------------------------------

class FakeSmtpServer(threading.Thread):
    """Minimal SMTP server: accepts recipients at @local.test, refuses the others."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received = b''

    def run(self):
        conn, _ = self.sock.accept()
        f = conn.makefile('rwb')

        def send(line):
            f.write(line.encode() + b'\r\n')
            f.flush()

        send('220 fake.test ESMTP ready')
        in_data = False
        while True:
            line = f.readline()
            if not line:
                break
            if in_data:
                if line == b'.\r\n':
                    in_data = False
                    send('250 2.0.0 Ok: queued as FAKE123')
                else:
                    self.received += line
                continue
            cmd = line.decode().strip()
            word = cmd.split(' ', 1)[0].upper()
            if word == 'EHLO':
                send('250-fake.test')
                send('250-SIZE 1000')
                send('250 STARTTLS')
            elif word == 'MAIL':
                send('250 2.1.0 Ok')
            elif word == 'RCPT':
                send('250 2.1.5 Ok' if '@local.test' in cmd else '554 5.7.1 Relay access denied')
            elif word == 'DATA':
                in_data = True
                send('354 End data with <CR><LF>.<CR><LF>')
            elif word == 'QUIT':
                send('221 2.0.0 Bye')
                break
            else:
                send('500 unknown')
        conn.close()


class TestProbeScript:
    def test_helpers(self):
        assert probe_script.queue_id('2.0.0 Ok: queued as 4ABC') == '4ABC'
        assert probe_script.queue_id('2.0.0 Ok') is None and probe_script.queue_id(None) is None
        assert probe_script.extensions({'size': '1000', 'auth': ' PLAIN LOGIN ', 'starttls': ''}) == {
            'SIZE': '1000', 'AUTH': 'PLAIN LOGIN', 'STARTTLS': ''}
        msg = probe_script.build_message('a@b', ['c@d', 'e@f'], {'headers': {'X-Test': '1'}, 'body': 'line1\nline2'}, 'h.test')
        assert msg.startswith(b'From: a@b\r\nTo: c@d, e@f\r\nDate: ') and b'\r\nX-Test: 1\r\nSubject: probe\r\n\r\nline1\r\nline2\r\n' in msg
        assert b'Message-ID: <' in msg and b'@h.test>' in msg

    def test_main_against_a_fake_server(self, capsys):
        server = FakeSmtpServer()
        server.start()
        spec = {'timeout': 5, 'queries': [
            smtp_query('ok', '127.0.0.1', port=server.port, helo='probe.test', mail_from='a@b.test',
                       rcpt_to=['x@local.test', 'y@other.test'], token='tok', body='hello'),
        ]}
        assert probe_script.main(['smtp_probe.py', smtp_probe_command(spec).split()[-1]]) == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc['errors'] == []
        r = parse_smtp_probe(json.dumps(doc))['ok']
        assert r.connected and r.banner == [220, 'fake.test ESMTP ready'] and r.extensions == {'SIZE': '1000', 'STARTTLS': ''}
        assert r.rcpt == {'x@local.test': [250, '2.1.5 Ok'], 'y@other.test': [554, '5.7.1 Relay access denied']}
        assert r.sent and r.queue_id == 'FAKE123' and r.error is None and r.starttls is None
        server.join(5)
        assert b'X-SRE-Probe: tok\r\n' in server.received and b'hello\r\n' in server.received

    def test_closed_port_and_bad_spec(self, capsys):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        spec = {'timeout': 2, 'queries': [smtp_query('refused', '127.0.0.1', port=port, mail_from='a@b', rcpt_to=['c@d']),
                                          imap_query('imap', '127.0.0.1', 'u', 'p', port=port, token='t')]}
        assert probe_script.main(['x', smtp_probe_command(spec).split()[-1]]) == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc['errors'] == []
        assert not doc['results']['refused']['connected'] and 'ConnectionRefusedError' in doc['results']['refused']['error']
        assert doc['results']['imap']['login'] is None and 'ConnectionRefusedError' in doc['results']['imap']['error']
        assert probe_script.main(['x', 'not-base64!!']) == 0
        assert json.loads(capsys.readouterr().out)['errors']


# ---------------------------------------------------------------------------
# tls.get_tls_server_certificate with STARTTLS
# ---------------------------------------------------------------------------

class TestStartTlsCertificate:
    def test_command_and_parsing(self):
        cmd = ("openssl s_client -connect 192.0.2.10:587 -servername mx1.alpha.tp -starttls smtp </dev/null 2>/dev/null"
               " | openssl x509 -noout -subject -issuer -fingerprint -sha256")
        grade = make_grade({('h2', cmd): (load('s_client_starttls_h2_final.txt'), 0)})
        cert = get_tls_server_certificate(grade, 'h2', '192.0.2.10', port=587, servername='mx1.alpha.tp', starttls='smtp')
        grade.test.assert_called_once_with(machine_name='h2', command=cmd, step=1, allow_error=True)
        assert cert['common_name'] == 'mx1.alpha.tp' and cert['fingerprint'].startswith('16:A9:71')

    def test_without_starttls_the_command_is_unchanged(self):
        grade = make_grade()
        get_tls_server_certificate(grade, 'h2', '192.0.2.10')
        assert '-starttls' not in grade.test.call_args.kwargs['command']
