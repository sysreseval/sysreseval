#!/usr/bin/env python3
# smtp_probe
# -------------------------------------------------
# Stand-alone SMTP / IMAP client probe run inside a lab container by the grader (see
# install_smtp_probe() / smtp_probe() in lib/smtp.py).  Standard library only.
#
# usage: smtp_probe.py <urlsafe-base64 of a JSON spec>
#
# spec = {"timeout": 5, "queries": [query, ...]}
# SMTP query = {"id": "ext_in", "kind": "smtp", "host": "192.0.2.10", "port": 25,
#               "helo": "sonde.example", "starttls": false, "auth": ["alice", "secret"] or null,
#               "mail_from": "sonde@example", "rcpt_to": ["alice@alpha.tp"],
#               "data": {"headers": {"Subject": "test"}, "body": "..."} or null,
#               "source_ip": null}
# IMAP query = {"id": "imap_alice", "kind": "imap", "host": "192.0.2.10", "port": 143,
#               "user": "alice", "password": "secret", "starttls": false, "ssl": false,
#               "header": ["X-SRE-Probe", "token"], "poll": 8, "fetch": ["Subject", "Received"]}
#
# The queries run one after the other, in the order given.  An SMTP query follows the usual
# dialogue, EHLO, [STARTTLS, EHLO], [AUTH], MAIL FROM, RCPT TO..., [DATA], QUIT, and records the
# reply to every command; DATA is only sent when a recipient was accepted.  An IMAP query logs
# in, looks for the messages carrying the given header (polling up to `poll` seconds) and
# returns some headers of the first ones.  Server certificates are never verified (the labs use
# self-signed certificates).
#
# Always prints one JSON document on stdout and exits 0:
# {"errors": [...], "results": {"ext_in": {...}, "imap_alice": {...}, ...}}
import base64
import imaplib
import json
import re
import smtplib
import ssl
import sys
import time
from email.parser import BytesHeaderParser
from email.utils import formatdate, make_msgid

DEFAULT_TIMEOUT = 5.0
MAX_FETCHED = 5
QUEUE_ID_RE = re.compile(r'queued as (\S+)')


def _text(msg):
    """Reply text as str (a server may answer in any encoding)."""
    if isinstance(msg, bytes):
        return msg.decode('utf-8', 'replace')
    return str(msg)


def _reply(code_msg):
    code, msg = code_msg
    return [int(code), _text(msg)]


def extensions(features):
    """{"SIZE": "10240000", "STARTTLS": "", "AUTH": "PLAIN LOGIN"} from smtplib's esmtp_features."""
    return {name.upper(): ' '.join(value.split()) for name, value in features.items()}


def queue_id(text):
    """Queue identifier of a `250 2.0.0 Ok: queued as 4XYZ` reply, else None."""
    m = QUEUE_ID_RE.search(text or '')
    return m.group(1) if m else None


def build_message(mail_from, rcpt_to, data, helo):
    """RFC 5322 text (CRLF, UTF-8 bytes) of the probe message."""
    headers = [('From', mail_from), ('To', ', '.join(rcpt_to)),
               ('Date', formatdate(localtime=True)), ('Message-ID', make_msgid(domain=helo))]
    for name, value in (data.get('headers') or {}).items():
        headers.append((name, value))
    if not any(name.lower() == 'subject' for name, _ in headers):
        headers.append(('Subject', 'probe'))
    lines = [f'{name}: {value}' for name, value in headers] + ['']
    lines += str(data.get('body') or '').splitlines()
    return ('\r\n'.join(lines) + '\r\n').encode('utf-8')


def _tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def smtp_query(q, timeout):
    """Run one SMTP query and return its record (see the module comment)."""
    r = {'connected': False, 'banner': None, 'ehlo': None, 'extensions': None, 'starttls': None,
         'tls_version': None, 'extensions_tls': None, 'auth': None, 'mail': None, 'rcpt': {},
         'data': None, 'queue_id': None, 'error': None}
    helo = q.get('helo') or 'probe.invalid'
    s = smtplib.SMTP(local_hostname=helo, timeout=timeout)
    try:
        source = (q['source_ip'], 0) if q.get('source_ip') else None
        r['banner'] = _reply(s.connect(q['host'], int(q.get('port', 25)), source_address=source))
        # smtplib only records the host given to the constructor; starttls() needs it as the
        # TLS server_hostname (an empty one is refused even without hostname checking).
        s._host = q['host']
        r['connected'] = True
        if r['banner'][0] != 220:
            return r
        r['ehlo'] = _reply(s.ehlo())
        r['extensions'] = extensions(s.esmtp_features)
        if q.get('starttls'):
            try:
                r['starttls'] = _reply(s.starttls(context=_tls_context()))
            except smtplib.SMTPNotSupportedError:
                r['starttls'] = [0, 'STARTTLS not advertised']
                return r
            except smtplib.SMTPResponseException as e:
                r['starttls'] = [e.smtp_code, _text(e.smtp_error)]
                return r
            r['tls_version'] = s.sock.version()
            r['ehlo'] = _reply(s.ehlo())
            r['extensions_tls'] = extensions(s.esmtp_features)
        if q.get('auth'):
            user, password = q['auth']
            try:
                r['auth'] = _reply(s.login(user, password))
            except smtplib.SMTPAuthenticationError as e:
                r['auth'] = [e.smtp_code, _text(e.smtp_error)]
            except smtplib.SMTPException as e:  # AUTH not advertised, no usable mechanism
                r['auth'] = [0, f'{type(e).__name__}: {e}']
        if q.get('mail_from') is not None:
            r['mail'] = _reply(s.mail(q['mail_from']))
            accepted = []
            for rcpt in q.get('rcpt_to') or []:
                r['rcpt'][rcpt] = _reply(s.rcpt(rcpt))
                if 200 <= r['rcpt'][rcpt][0] < 300:
                    accepted.append(rcpt)
            if accepted and q.get('data') is not None and 200 <= r['mail'][0] < 300:
                try:
                    message = build_message(q['mail_from'], q['rcpt_to'], q['data'], helo)
                    r['data'] = _reply(s.data(message))
                    r['queue_id'] = queue_id(r['data'][1])
                except smtplib.SMTPDataError as e:
                    r['data'] = [e.smtp_code, _text(e.smtp_error)]
        try:
            s.quit()
        except smtplib.SMTPException:
            pass
    except Exception as e:
        r['error'] = f'{type(e).__name__}: {e}'
    finally:
        try:
            s.close()
        except Exception:
            pass
    return r


def imap_query(q, timeout):
    """Run one IMAP query and return its record (see the module comment)."""
    r = {'connected': False, 'login': None, 'count': None, 'messages': [], 'error': None}
    conn = None
    try:
        host = q['host']
        port = int(q.get('port') or (993 if q.get('ssl') else 143))
        if q.get('ssl'):
            conn = imaplib.IMAP4_SSL(host, port, ssl_context=_tls_context(), timeout=timeout)
        else:
            conn = imaplib.IMAP4(host, port, timeout=timeout)
            if q.get('starttls'):
                conn.starttls(_tls_context())
        r['connected'] = True
        try:
            conn.login(q['user'], q['password'])
            r['login'] = 'OK'
        except imaplib.IMAP4.error as e:
            r['login'] = f'NO: {e}'
            return r
        header = q.get('header')
        deadline = time.monotonic() + float(q.get('poll') or 0)
        nums = []
        while True:
            conn.select('INBOX', readonly=True)
            if header:
                typ, found = conn.search(None, 'HEADER', header[0], header[1])
            else:
                typ, found = conn.search(None, 'ALL')
            nums = (found[0] or b'').split() if typ == 'OK' else []
            if nums or time.monotonic() >= deadline:
                break
            time.sleep(1)
        r['count'] = len(nums)
        fetch = list(q.get('fetch') or [])
        for num in nums[:MAX_FETCHED]:
            typ, parts = conn.fetch(num, '(BODY.PEEK[HEADER])')
            raw = b''
            for part in parts:
                if isinstance(part, tuple):
                    raw = part[1]
            msg = BytesHeaderParser().parsebytes(raw)
            r['messages'].append({
                'num': num.decode(),
                'headers': {name: [str(v) for v in msg.get_all(name, [])] for name in fetch},
            })
        conn.logout()
        conn = None
    except Exception as e:
        r['error'] = f'{type(e).__name__}: {e}'
    finally:
        if conn is not None:
            try:
                conn.shutdown()
            except Exception:
                pass
    return r


def main(argv):
    errors, results = [], {}
    try:
        spec = json.loads(base64.urlsafe_b64decode(argv[1]))
        timeout = float(spec.get('timeout', DEFAULT_TIMEOUT))
        for q in spec.get('queries', []):
            try:
                if q.get('kind') == 'imap':
                    results[q['id']] = imap_query(q, timeout)
                else:
                    results[q['id']] = smtp_query(q, timeout)
            except Exception as e:
                errors.append(f"{q.get('id')}: {type(e).__name__}: {e}")
    except Exception as e:  # the grader needs a JSON document whatever happens
        errors.append(f"{type(e).__name__}: {e}")
    print(json.dumps({'errors': errors, 'results': results}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
