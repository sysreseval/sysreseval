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
#               "helo": "sonde.example", "starttls": false, "ssl": false,
#               "auth": ["alice", "secret"] or null,
#               "mail_from": "sonde@example", "rcpt_to": ["alice@alpha.tp"],
#               "data": {"headers": {"Subject": "test"}, "body": "..."} or null,
#               "source_ip": null}
#              ("ssl": implicit TLS from the first byte, port 465; "starttls": the STARTTLS
#              command after EHLO, ports 25 / 587)
# IMAP query = {"id": "imap_alice", "kind": "imap", "host": "192.0.2.10", "port": 143,
#               "user": "alice", "password": "secret", "starttls": false, "ssl": false,
#               "header": ["X-SRE-Probe", "token"], "poll": 8, "fetch": ["Subject", "Received"]}
# ManageSieve query = {"id": "sieve_alice", "kind": "managesieve", "host": "192.0.2.10",
#               "port": 4190, "user": "alice", "password": "secret", "starttls": true}
#              (RFC 5804: the capabilities, STARTTLS, AUTHENTICATE PLAIN, LISTSCRIPTS; the result
#              holds "capabilities", "starttls", "tls_version", "login" and "scripts" =
#              [{"name": "filters", "active": true}])
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
import socket
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
    """RFC 5322 text (CRLF, UTF-8 bytes) of the probe message.  The headers of *data*
    replace the default From / To / Date / Message-ID of the same name (a message whose
    ``From:`` differs from the envelope sender)."""
    given = data.get('headers') or {}
    given_names = {name.lower() for name in given}
    headers = [(name, value) for name, value in (
        ('From', mail_from), ('To', ', '.join(rcpt_to)),
        ('Date', formatdate(localtime=True)), ('Message-ID', make_msgid(domain=helo)))
        if name.lower() not in given_names]
    for name, value in given.items():
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
    if q.get('ssl'):  # implicit TLS (SMTPS, port 465): the whole session is encrypted
        s = smtplib.SMTP_SSL(local_hostname=helo, timeout=timeout, context=_tls_context())
    else:
        s = smtplib.SMTP(local_hostname=helo, timeout=timeout)
    try:
        source = (q['source_ip'], 0) if q.get('source_ip') else None
        # smtplib only records the host given to the constructor; SMTP_SSL.connect() and
        # starttls() need it as the TLS server_hostname (an empty one is refused even without
        # hostname checking), so it is set before the connection.
        s._host = q['host']
        r['banner'] = _reply(s.connect(q['host'], int(q.get('port', 25)), source_address=source))
        r['connected'] = True
        if q.get('ssl'):
            r['tls_version'] = s.sock.version()
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


class _Lines:
    """Line reader on a socket (plain or TLS) for the ManageSieve dialogue."""

    def __init__(self, sock):
        self.sock, self.buf = sock, b''

    def readline(self):
        while b'\n' not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError('connection closed')
            self.buf += chunk
        line, self.buf = self.buf.split(b'\n', 1)
        return line.decode('utf-8', 'replace').rstrip('\r')

    def response(self):
        """The lines of one response, the final OK / NO / BYE line last."""
        lines = []
        while True:
            text = self.readline()
            lines.append(text)
            if re.match(r'^(OK|NO|BYE)(\s|$)', text):
                return lines


def _sieve_capabilities(lines):
    """{"IMPLEMENTATION": "Dovecot Pigeonhole", "SIEVE": "fileinto ...", "STARTTLS": "", ...}
    from the capability lines of a greeting (the final OK excluded)."""
    caps = {}
    for text in lines[:-1]:
        m = re.match(r'^"([^"]+)"(?:\s+"(.*)")?$', text)
        if m:
            caps[m.group(1).upper()] = m.group(2) or ''
    return caps


def managesieve_query(q, timeout):
    """Run one ManageSieve query (RFC 5804): greeting, [STARTTLS], [AUTHENTICATE PLAIN then
    LISTSCRIPTS], LOGOUT; see the module comment."""
    r = {'connected': False, 'capabilities': None, 'starttls': None, 'tls_version': None,
         'login': None, 'scripts': None, 'error': None}
    sock = None
    try:
        sock = socket.create_connection((q['host'], int(q.get('port') or 4190)), timeout=timeout)
        r['connected'] = True
        lines = _Lines(sock)
        r['capabilities'] = _sieve_capabilities(lines.response())
        if q.get('starttls'):
            sock.sendall(b'STARTTLS\r\n')
            reply = lines.response()[-1]
            r['starttls'] = reply
            if not reply.startswith('OK'):
                return r
            sock = _tls_context().wrap_socket(sock, server_hostname=q['host'])
            r['tls_version'] = sock.version()
            lines = _Lines(sock)
            r['capabilities'] = _sieve_capabilities(lines.response())  # sent again in TLS
        if q.get('user') is not None:
            token = base64.b64encode(f"\0{q['user']}\0{q.get('password') or ''}".encode()).decode()
            sock.sendall(f'AUTHENTICATE "PLAIN" "{token}"\r\n'.encode())
            reply = lines.response()[-1]
            r['login'] = 'OK' if reply.startswith('OK') else f'NO: {reply}'
            if r['login'] != 'OK':
                return r
            sock.sendall(b'LISTSCRIPTS\r\n')
            scripts = []
            for text in lines.response()[:-1]:
                m = re.match(r'^"(.*)"(\s+ACTIVE)?$', text)
                if m:
                    scripts.append({'name': m.group(1), 'active': bool(m.group(2))})
            r['scripts'] = scripts
        sock.sendall(b'LOGOUT\r\n')
    except Exception as e:
        r['error'] = f'{type(e).__name__}: {e}'
    finally:
        if sock is not None:
            try:
                sock.close()
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
                elif q.get('kind') == 'managesieve':
                    results[q['id']] = managesieve_query(q, timeout)
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
