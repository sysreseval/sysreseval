"""Electronic mail helpers for the SMTP labs (Postfix, Dovecot, OpenDKIM, SPF).

Pure parsers (unit-tested on the fixtures of ``tests/mock_data/smtp/``) and thin wrappers around
``grade.test()`` / ``net_scheme.file()``:

- **active probe**: :func:`install_smtp_probe` copies ``lib/smtp_probe.py`` (standard library
  only) into a container, usually a hidden one; :func:`smtp_probe` runs a list of SMTP / IMAP
  queries (:func:`smtp_query`, :func:`imap_query`) there and returns one :class:`ProbeResult`
  per query (reply code of every SMTP command, EHLO extensions before / after STARTTLS, queue
  identifier, IMAP search by header).  The spec must depend on lab data only: the command is the
  same on every grade pass.
- **Postfix**: :func:`get_postconf` (``postconf -x``), :func:`mynetworks_covers`,
  :func:`relayhost_target`, :func:`get_master_services` (``postconf -M``), :func:`get_mailq`
  (``postqueue -j``) / :func:`deferred_to`, :func:`queue_cleanup_command`.
- **Maildir**: :func:`get_maildir_messages` reads every message of some Maildirs in one command
  (base64 per file: the outputs of the tests must be UTF-8), :func:`find_messages` picks the
  probe's messages by their ``X-SRE-Probe`` header, :func:`received_hops` parses the ``Received``
  trace, :func:`parse_dsn` a bounce, :func:`parse_received_spf`,
  :func:`parse_authentication_results` and :func:`parse_dkim_signature` the authentication
  headers; :func:`maildir_cleanup_command` removes the probe's messages afterwards.
- **Dovecot**: :func:`get_doveconf` (``doveconf -n`` as nested dicts), :func:`doveconf_listener`.
- **DNS**: :func:`render_unbound_records` (``local-data:`` lines), :func:`parse_txt_strings`
  (``dig +short TXT``), :func:`parse_spf` / :func:`spf_record_ok`, :func:`parse_dkim_txt`,
  :func:`dkim_txt_record` and :func:`generate_dkim_keypair` (``cryptography``).
"""
from __future__ import annotations

import base64
import binascii
import email
import email.message
import json
import re
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_network
from pathlib import Path
from typing import Any

from SRE.lib_sre import Grade0, NetScheme0

# ---------------------------------------------------------------------------
# Active probe
# ---------------------------------------------------------------------------

SMTP_PROBE_PATH = '/usr/local/sbin/smtp_probe.py'
PROBE_HEADER = 'X-SRE-Probe'  # token of the lab instance, on every message sent by the probe
PROBE_QUERY_HEADER = 'X-SRE-Probe-Query'  # identifier of the query that sent the message
DEFAULT_PROBE_TIMEOUT = 5  # seconds, per socket operation inside the probe


def install_smtp_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy lib/smtp_probe.py to SMTP_PROBE_PATH on *machine* (usually a hidden one)."""
    script = Path(__file__).with_name('smtp_probe.py').read_text()
    net_scheme.file(machine, SMTP_PROBE_PATH, script, permissions=0o755, step=step)


def smtp_query(query_id: str, host: str, port: int = 25, helo: str = 'probe.invalid',
               mail_from: str | None = None, rcpt_to: list[str] | tuple[str, ...] = (),
               starttls: bool = False, auth: tuple[str, str] | None = None,
               send: bool = True, token: str | None = None, subject: str | None = None,
               body: str = '', headers: dict[str, str] | None = None,
               source_ip: str | None = None) -> dict:
    """One SMTP query of a probe spec.

    The dialogue is EHLO, [STARTTLS, EHLO], [AUTH *auth*], then, when *mail_from* is given,
    MAIL FROM, one RCPT TO per *rcpt_to* and, with *send*, DATA (only if a recipient was
    accepted).  The message carries ``X-SRE-Probe: token`` and ``X-SRE-Probe-Query: query_id``
    so that :func:`find_messages` recognises it in a Maildir.  *host* should be an address (the
    probe does not depend on the lab's DNS).
    """
    data = None
    if send and mail_from is not None:
        data_headers = {'Subject': subject or f'[SRE] {query_id}'}
        if token is not None:
            data_headers[PROBE_HEADER] = token
            data_headers[PROBE_QUERY_HEADER] = query_id
        data_headers.update(headers or {})
        data = {'headers': data_headers, 'body': body}
    return {
        'id': query_id, 'kind': 'smtp', 'host': str(host), 'port': int(port), 'helo': helo,
        'starttls': bool(starttls), 'auth': list(auth) if auth else None,
        'mail_from': mail_from, 'rcpt_to': list(rcpt_to), 'data': data,
        'source_ip': str(source_ip) if source_ip else None,
    }


def imap_query(query_id: str, host: str, user: str, password: str, port: int = 143,
               starttls: bool = False, ssl: bool = False, token: str | None = None,
               header: tuple[str, str] | None = None, poll: int = 0,
               fetch: tuple[str, ...] = ('Subject', 'Received', 'Return-Path')) -> dict:
    """One IMAP query of a probe spec: log in, count the INBOX messages carrying *header*
    (by default ``X-SRE-Probe: token``, every message without one) during at most *poll*
    seconds, and return the *fetch* headers of the first ones."""
    if header is None and token is not None:
        header = (PROBE_HEADER, token)
    return {
        'id': query_id, 'kind': 'imap', 'host': str(host), 'port': int(port), 'user': user,
        'password': password, 'starttls': bool(starttls), 'ssl': bool(ssl),
        'header': list(header) if header else None, 'poll': int(poll), 'fetch': list(fetch),
    }


def smtp_probe_command(spec: dict) -> str:
    """Shell command running the probe with *spec*; depends on *spec* only (stable across passes)."""
    encoded = base64.urlsafe_b64encode(
        json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).decode()
    return f'python3 {SMTP_PROBE_PATH} {encoded}'


@dataclass
class ProbeResult:
    """Record of one probe query.  SMTP replies are ``[code, text]`` (``None`` when the
    command was not sent); *rcpt* maps each recipient to its reply.  IMAP queries fill
    *login* (``'OK'`` or ``'NO: ...'``), *count* and *messages*."""
    query_id: str = ''
    connected: bool = False
    banner: list | None = None
    ehlo: list | None = None
    extensions: dict[str, str] | None = None
    starttls: list | None = None
    tls_version: str | None = None
    extensions_tls: dict[str, str] | None = None
    auth: list | None = None
    mail: list | None = None
    rcpt: dict[str, list] = field(default_factory=dict)
    data: list | None = None
    queue_id: str | None = None
    login: str | None = None
    count: int | None = None
    messages: list[dict] = field(default_factory=list)
    error: str | None = None

    @staticmethod
    def code(reply: list | None) -> int:
        """Reply code, 0 when the command was not sent / answered."""
        return int(reply[0]) if reply else 0

    def rcpt_code(self, address: str) -> int:
        return self.code(self.rcpt.get(address))

    def accepted(self, address: str) -> bool:
        """The recipient was accepted (2xx reply to RCPT TO)."""
        return 200 <= self.rcpt_code(address) < 300

    @property
    def sent(self) -> bool:
        """The message was accepted for delivery (2xx reply after DATA)."""
        return 200 <= self.code(self.data) < 300

    @property
    def logged_in(self) -> bool:
        return self.login == 'OK'


def parse_smtp_probe(output: str) -> dict[str, ProbeResult]:
    """Results of a probe run (``{query_id: ProbeResult}``); ``{}`` when the output is not
    the probe's JSON document."""
    try:
        doc = json.loads(output or '')
    except (TypeError, ValueError):
        return {}
    if not isinstance(doc, dict):
        return {}
    results = {}
    known = {f for f in ProbeResult.__dataclass_fields__}
    for query_id, record in (doc.get('results') or {}).items():
        if not isinstance(record, dict):
            continue
        fields = {k: v for k, v in record.items() if k in known and k != 'query_id'}
        if fields.get('rcpt') is None:
            fields['rcpt'] = {}
        if fields.get('messages') is None:
            fields['messages'] = []
        results[query_id] = ProbeResult(query_id=query_id, **fields)
    return results


def smtp_probe(grade: Grade0, machine: str, spec: dict, step: int = 1,
               timeout: int = 45) -> dict[str, ProbeResult]:
    """Run the probe installed on *machine* and return its results.

    *spec* is ``{'timeout': 5, 'queries': [smtp_query(...), imap_query(...), ...]}``.  It must
    be built from lab data only (never from test results) so that the command is identical on
    every grade pass.  *timeout* bounds the whole run (the probe spends at most
    ``spec['timeout']`` seconds per socket operation, plus the IMAP ``poll``).
    """
    output, _ = grade.test(machine, smtp_probe_command(spec), step=step, timeout=timeout,
                           allow_error=True)
    return parse_smtp_probe(output)


# ---------------------------------------------------------------------------
# Postfix
# ---------------------------------------------------------------------------

POSTCONF_PARAMS = (
    'myhostname', 'mydomain', 'myorigin', 'mydestination', 'mynetworks', 'inet_interfaces',
    'inet_protocols', 'relayhost', 'home_mailbox', 'mailbox_command', 'alias_maps',
    'smtpd_relay_restrictions', 'smtpd_recipient_restrictions', 'smtpd_sasl_auth_enable',
    'smtpd_sasl_type', 'smtpd_sasl_path', 'smtpd_tls_cert_file', 'smtpd_tls_key_file',
    'smtpd_tls_security_level', 'smtpd_tls_auth_only', 'smtpd_milters', 'non_smtpd_milters',
    'milter_default_action', 'maximal_queue_lifetime', 'compatibility_level',
)


def postconf_command(params: tuple[str, ...] | list[str] = POSTCONF_PARAMS) -> str:
    """``postconf -x`` of *params*: values with their ``$variables`` expanded."""
    return 'postconf -x ' + ' '.join(params)


def parse_postconf(output: str) -> dict[str, str]:
    """``{parameter: value}`` from ``postconf`` output (``name = value`` lines, empty values kept)."""
    result = {}
    for line in (output or '').splitlines():
        m = re.match(r'^([A-Za-z0-9_]+)\s*=\s?(.*)$', line)
        if m:
            result[m.group(1)] = m.group(2).strip()
    return result


def get_postconf(grade: Grade0, machine: str, params: tuple[str, ...] | list[str] = POSTCONF_PARAMS,
                 step: int = 1) -> dict[str, str]:
    """Expanded values of the Postfix parameters *params* on *machine* (``{}`` without Postfix)."""
    out, code = grade.test(machine, postconf_command(params), step=step, allow_error=True)
    return parse_postconf(out) if code == 0 else {}


def mynetworks_covers(value: str, network: IPv4Network | str) -> bool:
    """True when the ``mynetworks`` value *value* (addresses / CIDR blocks, separated by spaces
    or commas) contains the whole *network*.  IPv6 entries (``[::1]/128``) and lookup tables
    (``hash:/etc/postfix/network_table``) are ignored."""
    target = ip_network(network, strict=False)
    for entry in re.split(r'[\s,]+', (value or '').strip()):
        if not entry or entry.startswith('[') or ':' in entry or entry.startswith('!'):
            continue
        try:
            net = ip_network(entry, strict=False)
        except ValueError:
            continue
        if net.version == target.version and target.subnet_of(net):
            return True
    return False


def relayhost_target(value: str) -> tuple[str, int | None]:
    """``(host, port)`` of a ``relayhost`` value: ``[mx1.alpha.tp]:587`` → ``('mx1.alpha.tp', 587)``,
    ``''`` → ``('', None)``.  The brackets (no MX lookup) are stripped."""
    v = (value or '').strip()
    if not v:
        return '', None
    m = re.match(r'^\[([^\]]*)\](?::(\d+))?$', v)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else None
    m = re.match(r'^([^:\s]+)(?::(\d+))?$', v)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else None
    return v, None


def parse_master_services(output: str) -> dict[str, dict]:
    """Services of ``postconf -M``: ``{'submission/inet': {'name', 'type', 'private',
    'unprivileged', 'chroot', 'wakeup', 'maxproc', 'command', 'args', 'options'}}`` where
    *options* holds the ``-o name=value`` overrides."""
    services = {}
    for line in (output or '').splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[0].startswith('#'):
            continue
        name, stype, private, unpriv, chroot, wakeup, maxproc, command, *args = parts
        options, rest = {}, []
        i = 0
        while i < len(args):
            if args[i] == '-o' and i + 1 < len(args) and '=' in args[i + 1]:
                k, v = args[i + 1].split('=', 1)
                options[k] = v
                i += 2
            else:
                rest.append(args[i])
                i += 1
        services[f'{name}/{stype}'] = {
            'name': name, 'type': stype, 'private': private, 'unprivileged': unpriv,
            'chroot': chroot, 'wakeup': wakeup, 'maxproc': maxproc, 'command': command,
            'args': rest, 'options': options,
        }
    return services


def get_master_services(grade: Grade0, machine: str, step: int = 1) -> dict[str, dict]:
    """Services declared in the ``master.cf`` of *machine* (see :func:`parse_master_services`)."""
    out, code = grade.test(machine, 'postconf -M', step=step, allow_error=True)
    return parse_master_services(out) if code == 0 else {}


@dataclass
class MailqEntry:
    """One message of the Postfix queue (``postqueue -j``): *recipients* is a list of
    ``(address, delay_reason)``."""
    queue_id: str
    queue_name: str
    sender: str
    recipients: list[tuple[str, str]]
    arrival_time: int = 0
    message_size: int = 0


def parse_mailq(output: str) -> list[MailqEntry]:
    """Queue entries from ``postqueue -j`` (one JSON object per line; bad lines skipped)."""
    entries = []
    for line in (output or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if not isinstance(doc, dict) or 'queue_id' not in doc:
            continue
        raw_recipients = doc.get('recipients')
        recipients = [(r.get('address', ''), r.get('delay_reason', ''))
                      for r in (raw_recipients if isinstance(raw_recipients, list) else [])
                      if isinstance(r, dict)]
        entries.append(MailqEntry(
            queue_id=str(doc['queue_id']), queue_name=str(doc.get('queue_name', '')),
            sender=str(doc.get('sender', '')), recipients=recipients,
            arrival_time=int(doc.get('arrival_time') or 0),
            message_size=int(doc.get('message_size') or 0)))
    return entries


def get_mailq(grade: Grade0, machine: str, step: int = 1) -> list[MailqEntry]:
    """Messages waiting in the Postfix queue of *machine*."""
    out, _ = grade.test(machine, 'postqueue -j', step=step, allow_error=True)
    return parse_mailq(out)


def deferred_to(entries: list[MailqEntry], domain: str) -> list[MailqEntry]:
    """The deferred entries with a recipient at *domain*."""
    suffix = '@' + domain.lower()
    return [e for e in entries if e.queue_name == 'deferred'
            and any(addr.lower().endswith(suffix) for addr, _ in e.recipients)]


def queue_cleanup_command(sender: str) -> str:
    """Delete from the Postfix queue the messages whose envelope sender is *sender*
    (the probe's own messages); never fails."""
    py = ("import json,sys;[print(json.loads(l)['queue_id']) for l in sys.stdin"
          f" if l.strip() and json.loads(l).get('sender')=={sender!r}]")
    return (f'postqueue -j 2>/dev/null | python3 -c {shlex.quote(py)}'
            f' | postsuper -d - >/dev/null 2>&1; true')


# ---------------------------------------------------------------------------
# Maildir
# ---------------------------------------------------------------------------

MAILDIR_MARK = '===SRE-MAIL '


def _find_maildir_files(paths: list[str] | tuple[str, ...]) -> str:
    dirs = ' '.join(shlex.quote(p) for p in paths)
    return (f"find {dirs} -type f \\( -path '*/new/*' -o -path '*/cur/*' \\) 2>/dev/null | sort")


def maildir_dump_command(paths: list[str] | tuple[str, ...], token: str | None = None,
                         expected: int = 0, max_wait: int = 0) -> str:
    """One shell command printing every message of the Maildirs *paths* (``new/`` and ``cur/``),
    each as a ``===SRE-MAIL <path>`` line followed by its base64 text.  With *expected* and
    *max_wait*, it first waits (at most *max_wait* s, by 1 s steps) until at least *expected*
    files contain *token*: the time for Postfix to deliver what the probe has just sent."""
    wait = ''
    if token and expected and max_wait:
        # new/ and cur/ only: a message being written still sits in tmp/
        dirs = ' '.join(f'{shlex.quote(p)}/new {shlex.quote(p)}/cur' for p in paths)
        wait = (f"i=0; while [ $i -lt {int(max_wait)} ] && "
                f"[ $(grep -rls {shlex.quote(token)} {dirs} 2>/dev/null | wc -l) -lt {int(expected)} ];"
                f" do sleep 1; i=$((i+1)); done; ")
    return (wait + f"for f in $({_find_maildir_files(paths)}); do echo '{MAILDIR_MARK}'\"$f\";"
            f" base64 -w0 \"$f\"; echo; done")


def maildir_cleanup_command(paths: list[str] | tuple[str, ...], token: str) -> str:
    """Remove from the Maildirs *paths* every file containing *token* (the probe's messages and
    their bounces); never fails."""
    dirs = ' '.join(shlex.quote(p) for p in paths)
    return f'grep -rls {shlex.quote(token)} {dirs} 2>/dev/null | xargs -r rm -f; true'


@dataclass
class MaildirMessage:
    """One file of a Maildir: *user* is the home directory owner (``/home/<user>/``),
    *folder* ``new`` or ``cur``, *message* the parsed RFC 5322 message."""
    path: str
    user: str
    folder: str
    message: email.message.Message

    def __getitem__(self, header: str) -> str | None:
        return self.message.get(header)


def parse_maildir_dump(output: str) -> list[MaildirMessage]:
    """Messages of a :func:`maildir_dump_command` output (undecodable entries skipped)."""
    messages = []
    lines = (output or '').splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.startswith(MAILDIR_MARK):
            continue
        path = line[len(MAILDIR_MARK):].strip()
        raw = lines[i].strip() if i < len(lines) and not lines[i].startswith(MAILDIR_MARK) else ''
        if not raw:
            continue
        i += 1
        try:
            data = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            continue
        m = re.search(r'/home/([^/]+)/', path)
        user = m.group(1) if m else ''
        folder = 'cur' if '/cur/' in path else 'new' if '/new/' in path else ''
        messages.append(MaildirMessage(path=path, user=user, folder=folder,
                                       message=email.message_from_bytes(data)))
    return messages


def get_maildir_messages(grade: Grade0, machine: str, paths: list[str] | tuple[str, ...],
                         step: int = 1, token: str | None = None, expected: int = 0,
                         max_wait: int = 0, timeout: int = 30) -> list[MaildirMessage]:
    """Every message of the Maildirs *paths* on *machine* (see :func:`maildir_dump_command`)."""
    out, _ = grade.test(machine, maildir_dump_command(paths, token, expected, max_wait),
                        step=step, timeout=timeout, allow_error=True)
    return parse_maildir_dump(out)


def find_messages(messages: list[MaildirMessage], token: str,
                  query: str | None = None) -> list[MaildirMessage]:
    """The messages sent by the probe (``X-SRE-Probe: token``, and ``X-SRE-Probe-Query: query``
    when given)."""
    found = []
    for m in messages:
        if (m.message.get(PROBE_HEADER) or '').strip() != token:
            continue
        if query is not None and (m.message.get(PROBE_QUERY_HEADER) or '').strip() != query:
            continue
        found.append(m)
    return found


def body_text(msg: email.message.Message) -> str:
    """Text of the first ``text/plain`` part (or of the whole body), decoded."""
    parts = msg.walk() if msg.is_multipart() else [msg]
    fallback = None
    for part in parts:
        if part.is_multipart():
            continue
        if part.get_content_type() == 'text/plain' or fallback is None:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            text = payload.decode(part.get_content_charset() or 'utf-8', 'replace')
            if part.get_content_type() == 'text/plain':
                return text
            fallback = text
    return fallback or ''


def normalize_text(text: str) -> str:
    """Lower-case words without punctuation, single spaces: typed sentences compare loosely."""
    return ' '.join(re.sub(r'[^\w\s]', ' ', (text or '').lower()).split())


def body_contains(msg: email.message.Message, sentence: str) -> bool:
    """The body of *msg* contains *sentence* (punctuation, case and spacing ignored)."""
    needle = normalize_text(sentence)
    return bool(needle) and needle in normalize_text(body_text(msg))


_RECEIVED_RE = re.compile(
    r'(?:from\s+(?P<from>\S+)(?:\s+\((?P<from_info>[^)]*)\))?\s+)?'
    r'by\s+(?P<by>\S+)(?:\s+\([^)]*\))?'
    r'(?:\s+with\s+(?P<with>\S+))?(?:\s+id\s+(?P<id>\S+))?'
    r'(?:\s+for\s+<?(?P<for>[^>;\s]+)>?)?', re.S)
_IP_RE = re.compile(r'\[(\d+\.\d+\.\d+\.\d+)\]')


def received_hops(msg: email.message.Message) -> list[dict[str, str]]:
    """The ``Received`` headers of *msg*, most recent first, as ``{'from', 'from_ip', 'by',
    'with', 'id', 'for'}`` (empty strings when absent; ``from`` is absent for a message
    picked up locally: ``Received: by mx1 (Postfix, from userid 1000)``)."""
    hops = []
    for value in msg.get_all('Received', []):
        text = ' '.join(str(value).split())
        m = _RECEIVED_RE.search(text)
        if not m:
            continue
        ip = _IP_RE.search(m.group('from_info') or '')
        hops.append({
            'from': m.group('from') or '', 'from_ip': ip.group(1) if ip else '',
            'by': m.group('by') or '', 'with': m.group('with') or '',
            'id': m.group('id') or '', 'for': m.group('for') or '',
        })
    return hops


def is_bounce(msg: email.message.Message) -> bool:
    """A delivery status notification (``multipart/report; report-type=delivery-status``) or
    any message from MAILER-DAEMON."""
    if msg.get_content_type() == 'multipart/report' and \
            (msg.get_param('report-type') or '').lower() == 'delivery-status':
        return True
    return 'mailer-daemon' in (msg.get('From') or '').lower()


def parse_dsn(msg: email.message.Message) -> dict[str, Any]:
    """Content of a bounce: ``{'recipients': [{'final_recipient', 'action', 'status',
    'diagnostic_code'}], 'original': Message | None}`` (*original* is the returned message or
    its headers)."""
    recipients, original = [], None
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == 'message/delivery-status':
            payload = part.get_payload()
            blocks = payload if isinstance(payload, list) else [payload]
            for block in blocks:
                if not isinstance(block, email.message.Message) or not block.get('Final-Recipient'):
                    continue
                final = (block.get('Final-Recipient') or '').split(';', 1)[-1].strip()
                recipients.append({
                    'final_recipient': final,
                    'action': (block.get('Action') or '').strip().lower(),
                    'status': (block.get('Status') or '').strip(),
                    'diagnostic_code': ' '.join((block.get('Diagnostic-Code') or '').split()),
                })
        elif ctype in ('message/rfc822', 'text/rfc822-headers') and original is None:
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                original = payload[0]
            elif ctype == 'text/rfc822-headers':
                raw = part.get_payload(decode=True) or b''
                original = email.message_from_bytes(raw)
    return {'recipients': recipients, 'original': original}


def parse_received_spf(value: str) -> dict[str, str]:
    """``Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=10.1.1.2; ...`` →
    ``{'result': 'pass', 'comment': 'mailfrom', 'identity': 'mailfrom', 'client-ip': ...}``."""
    text = ' '.join((value or '').split())
    m = re.match(r'^(\w+)\s*(?:\(([^)]*)\))?\s*(.*)$', text)
    if not m:
        return {}
    result = {'result': m.group(1).lower(), 'comment': (m.group(2) or '').strip()}
    for item in m.group(3).split(';'):
        if '=' in item:
            k, v = item.split('=', 1)
            result[k.strip().lower()] = v.strip()
    return result


def parse_authentication_results(value: str) -> dict[str, Any]:
    """``Authentication-Results: mx2.beta.tp; dkim=pass (2048-bit key) header.d=alpha.tp ...``
    → ``{'authserv_id': 'mx2.beta.tp', 'results': {'dkim': 'pass'}, 'properties': {'dkim':
    {'header.d': 'alpha.tp', ...}}}``; comments in parentheses are dropped."""
    text = re.sub(r'\([^)]*\)', ' ', ' '.join((value or '').split()))
    parts = [p.strip() for p in text.split(';')]
    out: dict[str, Any] = {'authserv_id': parts[0].split()[0] if parts and parts[0] else '',
                           'results': {}, 'properties': {}}
    for clause in parts[1:]:
        tokens = clause.split()
        if not tokens or '=' not in tokens[0]:
            continue
        method, result = tokens[0].split('=', 1)
        method = method.lower()
        out['results'][method] = result.lower()
        props = {}
        for t in tokens[1:]:
            if '=' in t:
                k, v = t.split('=', 1)
                props[k.lower()] = v
        out['properties'][method] = props
    return out


def parse_dkim_signature(value: str) -> dict[str, str]:
    """Tags of a ``DKIM-Signature`` header (``{'v': '1', 'a': 'rsa-sha256', 'd': 'alpha.tp',
    's': 'tp', 'h': 'from:to:...', 'bh': ..., 'b': ...}``), folding whitespace removed."""
    tags = {}
    for item in (value or '').split(';'):
        if '=' not in item:
            continue
        k, v = item.split('=', 1)
        k = k.strip().lower()
        if k:
            tags[k] = ''.join(v.split()) if k in ('b', 'bh', 'h', 'd', 's', 'a', 'v', 'c') else v.strip()
    return tags


# ---------------------------------------------------------------------------
# Dovecot
# ---------------------------------------------------------------------------

def parse_doveconf(output: str) -> dict[str, Any]:
    """``doveconf -n`` as nested dicts: ``{'mail_location': 'maildir:~/Maildir', 'service auth':
    {'unix_listener /var/spool/postfix/private/auth': {'mode': '0660', ...}}, ...}``.  Blocks
    with the same header are merged; comment lines are skipped."""
    root: dict[str, Any] = {}
    stack = [root]
    for raw in (output or '').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line == '}':
            if len(stack) > 1:
                stack.pop()
            continue
        if line.endswith('{'):
            key = line[:-1].strip()
            block = stack[-1].get(key)
            if not isinstance(block, dict):
                block = {}
                stack[-1][key] = block
            stack.append(block)
            continue
        if '=' in line:
            k, v = line.split('=', 1)
            stack[-1][k.strip()] = v.strip()
    return root


def get_doveconf(grade: Grade0, machine: str, step: int = 1) -> dict[str, Any]:
    """Effective Dovecot configuration of *machine* (``{}`` when ``doveconf`` fails)."""
    out, code = grade.test(machine, 'doveconf -n', step=step, allow_error=True)
    return parse_doveconf(out) if code == 0 else {}


def doveconf_listener(conf: dict[str, Any], path: str) -> dict[str, str] | None:
    """The ``unix_listener <path>`` block of a parsed configuration (any service), else None."""
    for key, value in conf.items():
        if not isinstance(value, dict):
            continue
        if key.split() == ['unix_listener', path]:
            return value
        found = doveconf_listener(value, path)
        if found is not None:
            return found
    return None


def doveconf_value(conf: dict[str, Any], key: str) -> str:
    """Top-level value *key* of a parsed configuration, quotes stripped (``''`` when absent)."""
    v = conf.get(key)
    return v.strip().strip('"').strip() if isinstance(v, str) else ''


# ---------------------------------------------------------------------------
# DNS records: unbound local-data, SPF, DKIM
# ---------------------------------------------------------------------------

def render_unbound_records(records: list[tuple[str, str, str]], indent: str = '    ') -> str:
    """``local-data:`` lines for ``(name, type, value)`` records: a TXT value is quoted and split
    into 255-character strings, ``(address, 'PTR', name)`` becomes ``local-data-ptr:``; names
    are written absolute (trailing dot added)."""
    lines = []
    for name, rtype, value in records:
        rtype = rtype.upper()
        fqdn = name if name.endswith('.') else name + '.'
        if rtype == 'PTR':
            target = value if value.endswith('.') else value + '.'
            lines.append(f'{indent}local-data-ptr: "{name} {target}"')
        elif rtype == 'TXT':
            chunks = [value[i:i + 255] for i in range(0, len(value), 255)] or ['']
            quoted = ' '.join(f'"{c}"' for c in chunks)
            lines.append(f"{indent}local-data: '{fqdn} IN TXT {quoted}'")
        else:
            lines.append(f'{indent}local-data: "{fqdn} IN {rtype} {value}"')
    return '\n'.join(lines) + ('\n' if lines else '')


def parse_txt_strings(output: str) -> list[str]:
    """TXT records of a ``dig +short TXT`` output, one string per record (the quoted
    character-strings of a record are concatenated)."""
    records = []
    for line in (output or '').splitlines():
        pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        if pieces:
            records.append(''.join(p.replace('\\"', '"') for p in pieces))
    return records


def parse_spf(record: str) -> dict[str, Any] | None:
    """``{'version': 'spf1', 'terms': [(qualifier, mechanism, argument), ...]}`` of an SPF
    record, ``None`` when it does not start with ``v=spf1``."""
    words = (record or '').split()
    if not words or words[0].lower() != 'v=spf1':
        return None
    terms = []
    for w in words[1:]:
        qualifier = '+'
        if w[0] in '+-~?':
            qualifier, w = w[0], w[1:]
        if '=' in w:  # modifier (redirect=, exp=)
            name, arg = w.split('=', 1)
            terms.append((qualifier, name.lower() + '=', arg))
            continue
        name, _, arg = w.partition(':')
        terms.append((qualifier, name.lower(), arg or None))
    return {'version': 'spf1', 'terms': terms}


def spf_record_ok(record: str, mx_ip: str | IPv4Address | None = None,
                  mx_name: str | None = None) -> dict[str, Any]:
    """How an SPF *record* authorises the domain's MX: ``{'valid': bool, 'authorizes_mx': bool,
    'all': '-' | '~' | '?' | '+' | None}``.  The MX is authorised by ``mx``, by ``a:<mx_name>``
    (or ``a`` when *mx_name* is the domain itself) or by an ``ip4:`` block containing *mx_ip*."""
    parsed = parse_spf(record)
    out = {'valid': parsed is not None, 'authorizes_mx': False, 'all': None}
    if parsed is None:
        return out
    ip = IPv4Address(str(mx_ip)) if mx_ip else None
    for qualifier, mech, arg in parsed['terms']:
        if mech == 'all':
            out['all'] = qualifier
            continue
        if qualifier in '-~':
            continue
        if mech == 'mx' and arg is None:
            out['authorizes_mx'] = True
        elif mech == 'a' and mx_name and arg and arg.lower().rstrip('.') == mx_name.lower().rstrip('.'):
            out['authorizes_mx'] = True
        elif mech == 'ip4' and arg and ip is not None:
            try:
                if ip in ip_network(arg, strict=False):
                    out['authorizes_mx'] = True
            except ValueError:
                pass
    return out


def parse_dkim_txt(record: str) -> dict[str, str]:
    """Tags of a DKIM key record (``v=DKIM1; k=rsa; p=MIIB...``), whitespace removed from ``p``."""
    tags = {}
    for item in (record or '').split(';'):
        if '=' in item:
            k, v = item.split('=', 1)
            tags[k.strip().lower()] = ''.join(v.split()) if k.strip().lower() == 'p' else v.strip()
    return tags


def dkim_txt_record(public_key_b64: str) -> str:
    """The TXT record publishing an RSA public key (base64 DER) for DKIM."""
    return f'v=DKIM1; k=rsa; p={public_key_b64}'


def generate_dkim_keypair(bits: int = 2048) -> tuple[str, str]:
    """``(private_key_pem, public_key_b64)``: the private key as ``opendkim-genkey`` writes it
    (PKCS#8, ``BEGIN PRIVATE KEY``) and the public key as the ``p=`` tag expects it (base64 of
    the DER SubjectPublicKeyInfo)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, base64.b64encode(public_der).decode()
