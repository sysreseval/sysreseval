"""State and grade helpers of the QUIC / HTTP/3 lab (``lab/sre/_DRAFT_misc/quic.py``).

Images ``base13`` / ``init13`` (Debian 13): nginx 1.30 from nginx.org (HTTP/3 over OpenSSL 3.5's
QUIC API: 0-RTT works), curl 8.14 with HTTP/3, ``python3-aioquic`` 1.2, tshark 4.4, BIND 9.20,
Caddy 2.6.

State side: :func:`install_quic_client` copies ``lib/quic_probe.py`` (``quic-client``: GET,
0-RTT resumption, migration, version negotiation, JSON output); renderers of the nginx server
blocks (:func:`render_nginx_h3_server`), of a Caddyfile (:func:`render_caddyfile`) and of the
firewall ruleset (:func:`render_fw_ruleset`).

Grade side: :func:`quic_client_cmd` + :func:`parse_quic_client` (the probe's view: Retry seen,
0-RTT accepted, migrations survived...), :func:`parse_alt_svc`, :func:`nginx_directive_values`
(``nginx -T``), :func:`parse_access_log` (the log format :data:`ACCESS_LOG_FORMAT` written by
the pre-configured server), :func:`tshark_quic_cmd` + :func:`parse_tshark_rows` +
:func:`capture_summary` (a student's capture, decrypted or not with their key log),
:func:`parse_https_rr` (the HTTPS record of ``dig``).

Facts (nginx 1.30.6, curl 8.14.1 / OpenSSL 3.5.7, aioquic 1.2.0, tshark 4.4.19, checked on s16):
``http3_max_concurrent_streams`` is the server's ``initial_max_streams_bidi`` and
``keepalive_timeout`` its ``max_idle_timeout`` (both only readable after decryption, in the
EncryptedExtensions); with ``reuseport`` each worker has its own UDP socket, so a migrated
connection reaches the wrong worker unless ``quic_bpf on`` (or one worker); nginx needs a spare
connection ID of the client for each new path ("no available client ids for new path"): curl
(OpenSSL QUIC) gives none, so curl's connections never migrate, aioquic gives one (one rebinding
per connection); a client that only receives sends nothing once a NAT dropped its mapping, so the
migration needs a client packet (``quic-client --progress`` sends a PING each second).

Every command is a single line that only depends on its arguments.  Tests:
``tests/test_quic.py`` (fixtures in ``tests/mock_data/quic/``).
"""
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0, NetScheme0

#: where install_quic_client() puts lib/quic_probe.py
CLIENT_PATH = '/usr/local/bin/quic-client'

#: the access log format of the pre-configured servers (one line per request)
ACCESS_LOG_FORMAT_NAME = 'sre_quic'
ACCESS_LOG_FORMAT = "'$remote_addr $time_iso8601 $server_protocol $status \"$request_method $request_uri\"'"

#: tshark fields read by tshark_quic_cmd(), in this order
TSHARK_FIELDS = ('frame.number', 'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'quic.header_form',
                 'quic.long.packet_type', 'quic.frame_type', 'http3.headers.method', 'http3.headers.path',
                 'http3.headers.status', 'http3.stream_uni_type')

#: QUIC v1 long header packet types (RFC 9000 §17.2)
LONG_PACKET_TYPES = {0: 'initial', 1: '0rtt', 2: 'handshake', 3: 'retry'}


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def install_quic_client(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy lib/quic_probe.py to CLIENT_PATH (``quic-client``) on *machine*."""
    script = Path(__file__).with_name('quic_probe.py').read_text()
    net_scheme.file(machine, CLIENT_PATH, script, permissions=0o755, step=step)


def render_nginx_h3_server(server_name: str, cert: str, key: str, root: str, *, port: int = 443,
                           quic_ports: Sequence[int] = (), tcp: bool = True, alt_svc_port: Optional[int] = 443,
                           max_streams: Optional[int] = None, keepalive_timeout: Optional[int] = None,
                           quic_retry: bool = False, quic_host_key: Optional[str] = None,
                           early_data: bool = False, early_data_header: bool = False,
                           access_log: Optional[str] = None, locations: Sequence[Tuple[str, Sequence[str]]] = (),
                           log_format: bool = False) -> str:
    """An nginx ``server`` block serving *server_name* over HTTP/3 (UDP *port*, ``reuseport``)
    and, with *tcp*, HTTP/1.1 + HTTP/2 over TLS on TCP *port*; *quic_ports* are more QUIC-only
    ports.  *locations* is ``[(match, [directive lines])]``.  *log_format* puts the
    :data:`ACCESS_LOG_FORMAT` definition before the block (it belongs to the ``http`` context,
    where the files of conf.d are included)."""
    lines = []
    if log_format:
        lines.append(f"log_format {ACCESS_LOG_FORMAT_NAME} {ACCESS_LOG_FORMAT};")
        lines.append("")
    lines.append("server {")
    lines.append(f"    listen {port} quic reuseport;")
    if tcp:
        lines.append(f"    listen {port} ssl;")
    for extra in quic_ports:
        lines.append(f"    listen {extra} quic reuseport;")
    lines += ["    http2 on;", "    http3 on;", f"    server_name {server_name};",
              f"    ssl_certificate {cert};", f"    ssl_certificate_key {key};"]
    if max_streams is not None:
        lines.append(f"    http3_max_concurrent_streams {int(max_streams)};")
    if keepalive_timeout is not None:
        lines.append(f"    keepalive_timeout {int(keepalive_timeout)}s;")
    if quic_retry:
        lines.append("    quic_retry on;")
    if quic_host_key:
        lines.append(f"    quic_host_key {quic_host_key};")
    if early_data:
        lines.append("    ssl_early_data on;")
    if access_log:
        lines.append(f"    access_log {access_log} {ACCESS_LOG_FORMAT_NAME};")
    if alt_svc_port is not None:
        lines.append(f"    add_header Alt-Svc 'h3=\":{int(alt_svc_port)}\"; ma=86400' always;")
    if early_data_header:
        lines.append("    add_header Early-Data $ssl_early_data always;")
    lines.append(f"    root {root};")
    for match, body in locations:
        lines.append(f"    location {match} {{")
        lines += [f"        {line}" for line in body]
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_caddyfile(site: str, cert: str, key: str, root: str) -> str:
    """A Caddyfile serving *site* (``https://www.quic.tp:8444``) from *root* with the given
    certificate: HTTP/1.1, HTTP/2 and HTTP/3 (Caddy enables HTTP/3 itself); ``auto_https off``
    so that Caddy neither asks for a certificate nor takes port 80."""
    return (f"{{\n\tauto_https off\n}}\n\n{site} {{\n\ttls {cert} {key}\n\troot * {root}\n"
            f"\tfile_server\n}}\n")


def render_fw_ruleset(lan_if: str = 'eth1', wan_if: str = 'eth0', quic: bool = False) -> str:
    """``/etc/nftables.conf`` of the corporate firewall: forwarding from the LAN limited to TCP
    80/443, DNS and ping (plus UDP 443 with *quic*), NAT with random source ports
    (``masquerade random``: a mapping lost and made again gets a new port)."""
    quic_rule = f'\t\tiifname "{lan_if}" oifname "{wan_if}" udp dport 443 accept\n' if quic else ''
    return (
        "#!/usr/sbin/nft -f\n"
        "flush ruleset\n\n"
        "table inet filter {\n"
        "\tchain forward {\n"
        "\t\ttype filter hook forward priority filter; policy drop;\n"
        "\t\tct state established,related accept\n"
        f'\t\tiifname "{lan_if}" oifname "{wan_if}" tcp dport {{ 80, 443 }} accept\n'
        f"{quic_rule}"
        f'\t\tiifname "{lan_if}" oifname "{wan_if}" meta l4proto {{ tcp, udp }} th dport 53 accept\n'
        f'\t\tiifname "{lan_if}" icmp type echo-request accept\n'
        "\t}\n"
        "}\n\n"
        "table ip nat {\n"
        "\tchain postrouting {\n"
        "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
        f'\t\toifname "{wan_if}" masquerade random\n'
        "\t}\n"
        "}\n")


# ---------------------------------------------------------------------------
# quic-client (the probe)
# ---------------------------------------------------------------------------


def _address(value) -> str:
    return str(value).split('/')[0]


def quic_client_cmd(subcommand: str, urls: Iterable[str], connect_ip=None, connect_port: Optional[int] = None,
                    timeout: float = 6, **options) -> str:
    """One ``quic-client <subcommand> --json`` command line.  Options: ``connections``,
    ``rebinds``, ``step_timeout`` (migrate), ``session_ticket``, ``token``, ``zero_rtt``
    (get); the server is reached at *connect_ip*[:*connect_port*] whatever the name of the
    URLs (the name stays the SNI)."""
    args = [CLIENT_PATH, subcommand, '--json', '--timeout', f"{float(timeout):g}"]
    if connect_ip is not None:
        target = _address(connect_ip) + (f":{int(connect_port)}" if connect_port is not None else '')
        args += ['--connect', target]
    for name, value in sorted(options.items()):
        if value is None or value is False:
            continue
        flag = '--' + name.replace('_', '-')
        args += [flag] if value is True else [flag, str(value)]
    args += list(urls)
    return ' '.join(shlex.quote(a) for a in args) + ' 2>/dev/null'


def parse_quic_client(out: str) -> dict:
    """The JSON document of a ``quic-client --json`` run (the last line holding one), ``{}``
    when there is none (the tests have not run, the client crashed)."""
    for line in reversed((out or '').splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    return {}


def run_quic_client(grade: Grade0, machine: str, subcommand: str, urls: Iterable[str], connect_ip=None,
                    connect_port: Optional[int] = None, step: int = 1, timeout: float = 6, **options) -> dict:
    """Run :func:`quic_client_cmd` on *machine*, parse it (``{}`` until the tests have run)."""
    cmd = quic_client_cmd(subcommand, list(urls), connect_ip, connect_port, timeout=timeout, **options)
    budget = int(timeout * 4 + 10)
    if subcommand == 'migrate':
        budget += int(options.get('connections', 1)) * int(float(options.get('step_timeout', 3)) + 2)
    out, _ = grade.test(machine, cmd, step=step, timeout=budget, allow_error=True)
    return parse_quic_client(out)


def response_of(result: dict, path: str) -> dict:
    """The response to *path* in a ``get`` result (or in one connection of ``resume``), ``{}``
    when absent."""
    for request in (result or {}).get('requests', []) or []:
        if request.get('path') == path:
            return request
    return {}


def response_header(response: dict, name: str) -> str:
    wanted = name.lower()
    for key, value in (response or {}).get('headers', []) or []:
        if str(key).lower() == wanted:
            return str(value)
    return ''


# ---------------------------------------------------------------------------
# Alt-Svc
# ---------------------------------------------------------------------------


def parse_alt_svc(value: str) -> List[dict]:
    """``Alt-Svc`` header value → ``[{'alpn', 'host', 'port', 'ma'}]`` (``clear`` → ``[]``).
    ``h3=":443"; ma=86400, h3-29=":8443"`` gives two entries; *port* is ``None`` when absent or
    not a number, *ma* the max age in seconds (``None`` when absent)."""
    entries = []
    if not value or value.strip().lower() == 'clear':
        return entries
    for part in re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', value):
        items = [p.strip() for p in part.split(';') if p.strip()]
        if not items or '=' not in items[0]:
            continue
        alpn, _, authority = items[0].partition('=')
        authority = authority.strip().strip('"')
        host, _, port = authority.rpartition(':')
        entry = {'alpn': alpn.strip(), 'host': host, 'port': int(port) if port.isdigit() else None, 'ma': None}
        for param in items[1:]:
            k, _, v = param.partition('=')
            if k.strip().lower() == 'ma' and v.strip().strip('"').isdigit():
                entry['ma'] = int(v.strip().strip('"'))
        entries.append(entry)
    return entries


def alt_svc_offers(value: str, alpn: str = 'h3', port: int = 443) -> bool:
    """Whether the ``Alt-Svc`` value offers *alpn* on *port* (same host)."""
    return any(e['alpn'] == alpn and e['port'] == port and e['host'] in ('', None) for e in parse_alt_svc(value))


# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------


def strip_comments(text: str) -> str:
    """nginx configuration without its comments (a ``#`` outside quotes up to the end of the
    line); the ``# configuration file ...:`` headers of ``nginx -T`` go too."""
    out = []
    for line in (text or '').splitlines():
        quote = None
        for i, ch in enumerate(line):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in ('"', "'"):
                quote = ch
            elif ch == '#':
                line = line[:i]
                break
        out.append(line)
    return "\n".join(out)


def nginx_directive_values(text: str, name: str) -> List[List[str]]:
    """The argument lists of every ``name ...;`` directive of an ``nginx -T`` dump (any file,
    any context), comments ignored: ``[['on'], ['/etc/nginx/quic.key']]``."""
    clean = strip_comments(text)
    values = []
    for m in re.finditer(r'(?:^|[;{}\s])' + re.escape(name) + r'\s+([^;{}]*);', clean):
        values.append(shlex.split(m.group(1), posix=True) if m.group(1).strip() else [])
    return values


def nginx_test_ok(text: str) -> bool:
    """Whether the output of ``nginx -t`` / ``nginx -T`` says the configuration is valid."""
    return 'test is successful' in (text or '')


# ---------------------------------------------------------------------------
# access log of the pre-configured servers
# ---------------------------------------------------------------------------


_ACCESS_LINE = re.compile(r'^(?P<remote>\S+) (?P<time>\S+) (?P<protocol>\S+) (?P<status>\d{3}) '
                          r'"(?P<method>\S+) (?P<path>[^"]*)"\s*$')


def parse_access_log(text: str) -> List[dict]:
    """Lines of :data:`ACCESS_LOG_FORMAT` → ``[{'remote', 'time', 'protocol', 'status',
    'method', 'path'}]`` (``status`` an int); other lines are skipped."""
    entries = []
    for line in (text or '').splitlines():
        m = _ACCESS_LINE.match(line.strip())
        if m:
            entry = m.groupdict()
            entry['status'] = int(entry['status'])
            entries.append(entry)
    return entries


def requests_from(entries: List[dict], remote, protocol: Optional[str] = None, path: Optional[str] = None,
                  status: Optional[int] = None) -> List[dict]:
    """The log entries of the client *remote* (an address), filtered on the protocol
    (``HTTP/3.0``), the path and the status."""
    ip = _address(remote)
    return [e for e in entries if e['remote'] == ip and (protocol is None or e['protocol'] == protocol)
            and (path is None or e['path'].split('?')[0] == path) and (status is None or e['status'] == status)]


# ---------------------------------------------------------------------------
# captures (tshark)
# ---------------------------------------------------------------------------


def tshark_quic_cmd(pcap: str, keylog: Optional[str] = None, port: int = 443, max_packets: int = 4000) -> str:
    """One ``tshark`` reading *pcap* (decrypted with the TLS key log *keylog* when given):
    one tab-separated line of :data:`TSHARK_FIELDS` per QUIC packet to or from UDP *port*
    (multiple values of a field joined by ``,``).  UDP *port* is decoded as QUIC whatever the
    other port (``-d``): a client port of another protocol's (37008, TZSP) wins otherwise."""
    opts = ['tshark', '-n', '-r', pcap, '-c', str(int(max_packets)), '-d', f"udp.port=={int(port)},quic"]
    if keylog:
        opts += ['-o', f"tls.keylog_file:{keylog}"]
    opts += ['-Y', f"quic && udp.port == {int(port)}", '-T', 'fields', '-E', 'separator=/t',
             '-E', 'occurrence=a', '-E', 'aggregator=,']
    for name in TSHARK_FIELDS:
        opts += ['-e', name]
    return ' '.join(shlex.quote(o) for o in opts) + ' 2>/dev/null'


def parse_tshark_rows(out: str) -> List[Dict[str, List[str]]]:
    """Lines of :func:`tshark_quic_cmd` → one dict per packet, every field a list of values
    (``[]`` when empty)."""
    rows = []
    for line in (out or '').splitlines():
        cells = line.split('\t')
        if len(cells) < len(TSHARK_FIELDS) or not cells[0].strip().isdigit():
            continue
        rows.append({name: [v for v in cells[i].split(',') if v != ''] for i, name in enumerate(TSHARK_FIELDS)})
    return rows


@dataclass
class CaptureSummary:
    """What a capture shows of the QUIC traffic between *client* and *server*."""
    packets: int = 0                   # QUIC packets between the two
    long_types: Dict[str, int] = field(default_factory=dict)   # initial / handshake / retry / 0rtt
    short_packets: int = 0             # 1-RTT packets (short header)
    requests: List[Tuple[str, str]] = field(default_factory=list)    # (method, path) decrypted
    statuses: List[str] = field(default_factory=list)                # response statuses decrypted
    uni_stream_types: List[str] = field(default_factory=list)        # HTTP/3 unidirectional streams

    @property
    def decrypted(self) -> bool:
        return bool(self.requests or self.statuses)


def _packet_types(row: Dict[str, List[str]]) -> List[str]:
    """Long header packet types of a datagram (coalesced packets: several)."""
    forms = row.get('quic.header_form', [])
    types = row.get('quic.long.packet_type', [])
    result, t = [], iter(types)
    for form in forms:
        if form in ('1', 'True', 'true'):
            value = next(t, None)
            result.append(LONG_PACKET_TYPES.get(int(value), value) if value and value.isdigit() else 'long')
        else:
            result.append('short')
    return result


def capture_summary(rows: List[Dict[str, List[str]]], client, server, port: int = 443) -> CaptureSummary:
    """Summary of the packets of :func:`parse_tshark_rows` exchanged between *client* and
    *server* on UDP *port*."""
    c, s = _address(client), _address(server)
    summary = CaptureSummary()
    for row in rows:
        src = (row.get('ip.src') or [''])[0]
        dst = (row.get('ip.dst') or [''])[0]
        sport = (row.get('udp.srcport') or [''])[0]
        dport = (row.get('udp.dstport') or [''])[0]
        if not ((src == c and dst == s and dport == str(port)) or (src == s and dst == c and sport == str(port))):
            continue
        summary.packets += 1
        for kind in _packet_types(row):
            if kind == 'short':
                summary.short_packets += 1
            else:
                summary.long_types[kind] = summary.long_types.get(kind, 0) + 1
        methods, paths = row.get('http3.headers.method', []), row.get('http3.headers.path', [])
        for method, path in zip(methods, paths):
            if src == c:
                summary.requests.append((method, path))
        if src == s:
            summary.statuses += row.get('http3.headers.status', [])
            summary.uni_stream_types += row.get('http3.stream_uni_type', [])
    return summary


def file_status_cmd(*paths: str) -> str:
    """For each path a line ``<size> <mode> <path>`` (``missing <path>`` when absent)."""
    quoted = ' '.join(shlex.quote(p) for p in paths)
    return (f"for f in {quoted}; do if [ -f \"$f\" ]; then stat -c '%s %a %n' \"$f\"; "
            f"else echo \"missing $f\"; fi; done")


def nginx_files_status_cmd(directive: str, *extra: str) -> str:
    """:func:`file_status_cmd` of every file named by *directive* in ``nginx -T`` (a line
    ``directive path;``, comments excluded) and of the *extra* paths: one command, whatever the
    configuration (no command built from the output of another)."""
    finder = ("$(nginx -T 2>/dev/null | sed -n -E "
              f"'s/^[[:space:]]*{re.escape(directive)}[[:space:]]+([^;[:space:]]+)[[:space:]]*;.*$/\\1/p')")
    quoted = ' '.join(shlex.quote(p) for p in extra)
    return (f"for f in {finder} {quoted}; do if [ -f \"$f\" ]; then stat -c '%s %a %n' \"$f\"; "
            f"else echo \"missing $f\"; fi; done")


def parse_file_status(out: str) -> Dict[str, Optional[Tuple[int, int]]]:
    """``{path: (size, mode)}`` of :func:`file_status_cmd` (``None`` for a missing file); the
    mode is the octal ``stat`` value read as an int (``0o600``)."""
    result: Dict[str, Optional[Tuple[int, int]]] = {}
    for line in (out or '').splitlines():
        parts = line.split(None, 2)
        if len(parts) == 2 and parts[0] == 'missing':
            result[parts[1]] = None
        elif len(parts) == 3 and parts[0].isdigit() and re.fullmatch(r'[0-7]{3,4}', parts[1]):
            result[parts[2]] = (int(parts[0]), int(parts[1], 8))
    return result


def keylog_labels(text: str) -> Dict[str, int]:
    """``{label: count}`` of an SSLKEYLOGFILE (``CLIENT_TRAFFIC_SECRET_0``...)."""
    labels: Dict[str, int] = {}
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) == 3 and re.fullmatch(r'[A-Z_0-9]+', parts[0]) and re.fullmatch(r'[0-9a-fA-F]+', parts[2]):
            labels[parts[0]] = labels.get(parts[0], 0) + 1
    return labels


# ---------------------------------------------------------------------------
# DNS: HTTPS records
# ---------------------------------------------------------------------------


def parse_https_rr(rdata: str) -> Optional[dict]:
    """Rdata of an HTTPS / SVCB record as ``dig`` prints it (``1 . alpn="h3,h2" port=443``) →
    ``{'priority', 'target', 'params': {key: value}, 'alpn': [...]}``; ``None`` when it does
    not parse."""
    try:
        tokens = shlex.split(rdata or '')
    except ValueError:
        return None
    if len(tokens) < 2 or not tokens[0].isdigit():
        return None
    params = {}
    for token in tokens[2:]:
        key, sep, value = token.partition('=')
        params[key.lower()] = value if sep else ''
    alpn = [a.strip() for a in params.get('alpn', '').replace('\\,', ',').split(',') if a.strip()]
    return {'priority': int(tokens[0]), 'target': tokens[1], 'params': params, 'alpn': alpn}
