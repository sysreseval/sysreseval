#!/usr/bin/python3
"""quic-client: a small QUIC / HTTP/3 client of the QUIC lab (aioquic), for the students and the
hidden probe of the grader.

Copied into the machines by ``quic.install_quic_client()`` as ``/usr/local/bin/quic-client``;
needs the system ``python3`` with ``python3-aioquic`` (images ``base13`` / ``init13``).  What
curl does not show is printed: the QUIC version, the connection IDs, whether the server sent a
Retry, whether a session was resumed and its 0-RTT data accepted, what happens when the client
changes its address (migration).  ``--json`` prints one JSON document instead (the grader).

Sub-commands::

    quic-client get URL [URL...]            one connection, the URLs requested on it
        --connect IP[:PORT]                 address of the server (the name of the URL stays the
                                            SNI and the :authority)
        --keylog FILE                       TLS secrets (SSLKEYLOGFILE format, for Wireshark)
        --session-ticket FILE               reuse the ticket of FILE (resumption) and save the
                                            new one there
        --zero-rtt                          send the requests in 0-RTT (needs --session-ticket)
        --token FILE                        same for the NEW_TOKEN of the server (no Retry)
        -X METHOD, -d DATA, -H 'Name: value', -i (headers), -o FILE (body), --qlog DIR
    quic-client resume URL [URL...]         two connections: the first saves the session ticket
                                            and the token, the second sends the URLs in 0-RTT
    quic-client migrate URL [--connections M] [--rebinds N]
                                            M connections, each: the URL, then N times a new UDP
                                            socket (new source port), a new connection ID, the
                                            URL again (nginx answers one rebinding per connection)
    quic-client vn HOST [PORT]              a datagram with an unknown version: the Version
                                            Negotiation packet of the server (standard library)

The pure functions (``build_vn_probe``, ``parse_vn``, ``parse_connect``, ``parse_header``) are
imported by the unit tests without aioquic.
"""
import argparse
import asyncio
import contextlib
import json
import os
import pickle
import socket
import ssl
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

VERSION_1 = 0x00000001
#: a reserved version (pattern 0x?a?a?a?a of RFC 9000 §15): never supported, always negotiated
GREASE_VERSION = 0x1A2A3A4A
DEFAULT_CAFILE = '/etc/ssl/certs/ca-certificates.crt'
MIN_INITIAL_SIZE = 1200


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


def parse_connect(value: Optional[str], default_port: int) -> Tuple[Optional[str], int]:
    """``'IP'`` / ``'IP:PORT'`` / ``'[IPv6]:PORT'`` → ``(ip, port)``; ``(None, default_port)``
    for ``None``."""
    if not value:
        return None, default_port
    if value.startswith('['):
        host, _, rest = value[1:].partition(']')
        return host, int(rest[1:]) if rest.startswith(':') else default_port
    if value.count(':') == 1:
        host, port = value.split(':')
        return host, int(port)
    return value, default_port


def parse_header(value: str) -> Tuple[str, str]:
    """``'Name: value'`` → ``('name', 'value')``."""
    name, sep, rest = value.partition(':')
    if not sep or not name.strip():
        raise ValueError(f"bad header {value!r} (expected 'Name: value')")
    return name.strip().lower(), rest.strip()


def build_vn_probe(dcid: bytes, scid: bytes, version: int = GREASE_VERSION, size: int = MIN_INITIAL_SIZE) -> bytes:
    """A long-header datagram of *size* bytes with an unsupported *version*: a server answers
    with a Version Negotiation packet (RFC 9000 §6), whatever the rest of the packet holds."""
    first = 0xC0 | (os.urandom(1)[0] & 0x3F)
    packet = (bytes([first]) + struct.pack('!I', version) + bytes([len(dcid)]) + dcid
              + bytes([len(scid)]) + scid)
    return packet + os.urandom(max(0, size - len(packet)))


def parse_vn(data: bytes) -> Optional[dict]:
    """``{'dcid', 'scid', 'versions'}`` of a Version Negotiation packet (version field 0),
    ``None`` for anything else.  Versions are ``0x%08x`` strings."""
    if len(data) < 7 or not data[0] & 0x80:
        return None
    if struct.unpack('!I', data[1:5])[0] != 0:
        return None
    pos = 5
    dlen = data[pos]
    dcid = data[pos + 1:pos + 1 + dlen]
    pos += 1 + dlen
    if pos >= len(data):
        return None
    slen = data[pos]
    scid = data[pos + 1:pos + 1 + slen]
    pos += 1 + slen
    versions = [struct.unpack('!I', data[i:i + 4])[0] for i in range(pos, len(data) - 3, 4)]
    return {'dcid': dcid.hex(), 'scid': scid.hex(), 'versions': [f"0x{v:08x}" for v in versions]}


def version_name(version: Optional[int]) -> str:
    names = {0x00000001: 'QUIC v1 (RFC 9000)', 0x6B3343CF: 'QUIC v2 (RFC 9369)'}
    if version is None:
        return '?'
    return names.get(version, f"0x{version:08x}")


# ---------------------------------------------------------------------------
# version negotiation (no aioquic)
# ---------------------------------------------------------------------------


def run_vn(host: str, port: int, timeout: float) -> dict:
    dcid, scid = os.urandom(8), os.urandom(8)
    result = {'command': 'vn', 'server': f"{host}:{port}", 'sent_version': f"0x{GREASE_VERSION:08x}",
              'dcid': dcid.hex(), 'scid': scid.hex(), 'answer': None, 'error': ''}
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_vn_probe(dcid, scid), (host, port))
            data, _ = sock.recvfrom(65535)
            result['answer'] = parse_vn(data)
            if result['answer'] is None:
                result['error'] = 'not a Version Negotiation packet'
        except socket.timeout:
            result['error'] = 'timeout'
        except OSError as exc:
            result['error'] = str(exc)
    return result


# ---------------------------------------------------------------------------
# HTTP/3 over aioquic
# ---------------------------------------------------------------------------


def _client_class():
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

    class H3Client(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)
            self.waiters: Dict[int, asyncio.Future] = {}
            self.responses: Dict[int, dict] = {}
            self.handshake = None
            self.terminated = None

        def received_bytes(self) -> int:
            return sum(len(r['body']) for r in self.responses.values())

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                self.handshake = event
            elif isinstance(event, ConnectionTerminated):
                self.terminated = event
                for fut in self.waiters.values():
                    if not fut.done():
                        fut.set_exception(ConnectionError(
                            f"connection closed: {event.reason_phrase or hex(event.error_code)}"))
            for http_event in self.http.handle_event(event):
                stream_id = getattr(http_event, 'stream_id', None)
                response = self.responses.get(stream_id)
                if response is None:
                    continue
                if isinstance(http_event, HeadersReceived):
                    response['headers'].extend(http_event.headers)
                elif isinstance(http_event, DataReceived):
                    response['body'] += http_event.data
                if getattr(http_event, 'stream_ended', False):
                    fut = self.waiters.get(stream_id)
                    if fut is not None and not fut.done():
                        fut.set_result(response)

        def request(self, method: str, authority: str, path: str, headers=(), data: Optional[bytes] = None):
            stream_id = self._quic.get_next_available_stream_id()
            fields = [(b':method', method.encode()), (b':scheme', b'https'), (b':authority', authority.encode()),
                      (b':path', path.encode()), (b'user-agent', b'quic-client')]
            fields += [(k.encode(), v.encode()) for k, v in headers]
            early = not self._quic._handshake_complete
            self.responses[stream_id] = {'stream_id': stream_id, 'headers': [], 'body': bytearray(),
                                         'method': method, 'path': path, 'sent_before_handshake': early}
            fut = self._loop.create_future()
            self.waiters[stream_id] = fut
            self.http.send_headers(stream_id, fields, end_stream=data is None)
            if data is not None:
                self.http.send_data(stream_id, data, end_stream=True)
            self.transmit()
            return fut

    return H3Client


@contextlib.asynccontextmanager
async def _connect(ip: str, port: int, configuration, session_ticket_handler=None, token_handler=None,
                   wait_connected: bool = True):
    """aioquic's connect() on a socket of the family of *ip* (the containers of the lab have no
    IPv6: no dual-stack socket)."""
    from aioquic.quic.connection import QuicConnection
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    addr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    connection = QuicConnection(configuration=configuration, session_ticket_handler=session_ticket_handler,
                                token_handler=token_handler)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 0))
    transport, protocol = await loop.create_datagram_endpoint(lambda: _client_class()(connection), sock=sock)
    try:
        protocol.connect(addr, transmit=wait_connected)
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(protocol.wait_closed(), 2)
        protocol._transport.close()


async def _rebind(protocol) -> int:
    """Move the connection to a new UDP socket (a new source port, like a NAT rebinding): the
    server sees a new path.  Returns the new local port."""
    loop = asyncio.get_running_loop()
    old = protocol._transport
    family = old.get_extra_info('socket').family
    old.close()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 0))
    await loop.create_datagram_endpoint(lambda: protocol, sock=sock)
    return sock.getsockname()[1]


def _configuration(args, host: str):
    from aioquic.h3.connection import H3_ALPN
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.logger import QuicFileLogger, QuicLogger
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name=host,
                                      idle_timeout=max(5.0, args.timeout))
    configuration.supported_versions = [VERSION_1]
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    else:
        configuration.load_verify_locations(args.cafile)
    configuration.quic_logger = QuicFileLogger(args.qlog) if args.qlog else QuicLogger()
    if args.keylog:
        configuration.secrets_log_file = open(args.keylog, 'a')
    return configuration


def _events(configuration) -> List[dict]:
    logger = configuration.quic_logger
    try:
        traces = logger.to_dict()['traces'] if hasattr(logger, 'to_dict') else []
    except Exception:
        traces = []
    return [event for trace in traces for event in trace.get('events', [])]


def _received_frames(events: List[dict], frame_type: str) -> int:
    count = 0
    for event in events:
        if event.get('name') == 'transport:packet_received':
            for frame in event.get('data', {}).get('frames', []) or []:
                if frame.get('frame_type') == frame_type:
                    count += 1
    return count


def _retry_seen(protocol, events: List[dict]) -> bool:
    if getattr(protocol._quic, '_retry_count', 0):
        return True
    return any(event.get('name') == 'transport:packet_received'
               and event.get('data', {}).get('header', {}).get('packet_type') == 'retry' for event in events)


def _connection_facts(protocol, configuration) -> dict:
    quic = protocol._quic
    events = _events(configuration)
    tls = getattr(quic, 'tls', None)
    facts = {
        'version': f"0x{quic._version:08x}" if quic._version is not None else None,
        'alpn': protocol.handshake.alpn_protocol if protocol.handshake else None,
        'handshake': protocol.handshake is not None,
        'retry': _retry_seen(protocol, events),
        'session_resumed': bool(getattr(tls, 'session_resumed', False)),
        'early_data_accepted': bool(getattr(tls, 'early_data_accepted', False)),
        'cipher_suite': None,
        'host_cid': quic.host_cid.hex() if getattr(quic, 'host_cid', None) else None,
        'peer_cid': quic._peer_cid.cid.hex() if getattr(quic, '_peer_cid', None) else None,
        'path_challenges_received': _received_frames(events, 'path_challenge'),
        'new_tokens_received': _received_frames(events, 'new_token'),
    }
    with contextlib.suppress(Exception):
        facts['cipher_suite'] = tls.key_schedule.cipher_suite.name
    return facts


def _response_dict(response: dict, max_body: int) -> dict:
    headers = [(k.decode(errors='replace'), v.decode(errors='replace')) for k, v in response['headers']]
    status = next((v for k, v in headers if k == ':status'), None)
    body = bytes(response['body'])
    return {
        'path': response['path'], 'method': response['method'], 'stream_id': response['stream_id'],
        'status': int(status) if status and status.isdigit() else None,
        'headers': [[k, v] for k, v in headers if not k.startswith(':')],
        'body': body[:max_body].decode(errors='replace'), 'body_length': len(body),
        'sent_before_handshake': response['sent_before_handshake'],
    }


def _load_pickle(path: Optional[str]):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, 'rb') as fh:
            return pickle.load(fh)
    except Exception:
        return None


def _save_pickle(path: Optional[str], value) -> None:
    if path and value is not None:
        with open(path, 'wb') as fh:
            pickle.dump(value, fh)


class _Target:
    def __init__(self, args):
        first = urlparse(args.urls[0])
        if first.scheme != 'https' or not first.hostname:
            raise ValueError(f"an https:// URL is expected, not {args.urls[0]!r}")
        self.host = first.hostname
        self.port = first.port or 443
        ip, port = parse_connect(args.connect, self.port)
        if ip is None:
            ip = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)[0][4][0]
        self.ip, self.connect_port = ip, port
        self.authority = self.host if self.port == 443 else f"{self.host}:{self.port}"
        self.paths = []
        for url in args.urls:
            parsed = urlparse(url)
            if parsed.hostname and parsed.hostname != self.host:
                raise ValueError("every URL must name the same server")
            self.paths.append((parsed.path or '/') + (f"?{parsed.query}" if parsed.query else ''))


async def _progress(protocol, configuration, started: float) -> None:
    """Every second: the bytes received so far and the PATH_CHALLENGE frames of the server (it
    validates a new address of the client: a NAT that changed the source port).  A PING is
    sent each second too (a browser's keep-alive): a client that only receives sends nothing
    once the NAT dropped its mapping (the server's packets are lost on the old port), so the
    server could not learn its new address."""
    challenges = 0
    uid = 0
    while True:
        await asyncio.sleep(1)
        uid += 1
        with contextlib.suppress(Exception):
            protocol._quic.send_ping(uid)
            protocol.transmit()
        now = _received_frames(_events(configuration), 'path_challenge')
        note = ''
        if now > challenges:
            note = f"  <- {now - challenges} PATH_CHALLENGE received: the server saw a new address and checks it"
            challenges = now
        print(f"  {time.monotonic() - started:5.1f} s  {protocol.received_bytes():>10} bytes received{note}",
              file=sys.stderr, flush=True)


async def _one_connection(args, target: _Target, zero_rtt: bool, ticket=None, token: bytes = b'',
                          paths=None) -> Tuple[dict, object, bytes]:
    """One connection, the *paths* requested on it.  Returns (result, new ticket, new token)."""
    configuration = _configuration(args, target.host)
    if ticket is not None:
        configuration.session_ticket = ticket
    if token:
        configuration.token = token
    saved = {'ticket': None, 'token': b''}
    headers = [parse_header(h) for h in args.header]
    data = args.data.encode() if args.data is not None else None
    method = args.method or ('POST' if data is not None else 'GET')
    result = {'server': f"{target.ip}:{target.connect_port}", 'sni': target.host, 'zero_rtt_tried': zero_rtt,
              'requests': [], 'error': ''}
    started = time.monotonic()
    protocol = None
    try:
        async with _connect(target.ip, target.connect_port, configuration,
                            session_ticket_handler=lambda t: saved.__setitem__('ticket', t),
                            token_handler=lambda t: saved.__setitem__('token', t),
                            wait_connected=not zero_rtt) as protocol:
            futures = [protocol.request(method, target.authority, path, headers, data) for path in (paths or target.paths)]
            reporter = (asyncio.ensure_future(_progress(protocol, configuration, started))
                        if getattr(args, 'progress', False) else None)
            try:
                responses = await asyncio.wait_for(asyncio.gather(*futures), args.timeout)
            finally:
                if reporter is not None:
                    reporter.cancel()
            if not zero_rtt or protocol.handshake is None:
                await asyncio.wait_for(protocol.wait_connected(), args.timeout)
            # the session ticket and NEW_TOKEN come right after the handshake
            for _ in range(10):
                if saved['ticket'] is not None:
                    break
                await asyncio.sleep(0.05)
            result['requests'] = [_response_dict(r, args.max_body) for r in responses]
            if getattr(args, 'output', None) and responses:
                with open(args.output, 'wb') as fh:
                    fh.write(bytes(responses[-1]['body']))
    except Exception as exc:
        result['error'] = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        if protocol is not None:
            result['requests'] = [_response_dict(r, args.max_body) for r in protocol.responses.values()
                                  if r['headers']]
    result['time'] = round(time.monotonic() - started, 3)
    if protocol is not None:
        result.update(_connection_facts(protocol, configuration))
    if configuration.secrets_log_file is not None:
        configuration.secrets_log_file.close()
    return result, saved['ticket'], saved['token']


async def run_get(args) -> dict:
    target = _Target(args)
    ticket = _load_pickle(args.session_ticket)
    token = _load_pickle(args.token) or b''
    result, new_ticket, new_token = await _one_connection(args, target, args.zero_rtt and ticket is not None,
                                                          ticket=ticket, token=token)
    _save_pickle(args.session_ticket, new_ticket)
    _save_pickle(args.token, new_token or None)
    result['command'] = 'get'
    return result


async def run_resume(args) -> dict:
    target = _Target(args)
    first, ticket, token = await _one_connection(args, target, False)
    second = {'error': 'no session ticket received', 'requests': []}
    if ticket is not None:
        second, _, _ = await _one_connection(args, target, True, ticket=ticket, token=token)
    return {'command': 'resume', 'first': first, 'second': second,
            'ticket_received': ticket is not None, 'token_received': bool(token)}


async def _migrate_once(args, target: _Target) -> dict:
    """One connection: a request, then *args.rebinds* times a new UDP socket (and a new
    connection ID unless --keep-cid) and the request again.  nginx needs a spare connection ID
    of the client for each new path and aioquic gives it one only: more than one rebinding per
    connection is not answered ("no available client ids for new path")."""
    configuration = _configuration(args, target.host)
    result = {'steps': [], 'error': ''}
    path = target.paths[0]
    protocol = None
    try:
        async with _connect(target.ip, target.connect_port, configuration) as protocol:
            port = protocol._transport.get_extra_info('socket').getsockname()[1]
            for i in range(args.rebinds + 1):
                step = {'rebind': i, 'local_port': port, 'peer_cid': None, 'status': None, 'error': ''}
                if i:
                    port = await _rebind(protocol)
                    step['local_port'] = port
                    if not args.keep_cid:
                        protocol.change_connection_id()
                with contextlib.suppress(Exception):
                    step['peer_cid'] = protocol._quic._peer_cid.cid.hex()
                try:
                    response = await asyncio.wait_for(protocol.request('GET', target.authority, path),
                                                      args.step_timeout)
                    step['status'] = _response_dict(response, 0)['status']
                except Exception as exc:
                    step['error'] = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
                result['steps'].append(step)
                if step['error']:
                    break
                await asyncio.sleep(args.interval)
    except Exception as exc:
        result['error'] = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    if protocol is not None:
        facts = _connection_facts(protocol, configuration)
        result.update({k: facts[k] for k in ('version', 'alpn', 'handshake', 'retry', 'path_challenges_received')})
    result['rebinds_ok'] = sum(1 for s in result['steps'][1:] if s['status'] is not None and not s['error'])
    result['migrated'] = (len(result['steps']) == args.rebinds + 1 and result['rebinds_ok'] == args.rebinds
                          and args.rebinds > 0)
    return result


async def run_migrate(args) -> dict:
    target = _Target(args)
    connections = []
    for _ in range(max(1, args.connections)):
        connections.append(await _migrate_once(args, target))
    return {'command': 'migrate', 'server': f"{target.ip}:{target.connect_port}", 'sni': target.host,
            'rebinds': args.rebinds, 'connections': connections,
            'migrated': sum(1 for c in connections if c['migrated']),
            'error': '' if any(c['handshake'] for c in connections if 'handshake' in c)
            else next((c['error'] for c in connections if c['error']), 'no connection')}


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------


def _print_connection(r: dict, show_headers: bool, out_file: Optional[str]) -> None:
    if not r.get('handshake') and r.get('error'):
        print(f"connection to {r.get('server')} failed: {r['error']}")
        return
    print(f"server {r.get('server')} (SNI {r.get('sni')}), {version_name(int(r['version'], 16) if r.get('version') else None)}, "
          f"ALPN {r.get('alpn')}, {r.get('cipher_suite')}")
    print(f"connection IDs: client (source) {r.get('host_cid')}, server (destination) {r.get('peer_cid')}")
    print(f"Retry received: {'yes' if r.get('retry') else 'no'}; session resumed: "
          f"{'yes' if r.get('session_resumed') else 'no'}; 0-RTT: "
          + (('accepted' if r.get('early_data_accepted') else 'rejected') if r.get('zero_rtt_tried') else 'not tried')
          + f"; time {r.get('time')} s")
    for req in r.get('requests', []):
        when = '0-RTT' if req['sent_before_handshake'] and r.get('early_data_accepted') else '1-RTT'
        print(f"{req['method']} {req['path']} (stream {req['stream_id']}, {when}) -> {req['status']}, "
              f"{req['body_length']} bytes")
        if show_headers:
            for name, value in req['headers']:
                print(f"  {name}: {value}")
        if out_file:
            print(f"  (body written to {out_file})")
        elif req['body']:
            print(req['body'].rstrip('\n'))
    if r.get('error'):
        print(f"error: {r['error']}")


def print_human(result: dict, args) -> None:
    command = result.get('command')
    if command == 'vn':
        if result['answer']:
            print(f"Version Negotiation from {result['server']} (sent version {result['sent_version']}):")
            for v in result['answer']['versions']:
                print(f"  {v}  {version_name(int(v, 16))}")
            print(f"  connection IDs echoed: destination {result['answer']['dcid']} (our source {result['scid']}), "
                  f"source {result['answer']['scid']} (our destination {result['dcid']})")
        else:
            print(f"no Version Negotiation from {result['server']}: {result['error']}")
    elif command == 'resume':
        print("== first connection (full handshake: session ticket and token saved)")
        _print_connection(result['first'], args.include, None)
        print("== second connection (resumption, requests sent in 0-RTT)")
        _print_connection(result['second'], args.include, args.output)
    elif command == 'migrate':
        print(f"server {result['server']} (SNI {result['sni']})")
        for n, c in enumerate(result['connections'], 1):
            print(f"connection {n}: PATH_CHALLENGE frames received: {c.get('path_challenges_received')}")
            for s in c['steps']:
                what = 'first request' if not s['rebind'] else f"after rebinding #{s['rebind']}"
                print(f"  {what}: local port {s['local_port']}, server CID {s['peer_cid']} -> "
                      f"{s['status'] if not s['error'] else s['error']}")
            if c.get('error'):
                print(f"  error: {c['error']}")
        print(f"connections that survived their migration: {result['migrated']}/{len(result['connections'])}")
    else:
        _print_connection(result, args.include, args.output)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='quic-client', description="QUIC / HTTP/3 client of the QUIC lab")
    sub = parser.add_subparsers(dest='command', required=True)

    def common(p):
        p.add_argument('urls', nargs='+', metavar='URL')
        p.add_argument('--connect', help="IP[:PORT] of the server (the URL's name stays the SNI)")
        p.add_argument('--cafile', default=DEFAULT_CAFILE)
        p.add_argument('-k', '--insecure', action='store_true')
        p.add_argument('--keylog', help="append the TLS secrets to FILE (SSLKEYLOGFILE format)")
        p.add_argument('--qlog', help="write qlog files into DIR")
        p.add_argument('-X', '--method')
        p.add_argument('-d', '--data')
        p.add_argument('-H', '--header', action='append', default=[])
        p.add_argument('-i', '--include', action='store_true', help="print the response headers")
        p.add_argument('-o', '--output', help="write the body to FILE")
        p.add_argument('--timeout', type=float, default=8.0)
        p.add_argument('--max-body', type=int, default=4096)
        p.add_argument('--json', action='store_true')

    p = sub.add_parser('get')
    common(p)
    p.add_argument('--session-ticket')
    p.add_argument('--token')
    p.add_argument('--zero-rtt', action='store_true')
    p.add_argument('--progress', action='store_true',
                   help="every second on stderr: bytes received, PATH_CHALLENGE frames of the server")
    p = sub.add_parser('resume')
    common(p)
    p = sub.add_parser('migrate')
    common(p)
    p.add_argument('--rebinds', type=int, default=1, help="rebindings per connection (nginx answers one)")
    p.add_argument('--connections', type=int, default=1, help="connections, each one migrated")
    p.add_argument('--interval', type=float, default=0.3)
    p.add_argument('--step-timeout', type=float, default=3.0)
    p.add_argument('--keep-cid', action='store_true', help="keep the connection ID (NAT rebinding only)")
    p = sub.add_parser('vn')
    p.add_argument('host')
    p.add_argument('port', nargs='?', type=int, default=443)
    p.add_argument('--timeout', type=float, default=3.0)
    p.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    try:
        if args.command == 'vn':
            result = run_vn(args.host, args.port, args.timeout)
        else:
            runner = {'get': run_get, 'resume': run_resume, 'migrate': run_migrate}[args.command]
            result = asyncio.run(asyncio.wait_for(runner(args), args.timeout * 4 + 10))
    except Exception as exc:
        result = {'command': args.command, 'error': f"{type(exc).__name__}: {exc}"}
        if not getattr(args, 'json', False):
            print(f"error: {result['error']}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print_human(result, args)
    failed = result.get('error') or (result.get('command') == 'resume' and result['second'].get('error'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
