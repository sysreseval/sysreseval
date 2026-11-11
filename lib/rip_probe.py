#!/usr/bin/env python3
# rip_probe
# -------------------------------------------------
# Stand-alone RIP probe run inside lab containers (see install_rip_probe() and the command
# builders of lib/rip.py).  Standard library only.
#
# usage: rip_probe.py listen <urlsafe-base64 of a JSON spec>
#        rip_probe.py dump [STATE_FILE]
#        rip_probe.py announce <urlsafe-base64 of a JSON spec>
#
#   listen   — daemon of a hidden machine: one AF_PACKET socket per interface, nothing is ever
#              sent (no address needed, no IGMP report, never a RIP peer).  Every RIP datagram
#              (UDP port 520) seen on the wire is recorded in STATE_FILE per interface and
#              source address: the routes of its RESPONSEs sent to a group address (the
#              periodic and triggered updates), their authentication header, the time of the
#              last one.
#       {"interfaces": ["eth0", "eth1"], "keys": {"7": "secret"}, "state": "/run/rip_probe.json"}
#              "keys": the MD5 secrets of the lab by key id; a digest is "valid" when it
#              matches one of them, whatever the key id the packet announces.
#
#   dump     — what the grader runs (a static command): the state file with every time turned
#              into an age on the probe's own monotonic clock.  Always one JSON document and
#              exit 0:
#       {"errors": [...], "uptime": 123.4, "heartbeat_age": 0.3,
#        "interfaces": {"eth0": {"10.1.2.1": {"age": 3.2, "packets": 41, "version": 2,
#            "dst": "224.0.0.9", "requests": 1, "unicast": 0,
#            "auth": {"type": "md5", "key_id": 7, "auth_len": 20, "valid": true},
#            "entries": {"10.1.3.0/24": {"metric": 2, "next_hop": "0.0.0.0", "tag": 0,
#                                        "age": 3.2}}}}}}
#
#   announce — daemon of a rogue RIP speaker: every `interval` seconds one RIPv2 RESPONSE from
#              port 520 of `source` to 224.0.0.9 with the given routes.
#       {"source": "10.1.3.7", "interval": 2, "routes": [["192.168.77.0/24", 1]]}
import base64
import ctypes
import hashlib
import json
import os
import select
import socket
import struct
import sys
import time

RIP_PORT = 520
RIP_GROUP = '224.0.0.9'
RIP_REQUEST = 1
RIP_RESPONSE = 2
RIP_COMMANDS = {RIP_REQUEST: 'request', RIP_RESPONSE: 'response'}
RIP_INFINITY = 16
RIP_HEADER_SIZE = 4
RIP_RTE_SIZE = 20
RIP_MAX_RTE = 25
RIP_FAMILY_AUTH = 0xFFFF
RIP_AUTH_TEXT = 2
RIP_AUTH_MD5 = 3
RIP_AUTH_DATA = 1                      # "type" of the MD5 trailer
RIP_MD5_SIZE = 16
RIP_MD5_AUTH_LEN = 20                  # what ripd writes by default (RFC 2082 says 16)
AUTH_TYPES = {RIP_AUTH_TEXT: 'text', RIP_AUTH_MD5: 'md5'}
AF_INET_RIP = 2

ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
IPPROTO_UDP = 17

STATE_FILE = '/run/rip_probe.json'
LISTEN_PID_FILE = '/run/rip_probe_listen.pid'
ANNOUNCE_PID_FILE = '/run/rip_probe_announce.pid'
LOG_FILE = '/var/log/rip_probe.log'
HEARTBEAT = 1.0                        # the state file is written at least that often
MAX_SOURCES = 32                       # per interface
MAX_PREFIXES = 256                     # per source
ENTRY_MAX_AGE = 900.0                  # an entry not heard for that long is forgotten
DEFAULT_INTERVAL = 2.0

# Linux values of the constants some Python builds lack
SO_ATTACH_FILTER = getattr(socket, 'SO_ATTACH_FILTER', 26)
IP_MULTICAST_IF = getattr(socket, 'IP_MULTICAST_IF', 32)
IP_MULTICAST_TTL = getattr(socket, 'IP_MULTICAST_TTL', 33)
IP_MULTICAST_LOOP = getattr(socket, 'IP_MULTICAST_LOOP', 34)

# classic BPF of "ip and udp dst port 520" on an Ethernet link: (code, jt, jf, k)
BPF_RIP = (
    (0x28, 0, 0, 12),                  # ldh [12]            ethertype
    (0x15, 0, 8, ETH_P_IP),            # jeq #0x800          else drop
    (0x30, 0, 0, 23),                  # ldb [23]            IP protocol
    (0x15, 0, 6, IPPROTO_UDP),         # jeq #17             else drop
    (0x28, 0, 0, 20),                  # ldh [20]            flags + fragment offset
    (0x45, 4, 0, 0x1FFF),              # jset #0x1fff        a later fragment: drop
    (0xB1, 0, 0, 14),                  # ldxb 4*([14]&0xf)   IP header length
    (0x48, 0, 0, 16),                  # ldh [x + 16]        UDP destination port
    (0x15, 0, 1, RIP_PORT),            # jeq #520            else drop
    (0x06, 0, 0, 0x40000),             # ret #262144
    (0x06, 0, 0, 0),                   # ret #0
)


# ---------------------------------------------------------------------------
# RIP codec (pure)
# ---------------------------------------------------------------------------


def _key16(key):
    """The secret as ripd hashes it: its first 16 bytes, NUL-padded."""
    raw = key if isinstance(key, bytes) else str(key).encode()
    return raw[:RIP_MD5_SIZE].ljust(RIP_MD5_SIZE, b'\x00')


def md5_digest(packet, packet_len, key):
    """RFC 2082 digest of *packet*: MD5 of its first ``packet_len + 4`` bytes (the trailer's
    family and type included) followed by the 16-byte key."""
    return hashlib.md5(bytes(packet[:packet_len + 4]) + _key16(key)).digest()


def _classful_len(address):
    """Prefix length of a RIPv1 entry (no mask on the wire): the class of the address when its
    host part is null, else a host route."""
    value = struct.unpack('!I', address)[0]
    if value == 0:
        return 0
    first = value >> 24
    natural = 8 if first < 128 else 16 if first < 192 else 24
    return natural if value & ((1 << (32 - natural)) - 1) == 0 else 32


def _mask_len(mask):
    """Prefix length of a contiguous mask, or None."""
    value = struct.unpack('!I', mask)[0]
    length = bin(value).count('1')
    return length if value == ((0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF) else None


def parse_rip(payload):
    """Decode the UDP payload of a RIP datagram.

    Returns ``{'command': 'request' | 'response' | int, 'version': int, 'auth': None | {...},
    'entries': [{'prefix', 'metric', 'next_hop', 'tag'}], 'whole_table': bool}`` or None when the
    payload is not a RIP packet.  ``auth`` is ``{'type': 'text', 'password': str}`` or
    ``{'type': 'md5', 'key_id', 'auth_len', 'sequence', 'packet_len', 'digest': bytes | None}``
    (``digest`` None when the trailer is missing or misplaced).  ``whole_table``: the request of
    the whole routing table (one entry, family 0, metric 16).
    """
    if len(payload) < RIP_HEADER_SIZE:
        return None
    command, version = payload[0], payload[1]
    if version not in (1, 2) or command == 0:
        return None
    end = len(payload)
    offset = RIP_HEADER_SIZE
    auth = None
    if end - offset >= RIP_RTE_SIZE and struct.unpack('!H', payload[offset:offset + 2])[0] == RIP_FAMILY_AUTH:
        auth_type = struct.unpack('!H', payload[offset + 2:offset + 4])[0]
        if auth_type == RIP_AUTH_MD5:
            packet_len, key_id, auth_len, sequence = struct.unpack('!HBBI', payload[offset + 4:offset + 12])
            digest = None
            trailer = payload[packet_len:packet_len + 4 + RIP_MD5_SIZE]
            if (packet_len >= offset + RIP_RTE_SIZE and len(trailer) == 4 + RIP_MD5_SIZE
                    and struct.unpack('!HH', trailer[:4]) == (RIP_FAMILY_AUTH, RIP_AUTH_DATA)):
                digest = bytes(trailer[4:])
                end = packet_len
            auth = {'type': 'md5', 'key_id': key_id, 'auth_len': auth_len, 'sequence': sequence,
                    'packet_len': packet_len, 'digest': digest}
        elif auth_type == RIP_AUTH_TEXT:
            password = bytes(payload[offset + 4:offset + RIP_RTE_SIZE]).split(b'\x00')[0]
            auth = {'type': 'text', 'password': password.decode('latin-1')}
        else:
            auth = {'type': str(auth_type)}
        offset += RIP_RTE_SIZE
    if (end - offset) % RIP_RTE_SIZE:
        return None
    entries, whole_table = [], False
    count = (end - offset) // RIP_RTE_SIZE
    for n in range(count):
        rte = payload[offset + n * RIP_RTE_SIZE:offset + (n + 1) * RIP_RTE_SIZE]
        family, tag = struct.unpack('!HH', rte[:4])
        address, mask, next_hop = rte[4:8], rte[8:12], rte[12:16]
        metric = struct.unpack('!I', rte[16:20])[0]
        if family == 0 and count == 1 and metric == RIP_INFINITY and command == RIP_REQUEST:
            whole_table = True
            continue
        if family != AF_INET_RIP:
            continue
        length = _classful_len(address) if version == 1 else _mask_len(mask)
        if length is None or not 0 <= metric <= RIP_INFINITY:
            continue
        network = struct.unpack('!I', address)[0]
        if length < 32 and network & ((1 << (32 - length)) - 1):
            continue
        entries.append({'prefix': f"{socket.inet_ntoa(address)}/{length}", 'metric': metric,
                        'next_hop': socket.inet_ntoa(next_hop), 'tag': tag})
    return {'command': RIP_COMMANDS.get(command, command), 'version': version, 'auth': auth,
            'entries': entries, 'whole_table': whole_table}


def md5_valid(payload, key):
    """True when *payload* is a RIP packet whose MD5 trailer matches *key*."""
    rip = parse_rip(payload)
    auth = rip and rip['auth']
    if not auth or auth.get('type') != 'md5' or auth.get('digest') is None:
        return False
    return md5_digest(payload, auth['packet_len'], key) == auth['digest']


def _rte(prefix, metric, next_hop='0.0.0.0', tag=0):
    address, _, length = str(prefix).partition('/')
    length = int(length or 32)
    mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
    return (struct.pack('!HH', AF_INET_RIP, tag) + socket.inet_aton(address) + struct.pack('!I', mask)
            + socket.inet_aton(next_hop) + struct.pack('!I', metric))


def build_response(routes, version=2, auth=None):
    """UDP payload of one RIP RESPONSE.

    *routes*: ``[(prefix, metric)]`` or ``[(prefix, metric, next_hop, tag)]`` (at most 25, 24 with
    authentication).  *auth*: None, ``{'type': 'text', 'key': ...}`` or ``{'type': 'md5', 'key':
    ..., 'key_id': 1, 'auth_len': 20, 'sequence': 0}``.
    """
    packet = struct.pack('!BBH', RIP_RESPONSE, version, 0)
    limit = RIP_MAX_RTE - (1 if auth else 0)
    body = b''.join(_rte(*route) for route in list(routes)[:limit])
    if not auth:
        return packet + body
    if auth.get('type') == 'text':
        return (packet + struct.pack('!HH', RIP_FAMILY_AUTH, RIP_AUTH_TEXT) + _key16(auth['key']) + body)
    packet_len = RIP_HEADER_SIZE + RIP_RTE_SIZE + len(body)
    packet += struct.pack('!HHHBBI8x', RIP_FAMILY_AUTH, RIP_AUTH_MD5, packet_len,
                          int(auth.get('key_id', 1)) % 256, int(auth.get('auth_len', RIP_MD5_AUTH_LEN)),
                          int(auth.get('sequence', 0)))
    packet += body + struct.pack('!HH', RIP_FAMILY_AUTH, RIP_AUTH_DATA)
    return packet + md5_digest(packet, packet_len, auth['key'])


def build_request(version=2):
    """UDP payload of the request of the whole routing table."""
    return struct.pack('!BBH', RIP_REQUEST, version, 0) + struct.pack('!HH4x4x4xI', 0, 0, RIP_INFINITY)


def parse_frame(frame):
    """Decode an Ethernet frame holding an unfragmented IPv4 UDP datagram to port 520.

    Returns ``(src, dst, source_port, group, payload)`` — *group*: the Ethernet destination is a
    group address (multicast or broadcast) — or None for anything else.
    """
    try:
        offset = 12
        ethertype = struct.unpack('!H', frame[offset:offset + 2])[0]
        if ethertype == ETH_P_8021Q:
            offset += 4
            ethertype = struct.unpack('!H', frame[offset:offset + 2])[0]
        if ethertype != ETH_P_IP:
            return None
        ip = offset + 2
        if frame[ip] >> 4 != 4:
            return None
        header_len = (frame[ip] & 0x0F) * 4
        total_len = struct.unpack('!H', frame[ip + 2:ip + 4])[0]
        fragment = struct.unpack('!H', frame[ip + 6:ip + 8])[0]
        if header_len < 20 or frame[ip + 9] != IPPROTO_UDP or fragment & 0x3FFF:
            return None
        udp = ip + header_len
        if len(frame) < udp + 8:
            return None
        source_port, dest_port, udp_len = struct.unpack('!HHH', frame[udp:udp + 6])
        if dest_port != RIP_PORT or udp_len < 8:
            return None
        end = min(udp + udp_len, ip + total_len, len(frame))
        return (socket.inet_ntoa(frame[ip + 12:ip + 16]), socket.inet_ntoa(frame[ip + 16:ip + 20]),
                source_port, bool(frame[0] & 1), bytes(frame[udp + 8:end]))
    except (struct.error, IndexError, OSError):
        return None


# ---------------------------------------------------------------------------
# what the listener remembers (pure)
# ---------------------------------------------------------------------------


class State:
    """Everything heard, per interface and source address; times are those the caller gives
    (monotonic seconds)."""

    def __init__(self, started, keys=None, max_sources=MAX_SOURCES, max_prefixes=MAX_PREFIXES):
        self.started = started
        self.heartbeat = started
        self.keys = {str(key_id): secret for key_id, secret in (keys or {}).items()}
        self.max_sources = max_sources
        self.max_prefixes = max_prefixes
        self.interfaces = {}

    def _auth(self, payload, rip):
        auth = rip['auth']
        if auth is None:
            return {'type': 'none'}
        if auth['type'] == 'text':
            return {'type': 'text', 'password': auth['password']}
        if auth['type'] != 'md5':
            return {'type': auth['type']}
        valid = auth['digest'] is not None and any(
            md5_digest(payload, auth['packet_len'], secret) == auth['digest'] for secret in self.keys.values())
        return {'type': 'md5', 'key_id': auth['key_id'], 'auth_len': auth['auth_len'], 'valid': valid}

    def record(self, interface, src, dst, source_port, group, payload, now):
        """Take one datagram to port 520 into account; True when it was a RIP packet."""
        rip = parse_rip(payload)
        if rip is None:
            return False
        sources = self.interfaces.setdefault(interface, {})
        source = sources.get(src)
        if source is None:
            if len(sources) >= self.max_sources:
                return False
            source = sources[src] = {'last': None, 'packets': 0, 'version': None, 'dst': None, 'auth': None,
                                     'requests': 0, 'unicast': 0, 'entries': {}}
        if rip['command'] == 'request':
            source['requests'] += 1
            return True
        if rip['command'] != 'response' or source_port != RIP_PORT:
            return True
        if not group:
            # an answer to a request, a `neighbor` statement: not what the link's routers hear
            source['unicast'] += 1
            return True
        source.update(last=now, version=rip['version'], dst=dst, auth=self._auth(payload, rip))
        source['packets'] += 1
        entries = source['entries']
        for entry in rip['entries']:
            if entry['prefix'] not in entries and len(entries) >= self.max_prefixes:
                continue
            entries[entry['prefix']] = {'metric': entry['metric'], 'next_hop': entry['next_hop'],
                                        'tag': entry['tag'], 'seen': now}
        return True

    def expire(self, now, max_age=ENTRY_MAX_AGE):
        for sources in self.interfaces.values():
            for source in sources.values():
                for prefix in [p for p, e in source['entries'].items() if now - e['seen'] > max_age]:
                    del source['entries'][prefix]

    def to_dict(self):
        return {'started': self.started, 'heartbeat': self.heartbeat, 'interfaces': self.interfaces}


def _age(now, then):
    return None if then is None else round(max(0.0, now - then), 3)


def dump_state(state, now):
    """The document of ``dump``: *state* (a ``State.to_dict()``) with ages instead of times."""
    interfaces = {}
    for interface, sources in (state.get('interfaces') or {}).items():
        interfaces[interface] = {}
        for src, source in sources.items():
            entries = {prefix: {'metric': e['metric'], 'next_hop': e['next_hop'], 'tag': e['tag'],
                                'age': _age(now, e['seen'])}
                       for prefix, e in (source.get('entries') or {}).items()}
            interfaces[interface][src] = {
                'age': _age(now, source.get('last')), 'packets': source.get('packets', 0),
                'version': source.get('version'), 'dst': source.get('dst'), 'auth': source.get('auth'),
                'requests': source.get('requests', 0), 'unicast': source.get('unicast', 0), 'entries': entries}
    return {'uptime': _age(now, state.get('started')), 'heartbeat_age': _age(now, state.get('heartbeat')),
            'interfaces': interfaces}


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def _spec(argument):
    return json.loads(base64.urlsafe_b64decode(argument))


def write_state(path, state):
    tmp = f"{path}.tmp"
    with open(tmp, 'w') as out:
        json.dump(state.to_dict(), out, separators=(',', ':'))
    os.replace(tmp, path)


def daemonize(pid_file):
    if os.fork() != 0:
        os._exit(0)
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    for fd in (0, 1, 2):
        try:
            os.close(fd)
        except OSError:
            pass
    os.open(os.devnull, os.O_RDONLY)
    log = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(log, 1)
    os.dup2(log, 2)
    with open(pid_file, 'w') as out:
        out.write(str(os.getpid()))


def _attach_filter(sock):
    """Let the kernel drop everything but the datagrams to port 520 (the Python decoder checks
    again, so a kernel refusing the filter only costs CPU)."""
    try:
        program = b''.join(struct.pack('HBBI', *instruction) for instruction in BPF_RIP)
        buffer = ctypes.create_string_buffer(program)
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                        struct.pack('HL', len(BPF_RIP), ctypes.addressof(buffer)))
    except (OSError, ValueError, struct.error):
        pass


def _open_listener(interface):
    # protocol 0: the socket receives nothing until it is bound, so no frame of another
    # interface is ever queued on it; bind() converts the protocol to network order itself
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    _attach_filter(sock)
    sock.bind((interface, ETH_P_IP))
    sock.setblocking(False)
    return sock


def do_listen(spec):
    path = spec.get('state', STATE_FILE)
    sockets = {_open_listener(interface): interface for interface in spec['interfaces']}
    daemonize(LISTEN_PID_FILE)
    state = State(time.monotonic(), keys=spec.get('keys'))
    write_state(path, state)
    written = state.started
    while True:
        readable, _, _ = select.select(list(sockets), [], [], HEARTBEAT / 2)
        now = time.monotonic()
        changed = False
        for sock in readable:
            try:
                while True:
                    frame, address = sock.recvfrom(65535)
                    if len(address) > 2 and address[2] == 4:        # PACKET_OUTGOING
                        continue
                    decoded = parse_frame(frame)
                    if decoded is not None:
                        changed = state.record(sockets[sock], *decoded, now) or changed
            except (BlockingIOError, InterruptedError):
                pass
            except Exception as e:     # one bad packet must not stop the probe
                sys.stderr.write(f"{type(e).__name__}: {e}\n")
        if changed or now - written >= HEARTBEAT:
            state.heartbeat = now
            state.expire(now)
            try:
                write_state(path, state)
                written = now
            except OSError as e:
                sys.stderr.write(f"{type(e).__name__}: {e}\n")


def do_dump(path):
    errors, document = [], {'uptime': None, 'heartbeat_age': None, 'interfaces': {}}
    try:
        with open(path) as source:
            document = dump_state(json.load(source), time.monotonic())
    except Exception as e:             # the grader needs a JSON document whatever happens
        errors.append(f"{type(e).__name__}: {e}")
    document['errors'] = errors
    print(json.dumps(document, sort_keys=True))
    return 0


def do_announce(spec):
    source = spec['source']
    interval = max(0.2, float(spec.get('interval', DEFAULT_INTERVAL)))
    packet = build_response([tuple(route) for route in spec['routes']], version=int(spec.get('version', 2)))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((source, RIP_PORT))
    sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_LOOP, 0)
    sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, socket.inet_aton(source))
    daemonize(ANNOUNCE_PID_FILE)
    while True:
        try:
            sock.sendto(packet, (RIP_GROUP, RIP_PORT))
        except OSError as e:
            sys.stderr.write(f"{type(e).__name__}: {e}\n")
        time.sleep(interval)


def main(argv):
    usage = f"usage: {argv[0]} listen SPEC | dump [STATE_FILE] | announce SPEC\n"
    mode = argv[1] if len(argv) > 1 else ''
    if mode == 'dump':
        return do_dump(argv[2] if len(argv) > 2 else STATE_FILE)
    if mode in ('listen', 'announce') and len(argv) > 2:
        try:
            spec = _spec(argv[2])
        except ValueError:
            sys.stderr.write(usage)
            return 2
        (do_listen if mode == 'listen' else do_announce)(spec)
        return 0
    sys.stderr.write(usage)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
