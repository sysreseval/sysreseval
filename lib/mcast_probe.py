#!/usr/bin/env python3
# mcast_probe
# -------------------------------------------------
# Stand-alone multicast probe run inside lab containers (see install_mcast_probe() and the
# command builders of lib/mcast.py).  Standard library only, IPv4 and IPv6.
#
# usage: mcast_probe.py recv <urlsafe-base64 of a JSON spec>
#        mcast_probe.py sniff <urlsafe-base64 of a JSON spec>
#        mcast_probe.py send <urlsafe-base64 of a JSON spec>
#        mcast_probe.py dump TAG [TAG...]
#
#   recv  — daemon: one UDP socket bound to `port`, joined to every group of `joins` on `iface`
#           (`source` set: a source-specific join, IGMPv3 / MLDv2 INCLUDE; else an any-source
#           join), with IP_MULTICAST_ALL off so that it only gets what it joined.  Each datagram
#           is recorded per destination group: count, sources, the token of its payload, the
#           TTL / hop limit it arrived with.  The daemon stops after `duration` seconds (the
#           state file stays, "done": true); the joins go with it (the kernel sends the leave).
#       {"tag": "asm", "family": 4, "port": 5001, "iface": "eth0", "duration": 25,
#        "joins": [{"group": "239.1.2.3"}, {"group": "232.1.2.3", "source": "10.1.1.10"}]}
#
#   sniff — daemon: an AF_PACKET socket on `iface` (nothing joined, nothing sent) counting the
#           frames received for every group of `groups`, with their sources and tokens, plus
#           the IGMP messages seen (query, v1/v2/v3 report, leave).  Stops after `duration`.
#       {"tag": "flood", "iface": "eth0", "groups": ["239.1.2.3"], "duration": 25}
#
#   send  — blocking (or a daemon with "background": true): after `delay` seconds, `count`
#           datagrams to `group`:`port`, one every `interval` seconds, payload
#           "SREMCAST <token> <seq>", TTL / hop limit `ttl`, from `source` (an address of the
#           machine, bound before sending: the source address of the datagrams) or out of
#           `iface`.  Prints {"sent": n, "errors": [...]}.
#       {"family": 4, "group": "239.1.2.3", "port": 5001, "count": 20, "interval": 0.4,
#        "delay": 2, "ttl": 16, "token": "a1b2c3", "source": "10.1.1.10", "iface": "eth0"}
#
#   dump  — what the grader runs (a static command): one JSON document, keyed by tag, with
#           every time turned into an age on the probe's own monotonic clock; exit 0 always.
#       {"asm": {"kind": "recv", "uptime": 12.1, "heartbeat_age": 0.4, "done": false,
#                "joins": [...], "errors": [], "igmp": {},
#                "groups": {"239.1.2.3": {"count": 20, "sources": {"10.1.1.10": 20},
#                           "tokens": {"a1b2c3": 20}, "ttl_min": 13, "ttl_max": 13,
#                           "first_age": 9.0, "last_age": 1.2}}}}
import base64
import json
import os
import select
import socket
import struct
import sys
import time

PAYLOAD_PREFIX = b'SREMCAST '
STATE_DIR = '/run'
LOG_FILE = '/var/log/mcast_probe.log'
HEARTBEAT = 1.0
MAX_DURATION = 900
MAX_GROUPS = 64
MAX_SOURCES = 32
MAX_TOKENS = 16
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
PACKET_OUTGOING = 4
IGMP_TYPES = {0x11: 'query', 0x12: 'report_v1', 0x16: 'report_v2', 0x17: 'leave', 0x22: 'report_v3'}

# Linux values, for the constants a Python 3.11 socket module may lack
IP_TTL = 2
IP_PKTINFO = getattr(socket, 'IP_PKTINFO', 8)
IP_RECVTTL = getattr(socket, 'IP_RECVTTL', 12)
IP_MULTICAST_IF = getattr(socket, 'IP_MULTICAST_IF', 32)
IP_MULTICAST_TTL = getattr(socket, 'IP_MULTICAST_TTL', 33)
IP_MULTICAST_LOOP = getattr(socket, 'IP_MULTICAST_LOOP', 34)
IP_MULTICAST_ALL = 49
IPV6_MULTICAST_IF = getattr(socket, 'IPV6_MULTICAST_IF', 17)
IPV6_MULTICAST_HOPS = getattr(socket, 'IPV6_MULTICAST_HOPS', 18)
IPV6_MULTICAST_LOOP = getattr(socket, 'IPV6_MULTICAST_LOOP', 19)
IPV6_MULTICAST_ALL = 29
IPV6_RECVPKTINFO = getattr(socket, 'IPV6_RECVPKTINFO', 49)
IPV6_PKTINFO = getattr(socket, 'IPV6_PKTINFO', 50)
IPV6_RECVHOPLIMIT = getattr(socket, 'IPV6_RECVHOPLIMIT', 51)
IPV6_HOPLIMIT = getattr(socket, 'IPV6_HOPLIMIT', 52)
MCAST_JOIN_GROUP = 42
MCAST_JOIN_SOURCE_GROUP = 46


# ---------------------------------------------------------------------------
# pure helpers (tested offline)
# ---------------------------------------------------------------------------


def _af(family):
    return socket.AF_INET6 if int(family) == 6 else socket.AF_INET


def sockaddr_storage(address):
    """A struct sockaddr_storage (128 bytes) holding *address* (IPv4 or IPv6), port 0."""
    if ':' in address:
        raw = (struct.pack('=H', socket.AF_INET6) + struct.pack('!HI', 0, 0)
               + socket.inet_pton(socket.AF_INET6, address) + struct.pack('=I', 0))
    else:
        raw = struct.pack('=H', socket.AF_INET) + struct.pack('!H', 0) + socket.inet_pton(socket.AF_INET, address)
    return raw.ljust(128, b'\0')


def _req_head(ifindex):
    # struct group_req / group_source_req: a uint32 then sockaddr_storage members, which are
    # aligned like an unsigned long
    return struct.pack('=I', ifindex) + b'\0' * (struct.calcsize('P') - 4)


def group_req(ifindex, group):
    """struct group_req of MCAST_JOIN_GROUP (any-source join)."""
    return _req_head(ifindex) + sockaddr_storage(group)


def group_source_req(ifindex, group, source):
    """struct group_source_req of MCAST_JOIN_SOURCE_GROUP (source-specific join)."""
    return _req_head(ifindex) + sockaddr_storage(group) + sockaddr_storage(source)


def make_payload(token, seq):
    return PAYLOAD_PREFIX + f"{token} {seq}".encode()


def parse_payload(payload):
    """The token of a probe datagram, None for anything else."""
    if not payload.startswith(PAYLOAD_PREFIX):
        return None
    words = payload[len(PAYLOAD_PREFIX):].split()
    return words[0].decode(errors='replace')[:64] if words else None


def parse_frame(frame):
    """(family, src, dst, proto, igmp_type, token) of an Ethernet frame carrying IPv4 or IPv6,
    None otherwise.  igmp_type: the name of an IGMP message (proto 2), else None; token: the
    token of a probe UDP datagram, else None."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack('!H', frame[12:14])[0]
    offset = 14
    if ethertype == ETH_P_8021Q and len(frame) >= 18:
        ethertype = struct.unpack('!H', frame[16:18])[0]
        offset = 18
    packet = frame[offset:]
    if ethertype == ETH_P_IP and len(packet) >= 20 and packet[0] >> 4 == 4:
        ihl = (packet[0] & 0x0F) * 4
        proto = packet[9]
        src = socket.inet_ntop(socket.AF_INET, packet[12:16])
        dst = socket.inet_ntop(socket.AF_INET, packet[16:20])
        body = packet[ihl:]
        igmp = IGMP_TYPES.get(body[0], f"type_{body[0]:#x}") if proto == 2 and body else None
        token = parse_payload(body[8:]) if proto == 17 and len(body) >= 8 else None
        return 4, src, dst, proto, igmp, token
    if ethertype == ETH_P_IPV6 and len(packet) >= 40 and packet[0] >> 4 == 6:
        proto = packet[6]
        src = socket.inet_ntop(socket.AF_INET6, packet[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, packet[24:40])
        body = packet[40:]
        token = parse_payload(body[8:]) if proto == 17 and len(body) >= 8 else None
        return 6, src, dst, proto, None, token
    return None


class State:
    """What a recv / sniff daemon has seen (times on the monotonic clock)."""

    def __init__(self, kind, started, spec):
        self.kind = kind
        self.started = started
        self.heartbeat = started
        self.done = False
        self.spec = spec
        self.groups = {}
        self.igmp = {}
        self.errors = []

    def record(self, group, src, token, ttl, now):
        entry = self.groups.get(group)
        if entry is None:
            if len(self.groups) >= MAX_GROUPS:
                return False
            entry = self.groups[group] = {'count': 0, 'sources': {}, 'tokens': {}, 'ttl_min': None,
                                          'ttl_max': None, 'first': now, 'last': now}
        entry['count'] += 1
        entry['last'] = now
        if src in entry['sources'] or len(entry['sources']) < MAX_SOURCES:
            entry['sources'][src] = entry['sources'].get(src, 0) + 1
        if token is not None and (token in entry['tokens'] or len(entry['tokens']) < MAX_TOKENS):
            entry['tokens'][token] = entry['tokens'].get(token, 0) + 1
        if ttl is not None:
            entry['ttl_min'] = ttl if entry['ttl_min'] is None else min(entry['ttl_min'], ttl)
            entry['ttl_max'] = ttl if entry['ttl_max'] is None else max(entry['ttl_max'], ttl)
        return True

    def record_igmp(self, kind):
        self.igmp[kind] = self.igmp.get(kind, 0) + 1

    def to_dict(self):
        return {'kind': self.kind, 'started': self.started, 'heartbeat': self.heartbeat, 'done': self.done,
                'spec': self.spec, 'groups': self.groups, 'igmp': self.igmp, 'errors': self.errors[-10:]}


def _age(now, then):
    return None if then is None else round(max(0.0, now - then), 3)


def dump_state(state, now):
    """The document of ``dump`` for one tag: *state* (a ``State.to_dict()``) with ages."""
    groups = {}
    for group, e in (state.get('groups') or {}).items():
        groups[group] = {'count': e.get('count', 0), 'sources': e.get('sources', {}), 'tokens': e.get('tokens', {}),
                         'ttl_min': e.get('ttl_min'), 'ttl_max': e.get('ttl_max'),
                         'first_age': _age(now, e.get('first')), 'last_age': _age(now, e.get('last'))}
    spec = state.get('spec') or {}
    return {'kind': state.get('kind'), 'uptime': _age(now, state.get('started')),
            'heartbeat_age': _age(now, state.get('heartbeat')), 'done': bool(state.get('done')),
            'joins': spec.get('joins', []), 'watched': spec.get('groups', []), 'igmp': state.get('igmp', {}),
            'groups': groups, 'errors': list(state.get('errors') or [])}


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def _spec(argument):
    return json.loads(base64.urlsafe_b64decode(argument))


def _safe_tag(tag):
    tag = str(tag)
    if not tag or not all(c.isalnum() or c in '_-' for c in tag):
        raise ValueError(f"bad tag {tag!r}")
    return tag


def state_path(tag):
    return os.path.join(STATE_DIR, f"mcast_probe_{_safe_tag(tag)}.json")


def pid_path(tag):
    return os.path.join(STATE_DIR, f"mcast_probe_{_safe_tag(tag)}.pid")


def write_state(path, state):
    tmp = f"{path}.tmp"
    with open(tmp, 'w') as out:
        json.dump(state.to_dict(), out, separators=(',', ':'))
    os.replace(tmp, path)


def stop_previous(tag):
    """Kill the daemon of the same tag still running (a new evaluation restarts it)."""
    try:
        with open(pid_path(tag)) as source:
            pid = int(source.read().strip())
        if pid != os.getpid():
            os.kill(pid, 15)
            time.sleep(0.2)
    except (OSError, ValueError):
        pass


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


def _open_receiver(spec):
    family = int(spec.get('family', 4))
    af = _af(family)
    level = socket.IPPROTO_IPV6 if family == 6 else socket.IPPROTO_IP
    sock = socket.socket(af, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == 6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(level, IPV6_RECVPKTINFO, 1)
        sock.setsockopt(level, IPV6_RECVHOPLIMIT, 1)
        sock.setsockopt(level, IPV6_MULTICAST_ALL, 0)
        sock.bind(('::', int(spec['port'])))
    else:
        sock.setsockopt(level, IP_PKTINFO, 1)
        sock.setsockopt(level, IP_RECVTTL, 1)
        sock.setsockopt(level, IP_MULTICAST_ALL, 0)
        sock.bind(('0.0.0.0', int(spec['port'])))
    ifindex = socket.if_nametoindex(spec['iface']) if spec.get('iface') else 0
    errors = []
    for join in spec.get('joins', []):
        try:
            if join.get('source'):
                sock.setsockopt(level, MCAST_JOIN_SOURCE_GROUP, group_source_req(ifindex, join['group'], join['source']))
            else:
                sock.setsockopt(level, MCAST_JOIN_GROUP, group_req(ifindex, join['group']))
        except OSError as e:
            errors.append(f"join {join}: {e}")
    sock.setblocking(False)
    return sock, family, errors


def _ancillary(family, ancdata):
    """(destination address, ttl) from the control messages of recvmsg()."""
    dst, ttl = None, None
    for level, kind, data in ancdata:
        if family == 4 and level == socket.IPPROTO_IP:
            if kind == IP_PKTINFO and len(data) >= 12:
                dst = socket.inet_ntop(socket.AF_INET, data[8:12])
            elif kind == IP_TTL and len(data) >= 4:
                ttl = struct.unpack('=i', data[:4])[0]
        elif family == 6 and level == socket.IPPROTO_IPV6:
            if kind == IPV6_PKTINFO and len(data) >= 16:
                dst = socket.inet_ntop(socket.AF_INET6, data[:16])
            elif kind == IPV6_HOPLIMIT and len(data) >= 4:
                ttl = struct.unpack('=i', data[:4])[0]
    return dst, ttl


def _run(state, path, sockets, handler, duration):
    write_state(path, state)
    written = state.started
    end = state.started + duration
    while True:
        now = time.monotonic()
        if now >= end:
            break
        readable, _, _ = select.select(list(sockets), [], [], min(HEARTBEAT / 2, max(0.05, end - now)))
        now = time.monotonic()
        changed = False
        for sock in readable:
            try:
                while True:
                    changed = handler(sock, now) or changed
            except (BlockingIOError, InterruptedError):
                pass
            except Exception as e:     # one bad packet must not stop the probe
                sys.stderr.write(f"{type(e).__name__}: {e}\n")
        if changed or now - written >= HEARTBEAT:
            state.heartbeat = now
            try:
                write_state(path, state)
                written = now
            except OSError as e:
                sys.stderr.write(f"{type(e).__name__}: {e}\n")
    state.heartbeat = time.monotonic()
    state.done = True
    write_state(path, state)


def forget(tag):
    """Remove the state file of *tag*: a daemon that fails to start must not leave the counts of
    the previous run behind for the next dump."""
    try:
        os.remove(state_path(tag))
    except OSError:
        pass


def do_recv(spec):
    tag = _safe_tag(spec['tag'])
    stop_previous(tag)
    forget(tag)
    sock, family, errors = _open_receiver(spec)
    daemonize(pid_path(tag))
    state = State('recv', time.monotonic(), spec)
    state.errors.extend(errors)

    def handler(s, now):
        payload, ancdata, _flags, address = s.recvmsg(65535, 256)
        dst, ttl = _ancillary(family, ancdata)
        return state.record(dst or '?', address[0], parse_payload(payload), ttl, now)

    _run(state, state_path(tag), [sock], handler, min(float(spec.get('duration', 30)), MAX_DURATION))


def do_sniff(spec):
    tag = _safe_tag(spec['tag'])
    stop_previous(tag)
    forget(tag)
    watched = {str(g) for g in spec.get('groups', [])}
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    sock.bind((spec['iface'], ETH_P_ALL))
    sock.setblocking(False)
    daemonize(pid_path(tag))
    state = State('sniff', time.monotonic(), spec)

    def handler(s, now):
        frame, address = s.recvfrom(65535)
        if len(address) > 2 and address[2] == PACKET_OUTGOING:
            return False
        decoded = parse_frame(frame)
        if decoded is None:
            return False
        _family, src, dst, _proto, igmp, token = decoded
        changed = False
        if igmp is not None:
            state.record_igmp(igmp)
            changed = True
        if dst in watched:
            changed = state.record(dst, src, token, None, now) or changed
        return changed

    _run(state, state_path(tag), [sock], handler, min(float(spec.get('duration', 30)), MAX_DURATION))


def do_send(spec):
    family = int(spec.get('family', 4))
    errors, sent = [], 0
    try:
        sock = socket.socket(_af(family), socket.SOCK_DGRAM)
        if spec.get('source'):
            sock.bind((spec['source'], 0))
        ttl = int(spec.get('ttl', 16))
        ifindex = socket.if_nametoindex(spec['iface']) if spec.get('iface') else 0
        if family == 6:
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_HOPS, ttl)
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 0)
            if ifindex:
                sock.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_IF, ifindex)
        else:
            sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_TTL, ttl)
            sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_LOOP, 0)
            if ifindex or spec.get('source'):
                # struct ip_mreqn: the source address and / or the interface of the datagrams
                local = socket.inet_aton(spec['source']) if spec.get('source') else b'\0' * 4
                sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, b'\0' * 4 + local + struct.pack('=i', ifindex))
    except (OSError, ValueError) as e:
        print(json.dumps({'sent': 0, 'errors': [f"{type(e).__name__}: {e}"]}))
        return 0
    if spec.get('background'):
        daemonize(pid_path(_safe_tag(spec.get('tag', 'send'))))
    time.sleep(max(0.0, float(spec.get('delay', 0))))
    count = max(0, min(int(spec.get('count', 10)), 10000))
    interval = max(0.01, float(spec.get('interval', 0.5)))
    destination = (spec['group'], int(spec['port']))
    for seq in range(count):
        try:
            sock.sendto(make_payload(spec.get('token', 'x'), seq), destination)
            sent += 1
        except OSError as e:
            if len(errors) < 5:
                errors.append(f"{type(e).__name__}: {e}")
        if seq + 1 < count:
            time.sleep(interval)
    print(json.dumps({'sent': sent, 'errors': errors}))
    return 0


def do_dump(tags):
    now = time.monotonic()
    document = {}
    for tag in tags:
        try:
            with open(state_path(tag)) as source:
                document[tag] = dump_state(json.load(source), now)
        except Exception as e:         # the grader needs a JSON document whatever happens
            document[tag] = {'kind': None, 'uptime': None, 'heartbeat_age': None, 'done': False, 'joins': [],
                             'watched': [], 'igmp': {}, 'groups': {}, 'errors': [f"{type(e).__name__}: {e}"]}
    print(json.dumps(document, sort_keys=True))
    return 0


def main(argv):
    usage = f"usage: {argv[0]} recv SPEC | sniff SPEC | send SPEC | dump TAG [TAG...]\n"
    mode = argv[1] if len(argv) > 1 else ''
    if mode == 'dump' and len(argv) > 2:
        return do_dump(argv[2:])
    if mode in ('recv', 'sniff', 'send') and len(argv) > 2:
        try:
            spec = _spec(argv[2])
        except ValueError:
            sys.stderr.write(usage)
            return 2
        return {'recv': do_recv, 'sniff': do_sniff, 'send': do_send}[mode](spec) or 0
    sys.stderr.write(usage)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
