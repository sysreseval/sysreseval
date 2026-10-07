#!/usr/bin/env python3
# ipv6_probe
# -------------------------------------------------
# Stand-alone router-advertisement / DHCPv6 probe run inside a lab container by the grader
# (see install_ipv6_probe() / ipv6_probe() in lib/ipv6.py).  Standard library only.
#
# usage: ipv6_probe.py <urlsafe-base64 of a JSON spec>
#
# spec = {"interface": "eth0", "wait": 4.0, "rs": true,
#         "queries": [{"id": "dyn", "type": "solicit", "duid": "00:03:00:01:02:53:52:00:00:01", "iaid": 1},
#                     {"id": "info", "type": "information-request", "duid": "00:03:00:01:..."}]}
#
# With "rs" a Router Solicitation is sent to ff02::2 from the link-local address of the
# interface (raw ICMPv6 socket) and every Router Advertisement received during `wait` seconds
# is decoded (flags M/O, router lifetime, prefix information, MTU, RDNSS, DNSSL options).
# Every query is a DHCPv6 SOLICIT (with an IA_NA) or INFORMATION-REQUEST sent from the
# link-local address, port 546, to ff02::1:2 port 547; the ADVERTISE / REPLY messages are
# matched by transaction id and decoded (server DUID, IA_NA addresses and lifetimes, status,
# DNS servers, domain search list, preference).  No REQUEST is ever sent: the servers only
# advertise, no lease is committed.
#
# Always prints one JSON document on stdout and exits 0:
# {"errors": [...], "link_local": "fe80::...", "ra": [ra, ...], "dhcp6": {"dyn": [reply, ...], ...}}
import base64
import json
import os
import socket
import struct
import sys
import threading
import time

DEFAULT_WAIT = 4.0
ND_ROUTER_SOLICIT = 133
ND_ROUTER_ADVERT = 134
ALL_ROUTERS = 'ff02::2'
ALL_DHCP_AGENTS = 'ff02::1:2'
DHCP6_CLIENT_PORT, DHCP6_SERVER_PORT = 546, 547
# requested options: DNS servers (23), domain search list (24)
DHCP6_ORO = (23, 24)

MSG_TYPES = {1: 'SOLICIT', 2: 'ADVERTISE', 3: 'REQUEST', 4: 'CONFIRM', 5: 'RENEW', 6: 'REBIND', 7: 'REPLY',
             8: 'RELEASE', 9: 'DECLINE', 10: 'RECONFIGURE', 11: 'INFORMATION-REQUEST', 12: 'RELAY-FORW',
             13: 'RELAY-REPL'}
QUERY_TYPES = {'solicit': 1, 'information-request': 11}
STATUS_CODES = {0: 'Success', 1: 'UnspecFail', 2: 'NoAddrsAvail', 3: 'NoBinding', 4: 'NotOnLink', 5: 'UseMulticast',
                6: 'NoPrefixAvail'}


# ---------------------------------------------------------------------------
# interface facts
# ---------------------------------------------------------------------------

def _hex_to_bytes(text):
    return bytes(int(x, 16) for x in text.replace('-', ':').split(':') if x != '')


def _bytes_to_hex(raw):
    return ':'.join(f'{b:02x}' for b in raw)


def interface_mac(iface):
    with open(f'/sys/class/net/{iface}/address') as f:
        return _hex_to_bytes(f.read().strip())


def interface_link_local(iface):
    """Link-local address of *iface* (``/proc/net/if_inet6``, scope 0x20), or None."""
    with open('/proc/net/if_inet6') as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 6 and fields[5] == iface and int(fields[3], 16) == 0x20:
                return socket.inet_ntop(socket.AF_INET6, bytes.fromhex(fields[0]))
    return None


# ---------------------------------------------------------------------------
# packets
# ---------------------------------------------------------------------------

def build_rs(src_mac):
    """ICMPv6 Router Solicitation with a source link-layer address option (checksum left to
    the kernel)."""
    return struct.pack('!BBHI', ND_ROUTER_SOLICIT, 0, 0, 0) + bytes([1, 1]) + bytes(src_mac)


def _dns_names(raw):
    """Names of a DNS wire-format list (RDNSS/DNSSL options, DHCPv6 domain search list)."""
    names, i, labels = [], 0, []
    while i < len(raw):
        length = raw[i]
        i += 1
        if length == 0:
            if labels:
                names.append('.'.join(labels))
                labels = []
            continue
        if i + length > len(raw):
            break
        labels.append(raw[i:i + length].decode(errors='replace'))
        i += length
    if labels:
        names.append('.'.join(labels))
    return names


def _ip6_list(raw):
    return [socket.inet_ntop(socket.AF_INET6, raw[i:i + 16]) for i in range(0, len(raw) - len(raw) % 16, 16)]


def parse_ra(data, src=None):
    """Decode an ICMPv6 message; return a dict for a Router Advertisement, None otherwise."""
    try:
        if len(data) < 16 or data[0] != ND_ROUTER_ADVERT:
            return None
        hop_limit, flags, lifetime, reachable, retrans = struct.unpack('!BBHII', data[4:16])
        ra = {'src': src, 'hop_limit': hop_limit, 'managed': bool(flags & 0x80), 'other': bool(flags & 0x40),
              'router_lifetime': lifetime, 'reachable_time': reachable, 'retrans_timer': retrans,
              'prefixes': [], 'mtu': None, 'rdnss': [], 'rdnss_lifetime': None, 'dnssl': [],
              'dnssl_lifetime': None, 'source_mac': None, 'options': []}
        i = 16
        while i + 2 <= len(data):
            kind, units = data[i], data[i + 1]
            if units == 0:
                break
            opt = data[i:i + 8 * units]
            if len(opt) < 8 * units:
                break
            i += 8 * units
            ra['options'].append(kind)
            if kind == 1 and units == 1:
                ra['source_mac'] = _bytes_to_hex(opt[2:8])
            elif kind == 3 and units == 4:
                prefix_len, pflags = opt[2], opt[3]
                valid, preferred = struct.unpack('!II', opt[4:12])
                ra['prefixes'].append({'prefix': f"{socket.inet_ntop(socket.AF_INET6, opt[16:32])}/{prefix_len}",
                                       'on_link': bool(pflags & 0x80), 'autonomous': bool(pflags & 0x40),
                                       'valid': valid, 'preferred': preferred})
            elif kind == 5 and units == 1:
                ra['mtu'] = struct.unpack('!I', opt[4:8])[0]
            elif kind == 25 and units >= 3:
                ra['rdnss_lifetime'] = struct.unpack('!I', opt[4:8])[0]
                ra['rdnss'] += _ip6_list(opt[8:])
            elif kind == 31 and units >= 2:
                ra['dnssl_lifetime'] = struct.unpack('!I', opt[4:8])[0]
                ra['dnssl'] += _dns_names(opt[8:])
        return ra
    except (struct.error, IndexError, OSError, ValueError):
        return None


def _option(code, value):
    return struct.pack('!HH', code, len(value)) + value


def build_dhcp6(msg_type, xid, duid, ia_na=True, iaid=1):
    """A DHCPv6 SOLICIT (1) or INFORMATION-REQUEST (11): client identifier *duid* (bytes),
    elapsed time 0, option request (DNS servers, domain list) and, for a SOLICIT, one IA_NA."""
    message = bytes([msg_type]) + int(xid).to_bytes(3, 'big')
    options = _option(1, bytes(duid)) + _option(8, b'\x00\x00')
    options += _option(6, b''.join(struct.pack('!H', code) for code in DHCP6_ORO))
    if ia_na:
        options += _option(3, struct.pack('!III', int(iaid), 0, 0))
    return message + options


def _iter_options(raw):
    i = 0
    while i + 4 <= len(raw):
        code, length = struct.unpack('!HH', raw[i:i + 4])
        value = raw[i + 4:i + 4 + length]
        if len(value) < length:
            break
        yield code, value
        i += 4 + length


def parse_dhcp6(data, src=None):
    """Decode a DHCPv6 message (ADVERTISE / REPLY expected); None for anything malformed."""
    try:
        if len(data) < 4:
            return None
        msg_type = data[0]
        reply = {'msg_type': MSG_TYPES.get(msg_type, str(msg_type)), 'xid': int.from_bytes(data[1:4], 'big'),
                 'src': src, 'server_duid': None, 'client_duid': None, 'ia_na': [], 'addresses': [],
                 'status_code': None, 'status_message': None, 'dns_servers': [], 'domain_search': [],
                 'preference': None, 'rapid_commit': False, 'options': []}
        for code, value in _iter_options(data[4:]):
            reply['options'].append(code)
            if code == 1:
                reply['client_duid'] = _bytes_to_hex(value)
            elif code == 2:
                reply['server_duid'] = _bytes_to_hex(value)
            elif code == 3 and len(value) >= 12:
                iaid, t1, t2 = struct.unpack('!III', value[:12])
                ia = {'iaid': iaid, 't1': t1, 't2': t2, 'addresses': [], 'status_code': None, 'status_message': None}
                for sub_code, sub in _iter_options(value[12:]):
                    if sub_code == 5 and len(sub) >= 24:
                        preferred, valid = struct.unpack('!II', sub[16:24])
                        address = {'address': socket.inet_ntop(socket.AF_INET6, sub[:16]),
                                   'preferred': preferred, 'valid': valid}
                        ia['addresses'].append(address)
                        reply['addresses'].append(address)
                    elif sub_code == 13 and len(sub) >= 2:
                        ia['status_code'] = struct.unpack('!H', sub[:2])[0]
                        ia['status_message'] = sub[2:].decode(errors='replace')
                reply['ia_na'].append(ia)
            elif code == 7 and value:
                reply['preference'] = value[0]
            elif code == 13 and len(value) >= 2:
                reply['status_code'] = struct.unpack('!H', value[:2])[0]
                reply['status_message'] = value[2:].decode(errors='replace')
            elif code == 14:
                reply['rapid_commit'] = True
            elif code == 23:
                reply['dns_servers'] += _ip6_list(value)
            elif code == 24:
                reply['domain_search'] += _dns_names(value)
        return reply
    except (struct.error, IndexError, OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# exchanges
# ---------------------------------------------------------------------------

def _plain(address):
    return address.split('%')[0] if isinstance(address, str) else address


def _router_solicit(iface, link_local, wait, result, errors):
    """Send one Router Solicitation and collect the Router Advertisements of *wait* seconds."""
    try:
        ifindex = socket.if_nametoindex(iface)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except OSError as e:
        errors.append(f"rs {iface}: {e}")
        return
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
        if link_local:
            sock.bind((link_local, 0, 0, ifindex))
        sock.sendto(build_rs(interface_mac(iface)), (ALL_ROUTERS, 0, 0, ifindex))
        start = time.monotonic()
        while True:
            remaining = wait - (time.monotonic() - start)
            if remaining <= 0:
                return
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                return
            ra = parse_ra(data, _plain(addr[0]))
            if ra is not None:
                ra['delay'] = round(time.monotonic() - start, 3)
                result.append(ra)
    except (OSError, ValueError) as e:
        errors.append(f"rs {iface}: {type(e).__name__}: {e}")
    finally:
        sock.close()


def _dhcp6_exchange(iface, link_local, queries, wait, result, errors):
    """Send the DHCPv6 queries and collect their replies during *wait* seconds."""
    for q in queries:
        result[str(q.get('id'))] = []
    if not queries:
        return
    try:
        ifindex = socket.if_nametoindex(iface)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError as e:
        errors.append(f"dhcp6 {iface}: {e}")
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        sock.bind((link_local or '::', DHCP6_CLIENT_PORT, 0, ifindex))
        base = struct.unpack('!I', os.urandom(4))[0] & 0xffff00
        by_xid = {}
        for n, q in enumerate(queries):
            xid = (base + n) & 0xffffff
            by_xid[xid] = str(q.get('id'))
            msg_type = QUERY_TYPES[q.get('type', 'solicit')]
            duid = _hex_to_bytes(q['duid'])
            packet = build_dhcp6(msg_type, xid, duid, ia_na=(msg_type == 1), iaid=q.get('iaid', 1))
            sock.sendto(packet, (ALL_DHCP_AGENTS, DHCP6_SERVER_PORT, 0, ifindex))
        start = time.monotonic()
        while True:
            remaining = wait - (time.monotonic() - start)
            if remaining <= 0:
                return
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                return
            reply = parse_dhcp6(data, _plain(addr[0]))
            if reply is None or reply['xid'] not in by_xid:
                continue
            reply['delay'] = round(time.monotonic() - start, 3)
            result[by_xid[reply.pop('xid')]].append(reply)
    except (OSError, KeyError, ValueError) as e:
        errors.append(f"dhcp6 {iface}: {type(e).__name__}: {e}")
    finally:
        sock.close()


def main(argv):
    errors, ras, replies, link_local = [], [], {}, None
    try:
        spec = json.loads(base64.urlsafe_b64decode(argv[1]))
        iface = spec.get('interface', 'eth0')
        wait = float(spec.get('wait', DEFAULT_WAIT))
        try:
            link_local = interface_link_local(iface)
        except OSError as e:
            errors.append(f"{iface}: {e}")
        threads = []
        if spec.get('rs', True):
            threads.append(threading.Thread(target=_router_solicit, args=(iface, link_local, wait, ras, errors),
                                            daemon=True))
        threads.append(threading.Thread(target=_dhcp6_exchange,
                                        args=(iface, link_local, spec.get('queries', []), wait, replies, errors),
                                        daemon=True))
        for t in threads:
            t.start()
        for t in threads:
            t.join(wait + 5)
    except Exception as e:  # the grader needs a JSON document whatever happens
        errors.append(f"{type(e).__name__}: {e}")
    print(json.dumps({'errors': errors, 'link_local': link_local, 'ra': ras, 'dhcp6': replies}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
