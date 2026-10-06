#!/usr/bin/env python3
# dhcp_probe
# -------------------------------------------------
# Stand-alone DHCP client probe run inside a lab container by the grader (see
# install_dhcp_probe() / dhcp_probe() in lib/dhcp.py).  Standard library only.
#
# usage: dhcp_probe.py <urlsafe-base64 of a JSON spec>
#
# spec = {"wait": 2.5, "late_wait": 1.5,
#         "interfaces": {"eth0": [query, ...], ...}}
# query = {"id": "dyn", "type": "discover" | "request", "chaddr": "02:53:52:00:00:01",
#          "lease": 4000000, "requested": "192.0.2.77", "secs": 10, "hostname": "sonde",
#          "late": false}
#
# Every query is broadcast from the interface's own MAC address with the BOOTP broadcast
# flag set, so that the replies are broadcast too and can be read without owning `chaddr`.
# Queries with "late": true are sent `wait` seconds after the others (a server drops a
# second DISCOVER of the same client while it is still ping-checking the first one).
# A DHCPREQUEST is only sent in INIT-REBOOT form ("requested", no server identifier): no
# offered address is ever requested, so no lease is committed on the servers.
#
# Always prints one JSON document on stdout and exits 0:
# {"errors": [...], "replies": {"eth0": {"dyn": [reply, ...], ...}, ...}}
import base64
import json
import os
import socket
import struct
import sys
import threading
import time

ETH_P_IP = 0x0800
BOOTP_MAGIC = b'\x63\x82\x53\x63'
BOOTP_MIN_LEN = 300
FLAG_BROADCAST = 0x8000
DEFAULT_SECS = 120
DEFAULT_WAIT = 2.5
DEFAULT_LATE_WAIT = 1.5
# subnet mask, routers, DNS, domain name, broadcast, lease time, server id, T1, T2,
# classless static routes
PARAMETER_REQUEST_LIST = bytes([1, 3, 6, 15, 28, 51, 54, 58, 59, 121])

MSG_TYPES = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}
QUERY_TYPES = {'discover': 1, 'request': 3}


def _mac_bytes(mac):
    return bytes(int(x, 16) for x in mac.replace('-', ':').split(':'))


def _mac_str(raw):
    return ':'.join(f'{b:02x}' for b in raw)


def _checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def build_request(src_mac, chaddr, xid, msg_type='discover', lease=None, requested=None,
                  secs=DEFAULT_SECS, hostname=None):
    """Return the Ethernet frame of a broadcast DHCPDISCOVER / DHCPREQUEST.

    src_mac is the Ethernet source, chaddr the client hardware address of the BOOTP header
    (they may differ: servers identify the client by chaddr).
    """
    options = bytes([53, 1, QUERY_TYPES[msg_type]])
    if hostname:
        name = hostname.encode()[:63]
        options += bytes([12, len(name)]) + name
    if requested:
        options += bytes([50, 4]) + socket.inet_aton(requested)
    if lease is not None:
        options += bytes([51, 4]) + struct.pack('!I', int(lease))
    options += bytes([55, len(PARAMETER_REQUEST_LIST)]) + PARAMETER_REQUEST_LIST
    options += b'\xff'

    bootp = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
                        1, 1, 6, 0, xid, secs, FLAG_BROADCAST,
                        b'\x00' * 4, b'\x00' * 4, b'\x00' * 4, b'\x00' * 4,
                        _mac_bytes(chaddr), b'', b'')
    bootp += BOOTP_MAGIC + options
    bootp += b'\x00' * max(0, BOOTP_MIN_LEN - len(bootp))

    src_ip, dst_ip = b'\x00' * 4, b'\xff' * 4
    udp_len = 8 + len(bootp)
    pseudo = src_ip + dst_ip + struct.pack('!BBH', 0, socket.IPPROTO_UDP, udp_len)
    udp = struct.pack('!HHHH', 68, 67, udp_len, 0)
    udp_sum = _checksum(pseudo + udp + bootp) or 0xffff
    udp = struct.pack('!HHHH', 68, 67, udp_len, udp_sum)

    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0x10, 20 + udp_len, 0, 0, 64, socket.IPPROTO_UDP, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]

    return b'\xff' * 6 + _mac_bytes(src_mac) + struct.pack('!H', ETH_P_IP) + ip + udp + bootp


def _ip_list(raw):
    return [socket.inet_ntoa(raw[i:i + 4]) for i in range(0, len(raw) - len(raw) % 4, 4)]


def _classless_routes(raw):
    """Decode option 121 (RFC 3442): [["a.b.c.d/len", "gateway"], ...].  Each route is the prefix
    length, the significant bytes of the destination, then the 4 bytes of the router; decoding
    stops at the first malformed route."""
    routes, i = [], 0
    while i < len(raw):
        length = raw[i]
        size = (length + 7) // 8
        if length > 32 or i + 1 + size + 4 > len(raw):
            break
        destination = raw[i + 1:i + 1 + size] + b'\x00' * (4 - size)
        gateway = raw[i + 1 + size:i + 5 + size]
        routes.append([f"{socket.inet_ntoa(destination)}/{length}", socket.inet_ntoa(gateway)])
        i += 5 + size
    return routes


def parse_reply(frame):
    """Decode an Ethernet frame holding a BOOTREPLY; return a dict, or None for anything else."""
    try:
        if len(frame) < 14 + 20 + 8 + 240 or struct.unpack('!H', frame[12:14])[0] != ETH_P_IP:
            return None
        ihl = (frame[14] & 0x0f) * 4
        if frame[14] >> 4 != 4 or frame[14 + 9] != socket.IPPROTO_UDP:
            return None
        udp = 14 + ihl
        sport, dport = struct.unpack('!HH', frame[udp:udp + 4])
        if sport != 67 or dport not in (67, 68):
            return None
        bootp = frame[udp + 8:]
        if len(bootp) < 240 or bootp[0] != 2 or bootp[236:240] != BOOTP_MAGIC:
            return None
        xid, secs, flags = struct.unpack('!IHH', bootp[4:12])
        reply = {
            'xid': xid,
            'flags': flags,
            'hops': bootp[3],
            'src_mac': _mac_str(frame[6:12]),
            'dst_mac': _mac_str(frame[0:6]),
            'src_ip': socket.inet_ntoa(frame[14 + 12:14 + 16]),
            'dst_ip': socket.inet_ntoa(frame[14 + 16:14 + 20]),
            'ciaddr': socket.inet_ntoa(bootp[12:16]),
            'yiaddr': socket.inet_ntoa(bootp[16:20]),
            'siaddr': socket.inet_ntoa(bootp[20:24]),
            'giaddr': socket.inet_ntoa(bootp[24:28]),
            'chaddr': _mac_str(bootp[28:34]),
            'msg_type': None, 'server_id': None, 'subnet_mask': None, 'routers': [], 'dns_servers': [],
            'domain_name': None, 'broadcast': None, 'lease_time': None, 'renewal_time': None,
            'rebinding_time': None, 'message': None, 'classless_routes': [], 'options': [],
        }
        opts = bootp[240:]
        i = 0
        while i < len(opts):
            code = opts[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if i + 1 >= len(opts):
                break
            length = opts[i + 1]
            value = opts[i + 2:i + 2 + length]
            i += 2 + length
            reply['options'].append(code)
            if code == 53 and length == 1:
                reply['msg_type'] = MSG_TYPES.get(value[0], str(value[0]))
            elif code == 54 and length == 4:
                reply['server_id'] = socket.inet_ntoa(value)
            elif code == 1 and length == 4:
                reply['subnet_mask'] = socket.inet_ntoa(value)
            elif code == 3:
                reply['routers'] = _ip_list(value)
            elif code == 6:
                reply['dns_servers'] = _ip_list(value)
            elif code == 15:
                reply['domain_name'] = value.rstrip(b'\x00').decode(errors='replace')
            elif code == 28 and length == 4:
                reply['broadcast'] = socket.inet_ntoa(value)
            elif code == 51 and length == 4:
                reply['lease_time'] = struct.unpack('!I', value)[0]
            elif code == 58 and length == 4:
                reply['renewal_time'] = struct.unpack('!I', value)[0]
            elif code == 59 and length == 4:
                reply['rebinding_time'] = struct.unpack('!I', value)[0]
            elif code == 56:
                reply['message'] = value.rstrip(b'\x00').decode(errors='replace')
            elif code == 121:
                reply['classless_routes'] = _classless_routes(value)
        return reply
    except (struct.error, IndexError, OSError):
        return None


def _probe_interface(iface, queries, wait, late_wait, replies, errors):
    """Send the queries of one interface and collect the replies into replies[iface]."""
    result = {str(q.get('id')): [] for q in queries}
    replies[iface] = result
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        sock.bind((iface, ETH_P_IP))
    except OSError as e:
        errors.append(f"{iface}: {e}")
        return
    try:
        src_mac = _mac_str(sock.getsockname()[4][:6])
        base = struct.unpack('!I', os.urandom(4))[0] & 0xffffff00
        by_xid = {}
        frames = {False: [], True: []}
        for n, q in enumerate(queries):
            xid = (base + n) & 0xffffffff
            by_xid[xid] = str(q.get('id'))
            frames[bool(q.get('late'))].append(build_request(
                src_mac, q['chaddr'], xid, msg_type=q.get('type', 'discover'), lease=q.get('lease'),
                requested=q.get('requested'), secs=q.get('secs', DEFAULT_SECS), hostname=q.get('hostname')))

        def exchange(to_send, duration):
            start = time.monotonic()
            for frame in to_send:
                sock.send(frame)
            while True:
                remaining = duration - (time.monotonic() - start)
                if remaining <= 0:
                    return
                sock.settimeout(remaining)
                try:
                    frame = sock.recv(65535)
                except socket.timeout:
                    return
                reply = parse_reply(frame)
                if reply is None or reply['xid'] not in by_xid:
                    continue
                reply['delay'] = round(time.monotonic() - start, 3)
                result[by_xid[reply.pop('xid')]].append(reply)

        exchange(frames[False], wait)
        if frames[True]:
            exchange(frames[True], late_wait)
    except (OSError, KeyError, ValueError) as e:
        errors.append(f"{iface}: {type(e).__name__}: {e}")
    finally:
        sock.close()


def main(argv):
    errors, replies = [], {}
    try:
        spec = json.loads(base64.urlsafe_b64decode(argv[1]))
        wait = float(spec.get('wait', DEFAULT_WAIT))
        late_wait = float(spec.get('late_wait', DEFAULT_LATE_WAIT))
        threads = [threading.Thread(target=_probe_interface, args=(iface, queries, wait, late_wait, replies, errors),
                                    daemon=True)
                   for iface, queries in spec.get('interfaces', {}).items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join(wait + late_wait + 5)
    except Exception as e:  # the grader needs a JSON document whatever happens
        errors.append(f"{type(e).__name__}: {e}")
    print(json.dumps({'errors': errors, 'replies': replies}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
