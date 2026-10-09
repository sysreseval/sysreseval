#!/usr/bin/env python3
"""HTTP echo server of the SRE labs, copied into a container by ``vlan.install_http_echo()``
(standard library only, Python 3.11 of the images)::

    python3 sre_http_echo.py NAME PORT [PORT...]

The process daemonises itself (double fork, stdio detached, pid in ``/run/sre_http_echo.pid``,
log in ``/var/log/sre_http_echo.log``) and serves every PORT.  A ``GET`` of any path returns a
``text/plain`` body, the one of ``firewall.setup_http_server`` plus the TTL::

    SERVER=NAME
    SERVER_IP=<local address the connection landed on>
    SERVER_PORT=<local port>
    CLIENT_IP=<peer address as the server sees it: the NAT'ed one behind a masquerade>
    CLIENT_PORT=<peer port>
    TTL=<IPv4 TTL of the SYN that opened the connection, or ?>

The TTL comes from a sniffer thread: an ``AF_PACKET`` socket on every interface records the TTL
of each incoming TCP SYN addressed to one of the served ports, by ``(source address, source
port)``, and the handler looks the connection up.  802.1Q tags are skipped, so a server bound
to a VLAN sub-interface works too.  With a masquerading router on the path the TTL is the one of
the packet as it arrives: one less per router crossed (a bridge does not decrement it).
"""
import collections
import os
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PID_FILE = '/run/sre_http_echo.pid'
LOG_FILE = '/var/log/sre_http_echo.log'
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
PACKET_OUTGOING = 4
TCP_SYN = 0x02
TCP_ACK = 0x10
MAX_FLOWS = 4096

#: {(client ip, client port): ttl} of the SYNs seen by the sniffer
ttls = collections.OrderedDict()
_lock = threading.Lock()


def parse_syn(frame, ports=None):
    """``(src_ip, sport, dport, ttl)`` of an Ethernet frame holding an IPv4 TCP SYN (without
    ACK), ``None`` for anything else.  802.1Q / 802.1ad tags are skipped; with *ports* given,
    SYNs to other destination ports are ignored."""
    try:
        offset = 12
        ethertype = struct.unpack('!H', frame[offset:offset + 2])[0]
        while ethertype in (ETH_P_8021Q, ETH_P_8021AD):
            offset += 4
            ethertype = struct.unpack('!H', frame[offset:offset + 2])[0]
        if ethertype != ETH_P_IP:
            return None
        ip = offset + 2
        version_ihl = frame[ip]
        if version_ihl >> 4 != 4:
            return None
        ihl = (version_ihl & 0x0f) * 4
        if ihl < 20 or frame[ip + 9] != socket.IPPROTO_TCP:
            return None
        if struct.unpack('!H', frame[ip + 6:ip + 8])[0] & 0x1fff:
            return None   # not the first fragment
        ttl = frame[ip + 8]
        src = socket.inet_ntoa(frame[ip + 12:ip + 16])
        tcp = ip + ihl
        sport, dport = struct.unpack('!HH', frame[tcp:tcp + 4])
        flags = frame[tcp + 13]
        if not (flags & TCP_SYN) or flags & TCP_ACK:
            return None
        if ports is not None and dport not in ports:
            return None
        return src, sport, dport, ttl
    except (struct.error, IndexError):
        return None


def sniff(ports):
    """Record the TTL of every incoming TCP SYN to *ports* (runs in a daemon thread)."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    while True:
        try:
            frame, address = sock.recvfrom(2048)
        except OSError:
            continue
        if len(address) > 2 and address[2] == PACKET_OUTGOING:
            continue
        syn = parse_syn(frame, ports)
        if syn is None:
            continue
        src, sport, _dport, ttl = syn
        with _lock:
            ttls[(src, sport)] = ttl
            while len(ttls) > MAX_FLOWS:
                ttls.popitem(last=False)


def make_handler(name):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def log_message(self, *args):
            pass

        def do_GET(self):
            srv = self.connection.getsockname()
            cli = self.client_address
            with _lock:
                ttl = ttls.get((cli[0], cli[1]))
            body = (f"SERVER={name}\nSERVER_IP={srv[0]}\nSERVER_PORT={srv[1]}\n"
                    f"CLIENT_IP={cli[0]}\nCLIENT_PORT={cli[1]}\nTTL={'?' if ttl is None else ttl}\n").encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_HEAD = do_GET

    return Handler


def daemonize():
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
    log = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log, 1)
    os.dup2(log, 2)
    with open(PID_FILE, 'w') as pid_file:
        pid_file.write(str(os.getpid()))


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(f"usage: {argv[0]} NAME PORT [PORT...]\n")
        return 2
    name, ports = argv[1], [int(p) for p in argv[2:]]
    servers = [ThreadingHTTPServer(('0.0.0.0', port), make_handler(name)) for port in ports]
    daemonize()
    threading.Thread(target=sniff, args=(set(ports),), daemon=True).start()
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
