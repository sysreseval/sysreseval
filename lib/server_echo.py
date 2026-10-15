#!/usr/bin/env python3
"""HTTP and UDP echo server of the SRE labs, copied into a container by
``server_echo_helpers.install_echo_server()`` (standard library only, Python 3.11 of the images)::

    python3 sre_server_echo.py NAME PORT [PORT...] [udp:PORT...]

The process daemonises itself (double fork, stdio detached, pid in ``/run/sre_server_echo.pid``,
log in ``/var/log/sre_server_echo.log``) and serves every PORT: HTTP on the bare numbers, a UDP
service answering every datagram on the ``udp:N`` ones.  A ``GET`` of any path, or any
datagram, is answered by the same ``text/plain`` body, the one of ``firewall.setup_http_server``
plus the TTL::

    SERVER=NAME
    SERVER_IP=<local address the connection or the datagram landed on>
    SERVER_PORT=<local port>
    CLIENT_IP=<peer address as the server sees it: the NAT'ed one behind a masquerade>
    CLIENT_PORT=<peer port>
    TTL=<IPv4 TTL of the SYN that opened the connection, or of the datagram, or ?>

Over TCP the TTL comes from a sniffer thread: an ``AF_PACKET`` socket on every interface
records the TTL of each incoming TCP SYN addressed to one of the served ports, by ``(source
address, source port)``, and the handler looks the connection up.  802.1Q tags are skipped, so
a server bound to a VLAN sub-interface works too.  Over UDP the kernel hands the destination
address (``IP_PKTINFO``) and the TTL (``IP_RECVTTL``) of each datagram as control messages of
``recvmsg``, and the reply is sent from the address the client targeted (``IP_PKTINFO`` on
``sendmsg``), whatever the addresses of the machine.  With a masquerading router on the path
the TTL is the one of the packet as it arrives: one less per router crossed (a bridge does not
decrement it).
"""
import collections
import os
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PID_FILE = '/run/sre_server_echo.pid'
LOG_FILE = '/var/log/sre_server_echo.log'
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
PACKET_OUTGOING = 4
TCP_SYN = 0x02
TCP_ACK = 0x10
MAX_FLOWS = 4096
UDP_PREFIX = 'udp:'
# Linux values (the script only runs in the containers; Python 3.11 does not define them all):
# IP_PKTINFO asks for the destination address of each datagram, IP_RECVTTL for its TTL, given
# as control messages of types IP_PKTINFO and IP_TTL.
IP_PKTINFO = getattr(socket, 'IP_PKTINFO', 8)
IP_RECVTTL = getattr(socket, 'IP_RECVTTL', 12)
IP_TTL = getattr(socket, 'IP_TTL', 2)
ANCILLARY_SIZE = 256

#: {(client ip, client port): ttl} of the SYNs seen by the sniffer
ttls = collections.OrderedDict()
_lock = threading.Lock()


def split_ports(args):
    """``(tcp_ports, udp_ports)`` of the PORT arguments: a bare number is an HTTP port, ``udp:N``
    a UDP one (``ValueError`` on anything else)."""
    tcp_ports, udp_ports = [], []
    for arg in args:
        if arg.startswith(UDP_PREFIX):
            udp_ports.append(int(arg[len(UDP_PREFIX):]))
        else:
            tcp_ports.append(int(arg))
    return tcp_ports, udp_ports


def echo_body(name, server, client, ttl=None):
    """The answer (bytes): *server* and *client* are ``(address, port)`` pairs, *ttl* an int or
    ``None`` (printed ``?``)."""
    return (f"SERVER={name}\nSERVER_IP={server[0]}\nSERVER_PORT={server[1]}\n"
            f"CLIENT_IP={client[0]}\nCLIENT_PORT={client[1]}\nTTL={'?' if ttl is None else ttl}\n").encode()


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
            cli = self.client_address
            with _lock:
                ttl = ttls.get((cli[0], cli[1]))
            body = echo_body(name, self.connection.getsockname(), cli, ttl)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_HEAD = do_GET

    return Handler


def parse_ancillary(ancdata):
    """``(destination address, ttl)`` of a datagram from the control messages of ``recvmsg``:
    ``IP_PKTINFO`` holds a ``struct in_pktinfo`` (interface index, local address, destination
    address), ``IP_TTL`` an int; ``None`` for what is missing."""
    dst, ttl = None, None
    for level, kind, data in ancdata:
        if level != socket.IPPROTO_IP:
            continue
        if kind == IP_PKTINFO and len(data) >= 12:
            dst = socket.inet_ntoa(data[8:12])
        elif kind == IP_TTL and len(data) >= 4:
            ttl = struct.unpack('=i', data[:4])[0]
    return dst, ttl


def pktinfo(source):
    """The ``IP_PKTINFO`` control message making a datagram leave from the address *source*."""
    return (socket.IPPROTO_IP, IP_PKTINFO, struct.pack('=I4s4s', 0, socket.inet_aton(source), b'\0\0\0\0'))


def udp_socket(port):
    """A UDP socket bound to *port* on every address, asking for the destination address and
    the TTL of each datagram."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
    sock.bind(('0.0.0.0', port))
    return sock


def serve_udp(name, sock):
    """Answer every datagram received on *sock* with the page (runs in a daemon thread), from
    the address the datagram was sent to."""
    port = sock.getsockname()[1]
    while True:
        try:
            _data, ancdata, _flags, client = sock.recvmsg(4096, ANCILLARY_SIZE)
        except OSError:
            continue
        dst, ttl = parse_ancillary(ancdata)
        body = echo_body(name, (dst or sock.getsockname()[0], port), client, ttl)
        try:
            if dst is None:
                sock.sendto(body, client)
            else:
                sock.sendmsg([body], [pktinfo(dst)], 0, client)
        except OSError:
            try:
                sock.sendto(body, client)
            except OSError:
                pass


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
    usage = f"usage: {argv[0]} NAME PORT [PORT...] [udp:PORT...]\n"
    if len(argv) < 3:
        sys.stderr.write(usage)
        return 2
    name = argv[1]
    try:
        tcp_ports, udp_ports = split_ports(argv[2:])
    except ValueError:
        sys.stderr.write(usage)
        return 2
    # the sockets are opened before the fork: a port already in use fails the command
    servers = [ThreadingHTTPServer(('0.0.0.0', port), make_handler(name)) for port in tcp_ports]
    sockets = [udp_socket(port) for port in udp_ports]
    daemonize()
    if tcp_ports:
        threading.Thread(target=sniff, args=(set(tcp_ports),), daemon=True).start()
    for sock in sockets:
        threading.Thread(target=serve_udp, args=(name, sock), daemon=True).start()
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    if servers:
        servers[0].serve_forever()
    else:
        threading.Event().wait()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
