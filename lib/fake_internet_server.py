#!/usr/bin/env python3
"""Catch-all HTTP server of the fake Internet of the SRE labs, copied into a container by
``fake_internet.setup_fake_internet()`` (standard library only, Python 3.11 of the images)::

    python3 sre_fake_internet.py NAME PORT [PORT...]

The machine stands for the Internet: the lab's gateway sends it every packet bound for an
address outside the lab, and an ``nft`` rule (``tcp dport { 80, 8080 } redirect``) translates
every TCP connection to a served port, whatever its destination, into a connection to this
server.  Every request, whatever its method and path, is answered by a small HTML page::

    You tried to reach http://<Host header, or the address the client targeted>[:port]<path>

followed by the original destination of the connection (the address the client targeted, read
with the ``SO_ORIGINAL_DST`` socket option of the NAT'ed connection; the local address when the
connection was not translated), the client address and the name of the machine.  The process
daemonises itself (double fork, stdio detached, pid in ``/run/sre_fake_internet.pid``, one
line per request in ``/var/log/sre_fake_internet.log``).
"""
import html
import os
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PID_FILE = '/run/sre_fake_internet.pid'
LOG_FILE = '/var/log/sre_fake_internet.log'
# linux/netfilter_ipv4.h: the destination of a connection before the NAT, a struct sockaddr_in
SO_ORIGINAL_DST = 80
SOL_IP = getattr(socket, 'SOL_IP', 0)
MARKER = 'You tried to reach'


def parse_original_dst(data):
    """``(address, port)`` of a ``struct sockaddr_in`` (``sin_family`` in host byte order,
    ``sin_port`` and ``sin_addr`` in network byte order), ``None`` unless it is an AF_INET one."""
    if len(data) < 8:
        return None
    family = struct.unpack('=H', data[:2])[0]
    if family != socket.AF_INET:
        return None
    port = struct.unpack('!H', data[2:4])[0]
    return socket.inet_ntoa(data[4:8]), port


def original_destination(conn):
    """The address the client targeted: the original destination of a NAT'ed connection, the
    local address of the socket otherwise."""
    try:
        parsed = parse_original_dst(conn.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16))
    except OSError:
        parsed = None
    if parsed is None:
        local = conn.getsockname()
        parsed = (local[0], local[1])
    return parsed


def requested_url(host_header, original, path):
    """The URL the client asked for: the ``Host`` header when it sent one (what the user typed,
    port included when it is not 80), else the original destination."""
    host = (host_header or '').strip()
    if not host:
        address, port = original
        host = address if port == 80 else f"{address}:{port}"
    return f"http://{host}{path or '/'}"


def page(name, url, original, client):
    """The HTML page (bytes) answering a request for *url*."""
    url_text = html.escape(url)
    return (
        "<!DOCTYPE html>\n"
        '<html><head><meta charset="utf-8">'
        f"<title>{MARKER} {url_text}</title></head>\n"
        f"<body>\n<h1>{MARKER} {url_text}</h1>\n"
        f"<p>This page is served by <b>{html.escape(name)}</b>, the machine standing for the"
        " Internet in this lab: it answers every HTTP request sent to an address outside the lab.</p>\n"
        "<ul>\n"
        f"<li>original destination: {original[0]}:{original[1]}</li>\n"
        f"<li>client: {client[0]}:{client[1]}</li>\n"
        "</ul>\n</body></html>\n"
    ).encode()


def make_handler(name):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def log_message(self, *args):
            pass

        def answer(self):
            original = original_destination(self.connection)
            client = self.client_address
            url = requested_url(self.headers.get('Host'), original, self.path)
            length = self.headers.get('Content-Length')
            if length and length.isdigit():
                self.rfile.read(int(length))
            body = page(name, url, original, client)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            sys.stdout.write(f"{client[0]}:{client[1]} -> {original[0]}:{original[1]} {self.command} {url}\n")
            sys.stdout.flush()

        do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = answer

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
    usage = f"usage: {argv[0]} NAME PORT [PORT...]\n"
    if len(argv) < 3:
        sys.stderr.write(usage)
        return 2
    name = argv[1]
    try:
        ports = [int(p) for p in argv[2:]]
    except ValueError:
        sys.stderr.write(usage)
        return 2
    # the sockets are opened before the fork: a port already in use fails the command
    servers = [ThreadingHTTPServer(('0.0.0.0', port), make_handler(name)) for port in ports]
    daemonize()
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
