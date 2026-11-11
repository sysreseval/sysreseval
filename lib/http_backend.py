#!/usr/bin/env python3
"""Backend web application of the HTTP proxy labs, copied into a container by
``http_proxy.install_backend()`` (standard library only, Python 3.11 of the images)::

    python3 sre_http_backend.py CONFIG.json

The process daemonises itself (double fork, pid in ``/run/sre_http_backend.pid``) and serves one
HTTP/1.1 port per application of the configuration (keep-alive supported), e.g. the shop on 8080
and its API on 8081.  It stands for the application servers a reverse proxy or a load balancer
is put in front of: what a proxy does to a request is read in the answer.  Configuration (JSON)::

    {"name": "web1", "apps": {"8080": "shop", "8081": "api"}, "version": "4.2.7",
     "vhosts": {"intranet.shop.tp": "a secret word"}, "old_slug": "summer-sale",
     "form_code": "1234", "form_token": "abcd", "catalog_delay_ms": 200,
     "state_dir": "/var/lib/sre_http_backend", "log_file": "/var/log/sre_http_backend/access.log"}

Every path that is not listed below answers a ``text/plain`` *whoami*: one ``KEY=value`` per
line, the first ones being those of ``lib/server_echo.py``::

    SERVER=<name>              APP=<application of the port>
    SERVER_IP= SERVER_PORT=    where the connection landed
    CLIENT_IP= CLIENT_PORT=    the peer as the server sees it: the proxy, behind a proxy
    METHOD= PATH= HTTP_VERSION=  the request line as received (PATH with its query string)
    CONN_REQUESTS=<n>          requests received on this TCP connection (keep-alive reuse)
    REQUEST_ID=<name>-<n>      a counter: the same id twice means the answer came from a cache
    HOST=<Host header>
    HEADER_<NAME>=<value>      every request header (``X-Forwarded-For`` -> ``HEADER_X_FORWARDED_FOR``)

Special paths:

``/health``                 ``200 OK`` or ``503 SICK`` (the pages still answer when sick)
``/catalog/<item>``         a page worth caching, slow to build, sent with a tracking ``Set-Cookie``
``/cart``                   a private page: ``CART=`` is the ``cart`` cookie of the request
``/login?user=NAME``        opens a session **in the memory of this backend** (``Set-Cookie: SESSIONID``)
``/account``                ``200`` with ``USER=`` for a session this backend knows, ``401`` otherwise
``/slow?ms=N``              answers after N milliseconds
``/big``                    20 kB of text (compression)
``/admin/...``              the whoami plus ``AREA=admin``
``/status/<code>``          answers with that status
``/old-page``               ``301`` to ``/catalog/<old_slug>``
``/form``                   ``POST code=<form_code>`` -> ``TOKEN=<form_token>``; ``405`` for a ``GET``
``/_log?n=20``              the last lines of the access log
``/_admin/health?state=up|down``   make ``/health`` answer 200 / 503 (kept across a restart)
``/_admin/down?seconds=N``  reset every new connection for N seconds (a crashed application)

A request whose ``Host`` is one of ``vhosts`` gets the page of that virtual host (``VHOST=``,
``SECRET=``).  ``OPTIONS`` answers 200 on every path, other methods 405.
"""
import json
import os
import secrets
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PID_FILE = '/run/sre_http_backend.pid'
SERVER_LOG = '/var/log/sre_http_backend/server.log'
DEFAULT_STATE_DIR = '/var/lib/sre_http_backend'
DEFAULT_LOG_FILE = '/var/log/sre_http_backend/access.log'
SICK_FILE = 'sick'
SESSION_COOKIE = 'SESSIONID'
TRACKING_COOKIE = 'tracking'
CART_COOKIE = 'cart'
PRODUCT = 'ShopApp'
BIG_SIZE = 20000
MAX_SLOW_MS = 15000
MAX_DOWN_SECONDS = 300
MAX_SESSIONS = 10000
MAX_LOG_LINES = 200
LOG_MAX_BYTES = 4_000_000  # the access log is rotated (one generation kept) above this size
IDLE_TIMEOUT = 75          # seconds an idle keep-alive connection is kept (above nginx's 60)
ALLOWED_METHODS = 'GET, HEAD, POST, OPTIONS'
REASONS = {200: 'OK', 301: 'Moved Permanently', 400: 'Bad Request', 401: 'Unauthorized', 404: 'Not Found',
           405: 'Method Not Allowed', 503: 'Service Unavailable'}


class Request:
    """What the application reads of a request."""

    def __init__(self, method, target, version='HTTP/1.1', headers=(), body=b'', client=('', 0),
                 server=('', 0), app='shop', conn_requests=1):
        self.method = method
        self.target = target
        self.version = version
        self.headers = list(headers)          # [(name, value)] in arrival order
        self.body = body
        self.client = client
        self.server = server
        self.app = app
        self.conn_requests = conn_requests
        split = urlsplit(target)
        self.path = split.path or '/'
        self.query = parse_qs(split.query, keep_blank_values=True)

    def header(self, name, default=''):
        """First value of the header *name* (case-insensitive)."""
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return default

    def param(self, name, default=''):
        values = self.query.get(name)
        return values[0] if values else default

    def cookies(self):
        """``{name: value}`` of the ``Cookie`` headers."""
        jar = {}
        for key, value in self.headers:
            if key.lower() != 'cookie':
                continue
            for part in value.split(';'):
                name, sep, val = part.strip().partition('=')
                if sep and name:
                    jar[name] = val
        return jar

    def host(self):
        """The ``Host`` header without its port, lower case."""
        host = self.header('Host').strip().lower()
        if host.startswith('['):
            return host.partition(']')[0] + ']'
        return host.rsplit(':', 1)[0] if ':' in host else host


class Response:
    def __init__(self, status=200, lines=(), headers=(), text=None):
        self.status = status
        self.headers = list(headers)
        body = text if text is not None else ''.join(f"{line}\n" for line in lines)
        self.body = body.encode() if isinstance(body, str) else body


def header_key(name):
    """``X-Forwarded-For`` -> ``HEADER_X_FORWARDED_FOR``."""
    return 'HEADER_' + ''.join(c if c.isalnum() else '_' for c in name.upper())


def item_price(item):
    """A stable price for a catalog item."""
    return sum(item.encode()) % 90 + 10


class App:
    """The application: its state (sessions, counter, health) and one answer per request."""

    def __init__(self, config, clock=time.time, sleep=time.sleep):
        self.name = str(config.get('name', 'backend'))
        self.apps = {int(port): str(app) for port, app in (config.get('apps') or {'8080': 'shop'}).items()}
        self.version = str(config.get('version', '1.0'))
        self.vhosts = {str(k).lower(): str(v) for k, v in (config.get('vhosts') or {}).items()}
        self.old_slug = str(config.get('old_slug', 'welcome'))
        self.form_code = str(config.get('form_code', ''))
        self.form_token = str(config.get('form_token', ''))
        self.catalog_delay = int(config.get('catalog_delay_ms', 200)) / 1000.0
        self.state_dir = str(config.get('state_dir', DEFAULT_STATE_DIR))
        self.log_file = str(config.get('log_file', DEFAULT_LOG_FILE))
        self.clock = clock
        self.sleep = sleep
        self.sessions = {}
        self.counter = 0
        self.down_until = 0.0
        self.lock = threading.Lock()
        self.log_lock = threading.Lock()

    # -- state -------------------------------------------------------------------

    def sick_path(self):
        return os.path.join(self.state_dir, SICK_FILE)

    def is_sick(self):
        return os.path.exists(self.sick_path())

    def set_sick(self, sick):
        os.makedirs(self.state_dir, exist_ok=True)
        if sick:
            with open(self.sick_path(), 'w') as marker:
                marker.write('sick\n')
        else:
            try:
                os.unlink(self.sick_path())
            except FileNotFoundError:
                pass

    def is_down(self):
        return self.clock() < self.down_until

    def next_id(self):
        with self.lock:
            self.counter += 1
            return f"{self.name}-{self.counter:06d}"

    def open_session(self, user):
        sid = secrets.token_hex(8)
        with self.lock:
            while len(self.sessions) >= MAX_SESSIONS:
                self.sessions.pop(next(iter(self.sessions)))
            self.sessions[sid] = user
        return sid

    # -- pages -------------------------------------------------------------------

    def whoami(self, req, extra=()):
        lines = [
            f"SERVER={self.name}", f"APP={req.app}",
            f"SERVER_IP={req.server[0]}", f"SERVER_PORT={req.server[1]}",
            f"CLIENT_IP={req.client[0]}", f"CLIENT_PORT={req.client[1]}",
            f"METHOD={req.method}", f"PATH={req.target}", f"HTTP_VERSION={req.version}",
            f"CONN_REQUESTS={req.conn_requests}", f"REQUEST_ID={self.next_id()}",
            f"HOST={req.header('Host')}",
        ]
        lines.extend(extra)
        lines.extend(f"{header_key(name)}={value}" for name, value in req.headers)
        return lines

    def handle(self, req):
        """The :class:`Response` to *req* (the common headers are added by :meth:`answer`)."""
        if req.method == 'OPTIONS':
            return Response(200, headers=[('Allow', ALLOWED_METHODS)], text='')
        if req.method not in ('GET', 'HEAD', 'POST'):
            return Response(405, [f"SERVER={self.name}", f"ERROR=method {req.method} not allowed"],
                            headers=[('Allow', ALLOWED_METHODS)])
        path = req.path
        if path.startswith('/_admin/') or path == '/_log':
            return self.handle_admin(req)
        if path == '/health':
            if self.is_sick():
                return Response(503, ["SICK", f"SERVER={self.name}"], headers=[('Cache-Control', 'no-store')])
            return Response(200, ["OK", f"SERVER={self.name}"], headers=[('Cache-Control', 'no-store')])
        secret = self.vhosts.get(req.host())
        if secret is not None:
            return Response(200, self.whoami(req, [f"VHOST={req.host()}", f"SECRET={secret}"]),
                            headers=[('Cache-Control', 'no-store')])
        if path == '/old-page':
            location = f"/catalog/{self.old_slug}"
            return Response(301, [f"SERVER={self.name}", f"MOVED={location}"], headers=[('Location', location)])
        if path == '/form':
            return self.handle_form(req)
        if path == '/login':
            user = req.param('user', 'guest') or 'guest'
            sid = self.open_session(user)
            return Response(200, self.whoami(req, ["LOGIN=ok", f"USER={user}"]),
                            headers=[('Set-Cookie', f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly"),
                                     ('Cache-Control', 'no-store')])
        if path == '/account':
            user = self.sessions.get(req.cookies().get(SESSION_COOKIE, ''))
            if user is None:
                return Response(401, self.whoami(req, ["SESSION=unknown"]), headers=[('Cache-Control', 'no-store')])
            return Response(200, self.whoami(req, [f"USER={user}"]), headers=[('Cache-Control', 'no-store')])
        if path == '/cart':
            return Response(200, self.whoami(req, [f"CART={req.cookies().get(CART_COOKIE, '')}"]),
                            headers=[('Cache-Control', 'private')])
        if path.startswith('/catalog/'):
            item = path[len('/catalog/'):]
            self.sleep(self.catalog_delay)
            return Response(200, self.whoami(req, [f"ITEM={item}", f"PRICE={item_price(item)}"]),
                            headers=[('Set-Cookie', f"{TRACKING_COOKIE}={secrets.token_hex(6)}; Path=/")])
        if path == '/big':
            line = f"SERVER={self.name} " + 'lorem ipsum dolor sit amet ' * 3 + '\n'
            return Response(200, text=line * (BIG_SIZE // len(line) + 1),
                            headers=[('Cache-Control', 'public, max-age=60')])
        if path == '/slow':
            try:
                delay = max(0, min(int(req.param('ms', '1000')), MAX_SLOW_MS))
            except ValueError:
                delay = 1000
            self.sleep(delay / 1000.0)
            return Response(200, self.whoami(req, [f"SLEPT_MS={delay}"]), headers=[('Cache-Control', 'no-store')])
        if path.startswith('/status/'):
            try:
                status = int(path[len('/status/'):])
            except ValueError:
                status = 0
            if not 200 <= status <= 599:
                return Response(404, [f"SERVER={self.name}", "ERROR=unknown status"])
            return Response(status, [f"SERVER={self.name}", f"STATUS={status}"], headers=[('Cache-Control', 'no-store')])
        extra = ["AREA=admin"] if path == '/admin' or path.startswith('/admin/') else []
        if path.startswith('/api/'):
            extra.append("API=ok")
        return Response(200, self.whoami(req, extra), headers=[('Cache-Control', 'no-store')])

    def handle_form(self, req):
        if req.method != 'POST':
            return Response(405, [f"SERVER={self.name}", "ERROR=this form only accepts POST"],
                            headers=[('Allow', 'POST')])
        fields = parse_qs(req.body.decode('utf-8', 'replace'), keep_blank_values=True)
        code = (fields.get('code') or [''])[0]
        if not self.form_code or code != self.form_code:
            return Response(400, [f"SERVER={self.name}", "ERROR=bad code"])
        return Response(200, [f"SERVER={self.name}", f"TOKEN={self.form_token}"], headers=[('Cache-Control', 'no-store')])

    def handle_admin(self, req):
        path = req.path
        if path == '/_log':
            try:
                count = max(1, min(int(req.param('n', '20')), MAX_LOG_LINES))
            except ValueError:
                count = 20
            return Response(200, text=''.join(self.log_tail(count)), headers=[('Cache-Control', 'no-store')])
        if path == '/_admin/health':
            state = req.param('state')
            if state in ('up', 'down'):
                self.set_sick(state == 'down')
            elif state:
                return Response(400, [f"SERVER={self.name}", "ERROR=state is up or down"])
            return Response(200, [f"SERVER={self.name}", f"HEALTH={'down' if self.is_sick() else 'up'}"],
                            headers=[('Cache-Control', 'no-store')])
        if path == '/_admin/down':
            try:
                seconds = max(0, min(int(req.param('seconds', '30')), MAX_DOWN_SECONDS))
            except ValueError:
                return Response(400, [f"SERVER={self.name}", "ERROR=seconds is a number"])
            self.down_until = self.clock() + seconds
            return Response(200, [f"SERVER={self.name}", f"DOWN_SECONDS={seconds}"],
                            headers=[('Cache-Control', 'no-store'), ('Connection', 'close')])
        return Response(404, [f"SERVER={self.name}", "ERROR=unknown admin page"])

    def answer(self, req):
        """``(status, headers, body)`` of *req*, the common headers added; the request is logged."""
        response = self.handle(req)
        headers = [('Content-Type', 'text/plain; charset=utf-8'), ('Content-Length', str(len(response.body))),
                   ('X-Powered-By', f"{PRODUCT}/{self.version}"), ('X-Backend-Server', self.name)]
        headers.extend(response.headers)
        if req.path != '/_log':
            self.log(req, response.status)
        return response.status, headers, response.body

    # -- access log --------------------------------------------------------------

    def log_line(self, req, status):
        return (f"{self.clock():.3f} {req.client[0]} {req.method} {req.target} {status}"
                f" port={req.server[1]} host={req.header('Host') or '-'}"
                f" xff={req.header('X-Forwarded-For') or '-'} ua={req.header('User-Agent') or '-'}\n")

    def log(self, req, status):
        try:
            with self.log_lock:
                os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
                with open(self.log_file, 'a') as log:
                    log.write(self.log_line(req, status))
                    full = log.tell() > LOG_MAX_BYTES
                if full:
                    os.replace(self.log_file, self.log_file + '.1')
        except OSError:
            pass

    def log_tail(self, count):
        try:
            with open(self.log_file) as log:
                return log.readlines()[-count:]
        except OSError:
            return []


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        timeout = IDLE_TIMEOUT
        server_version = PRODUCT
        sys_version = ''

        def setup(self):
            super().setup()
            self.conn_requests = 0

        def log_message(self, *args):
            pass

        def serve(self):
            self.conn_requests += 1
            length = self.headers.get('Content-Length', '')
            body = self.rfile.read(int(length)) if length.isdigit() and int(length) > 0 else b''
            local = self.connection.getsockname()
            req = Request(self.command, self.path, self.request_version, self.headers.items(), body,
                          client=self.client_address[:2], server=local[:2],
                          app=app.apps.get(local[1], 'shop'), conn_requests=self.conn_requests)
            status, headers, payload = app.answer(req)
            self.send_response(status, REASONS.get(status))
            for name, value in headers:
                self.send_header(name, value)
                if name.lower() == 'connection' and value.lower() == 'close':
                    self.close_connection = True
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(payload)

        do_GET = do_HEAD = do_POST = do_OPTIONS = do_PUT = do_DELETE = do_PATCH = do_PURGE = serve

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, address, app):
        self.app = app
        super().__init__(address, make_handler(app))

    def verify_request(self, request, client_address):
        if not self.app.is_down():
            return True
        try:
            # SO_LINGER with a zero timeout: the close sends a RST, as a dead application would
            request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        except OSError:
            pass
        return False


def make_servers(app, bind='0.0.0.0', ports=None):
    """One :class:`Server` per port of the application (*ports* overrides the configured ones)."""
    return [Server((bind, port), app) for port in (ports if ports is not None else sorted(app.apps))]


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
    os.makedirs(os.path.dirname(SERVER_LOG), exist_ok=True)
    log = os.open(SERVER_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log, 1)
    os.dup2(log, 2)
    with open(PID_FILE, 'w') as pid_file:
        pid_file.write(str(os.getpid()))


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(f"usage: {argv[0]} CONFIG.json\n")
        return 2
    with open(argv[1]) as config_file:
        app = App(json.load(config_file))
    # the sockets are opened before the fork: a port already in use fails the command
    servers = make_servers(app)
    daemonize()
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
