#!/usr/bin/env python3
"""The web application of the Docker and Docker Compose labs (stdlib only): the states copy it as
``app.py`` into the build contexts of the students (``/root/app/``, ``/root/compose/<part>/app/``),
whose images run it in the foreground as the PID 1 of a container (``python:alpine``).

``app.py [--port 8080]``

- ``GET /`` (any path but ``/health``, query string ignored): one JSON line, for instance::

      {"service": "sre-app", "version": "2.4.1", "color": "", "hostname": "3f2a9c1e7b0d",
       "user": "app", "uid": 1500, "visits": 7, "store": "redis"}

  ``version`` = ``APP_VERSION`` (``dev`` without it), ``color`` = ``APP_COLOR``, ``service`` =
  ``APP_NAME`` (``sre-app``), ``hostname`` = the container's host name (its short id unless the
  container was given one), ``user`` / ``uid`` = the effective user of the process;
- ``GET /health``: ``200 OK`` when the visit store answers, ``503`` otherwise.

The visits are counted, in this order of preference:

- in Redis when ``REDIS_HOST`` is set (``REDIS_PORT``, default 6379; the password read at each
  request from the file ``REDIS_PASSWORD_FILE``, a Compose secret, else ``REDIS_PASSWORD``): ``INCR
  visits`` through a minimal RESP client;
- in the file ``$DATA_DIR/visits`` (``DATA_DIR`` default ``/data``) when that directory is writable;
- in memory otherwise (a non-root user without a writable ``/data``: the application still works,
  its visits are lost with the container).

``SIGTERM`` ends the process at once (a Python PID 1 would otherwise ignore it and ``docker stop``
wait ten seconds), and every request is logged on stdout, flushed (``docker logs``).
"""
import json
import os
import pwd
import signal
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlsplit

REDIS_KEY = "visits"


class RedisError(Exception):
    """An error reply of the Redis server (``-ERR ...``, ``-NOAUTH ...``)."""


def encode_command(*args) -> bytes:
    """A command in the RESP protocol (an array of bulk strings)."""
    out = [b"*%d\r\n" % len(args)]
    for arg in args:
        data = arg if isinstance(arg, bytes) else str(arg).encode()
        out.append(b"$%d\r\n%s\r\n" % (len(data), data))
    return b"".join(out)


def read_reply(stream):
    """One RESP reply read from a binary file object: str, int, bytes, None or a list;
    :class:`RedisError` for an error reply, :class:`ConnectionError` on a closed connection."""
    line = stream.readline()
    if not line.endswith(b"\r\n"):
        raise ConnectionError("connection closed by the Redis server")
    kind, body = line[:1], line[1:-2]
    if kind == b"+":
        return body.decode()
    if kind == b"-":
        raise RedisError(body.decode())
    if kind == b":":
        return int(body)
    if kind == b"$":
        size = int(body)
        if size < 0:
            return None
        data = stream.read(size + 2)
        if len(data) != size + 2:
            raise ConnectionError("connection closed by the Redis server")
        return data[:-2]
    if kind == b"*":
        size = int(body)
        return None if size < 0 else [read_reply(stream) for _ in range(size)]
    raise ConnectionError(f"unexpected reply from the Redis server: {line[:40]!r}")


def resolve(host: str, port: int, timeout: float = 2.0):
    """The address of *host*, IPv4 first (``getaddrinfo``, which no socket timeout bounds, run in
    a thread): :class:`OSError` when the name is unknown or the resolver does not answer in time
    (a container's embedded DNS forwards an unknown name to the resolvers of the host)."""
    result = {}

    def work():
        try:
            result['infos'] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as e:
            result['error'] = e

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    infos = result.get('infos') or []
    if infos:
        # an IPv4 address first: the networks of the labs are IPv4 (localhost may come as ::1 first)
        infos = sorted(infos, key=lambda info: info[0] != socket.AF_INET)
        return infos[0][4][:2]
    raise result.get('error') or OSError(f"cannot resolve {host}")


def redis_command(host: str, port: int, password: Optional[str], *args, timeout: float = 2.0):
    """Run one command (after ``AUTH`` when a password is given) on a new connection."""
    with socket.create_connection(resolve(host, port, timeout), timeout=timeout) as sock:
        stream = sock.makefile("rb")
        if password:
            sock.sendall(encode_command("AUTH", password))
            read_reply(stream)
        sock.sendall(encode_command(*args))
        return read_reply(stream)


def redis_password(env=os.environ) -> Optional[str]:
    """The Redis password: the content of ``REDIS_PASSWORD_FILE`` (stripped) when it names a
    readable file, else ``REDIS_PASSWORD``, else None."""
    path = env.get("REDIS_PASSWORD_FILE")
    if path:
        try:
            with open(path) as f:
                return f.read().strip() or None
        except OSError:
            return None
    return env.get("REDIS_PASSWORD") or None


class Store:
    """The visit counter (see the module docstring for the choice of the store)."""

    def __init__(self, env=os.environ):
        self.env = env
        self.lock = threading.Lock()
        self.memory = 0
        self.redis_host = env.get("REDIS_HOST", "")
        self.redis_port = int(env.get("REDIS_PORT", "6379") or 6379)
        self.data_dir = env.get("DATA_DIR", "/data")
        if self.redis_host:
            self.kind = "redis"
        elif os.path.isdir(self.data_dir) and os.access(self.data_dir, os.W_OK):
            self.kind = "file"
        else:
            self.kind = "memory"

    def _redis(self, *args):
        return redis_command(self.redis_host, self.redis_port, redis_password(self.env), *args)

    def _file(self) -> str:
        return os.path.join(self.data_dir, "visits")

    def incr(self) -> int:
        with self.lock:
            if self.kind == "redis":
                return int(self._redis("INCR", REDIS_KEY))
            if self.kind == "file":
                try:
                    with open(self._file()) as f:
                        count = int(f.read().strip() or 0)
                except (OSError, ValueError):
                    count = 0
                count += 1
                with open(self._file(), "w") as f:
                    f.write(f"{count}\n")
                return count
            self.memory += 1
            return self.memory

    def healthy(self) -> bool:
        try:
            if self.kind == "redis":
                return self._redis("PING") == "PONG"
            if self.kind == "file":
                return os.access(self.data_dir, os.W_OK)
            return True
        except (OSError, RedisError, ValueError):
            return False


def user_name() -> str:
    uid = os.geteuid()
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def page(store: Store, env=os.environ) -> dict:
    """The document of ``GET /`` (counts one visit)."""
    return {
        "service": env.get("APP_NAME", "sre-app"),
        "version": env.get("APP_VERSION", "dev"),
        "color": env.get("APP_COLOR", ""),
        "hostname": socket.gethostname(),
        "user": user_name(),
        "uid": os.geteuid(),
        "visits": store.incr(),
        "store": store.kind,
    }


def make_handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "sre-app/1.0"

        def log_message(self, fmt, *args):
            print(f"{self.address_string()} {fmt % args}", flush=True)

        def _send(self, code: int, body: str, content_type: str):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/health":
                if store.healthy():
                    self._send(200, "OK\n", "text/plain")
                else:
                    self._send(503, "store unavailable\n", "text/plain")
                return
            try:
                doc = page(store)
            except (OSError, RedisError, ValueError) as e:
                self._send(503, json.dumps({"error": str(e)}) + "\n", "application/json")
                return
            self._send(200, json.dumps(doc) + "\n", "application/json")

    return Handler


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    port = 8080
    if len(argv) >= 2 and argv[0] == "--port":
        port = int(argv[1])
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    store = Store()
    server = ThreadingHTTPServer(("", port), make_handler(store))
    server.daemon_threads = True
    print(f"sre-app listening on port {port}, visits in {store.kind}", flush=True)
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
