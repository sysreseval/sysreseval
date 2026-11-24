"""Tests of lib/docker_app.py, the application the Docker labs run in containers: the RESP
client against a small fake Redis server, the visit stores, the HTTP handler on a local port."""
import io
import json
import os
import socket
import socketserver
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import docker_app as app  # noqa: E402


class FakeRedis(socketserver.ThreadingTCPServer):
    """INCR / PING / AUTH of a Redis server, enough for the application."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, password=None):
        self.password = password
        self.counters = {}
        super().__init__(('127.0.0.1', 0), FakeRedisHandler)


class FakeRedisHandler(socketserver.StreamRequestHandler):
    def handle(self):
        authed = self.server.password is None
        while True:
            try:
                args = app.read_reply(self.rfile)
            except ConnectionError:
                return
            command = args[0].decode().upper()
            if command == 'AUTH':
                if args[1].decode() == self.server.password:
                    authed = True
                    self.wfile.write(b"+OK\r\n")
                else:
                    self.wfile.write(b"-WRONGPASS invalid password\r\n")
            elif not authed:
                self.wfile.write(b"-NOAUTH Authentication required.\r\n")
            elif command == 'PING':
                self.wfile.write(b"+PONG\r\n")
            elif command == 'INCR':
                key = args[1].decode()
                self.server.counters[key] = self.server.counters.get(key, 0) + 1
                self.wfile.write(b":%d\r\n" % self.server.counters[key])
            else:
                self.wfile.write(b"-ERR unknown command\r\n")


@pytest.fixture
def redis_server():
    servers = []

    def make(password=None):
        server = FakeRedis(password)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


class TestResp:
    def test_encode(self):
        assert app.encode_command("SET", "k", 12) == b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\n12\r\n"

    @pytest.mark.parametrize('raw, value', [
        (b"+PONG\r\n", "PONG"), (b":42\r\n", 42), (b"$3\r\nabc\r\n", b"abc"), (b"$-1\r\n", None),
        (b"*2\r\n$10\r\nappendonly\r\n$3\r\nyes\r\n", [b"appendonly", b"yes"]), (b"*-1\r\n", None),
    ])
    def test_replies(self, raw, value):
        assert app.read_reply(io.BytesIO(raw)) == value

    def test_errors(self):
        with pytest.raises(app.RedisError, match='NOAUTH'):
            app.read_reply(io.BytesIO(b"-NOAUTH Authentication required.\r\n"))
        for raw in (b"", b"+PON", b"$5\r\nab", b"?x\r\n"):
            with pytest.raises(ConnectionError):
                app.read_reply(io.BytesIO(raw))

    def test_commands(self, redis_server):
        server = redis_server('s3cret')
        port = server.server_address[1]
        assert app.redis_command('127.0.0.1', port, 's3cret', 'PING') == 'PONG'
        assert app.redis_command('localhost', port, 's3cret', 'INCR', 'visits') == 1
        with pytest.raises(app.RedisError, match='NOAUTH'):
            app.redis_command('127.0.0.1', port, None, 'PING')
        with pytest.raises(app.RedisError, match='WRONGPASS'):
            app.redis_command('127.0.0.1', port, 'bad', 'PING')

    def test_resolve(self):
        assert app.resolve('127.0.0.1', 6379) == ('127.0.0.1', 6379)
        with pytest.raises(OSError):
            app.resolve('no-such-host.invalid', 6379, timeout=3)

    def test_password(self, tmp_path):
        secret = tmp_path / 'pw'
        secret.write_text('s3cret\n')
        assert app.redis_password({'REDIS_PASSWORD_FILE': str(secret)}) == 's3cret'
        assert app.redis_password({'REDIS_PASSWORD_FILE': str(tmp_path / 'none'), 'REDIS_PASSWORD': 'x'}) is None
        assert app.redis_password({'REDIS_PASSWORD': 'x'}) == 'x'
        assert app.redis_password({}) is None


class TestStores:
    def test_redis(self, redis_server, tmp_path):
        server = redis_server('pw')
        secret = tmp_path / 'pw'
        secret.write_text('pw')
        store = app.Store({'REDIS_HOST': '127.0.0.1', 'REDIS_PORT': str(server.server_address[1]),
                           'REDIS_PASSWORD_FILE': str(secret)})
        assert store.kind == 'redis' and store.healthy()
        assert [store.incr(), store.incr()] == [1, 2] and server.counters == {'visits': 2}

    def test_redis_down(self):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        store = app.Store({'REDIS_HOST': '127.0.0.1', 'REDIS_PORT': str(port)})
        assert store.kind == 'redis' and not store.healthy()
        with pytest.raises(OSError):
            store.incr()

    def test_file(self, tmp_path):
        store = app.Store({'DATA_DIR': str(tmp_path)})
        assert store.kind == 'file' and store.healthy()
        assert [store.incr(), store.incr()] == [1, 2] and (tmp_path / 'visits').read_text() == "2\n"
        again = app.Store({'DATA_DIR': str(tmp_path)})
        assert again.incr() == 3

    def test_memory(self, tmp_path):
        store = app.Store({'DATA_DIR': str(tmp_path / 'missing')})
        assert store.kind == 'memory' and store.healthy() and [store.incr(), store.incr()] == [1, 2]

    def test_page(self, tmp_path):
        doc = app.page(app.Store({'DATA_DIR': str(tmp_path / 'missing')}),
                       {'APP_VERSION': '2.4.1', 'APP_COLOR': 'red'})
        assert doc['version'] == '2.4.1' and doc['color'] == 'red' and doc['service'] == 'sre-app'
        assert doc['visits'] == 1 and doc['store'] == 'memory' and doc['uid'] == os.geteuid()
        assert doc['hostname'] == socket.gethostname()
        assert app.page(app.Store({'DATA_DIR': str(tmp_path / 'missing')}), {})['version'] == 'dev'


class TestHttp:
    @pytest.fixture
    def serve(self):
        servers = []

        def make(store):
            server = ThreadingHTTPServer(('127.0.0.1', 0), app.make_handler(store))
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
            return f"http://127.0.0.1:{server.server_address[1]}"

        yield make
        for server in servers:
            server.shutdown()
            server.server_close()

    def test_pages(self, serve, tmp_path, capsys):
        url = serve(app.Store({'DATA_DIR': str(tmp_path)}))
        with urllib.request.urlopen(f"{url}/?i=1") as r:
            first = json.loads(r.read())
            assert r.headers['Content-Type'] == 'application/json'
        with urllib.request.urlopen(f"{url}/anything") as r:
            assert json.loads(r.read())['visits'] == first['visits'] + 1
        with urllib.request.urlopen(f"{url}/health") as r:
            assert r.status == 200 and r.read() == b"OK\n"
        assert 'GET /health' in capsys.readouterr().out

    def test_unhealthy(self, serve):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        url = serve(app.Store({'REDIS_HOST': '127.0.0.1', 'REDIS_PORT': str(port)}))
        for path in ('/health', '/'):
            with pytest.raises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(url + path)
            assert e.value.code == 503
