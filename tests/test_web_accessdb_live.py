"""The database of the connection log against a real MariaDB / MySQL server, skipped unless
``SRE_TEST_MYSQL`` names one: ``mysql://user:password@host:3306/db`` or
``mysql://user:password@/db?unix_socket=/run/mysqld/mysqld.sock`` (the account needs ``SELECT,
INSERT, DELETE`` and ``CREATE`` / ``DROP``: a table of its own is created and dropped), or
``docker`` / ``docker:<image>``: a MariaDB (``mariadb:11`` by default) or MySQL container started
for the module on a port of the loopback and removed afterwards, what ``make docker-tests`` does
(a reachable Docker daemon: root or the docker group; skipped without one).  The offline tests
are in test_web_accessdb.py."""
import math
import os
import secrets
import time
import urllib.parse

import pytest

pymysql = pytest.importorskip('pymysql')
pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.config import AccessDatabaseConfig  # noqa: E402
from sreweb.portal.accessdb import DatabaseSink, connector  # noqa: E402
from sreweb.portal.accesshistory import AccessDatabase, parse_filters  # noqa: E402
from sreweb.portal.accesslog import ALL_EVENTS  # noqa: E402

DSN = os.environ.get('SRE_TEST_MYSQL', '')
DOCKER_MODE = 'docker'
DEFAULT_IMAGE = 'mariadb:11'
READY_TIMEOUT = 90.0        # the first start of the image initialises its data directory
pytestmark = pytest.mark.skipif(not DSN, reason="set SRE_TEST_MYSQL=mysql://user:password@host:3306/db, or "
                                                "SRE_TEST_MYSQL=docker for a MariaDB container, to run against "
                                                "a MariaDB / MySQL server")


def docker_image(dsn: str) -> str | None:
    """The image of ``docker`` / ``docker:<image>``, None for a server given by its URL."""
    if dsn == DOCKER_MODE:
        return DEFAULT_IMAGE
    if dsn.startswith(DOCKER_MODE + ':'):
        return dsn[len(DOCKER_MODE) + 1:]
    return None


@pytest.fixture(scope='module')
def dsn():
    """The URL of the server: SRE_TEST_MYSQL itself, or that of the container it asks for."""
    image = docker_image(DSN)
    if image is None:
        yield DSN
        return
    docker = pytest.importorskip('docker')
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:  # noqa: BLE001 - any failure means "no usable daemon"
        pytest.skip(f"Docker daemon not reachable: {e}")
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        client.images.pull(image)
    password = secrets.token_hex(8)
    # the MYSQL_* names of the mysql image, which the mariadb image accepts too
    container = client.containers.run(
        image, detach=True, name=f"sre-test-mysql-{os.getpid()}", labels={'sre-test': 'mysql'},
        environment={'MYSQL_ROOT_PASSWORD': password, 'MYSQL_DATABASE': 'sre_test',
                     'MYSQL_USER': 'sre_test', 'MYSQL_PASSWORD': password},
        ports={'3306/tcp': ('127.0.0.1', None)})     # a free port of the loopback
    try:
        container.reload()
        port = int(container.ports['3306/tcp'][0]['HostPort'])
        url = f"mysql://sre_test:{password}@127.0.0.1:{port}/sre_test"
        _wait_for_server(container, image, config_from_dsn(url, 'unused'))
        yield url
    finally:
        container.remove(force=True)


def _wait_for_server(container, image: str, cfg: AccessDatabaseConfig):
    """Until the server accepts the account.  The images initialise their data directory on a
    temporary server without networking, so a TCP connection means the final one, with the
    account and the database created."""
    deadline = time.monotonic() + READY_TIMEOUT
    while True:
        try:
            pymysql.connect(host=cfg.host, port=cfg.port, user=cfg.user, password=cfg.password,
                            database=cfg.name, connect_timeout=2).close()
            return
        except Exception as e:  # noqa: BLE001 - not up yet
            error = e
        container.reload()
        if container.status != 'running':
            logs = container.logs(tail=20).decode(errors='replace')
            pytest.fail(f"the {image} container is {container.status}:\n{logs}")
        if time.monotonic() >= deadline:
            pytest.fail(f"the {image} server does not answer after {READY_TIMEOUT:.0f} s: {error}")
        time.sleep(0.5)


def config_from_dsn(dsn: str, table: str) -> AccessDatabaseConfig:
    url = urllib.parse.urlsplit(dsn)
    query = urllib.parse.parse_qs(url.query)
    return AccessDatabaseConfig(host=url.hostname or '', port=url.port or 3306,
                                unix_socket=query.get('unix_socket', [''])[0],
                                user=urllib.parse.unquote(url.username or ''),
                                password=urllib.parse.unquote(url.password or ''),
                                name=url.path.lstrip('/'), table=table, keep=1)


@pytest.fixture
def cfg(dsn):
    cfg = config_from_dsn(dsn, f"sre_test_{os.getpid()}_{int(time.time())}")
    yield cfg
    connect, _ = connector(cfg)
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(f"DROP TABLE IF EXISTS `{cfg.table}`")
        conn.commit()
    finally:
        conn.close()


def wait_until(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timeout"
        time.sleep(0.05)


class TestLive:
    def test_round_trip(self, cfg):
        connect, transient = connector(cfg)
        sink = DatabaseSink(cfg, connect=connect, transient=transient)
        sink.start()
        now = time.time()
        sink.put(now - 10 * 86400, 'login', {'login': 'old', 'addr': '10.0.0.1'})        # purged (keep = 1 day)
        for i, event in enumerate(ALL_EVENTS):
            sink.put(now + i * 0.001, event, {'login': 'alice', 'addr': '10.0.1.7', 'host': 'a01',
                                               'rln': '1761466323@@@dhcp@@@alice', 'n': i})
        sink.put(now + 1, 'start', {'login': 'bob_1', 'addr': '2001:db8::7', 'lab': 'sre/dhcp%.py', 'instructor': False,
                                    'host': 'a01', 'placement': 'load', 'result': 'created', 'status': 200,
                                    'duration': 12.345, 'name': 'Émile Dupont'})
        sink.put(now + 2, 'session_close', {'login': 'alice', 'addr': '10.0.1.7', 'reason': 'idle',
                                            'projects': ['a', 'b'], 'duration': 3, 'status': 'abort'})
        sink.put(now + 3, 'denied', {'login': '-', 'addr': '10.0.2.3', 'method': 'GET', 'path': '/watch',
                                     'status': 403, 'ua': 'x' * 200})
        assert sink.flush(10), sink.status()
        db = AccessDatabase(cfg, connect=connect)

        def rows_of(**query) -> list:
            return db.query_sync(parse_filters({k: str(v) for k, v in query.items()}))['rows']

        wait_until(lambda: 'old' not in {r['login'] for r in rows_of(limit=1000)})   # the purge follows the batch
        page = db.query_sync(parse_filters({'limit': '1000'}))
        rows = page['rows']
        assert not page['more'] and len(rows) == len(ALL_EVENTS) + 3
        assert [r['id'] for r in rows] == sorted((r['id'] for r in rows), reverse=True)
        start = next(r for r in rows if r['event'] == 'start' and r['login'] == 'bob_1')
        assert abs(start['ts'] - math.floor((now + 1) * 1000) / 1000) < 0.002
        assert start['details'] == {'instructor': False, 'placement': 'load', 'result': 'created', 'name': 'Émile Dupont'}
        assert (start['lab'], start['status'], start['duration'], start['addr']) == ('sre/dhcp%.py', '200', 12.345, '2001:db8::7')
        closed = next(r for r in rows if r['event'] == 'session_close')
        assert closed['details']['projects'] == ['a', 'b'] and closed['status'] == 'abort' and closed['duration'] == 3.0
        denied = next(r for r in rows if r['event'] == 'denied')
        assert denied['login'] == '' and len(denied['details']['ua']) == 200
        # the filters: prefixes with the wildcards escaped, events, host, substrings, the time window
        assert [r['login'] for r in rows_of(login='bob_')] == ['bob_1']
        assert rows_of(login='bob%') == [] and rows_of(login='BOB') != []               # case-insensitive collation
        assert [r['event'] for r in rows_of(lab='%.py')] == ['start'] and rows_of(lab='dhcp_py') == []
        assert len(rows_of(addr='10.0.1.')) == len(ALL_EVENTS) + 1 and len(rows_of(addr='10.0.1.7')) == len(ALL_EVENTS) + 1
        # two of each: one per name of ALL_EVENTS (alice) and the explicit rows (bob_1, nobody)
        assert sorted(r['event'] for r in rows_of(event='denied,start')) == ['denied', 'denied', 'start', 'start']
        assert [r['login'] for r in rows_of(event='start', login='bob')] == ['bob_1']
        assert len(rows_of(host='a01')) == len(ALL_EVENTS) + 1 and rows_of(host='a0') == []
        assert len(rows_of(rln='@@@dhcp@@@')) == len(ALL_EVENTS)
        assert [r['event'] for r in rows_of(since=now + 0.5, until=now + 2.5)] == ['session_close', 'start']
        # the cursor pages
        seen, before, pages = [], None, 0
        while True:
            query = {'limit': '4', **({'before': str(before)} if before else {})}
            page = db.query_sync(parse_filters(query))
            seen.extend(r['id'] for r in page['rows'])
            pages += 1
            if not page['more']:
                break
            before = page['rows'][-1]['id']
        assert len(seen) == len(set(seen)) == len(rows) and pages == math.ceil(len(rows) / 4)
        sink.close()

    def test_table_definition(self, cfg):
        connect, transient = connector(cfg)
        sink = DatabaseSink(cfg, connect=connect, transient=transient)
        sink.start()
        sink.put(time.time(), 'login', {'login': 'alice'})
        assert sink.flush(10), sink.status()
        sink.close()
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"SHOW CREATE TABLE `{cfg.table}`")
                definition = cur.fetchall()[0][1].lower()
        finally:
            conn.close()
        assert 'utf8mb4' in definition and 'datetime(3)' in definition and 'login_ts' in definition
        # a second sink finds the table (no CREATE needed any more)
        again = DatabaseSink(cfg, connect=connect, transient=transient)
        again.start()
        again.put(time.time(), 'login', {'login': 'bob'})
        assert again.flush(10)
        again.close()
        assert len(AccessDatabase(cfg, connect=connect).query_sync(parse_filters({}))['rows']) == 2
