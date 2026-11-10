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


class TestLiveArchives:
    """The archives of the evaluations on a real server: the table, a duplicate name left as it
    is, the queries of the Archives page (the newest of each project / student among the rows of
    the filters, the student / group / lab / host / exam filters, the cursor pages, the detail,
    the options, the cursors of the collector)."""

    @pytest.fixture
    def archives_cfg(self, cfg):
        from sreweb.config import ArchivesConfig
        acfg = ArchivesConfig(table=cfg.table + '_archives')
        yield acfg
        connect, _ = connector(cfg)
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"DROP TABLE IF EXISTS `{acfg.table}`")
            conn.commit()
        finally:
            conn.close()

    def test_round_trip(self, cfg, archives_cfg):
        from datetime import datetime, timezone
        from sreweb.portal.archives import ArchiveDatabase, row_of_record, table_spec, parse_archive_filters
        from test_web_archives import record, RLN
        other = '20261025110000@@@sre@dhcp.py@@@alice'
        bob = '20261025100000@@@sre@dhcp.py@@@bob'
        carol = '20261025100000@@@other.py@@@carol'
        names = [f'20261025100102_{RLN}.zst', f'20261025100500_{RLN}.zst', f'20261025110500_{other}.zst',
                 f'20261025100300_{bob}.zst', f'20261025100400_{carol}.zst']
        records = [
            record(archive=names[0], eval_date='2026-10-25T10:01:02+02:00', grade=1.0),
            record(archive=names[1], eval_date='2026-10-25T10:05:00+02:00', grade=2.0, exam_time_remaining=600),
            record(archive=names[2], running_lab_name=other, eval_date='2026-10-25T11:05:00+02:00', grade=3.0),
            record(archive=names[3], running_lab_name=bob, login='bob', fullname='Bob B', group='INFO2',
                   eval_date='2026-10-25T10:03:00+02:00', grade=0.5, exam=True),
            record(archive=names[4], running_lab_name=carol, lab='other.py', login='carol', fullname='Carol C',
                   group='', eval_date='2026-10-25T10:04:00+02:00', grade=5.0),
        ]
        connect, transient = connector(cfg)
        sink = DatabaseSink(cfg, connect=connect, transient=transient, spec=table_spec(archives_cfg))
        sink.start()
        for r in records:
            sink.put_row(row_of_record('a01', r))
        sink.put_row(row_of_record('b02', records[0]))            # the same archive seen from another host: left as it is
        assert sink.flush(10), sink.status()
        db = ArchiveDatabase(archives_cfg.table, connect=connect)

        def rows_of(**query) -> list:
            return db.query_sync(parse_archive_filters({k: str(v) for k, v in query.items()}))['rows']

        every = rows_of(show='all')
        assert [r['archive'] for r in every] == names[::-1] and {r['host'] for r in every} == {'a01'}
        assert every[-1]['ts'] == datetime(2026, 10, 25, 8, 1, 2, tzinfo=timezone.utc).timestamp()
        assert (every[-1]['group'], every[-1]['exam'], every[1]['exam'], every[-1]['mark']) == ('INFO1', False, True, 6.7)
        assert 'details' not in every[0]
        # the newest of each project, of each student and lab
        assert [r['archive'] for r in rows_of()] == [names[4], names[3], names[2], names[1]]
        assert [(r['login'], r['archive']) for r in rows_of(show='student')] == \
            [('carol', names[4]), ('bob', names[3]), ('alice', names[2])]
        # among the rows of the window: alice's first project at 10:01, bob's at 10:03
        until = datetime(2026, 10, 25, 8, 4, tzinfo=timezone.utc).timestamp()
        assert [r['archive'] for r in rows_of(until=until)] == [names[3], names[0]]
        assert [r['archive'] for r in rows_of(show='student', until=until)] == [names[3], names[0]]
        # the student (a login prefix or a part of a name, case-insensitive), group, lab, host and exam filters
        assert [r['login'] for r in rows_of(student='ali', show='all')] == ['alice'] * 3
        assert [r['login'] for r in rows_of(student='ob b')] == ['bob'] and rows_of(student='zz') == []
        assert [r['login'] for r in rows_of(group='INFO2')] == ['bob'] and rows_of(group='INFO') == []
        assert [r['login'] for r in rows_of(lab='other')] == ['carol'] and len(rows_of(lab='dhcp', show='all')) == 4
        assert [r['login'] for r in rows_of(exam=1)] == ['bob'] and len(rows_of(exam=0, show='all')) == 4
        assert rows_of(host='b02') == [] and len(rows_of(host='a01', show='all')) == 5
        # the detail, the options, the cursors of the collector
        full = db.get_sync(every[-1]['id'])
        assert full['details']['elements'][0]['title'] == {'en': 'both', 'fr': 'les deux'} and full['login'] == 'alice'
        assert db.get_sync(999999999) is None
        assert db.options_sync() == {'labs': ['other.py', 'sre/dhcp.py'], 'groups': ['INFO1', 'INFO2']}
        assert db.cursors_sync() == {'a01': max(names)}
        # the summary: by student, with the details, capped
        summary = db.summary_sync(parse_archive_filters({'lab': 'dhcp'}, default_show='student'), limit=1)
        assert summary['truncated'] is True and [r['login'] for r in summary['rows']] == ['alice']
        assert summary['rows'][0]['archive'] == names[2] and summary['rows'][0]['details']['managed'] is True
        # a PDF report on every evaluation of alice's first project: the rows without their
        # details (the remaining exam time read out of them by the server), the best one in full
        page = db.light_report_sync([every[-1]['id']], remaining_time=True)
        assert (page['count'], page['projects'], page['full'], page['truncated']) == (2, 1, 1, False)
        first, best = page['records']
        assert (first['grade'], 'elements' in first, first['exam_time_remaining'], first['email']) == (1.0, False, None, 'a@x.org')
        assert (best['grade'], best['exam_time_remaining'], best['archive']) == (2.0, 600, names[1])
        assert best['elements'][0]['title'] == {'en': 'both', 'fr': 'les deux'}
        assert db.light_report_sync([every[-1]['id']], limit=1)['truncated'] is True
        # the cursor pages of every row
        seen, before = [], None
        while True:
            page = db.query_sync(parse_archive_filters({'show': 'all', 'limit': '2', **({'before': str(before)} if before else {})}))
            seen.extend(r['id'] for r in page['rows'])
            if not page['more']:
                break
            before = page['rows'][-1]['id']
        assert len(seen) == len(set(seen)) == 5
        sink.close()
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"SHOW CREATE TABLE `{archives_cfg.table}`")
                definition = cur.fetchall()[0][1].lower()
        finally:
            conn.close()
        assert 'unique key `archive`' in definition and 'mediumtext' in definition and 'login_lab_id' in definition


    def test_upgrade_of_a_table_created_before_canonical_lab(self, cfg, archives_cfg, caplog):
        """A table of a release before the canonical_lab column, with a row of that release: the
        sink probes the columns, keeps its row and warns once (nothing dropped); the ALTER TABLE
        and the UPDATE of web.md (*Upgrading*) then let the writes through, the old row keeping
        its path as the file run, the new one its real file, and the lab list merging them."""
        import logging
        from sreweb.portal import archives as R
        from sreweb.portal.archives import ArchiveDatabase, row_of_record, table_spec, parse_archive_filters
        from test_web_archives import record, RLN, NAME
        table = archives_cfg.table
        old_ddl = '\n'.join(line for line in R.DDL.splitlines() if 'canonical_lab' not in line)   # the column, its two keys
        old_columns = [c for c in R.COLUMNS if c != 'canonical_lab']
        old_row = [v for c, v in zip(R.COLUMNS, row_of_record('a01', record(lab='s3/r306/dhcp.py'))) if c != 'canonical_lab']
        connect, transient = connector(cfg)
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(old_ddl.format(table=table))
                cur.execute(f"INSERT INTO `{table}` ({', '.join(old_columns)}) VALUES ({', '.join(['%s'] * len(old_columns))})",
                            old_row)
            conn.commit()
        finally:
            conn.close()
        sink = DatabaseSink(cfg, connect=connect, transient=transient, spec=table_spec(archives_cfg),
                            sleep=lambda seconds: time.sleep(0.2))
        sink.start()
        linked = '20261109104225@@@s3@r306@dhcp.py@@@wbouzga'
        new = record(archive=f'20261109104300_{linked}.zst', running_lab_name=linked, login='wbouzga', lab='s3/r306/dhcp.py',
                     canonical_lab='sre/dhcp.py')
        with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
            assert sink.put_row(row_of_record('a01', new))
            assert not sink.flush(3)
        status = sink.status()
        assert status['connected'] is False and status['dropped'] == 0, status
        assert status['last_error'].startswith(f'the table {table} lacks a column') and 'canonical_lab' in status['last_error']
        assert len([r for r in caplog.records if 'lacks a column' in r.message]) == 1
        # the administrator runs the statements of the documentation
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"ALTER TABLE `{table}` ADD COLUMN canonical_lab VARCHAR(255) NOT NULL DEFAULT '' AFTER lab, "
                            "ADD KEY login_canonical_id (login, canonical_lab, id), ADD KEY canonical_lab_ts (canonical_lab, ts)")
                cur.execute(f"UPDATE `{table}` SET canonical_lab = lab WHERE canonical_lab = ''")
            conn.commit()
        finally:
            conn.close()
        assert sink.flush(20), sink.status()
        assert sink.status()['connected'] is True and sink.status()['dropped'] == 0
        db = ArchiveDatabase(table, connect=connect)
        rows = db.query_sync(parse_archive_filters({'show': 'all'}))['rows']
        assert sorted((r['archive'], r['lab'], r['canonical_lab']) for r in rows) == \
            [(NAME, 's3/r306/dhcp.py', 's3/r306/dhcp.py'), (new['archive'], 's3/r306/dhcp.py', 'sre/dhcp.py')]
        assert db.options_sync()['labs'] == ['s3/r306/dhcp.py', 'sre/dhcp.py']
        assert [r['login'] for r in db.query_sync(parse_archive_filters({'lab': 'sre/dhcp'}))['rows']] == ['wbouzga']
        sink.close()


class TestLiveExams:
    """The exams of the Exams page on a real server: the two tables created at the first
    operation, an exam inserted then updated, its members replaced, everything read back as it
    was kept, the deletion of an exam with its members, the purge of the past ones."""

    @pytest.fixture
    def exams_cfg(self, cfg):
        from sreweb.config import ExamsConfig
        xcfg = ExamsConfig(table=cfg.table + '_exams')
        yield xcfg
        connect, _ = connector(cfg)
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"DROP TABLE IF EXISTS `{xcfg.members_table}`")
                cur.execute(f"DROP TABLE IF EXISTS `{xcfg.table}`")
            conn.commit()
        finally:
            conn.close()

    def test_round_trip(self, cfg, exams_cfg):
        import ipaddress
        from sreweb.identity import Identity
        from sreweb.portal.exams import Exam, ExamLab, Member
        from sreweb.portal.examstore import ExamStore
        connect, _ = connector(cfg)
        now = math.floor(time.time() * 1000) / 1000
        store = ExamStore(cfg, exams_cfg, connect=connect, clock=lambda: now)
        assert store.load_all() == []                                  # the tables created
        exam = Exam(id=0, title='Partiel réseau', created_by='prof', created_at=now, updated_at=now,
                    logins={'dave'}, groups={'department:INFO1', 'custom:TP lundi'},
                    labs=[ExamLab('sre/_EXAM_/exam1.py', 'hard'), ExamLab('s4/tp_ssh')],
                    duration=5400.0, start_after=now + 3600, end_before=now + 9000, lead=720.0, pre_start=300.0,
                    networks=[ipaddress.ip_network('10.0.0.0/8')], eval_interval=30.0)
        exam.id = store.save_exam(exam)
        assert exam.id > 0
        alice = Member('alice', first_seen=now, started_at=now + 3600, extra_minutes=5, address='10.0.0.5',
                       projects={'sre/_EXAM_/exam1.py': {'host': 'a01', 'rln': 'r1', 'synced': None}})
        bob = Member('bob', labs=[ExamLab('s4/tp_ssh')], ended_at=now + 4000, dismissed_at=now + 4001)
        store.save_member(exam.id, alice)
        store.save_member(exam.id, bob)
        alice.extra_minutes = 10                                        # replaced, not duplicated
        store.save_member(exam.id, alice)
        exam.ended_at = now + 5000
        exam.title = 'Partiel'
        store.save_exam(exam)
        loaded = store.load_all()
        assert len(loaded) == 1
        back = loaded[0]
        assert (back.id, back.title, back.created_by, back.created_at) == (exam.id, 'Partiel', 'prof', now)
        assert (back.logins, back.groups) == ({'dave'}, {'department:INFO1', 'custom:TP lundi'})
        assert back.labs == exam.labs and back.networks == exam.networks
        assert (back.duration, back.start_after, back.end_before, back.ended_at) == (5400.0, now + 3600, now + 9000, now + 5000)
        assert (back.lead, back.pre_start, back.eval_interval) == (720.0, 300.0, 30.0)
        a, b = back.members['alice'], back.members['bob']
        assert (a.first_seen, a.started_at, a.extra_minutes, a.address, a.labs) == (now, now + 3600, 10, '10.0.0.5', None)
        assert a.projects == alice.projects and a.orphans == []
        assert (b.labs, b.ended_at, b.dismissed_at, b.started_at) == ([ExamLab('s4/tp_ssh')], now + 4000, now + 4001, None)
        assert store.status() == {'connected': True, 'last_error': None}
        # the purge: a past exam last changed before the limit goes, with its members
        assert store.purge(now - 1) == 0
        assert store.purge(now + 1) == 1 and store.load_all() == []
        other = Exam(id=0, title='Other', created_by='prof', created_at=now, updated_at=now, logins=set(), groups=set(),
                     labs=[ExamLab('s4/tp_ssh')], duration=600.0, start_after=None, end_before=None, lead=0.0,
                     pre_start=0.0, networks=[], eval_interval=60.0)
        other.id = store.save_exam(other)
        store.save_member(other.id, Member('carol'))
        store.delete_exam(other.id)
        assert store.load_all() == []
        assert Identity(login='prof', role='instructor').is_instructor   # the identity the agents are called with


class TestLiveGroups:
    """The custom groups of the Groups page on a real server: the two tables created at the first
    operation, the exact names and logins (binary collation), a duplicate, the members, a rename,
    the deletion of a group with its members."""

    @pytest.fixture
    def groups_cfg(self, cfg):
        from sreweb.config import GroupsConfig
        gcfg = GroupsConfig(table=cfg.table + '_groups')
        yield gcfg
        connect, _ = connector(cfg)
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"DROP TABLE IF EXISTS `{gcfg.members_table}`")
                cur.execute(f"DROP TABLE IF EXISTS `{gcfg.table}`")
            conn.commit()
        finally:
            conn.close()

    def test_round_trip(self, cfg, groups_cfg):
        from sreweb.portal.groups import GroupStore, GroupExists, GroupNotFound
        connect, _ = connector(cfg)
        store = GroupStore(cfg, groups_cfg, connect=connect)
        assert store.list_sync() == []                         # the tables created
        group = store.create_sync('TP lundi', 'Lundi 8h', 'prof')
        assert group.name == 'TP lundi' and group.members == 0 and group.id > 0
        with pytest.raises(GroupExists):
            store.create_sync('TP lundi', '', 'prof')
        other = store.create_sync('tp lundi', '', 'prof')      # binary collation: another name
        assert other.id != group.id
        assert store.add_members_sync('TP lundi', ['alice', 'bob', 'alice'], 'prof') == (2, 2)
        assert store.add_members_sync('TP lundi', ['bob', 'carol'], 'prof') == (1, 3)
        assert store.add_members_sync('TP lundi', ['Alice'], 'prof') == (1, 4)    # the logins are exact too
        found, members = store.get_sync('TP lundi')
        assert found.members == 4 and [m['login'] for m in members] == ['Alice', 'alice', 'bob', 'carol']
        assert members[0]['added_by'] == 'prof' and members[0]['added_at'].endswith('+00:00')
        assert [(g.name, g.members) for g in store.list_sync()] == [('TP lundi', 4), ('tp lundi', 0)]
        renamed = store.update_sync('TP lundi', new_name='TP mardi', description='Mardi')
        assert (renamed.name, renamed.description, renamed.members) == ('TP mardi', 'Mardi', 4)
        with pytest.raises(GroupExists):
            store.update_sync('TP mardi', new_name='tp lundi')
        store.remove_member_sync('TP mardi', 'Alice')
        with pytest.raises(GroupNotFound):
            store.remove_member_sync('TP mardi', 'Alice')
        assert store.memberships_sync() == {'TP mardi': frozenset({'alice', 'bob', 'carol'}), 'tp lundi': frozenset()}
        assert store.remove_members_sync('TP mardi', ['bob', 'Alice', 'zed']) == (1, 2)   # Alice gone, zed never there
        assert store.remove_members_sync('TP mardi', []) == (0, 2)
        with pytest.raises(GroupNotFound):
            store.remove_members_sync('nope', ['alice'])
        assert store.memberships_sync() == {'TP mardi': frozenset({'alice', 'carol'}), 'tp lundi': frozenset()}
        store.delete_sync('TP mardi')
        with pytest.raises(GroupNotFound):
            store.get_sync('TP mardi')
        assert store.memberships_sync() == {'tp lundi': frozenset()}
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM `{groups_cfg.members_table}`")
                assert cur.fetchone()[0] == 0                  # the members went with the group
                cur.execute(f"SHOW CREATE TABLE `{groups_cfg.table}`")
                assert 'utf8mb4_bin' in cur.fetchone()[1]
        finally:
            conn.close()
        assert store.status() == {'connected': True, 'last_error': None}
