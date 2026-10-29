"""Tests of the database of the connection log (sreweb.portal.accessdb and accesshistory)
without a server: the rows built from the lines, the SQL, the filters of the History page, the
writer thread on a fake connection (batches, the table probed then created, a server down, a lost
connection, a refused row, a full queue, the daily purge, the flush at close) and the reader; the
hook of AccessLog.  A real MariaDB / MySQL is exercised by test_web_accessdb_live.py."""
import asyncio
import json
import logging
import re
import sys
import time
import types
from datetime import datetime
from pathlib import Path

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.config import AccessDatabaseConfig, AccessLogConfig, ConfigError  # noqa: E402
from sreweb.portal import accessdb as D  # noqa: E402
from sreweb.portal import accesshistory as H  # noqa: E402
from sreweb.portal import accesslog as A  # noqa: E402
from sreweb.portal.accessdb import DatabaseSink, row_of, utc_datetime, epoch  # noqa: E402
from sreweb.portal.accesshistory import AccessDatabase, HistoryError, parse_filters, build_select  # noqa: E402

NAMES = ['id', 'ts', 'event', 'login', 'addr', 'host', 'rln', 'lab', 'status', 'duration', 'details']


# ---------------------------------------------------------------------------------------------
# a fake server: connections whose statements are recorded, failures on demand
# ---------------------------------------------------------------------------------------------

class Down(Exception):
    """Transient: the server is unreachable (the rows are kept)."""


class Broken(Exception):
    """Not transient: a refused statement (a bad row is dropped)."""


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.server = conn.server
        self.description = None
        self.rowcount = -1
        self._rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, args=None):
        self.server.statements.append(('one', sql, args))
        self.server.maybe_fail(sql, args)
        if sql.startswith('SELECT 1 FROM'):
            if not self.server.table_exists:
                raise Broken(D.NO_SUCH_TABLE, "Table 'sre.access_log' doesn't exist")
        elif sql.startswith('CREATE TABLE'):
            self.server.table_exists = True
            self.server.created += 1
        elif sql.startswith('INSERT'):
            self.conn.pending.append(tuple(args))
        elif sql.startswith('DELETE'):
            self.rowcount = self.server.purge_counts.pop(0) if self.server.purge_counts else 0
        elif sql.startswith('SELECT'):
            self.description = [(name,) for name in self.server.select_names]
            self._rows = list(self.server.select_rows)

    def executemany(self, sql, rows):
        rows = list(rows)
        self.server.statements.append(('many', sql, rows))
        self.server.maybe_fail(sql, rows)
        self.conn.pending.extend(tuple(r) for r in rows)

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def close(self):
        pass


class FakeConnection:
    def __init__(self, server):
        self.server = server
        self.pending = []
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.server.maybe_fail('COMMIT', None)
        self.server.committed.extend(self.pending)
        self.pending = []

    def rollback(self):
        self.pending = []

    def close(self):
        self.closed = True
        self.server.closed += 1


class FakeServer:
    """``connect()`` gives a FakeConnection (or raises Down while ``down``); every statement is
    recorded in ``statements`` as ``(kind, sql, args)``, the committed rows in ``committed``;
    ``fail_next`` holds ``(predicate(sql, args), exception)`` pairs raised once at the first
    matching statement; the SELECTs of the reader answer ``select_names`` / ``select_rows``."""

    def __init__(self, table_exists=False):
        self.down = False
        self.table_exists = table_exists
        self.statements = []
        self.committed = []
        self.connections = []
        self.connects = 0
        self.closed = 0
        self.created = 0
        self.purge_counts = []
        self.select_names = []
        self.select_rows = []
        self.fail_next = []

    def connect(self):
        self.connects += 1
        if self.down:
            raise Down(2003, "Can't connect to MySQL server on 'db.example.org'")
        conn = FakeConnection(self)
        self.connections.append(conn)
        return conn

    def maybe_fail(self, sql, args):
        for i, (match, exc) in enumerate(self.fail_next):
            if match(sql, args):
                del self.fail_next[i]
                raise exc

    def statements_of(self, kind: str) -> list:
        return [s for s in self.statements if s[1].startswith(kind)]


def config(**over) -> AccessDatabaseConfig:
    return AccessDatabaseConfig(**{'host': 'db.example.org', 'user': 'sre_web', 'password': 'hunter2', 'name': 'sre',
                                   **over})


def make_sink(server, *, start=True, **over):
    """A sink on *server* with a fake clock (``now[0]``) and a recording, near-instant sleep."""
    sleeps, now = [], [1000.0]

    def sleep(seconds):
        sleeps.append(seconds)
        time.sleep(0.001)

    sink = DatabaseSink(config(**over), connect=server.connect, transient=(Down,), clock=lambda: now[0], sleep=sleep)
    if start:
        sink.start()
    return sink, sleeps, now


def wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("timeout")
        time.sleep(0.005)


def logins(rows) -> list:
    return [row[2] for row in rows]


# ---------------------------------------------------------------------------------------------
# the rows and the SQL
# ---------------------------------------------------------------------------------------------

class TestRowOf:
    def test_columns_and_details(self):
        row = row_of(1000.0, 'start', {'login': 'alice', 'addr': '10.0.1.7', 'lab': 'sre/dhcp.py', 'instructor': False,
                                       'host': 'a01', 'placement': 'load', 'result': 'created', 'rln': '1@@@d@@@alice',
                                       'status': 200, 'duration': 12.44})
        assert len(row) == len(D.COLUMNS)
        assert row[0] == datetime(1970, 1, 1, 0, 16, 40) and row[1] == 'start'
        assert row[2:9] == ('alice', '10.0.1.7', 'a01', '1@@@d@@@alice', 'sre/dhcp.py', '200', 12.44)
        assert json.loads(row[9]) == {'instructor': False, 'placement': 'load', 'result': 'created'}

    def test_nothing_bools_lists_and_sets(self):
        row = row_of(1000.0, 'session_close', {'login': '-', 'addr': None, 'projects': ['a', 'b'], 'anon': True,
                                               'empty': '', 'tags': {'y', 'x'}, 'n': 3, 'join': None, 'private': False})
        assert row[2] == '' and row[3] == '' and row[8] is None
        assert json.loads(row[9]) == {'projects': ['a', 'b'], 'anon': True, 'empty': '', 'tags': ['x', 'y'], 'n': 3,
                                      'join': None, 'private': False}
        assert row_of(1.0, 'x', {'login': True, 'addr': False})[2:4] == ('1', '0')
        assert json.loads(row_of(1.0, 'x', {})[9]) == {}

    def test_status_text_and_duration(self):
        row = row_of(1000.0, 'stop', {'status': 'abort', 'duration': True})
        assert row[7] == 'abort' and row[8] is None
        assert row_of(1000.0, 'stop', {'duration': 3})[8] == 3.0
        assert row_of(1000.0, 'stop', {'duration': '3'})[8] is None

    def test_truncation(self):
        row = row_of(1000.0, 'e' * 40, {'login': 'x' * 100, 'rln': 'r' * 300, 'status': 's' * 20})
        assert len(row[1]) == 32 and len(row[2]) == 64 and len(row[5]) == 255 and len(row[7]) == 16

    def test_milliseconds(self):
        assert row_of(1000.0019, 'x', {})[0].microsecond == 1000
        assert row_of(1000.9999, 'x', {})[0].microsecond == 999000
        assert utc_datetime(1761466323.123) == datetime(2025, 10, 26, 8, 12, 3, 123000)
        assert epoch(utc_datetime(1761466323.123)) == pytest.approx(1761466323.123, abs=1e-6)

    def test_over_long_details_and_odd_values(self):
        assert json.loads(row_of(1.0, 'x', {'ua': 'x' * 70000})[9]) == {'truncated': True, 'keys': ['ua']}
        assert json.loads(row_of(1.0, 'x', {'when': datetime(2026, 1, 2)})[9]) == {'when': '2026-01-02 00:00:00'}
        assert 'É' in row_of(1.0, 'x', {'name': 'Émile'})[9]          # not escaped


class TestSql:
    def test_statements(self):
        assert D.INSERT.count('%s') == len(D.COLUMNS)
        for sql in (D.DDL, D.PROBE, D.INSERT, D.PURGE, D.SELECT):
            assert sql.replace('%s', '').count('%') == 0, sql      # PyMySQL %-formats the statement
            assert '{table}' in sql
        ddl = D.DDL.format(table='t')
        assert ddl.startswith('CREATE TABLE IF NOT EXISTS `t`')
        for column in D.COLUMNS:
            assert re.search(rf'^\s+{column}\s', ddl, re.M), column
        assert 'DATETIME(3)' in ddl and 'utf8mb4' in ddl and 'KEY login_ts (login, ts)' in ddl
        assert D.PURGE.format(table='t') == "DELETE FROM `t` WHERE ts < %s LIMIT 10000"

    def test_escape_like(self):
        assert H.escape_like('50%_a!b') == '50!%!_a!!b' and H.escape_like('plain') == 'plain'

    def test_connector(self, monkeypatch):
        calls = []

        class Err:
            class OperationalError(Exception):
                pass

            class InterfaceError(Exception):
                pass

        fake = types.SimpleNamespace(connect=lambda **kw: calls.append(kw) or 'conn', err=Err)
        monkeypatch.setitem(sys.modules, 'pymysql', fake)
        monkeypatch.setitem(sys.modules, 'pymysql.err', Err)
        connect, transient = D.connector(config(connect_timeout=2.5))
        assert connect() == 'conn' and transient == (Err.OperationalError, Err.InterfaceError)
        kw = calls[0]
        assert (kw['host'], kw['port'], kw['unix_socket'], kw['user'], kw['password'], kw['database']) == \
            ('db.example.org', 3306, None, 'sre_web', 'hunter2', 'sre')
        assert kw['charset'] == 'utf8mb4' and kw['autocommit'] is False
        assert kw['connect_timeout'] == 3 and kw['read_timeout'] == 30 and kw['write_timeout'] == 30
        D.connector(config(host='', unix_socket='/run/mysqld/mysqld.sock', connect_timeout=45))[0]()
        assert calls[1]['host'] is None and calls[1]['unix_socket'] == '/run/mysqld/mysqld.sock'
        assert calls[1]['connect_timeout'] == 45 and calls[1]['read_timeout'] == 45

    def test_connector_without_the_driver(self, monkeypatch):
        monkeypatch.setitem(sys.modules, 'pymysql', None)
        with pytest.raises(ConfigError, match='PyMySQL'):
            D.connector(config())


# ---------------------------------------------------------------------------------------------
# the filters and the queries of the History page
# ---------------------------------------------------------------------------------------------

class TestFilters:
    def test_defaults_and_values(self):
        assert parse_filters({}) == {'limit': 100}
        filters = parse_filters({'login': ' alice ', 'addr': '10.0.1.', 'event': 'start, stop,start', 'host': 'a01',
                                 'rln': '@@@dhcp', 'lab': 'dhcp', 'since': '1000', 'until': '2000.5', 'before': '42',
                                 'limit': '500', 'ignored': 'x'})
        assert filters == {'login': 'alice', 'addr': '10.0.1.', 'event': ['start', 'stop'], 'host': 'a01',
                           'rln': '@@@dhcp', 'lab': 'dhcp', 'since': 1000.0, 'until': 2000.5, 'before': 42, 'limit': 500}
        assert parse_filters({'login': '', 'event': ' , '}) == {'limit': 100}
        assert len(parse_filters({'login': 'x' * 300})['login']) == H.MAX_TEXT

    def test_event_repeated(self):
        MultiDict = pytest.importorskip('multidict').MultiDict
        query = MultiDict([('event', 'start'), ('event', 'stop,eval')])
        assert parse_filters(query)['event'] == ['start', 'stop', 'eval']

    def test_limit(self):
        assert parse_filters({'limit': '5000'})['limit'] == H.MAX_LIMIT
        assert parse_filters({'limit': '1'})['limit'] == 1

    @pytest.mark.parametrize('query, fragment', [
        ({'since': 'yesterday'}, 'since'), ({'until': '2026-10-29'}, 'until'), ({'before': '-1'}, 'before'),
        ({'before': 'x'}, 'before'), ({'limit': '0'}, 'limit'), ({'limit': 'many'}, 'limit'),
    ])
    def test_bad_values(self, query, fragment):
        with pytest.raises(ValueError, match=fragment):
            parse_filters(query)


class TestBuildQuery:
    def test_no_filter(self):
        sql, params = build_select('t', {'limit': 100})
        assert sql == ("SELECT id, ts, event, login, addr, host, rln, lab, status, duration, details FROM `t` "
                       "ORDER BY id DESC LIMIT %s")
        assert params == [101]
        assert build_select('t', {})[1] == [H.DEFAULT_LIMIT + 1]

    @pytest.mark.parametrize('filters, fragment, values', [
        ({'login': 'ali'}, "login LIKE %s ESCAPE '!'", ['ali%']),
        ({'login': 'a_b%c'}, "login LIKE %s ESCAPE '!'", ['a!_b!%c%']),
        ({'addr': '10.0.1.'}, "addr LIKE %s ESCAPE '!'", ['10.0.1.%']),
        ({'event': ['start']}, "event IN (%s)", ['start']),
        ({'event': ['start', 'stop']}, "event IN (%s, %s)", ['start', 'stop']),
        ({'host': 'a01'}, "host = %s", ['a01']),
        ({'rln': 'dhcp'}, "rln LIKE %s ESCAPE '!'", ['%dhcp%']),
        ({'lab': 'sre/'}, "lab LIKE %s ESCAPE '!'", ['%sre/%']),
        ({'since': 1000.0}, "ts >= %s", [datetime(1970, 1, 1, 0, 16, 40)]),
        ({'until': 2000.0}, "ts < %s", [datetime(1970, 1, 1, 0, 33, 20)]),
        ({'before': 42}, "id < %s", [42]),
    ])
    def test_each_filter(self, filters, fragment, values):
        sql, params = build_select('t', {**filters, 'limit': 10})
        assert f" WHERE {fragment} ORDER BY id DESC LIMIT %s" in sql
        assert params == values + [11]
        assert sql.replace('%s', '').count('%') == 0

    def test_all_together(self):
        sql, params = build_select('access_log', {'login': 'a', 'addr': '1', 'event': ['x'], 'host': 'h', 'rln': 'r',
                                                  'lab': 'l', 'since': 1.0, 'until': 2.0, 'before': 9, 'limit': 5})
        where = sql.split(' WHERE ')[1].split(' ORDER BY')[0]
        assert where.split(' AND ') == ["login LIKE %s ESCAPE '!'", "addr LIKE %s ESCAPE '!'", "event IN (%s)",
                                        "host = %s", "rln LIKE %s ESCAPE '!'", "lab LIKE %s ESCAPE '!'", "ts >= %s",
                                        "ts < %s", "id < %s"]
        assert params == ['a%', '1%', 'x', 'h', '%r%', '%l%', utc_datetime(1.0), utc_datetime(2.0), 9, 6]


# ---------------------------------------------------------------------------------------------
# the writer thread
# ---------------------------------------------------------------------------------------------

class TestWriter:
    def test_connects_lazily_probes_creates_and_batches(self):
        server = FakeServer()
        sink, sleeps, now = make_sink(server, start=False)
        for i in range(3):
            assert sink.put(1000.0 + i, 'login', {'login': f'u{i}', 'addr': '10.0.0.1', 'mode': 'ldap'})
        assert server.connects == 0
        sink.start()
        assert sink.flush(5)
        assert server.connects == 1 and server.created == 1
        kinds = [(kind, sql.split()[0]) for kind, sql, args in server.statements[:3]]
        assert kinds == [('one', 'SELECT'), ('one', 'CREATE'), ('many', 'INSERT')]   # one batch of three
        assert len(server.statements[2][2]) == 3
        assert logins(server.committed) == ['u0', 'u1', 'u2'] and server.committed[0][0] == utc_datetime(1000.0)
        assert sink.status() == {'connected': True, 'last_error': None, 'queued': 0, 'dropped': 0}
        sink.close()
        assert not sink.alive and server.connections[0].closed and sleeps == []

    def test_existing_table_is_not_created(self):
        server = FakeServer(table_exists=True)
        sink, sleeps, now = make_sink(server)
        sink.put(1000.0, 'login', {'login': 'u'})
        assert sink.flush(5)
        assert server.created == 0 and server.statements[0][1] == "SELECT 1 FROM `access_log` LIMIT 0"
        assert not server.statements_of('CREATE')
        sink.close()

    def test_server_down_keeps_the_rows_and_warns_once(self, caplog):
        server = FakeServer()
        server.down = True
        sink, sleeps, now = make_sink(server)
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            for i in range(5):
                assert sink.put(1000.0, 'login', {'login': f'u{i}'})
            wait_until(lambda: len(sleeps) >= 4)
            status = sink.status()
            assert status['connected'] is False and "Can't connect" in status['last_error'] and status['queued'] == 0
            assert sleeps[:4] == [1.0, 2.0, 5.0, 10.0]
            assert not sink.flush(0.05)
            warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
            assert len(warnings) == 1 and "Can't connect" in warnings[0] and 'wait in memory' in warnings[0]
            server.down = False
            assert sink.flush(5)
            assert logins(server.committed) == [f'u{i}' for i in range(5)]
            assert sink.status()['connected'] is True and sink.status()['last_error'] is None
            infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO and 'writing again' in r.getMessage()]
            assert len(infos) == 1 and 'attempt(s)' in infos[0]
            assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1
        sink.close()

    def test_lost_connection_retries_the_batch_once(self):
        server = FakeServer(table_exists=True)
        server.fail_next.append((lambda sql, args: sql.startswith('INSERT'), Down(2013, "Lost connection to server")))
        sink, sleeps, now = make_sink(server, start=False)
        sink.put(1000.0, 'login', {'login': 'u0'})
        sink.put(1001.0, 'login', {'login': 'u1'})
        sink.start()
        assert sink.flush(5)
        assert server.connects == 2 and logins(server.committed) == ['u0', 'u1'] and sleeps == [1.0]
        assert server.connections[0].closed
        sink.close()

    def test_bad_row_is_dropped_not_the_batch(self, caplog):
        server = FakeServer(table_exists=True)
        server.fail_next.append((lambda sql, args: isinstance(args, list), Broken(1406, "Data too long")))
        server.fail_next.append((lambda sql, args: sql.startswith('INSERT') and not isinstance(args, list)
                                 and args[2] == 'bad', Broken(1406, "Data too long")))
        sink, sleeps, now = make_sink(server, start=False)
        for login in ('u0', 'bad', 'u2'):
            sink.put(1000.0, 'login', {'login': login})
        sink.start()
        with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
            assert sink.flush(5)
        assert logins(server.committed) == ['u0', 'u2'] and server.connects == 1 and sleeps == []
        messages = [r.getMessage() for r in caplog.records]
        assert any('written one by one' in m for m in messages)
        assert any('row dropped' in m and 'login=bad' in m for m in messages)
        sink.close()

    def test_queue_full_drops_the_oldest(self, caplog):
        server = FakeServer(table_exists=True)
        server.down = True
        sink, sleeps, now = make_sink(server, queue=3, start=False)
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            results = [sink.put(1000.0, 'login', {'login': f'u{i}'}) for i in range(5)]   # nobody takes them yet
            assert results == [True, True, True, False, False] and sink.dropped == 2
            assert sink.status()['queued'] == 3 and sink.status()['dropped'] == 2
            sink.start()
            wait_until(lambda: len(sleeps) >= 1)        # the writer holds the three rows, the server is down
            server.down = False
            assert sink.flush(5)
            assert logins(server.committed) == ['u2', 'u3', 'u4']
            messages = [r.getMessage() for r in caplog.records]
            assert len([m for m in messages if 'oldest are dropped' in m]) == 1
            assert any('writing again' in m and '2 row(s) dropped' in m for m in messages)
        sink.close()

    def test_purge_daily(self):
        server = FakeServer(table_exists=True)
        server.purge_counts = [D.PURGE_BATCH, 7]
        sink, sleeps, now = make_sink(server, keep=30)
        sink.put(1000.0, 'login', {'login': 'u'})
        assert sink.flush(5)
        wait_until(lambda: len(server.statements_of('DELETE')) == 2)
        cutoff = utc_datetime(1000.0 - 30 * 86400)
        assert [args for kind, sql, args in server.statements_of('DELETE')] == [(cutoff,), (cutoff,)]
        sink.put(1000.0, 'login', {'login': 'v'})
        assert sink.flush(5)
        time.sleep(0.05)
        assert len(server.statements_of('DELETE')) == 2                 # not before a day
        now[0] += D.PURGE_PERIOD
        sink.put(now[0], 'login', {'login': 'w'})
        assert sink.flush(5)
        wait_until(lambda: len(server.statements_of('DELETE')) == 3)
        assert server.statements_of('DELETE')[-1][2] == (utc_datetime(now[0] - 30 * 86400),)
        sink.close()
        forever = FakeServer(table_exists=True)
        sink, sleeps, now = make_sink(forever, keep=0)
        sink.put(1000.0, 'login', {'login': 'u'})
        assert sink.flush(5)
        sink.close()
        assert not forever.statements_of('DELETE')

    def test_purge_refused_is_warned_once_and_retried_tomorrow(self, caplog):
        server = FakeServer(table_exists=True)
        server.fail_next.append((lambda sql, args: sql.startswith('DELETE'), Broken(1142, "DELETE command denied")))
        sink, sleeps, now = make_sink(server, keep=30)
        with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
            sink.put(1000.0, 'login', {'login': 'u'})
            assert sink.flush(5)
            wait_until(lambda: any('purge' in r.getMessage() for r in caplog.records))
            sink.put(1000.0, 'login', {'login': 'v'})
            assert sink.flush(5)
            time.sleep(0.05)
        assert len(server.statements_of('DELETE')) == 1 and logins(server.committed) == ['u', 'v']
        assert len([r for r in caplog.records if 'purge' in r.getMessage()]) == 1
        sink.close()

    def test_close_flushes_then_stops(self):
        server = FakeServer(table_exists=True)
        sink, sleeps, now = make_sink(server, start=False)
        sink.put(1000.0, 'session_close', {'login': 'u', 'reason': 'shutdown'})
        sink.put(1000.0, 'session_close', {'login': 'v', 'reason': 'shutdown'})
        sink.start()
        sink.close()
        assert logins(server.committed) == ['u', 'v'] and not sink.alive and server.connections[0].closed
        sink.close()
        assert sink.put(1000.0, 'login', {'login': 'late'}) is False

    def test_close_with_the_server_down_gives_up(self, caplog):
        server = FakeServer()
        server.down = True
        sink, sleeps, now = make_sink(server)
        sink.put(1000.0, 'login', {'login': 'u'})
        sink.put(1000.0, 'login', {'login': 'v'})
        wait_until(lambda: len(sleeps) >= 1)
        with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
            t0 = time.monotonic()
            sink.close(timeout=2)
            assert time.monotonic() - t0 < 2 and not sink.alive
        assert any('2 row(s) not written at shutdown' in r.getMessage() for r in caplog.records)

    def test_describe(self):
        sink, sleeps, now = make_sink(FakeServer(), start=False)
        assert sink.describe() == "database sre on db.example.org:3306 (table access_log, 400 days kept)"
        assert 'hunter2' not in sink.describe()
        sink, sleeps, now = make_sink(FakeServer(), start=False, host='', unix_socket='/run/mysqld/mysqld.sock', keep=0)
        assert sink.describe() == "database sre on /run/mysqld/mysqld.sock (table access_log, rows kept forever)"


# ---------------------------------------------------------------------------------------------
# the reader
# ---------------------------------------------------------------------------------------------

class TestReader:
    @staticmethod
    def server_with_rows() -> FakeServer:
        server = FakeServer(table_exists=True)
        server.select_names = NAMES
        server.select_rows = [
            (3, datetime(2026, 10, 29, 9, 0, 0, 500000), 'start', 'alice', '10.0.1.7', 'a01', '1@@@d@@@alice',
             'sre/dhcp.py', '200', 12.4, '{"result":"created","instructor":false}'),
            (2, datetime(2026, 10, 29, 8, 59, 0), 'login', 'bob', '10.0.1.8', '', '', '', '', None, 'not json'),
            (1, datetime(2026, 10, 29, 8, 58, 0), 'denied', '', '10.0.2.3', '', '', '', '403', None, '[1, 2]'),
        ]
        return server

    def test_query(self):
        server = self.server_with_rows()
        db = AccessDatabase(config(), connect=server.connect)
        page = db.query_sync({'limit': 2, 'login': 'a'})
        assert page['more'] is True and [r['id'] for r in page['rows']] == [3, 2]
        first = page['rows'][0]
        assert first['ts'] == epoch(datetime(2026, 10, 29, 9, 0, 0, 500000)) and isinstance(first['ts'], float)
        assert first['details'] == {'result': 'created', 'instructor': False} and first['duration'] == 12.4
        assert page['rows'][1]['details'] == {} and page['rows'][1]['duration'] is None
        kind, sql, args = server.statements[-1]
        assert kind == 'one' and "login LIKE %s ESCAPE '!'" in sql and args == ['a%', 3]
        assert server.connections[-1].closed
        page = asyncio.run(db.query({'limit': 5}))
        assert page['more'] is False and len(page['rows']) == 3 and page['rows'][2]['details'] == {}
        assert page['rows'][2]['login'] == '' and page['rows'][2]['status'] == '403'

    def test_errors(self):
        server = self.server_with_rows()
        server.down = True
        db = AccessDatabase(config(), connect=server.connect)
        with pytest.raises(HistoryError, match="Can't connect"):
            db.query_sync({'limit': 5})
        server.down = False
        server.fail_next.append((lambda sql, args: sql.startswith('SELECT id'), Broken(1146, "no table")))
        with pytest.raises(HistoryError, match='no table'):
            db.query_sync({'limit': 5})
        assert server.connections[-1].closed


# ---------------------------------------------------------------------------------------------
# the hook of AccessLog and the event names
# ---------------------------------------------------------------------------------------------

class TestAccessLogWithDatabase:
    @staticmethod
    def cfg(**over) -> AccessLogConfig:
        return AccessLogConfig(journal=False, database=config(**over))

    def test_rows_follow_the_lines(self):
        server = FakeServer()
        access = A.AccessLog(self.cfg(), [], clock=lambda: 1000.0, connect=(server.connect, (Down,)))
        access.open()
        try:
            assert access.db is not None and access.history is not None
            assert access.describe() == "the database sre on db.example.org:3306 (table access_log, 400 days kept)"
            access.record('login', login='alice', addr='10.0.1.7', mode='ldap', role='student', anon=False, name='Alice')
            assert access.db.flush(5)
            access.clock = lambda: 2000.0                   # replaced after open(): the sink follows
            access.record('denied', login='-', addr='10.0.2.3', method='GET', path='/watch', status=403)
            assert access.db.flush(5)
        finally:
            access.close()
        assert access.db is None and access.history is None
        assert server.committed[0][:4] == (utc_datetime(1000.0), 'login', 'alice', '10.0.1.7')
        assert json.loads(server.committed[0][9]) == {'mode': 'ldap', 'role': 'student', 'anon': False, 'name': 'Alice'}
        assert server.committed[1][:3] == (utc_datetime(2000.0), 'denied', '') and server.committed[1][7] == '403'
        assert server.connections[0].closed

    def test_open_twice_keeps_one_writer(self):
        server = FakeServer(table_exists=True)
        access = A.AccessLog(self.cfg(), [], connect=(server.connect, (Down,)))
        access.open()
        first = access.db
        access.open()
        try:
            assert access.db is not first and not first.alive and access.db.alive
        finally:
            access.close()

    def test_disabled_and_missing_driver(self, monkeypatch):
        access = A.AccessLog(AccessLogConfig(journal=False), [])
        access.open()
        try:
            assert access.db is None and access.history is None and 'database' not in access.describe()
        finally:
            access.close()
        monkeypatch.setitem(sys.modules, 'pymysql', None)
        access = A.AccessLog(self.cfg(), [])
        with pytest.raises(ConfigError, match='PyMySQL'):
            access.open()
        access.close()


class TestEvents:
    def test_all_events_cover_the_lines(self):
        source = Path(A.__file__).read_text()
        literals = set(re.findall(r"record\('([a-z_]+)'", source))
        assert literals <= set(A.ALL_EVENTS), literals - set(A.ALL_EVENTS)
        assert {e for e in A.EVENTS.values() if e not in A.WS_EVENTS} <= set(A.ALL_EVENTS)
        assert {'project_open', 'terminal_close', 'display_open', 'history', 'denied', 'session_close',
                'login_failed', 'admin', 'start'} <= set(A.ALL_EVENTS)
        assert 'project' not in A.ALL_EVENTS and list(A.ALL_EVENTS) == sorted(set(A.ALL_EVENTS))
        assert A.event_for('GET', '/api/history') == 'history' and ('GET', '/api/history') not in A.KEEPALIVE
