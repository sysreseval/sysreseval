"""Tests of the archives of the evaluations in the database (sreweb.portal.archives) without a
server: the rows built from the records of the agents, the filters and the SQL of the Archives
page, the sink on the archives table (a fake connection), the collector on a fake pool, the
``[archives]`` configuration.  The portal and the agent together are exercised by
test_web_portal.py (TestArchives), a real MariaDB / MySQL by test_web_accessdb_live.py."""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.config import ArchivesConfig, ConfigError, HostConfig, web_config_from_dict  # noqa: E402
from sreweb.portal import archives as R  # noqa: E402
from sreweb.portal.accessdb import DatabaseSink, utc_datetime  # noqa: E402
from sreweb.portal.accesshistory import HistoryError  # noqa: E402
from sreweb.portal.pool import HostStatus  # noqa: E402
from test_web_accessdb import FakeServer, Down, Broken, config, wait_until  # noqa: E402

RLN = '20261025100000@@@sre@dhcp.py@@@alice'
NAME = f'20261025100102_{RLN}.zst'


def record(**over) -> dict:
    """A record of the agent (SRE.archive_summary.archive_record + managed)."""
    r = {
        'archive': NAME, 'running_lab_name': RLN, 'lab': 'sre/dhcp.py', 'eval_date': '2026-10-25T10:01:02+02:00',
        're_eval_date': None, 'login': 'alice', 'fullname': 'Alice A', 'group': 'INFO1', 'email': 'a@x.org',
        'hostname': 'pool1', 'language': 'fr', 'exam': False, 'exam_started_at': None, 'exam_duration': None,
        'exam_time_remaining': None, 'auto_eval_count': 3, 'answers_updated_at': '20261025100030',
        'grade': 1.0, 'max_grade': 3.0, 'mark': 6.7, 'maximum_mark': 20.0,
        'self_grade': 2.0, 'self_max_grade': 3.0, 'self_mark': 13.3,
        'errors': [{'category': 'ERROR', 'text': 'm1 unreachable'}, {'category': 'WARNING', 'text': 'slow'}],
        'error_count': 1, 'warning_count': 1,
        'elements': [{'key': '{"en": "both"}', 'title': {'en': 'both', 'fr': 'les deux'}, 'description': '', 'grade': 1.0,
                      'max_grade': 2.0, 'grade_letter': None, 'part': None, 'bonus': False, 'scope': 3}],
        'parts': [], 'managed': True,
    }
    r.update(over)
    return r


class TestRows:
    def test_row_of_record(self):
        row = R.row_of_record('a01', record())
        assert len(row) == len(R.COLUMNS)
        assert row[0] == datetime(2026, 10, 25, 8, 1, 2)                  # UTC (the record says +02:00)
        assert row[1:9] == ('a01', NAME, RLN, 'sre/dhcp.py', 'alice', 'Alice A', 'INFO1', 'pool1')
        assert row[9:17] == (1.0, 3.0, 6.7, 20.0, 1, 1, 0, 3)
        details = json.loads(row[17])
        assert set(details) == set(R.DETAIL_KEYS) and details['elements'][0]['title'] == {'en': 'both', 'fr': 'les deux'}
        assert details['self_mark'] == 13.3 and details['managed'] is True and details['errors'][1]['category'] == 'WARNING'
        # the widths, the exam flag, the missing values
        long = record(archive='x' * 400, fullname='n' * 300, exam=True, mark=None, maximum_mark=None, auto_eval_count=None)
        row = R.row_of_record('h' * 70, long)
        assert (len(row[1]), len(row[2]), len(row[6])) == (64, 300, 255) and row[11:13] == (None, None)
        assert row[15] == 1 and row[16] is None
        assert R.row_of_record('a01', {'archive': NAME, 'running_lab_name': RLN})[9:17] == (0.0, 0.0, None, None, 0, 0, 0, None)
        # what an agent may send: a lone surrogate in a name, NaN / Infinity grades (MySQL refuses
        # the row): the text cleaned, the numbers defaulted (security review, last Low finding)
        odd = R.row_of_record('a01', {'archive': NAME, 'running_lab_name': RLN, 'fullname': 'Al\ud800ice',
                                      'grade': float('nan'), 'max_grade': float('inf'), 'mark': '12.5',
                                      'elements': [{'label': 'x\udc00'}]})
        assert odd[6] == 'Al?ice' and odd[9:13] == (0.0, 0.0, 12.5, None)
        assert '\ud800' not in odd[-1] and '\udc00' not in odd[-1] and '"x?"' in odd[-1]
        for value in odd:
            if isinstance(value, str):
                value.encode('utf-8')
        assert R._float('nan') is None and R._float('-inf', 0.0) == 0.0 and R._float(7) == 7.0

    def test_record_time(self):
        assert R.record_time(record()) == datetime(2026, 10, 25, 8, 1, 2, tzinfo=timezone.utc).timestamp()
        local = datetime(2026, 10, 25, 10, 1, 2).timestamp()               # a naive date: the portal's zone
        assert R.record_time(record(eval_date='2026-10-25T10:01:02')) == local
        assert R.record_time(record(eval_date='garbage')) == local         # the prefix of the name, local too
        assert abs(R.record_time({'archive': 'junk'}) - time.time()) < 5

    def test_details_capped(self):
        big = record(elements=[dict(record()['elements'][0], description='x' * 300) for _ in range(5000)])
        row = R.row_of_record('a01', big)
        details = json.loads(row[17])
        assert len(row[17].encode()) <= R.MAX_DETAILS and details['truncated'] is True
        assert 'elements' not in details and 'parts' not in details and details['self_mark'] == 13.3

    def test_row_to_dict(self):
        names = ['id', *R.COLUMNS]
        row = (7, *R.row_of_record('a01', record()))
        data = R.row_to_dict(names, row)
        assert data['id'] == 7 and data['ts'] == datetime(2026, 10, 25, 8, 1, 2, tzinfo=timezone.utc).timestamp()
        assert data['group'] == 'INFO1' and 'grp' not in data and data['exam'] is False
        assert data['details']['elements'][0]['key'] == '{"en": "both"}' and data['mark'] == 6.7
        short = R.row_to_dict(names[:-1], row[:-1])
        assert 'details' not in short and short['login'] == 'alice'
        bad = R.row_to_dict(names, row[:-1] + (b'{not json',))
        assert bad['details'] == {}


class TestFilters:
    def test_defaults_and_values(self):
        f = R.parse_archive_filters({})
        assert f == {'show': 'project', 'limit': 100}
        f = R.parse_archive_filters({'student': ' Ali ', 'group': 'INFO1', 'lab': 'dhcp', 'host': 'a01',
                                     'since': '1761400000', 'until': '1761500000.5', 'exam': '1', 'show': 'all',
                                     'before': '42', 'limit': '500'})
        assert f == {'student': 'Ali', 'group': 'INFO1', 'lab': 'dhcp', 'host': 'a01', 'since': 1761400000.0,
                     'until': 1761500000.5, 'exam': True, 'show': 'all', 'before': 42, 'limit': 500}
        assert R.parse_archive_filters({'exam': '0'})['exam'] is False
        assert R.parse_archive_filters({'exam': ''}).get('exam') is None
        assert R.parse_archive_filters({}, default_show='student')['show'] == 'student'
        assert R.parse_archive_filters({'show': 'project'}, default_show='student')['show'] == 'project'
        assert len(R.parse_archive_filters({'student': 'x' * 400})['student']) == 255

    @pytest.mark.parametrize('query, key', [
        ({'since': 'yesterday'}, 'since'), ({'until': '2026-10-29'}, 'until'), ({'exam': 'maybe'}, 'exam'),
        ({'since': 'nan'}, 'since'), ({'until': 'inf'}, 'until'), ({'since': '-1'}, 'since'), ({'until': '1e30'}, 'until'),
        ({'show': 'best'}, 'show'), ({'before': 'x'}, 'before'), ({'limit': '0'}, 'limit'), ({'limit': '5000'}, 'limit'),
    ])
    def test_refused(self, query, key):
        with pytest.raises(ValueError, match=key):
            R.parse_archive_filters(query)


class TestSelect:
    def test_filters_and_show(self):
        f = R.parse_archive_filters({'student': 'al_i', 'group': 'INFO1', 'lab': 'dhcp%', 'host': 'a01',
                                     'since': '1761400000', 'until': '1761500000', 'exam': '1', 'before': '42',
                                     'limit': '2'})
        sql, params = R.build_archives_select('archives', f)
        assert sql.startswith('SELECT t.id, t.ts, t.host, t.archive, t.rln, t.lab, t.login, t.fullname, t.grp') \
            and 't.details' not in sql
        assert "(t.login LIKE %s ESCAPE '!' OR t.fullname LIKE %s ESCAPE '!')" in sql and 't.grp = %s' in sql
        assert "t.lab LIKE %s ESCAPE '!'" in sql and 't.host = %s' in sql and 't.exam = %s' in sql
        assert 't.ts >= %s' in sql and 't.ts < %s' in sql and 't.id < %s' in sql
        # the newest of each project among the rows of the window, the host and the exam flag
        assert ("NOT EXISTS (SELECT 1 FROM `archives` t2 WHERE t2.rln = t.rln AND t2.id > t.id AND t2.ts >= %s "
                "AND t2.ts < %s AND t2.host = %s AND t2.exam = %s)") in sql
        assert sql.endswith(' ORDER BY t.id DESC LIMIT %s')
        since, until = utc_datetime(1761400000), utc_datetime(1761500000)
        assert params == ['al!_i%', '%al!_i%', 'INFO1', '%dhcp!%%', since, until, 'a01', 1, since, until, 'a01', 1, 42, 3]
        student = R.build_archives_select('archives', R.parse_archive_filters({'show': 'student'}))
        assert student[0].endswith("WHERE NOT EXISTS (SELECT 1 FROM `archives` t2 WHERE t2.login = t.login "
                                   "AND t2.lab = t.lab AND t2.id > t.id) ORDER BY t.id DESC LIMIT %s") and student[1] == [101]
        every = R.build_archives_select('archives', R.parse_archive_filters({'show': 'all', 'limit': '500'}))
        assert 'WHERE' not in every[0] and every[1] == [501]

    def test_summary_and_fixed_statements(self):
        sql, params = R.build_summary_select('t_arch', R.parse_archive_filters({'lab': 'dhcp'}, default_show='student'), 10)
        assert sql.startswith('SELECT ') and ', t.details FROM `t_arch` t WHERE' in sql
        assert sql.endswith(' ORDER BY t.login, t.lab, t.id DESC LIMIT %s') and params == ['%dhcp%', 11]
        for statement in (R.DDL, R.INSERT, R.SELECT_ROWS, R.SELECT_FULL, R.CURSORS, R.LABS, R.GROUPS, sql):
            assert '{table}' in statement or '`t_arch`' in statement
            assert not any(c == '%' and statement[i + 1] != 's' for i, c in enumerate(statement[:-1])), statement
        assert R.INSERT.count('%s') == len(R.COLUMNS) and R.INSERT.startswith('INSERT IGNORE INTO `{table}` (ts, host, archive')
        assert 'UPDATE' not in R.INSERT                      # the account has no UPDATE privilege
        assert 'UNIQUE KEY archive (archive)' in R.DDL and 'details         MEDIUMTEXT' in R.DDL
        for column in R.COLUMNS:
            assert f'\n  {column} ' in R.DDL, column


class TestReports:
    """The downloads of the page: the rows back into records, the request body, the SQL."""

    def test_record_of_row_round_trip(self):
        rec = record()
        names = ['id', *R.COLUMNS]
        back = R.record_of_row(R.row_to_dict(names, (7, *R.row_of_record('a01', rec))))
        assert back['id'] == 7 and back['host'] == 'a01' and back['archive'] == NAME
        assert back['running_lab_name'] == RLN and back['lab'] == 'sre/dhcp.py'
        assert back['eval_date'] == '2026-10-25T08:01:02+00:00'      # the UTC ts of the row, aware
        for key in ('login', 'fullname', 'group', 'hostname', 'grade', 'max_grade', 'mark', 'maximum_mark', 'exam',
                    'auto_eval_count', 'error_count', 'warning_count', 'elements', 'parts', 'errors', 'self_grade',
                    'self_max_grade', 'self_mark', 'email', 'language', 'exam_time_remaining', 'managed'):
            assert back[key] == rec[key], key
        assert 'details' not in back and 'rln' not in back and 'grp' not in back and 'ts' not in back
        # a row whose details were truncated keeps the counts and says so
        big = record(elements=[dict(record()['elements'][0], description='x' * (R.MAX_DETAILS + 1))])
        back = R.record_of_row(R.row_to_dict(names, (8, *R.row_of_record('a01', big))))
        assert back['truncated'] is True and 'elements' not in back and back['error_count'] == 1
        # the rows of the page (without details) give a record too
        assert R.record_of_row(R.row_to_dict(['id', *R.COLUMNS[:-1]], (9, *R.row_of_record('a01', rec)[:-1])))['login'] == 'alice'

    def test_parse_report_request(self):
        kind, ids, options = R.parse_report_request({'kind': 'sheet', 'ids': [3, 1, 3], 'options': {'no_parts': True}})
        assert (kind, ids) == ('sheet', [3, 1])
        assert options == {'all_evaluations': True, 'separate_instances': False, 'bonus_in_prefix': False,
                           'no_timeline': False, 'remaining_time': False, 'no_parts': True}
        assert R.parse_report_request({'kind': 'outline', 'ids': [1]})[2]['all_evaluations'] is True
        assert R.parse_report_request({'kind': 'outline', 'ids': [1], 'options': {'all_evaluations': False}})[2]['all_evaluations'] is False
        for body, key in (([], 'object'), ({'kind': 'pdf', 'ids': [1]}, 'kind'), ({'kind': 'sheet'}, 'ids'),
                          ({'kind': 'sheet', 'ids': []}, 'ids'), ({'kind': 'sheet', 'ids': ['1']}, 'ids'),
                          ({'kind': 'sheet', 'ids': [-1]}, 'ids'), ({'kind': 'sheet', 'ids': [True]}, 'ids'),
                          ({'kind': 'sheet', 'ids': list(range(R.REPORT_MAX_IDS + 1))}, 'at most'),
                          ({'kind': 'sheet', 'ids': [1], 'options': []}, 'options'),
                          ({'kind': 'sheet', 'ids': [1], 'options': {'bogus': True}}, 'bogus'),
                          ({'kind': 'sheet', 'ids': [1], 'options': {'no_parts': 'yes'}}, 'no_parts')):
            with pytest.raises(ValueError, match=key):
                R.parse_report_request(body)

    def test_report_select(self):
        sql, params = R.build_report_select('archives', [5, 9], all_evaluations=True, limit=100)
        assert sql.startswith('SELECT t.id, t.ts') and ', t.details FROM `archives` t WHERE' in sql
        assert sql.endswith("WHERE t.rln IN (SELECT s.rln FROM `archives` s WHERE s.id IN (%s, %s)) "
                            "ORDER BY t.rln, t.id LIMIT %s")
        assert params == [5, 9, 101]
        sql, params = R.build_report_select('archives', [5], all_evaluations=False, limit=10)
        assert sql.endswith('WHERE t.id IN (%s) ORDER BY t.rln, t.id LIMIT %s') and params == [5, 11]
        assert not any(c == '%' and sql[i + 1] != 's' for i, c in enumerate(sql[:-1]))

    def test_report_rows(self):
        server = FakeServer(table_exists=True)
        server.select_names = ['id', *R.COLUMNS]
        server.select_rows = [(5, *R.row_of_record('a01', record())), (6, *R.row_of_record('a01', record(login='bob')))]
        reader = R.ArchiveDatabase('archives', connect=server.connect)
        page = reader.report_rows_sync([5], all_evaluations=True, limit=10)
        assert [r['login'] for r in page['rows']] == ['alice', 'bob'] and page['truncated'] is False
        assert page['rows'][0]['details']['elements'][0]['title'] == {'en': 'both', 'fr': 'les deux'}
        assert reader.report_rows_sync([5], all_evaluations=False, limit=1) == {'rows': page['rows'][:1], 'truncated': True}


class TestSink:
    """The sink of accessdb.py on the archives table: its own statements and words."""

    def test_rows_written_in_the_archives_table(self, caplog):
        server = FakeServer()
        cfg = config(table='access_log')
        sink = DatabaseSink(cfg, connect=server.connect, transient=(Down,), spec=R.table_spec(ArchivesConfig()))
        sink.start()
        assert sink.table == 'archives' and sink.describe() == 'database sre on db.example.org:3306 (table archives, rows kept forever)'
        assert sink.put_row(R.row_of_record('a01', record()))
        assert sink.put_row(R.row_of_record('a01', record(archive='x' + NAME, login='bob')))
        assert sink.flush(5)
        assert server.created == 1 and server.statements_of('CREATE TABLE')[0][1].startswith('CREATE TABLE IF NOT EXISTS `archives`')
        kind, sql, rows = server.statements_of('INSERT')[-1]
        assert kind == 'many' and sql.startswith('INSERT IGNORE INTO `archives` (ts, host, archive') and len(rows) == 2
        assert [r[5] for r in server.committed] == ['alice', 'bob']
        assert not server.statements_of('DELETE')                      # keep = 0: no purge
        # a refused row is named by its archive and login
        server.fail_next.append((lambda sql, args: sql.startswith('INSERT') and isinstance(args, list), Broken(1406, 'too long')))
        server.fail_next.append((lambda sql, args: sql.startswith('INSERT') and isinstance(args, tuple), Broken(1406, 'too long')))
        with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
            sink.put_row(R.row_of_record('a01', record(archive='y' + NAME, login='carol')))
            assert sink.flush(5)
        assert any('archives database: row dropped' in r.message and f'archive=y{NAME} login=carol' in r.message
                   for r in caplog.records)
        sink.close()

    def test_purge_of_keep_days(self):
        server = FakeServer(table_exists=True)
        now = [time.time()]
        sink = DatabaseSink(config(), connect=server.connect, transient=(Down,), clock=lambda: now[0],
                            spec=R.table_spec(ArchivesConfig(keep=30)))
        sink.start()
        server.purge_counts = [3]
        sink.put_row(R.row_of_record('a01', record()))
        wait_until(lambda: server.statements_of('DELETE'))
        kind, sql, args = server.statements_of('DELETE')[0]
        assert sql.startswith('DELETE FROM `archives` WHERE ts < %s') and args == (utc_datetime(now[0] - 30 * 86400),)
        sink.close()


class FakeResponse:
    def __init__(self, status, data):
        self.status = status
        self.data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self):
        return self.data

    async def text(self):
        return json.dumps(self.data)


class FakeSession:
    """``get()`` answers ``pages(after)`` -> (status, data) and records the calls."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append((url, params['after'], params['limit']))
        status, data = self.pages(params['after'])
        return FakeResponse(status, data)


class FakePool:
    def __init__(self, session, names=('a01',)):
        self.session = session
        self.hosts = {n: HostConfig(name=n, url=f'http://{n}:8451', token='t' * 32) for n in names}
        self.status = {n: HostStatus(reachable=True) for n in names}

    @staticmethod
    def headers(host, identity=None):
        return {'Authorization': 'Bearer x'}


class FakeSink:
    def __init__(self):
        self.rows = []

    def put_row(self, row):
        self.rows.append(row)
        return True


class FakeReader:
    def __init__(self, cursors=None, fail=False):
        self._cursors = cursors or {}
        self.fail = fail
        self.calls = 0

    async def cursors(self):
        self.calls += 1
        if self.fail:
            raise HistoryError("down")
        return dict(self._cursors)


def run(coro):
    return asyncio.run(coro)


class TestCollector:
    def test_cursors_then_pages(self, caplog):
        """The cursors read once from the database, then the pages of each host until the agent
        says no more, the cursor following the last name listed (an unreadable archive gives no
        record but is passed), the rows queued in the sink."""
        names = [f'2026102510010{i}_{RLN}.zst' for i in range(4)]

        def pages(after):
            listed = [n for n in names if n > after][:2]
            records = [record(archive=n) for n in listed if not n.startswith('20261025100102')]  # one unreadable
            return 200, {'archives': records, 'more': len([n for n in names if n > after]) > 2, 'last': listed[-1] if listed else ''}

        session = FakeSession(pages)
        pool = FakePool(session, names=('a01', 'b02'))
        pool.status['b02'] = HostStatus(reachable=False)
        sink, reader = FakeSink(), FakeReader({'a01': names[0], 'zzz': 'old'})
        collector = R.ArchiveCollector(pool, sink, reader, interval=1.0, page=2)

        async def go():
            await collector.tick()
            assert reader.calls == 1 and collector.cursors['a01'] == names[3] and collector.cursors['zzz'] == 'old'
            assert [c[1] for c in session.calls] == [names[0], names[2]] and all(c[2] == '2' for c in session.calls)
            assert [r[2] for r in sink.rows] == [names[1], names[3]] and collector.collected == 2
            assert all(c[0].startswith('http://a01:') for c in session.calls)         # b02 is not reachable
            await collector.tick()                                                   # nothing new
            assert reader.calls == 1 and len(session.calls) == 3 and len(sink.rows) == 2 and collector.ticks == 2
            assert collector.status() == {'hosts': 2, 'collected': 2, 'ticks': 2, 'cursors_known': True}
        run(go())

    def test_calls_per_tick_cap(self):
        names = [f'20261025{i:06d}_{RLN}.zst' for i in range(10)]

        def pages(after):
            listed = [n for n in names if n > after][:1]
            return 200, {'archives': [record(archive=n) for n in listed], 'more': len(listed) == 1
                         and listed[-1] != names[-1], 'last': listed[-1] if listed else ''}

        session = FakeSession(pages)
        sink = FakeSink()
        collector = R.ArchiveCollector(FakePool(session), sink, FakeReader(), page=1, calls_per_tick=3)

        async def go():
            await collector.tick()
            assert len(session.calls) == 3 and len(sink.rows) == 3 and collector.cursors['a01'] == names[2]
            await collector.tick()
            assert len(sink.rows) == 6
        run(go())

    def test_database_down_then_agent_failures(self, caplog):
        """Nothing is collected until the cursors are known; a host that fails (an agent without
        the route, a bad answer) is warned about once and skipped."""
        answers = {'a01': (404, {'error': 'not found'}), 'b02': (200, ['not', 'a', 'dict'])}
        session = FakeSession(lambda after: (200, {'archives': []}))
        pool = FakePool(session, names=('a01', 'b02'))
        session.get = lambda url, headers=None, params=None, timeout=None: FakeResponse(*answers[url.split('/')[2].split(':')[0]])
        reader = FakeReader(fail=True)
        collector = R.ArchiveCollector(pool, FakeSink(), reader)

        async def go():
            with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
                await collector.tick()
                await collector.tick()
                assert collector.cursors is None and reader.calls == 2 and collector.ticks == 0
                assert sum('cannot read the cursors' in r.message for r in caplog.records) == 1    # warned once
                reader.fail = False
                await collector.tick()
                await collector.tick()
            assert collector.cursors == {} and collector.ticks == 2
            messages = [r.message for r in caplog.records]
            assert sum('a01: no /v1/archives' in m for m in messages) == 1
            assert sum('b02: GET /v1/archives: not a JSON object' in m for m in messages) == 1
        run(go())

    def test_start_and_stop(self):
        session = FakeSession(lambda after: (200, {'archives': [], 'more': False, 'last': ''}))
        collector = R.ArchiveCollector(FakePool(session), FakeSink(), FakeReader(), interval=0.02)

        async def go():
            collector.start()
            await asyncio.sleep(0.1)
            await collector.stop()
            assert collector.ticks >= 2 and collector._task is None
            ticks = collector.ticks
            await asyncio.sleep(0.05)
            assert collector.ticks == ticks
        run(go())


class TestConfig:
    BASE = {'secret': 's' * 32}

    def test_defaults_and_values(self):
        cfg = web_config_from_dict(dict(self.BASE))
        assert cfg.archives == ArchivesConfig() and cfg.archives.table == 'archives' and cfg.archives.keep == 0
        cfg = web_config_from_dict({**self.BASE, 'archives': {'table': 'evals', 'keep': 30, 'poll_interval': '2m'}})
        assert (cfg.archives.table, cfg.archives.keep, cfg.archives.poll_interval) == ('evals', 30, 120.0)

    @pytest.mark.parametrize('data, key', [
        ({'archives': 3}, 'archives'), ({'archives': {'typo': 1}}, 'typo'), ({'archives': {'table': 'drop;'}}, 'table'),
        ({'archives': {'table': ''}}, 'table'), ({'archives': {'keep': -1}}, 'keep'), ({'archives': {'keep': True}}, 'keep'),
        ({'archives': {'poll_interval': 0}}, 'poll_interval'), ({'archives': {'poll_interval': 'soon'}}, 'poll_interval'),
    ])
    def test_refused(self, data, key):
        with pytest.raises(ConfigError, match=key):
            web_config_from_dict({**self.BASE, **data})
