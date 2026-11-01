"""Tests of the Statistics view of the History page (sreweb.portal.accessstats) without a
server: the window and the query it builds, the lab of a running lab name, the interval maths,
the distribution, and compute_statistics on hand-built rows and open sessions (the clipping,
the union of a user's sessions, the roles, the groups, the labs, the starts and evaluations,
the peak, the sort orders, an empty period).  The route is exercised by
test_web_portal.py::TestHistory."""
import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.portal import accessstats as ST  # noqa: E402
from sreweb.portal.accessdb import utc_datetime  # noqa: E402
from sreweb.portal.accesshistory import parse_filters, build_select  # noqa: E402
from sreweb.portal.accesslog import iso_time  # noqa: E402

H = 3600.0
T0 = 1761465600.0                     # 2026-10-26 08:00 UTC
SINCE, UNTIL = T0, T0 + 8 * H         # an eight-hour period
DHCP_ALICE = '20261026090000@@@sre@dhcp.py@@@alice'
DHCP_FRANK = '20261026100000@@@sre@dhcp.py@@@frank'


def session_row(id, login, addr, start, duration, *, role='student', name='', group='', projects=(), requests=1,
                since=True, closed=None):
    """A session_close row as row_to_dict gives it (the closing line 60 s after the end)."""
    details = {'reason': 'idle', 'requests': requests, 'projects': list(projects)}
    if role:
        details['role'] = role
    if name:
        details['name'] = name
    if group:
        details['group'] = group
    if since:
        details['since'] = iso_time(start)
    ts = closed if closed is not None else start + (duration or 0) + 60
    return {'id': id, 'ts': ts, 'event': 'session_close', 'login': login, 'addr': addr, 'host': '', 'rln': '',
            'lab': '', 'status': '', 'duration': duration, 'details': details}


def row(id, event, login, ts, *, rln='', lab='', status='', duration=None, **details):
    return {'id': id, 'ts': ts, 'event': event, 'login': login, 'addr': '10.0.1.1', 'host': 'a01', 'rln': rln,
            'lab': lab, 'status': status, 'duration': duration, 'details': details}


def open_session(login, addr, start, end, **over):
    return {'id': None, 'login': login, 'name': '', 'role': 'student', 'group': '', 'addr': addr, 'start': start,
            'end': end, 'closed': None, 'duration': end - start, 'requests': 1, 'projects': [], 'reason': None,
            'sockets': 1, **over}


class TestWindow:
    def test_defaults_and_prefixes(self):
        now = 1000000.0
        assert ST.statistics_window({'limit': 100}, now) == {'since': now - ST.DEFAULT_PERIOD, 'until': now}
        window = ST.statistics_window(parse_filters({'login': 'ali', 'addr': '10.', 'event': 'start', 'host': 'a01',
                                                     'rln': 'x', 'lab': 'y', 'since': '500', 'before': '42',
                                                     'limit': '2'}), now)
        assert window == {'login': 'ali', 'addr': '10.', 'since': 500.0, 'until': now}
        assert ST.statistics_window({'until': 800.0}, now) == {'since': 800.0 - ST.DEFAULT_PERIOD, 'until': 800.0}
        assert ST.statistics_window({'since': 1.0, 'until': 2.0}, now) == {'since': 1.0, 'until': 2.0}

    def test_empty_period_refused(self):
        with pytest.raises(ValueError, match='since'):
            ST.statistics_window({'since': 2000.0, 'until': 1000.0}, 5000.0)
        with pytest.raises(ValueError):
            ST.statistics_window({'since': 1000.0, 'until': 1000.0}, 5000.0)
        with pytest.raises(ValueError):
            ST.statistics_window({'since': 9000.0}, 5000.0)         # after now

    def test_query(self):
        window = ST.statistics_window({'login': 'b', 'since': 1000.0, 'until': 2000.0}, 5000.0)
        query = ST.statistics_query(window)
        assert query == {'login': 'b', 'since': 1000.0, 'until': 2000.0 + ST.SLACK,
                         'event': ['session_close', 'project_close', 'start', 'eval'], 'limit': ST.MAX_ROWS}
        sql, params = build_select('t', query)
        where = sql.split(' WHERE ')[1].split(' ORDER BY')[0]
        assert where.split(' AND ') == ["login LIKE %s ESCAPE '!'", "event IN (%s, %s, %s, %s)", "ts >= %s", "ts < %s"]
        assert params == ['b%', 'session_close', 'project_close', 'start', 'eval', utc_datetime(1000.0),
                          utc_datetime(2000.0 + ST.SLACK), ST.MAX_ROWS + 1]
        assert ST.SLACK == 2 * 86400 and ST.DEFAULT_PERIOD == 86400


class TestHelpers:
    def test_lab_of_rln(self):
        assert ST.lab_of_rln(DHCP_ALICE) == 'sre/dhcp.py'
        assert ST.lab_of_rln('1761466323@@@dhcp@@@alice') == 'dhcp'
        assert ST.lab_of_rln('1@@@em@s4@bgp.py@@@bob') == 'em/s4/bgp.py'
        assert ST.lab_of_rln('oops') == '' and ST.lab_of_rln('') == '' and ST.lab_of_rln(None) == ''
        assert ST.lab_of_rln('1@@@@@@bob') == '' and ST.lab_of_rln('a@@@b@@@c@@@d') == ''

    def test_intersects_and_clip(self):
        assert ST.intersects(5, 15, 10, 20) and ST.clip(5, 15, 10, 20) == (10, 15)
        assert ST.intersects(15, 25, 10, 20) and ST.clip(15, 25, 10, 20) == (15, 20)
        assert ST.intersects(0, 30, 10, 20) and ST.clip(0, 30, 10, 20) == (10, 20)
        assert ST.intersects(12, 12, 10, 20) and ST.clip(12, 12, 10, 20) == (12, 12)     # zero-length inside
        assert ST.intersects(10, 10, 10, 20)                                              # at since
        assert not ST.intersects(5, 10, 10, 20)                                           # ended at since
        assert not ST.intersects(20, 25, 10, 20) and not ST.intersects(20, 20, 10, 20)   # from until
        assert not ST.intersects(None, 5, 10, 20) and not ST.intersects(5, None, 10, 20)
        assert ST.clip(0, 5, 10, 20) is None

    def test_merge_total_peak(self):
        assert ST.merge_intervals([]) == [] and ST.total_of([]) == 0.0 and ST.peak_of([]) == (0, None)
        merged = ST.merge_intervals([(5, 8), (1, 3), (2, 4), (8, 9), (12, 13)])
        assert merged == [(1, 4), (5, 9), (12, 13)] and ST.total_of(merged) == 8.0
        assert ST.peak_of([(1, 4), (2, 6), (3, 5), (10, 11)]) == (3, 3)
        assert ST.peak_of([(1, 4), (2, 6), (4, 5), (10, 11)]) == (2, 2)       # at 4 the first ends before one starts
        assert ST.peak_of([(1, 4), (4, 6)]) == (1, 1)                           # touching: never two at once
        assert ST.peak_of([(1, 4), (2, 2), (3, 5)]) == (2, 3)                   # a zero-length one is ignored

    def test_distribution(self):
        rows = ST.distribution_of([0, 899, 900, 1800, 3599, 3600, 7199, 7200, 14399, 14400, 99999])
        assert [(r['min'], r['max'], r['users']) for r in rows] == \
               [(0, 900, 2), (900, 1800, 1), (1800, 3600, 2), (3600, 7200, 2), (7200, 14400, 2), (14400, None, 2)]
        assert [r['users'] for r in ST.distribution_of([])] == [0] * 6


class TestComputeStatistics:
    """A period of eight hours: alice from two addresses at once (the union counts), bob straddling
    the start (clipped) with a second session later (the newest group wins), carol closed in the
    slack but after the period (ignored), dave on an old row without since nor role (a student),
    erin without duration (a zero-length session), prof an instructor with a group, frank still
    open; the project pages (two overlapping of alice on one lab, a spectator left out, prof's
    instructor view, bob's on a malformed name), the starts and the evaluations."""

    def rows(self) -> list:
        rows = [
            session_row(1, 'bob', '10.0.1.8', T0 - H, 2 * H, group='', role='', projects=[]),        # old row, clipped
            session_row(2, 'alice', '10.0.1.7', T0 + H, 2 * H, name='Alice Test', group='INFO1', projects=[DHCP_ALICE],
                        requests=10),
            session_row(3, 'alice', '10.0.1.9', T0 + 2 * H, 2 * H, name='Alice Test', group='INFO1',
                        projects=[DHCP_ALICE], requests=5),
            session_row(4, 'prof', '10.0.2.1', T0 + 2 * H, 0.75 * H, role='instructor', name='Prof Essor',
                        group='TEACHERS', projects=[DHCP_ALICE]),
            session_row(5, 'dave', '10.0.1.10', T0 + 3.5 * H, 0.5 * H, role='', since=False, closed=T0 + 4 * H),
            session_row(6, 'bob', '10.0.1.8', T0 + 6 * H, 0.5 * H, group='INFO2', name='Bob Test', projects=['oops']),
            session_row(7, 'erin', '10.0.1.11', T0 + 7 * H, None, closed=T0 + 7 * H),
            session_row(8, 'carol', '10.0.1.12', UNTIL + 600, H, group='INFO1'),                      # in the slack
            row(9, 'project_close', 'alice', T0 + 3 * H, rln=DHCP_ALICE, duration=H, code=1001),
            row(10, 'project_close', 'alice', T0 + 2.5 * H, rln=DHCP_ALICE, duration=H, code=1000),  # overlaps 9
            row(11, 'project_close', 'bob', T0 + 3 * H, rln=DHCP_ALICE, duration=H, code=1000, spectator=True),
            row(12, 'project_close', 'prof', T0 + 4 * H, rln=DHCP_ALICE, duration=0.5 * H, code=1000, view='instructor'),
            row(13, 'project_close', 'bob', T0 + 6.5 * H, rln='oops', duration=600, code=1000),
            row(14, 'project_close', 'alice', T0 + 3 * H, rln=DHCP_ALICE, duration=None, code=1006),  # no duration
            row(15, 'start', 'alice', T0 + H, rln=DHCP_ALICE, lab='sre/dhcp.py', status='200', result='created'),
            row(16, 'start', 'bob', T0 + 6 * H, lab='sre/dhcp.py', status='200', result='flavor_form'),
            row(17, 'start', 'carol', UNTIL + 60, rln='1@@@sre@dhcp.py@@@carol', lab='sre/dhcp.py', status='200',
                result='created'),
            row(18, 'start', 'dave', T0 + 3.5 * H, rln='', lab='sre/x.py', status='200', result='created'),
            row(19, 'eval', 'alice', T0 + 2 * H, rln=DHCP_ALICE, status='200', duration=8.0),
            row(20, 'eval', 'alice', T0 + 3 * H, rln=DHCP_ALICE, status='200', duration=8.0),
            row(21, 'eval', 'bob', T0 + 6.2 * H, rln='oops', status='429', duration=0.1),
        ]
        return sorted(rows, key=lambda r: -r['id'])        # newest first, as the query gives them

    def open(self) -> list:
        return [open_session('frank', '10.0.1.20', T0 + 5 * H, T0 + 6 * H, name='Frank Test', group='INFO1',
                             projects=[DHCP_FRANK], requests=7)]

    def test_users(self):
        stats = ST.compute_statistics(self.rows(), self.open(), SINCE, UNTIL)
        assert stats['since'] == SINCE and stats['until'] == UNTIL
        users = {u['login']: u for u in stats['users']}
        assert [u['login'] for u in stats['users']] == ['alice', 'bob', 'frank', 'prof', 'dave', 'erin']
        assert users['alice'] == {'login': 'alice', 'name': 'Alice Test', 'role': 'student', 'group': 'INFO1',
                                  'sessions': 2, 'open': 0, 'time': 3 * H, 'page_time': 1.5 * H, 'first': T0 + H,
                                  'last': T0 + 4 * H, 'addresses': 2, 'projects': 1, 'evaluations': 2, 'requests': 15}
        assert users['bob']['time'] == 1.5 * H and users['bob']['sessions'] == 2 and users['bob']['first'] == T0
        assert users['bob']['group'] == 'INFO2' and users['bob']['name'] == 'Bob Test' and users['bob']['role'] == 'student'
        assert users['bob']['page_time'] == 600 and users['bob']['projects'] == 1 and users['bob']['evaluations'] == 0
        assert users['frank']['open'] == 1 and users['frank']['time'] == H and users['frank']['group'] == 'INFO1'
        assert users['prof']['role'] == 'instructor' and users['prof']['time'] == 0.75 * H
        assert users['prof']['page_time'] == 0.5 * H and users['prof']['group'] == 'TEACHERS'
        assert users['dave'] == {'login': 'dave', 'name': '', 'role': 'student', 'group': '', 'sessions': 1, 'open': 0,
                                 'time': 0.5 * H, 'page_time': 0.0, 'first': T0 + 3.5 * H, 'last': T0 + 4 * H,
                                 'addresses': 1, 'projects': 0, 'evaluations': 0, 'requests': 1}
        assert users['erin']['time'] == 0.0 and users['erin']['sessions'] == 1 and users['erin']['first'] == T0 + 7 * H
        assert 'carol' not in users

    def test_groups_labs_totals_distribution(self):
        stats = ST.compute_statistics(self.rows(), self.open(), SINCE, UNTIL)
        assert stats['groups'] == [
            {'group': '', 'students': 2, 'sessions': 2, 'time': 0.5 * H, 'average': 0.25 * H, 'projects': 0,
             'evaluations': 0},
            {'group': 'INFO1', 'students': 2, 'sessions': 3, 'time': 4 * H, 'average': 2 * H, 'projects': 2,
             'evaluations': 2},
            {'group': 'INFO2', 'students': 1, 'sessions': 2, 'time': 1.5 * H, 'average': 1.5 * H, 'projects': 1,
             'evaluations': 0}]
        assert stats['labs'] == [
            {'lab': 'sre/dhcp.py', 'projects': 1, 'users': 2, 'students': 1, 'time': 2 * H, 'average': H, 'starts': 1,
             'evaluations': 2},
            {'lab': 'sre/x.py', 'projects': 0, 'users': 1, 'students': 1, 'time': 0.0, 'average': 0.0, 'starts': 1,
             'evaluations': 0}]
        student_times = [3 * H, 1.5 * H, H, 0.5 * H, 0.0]
        assert stats['totals'] == {
            'users': 6, 'students': 5, 'instructors': 1, 'groups': 2, 'sessions': 8, 'open': 1, 'addresses': 7,
            'time': sum(student_times) + 0.75 * H, 'students_time': sum(student_times),
            'average': sum(student_times) / 5, 'median': H, 'longest': 3 * H,
            'peak': {'users': 2, 'at': T0 + 2 * H}, 'projects_started': 2, 'projects_used': 3, 'evaluations': 2,
            'page_time': 1.5 * H + 0.5 * H + 600}
        assert [r['users'] for r in stats['distribution']] == [1, 0, 1, 2, 1, 0]

    def test_window_moves(self):
        """The same rows over the second half of the day: alice's sessions clipped, her pages
        before the window gone (one ends exactly at its start), bob's first session gone, the
        open session whole, the evaluations and the start before the window not counted, prof
        present through the project page alone (the session is before the window)."""
        stats = ST.compute_statistics(self.rows(), self.open(), T0 + 3 * H, UNTIL)
        users = {u['login']: u for u in stats['users']}
        assert users['alice']['time'] == H and users['alice']['first'] == T0 + 3 * H and users['alice']['evaluations'] == 1
        assert users['alice']['page_time'] == 0.0
        assert users['prof']['sessions'] == 0 and users['prof']['time'] == 0.0 and users['prof']['page_time'] == 0.5 * H
        assert users['prof']['first'] is None and users['prof']['role'] == 'student'   # no session: no role known
        assert users['bob']['sessions'] == 1 and users['bob']['time'] == 0.5 * H
        assert stats['totals']['users'] == 6 and stats['totals']['projects_started'] == 1
        assert stats['labs'] == [
            {'lab': 'sre/dhcp.py', 'projects': 1, 'users': 2, 'students': 2, 'time': 0.5 * H, 'average': 0.5 * H,
             'starts': 0, 'evaluations': 1},
            {'lab': 'sre/x.py', 'projects': 0, 'users': 1, 'students': 1, 'time': 0.0, 'average': 0.0, 'starts': 1,
             'evaluations': 0}]
        assert stats['totals']['peak'] == {'users': 2, 'at': T0 + 3.5 * H}       # alice and dave

    def test_empty(self):
        stats = ST.compute_statistics([], [], SINCE, UNTIL)
        assert stats['users'] == [] and stats['groups'] == [] and stats['labs'] == []
        assert stats['totals'] == {'users': 0, 'students': 0, 'instructors': 0, 'groups': 0, 'sessions': 0, 'open': 0,
                                   'addresses': 0, 'time': 0.0, 'students_time': 0.0, 'average': 0.0, 'median': 0.0,
                                   'longest': 0.0, 'peak': {'users': 0, 'at': None}, 'projects_started': 0,
                                   'projects_used': 0, 'evaluations': 0, 'page_time': 0.0}
        assert [r['users'] for r in stats['distribution']] == [0] * 6
        # rows of other events, a session without time, are ignored
        assert ST.compute_statistics([row(1, 'denied', '-', T0 + H, status='403'),
                                      {'event': 'session_close', 'login': 'x', 'details': {}, 'duration': 5.0}],
                                     [], SINCE, UNTIL)['users'] == []

    def test_a_user_without_session(self):
        """A project page of a user whose session is not in the rows (closed beyond the slack):
        a user with no session, counted on the lab."""
        rows = [row(1, 'project_close', 'zoe', T0 + 2 * H, rln=DHCP_ALICE, duration=H, code=1000)]
        stats = ST.compute_statistics(rows, [], SINCE, UNTIL)
        assert stats['users'] == [{'login': 'zoe', 'name': '', 'role': 'student', 'group': '', 'sessions': 0, 'open': 0,
                                   'time': 0.0, 'page_time': H, 'first': None, 'last': None, 'addresses': 0,
                                   'projects': 1, 'evaluations': 0, 'requests': 0}]
        assert stats['labs'][0]['users'] == 1 and stats['labs'][0]['time'] == H
        assert stats['totals']['sessions'] == 0 and stats['totals']['students'] == 1
