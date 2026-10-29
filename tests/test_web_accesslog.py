"""Tests of the connection log of the portal (sreweb.portal.accesslog): the client address
behind a trusted proxy, the line format and its parser, the events of the routes, the sessions
(open, count, projects, expiry, open sockets) and the file handler.  The lines of a real portal
are checked in test_web_portal.py (TestAccessLog)."""
import ipaddress
import logging
import logging.handlers
import os

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.config import AccessDatabaseConfig, AccessLogConfig, ConfigError, web_config_from_dict  # noqa: E402
from sreweb.identity import Identity  # noqa: E402
from sreweb.portal import accesslog as A  # noqa: E402

TRUSTED = [ipaddress.ip_network('127.0.0.1/32'), ipaddress.ip_network('10.0.0.0/24')]
ALICE = Identity(login='alice', fullname='Alice Test', role='student', anonymous=False)


class TestForwardedAddress:
    def test_trusted_peer_takes_the_last_entry(self):
        assert A.forwarded_address('127.0.0.1', '1.2.3.4, 10.0.1.7', TRUSTED) == '10.0.1.7'
        assert A.forwarded_address('10.0.0.5', '2001:db8::7', TRUSTED) == '2001:db8::7'
        assert A.forwarded_address('::ffff:127.0.0.1', ' 10.0.1.8 ', TRUSTED) == '10.0.1.8'

    def test_untrusted_peer_or_no_header_or_no_proxies(self):
        assert A.forwarded_address('10.0.1.5', '10.0.1.7', TRUSTED) == '10.0.1.5'
        assert A.forwarded_address('127.0.0.1', None, TRUSTED) == '127.0.0.1'
        assert A.forwarded_address('127.0.0.1', '', TRUSTED) == '127.0.0.1'
        # an empty trusted list means "every peer" for the agent's allow-list, never here
        assert A.forwarded_address('127.0.0.1', '10.0.1.7', []) == '127.0.0.1'

    def test_garbage_and_unknown_peer(self):
        assert A.forwarded_address('127.0.0.1', 'evil.example', TRUSTED) == '127.0.0.1'
        assert A.forwarded_address('127.0.0.1', 'a=b c', TRUSTED) == '127.0.0.1'
        assert A.forwarded_address(None, '10.0.1.7', TRUSTED) == '-'
        assert A.forwarded_address(None, None, []) == '-'


class TestFormat:
    def test_values(self):
        assert A.format_value(None) == '-' and A.format_value('') == '-'
        assert A.format_value(True) == '1' and A.format_value(False) == '0'
        assert A.format_value(0) == '0' and A.format_value(12) == '12'
        assert A.format_value(1.26) == '1.3' and A.format_value(0.0) == '0.0'
        assert A.format_value('sre/dhcp.py') == 'sre/dhcp.py'
        assert A.format_value('1761466323@@@dhcp@@@alice') == '1761466323@@@dhcp@@@alice'
        assert A.format_value('2026-10-26T09:12:03+0100') == '2026-10-26T09:12:03+0100'
        assert A.format_value('Alice Test') == '"Alice Test"'
        assert A.format_value('Émile') == '"Émile"'
        assert A.format_value('a"b\\c\n') == '"a\\"b\\\\c\\n"'
        assert A.format_value(['x@@@y@@@z', 'a@@@b@@@c']) == 'x@@@y@@@z,a@@@b@@@c'
        assert A.format_value([]) == '-'
        assert A.format_value({'b', 'a'}) == 'a,b'

    def test_line_round_trip(self):
        fields = {'event': 'session_open', 'login': 'alice', 'addr': '10.0.1.7', 'role': 'student', 'anon': False,
                  'name': 'Alice "the" Test', 'ua': 'Mozilla/5.0 (X11; Linux) Gecko\tx', 'n': 3, 'empty': None,
                  'projects': ['1@@@a@@@u', '2@@@b@@@u'], 'duration': 1.26}
        line = A.format_line(fields)
        assert line.startswith('event=session_open login=alice addr=10.0.1.7 role=student anon=0 name="Alice \\"the\\" Test" ')
        assert '\n' not in line and '\t' not in line
        parsed = A.parse_line(line)
        assert parsed == {'event': 'session_open', 'login': 'alice', 'addr': '10.0.1.7', 'role': 'student', 'anon': '0',
                          'name': 'Alice "the" Test', 'ua': 'Mozilla/5.0 (X11; Linux) Gecko\tx', 'n': '3', 'empty': '',
                          'projects': '1@@@a@@@u,2@@@b@@@u', 'duration': '1.3'}

    def test_parse_line_with_timestamp(self):
        parsed = A.parse_line('2026-10-26T09:12:03+0100 event=start login=alice addr=- host=a01 status=200\n')
        assert parsed == {'ts': '2026-10-26T09:12:03+0100', 'event': 'start', 'login': 'alice', 'addr': '',
                          'host': 'a01', 'status': '200'}
        assert A.parse_line('') == {}

    def test_injection_is_escaped(self):
        line = A.format_line({'event': 'login', 'name': 'x\nevent=admin login=root'})
        assert '\n' not in line and line == 'event=login name="x\\nevent=admin login=root"'
        assert A.parse_line(line) == {'event': 'login', 'name': 'x\nevent=admin login=root'}


class TestEventFor:
    @pytest.mark.parametrize('method, canonical, event', [
        ('POST', '/api/projects', 'start'),
        ('DELETE', '/api/projects/{host}/{rln}', 'stop'),
        ('GET', '/api/projects/{host}/{rln}/events', 'project'),
        ('HEAD', '/api/projects/{host}/{rln}/events', 'project'),
        ('GET', '/api/projects/{host}/{rln}/terminals/{device}', 'terminal'),
        ('GET', '/api/projects/{host}/{rln}/display/ws', 'display'),
        ('POST', '/api/projects/{host}/{rln}/display', 'display_start'),
        ('POST', '/api/projects/{host}/{rln}/eval', 'eval'),
        ('POST', '/api/projects/{host}/{rln}/states/{state}', 'state'),
        ('POST', '/logout', 'logout'),
        ('POST', '/api/logout', 'logout'),
        ('POST', '/api/pool/hosts/{name}/{action}', 'admin'),
        ('POST', '/api/presentations', 'present_start'),
        ('PUT', '/api/presentations/{id}/audience', 'present_audience'),
        ('DELETE', '/api/presentations/{id}', 'present_stop'),
        ('GET', '/present/{id}', 'present_open'),
        ('GET', '/api/presence', None),
        ('GET', '/api/presence/ws', None),
        ('PUT', '/api/presentations/{id}/view', None),
        ('GET', '/api/projects', None),
        ('GET', '/api/projects/{host}/{rln}', None),
        ('PUT', '/api/projects/{host}/{rln}/answers', None),
        ('GET', '/api/pool', None),
        ('GET', '/projects/{host}/{rln}', None),
        ('GET', '/static', None),
        ('GET', '', None),
    ])
    def test_table(self, method, canonical, event):
        assert A.event_for(method, canonical) == event

    def test_sets(self):
        assert A.WS_EVENTS == {'project', 'terminal', 'display'}
        assert ('GET', '/api/projects') in A.KEEPALIVE and ('POST', '/api/projects/{host}/{rln}/touch') in A.KEEPALIVE
        assert ('GET', '/api/pool') in A.KEEPALIVE and ('GET', '/api/pool/status') in A.KEEPALIVE
        assert '/static' in A.IGNORED and '' in A.IGNORED and '/i18n/{lang}.json' in A.IGNORED
        assert '/api/presence/ws' in A.IGNORED
        assert ('GET', '/api/presence') in A.KEEPALIVE and ('PUT', '/api/presentations/{id}/view') in A.KEEPALIVE
        assert ('GET', '/api/presentations/{id}/ws') in A.KEEPALIVE
        assert {'present_start', 'present_open'} <= A.PROJECT_EVENTS
        assert A.LOGIN_ROUTES == {('POST', '/login'), ('POST', '/api/login')}
        assert set(A.EVENTS.values()) - A.WS_EVENTS - A.PROJECT_EVENTS == {'start', 'logout', 'admin',
                                                                            'present_audience', 'present_stop',
                                                                            'history'}


class TestVisits:
    def test_open_touch_count_and_projects(self):
        visits = A.Visits()
        visit, new = visits.touch(ALICE, '10.0.1.7', 'UA', 1000.0)
        assert new and len(visits) == 1 and visit.key == ('alice', '10.0.1.7')
        assert (visit.login, visit.addr, visit.role, visit.anon, visit.name, visit.ua) == \
               ('alice', '10.0.1.7', 'student', False, 'Alice Test', 'UA')
        assert visit.first_seen == visit.last_seen == 1000.0 and visit.requests == 1
        again, new = visits.touch(ALICE, '10.0.1.7', 'UA', 1030.0, count=False)   # a poll
        assert again is visit and not new and visit.last_seen == 1030.0 and visit.requests == 1
        visits.touch(ALICE, '10.0.1.7', 'UA', 1060.0)
        assert visit.requests == 2 and visit.duration == 60.0
        other, new = visits.touch(ALICE, '10.0.1.8', 'UA', 1060.0)   # another address: another session
        assert new and other is not visit and len(visits) == 2
        visits.add_project(visit.key, '1@@@a@@@alice')
        visits.add_project(visit.key, '1@@@a@@@alice')
        visits.add_project(visit.key, '2@@@b@@@alice')
        visits.add_project(visit.key, None)
        visits.add_project(('nobody', 'x'), '3@@@c@@@x')
        assert visit.projects == ['1@@@a@@@alice', '2@@@b@@@alice'] and other.projects == []
        assert visits.close(visit.key) is visit and visits.close(visit.key) is None and len(visits) == 1

    def test_expiry_skips_open_sockets_and_excludes_the_idle_gap(self):
        visits = A.Visits()
        visit, _ = visits.touch(ALICE, '10.0.1.7', 'UA', 1000.0)
        visits.touch(ALICE, '10.0.1.7', 'UA', 1100.0)
        assert visits.expire(1699.0, 600.0) == []
        assert visits.expire(1700.0, 600.0) == [visit] and len(visits) == 0
        assert visit.duration == 100.0                     # up to the last request, not the expiry
        visit, _ = visits.touch(ALICE, '10.0.1.7', 'UA', 2000.0)
        visits.socket_opened(visit.key)
        visits.socket_opened(visit.key)
        assert visits.expire(9000.0, 600.0) == [] and visit.sockets == 2
        visits.socket_closed(visit.key, 5000.0)
        assert visits.expire(9000.0, 600.0) == [] and visit.sockets == 1
        visits.socket_closed(visit.key, 6000.0)
        assert visit.sockets == 0 and visit.last_seen == 6000.0
        assert visits.expire(6599.0, 600.0) == []
        assert visits.expire(6600.0, 600.0) == [visit] and visit.duration == 4000.0
        visits.socket_closed(visit.key, 7000.0)            # a socket of a closed session: ignored
        visits.socket_opened(('nobody', 'x'))

    def test_close_all(self):
        visits = A.Visits()
        a, _ = visits.touch(ALICE, '10.0.1.7', 'UA', 1000.0)
        b, _ = visits.touch(Identity(login='bob'), '10.0.1.7', 'UA', 1000.0)
        assert visits.close_all() == [a, b] and len(visits) == 0 and visits.close_all() == []


class TestAccessLogFile:
    def _log(self, tmp_path, **over):
        cfg = AccessLogConfig(**{'file': str(tmp_path / 'access.log'), 'journal': False, **over})
        return A.AccessLog(cfg, [], clock=lambda: 1000.0)

    def test_writes_timestamped_lines(self, tmp_path):
        access = self._log(tmp_path)
        access.open()
        try:
            assert access.logger.propagate is False and access.logger.level == logging.INFO
            assert isinstance(access._handler, logging.handlers.TimedRotatingFileHandler)
            assert access._handler.backupCount == 400 and access._handler.when == 'MIDNIGHT'
            access.record('login', login='alice', addr='10.0.1.7', name='Alice Test')
        finally:
            access.close()
        lines = (tmp_path / 'access.log').read_text().splitlines()
        assert len(lines) == 1
        parsed = A.parse_line(lines[0])
        assert parsed['ts'][:2] == '20' and 'T' in parsed['ts'] and parsed['event'] == 'login'
        assert parsed['name'] == 'Alice Test' and parsed['addr'] == '10.0.1.7'
        assert access.logger.handlers == [] and "rotated daily, 400 days" in access.describe()

    def test_no_rotation_and_no_file(self, tmp_path):
        access = self._log(tmp_path, keep=0)
        access.open()
        try:
            assert isinstance(access._handler, logging.handlers.WatchedFileHandler)
            assert "no rotation" in access.describe()
        finally:
            access.close()
        journal = A.AccessLog(AccessLogConfig(), [])
        journal.open()
        try:
            assert isinstance(journal._handler, logging.NullHandler) and journal.logger.propagate is True
            assert journal.describe() == "the journal"
        finally:
            journal.close()
        off = A.AccessLog(AccessLogConfig(journal=False), [])
        off.open()
        try:
            assert off.logger.propagate is False and off.describe().startswith("nowhere")
        finally:
            off.close()

    def test_one_handler_whatever_the_instances(self, tmp_path):
        first = self._log(tmp_path)
        first.open()
        first.open()
        second = self._log(tmp_path)
        second.open()      # the handler of a previous instance (another test, another portal) is dropped
        try:
            ours = [h for h in second.logger.handlers if getattr(h, 'sreweb_access', False)]
            assert len(ours) == 1 and ours[0] is second._handler
            second.record('x')
        finally:
            second.close()
            first.close()
        assert len((tmp_path / 'access.log').read_text().splitlines()) == 1

    def test_unwritable_file_is_a_config_error(self, tmp_path):
        access = A.AccessLog(AccessLogConfig(file=str(tmp_path / 'missing' / 'access.log')), [])
        with pytest.raises(ConfigError, match='access_log.file'):
            access.open()
        assert access._handler is None

    def test_sessions_and_lines(self, tmp_path):
        """The session lines without a server: login, close by reason, expiry, close_all."""
        access = self._log(tmp_path, session_timeout=600.0)
        now = [1000.0]
        access.clock = lambda: now[0]
        access.open()
        try:
            class Req:
                remote = '127.0.0.1'
                headers = {'User-Agent': 'UA ' + 'x' * 300}
            access.login(Req(), ALICE, 'ldap')
            key = ('alice', '127.0.0.1')
            visit = access.visits.get(key)
            assert visit is not None and visit.requests == 1 and len(visit.ua) == A.MAX_USER_AGENT
            access.visits.add_project(key, '1@@@a@@@alice')
            now[0] = 1500.0
            access.touch(Req(), ALICE, count=False)
            now[0] = 2099.0
            access.expire()
            assert access.visits.get(key) is not None
            now[0] = 2100.0
            access.expire()
            assert access.visits.get(key) is None
            access.login_failed(Req(), 'mallory', 'password')
            access.touch(Req(), ALICE)
            access.close_all('shutdown')
            access.close_visit(key, 'logout')      # already closed: nothing
        finally:
            access.close()
        lines = [A.parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
        assert [l['event'] for l in lines] == ['login', 'session_open', 'session_close', 'login_failed',
                                               'session_open', 'session_close']
        assert lines[0]['mode'] == 'ldap' and lines[0]['role'] == 'student' and lines[0]['anon'] == '0'
        assert lines[1]['ua'] == 'UA ' + 'x' * (A.MAX_USER_AGENT - 3)
        assert lines[2] == {'ts': lines[2]['ts'], 'event': 'session_close', 'login': 'alice', 'addr': '127.0.0.1',
                            'reason': 'idle', 'since': A.iso_time(1000.0), 'duration': '500', 'requests': '1',
                            'projects': '1@@@a@@@alice'}
        assert lines[3] == dict(ts=lines[3]['ts'], event='login_failed', login='mallory', addr='127.0.0.1', reason='password')
        assert lines[5]['reason'] == 'shutdown' and lines[5]['duration'] == '0' and lines[5]['projects'] == ''

    def test_period(self):
        assert A.AccessLog(AccessLogConfig(session_timeout=1800.0), []).period == 60.0
        assert A.AccessLog(AccessLogConfig(session_timeout=10.0), []).period == 5.0
        assert A.AccessLog(AccessLogConfig(session_timeout=1.0), []).period == 1.0


class TestConfig:
    def test_defaults_and_values(self):
        cfg = web_config_from_dict({'secret': 's' * 32, 'hosts': [{'name': 'a01', 'url': 'http://x', 'token': 't' * 32}]})
        assert cfg.access_log == AccessLogConfig(file='', journal=True, keep=400, session_timeout=1800.0)
        cfg = web_config_from_dict({'secret': 's' * 32, 'hosts': [{'name': 'a01', 'url': 'http://x', 'token': 't' * 32}],
                                    'access_log': {'file': '/var/log/sre-web/access.log', 'journal': False, 'keep': 0,
                                                   'session_timeout': '15m'}})
        assert cfg.access_log == AccessLogConfig(file='/var/log/sre-web/access.log', journal=False, keep=0,
                                                 session_timeout=900.0)
        assert not cfg.access_log.database.enabled and cfg.access_log.database == AccessDatabaseConfig()

    def test_database(self):
        hosts = [{'name': 'a01', 'url': 'http://x', 'token': 't' * 32}]
        cfg = web_config_from_dict({'secret': 's' * 32, 'hosts': hosts,
                                    'access_log': {'journal': False,
                                                   'database': {'host': 'db.example.org', 'user': 'sre_web',
                                                                'password': 'pw', 'name': 'sre', 'keep': 30,
                                                                'queue': 500, 'connect_timeout': '2s'}}})
        db = cfg.access_log.database
        assert db.enabled and cfg.access_log.journal is False
        assert (db.host, db.port, db.unix_socket, db.user, db.password, db.name, db.table, db.keep, db.queue,
                db.connect_timeout) == ('db.example.org', 3306, '', 'sre_web', 'pw', 'sre', 'access_log', 30, 500, 2.0)
        cfg = web_config_from_dict({'secret': 's' * 32, 'hosts': hosts,
                                    'access_log': {'database': {'unix_socket': '/run/mysqld/mysqld.sock', 'user': 'u',
                                                                'name': 'sre', 'table': 'web_log', 'port': 3307}}})
        db = cfg.access_log.database
        assert db.enabled and db.host == '' and db.table == 'web_log' and db.port == 3307

    @pytest.mark.parametrize('table, fragment', [
        ({'file': 'access.log'}, 'absolute'),
        ({'file': 3}, 'absolute'),
        ({'journal': 'yes'}, 'journal'),
        ({'keep': -1}, 'keep'),
        ({'keep': True}, 'keep'),
        ({'keep': '30'}, 'keep'),
        ({'session_timeout': 0}, 'session_timeout'),
        ({'session_timeout': 'soon'}, 'session_timeout'),
        ({'typo': 1}, 'typo'),
        ({'database': 3}, 'database'),
        ({'database': {'typo': 1}}, 'typo'),
        ({'database': {'host': 3}}, 'host'),
        ({'database': {'host': 'db'}}, 'name'),
        ({'database': {'host': 'db', 'name': 'sre'}}, 'user'),
        ({'database': {'host': 'db', 'unix_socket': '/run/x', 'user': 'u', 'name': 'sre'}}, 'not both'),
        ({'database': {'unix_socket': 'relative.sock', 'user': 'u', 'name': 'sre'}}, 'unix_socket'),
        ({'database': {'port': 70000}}, 'port'),
        ({'database': {'port': True}}, 'port'),
        ({'database': {'table': 'drop table;'}}, 'table'),
        ({'database': {'table': ''}}, 'table'),
        ({'database': {'keep': -1}}, 'keep'),
        ({'database': {'keep': True}}, 'keep'),
        ({'database': {'queue': 0}}, 'queue'),
        ({'database': {'connect_timeout': 0}}, 'connect_timeout'),
        ({'database': {'connect_timeout': 'soon'}}, 'connect_timeout'),
    ])
    def test_refused(self, table, fragment):
        with pytest.raises(ConfigError, match=fragment):
            web_config_from_dict({'secret': 's' * 32, 'hosts': [{'name': 'a01', 'url': 'http://x', 'token': 't' * 32}],
                                  'access_log': table})
