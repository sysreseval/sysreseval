"""The clients of the Watch page (sreweb/portal/clients.py): one row per browser connected to
the portal, one per user in the Qt GUI of a pool host, and the clients of its owner counted on
each project; the new fields of the presence sockets (sreweb/portal/presentation.py)."""
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from sreweb.identity import Identity
from sreweb.portal import clients as C
from sreweb.portal import presentation as PR

from test_web_presentation import Clock, FakeWatcher
from test_web_useragent import CHROME_WINDOWS, FIREFOX_LINUX, SAFARI_IPHONE

ALICE = Identity(login='alice', fullname='Alice Liddell', group='INFO1')
BOB = Identity(login='bob', fullname='Bob')
PROF = Identity(login='prof', fullname='Prof', role='instructor')

ALICE_RLN = '20261118091203@@@sre@dhcp.py@@@alice'
BOB_RLN = '20261118091540@@@s3@r306@static_routing.py@@@bob'
PROF_RLN = '20261118100111@@@sre@dhcp.py@@@prof'
ID_A = 'aaaaaaaaaaaaaaaaaaaaaaaa'
ID_B = 'bbbbbbbbbbbbbbbbbbbbbbbb'


def page_of(host: str, rln: str) -> str:
    """The path of a project page, as ``projectUrl()`` of creation.js builds it."""
    return f'/projects/{quote(host, safe="")}/{quote(rln, safe="")}'


def presence_at(now=1000.0):
    clock = Clock(now)
    return clock, PR.Presence(clock=clock)


def add(presence, identity, page, **kwargs):
    return presence.add(identity, page, FakeWatcher(), **kwargs)


class TestPageProject:
    def test_a_project_page(self):
        assert C.page_project(page_of('a01', ALICE_RLN)) == ('a01', ALICE_RLN)
        assert C.page_project(f'/projects/a01/{ALICE_RLN}') == ('a01', ALICE_RLN)          # not quoted
        assert C.page_project(page_of('room h/12', BOB_RLN)) == ('room h/12', BOB_RLN)

    @pytest.mark.parametrize('page', ['', None, 7, '/projects', '/projects/', '/projects/a01', '/projects/a01/',
                                      '/projects//' + ALICE_RLN, '/projects/a01/not-a-project',
                                      f'/projects/a01/{ALICE_RLN}/extra', '/watch', '/open',
                                      f'/present/{ALICE_RLN}', '/projects/a01/1@@@x%2Fy@@@alice'])
    def test_any_other_page(self, page):
        assert C.page_project(page) is None


class TestPresenceSockets:
    def test_the_browser_of_a_socket(self):
        _clock, presence = presence_at()
        plain = add(presence, ALICE, '/projects')
        assert (plain.addr, plain.ua, plain.client, plain.away) == ('', '', '', False)
        full = add(presence, ALICE, '/open', addr='10.0.1.7', ua=FIREFOX_LINUX, client=ID_A)
        assert (full.addr, full.ua, full.client) == ('10.0.1.7', FIREFOX_LINUX, ID_A)
        assert presence.sockets() == [plain, full]
        assert C.browser_key(plain) == ('alice', 'ua', '', '') and C.browser_key(full) == ('alice', 'id', ID_A)

    def test_sockets_by_login_then_age(self):
        _clock, presence = presence_at()
        first = add(presence, BOB, '/projects')
        second = add(presence, ALICE, '/projects')
        third = add(presence, BOB, '/open')
        assert presence.sockets() == [second, first, third]
        presence.remove(first)
        assert presence.sockets() == [second, third]

    def test_an_away_page_is_not_a_page_shown_but_still_gets_the_pushes(self):
        import asyncio
        _clock, presence = presence_at()
        shown = add(presence, ALICE, '/projects')
        left = add(presence, ALICE, '/open')
        left.away = True
        assert presence.connected()[0]['pages'] == ['/projects']
        assert presence.logins() == {'alice'} and presence.identity_of('alice') is ALICE
        asyncio.run(presence.push('alice', {'t': 'presentation', 'id': 'x'}))
        assert shown.watcher.sent == left.watcher.sent == [{'t': 'presentation', 'id': 'x'}]

    @pytest.mark.parametrize('page, kept', [
        ('/projects', '/projects'), (page_of('a01', ALICE_RLN), page_of('a01', ALICE_RLN)),
        ('/' + 'x' * (PR.MAX_PAGE_LENGTH - 1), '/' + 'x' * (PR.MAX_PAGE_LENGTH - 1)),
        ('/' + 'x' * PR.MAX_PAGE_LENGTH, ''), ('//evil.example/x', ''), ('/a\\b', ''), ('projects', ''),
        ('https://evil.example/', ''), ('/a\nb', ''), ('', ''), (None, ''), (['/x'], ''),
    ])
    def test_clean_page(self, page, kept):
        assert PR.clean_page(page) == kept

    def test_a_long_project_path_is_kept(self):
        long_rln = '20261118091203@@@' + '@'.join(['directory'] * 20) + '@lab.py@@@alice'
        page = page_of('a01', long_rln)
        assert 200 < len(page) <= PR.MAX_PAGE_LENGTH and PR.clean_page(page) == page

    @pytest.mark.parametrize('client, kept', [
        (ID_A, ID_A), ('abc-DEF_12', 'abc-DEF_12'), ('short', ''), ('a' * 65, ''), ('with space', ''),
        ('<script>12345', ''), ('', ''), (None, ''), (12345678, ''),
    ])
    def test_clean_client(self, client, kept):
        assert PR.clean_client(client) == kept

    def test_away_after(self):
        assert PR.away_after('{"t": "away"}', False) is True and PR.away_after('{"t": "back"}', True) is False
        for frame in ('{"t": "pointer"}', '{"away": true}', '"away"', '[1]', 'not json', '', None, '{"t": 3}'):
            assert PR.away_after(frame, False) is False and PR.away_after(frame, True) is True


class TestWebClients:
    def test_one_row_per_browser(self):
        clock, presence = presence_at()
        add(presence, ALICE, '/projects', addr='10.0.1.7', ua=FIREFOX_LINUX, client=ID_A)
        clock.now += 5
        add(presence, ALICE, page_of('a01', ALICE_RLN), addr='10.0.1.7', ua=FIREFOX_LINUX, client=ID_A)   # a second tab
        clock.now += 5
        add(presence, ALICE, '/projects', addr='10.0.1.7', ua=CHROME_WINDOWS, client=ID_B)     # another browser
        add(presence, PROF, '/watch', addr='10.0.9.1', ua=SAFARI_IPHONE, client=ID_A)          # the same id, another login
        rows = C.web_clients(presence.sockets())
        assert [(r['login'], r['browser'], r['version'], r['system'], r['mobile'], r['tabs']) for r in rows] == [
            ('alice', 'Firefox', '131', 'Linux', False, 2), ('alice', 'Chrome', '130', 'Windows', False, 1),
            ('prof', 'Safari', '18', 'iOS', True, 1)]
        first = rows[0]
        assert (first['fullname'], first['group'], first['role']) == ('Alice Liddell', 'INFO1', 'student')
        assert first['addrs'] == ['10.0.1.7'] and first['since'] == 1000.0 and first['ua'] == FIREFOX_LINUX
        assert first['pages'] == [{'path': '/projects', 'host': None, 'rln': None},
                                  {'path': page_of('a01', ALICE_RLN), 'host': 'a01', 'rln': ALICE_RLN}]
        assert rows[2]['role'] == 'instructor'
        assert not any('client' in row for row in rows)                    # the id is never handed out

    def test_without_an_id_the_address_and_the_user_agent_tell_the_browsers(self):
        _clock, presence = presence_at()
        add(presence, ALICE, '/projects', addr='10.0.1.7', ua=FIREFOX_LINUX)
        add(presence, ALICE, '/open', addr='10.0.1.7', ua=FIREFOX_LINUX)
        add(presence, ALICE, '/open', addr='10.0.1.8', ua=FIREFOX_LINUX)          # another machine
        add(presence, ALICE, '/open', addr='10.0.1.7', ua=CHROME_WINDOWS)         # another browser
        rows = C.web_clients(presence.sockets())
        assert sorted((r['addrs'][0], r['browser'], r['tabs']) for r in rows) == [
            ('10.0.1.7', 'Chrome', 1), ('10.0.1.7', 'Firefox', 2), ('10.0.1.8', 'Firefox', 1)]

    def test_the_same_page_in_two_tabs_is_listed_once(self):
        _clock, presence = presence_at()
        for _ in range(2):
            add(presence, ALICE, '/projects', client=ID_A)
        row, = C.web_clients(presence.sockets())
        assert row['tabs'] == 2 and [page['path'] for page in row['pages']] == ['/projects']

    def test_away_pages(self):
        """A page left (kept by the browser in its back/forward cache) is not shown, and a
        browser whose pages are all away is not connected."""
        _clock, presence = presence_at()
        left = add(presence, ALICE, page_of('a01', ALICE_RLN), client=ID_A)
        add(presence, ALICE, '/projects', client=ID_A)
        only = add(presence, BOB, '/projects', client=ID_B)
        left.away = only.away = True
        row, = C.web_clients(presence.sockets())
        assert row['login'] == 'alice' and row['tabs'] == 1 and [p['path'] for p in row['pages']] == ['/projects']
        only.away = False
        assert [r['login'] for r in C.web_clients(presence.sockets())] == ['alice', 'bob']

    def test_since_is_the_start_of_the_session(self):
        clock, presence = presence_at(5000.0)
        add(presence, ALICE, '/projects', addr='10.0.1.7', client=ID_A)
        clock.now += 60
        add(presence, ALICE, '/open', addr='2001:db8::7', client=ID_A)            # a dual-stack browser
        visits = {('alice', '10.0.1.7'): SimpleNamespace(first_seen=1200.0),
                  ('alice', '2001:db8::7'): SimpleNamespace(first_seen=900.5)}
        row, = C.web_clients(presence.sockets(), visit_of=visits.get)
        assert row['since'] == 900.5 and row['addrs'] == ['10.0.1.7', '2001:db8::7']
        row, = C.web_clients(presence.sockets(), visit_of={}.get)       # the session expired: the oldest socket
        assert row['since'] == 5000.0
        row, = C.web_clients(presence.sockets())
        assert row['since'] == 5000.0

    def test_the_identity_of_the_newest_socket(self):
        clock, presence = presence_at()
        add(presence, Identity(login='alice', fullname='Alice'), '/projects', client=ID_A)
        clock.now += 1
        add(presence, ALICE, '/open', client=ID_A)                       # the directory answered meanwhile
        row, = C.web_clients(presence.sockets())
        assert (row['fullname'], row['group']) == ('Alice Liddell', 'INFO1')

    def test_at_most_a_number_of_browsers_per_login(self):
        clock, presence = presence_at()
        for i in range(C.MAX_BROWSERS_PER_LOGIN + 5):
            add(presence, ALICE, '/projects', client=f'flood-{i:04d}')
            clock.now += 1
        add(presence, BOB, '/projects', client=ID_B)
        rows = C.web_clients(presence.sockets())
        assert [r['login'] for r in rows].count('alice') == C.MAX_BROWSERS_PER_LOGIN and rows[-1]['login'] == 'bob'
        assert rows[0]['since'] == 1000.0                                          # the oldest ones are kept
        assert len(C.web_clients(presence.sockets(), limit=2)) == 3

    def test_nobody(self):
        assert C.web_clients([]) == []


class TestLocalClients:
    def test_one_row_per_user_and_host(self):
        gui = {'z02': [{'login': 'zoe', 'fullname': 'zoe martin', 'since': 1700000000.5}],
               'a01': [{'login': 'bob', 'fullname': '', 'since': None},
                       {'login': 'alice', 'fullname': 'alice', 'since': 1700000100.0}]}
        assert C.local_clients(gui) == [
            {'host': 'a01', 'login': 'alice', 'fullname': 'alice', 'group': '', 'since': 1700000100.0, 'managed': False},
            {'host': 'a01', 'login': 'bob', 'fullname': '', 'group': '', 'since': None, 'managed': False},
            {'host': 'z02', 'login': 'zoe', 'fullname': 'zoe martin', 'group': '', 'since': 1700000000.5,
             'managed': False}]
        assert C.local_clients({}) == []


def watch_rows():
    return [{'host': 'a01', 'running_lab_name': ALICE_RLN, 'owner': 'alice'},
            {'host': 'a01', 'running_lab_name': BOB_RLN, 'owner': 'bob'},
            {'host': 'z02', 'running_lab_name': PROF_RLN, 'owner': 'prof'}]


def counts(rows):
    return [(row['clients'], row['client_local']) for row in rows]


class TestAnnotateProjects:
    def test_the_browsers_of_the_owner_on_the_page(self):
        _clock, presence = presence_at()
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), {})) == [(0, False)] * 3
        add(presence, ALICE, page_of('a01', ALICE_RLN), client=ID_A)
        add(presence, ALICE, page_of('a01', ALICE_RLN), client=ID_A)          # a second tab of the same browser
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), {})) == [(1, False), (0, False), (0, False)]
        add(presence, ALICE, page_of('a01', ALICE_RLN), client=ID_B)          # a second browser
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), {}))[0] == (2, False)

    def test_nobody_else_counts(self):
        """An instructor helping on the project, a student claiming the page of another one's
        project: the page is what the browser says."""
        _clock, presence = presence_at()
        add(presence, PROF, page_of('a01', ALICE_RLN), client=ID_A)
        add(presence, BOB, page_of('a01', ALICE_RLN), client=ID_B)
        add(presence, ALICE, '/projects', client=ID_A)                        # the owner, on another page
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), {})) == [(0, False)] * 3

    def test_an_instructor_counts_on_their_own_project(self):
        _clock, presence = presence_at()
        add(presence, PROF, page_of('z02', PROF_RLN), client=ID_A)
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), {}))[2] == (1, False)

    def test_the_host_of_the_page_matters(self):
        _clock, presence = presence_at()
        add(presence, ALICE, page_of('z02', ALICE_RLN), client=ID_A)          # the project is on a01
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), {}))[0] == (0, False)

    def test_an_away_page_does_not_count(self):
        _clock, presence = presence_at()
        socket = add(presence, ALICE, page_of('a01', ALICE_RLN), client=ID_A)
        socket.away = True
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), {}))[0] == (0, False)

    def test_the_local_gui_of_the_owner_on_the_host(self):
        _clock, presence = presence_at()
        add(presence, ALICE, page_of('a01', ALICE_RLN), client=ID_A)
        gui = {'a01': [{'login': 'alice', 'fullname': '', 'since': None}],      # the GUI shows her projects of a01
               'z02': [{'login': 'bob', 'fullname': '', 'since': None}]}        # bob's project is on a01
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), gui)) == [(2, True), (0, False), (0, False)]
        gui = {'a01': [{'login': 'bob', 'fullname': '', 'since': None}]}
        assert counts(C.annotate_projects(watch_rows(), presence.sockets(), gui)) == [(1, False), (1, True), (0, False)]

    def test_rows_without_the_keys(self):
        assert counts(C.annotate_projects([{}], [], {'a01': [{'login': 'alice'}]})) == [(0, False)]
