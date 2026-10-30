"""Tests of the presentations of the web front-end: an instructor shows a project, read-only, on
the browsers of chosen students.  The registries of ``sreweb.portal.presentation`` alone (fake
sockets, a fixed clock), then a real portal in front of a real agent on the fake ``sre``
(``test_web_portal.Harness`` in proxy mode: the identity is in the headers of every request)."""
import asyncio
import json
import shutil
import struct
import tempfile
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from test_agent_api import read_until, receive_event          # noqa: E402
from sreweb.identity import Identity                          # noqa: E402
from sreweb.portal import presentation as PR                  # noqa: E402
from sreweb.portal.accesslog import iso_time, parse_line      # noqa: E402
from sreweb.portal.routes import TERMINAL_SUBPROTOCOL, DISPLAY_SUBPROTOCOL   # noqa: E402

RLN = '20261026100000@@@sre/dhcp.py@@@alice'
RLN2 = '20261026100100@@@sre/dhcp.py@@@bob'
ALICE = Identity(login='alice', fullname='Alice A', group='INFO1')
BOB = Identity(login='bob', fullname='Bob B', group='INFO1')
CAROL = Identity(login='carol', group='INFO2')
DAVE = Identity(login='dave', group='INFO1')
PROF = Identity(login='prof', fullname='Pr. Of', role='instructor')
PROF2 = Identity(login='prof2', role='instructor')


def run(coro):
    return asyncio.run(coro)


class FakeWatcher(PR.Watcher):
    """A socket as the registries see it: what was sent, how it was closed."""

    def __init__(self, fail=False):
        self.sent = []
        self.closed = None
        self.fail = fail
        super().__init__(self._send, self._close)

    async def _send(self, message):
        if self.fail:
            raise ConnectionError("gone")
        self.sent.append(message)

    async def _close(self, code, reason):
        self.closed = (code, reason)


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def registries(now=1000.0):
    clock = Clock(now)
    presence = PR.Presence(clock=clock)
    return clock, presence, PR.Presentations(presence, clock=clock)


def started(p: PR.Presentation) -> dict:
    return {'t': 'presentation', 'id': p.id, 'url': f'/present/{p.id}', 'presenter': p.presenter.fullname or p.presenter.login}


def ended(p: PR.Presentation) -> dict:
    return {'t': 'presentation', 'id': p.id, 'ended': True}


# ---------------------------------------------------------------------------------------------
# the registries
# ---------------------------------------------------------------------------------------------

class TestPresence:
    def test_rows_pages_since_exclude_and_groups(self):
        clock, presence, _ = registries()
        s1 = presence.add(ALICE, '/projects', FakeWatcher())
        clock.now = 1005
        s2 = presence.add(ALICE, '/open', FakeWatcher())
        presence.add(PROF, '/watch', FakeWatcher())
        rows = presence.connected()
        assert [r['login'] for r in rows] == ['alice', 'prof']
        alice = rows[0]
        assert (alice['fullname'], alice['group'], alice['role'], alice['pages'], alice['presentation']) == \
            ('Alice A', 'INFO1', 'student', ['/open', '/projects'], None)
        assert alice['since'] == iso_time(1000)
        assert [r['login'] for r in presence.connected(exclude_login='prof')] == ['alice']
        assert presence.connected(presentation_of=lambda identity: identity.login)[1]['presentation'] == 'prof'
        assert presence.logins() == {'alice', 'prof'}
        assert presence.logins_of_group('INFO1') == {'alice'} and presence.logins_of_group('') == set()
        assert presence.identity_of('alice') == ALICE and presence.identity_of('nobody') is None
        presence.remove(s1)
        presence.remove(s2)
        presence.remove(s2)                                      # twice: harmless
        assert presence.identity_of('alice') is None and presence.logins() == {'prof'}

    def test_push_forgets_a_dead_socket(self):
        _, presence, _ = registries()
        dead, live = FakeWatcher(fail=True), FakeWatcher()
        presence.add(ALICE, '/a', dead)
        presence.add(ALICE, '/b', live)
        run(presence.push('alice', {'t': 'x'}))
        run(presence.push('nobody', {'t': 'x'}))
        assert live.sent == [{'t': 'x'}]
        assert presence.connected()[0]['pages'] == ['/b']


class TestPresentationsRegistry:
    def test_start_tells_the_connected_members_and_strips_the_presenter(self):
        _, presence, pres = registries()
        wa, wp = FakeWatcher(), FakeWatcher()
        presence.add(ALICE, '/projects', wa)
        presence.add(PROF, f'/projects/a01/{RLN}', wp)
        p = run(pres.start(PROF, 'a01', RLN, ({'alice', 'bob', 'prof'}, set())))
        assert p.logins == {'alice', 'bob'} and p.groups == set() and p.presenter_absent_since == 1000
        assert wa.sent == [started(p)] and wp.sent == []
        assert pres.of_spectator(ALICE) is p and pres.of_spectator(BOB) is p and pres.of_spectator(PROF) is None
        assert pres.spectator_of(ALICE, 'a01', RLN) is p and pres.spectator_of(ALICE, 'a02', RLN) is None
        assert pres.presentation_id_of(ALICE) == p.id and pres.presentation_id_of(CAROL) is None
        assert pres.for_presenter('prof') == [p] and pres.listing() == [p] and pres.get('nope') is None
        d = p.to_dict(presence)
        assert d['audience'] == {'logins': ['alice', 'bob'], 'groups': []}
        assert d['presenter'] == {'login': 'prof', 'fullname': 'Pr. Of'} and (d['count'], d['connected']) == (2, 0)
        assert d['started_at'] == iso_time(1000) and d['view'] == {}
        # bob connects later: the route calls resync for him
        wb = FakeWatcher()
        presence.add(BOB, '/open', wb)
        run(pres.resync({'bob'}))
        assert wb.sent == [started(p)]
        run(pres.resync({'bob'}))
        assert wb.sent == [started(p)]                           # told once

    def test_groups_and_the_newest_presentation_wins(self):
        clock, presence, pres = registries()
        wa, wb, wc = FakeWatcher(), FakeWatcher(), FakeWatcher()
        presence.add(ALICE, '/', wa)
        presence.add(BOB, '/', wb)
        presence.add(CAROL, '/', wc)
        p1 = run(pres.start(PROF, 'a01', RLN, (set(), {'INFO1'})))
        assert wa.sent == [started(p1)] and wb.sent == [started(p1)] and wc.sent == []
        assert p1.to_dict(presence)['count'] == 2                 # the connected members of the group
        # a second presentation naming bob: bob moves to it, alice stays
        clock.now = 1010
        p2 = run(pres.start(PROF2, 'a01', RLN2, ({'bob'}, set())))
        assert wb.sent[1:] == [ended(p1), started(p2)] and wa.sent == [started(p1)]
        assert pres.of_spectator(BOB) is p2 and pres.of_spectator(ALICE) is p1
        # a member of the group connecting later gets p1
        wd = FakeWatcher()
        presence.add(DAVE, '/', wd)
        run(pres.resync({'dave'}))
        assert wd.sent == [started(p1)]
        # p2 ends: bob falls back to p1, which still runs
        run(pres.end(p2.id))
        assert wb.sent[3:] == [ended(p2), started(p1)]
        # the same presenter on the same project again: the first one is replaced
        clock.now = 1020
        p3 = run(pres.start(PROF, 'a01', RLN, ({'alice'}, set())))
        assert pres.get(p1.id) is None and pres.listing() == [p3]
        assert wa.sent[1:] == [ended(p1), started(p3)]
        assert wb.sent[5:] == [ended(p1)] and wd.sent[1:] == [ended(p1)]

    def test_audience_view_sockets_and_end(self):
        _, presence, pres = registries()
        wa, wb = FakeWatcher(), FakeWatcher()
        presence.add(ALICE, '/', wa)
        presence.add(BOB, '/', wb)
        p = run(pres.start(PROF, 'a01', RLN, ({'alice'}, set())))
        presenter = FakeWatcher()
        assert run(pres.attach_presenter(p.id, presenter)) is True
        assert presenter.sent == [{'t': 'audience', 'count': 1, 'connected': 0}] and p.presenter_absent_since is None
        spectator = FakeWatcher()
        assert run(pres.attach_spectator(p.id, ALICE, spectator)) is True
        assert spectator.sent == [{'t': 'view', 'view': {}}]
        assert presenter.sent[-1] == {'t': 'audience', 'count': 1, 'connected': 1}
        assert run(pres.attach_spectator(p.id, BOB, FakeWatcher())) is False     # not in the audience
        # the view: validated, stored, pushed; a new spectator gets it at once
        with pytest.raises(ValueError):
            run(pres.set_view(p.id, [1]))
        with pytest.raises(ValueError):
            run(pres.set_view(p.id, {'x': 'y' * PR.MAX_VIEW_BYTES}))
        with pytest.raises(KeyError):
            run(pres.set_view('nope', {}))
        run(pres.set_view(p.id, {'tab': 'schema'}))
        assert spectator.sent[-1] == {'t': 'view', 'view': {'tab': 'schema'}}
        again = FakeWatcher()
        run(pres.attach_spectator(p.id, ALICE, again))
        assert again.sent == [{'t': 'view', 'view': {'tab': 'schema'}}]
        # the table of the presenter's Evaluation tab: validated, stored, pushed; a spectator
        # attaching later gets it right after the view; a dead socket is forgotten
        with pytest.raises(ValueError):
            run(pres.set_evaluation(p.id, {'rows': []}))                   # no header
        with pytest.raises(ValueError):
            run(pres.set_evaluation(p.id, {'header': [], 'rows': 'x'}))
        with pytest.raises(ValueError):
            run(pres.set_evaluation(p.id, {'header': [], 'rows': [], 'caption': 'y' * PR.MAX_EVALUATION_BYTES}))
        with pytest.raises(KeyError):
            run(pres.set_evaluation('nope', {'header': [], 'rows': []}))
        table = {'header': ['Element', 'Grade', 'Max grade'], 'rows': [{'kind': 'element', 'cells': []}],
                 'caption': '', 'title': ''}
        dead = FakeWatcher(fail=True)
        run(pres.attach_spectator(p.id, ALICE, dead))
        run(pres.set_evaluation(p.id, table))
        assert spectator.sent[-1] == {'t': 'evaluation', 'evaluation': table}
        assert again.sent[-1] == {'t': 'evaluation', 'evaluation': table}
        assert dead not in p.spectator_sockets['alice'] and p.evaluation == table
        late = FakeWatcher()
        run(pres.attach_spectator(p.id, ALICE, late))
        assert late.sent == [{'t': 'view', 'view': {'tab': 'schema'}}, {'t': 'evaluation', 'evaluation': table}]
        run(pres.detach_spectator(p.id, 'alice', late))
        run(pres.detach_spectator(p.id, 'alice', again))
        assert presenter.sent[-1] == {'t': 'audience', 'count': 1, 'connected': 1}
        # the audience changed: alice out (her socket closed, her browser told), bob in
        run(pres.set_audience(p.id, ({'bob'}, set())))
        assert spectator.closed == (PR.WS_PRESENTATION_ENDED, "the presentation has ended")
        assert wa.sent[1:] == [ended(p)] and wb.sent == [started(p)]
        assert presenter.sent[-1] == {'t': 'audience', 'count': 1, 'connected': 0}
        assert run(pres.attach_spectator(p.id, ALICE, FakeWatcher())) is False
        with pytest.raises(KeyError):
            run(pres.set_audience('nope', (set(), set())))
        # the end: every socket closed once, the browsers told, idempotent
        viewer = FakeWatcher()
        run(pres.attach_spectator(p.id, BOB, viewer))
        assert run(pres.end(p.id)) is p and run(pres.end(p.id)) is None
        assert viewer.closed == (PR.WS_PRESENTATION_ENDED, "the presentation has ended")
        assert presenter.closed == (PR.WS_PRESENTATION_ENDED, "the presentation has ended")
        assert wb.sent[-1] == ended(p) and pres.listing() == [] and pres.shown == {}
        assert run(pres.attach_presenter(p.id, FakeWatcher())) is False
        pres.detach_presenter(p.id, presenter)                   # gone: harmless

    def test_grace_of_an_absent_presenter(self):
        clock, presence, pres = registries()
        p = run(pres.start(PROF, 'a01', RLN, ({'alice'}, set())))
        run(pres.tick(1059))
        assert pres.get(p.id) is p
        run(pres.tick(1060))
        assert pres.get(p.id) is None
        p = run(pres.start(PROF, 'a01', RLN, ({'alice'}, set())))
        w = FakeWatcher()
        run(pres.attach_presenter(p.id, w))
        run(pres.tick(5000))
        assert pres.get(p.id) is p                                # present: never ends
        clock.now = 5000
        pres.detach_presenter(p.id, w)
        assert p.presenter_absent_since == 5000
        run(pres.tick(5059))
        assert pres.get(p.id) is p
        run(pres.tick(5060))
        assert pres.get(p.id) is None
        p = run(pres.start(PROF, 'a01', RLN, ({'alice'}, set())))
        run(pres.shutdown())
        assert pres.listing() == []

    def test_parse_audience(self):
        assert PR.parse_audience(['alice', 'prof'], 'prof') == ({'alice'}, set())
        assert PR.parse_audience({'logins': ['bob'], 'groups': [' INFO1 ']}, 'prof') == ({'bob'}, {'INFO1'})
        assert PR.parse_audience({}, 'prof') == (set(), set())
        assert PR.audience_size(({'a', 'b'}, {'g'})) == 3
        for bad in ('x', None, {'logins': 'alice'}, ['bad login!'], [1], {'groups': ['']}, {'groups': ['a\x00b']},
                    {'groups': [3]}):
            with pytest.raises(ValueError):
                PR.parse_audience(bad, 'prof')
        with pytest.raises(ValueError):
            PR.parse_audience([f'u{i}' for i in range(PR.MAX_AUDIENCE + 1)], 'prof')


# ---------------------------------------------------------------------------------------------
# through the portal
# ---------------------------------------------------------------------------------------------

async def start_project(h, headers, **body) -> str:
    resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py', **body}, headers={**headers, **P.CSRF})
    assert resp.status == 200, await resp.text()
    return [json.loads(l) for l in (await resp.text()).splitlines()][-1]['running_lab_name']


async def present(h, headers, rln, audience) -> dict:
    resp = await h.client.post('/api/presentations', json={'host': 'a01', 'rln': rln, 'audience': audience},
                               headers={**headers, **P.CSRF})
    assert resp.status == 201, await resp.text()
    return await resp.json()


async def receive_text(ws, kind, timeout=5.0) -> dict:
    """The next text frame of *kind* on a terminal WebSocket (the binary frames are skipped)."""
    async with asyncio.timeout(timeout):
        while True:
            msg = await ws.receive()
            assert msg.type in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT), msg
            if msg.type == aiohttp.WSMsgType.TEXT and json.loads(msg.data).get('t') == kind:
                return json.loads(msg.data)


async def receive_close(ws, timeout=5.0):
    """The close frame of a socket (the text frames before it are skipped); its code is the
    frame's data: what a browser gets as the close event's code."""
    async with asyncio.timeout(timeout):
        while True:
            msg = await ws.receive()
            if msg.type == aiohttp.WSMsgType.CLOSE:
                return msg
            assert msg.type == aiohttp.WSMsgType.TEXT, msg


async def collect_bytes(ws, n: int, timeout=5.0) -> bytes:
    out = b''
    async with asyncio.timeout(timeout):
        while len(out) < n:
            msg = await ws.receive()
            assert msg.type == aiohttp.WSMsgType.BINARY, msg
            out += msg.data
    return out


class TestPresentationThroughThePortal:
    def test_lifecycle(self, tmp_path):
        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                alice, bob = P.who('alice', 'Alice', group='INFO1'), P.who('bob', 'Bob', group='INFO1')
                carol, prof = P.who('carol', group='INFO2'), P.who('prof', 'Pr. Of', groups=P.TEACHERS)
                rln = await start_project(h, alice)
                # the presence sockets and the list of the connected users
                bob_ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=bob)
                carol_ws = await h.client.ws_connect('/api/presence/ws', headers=carol)
                assert (await h.client.get('/api/presence', headers=bob)).status == 403
                rows = await (await h.client.get('/api/presence', headers=prof)).json()
                assert [(r['login'], r['group'], r['pages'], r['presentation']) for r in rows] == \
                    [('bob', 'INFO1', ['/projects'], None), ('carol', 'INFO2', [], None)]
                # the start: bob by login, carol by her group; both told at once
                assert (await h.client.post('/api/presentations', json={'host': 'a01', 'rln': rln, 'audience': ['bob']},
                                            headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.post('/api/presentations', json={'host': 'nope', 'rln': rln, 'audience': []},
                                            headers={**prof, **P.CSRF})).status == 404
                assert (await h.client.post('/api/presentations', json={'host': 'a01', 'rln': 'x', 'audience': []},
                                            headers={**prof, **P.CSRF})).status == 400
                assert (await h.client.post('/api/presentations', json={'host': 'a01', 'rln': rln, 'audience': 'bob'},
                                            headers={**prof, **P.CSRF})).status == 400
                p = await present(h, prof, rln, {'logins': ['bob'], 'groups': ['INFO2']})
                pid = p['id']
                assert (p['host'], p['rln'], p['presenter']) == ('a01', rln, {'login': 'prof', 'fullname': 'Pr. Of'})
                assert p['audience'] == {'logins': ['bob'], 'groups': ['INFO2']} and (p['count'], p['connected']) == (2, 0)
                told = {'t': 'presentation', 'id': pid, 'url': f'/present/{pid}', 'presenter': 'Pr. Of'}
                assert await asyncio.wait_for(bob_ws.receive_json(), 5) == told
                assert await asyncio.wait_for(carol_ws.receive_json(), 5) == told
                # a student of the group connecting later is told at once
                dave_ws = await h.client.ws_connect('/api/presence/ws', headers=P.who('dave', group='INFO2'))
                assert await asyncio.wait_for(dave_ws.receive_json(), 5) == told
                rows = await (await h.client.get('/api/presence', headers=prof)).json()
                assert {r['login']: r['presentation'] for r in rows} == {'bob': pid, 'carol': pid, 'dave': pid}
                # the page of a spectator, framed; the other pages keep the strict policy
                page = await h.client.get(f'/present/{pid}', headers=bob)
                assert page.status == 200 and rln in await page.text()
                assert "frame-ancestors 'self'" in page.headers['Content-Security-Policy']
                assert page.headers['X-Frame-Options'] == 'SAMEORIGIN'
                assert (await h.client.get(f'/present/{pid}', headers=alice)).status == 403     # the owner is not in it
                assert (await h.client.get(f'/present/{pid}', headers=prof)).status == 403      # nor the presenter
                assert (await h.client.get('/present/nope', headers=bob)).status == 404
                assert (await h.client.get(f'/present/{pid}', allow_redirects=False)).status == 302
                other = await h.client.get('/projects', headers=bob)
                assert "frame-ancestors 'none'" in other.headers['Content-Security-Policy']
                assert other.headers['X-Frame-Options'] == 'DENY'
                # the API of a presentation
                assert (await h.client.get('/api/presentations', headers=bob)).status == 403
                assert [x['id'] for x in await (await h.client.get('/api/presentations', headers=prof)).json()] == [pid]
                assert (await h.client.get(f'/api/presentations/{pid}', headers=bob)).status == 200
                assert (await h.client.get(f'/api/presentations/{pid}', headers=prof)).status == 200
                assert (await h.client.get(f'/api/presentations/{pid}', headers=alice)).status == 403
                assert (await h.client.put(f'/api/presentations/{pid}/view', json={'view': {}},
                                           headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.put(f'/api/presentations/{pid}/audience', json={'audience': []},
                                           headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.put(f'/api/presentations/{pid}/view', json={'view': {}},
                                           headers=prof)).status == 403                        # no CSRF header
                # the sockets: the presenter's counts, a spectator's view
                prof_ws = await h.client.ws_connect(f'/api/presentations/{pid}/ws', headers=prof)
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == {'t': 'audience', 'count': 3, 'connected': 0}
                bob_pws = await h.client.ws_connect(f'/api/presentations/{pid}/ws', headers=bob)
                assert await asyncio.wait_for(bob_pws.receive_json(), 5) == {'t': 'view', 'view': {}}
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == {'t': 'audience', 'count': 3, 'connected': 1}
                with pytest.raises(aiohttp.WSServerHandshakeError):
                    await h.client.ws_connect(f'/api/presentations/{pid}/ws', headers=alice)
                view = {'tab': 'terminals', 'instructorView': False, 'terminals': {'open': [], 'active': None}}
                resp = await h.client.put(f'/api/presentations/{pid}/view', json={'view': view}, headers={**prof, **P.CSRF})
                assert resp.status == 204
                assert await asyncio.wait_for(bob_pws.receive_json(), 5) == {'t': 'view', 'view': view}
                assert (await h.client.put(f'/api/presentations/{pid}/view', json={'view': [1]},
                                           headers={**prof, **P.CSRF})).status == 400
                assert (await (await h.client.get(f'/api/presentations/{pid}', headers=bob)).json())['view'] == view
                # the audience edited: carol by login now, her group dropped: dave leaves
                resp = await h.client.put(f'/api/presentations/{pid}/audience',
                                          json={'audience': {'logins': ['bob', 'carol'], 'groups': []}},
                                          headers={**prof, **P.CSRF})
                assert resp.status == 200 and (await resp.json())['count'] == 2
                assert await asyncio.wait_for(dave_ws.receive_json(), 5) == {'t': 'presentation', 'id': pid, 'ended': True}
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == {'t': 'audience', 'count': 2, 'connected': 1}
                # the end: the presenter or an instructor; every socket closed, the browsers told
                assert (await h.client.delete(f'/api/presentations/{pid}', headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.delete(f'/api/presentations/{pid}', headers={**prof, **P.CSRF})).status == 200
                assert (await receive_close(bob_pws)).data == 4411     # the frame: what a browser sees
                assert (await receive_close(prof_ws)).data == 4411
                over = {'t': 'presentation', 'id': pid, 'ended': True}
                assert await asyncio.wait_for(bob_ws.receive_json(), 5) == over
                assert await asyncio.wait_for(carol_ws.receive_json(), 5) == over
                gone = await h.client.ws_connect(f'/api/presentations/{pid}/ws', headers=bob)
                assert (await receive_close(gone)).data == 4411
                assert (await h.client.get(f'/present/{pid}', headers=bob)).status == 404
                assert (await h.client.delete(f'/api/presentations/{pid}', headers={**prof, **P.CSRF})).status == 404
                for ws in (bob_ws, carol_ws, dave_ws):
                    await ws.close()
        P.run(go())

    def test_evaluation_table_of_the_presenter(self, tmp_path):
        """The spectators show the table of the presenter's Evaluation tab as their page sends it
        (PUT .../evaluation: the presenter's own self-evaluation may be letters no archive holds),
        at attach and on every change; they no longer read the last archived evaluation."""
        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                bob, prof = P.who('bob', 'Bob'), P.who('prof', 'Pr. Of', groups=P.TEACHERS)
                rln = await start_project(h, prof)                 # the instructor's own project
                pid = (await present(h, prof, rln, ['bob']))['id']
                table = {'header': ['Element', 'Grade', 'Max grade'],
                         'rows': [{'kind': 'element', 'bold': False, 'span': False,
                                   'cells': [{'text': 'Default route of m1', 'color': None, 'align': 'left'},
                                             {'text': 'OK', 'color': '#c8e6c9', 'align': 'center'},
                                             {'text': '', 'color': None, 'align': 'center'}]}],
                         'caption': '', 'title': ''}
                assert (await h.client.put(f'/api/presentations/{pid}/evaluation', json={'evaluation': table},
                                           headers={**bob, **P.CSRF})).status == 403          # the presenter only
                assert (await h.client.put(f'/api/presentations/{pid}/evaluation', json={'evaluation': table},
                                           headers=prof)).status == 403                        # no CSRF header
                assert (await h.client.put(f'/api/presentations/{pid}/evaluation', json={'evaluation': [1]},
                                           headers={**prof, **P.CSRF})).status == 400
                big = {**table, 'caption': 'x' * PR.MAX_EVALUATION_BYTES}
                assert (await h.client.put(f'/api/presentations/{pid}/evaluation', json={'evaluation': big},
                                           headers={**prof, **P.CSRF})).status == 413
                bob_ws = await h.client.ws_connect(f'/api/presentations/{pid}/ws', headers=bob)
                assert await asyncio.wait_for(bob_ws.receive_json(), 5) == {'t': 'view', 'view': {}}
                resp = await h.client.put(f'/api/presentations/{pid}/evaluation', json={'evaluation': table},
                                          headers={**prof, **P.CSRF})
                assert resp.status == 204
                assert await asyncio.wait_for(bob_ws.receive_json(), 5) == {'t': 'evaluation', 'evaluation': table}
                # a page of bob's opened now: the view, then the table; the listing stays small
                late = await h.client.ws_connect(f'/api/presentations/{pid}/ws', headers=bob)
                assert await asyncio.wait_for(late.receive_json(), 5) == {'t': 'view', 'view': {}}
                assert await asyncio.wait_for(late.receive_json(), 5) == {'t': 'evaluation', 'evaluation': table}
                assert 'evaluation' not in await (await h.client.get(f'/api/presentations/{pid}', headers=bob)).json()
                # the last archived evaluation is no longer relayed to a spectator
                assert (await h.client.get(f'/api/projects/a01/{rln}/evaluation', headers=bob)).status == 403
                await late.close()
                await bob_ws.close()
        P.run(go())

    def test_spectator_relays(self, tmp_path):
        async def go():
            log = tmp_path / 'mock.log'
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER,
                                 mock_env={'MOCK_SRE_LOG': str(log)}) as h:
                alice, bob, prof = P.who('alice', 'Alice'), P.who('bob', 'Bob'), P.who('prof', 'Pr. Of', groups=P.TEACHERS)
                rln = await start_project(h, alice)
                base = f'/api/projects/a01/{rln}'
                assert (await h.client.get(base, headers=bob)).status == 403                   # before the presentation
                pid = (await present(h, prof, rln, ['bob']))['id']
                data = await (await h.client.get(base, headers=bob)).json()
                assert data['owner'] == 'alice' and data['running_lab_name'] == rln and data['host'] == 'a01'
                assert 'answers_readonly' not in data      # no flag: the portal refuses a spectator's PUT (below)
                assert (await h.client.get(f'{base}/evaluation', headers=bob)).status == 403   # the presenter's table comes by the presentation socket
                assert (await h.client.get(f'{base}/schema.svg?curved=1', headers=bob)).status in (200, 500)
                assert (await h.client.post(f'{base}/touch', headers={**bob, **P.CSRF})).status == 204
                # everything that acts on the project, and the project page itself
                assert (await h.client.put(f'{base}/answers', json={'answers': {}}, headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.post(f'{base}/eval', headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.post(f'{base}/states/final', headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.get(f'{base}/schema.pdf', headers=bob)).status == 403
                assert (await h.client.post(f'{base}/display', headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.delete(base, headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.get(f'/projects/a01/{rln}', headers=bob)).status == 403
                # another student is still refused
                assert (await h.client.get(base, headers=P.who('carol'))).status == 403
                # the events socket (quiet until something happens: the presenter's terminal below)
                events = await h.client.ws_connect(f'{base}/events', headers=bob)
                # the terminals: a spectator only joins what the presenter opened, read-only
                with pytest.raises(aiohttp.WSServerHandshakeError):
                    await h.client.ws_connect(f'{base}/terminals/m1', headers=bob, protocols=(TERMINAL_SUBPROTOCOL,))
                prof_term = await h.client.ws_connect(f'{base}/terminals/m1?cols=100&rows=30', headers=prof,
                                                      protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(prof_term.receive_json(), 5)
                sid = ready['session']
                assert ready['readonly'] is False and (ready['cols'], ready['rows']) == (100, 30)
                await read_until(prof_term, b'mock$')
                assert (await receive_event(events, 'terminals'))['terminals'][0]['id'] == sid
                bob_term = await h.client.ws_connect(f'{base}/terminals/m1?join={sid}&cols=20&rows=5&private=1',
                                                     headers=bob, protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(bob_term.receive_json(), 5)
                assert ready['readonly'] is True and ready['joined'] and (ready['clients'], ready['viewers']) == (1, 1)
                assert (ready['cols'], ready['rows']) == (100, 30)
                await read_until(bob_term, b'mock$')                       # the replay
                await bob_term.send_bytes(b'echo NOPE\n')                 # dropped by the portal
                await bob_term.send_str(json.dumps({'t': 'resize', 'cols': 10, 'rows': 3}))
                await prof_term.send_str(json.dumps({'t': 'resize', 'cols': 90, 'rows': 25}))
                size = await receive_text(bob_term, 'size')
                assert (size['cols'], size['rows']) == (90, 25)
                await prof_term.send_bytes(b'echo STILL\n')
                out = await read_until(prof_term, b'STILL', after=b'echo STILL')
                assert b'NOPE' not in out
                await read_until(bob_term, b'STILL', after=b'echo STILL')  # the spectator sees it
                connects = [json.loads(l) for l in log.read_text().splitlines() if '"connect"' in l]
                assert len(connects) == 1 and connects[0]['username'] == 'prof'   # the presenter's shell, nothing of bob's
                await bob_term.close()
                await prof_term.close()
                await events.close()
                # the presentation over: the spectator is a stranger again
                assert (await h.client.delete(f'/api/presentations/{pid}', headers={**prof, **P.CSRF})).status == 200
                assert (await h.client.get(base, headers=bob)).status == 403
        P.run(go())

    def test_instructor_view_follows_the_presenter(self, tmp_path):
        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                bob, prof = P.who('bob'), P.who('prof', 'Pr. Of', groups=P.TEACHERS)
                rln = await start_project(h, prof, instructor_mode=True)
                base = f'/api/projects/a01/{rln}'
                pid = (await present(h, prof, rln, ['bob']))['id']
                view = (await (await h.client.get(base, headers=bob)).json())['project']
                assert view['instructor_mode'] and view['has_instructor_texts'] and not view['instructor_view']
                assert 'Solution' not in view['informations_html'] and 'log' not in view['tabs']
                # the spectator's own ?view= is ignored
                view = (await (await h.client.get(f'{base}?view=instructor', headers=bob)).json())['project']
                assert not view['instructor_view']
                # the presenter turns the instructor texts on: the spectators get them
                resp = await h.client.put(f'/api/presentations/{pid}/view', json={'view': {'instructorView': True}},
                                          headers={**prof, **P.CSRF})
                assert resp.status == 204
                view = (await (await h.client.get(base, headers=bob)).json())['project']
                assert view['instructor_view'] and 'Solution' in view['informations_html'] and 'log' in view['tabs']
                resp = await h.client.put(f'/api/presentations/{pid}/view', json={'view': {'instructorView': 'yes'}},
                                          headers={**prof, **P.CSRF})
                assert resp.status == 204                                 # not a bool: the student view
                view = (await (await h.client.get(base, headers=bob)).json())['project']
                assert not view['instructor_view']
        P.run(go())

    def test_presenter_grace_through_the_portal(self, tmp_path):
        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                alice, bob, prof = P.who('alice'), P.who('bob'), P.who('prof', groups=P.TEACHERS)
                rln = await start_project(h, alice)
                pid = (await present(h, prof, rln, ['bob']))['id']
                bob_pws = await h.client.ws_connect(f'/api/presentations/{pid}/ws', headers=bob)
                await asyncio.wait_for(bob_pws.receive_json(), 5)
                pres = h.portal.presentations
                now = pres.clock()
                await pres.tick(now + PR.PRESENTER_GRACE - 1)
                assert pres.get(pid) is not None
                await pres.tick(now + PR.PRESENTER_GRACE)
                assert pres.listing() == []
                assert (await receive_close(bob_pws)).data == 4411
        P.run(go())

    def test_access_log_lines(self, tmp_path):
        over = {**P.PROXY_OVER, 'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over) as h:
                alice, bob, prof = P.who('alice'), P.who('bob'), P.who('prof', groups=P.TEACHERS)
                rln = await start_project(h, alice)
                bob_ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=bob)
                pid = (await present(h, prof, rln, {'logins': ['bob'], 'groups': ['INFO9']}))['id']
                await asyncio.wait_for(bob_ws.receive_json(), 5)
                assert (await h.client.get(f'/present/{pid}', headers=bob)).status == 200
                events = await h.client.ws_connect(f'/api/projects/a01/{rln}/events', headers=bob)
                await events.close()
                await h.client.put(f'/api/presentations/{pid}/audience', json={'audience': ['bob']},
                                   headers={**prof, **P.CSRF})
                await h.client.put(f'/api/presentations/{pid}/view', json={'view': {'tab': 'schema'}},
                                   headers={**prof, **P.CSRF})
                await h.client.delete(f'/api/presentations/{pid}', headers={**prof, **P.CSRF})
                await bob_ws.close()
                return rln, pid

        rln, pid = P.run(go())
        lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
        by_event = {}
        for line in lines:
            by_event.setdefault(line['event'], []).append(line)
        start = by_event['present_start'][0]
        assert (start['login'], start['host'], start['rln'], start['audience'], start['status']) == ('prof', 'a01', rln, '2', '201')
        opened = by_event['present_open'][0]
        assert (opened['login'], opened['host'], opened['rln'], opened['presenter'], opened['id']) == ('bob', 'a01', rln, 'prof', pid)
        assert by_event['present_audience'][0]['audience'] == '1' and by_event['present_stop'][0]['login'] == 'prof'
        close = [l for l in by_event['project_close'] if l['login'] == 'bob'][0]
        assert close['spectator'] == '1' and close['rln'] == rln
        assert 'spectator' not in by_event['project_open'][0]                     # not known when the socket opens
        text = (tmp_path / 'access.log').read_text()
        assert 'presence' not in text and '/view' not in text         # neither the presence socket nor the view
        bob_session = [l for l in by_event['session_close'] if l['login'] == 'bob'][0]
        assert bob_session['requests'] == '2' and bob_session['projects'] == rln    # the page and the events socket


class TestSpectatorDisplay:
    def test_view_only_stream(self, tmp_path):
        runtime_dir = Path(tempfile.mkdtemp(prefix='sre-x11-', dir='/tmp'))    # short: an AF_UNIX path

        async def go():
            display = P.TestDisplayThroughThePortal.display_over(runtime_dir)
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER, mock_env={'MOCK_X11': '1'},
                                 agent_over=display) as h:
                alice, bob, prof = P.who('alice'), P.who('bob'), P.who('prof', groups=P.TEACHERS)
                rln = await start_project(h, alice)
                base = f'/api/projects/a01/{rln}'
                await present(h, prof, rln, ['bob'])
                status = await (await h.client.get(f'{base}/display', headers=bob)).json()
                assert status['available'] is True
                assert (await h.client.post(f'{base}/display', headers={**bob, **P.CSRF})).status == 403
                ws = await h.client.ws_connect(f'{base}/display/ws', headers=bob, protocols=(DISPLAY_SUBPROTOCOL,))
                assert (await asyncio.wait_for(ws.receive(), 5)).data == b'RFB 003.008\n'
                handshake = b'RFB 003.008\n\x01\x01'
                await ws.send_bytes(handshake)
                assert await collect_bytes(ws, len(handshake)) == handshake   # the handshake passes (echoed back)
                key = b'\x04\x01\x00\x00\x00\x00\x00\x61'
                request = b'\x03\x00' + struct.pack('>HHHH', 0, 0, 10, 10)
                pointer = b'\x05\x01\x00\x0a\x00\x14'
                await ws.send_bytes(key + request + pointer)
                assert await collect_bytes(ws, len(request)) == request       # the input never reached the server
                await ws.send_bytes(b'\x07')
                closing = await asyncio.wait_for(ws.receive(), 5)
                assert closing.type == aiohttp.WSMsgType.CLOSE and closing.data == 4403
        try:
            P.run(go())
        finally:
            shutil.rmtree(runtime_dir, ignore_errors=True)
