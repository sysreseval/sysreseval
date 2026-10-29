"""The focus of the web front-end: an instructor helping a student keeps the student's browser
on the project they look at together, the two pages sharing the tab, the terminal and the
question (``src/sreweb/portal/focus.py``, the ``/api/focus`` routes).  The registry alone with
fake sockets, then through the portal with a real agent on the fake ``sre``."""
import asyncio
import urllib.parse

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
import test_web_presentation as T                             # noqa: E402  (the fakes and the identities)
from sreweb.identity import Identity                          # noqa: E402
from sreweb.portal import focus as FO                         # noqa: E402
from sreweb.portal import presentation as PR                  # noqa: E402
from sreweb.portal.accesslog import iso_time, parse_line      # noqa: E402

RLN = '20261026100000@@@sre@dhcp.py@@@alice'                   # the @ form of the real names
RLN_PROF = '20261026100200@@@sre@dhcp.py@@@prof'
ALICE, BOB, PROF, PROF2 = T.ALICE, T.BOB, T.PROF, T.PROF2
run = T.run
FakeWatcher = T.FakeWatcher


def registries(now=1000.0):
    clock = T.Clock(now)
    presence = PR.Presence(clock=clock)
    return clock, presence, FO.Focuses(presence, clock=clock)


def started(f: FO.Focus) -> dict:
    return {'t': 'focus', 'id': f.id, 'url': FO.project_page_url(f.host, f.rln), 'host': f.host, 'rln': f.rln,
            'instructor': f.instructor.fullname or f.instructor.login}


def ended(f: FO.Focus) -> dict:
    return {'t': 'focus', 'id': f.id, 'ended': True}


def status(n: int) -> dict:
    return {'t': 'student', 'connected': n}


def view_of(view: dict) -> dict:
    return {'t': 'view', 'view': view}


# ---------------------------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------------------------

class TestFocusRegistry:
    def test_project_page_url_is_what_the_browser_builds(self):
        # encodeURIComponent: the @ and the / of a running lab name encoded
        assert FO.project_page_url('a01', '2026@@@sre/dhcp.py@@@alice') == '/projects/a01/2026%40%40%40sre%2Fdhcp.py%40%40%40alice'

    def test_start_tells_the_student_and_every_new_page(self):
        _, presence, foc = registries()
        wa, wp = FakeWatcher(), FakeWatcher()
        presence.add(ALICE, '/projects', wa)
        presence.add(PROF, f'/projects/a01/{RLN}', wp)
        f = run(foc.start(PROF, 'a01', RLN, {'tab': 'schema'}))
        assert (f.student, f.instructor, f.host, f.rln, f.instructor_absent_since) == ('alice', PROF, 'a01', RLN, 1000)
        assert wa.sent == [started(f)] and wp.sent == []
        assert started(f)['url'] == f'/projects/a01/{urllib.parse.quote(RLN, safe="")}'
        assert foc.of_student('alice') is f and foc.of_student('bob') is None and foc.of_student(None) is None
        assert foc.for_instructor('prof') == [f] and foc.for_instructor('prof2') == []
        assert foc.listing() == [f] and foc.get('nope') is None and foc.get(f.id) is f
        assert f.participant(ALICE) and f.participant(PROF) and not f.participant(BOB) and not f.participant(None)
        assert f.to_dict() == {'id': f.id, 'host': 'a01', 'rln': RLN, 'instructor': {'login': 'prof', 'fullname': 'Pr. Of'},
                               'student': 'alice', 'view': {'tab': 'schema'}, 'started_at': iso_time(1000), 'connected': 0}
        # alice opens another page: resync has nothing new for her login, tell() informs that page
        wa2 = FakeWatcher()
        presence.add(ALICE, '/open', wa2)
        run(foc.resync({'alice'}))
        assert wa.sent == [started(f)] and wa2.sent == []
        run(foc.tell('alice', wa2))
        assert wa2.sent == [started(f)] and wa.sent == [started(f)]
        wb = FakeWatcher()
        presence.add(BOB, '/open', wb)
        run(foc.tell('bob', wb))
        assert wb.sent == []
        # a student connecting later is told by resync (the route calls it on every presence socket)
        presence.remove(presence._sockets['alice'][0])
        presence.remove(presence._sockets['alice'][0])
        run(foc.resync({'alice'}))                               # gone: forgotten
        assert foc.shown == {}
        wa3 = FakeWatcher()
        presence.add(ALICE, '/projects', wa3)
        run(foc.resync({'alice'}))
        assert wa3.sent == [started(f)] and foc.shown == {'alice': f.id}

    def test_start_refusals(self):
        _, _, foc = registries()
        with pytest.raises(ValueError, match="bad running lab name"):
            run(foc.start(PROF, 'a01', 'x'))
        with pytest.raises(ValueError, match="your own project"):
            run(foc.start(PROF, 'a01', RLN_PROF))
        with pytest.raises(ValueError, match="JSON object"):
            run(foc.start(PROF, 'a01', RLN, [1]))
        with pytest.raises(ValueError, match="too large"):
            run(foc.start(PROF, 'a01', RLN, {'x': 'a' * PR.MAX_VIEW_BYTES}))
        assert foc.listing() == []
        f = run(foc.start(PROF, 'a01', RLN))                     # no view: an empty one
        assert f.view == {}
        # another instructor may focus an instructor's own project: its owner is the student
        g = run(foc.start(PROF2, 'a01', RLN_PROF))
        assert g.student == 'prof' and g.participant(PROF)

    def test_replaced_newest_wins_and_fallback(self):
        clock, presence, foc = registries()
        wa = FakeWatcher()
        presence.add(ALICE, '/', wa)
        f1 = run(foc.start(PROF, 'a01', RLN))
        f2 = run(foc.start(PROF, 'a01', RLN))                    # the same instructor again: replaced
        assert foc.get(f1.id) is None and foc.listing() == [f2]
        assert wa.sent == [started(f1), ended(f1), started(f2)]
        # a second instructor focuses alice: the newest wins, her socket on f2 is closed
        ws2 = FakeWatcher()
        assert run(foc.attach_student(f2.id, ALICE, ws2))
        clock.now = 1010
        f3 = run(foc.start(PROF2, 'a01', RLN))
        assert foc.of_student('alice') is f3 and foc.listing() == [f2, f3]
        assert wa.sent[3:] == [ended(f2), started(f3)]
        assert ws2.closed == (FO.WS_FOCUS_ENDED, "the focus has ended") and f2.student_sockets == set()
        # f3 ends: alice falls back to f2, which still runs
        run(foc.end(f3.id))
        assert wa.sent[5:] == [ended(f3), started(f2)] and foc.of_student('alice') is f2
        run(foc.end(f2.id))
        assert wa.sent[7:] == [ended(f2)] and foc.shown == {}

    def test_view_sockets_and_end(self):
        _, presence, foc = registries()
        wa = FakeWatcher()
        presence.add(ALICE, '/', wa)
        f = run(foc.start(PROF, 'a01', RLN, {'tab': 'schema'}))
        wi, ws = FakeWatcher(), FakeWatcher()
        assert run(foc.attach_instructor(f.id, wi))
        assert wi.sent == [status(0), view_of({'tab': 'schema'})] and f.instructor_absent_since is None
        assert not run(foc.attach_student(f.id, BOB, FakeWatcher()))        # not the student
        assert run(foc.attach_student(f.id, ALICE, ws))
        assert ws.sent == [view_of({'tab': 'schema'})] and wi.sent[2:] == [status(1)]
        # a view from either page reaches every socket of both
        run(foc.set_view(f.id, {'tab': 'terminals', 'terminal': 's1', 'question': None}))
        v = view_of({'tab': 'terminals', 'terminal': 's1', 'question': None})
        assert ws.sent[1:] == [v] and wi.sent[3:] == [v] and f.view == v['view']
        with pytest.raises(ValueError):
            run(foc.set_view(f.id, [1]))
        with pytest.raises(ValueError):
            run(foc.set_view(f.id, {'x': 'a' * PR.MAX_VIEW_BYTES}))
        with pytest.raises(KeyError):
            run(foc.set_view('nope', {}))
        # the student's page goes and comes back: the instructor's page is told each time
        run(foc.detach_student(f.id, ws))
        assert wi.sent[4:] == [status(0)]
        assert run(foc.attach_student(f.id, ALICE, ws))
        assert wi.sent[5:] == [status(1)]
        # a dead socket is forgotten on the next push
        dead = FakeWatcher(fail=True)
        assert run(foc.attach_student(f.id, ALICE, dead))
        run(foc.set_view(f.id, {}))
        assert f.student_sockets == {ws}
        # the end: every socket closed, the student's pages told; idempotent
        run(foc.end(f.id))
        assert ws.closed == (FO.WS_FOCUS_ENDED, "the focus has ended") and wi.closed == ws.closed
        assert wa.sent == [started(f), ended(f)] and foc.listing() == []
        assert run(foc.end(f.id)) is None
        assert not run(foc.attach_instructor(f.id, wi)) and not run(foc.attach_student(f.id, ALICE, ws))
        foc.detach_instructor(f.id, wi)                          # harmless
        run(foc.detach_student(f.id, ws))

    def test_grace_and_shutdown(self):
        clock, presence, foc = registries()
        wa = FakeWatcher()
        presence.add(ALICE, '/', wa)
        f = run(foc.start(PROF, 'a01', RLN))
        run(foc.tick(1000 + FO.INSTRUCTOR_GRACE - 1))
        assert foc.get(f.id) is f
        wi = FakeWatcher()
        run(foc.attach_instructor(f.id, wi))                     # the page is there: no end
        run(foc.tick(1000 + FO.INSTRUCTOR_GRACE + 10))
        assert foc.get(f.id) is f
        clock.now = 2000
        foc.detach_instructor(f.id, wi)
        assert f.instructor_absent_since == 2000
        run(foc.tick(2000 + FO.INSTRUCTOR_GRACE - 1))
        assert foc.get(f.id) is f
        run(foc.tick(2000 + FO.INSTRUCTOR_GRACE))
        assert foc.get(f.id) is None and wa.sent[-1] == ended(f)
        g = run(foc.start(PROF, 'a01', RLN))
        run(foc.shutdown())
        assert foc.listing() == [] and wa.sent[-1] == ended(g)


# ---------------------------------------------------------------------------------------------
# through the portal
# ---------------------------------------------------------------------------------------------

async def focus(h, headers, rln, view=None) -> dict:
    body = {'host': 'a01', 'rln': rln}
    if view is not None:
        body['view'] = view
    resp = await h.client.post('/api/focus', json=body, headers={**headers, **P.CSRF})
    assert resp.status == 201, await resp.text()
    return await resp.json()


async def nothing(ws, timeout=0.3):
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(ws.receive_json(), timeout)


class TestFocusThroughThePortal:
    def test_lifecycle(self, tmp_path):
        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                alice, bob = P.who('alice', 'Alice', group='INFO1'), P.who('bob', 'Bob', group='INFO1')
                prof, prof2 = P.who('prof', 'Pr. Of', groups=P.TEACHERS), P.who('prof2', groups=P.TEACHERS)
                rln = await T.start_project(h, alice)
                own = await T.start_project(h, prof)
                alice_ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=alice)
                bob_ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=bob)
                # the refusals
                assert (await h.client.post('/api/focus', json={'host': 'a01', 'rln': rln},
                                            headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.post('/api/focus', json={'host': 'nope', 'rln': rln},
                                            headers={**prof, **P.CSRF})).status == 404
                assert (await h.client.post('/api/focus', json={'host': 'a01', 'rln': 'x'},
                                            headers={**prof, **P.CSRF})).status == 400
                assert (await h.client.post('/api/focus', json={'host': 'a01', 'rln': own},
                                            headers={**prof, **P.CSRF})).status == 400          # prof's own project
                assert (await h.client.post('/api/focus', json={'host': 'a01', 'rln': rln, 'view': 'x'},
                                            headers={**prof, **P.CSRF})).status == 400
                assert (await h.client.post('/api/focus', json=[1], headers={**prof, **P.CSRF})).status == 400
                # the start: alice's pages told, bob's not
                f = await focus(h, prof, rln, {'tab': 'schema'})
                fid = f['id']
                assert (f['host'], f['rln'], f['student'], f['connected'], f['view']) == ('a01', rln, 'alice', 0, {'tab': 'schema'})
                assert f['instructor'] == {'login': 'prof', 'fullname': 'Pr. Of'}
                told = {'t': 'focus', 'id': fid, 'url': f'/projects/a01/{urllib.parse.quote(rln, safe="")}',
                        'host': 'a01', 'rln': rln, 'instructor': 'Pr. Of'}
                assert await asyncio.wait_for(alice_ws.receive_json(), 5) == told
                await nothing(bob_ws)
                # a page alice opens meanwhile is told at once
                alice_ws2 = await h.client.ws_connect(f'/api/presence/ws?page=/projects/a01/{rln}', headers=alice)
                assert await asyncio.wait_for(alice_ws2.receive_json(), 5) == told
                await nothing(alice_ws)
                # the listing of each side
                mine = await (await h.client.get('/api/focus', headers=prof)).json()
                assert [x['id'] for x in mine['leading']] == [fid] and mine['following'] is None
                hers = await (await h.client.get('/api/focus', headers=alice)).json()
                assert hers['leading'] == [] and hers['following']['id'] == fid
                assert await (await h.client.get('/api/focus', headers=bob)).json() == {'leading': [], 'following': None}
                assert (await h.client.get('/api/focus', allow_redirects=False)).status == 401
                assert (await h.client.get(f'/api/focus/{fid}', headers=alice)).status == 200
                assert (await h.client.get(f'/api/focus/{fid}', headers=prof)).status == 200
                assert (await h.client.get(f'/api/focus/{fid}', headers=prof2)).status == 403
                assert (await h.client.get(f'/api/focus/{fid}', headers=bob)).status == 403
                assert (await h.client.get('/api/focus/nope', headers=prof)).status == 404
                # the sockets: the instructor's status and view, the student's view
                prof_ws = await h.client.ws_connect(f'/api/focus/{fid}/ws', headers=prof)
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == status(0)
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == view_of({'tab': 'schema'})
                with pytest.raises(aiohttp.WSServerHandshakeError):
                    await h.client.ws_connect(f'/api/focus/{fid}/ws', headers=bob)
                alice_fws = await h.client.ws_connect(f'/api/focus/{fid}/ws', headers=alice)
                assert await asyncio.wait_for(alice_fws.receive_json(), 5) == view_of({'tab': 'schema'})
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == status(1)
                # the view from either page reaches both
                view = {'tab': 'terminals', 'terminal': 'abc', 'question': None}
                resp = await h.client.put(f'/api/focus/{fid}/view', json={'view': view}, headers={**alice, **P.CSRF})
                assert resp.status == 204
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == view_of(view)
                assert await asyncio.wait_for(alice_fws.receive_json(), 5) == view_of(view)     # the echo
                view2 = {'tab': 'questions', 'terminal': None, 'question': 'h1'}
                assert (await h.client.put(f'/api/focus/{fid}/view', json=view2, headers={**prof, **P.CSRF})).status == 204
                assert await asyncio.wait_for(alice_fws.receive_json(), 5) == view_of(view2)
                assert await asyncio.wait_for(prof_ws.receive_json(), 5) == view_of(view2)
                assert (await (await h.client.get(f'/api/focus/{fid}', headers=alice)).json())['view'] == view2
                assert (await h.client.put(f'/api/focus/{fid}/view', json={'view': {}}, headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.put(f'/api/focus/{fid}/view', json={'view': {}}, headers=prof)).status == 403  # no CSRF
                assert (await h.client.put(f'/api/focus/{fid}/view', json={'view': [1]}, headers={**prof, **P.CSRF})).status == 400
                assert (await h.client.put(f'/api/focus/{fid}/view', json={'view': {'x': 'a' * 9000}},
                                           headers={**prof, **P.CSRF})).status == 413
                # the end: the instructor (or any instructor), never the student; every socket closed
                assert (await h.client.delete(f'/api/focus/{fid}', headers={**alice, **P.CSRF})).status == 403
                assert (await h.client.delete(f'/api/focus/{fid}', headers={**bob, **P.CSRF})).status == 403
                assert (await h.client.delete(f'/api/focus/{fid}', headers={**prof, **P.CSRF})).status == 200
                assert (await T.receive_close(alice_fws)).data == FO.WS_FOCUS_ENDED
                assert (await T.receive_close(prof_ws)).data == FO.WS_FOCUS_ENDED
                over = {'t': 'focus', 'id': fid, 'ended': True}
                assert await asyncio.wait_for(alice_ws.receive_json(), 5) == over
                assert await asyncio.wait_for(alice_ws2.receive_json(), 5) == over
                gone = await h.client.ws_connect(f'/api/focus/{fid}/ws', headers=alice)
                assert (await T.receive_close(gone)).data == FO.WS_FOCUS_ENDED
                assert (await h.client.delete(f'/api/focus/{fid}', headers={**prof, **P.CSRF})).status == 404
                assert await (await h.client.get('/api/focus', headers=alice)).json() == {'leading': [], 'following': None}
                # another instructor may end it
                fid2 = (await focus(h, prof, rln))['id']
                assert await asyncio.wait_for(alice_ws.receive_json(), 5) == {**told, 'id': fid2}
                assert (await h.client.delete(f'/api/focus/{fid2}', headers={**prof2, **P.CSRF})).status == 200
                assert await asyncio.wait_for(alice_ws.receive_json(), 5) == {'t': 'focus', 'id': fid2, 'ended': True}
                for ws in (alice_ws, alice_ws2, bob_ws):
                    await ws.close()
        P.run(go())

    def test_instructor_grace_through_the_portal(self, tmp_path):
        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                alice, prof = P.who('alice'), P.who('prof', groups=P.TEACHERS)
                rln = await T.start_project(h, alice)
                fid = (await focus(h, prof, rln))['id']
                alice_fws = await h.client.ws_connect(f'/api/focus/{fid}/ws', headers=alice)
                await asyncio.wait_for(alice_fws.receive_json(), 5)
                foc = h.portal.focuses
                now = foc.clock()
                await foc.tick(now + FO.INSTRUCTOR_GRACE - 1)
                assert foc.get(fid) is not None
                await foc.tick(now + FO.INSTRUCTOR_GRACE)
                assert foc.listing() == []
                assert (await T.receive_close(alice_fws)).data == FO.WS_FOCUS_ENDED
        P.run(go())

    def test_access_log_lines(self, tmp_path):
        over = {**P.PROXY_OVER, 'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over) as h:
                alice, prof = P.who('alice'), P.who('prof', groups=P.TEACHERS)
                rln = await T.start_project(h, alice)
                alice_ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=alice)
                fid = (await focus(h, prof, rln, {'tab': 'schema'}))['id']
                await asyncio.wait_for(alice_ws.receive_json(), 5)
                assert (await h.client.get('/api/focus', headers=alice)).status == 200
                alice_fws = await h.client.ws_connect(f'/api/focus/{fid}/ws', headers=alice)
                await asyncio.wait_for(alice_fws.receive_json(), 5)
                await h.client.put(f'/api/focus/{fid}/view', json={'view': {'tab': 'questions'}}, headers={**alice, **P.CSRF})
                await h.client.delete(f'/api/focus/{fid}', headers={**prof, **P.CSRF})
                await alice_ws.close()
                return rln

        rln = P.run(go())
        lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
        by_event = {}
        for line in lines:
            by_event.setdefault(line['event'], []).append(line)
        start = by_event['focus_start'][0]
        assert (start['login'], start['host'], start['rln'], start['student'], start['status']) == ('prof', 'a01', rln, 'alice', '201')
        stop = by_event['focus_stop'][0]
        assert (stop['login'], stop['instructor'], stop['student'], stop['rln']) == ('prof', 'prof', 'alice', rln)
        text = (tmp_path / 'access.log').read_text()
        assert '/view' not in text and '/ws' not in text and 'GET' not in text   # the view, the sockets, the listing: not logged
        alice_session = [l for l in by_event['session_close'] if l['login'] == 'alice'][0]
        assert alice_session['requests'] == '1'                  # the start of the project; the rest keeps alive
