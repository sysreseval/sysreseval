"""A participant of a shared project on the agent (``sreweb.agent``): a student the portal says
the owner of the project shares it with (the ``participant`` flag of the identity, the
``X-SRE-Participant`` header).  They are served as the owner is — ``sre --user`` run as the owner,
the owner's answers file with its metadata kept, the owner's self-evaluation — on the routes
opened to them, and refused on the others: the close, the save, the log, the last archived
evaluation, the exam.  The fake sre of tests/mock_sre.py behind the API."""
import asyncio
import json

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")

from sreweb.agent import access                                    # noqa: E402
from sreweb.agent.access import AccessError                        # noqa: E402
from sreweb.agent.registry import EVENT_SELF_EVALUATION            # noqa: E402
from sreweb.identity import Identity, STATUS_PROJECT_NAMES         # noqa: E402

from test_agent_api import (Harness, headers, ALICE, BOB, PROF, PROF_NOVIEW, TEXT_HASH, TERMINAL_SUBPROTOCOL,   # noqa: E402
                            receive_event, events_of, read_until, end_terminal, run, command_of)
from test_agent_exam import exam_body, start_by_hand               # noqa: E402

PARTNER = BOB.as_participant()                 # bob, on a project its owner shares with him
CAROL = Identity(login='carol', fullname='Carol C', language='en').as_participant()
RLN = '20261126100000@@@sre@dhcp.py@@@alice'

#: Every route about one project, with the decision taken for a participant: a route added to
#: the agent without one fails ``test_every_project_route_has_a_decision``.
OPEN = {
    ('GET', '/v1/projects/{rln}'),
    ('GET', '/v1/projects/{rln}/events'),
    ('GET', '/v1/projects/{rln}/schema.svg'),
    ('GET', '/v1/projects/{rln}/schema.pdf'),
    ('PUT', '/v1/projects/{rln}/answers'),
    ('POST', '/v1/projects/{rln}/eval'),
    ('POST', '/v1/projects/{rln}/states/{state}'),
    ('GET', '/v1/projects/{rln}/terminals/{device}'),
    ('GET', '/v1/projects/{rln}/display'),
    ('POST', '/v1/projects/{rln}/display'),
    ('GET', '/v1/projects/{rln}/display/ws'),
    ('POST', '/v1/projects/{rln}/touch'),
}
CLOSED = {
    ('DELETE', '/v1/projects/{rln}'),
    ('POST', '/v1/projects/{rln}/save'),
    ('GET', '/v1/projects/{rln}/log'),
    ('GET', '/v1/projects/{rln}/evaluation'),
    ('PUT', '/v1/projects/{rln}/exam'),
    ('DELETE', '/v1/projects/{rln}/exam'),
}


async def status_of(h, method: str, path: str, identity, **kwargs) -> int:
    resp = await h.client.request(method, path, headers=headers(identity), **kwargs)
    return resp.status


async def refused_socket(h, path: str, identity, **kwargs) -> int:
    """The status a WebSocket route answers instead of the handshake."""
    with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
        await h.client.ws_connect(path, headers=headers(identity), **kwargs)
    return refused.value.status


async def close_frame(ws, timeout=5.0):
    """The CLOSE frame of a WebSocket the server closes, the frames before it skipped."""
    async with asyncio.timeout(timeout):
        while True:
            msg = await ws.receive()
            if msg.type == aiohttp.WSMsgType.CLOSE:
                return msg
            assert msg.type in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT), msg


class TestRules:
    def test_check_owner(self):
        access.check_owner(RLN, ALICE)
        access.check_owner(RLN, PROF)
        for identity in (BOB, PARTNER):
            with pytest.raises(AccessError) as refused:
                access.check_owner(RLN, identity)                  # the routes that stay the owner's
            assert refused.value.status == 403
        access.check_owner(RLN, PARTNER, participants=True)
        with pytest.raises(AccessError):
            access.check_owner(RLN, BOB, participants=True)        # the portal did not say so

    def test_is_participant(self):
        assert access.is_participant(RLN, PARTNER)
        assert not access.is_participant(RLN, BOB)
        # the owner is the owner whatever the header says
        assert not access.is_participant(RLN, ALICE.as_participant())
        assert not access.is_privileged_caller(RLN, PARTNER)       # the student path, never the privileged one

    def test_check_shareable(self):
        access.check_shareable({}, managed=True, exam=False)
        for info, managed, exam in (({}, True, True), ({}, False, False), ({'debug_project': True}, True, False),
                                    ({'instructor_mode': True}, True, False)):
            with pytest.raises(AccessError) as refused:
                access.check_shareable(info, managed=managed, exam=exam)
            assert refused.value.status == 403


class TestRoutes:
    def test_every_project_route_has_a_decision(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                routes = {(route.method, route.resource.canonical) for route in h.agent.make_app().router.routes()
                          if route.resource is not None and route.method != 'HEAD'
                          and route.resource.canonical.startswith('/v1/projects/{rln}')}
                assert not OPEN & CLOSED
                assert routes == OPEN | CLOSED, sorted(routes ^ (OPEN | CLOSED))
        run(go())

    def test_a_participant_is_served_as_the_owner(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                base = f'/v1/projects/{rln}'
                page = await (await h.client.get(base, headers=headers(PARTNER))).json()
                assert page['participant'] is True and page['owner'] == 'alice' and page['fullname'] == 'Alice A'
                assert page['project']['can_save'] is False
                # the tabs of the owner: the student path (the Evaluation tab by allow_self_grade, no log)
                own = await (await h.client.get(base, headers=headers())).json()
                assert own['participant'] is False and page['project']['tabs'] == own['project']['tabs']
                assert (await (await h.client.get(base, headers=headers(PROF))).json())['participant'] is False
                assert await status_of(h, 'POST', base + '/touch', PARTNER) == 204
                assert await status_of(h, 'GET', base + '/schema.svg', PARTNER) == 200
                assert await status_of(h, 'GET', base + '/display', PARTNER) == 200
                # the answers: the owner's file, the owner's name and group kept
                resp = await h.client.put(base + '/answers', json={'answers': {TEXT_HASH: 'from bob'}},
                                          headers=headers(PARTNER))
                assert resp.status == 200 and (await resp.json())['answers'] == {TEXT_HASH: 'from bob'}
                on_disk = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert (on_disk['login'], on_disk['fullname'], on_disk['group'], on_disk[TEXT_HASH]) == \
                    ('alice', 'Alice A', 'INFO1', 'from bob')
                # the self-evaluation and a state: sre --user, as the owner
                assert await status_of(h, 'POST', base + '/eval', PARTNER) == 200
                entry = h.entries()[-1]
                assert entry['argv'] == ['--user', 'eval', '--auto-eval', '--', rln]
                assert (entry['user_mode'], entry['username'], entry['env']['SUDO_USER']) == (True, 'alice', 'alice')
                assert await status_of(h, 'POST', base + '/states/final', PARTNER) == 200
                entry = h.entries()[-1]
                assert entry['argv'] == ['--user', 'state', '--', rln, 'final']
                assert (entry['user_mode'], entry['username']) == (True, 'alice')
                # the states and the machines of a student, not those a privileged call opens
                assert await status_of(h, 'POST', base + '/states/initial', PARTNER) == 403
                rows = await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json()
                assert rows[0]['auto_eval_count'] == 1 and rows[0]['fullname'] == 'Alice A'
                # nothing of theirs in the list of their own projects
                assert await (await h.client.get('/v1/projects', headers=headers(PARTNER))).json() == []
        run(go())

    def test_what_stays_the_owners(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                base = f'/v1/projects/{rln}'
                for method, suffix, body in (('POST', '/save', {'comment': 'mine now'}), ('GET', '/log', None),
                                             ('GET', '/evaluation', None), ('PUT', '/exam', exam_body()),
                                             ('DELETE', '/exam', None), ('DELETE', '', None)):
                    kwargs = {'json': body} if body is not None else {}
                    assert await status_of(h, method, base + suffix, PARTNER, **kwargs) == 403, (method, suffix)
                assert {command_of(c) for c in h.calls()} == {'list', 'start'}
                assert h.agent.registry.get(rln) is not None
                # the owner still closes it
                assert await status_of(h, 'DELETE', base, ALICE) == 200
        run(go())

    def test_a_student_the_portal_does_not_name_is_refused(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                base = f'/v1/projects/{rln}'
                for method, canonical in sorted(OPEN | CLOSED):
                    path = canonical.replace('/v1/projects/{rln}', base).replace('{state}', 'final').replace('{device}', 'm1')
                    if path.endswith(('/events', '/display/ws')) or '/terminals/' in path:
                        assert await refused_socket(h, path, BOB) == 403, path
                    else:
                        assert await status_of(h, method, path, BOB, json={}) == 403, (method, path)
                # nothing but the start of the project (its lab list, the start) was run
                assert {command_of(c) for c in h.calls()} == {'list', 'start'}
        run(go())

    def test_last_action_and_status(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                assert (await (await h.client.get('/v1/status', headers=headers())).json())[STATUS_PROJECT_NAMES] == []
                rln = await h.started()
                other = await h.started(BOB, lab='s4/tp_ssh')
                status = await (await h.client.get('/v1/status', headers=headers())).json()
                assert status[STATUS_PROJECT_NAMES] == sorted([rln, other])
                project = h.agent.registry.get(rln)
                assert project.last_action_at is None
                # what a participant does is an action of the students of the project
                await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'x'}}, headers=headers(PARTNER))
                assert project.last_action_at is not None
                # ... what bob does there without being named is nothing at all
                assert h.agent.registry.get(other).last_action_at is None
        run(go())


class TestTerminals:
    def test_shared_with_the_owner(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                base = f'/v1/projects/{rln}/terminals'
                alice = await h.client.ws_connect(f'{base}/m1', headers=headers(), protocols=(TERMINAL_SUBPROTOCOL,))
                sid = (await asyncio.wait_for(alice.receive_json(), 5))['session']
                await read_until(alice, b'mock$')
                # the participant sees the owner's session and joins it: one shell for both
                page = await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PARTNER))).json()
                assert [(t['id'], t['created_by']) for t in page['terminals']] == [(sid, 'alice')]
                bob = await h.client.ws_connect(f'{base}/m1?join={sid}', headers=headers(PARTNER),
                                                protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(bob.receive_json(), 5)
                assert (ready['t'], ready['session'], ready['clients'], ready['joined'], ready['readonly']) == \
                    ('ready', sid, 2, True, False)
                await read_until(bob, b'mock$')
                await bob.send_bytes(b'echo FROM-BOB\n')
                await read_until(alice, b'FROM-BOB', after=b'echo FROM-BOB')
                # ... and opens one of their own, under their own name, as the owner (sre --user)
                own = await h.client.ws_connect(f'{base}/m1', headers=headers(PARTNER), protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(own.receive_json(), 5)
                assert ready['t'] == 'ready' and ready['private'] is False and not ready['joined']
                mine = ready['session']
                await read_until(own, b'mock$')
                listed = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['terminals']
                assert {(t['id'], t['created_by']) for t in listed} == {(sid, 'alice'), (mine, 'bob')}
                connects = [e for e in h.entries() if 'connect' in e['argv']]
                assert [e['argv'] for e in connects] == [['--user', 'connect', '--', rln, 'm1']] * 2
                assert {e['username'] for e in connects} == {'alice'}
                # the x of the participant on the owner's terminal leaves the shell alone, even
                # when nobody else types in it: the session lingers for its owner
                await alice.close()
                await end_terminal(bob)
                await asyncio.sleep(0.3)
                session = h.agent.registry.get(rln).terminals[sid]
                assert session.lingering and not session.closing
                # ... and ends the terminal they opened
                await end_terminal(own)
                async with asyncio.timeout(5):
                    while mine in h.agent.registry.get(rln).terminals:
                        await asyncio.sleep(0.02)
        run(go())

    def test_the_rules_of_a_student(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                base = f'/v1/projects/{rln}/terminals'
                # no private terminal, no closed machine (a privileged call would open both)
                for path in (f'{base}/m1?private=1', f'{base}/m2'):
                    ws = await h.client.ws_connect(path, headers=headers(PARTNER), protocols=(TERMINAL_SUBPROTOCOL,))
                    assert (await asyncio.wait_for(ws.receive_json(), 5))['t'] == 'error', path
                    closing = await ws.receive()
                    assert closing.type == aiohttp.WSMsgType.CLOSE and ws.close_code == 4403, path
                # the private terminal of an instructor is neither listed nor joined
                prof = await h.client.ws_connect(f'{base}/m1?private=1', headers=headers(PROF),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                pid = (await asyncio.wait_for(prof.receive_json(), 5))['session']
                assert (await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PARTNER))).json())['terminals'] == []
                ws = await h.client.ws_connect(f'{base}/m1?join={pid}', headers=headers(PARTNER),
                                               protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(ws.receive_json(), 5))['t'] == 'error'
                await ws.receive()
                assert ws.close_code == 4403
                await end_terminal(prof)
        run(go())


class TestEvaluationShownToTheOthers:
    def test_pushed_to_the_owner_and_the_participants(self, tmp_path):
        async def go():
            async with Harness(tmp_path, {'MOCK_COOLDOWN': '30'}) as h:
                rln = await h.started()
                base = f'/v1/projects/{rln}'
                alice = await h.client.ws_connect(base + '/events', headers=headers())
                bob = await h.client.ws_connect(base + '/events', headers=headers(PARTNER))
                carol = await h.client.ws_connect(base + '/events', headers=headers(CAROL))
                prof = await h.client.ws_connect(base + '/events', headers=headers(PROF))
                answer = await (await h.client.post(base + '/eval', headers=headers(PARTNER))).json()
                assert answer['result']['grades'] is not None and answer['rows']
                for ws, language in ((alice, 'fr'), (carol, 'en')):
                    event = await receive_event(ws, EVENT_SELF_EVALUATION)
                    assert event['by'] == {'login': 'bob', 'fullname': ''}
                    assert event['result'] == answer['result'] and len(event['rows']) == len(answer['rows'])
                    assert event['delay_before_self_grade'] == answer['delay_before_self_grade']
                # not to the one who ran it (the answer of their request), nor to an instructor
                # helping (their page reads the archive)
                for ws in (bob, prof):
                    seen = [e['t'] for e in await events_of(ws, 0.5)]
                    assert EVENT_SELF_EVALUATION not in seen and 'evaluated' in seen
                # the owner's own evaluation reaches the participants the same way; here the
                # cooldown refuses it: they are told the wait all the same
                refused = await (await h.client.post(base + '/eval', headers=headers())).json()
                assert refused['result']['grades'] is None and refused['delay_before_self_grade'] > 0
                event = await receive_event(bob, EVENT_SELF_EVALUATION)
                assert event['by']['login'] == 'alice' and event['rows'] == []
                assert event['delay_before_self_grade'] == refused['delay_before_self_grade']
                # an instructor's evaluation of the project is not a self-evaluation
                assert (await h.client.post(base + '/eval', headers=headers(PROF))).status == 200
                assert EVENT_SELF_EVALUATION not in [e['t'] for e in await events_of(alice, 0.5)]
                for ws in (alice, bob, carol, prof):
                    await ws.close()
        run(go())


class TestNeverShared:
    def test_exam_project(self, tmp_path):
        """A project given an exam is closed to the participants at once, their terminals cut."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                base = f'/v1/projects/{rln}'
                term = await h.client.ws_connect(base + '/terminals/m1', headers=headers(PARTNER),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(term.receive_json(), 5))['t'] == 'ready'
                await read_until(term, b'mock$')
                owner = await h.client.ws_connect(base + '/terminals/m1', headers=headers(),
                                                  protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(owner.receive_json(), 5))['t'] == 'ready'
                assert (await h.client.put(base + '/exam', json=exam_body(), headers=headers(PROF))).status == 200
                # closed from another task than the handler of the socket: the code is the one of
                # the CLOSE frame (what a browser gets), the client's close_code may say 1006
                assert (await close_frame(term)).data == 4403
                assert not owner.closed                                  # the owner's own terminal stays
                assert await status_of(h, 'GET', base, PARTNER) == 403
                assert await status_of(h, 'PUT', base + '/answers', PARTNER, json={'answers': {TEXT_HASH: 'x'}}) == 403
                assert await refused_socket(h, base + '/events', PARTNER) == 403
                assert await status_of(h, 'GET', base, ALICE) == 200
                await owner.close()
        run(go())

    def test_local_debug_and_instructor_mode_projects(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                local = start_by_hand(h)                                 # the Qt GUI of alice
                await h.agent.registry.tick()
                assert h.agent.registry.get(local) is not None and not h.agent.registry.get(local).managed
                debug = await h.started(PROF_NOVIEW, debug_project=True)
                teaching = await h.started(PROF_NOVIEW, lab='s4/tp_ssh', instructor_mode=True)
                for rln in (local, debug, teaching):
                    assert await status_of(h, 'GET', f'/v1/projects/{rln}', PARTNER) == 403, rln
                    assert await refused_socket(h, f'/v1/projects/{rln}/terminals/m1', PARTNER,
                                                protocols=(TERMINAL_SUBPROTOCOL,)) == 403, rln
        run(go())

    def test_a_standard_project_of_an_instructor_is_shared_like_any(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started(PROF_NOVIEW)
                page = await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PARTNER))).json()
                assert page['participant'] is True and page['owner'] == 'prof'
        run(go())
