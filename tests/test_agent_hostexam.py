"""Tests of the exam of the host the agent writes for an exam of the web site
(``sreweb.agent.hostexam``: ``exam.json`` in place of ``sre set-exam`` / ``sre del-exam``): the
definition parsed, the document merged into the file of the GUI's commands, the write checked
against a command rewriting the file meanwhile, the view of the status, and the API
(``PUT`` / ``DELETE /v1/exam``: the refusals, the close stopping the local projects of the exam
alone) on the fake sre of tests/mock_sre.py."""
import asyncio
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")

from SRE import params
from sreweb.agent import app as agent_app
from sreweb.agent import hostexam as H
from sreweb.agent.access import AccessError

import test_agent_api as A
from test_agent_api import Harness, headers, ALICE, BOB, PROF, run
from test_agent_exam import EXAM_LAB, exam_body, start_by_hand

EXAM_ID = '12'
ORIGIN = 'portal-a'
PLAIN_LAB = 'sre/dhcp.py'


#: The whole second a test started at (``pinned`` below): every instant of a test is counted
#: from it, so that two of them never straddle a tick of the clock.
_base = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture(autouse=True)
def pinned():
    global _base
    _base = datetime.now(timezone.utc).replace(microsecond=0)


def at(seconds: float) -> datetime:
    """An aware UTC instant *seconds* from the start of the test, whole seconds."""
    return _base + timedelta(seconds=seconds)


def iso(seconds: float) -> str:
    return at(seconds).isoformat(timespec='seconds')


def local(seconds_or_dt) -> str:
    """The same instant as the file holds it: naive, in the time of the host."""
    dt = seconds_or_dt if isinstance(seconds_or_dt, datetime) else at(seconds_or_dt)
    return datetime.fromtimestamp(dt.timestamp()).isoformat(timespec='seconds')


def body(start: float | None = 600, end: float | None = 7200, **over) -> dict:
    data = {'id': EXAM_ID, 'title': 'Partiel', 'rev': 'r1', 'origin': ORIGIN,
            'labs': [{'lab': EXAM_LAB, 'flavor': 'hard'}, {'lab': PLAIN_LAB}],
            'start_after': iso(start) if start is not None else None,
            'end_before': iso(end) if end is not None else None,
            'duration': 90, 'eval_interval': 60, 'now': iso(0)}
    data.update(over)
    return data


def spec(**over) -> dict:
    return H.parse_host_exam(body(**over))[0]


def exam_file(pub):
    return pub / params.exam_json_name


def stored(pub) -> dict:
    return json.loads(exam_file(pub).read_text())


class TestParse:
    def test_a_definition(self):
        parsed, skew = H.parse_host_exam(body())
        assert parsed['id'] == EXAM_ID and parsed['title'] == 'Partiel' and parsed['rev'] == 'r1'
        assert parsed['origin'] == ORIGIN and parsed['labs'] == [[EXAM_LAB, 'hard'], [PLAIN_LAB, None]]
        assert parsed['duration'] == 90 and parsed['eval_interval'] == 60 and parsed['record_sessions'] is True
        assert parsed['end_before'] - parsed['start_after'] == 6600
        assert abs(skew) < 5
        parsed, skew = H.parse_host_exam(body(start=None, now=None, record_sessions=False, labs=[PLAIN_LAB]))
        assert parsed['start_after'] is None and skew is None and parsed['record_sessions'] is False
        assert parsed['labs'] == [[PLAIN_LAB, None]]

    @pytest.mark.parametrize('over, message', [
        ({'id': '../x'}, 'bad id'), ({'id': 12}, 'bad id'),
        ({'title': 'x' * 201}, 'bad title'), ({'title': 'a\nb'}, 'bad title'),
        ({'rev': ''}, 'bad rev'), ({'origin': None}, 'bad origin'),
        ({'labs': []}, 'labs are required'), ({'labs': 'sre/dhcp.py'}, 'labs are required'),
        ({'labs': [PLAIN_LAB, {'lab': PLAIN_LAB}]}, 'listed twice'),
        ({'labs': ['/etc/passwd']}, 'bad lab name'), ({'labs': ['sre/../x.py']}, 'bad lab name'),
        ({'labs': ['sre@dhcp.py']}, 'bad lab name'), ({'labs': [{'lab': PLAIN_LAB, 'flavor': 'a b'}]}, 'flavor'),
        ({'start_after': '2026-11-16T09:00:00'}, 'timezone'), ({'end_before': 'tomorrow'}, 'ISO 8601'),
        ({'duration': 0}, 'duration'), ({'duration': True}, 'duration'), ({'duration': None}, 'duration'),
        ({'eval_interval': 0}, 'eval_interval'), ({'eval_interval': 1.5}, 'eval_interval'),
        ({'record_sessions': 'yes'}, 'record_sessions'),
    ])
    def test_refusals(self, over, message):
        with pytest.raises(AccessError) as e:
            H.parse_host_exam(body(**over))
        assert e.value.status == 400 and message in e.value.message

    def test_not_an_object(self):
        with pytest.raises(AccessError) as e:
            H.parse_host_exam([])
        assert e.value.status == 400


class TestDocument:
    def test_a_new_file_is_the_one_of_set_exam(self):
        doc = H.document(spec())
        assert doc == {params.exam_labs: [[EXAM_LAB, 'hard'], [PLAIN_LAB, None]],
                       params.exam_start_after: local(600), params.exam_end_before: local(7200),
                       params.exam_duration: 90, params.exam_eval_interval: 60, params.exam_record_sessions: True,
                       params.exam_web: {params.exam_web_id: EXAM_ID, params.exam_web_title: 'Partiel',
                                         params.exam_web_rev: 'r1', params.exam_web_origin: ORIGIN}}
        # naive times, as set-exam writes them: every reader of the file takes them for local
        assert datetime.fromisoformat(doc[params.exam_start_after]).tzinfo is None
        assert json.loads(json.dumps(doc)) == doc

    def test_the_progress_of_the_gui_is_kept(self):
        current = H.document(spec())
        current.update({params.exam_pre_start_date: [local(-30)], params.exam_started_at: local(-20), 'other': 1})
        doc = H.document(spec(start=-60, rev='r2', duration=95), current)
        assert doc[params.exam_pre_start_date] == [local(-30)] and doc[params.exam_started_at] == local(-20)
        assert doc['other'] == 1 and doc[params.exam_duration] == 95
        assert doc[params.exam_web][params.exam_web_rev] == 'r2' and doc[params.exam_start_after] == local(-60)

    def test_no_start_time_drops_the_key(self):
        doc = H.document(spec(start=None), H.document(spec()))
        assert params.exam_start_after not in doc and params.exam_end_before in doc

    def test_the_recorded_end_is_dropped_by_a_resume_only(self):
        ended = H.document(spec(start=-3600, end=-10))
        ended.update({params.exam_started_at: local(-3500), params.exam_ended_at: local(-9)})
        # still over: what sre end-exam recorded stays
        assert H.document(spec(start=-3600, end=-5, rev='r2'), ended)[params.exam_ended_at] == local(-9)
        # the end moved into the future: the exam goes on
        assert params.exam_ended_at not in H.document(spec(start=-3600, end=600, rev='r3'), ended)
        # ... but not when the duration of the machine is still spent
        spent = dict(ended, **{params.exam_started_at: local(-7200)})
        assert params.exam_ended_at in H.document(spec(start=-7300, end=600, rev='r4'), spent)

    def test_the_end_as_the_gui_computes_it(self):
        doc = H.document(spec(start=-600, end=3600))
        assert H.end_of(doc) == at(3600).timestamp() and not H.over(doc) and not H.running(doc)
        doc[params.exam_started_at] = local(-300)        # 90 min from the start: after end_before
        assert H.end_of(doc) == at(3600).timestamp() and H.running(doc) and H.needs_final_evaluation(doc)
        doc[params.exam_duration] = 4
        assert H.over(doc) and not H.running(doc)
        doc[params.exam_ended_at] = local(-60)
        assert not H.needs_final_evaluation(doc)
        assert H.end_of({}) is None and not H.over({}) and not H.needs_final_evaluation({})
        assert H.epoch_of('2026-11-16T09:00:00+00:00') == datetime(2026, 11, 16, 9, tzinfo=timezone.utc).timestamp()
        assert H.epoch_of('nope') is None and H.epoch_of(None) is None

    def test_lab_names_are_those_of_the_projects(self):
        assert H.lab_names(H.document(spec())) == {'sre@_EXAM_@exam1.py', 'sre@dhcp.py'}
        assert H.lab_names({params.exam_labs: ['s4/tp_ssh']}) == {'s4@tp_ssh'}      # the legacy form
        assert H.lab_names({}) == set()


class TestFile:
    def test_read_tells_whose_file_it_is(self, tmp_path):
        assert H.read(str(tmp_path)) == (H.ABSENT, None)
        exam_file(tmp_path).write_text('{}')
        assert H.read(str(tmp_path)) == (H.FOREIGN, {})
        exam_file(tmp_path).write_text(json.dumps({params.exam_labs: [['a', None]], params.exam_duration: 5}))
        assert H.read(str(tmp_path))[0] == H.FOREIGN
        exam_file(tmp_path).write_text(json.dumps(H.document(spec())))
        state, data = H.read(str(tmp_path))
        assert state == H.WEB and H.marker_of(data)[params.exam_web_id] == EXAM_ID
        for broken in ('', '{"labs": [', '[]', '"x"'):
            exam_file(tmp_path).write_text(broken)
            assert H.read(str(tmp_path)) == (H.UNREADABLE, None)

    def test_check_ours(self):
        doc = H.document(spec())
        H.check_ours(H.ABSENT, None, EXAM_ID, ORIGIN)
        H.check_ours(H.WEB, doc, EXAM_ID, ORIGIN)
        H.check_ours(H.WEB, doc, EXAM_ID)                    # a removal may leave the origin out
        for state, data, exam_id, origin, status, text in (
                (H.UNREADABLE, None, EXAM_ID, ORIGIN, 503, 'cannot be read'),
                (H.FOREIGN, {}, EXAM_ID, ORIGIN, 409, 'sre set-exam'),
                (H.WEB, doc, '13', ORIGIN, 409, 'the exam 12 «Partiel» is on this host'),
                (H.WEB, doc, EXAM_ID, 'portal-b', 409, 'another web site')):
            with pytest.raises(AccessError) as e:
                H.check_ours(state, data, exam_id, origin)
            assert e.value.status == status and text in e.value.message

    def test_write_creates_a_readable_file(self, tmp_path):
        doc = H.write(str(tmp_path), spec())
        assert stored(tmp_path) == doc == H.document(spec())
        assert stat.S_IMODE(exam_file(tmp_path).stat().st_mode) == 0o644      # the GUI of the student reads it
        assert [p.name for p in tmp_path.iterdir()] == [params.exam_json_name]   # no temporary file left

    def test_write_keeps_what_a_command_wrote_meanwhile(self, tmp_path):
        """``sre start-exam`` stamps ``started_at`` into the file (in place) between the read
        and the replace: the stamp is found in the file just replaced and merged."""
        H.write(str(tmp_path), spec())
        calls = []

        def cli_writes():
            calls.append(1)
            if len(calls) == 1:
                data = stored(tmp_path)
                data[params.exam_started_at] = local(-1)
                exam_file(tmp_path).write_text(json.dumps(data, indent=4))     # in place, like the CLI

        doc = H.write(str(tmp_path), spec(rev='r2', duration=100), before_replace=cli_writes)
        assert len(calls) == 2
        assert doc[params.exam_started_at] == local(-1) and doc[params.exam_duration] == 100
        assert stored(tmp_path) == doc and doc[params.exam_web][params.exam_web_rev] == 'r2'

    def test_write_gives_up_on_a_file_that_keeps_changing(self, tmp_path):
        """A writer holding the file that was read (the inode the replace unlinks) and changing
        it at every attempt: bounded, 503."""
        H.write(str(tmp_path), spec())
        count = [0]
        with open(exam_file(tmp_path), 'r+') as held:
            def cli_writes():
                count[0] += 1
                held.seek(0)
                data = json.loads(held.read())
                data['tick'] = count[0]
                held.seek(0)
                held.truncate()
                held.write(json.dumps(data))
                held.flush()

            with pytest.raises(AccessError) as e:
                H.write(str(tmp_path), spec(rev='r2'), before_replace=cli_writes)
        assert e.value.status == 503 and count[0] == H.WRITE_ATTEMPTS

    def test_write_never_replaces_a_file_it_cannot_read_or_does_not_own(self, tmp_path, monkeypatch):
        monkeypatch.setattr(H, 'REREAD_DELAY', 0)
        exam_file(tmp_path).write_text('{"labs": [')          # a command in the middle of its write
        with pytest.raises(AccessError) as e:
            H.write(str(tmp_path), spec())
        assert e.value.status == 503 and exam_file(tmp_path).read_text() == '{"labs": ['
        exam_file(tmp_path).write_text('{"duration": 5}')     # set by hand
        with pytest.raises(AccessError) as e:
            H.write(str(tmp_path), spec())
        assert e.value.status == 409 and stored(tmp_path) == {'duration': 5}
        H.remove(str(tmp_path))
        H.write(str(tmp_path), spec())
        with pytest.raises(AccessError) as e:
            H.write(str(tmp_path), spec(id='13'))
        assert e.value.status == 409 and stored(tmp_path)[params.exam_web][params.exam_web_id] == EXAM_ID

    def test_remove(self, tmp_path):
        assert H.remove(str(tmp_path)) is False
        H.write(str(tmp_path), spec())
        assert H.remove(str(tmp_path)) is True and not exam_file(tmp_path).exists()

    def test_view(self):
        assert H.view(None) is None
        doc = H.document(spec())
        assert H.view(doc) == {'id': EXAM_ID, 'title': 'Partiel', 'rev': 'r1', 'origin': ORIGIN,
                               'labs': [[EXAM_LAB, 'hard'], [PLAIN_LAB, None]],
                               'start_after': iso(600), 'end_before': iso(7200), 'duration': 90, 'eval_interval': 60,
                               'pre_started': False, 'started_at': None, 'ended_at': None}
        doc.update({params.exam_pre_start_date: [local(-30)], params.exam_started_at: local(-20) + '.123456'})
        view = H.view(doc)
        assert view['pre_started'] is True and view['started_at'] == iso(-20)
        # a file set by hand: no id, whatever it holds is described without failing
        assert H.view({}) == {'id': None, 'title': '', 'rev': None, 'origin': None, 'labs': [], 'start_after': None,
                              'end_before': None, 'duration': None, 'eval_interval': None, 'pre_started': False,
                              'started_at': None, 'ended_at': None}
        view = H.view({params.exam_labs: ['s4/tp_ssh', ['a', 'b']], params.exam_duration: 'x',
                       params.exam_start_after: 'never', params.exam_web: 'x'})
        assert view['labs'] == [['s4/tp_ssh', None], ['a', 'b']] and view['duration'] is None and view['id'] is None


# -- the API -----------------------------------------------------------------------------------

async def put(h, data=None, identity=PROF):
    return await h.client.put('/v1/exam', json=data if data is not None else body(), headers=headers(identity))


async def delete(h, exam_id=EXAM_ID, identity=PROF, **query):
    return await h.client.delete('/v1/exam', params={'id': exam_id, **query}, headers=headers(identity))


async def status(h) -> dict:
    return await (await h.client.get('/v1/status', headers=headers(identity=None))).json()


class TestApi:
    def test_put_writes_the_file_and_the_status_tells(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                assert (await status(h))['exam'] is None
                resp = await put(h, identity=ALICE)
                assert resp.status == 403 and not exam_file(h.pub).exists()
                assert (await h.client.put('/v1/exam', json=body(), headers=headers(identity=None))).status == 400
                resp = await put(h)
                answer = await resp.json()
                assert resp.status == 200 and answer['ok'] is True and answer['exam']['id'] == EXAM_ID
                assert stored(h.pub) == H.document(spec())
                assert stat.S_IMODE(exam_file(h.pub).stat().st_mode) == 0o644
                st = await status(h)
                assert st['exam_mode'] is True and st['exam'] == answer['exam']
                assert st['exam']['rev'] == 'r1' and st['exam']['start_after'] == body()['start_after']
                # the same revision: nothing written (the file is not replaced)
                inode = exam_file(h.pub).stat().st_ino
                assert (await put(h)).status == 200 and exam_file(h.pub).stat().st_ino == inode
                # the GUI started the exam, then the portal moves the end: the clock is kept
                data = stored(h.pub)
                data[params.exam_started_at] = local(-5)
                exam_file(h.pub).write_text(json.dumps(data, indent=4))
                resp = await put(h, body(rev='r2', end=9000))
                assert resp.status == 200 and (await resp.json())['exam']['started_at'] == iso(-5)
                assert stored(h.pub)[params.exam_started_at] == local(-5)
                assert stored(h.pub)[params.exam_end_before] == local(9000)
                assert (await status(h))['exam']['rev'] == 'r2'
        run(go())

    def test_put_refusals(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await put(h, body(labs=['nope.py']))
                assert resp.status == 404 and 'unknown lab nope.py' in (await resp.json())['error']
                resp = await put(h, body(labs=['sre']))                  # a directory of the tree is no lab
                assert resp.status == 404
                assert (await put(h, body(duration=0))).status == 400
                assert not exam_file(h.pub).exists()
                # a file set by hand, another exam, another portal: never touched
                exam_file(h.pub).write_text('{"duration": 5}')
                resp = await put(h)
                assert resp.status == 409 and 'sre set-exam' in (await resp.json())['error']
                assert stored(h.pub) == {'duration': 5}
                assert (await status(h))['exam']['id'] is None
                H.remove(str(h.pub))
                assert (await put(h)).status == 200
                resp = await put(h, body(id='13'))
                assert resp.status == 409 and 'the exam 12' in (await resp.json())['error']
                resp = await put(h, body(origin='portal-b', rev='r9'))
                assert resp.status == 409 and stored(h.pub)[params.exam_web][params.exam_web_rev] == 'r1'
                # a command of the CLI in the middle of its write: tried again later, the status
                # goes on telling what it read last
                good = exam_file(h.pub).read_text()
                exam_file(h.pub).write_text(good[:40])
                assert (await put(h, body(rev='r2'))).status == 503
                assert (await status(h))['exam']['rev'] == 'r1'
                exam_file(h.pub).write_text(good)
                h.agent.restarting = 1.0
                resp = await put(h, body(rev='r2'))
                assert resp.status == 503 and 'restarting' in (await resp.json())['error']
        run(go())

    def test_no_host_exam_under_the_exam_projects_of_the_web_site(self, tmp_path):
        """A machine running exam projects of the web site is not put in exam mode (their
        evaluations and terminals would stop); a plain project does not hold it."""
        async def go():
            async with Harness(tmp_path) as h:
                await h.started(BOB)
                rln = await h.started(ALICE, lab=EXAM_LAB, exam=exam_body())
                resp = await put(h)
                assert resp.status == 409 and '1 exam project(s)' in (await resp.json())['error']
                assert not exam_file(h.pub).exists()
                assert (await h.client.delete(f'/v1/projects/{rln}/exam', headers=headers(PROF))).status == 200
                assert (await put(h)).status == 200
        run(go())

    def test_delete_removes_the_file_and_leaves_the_projects(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await delete(h)
                assert resp.status == 200 and await resp.json() == {'ok': True, 'exam': None, 'closed': 0, 'failed': 0}
                local_rln = start_by_hand(h, lab=EXAM_LAB, login='bob')
                assert (await put(h)).status == 200
                assert (await delete(h, identity=ALICE)).status == 403
                resp = await delete(h, exam_id='13')
                assert resp.status == 409 and exam_file(h.pub).exists()
                resp = await delete(h, origin='portal-b')
                assert resp.status == 409 and exam_file(h.pub).exists()
                resp = await delete(h, origin=ORIGIN)
                assert resp.status == 200 and (await resp.json())['closed'] == 0
                assert not exam_file(h.pub).exists() and (h.pub / 'projects' / local_rln).is_dir()
                st = await status(h)
                assert st['exam'] is None and st['exam_mode'] is False
                assert not any(call[0] in ('stop', 'end-exam') for call in h.calls())
                # a file set by hand is not the portal's to remove
                exam_file(h.pub).write_text('{}')
                assert (await delete(h)).status == 409 and exam_file(h.pub).exists()
        run(go())

    def test_close_ends_and_stops_the_local_projects_of_the_exam_alone(self, tmp_path):
        """``close=1``: the final evaluation (the exam started, its end not recorded), then the
        projects of the exam's labs the agent does not manage, with privileged calls; the web
        project of another user and a local project of another lab are left alone."""
        async def go():
            async with Harness(tmp_path) as h:
                web = await h.started(ALICE, lab=PLAIN_LAB)
                exam_rln = start_by_hand(h, lab=EXAM_LAB, login='bob')
                other = start_by_hand(h, lab='s4/tp_ssh', login='carol')
                assert (await put(h, body(start=-600, labs=[EXAM_LAB]))).status == 200
                data = stored(h.pub)
                data[params.exam_started_at] = local(-500)
                exam_file(h.pub).write_text(json.dumps(data, indent=4))
                before = len(h.entries())
                resp = await delete(h, close='1')
                assert resp.status == 200 and await resp.json() == {'ok': True, 'exam': None, 'closed': 1, 'failed': 0}
                made = h.entries()[before:]
                A.privileged_call(made[0], ['end-exam'], 'prof')
                A.privileged_call(made[1], ['stop', '--', exam_rln], 'prof')
                assert len(made) == 2
                assert not exam_file(h.pub).exists() and not (h.pub / 'projects' / exam_rln).exists()
                assert (h.pub / 'projects' / web).is_dir() and (h.pub / 'projects' / other).is_dir()
                assert (await status(h))['exam'] is None
        run(go())

    def test_close_runs_no_second_final_evaluation(self, tmp_path):
        """The GUI ended the exam (``ended_at``): the close only stops; a machine that never
        started has nothing to evaluate either."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = start_by_hand(h, lab=EXAM_LAB, login='bob')
                assert (await put(h, body(start=-600, end=-10, labs=[EXAM_LAB]))).status == 200
                data = stored(h.pub)
                data.update({params.exam_started_at: local(-500), params.exam_ended_at: local(-9)})
                exam_file(h.pub).write_text(json.dumps(data, indent=4))
                assert (await delete(h, close='1')).status == 200
                assert [c for c in h.calls() if c[0] in ('end-exam', 'stop')] == [['stop', '--', rln]]
            async with Harness(tmp_path / 'b') as h:
                assert (await put(h)).status == 200                        # never started, no project
                resp = await delete(h, close='1')
                assert resp.status == 200 and (await resp.json())['closed'] == 0
                assert not any(c[0] in ('end-exam', 'stop') for c in h.calls())
        run(go())

    def test_a_failed_stop_keeps_the_file(self, tmp_path):
        """The file goes last: the portal still sees the exam on the machine and asks again."""
        async def go():
            async with Harness(tmp_path, {'MOCK_FAIL': 'stop'}) as h:
                rln = start_by_hand(h, lab=EXAM_LAB, login='bob')
                assert (await put(h, body(labs=[EXAM_LAB]))).status == 200
                resp = await delete(h, close='1')
                assert resp.status == 502 and '1 project(s)' in (await resp.json())['error']
                assert exam_file(h.pub).exists() and (h.pub / 'projects' / rln).is_dir()
                assert (await status(h))['exam']['id'] == EXAM_ID
                assert h.agent.registry.projects[rln].closing is False      # a second close may try again
        run(go())

    def test_close_waits_for_an_evaluation_in_progress(self, tmp_path, monkeypatch):
        """The ``end-exam`` the GUI launched at the end may still evaluate when the release
        delay is 0: the stop waits for the lock of ``sre eval`` (a live process), not for the
        lock a dead one left."""
        monkeypatch.setattr(agent_app, 'EVAL_LOCK_POLL', 0.02)

        async def go():
            async with Harness(tmp_path) as h:
                rln = start_by_hand(h, lab=EXAM_LAB, login='bob')
                assert (await put(h, body(labs=[EXAM_LAB]))).status == 200
                lock = h.pub / 'projects' / rln / params.private_dir_name / params.eval_in_progress_name
                lock.write_text(str(os.getpid()))
                closing = asyncio.ensure_future(delete(h, close='1'))
                await asyncio.sleep(0.3)
                assert not closing.done() and not any(c[0] == 'stop' for c in h.calls())
                lock.unlink()
                resp = await closing
                assert resp.status == 200 and (await resp.json())['closed'] == 1
            async with Harness(tmp_path / 'b') as h:
                rln = start_by_hand(h, lab=EXAM_LAB, login='bob')
                assert (await put(h, body(labs=[EXAM_LAB]))).status == 200
                lock = h.pub / 'projects' / rln / params.private_dir_name / params.eval_in_progress_name
                lock.write_text('999999999')                                  # no such process
                resp = await asyncio.wait_for(delete(h, close='1'), 20)
                assert resp.status == 200 and (await resp.json())['closed'] == 1
        run(go())

    def test_the_labs_of_an_instructor_are_listed_in_exam_mode(self, tmp_path):
        """The exam form of the portal asks one host for every lab: an exam machine answers
        (a privileged list), a student still gets nothing there."""
        async def go():
            async with Harness(tmp_path) as h:
                assert (await put(h)).status == 200
                labs = await (await h.client.get('/v1/labs', params={'all': '1'}, headers=headers(PROF))).json()
                assert EXAM_LAB in {entry['name'] for entry in labs}
                assert await (await h.client.get('/v1/labs', headers=headers(ALICE))).json() == []
                assert await (await h.client.get('/v1/labs', headers=headers(PROF))).json() == []
        run(go())
