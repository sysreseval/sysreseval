"""Tests of the exam projects of the agent: the per-project exam the portal programs
(``sreweb.agent.exam``), what the schedulers do with it (the periodic evaluation at its interval,
the cut and the final evaluation at its end, no reaping before), the exam fields of the answers
metadata, and the API (the privileged start with a preset and an exam-only lab, the owner's
refusals, ``PUT`` / ``DELETE …/exam``, the restart of the agent).  Hand-made projects for the
schedulers and the answers (no sre), the fake sre of tests/mock_sre.py behind the API."""
import asyncio
import json
import logging
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")

from SRE import params
from SRE.answers import exam_fields
from sreweb.agent import exam as X
from sreweb.agent.access import AccessError
from sreweb.agent.answers import AnswersStore
from sreweb.agent.registry import Registry, EVENT_EXAM, EVENT_INFO
from sreweb.agent.schedulers import Schedulers, FINAL_EVAL_RETRY
from sreweb.identity import Identity

import test_agent_api as A
import test_agent_registry as R
from test_agent_api import Harness, headers, ALICE, BOB, PROF, receive_event, run, TERMINAL_SUBPROTOCOL

EXAM_LAB = 'sre/_EXAM_/exam1.py'
EXAM_ID = 'exam-7'


def iso(seconds: float, origin: datetime | None = None) -> str:
    """An aware UTC instant *seconds* from now (or from *origin*), whole seconds."""
    base = origin or datetime.now(timezone.utc)
    return (base.replace(microsecond=0) + timedelta(seconds=seconds)).isoformat(timespec='seconds')


def exam_body(start: float = -60, end: float | None = 3600, **over) -> dict:
    body = {'id': EXAM_ID, 'title': 'Partiel', 'started_at': iso(start) if start is not None else None,
            'end_at': iso(end) if end is not None else None, 'eval_interval': 60}
    body.update(over)
    return body


def exam_project(pub, exam: dict, **over):
    """A hand-made managed project whose state file carries *exam*."""
    path = R.make_project(pub, **over)
    (pub / 'web-agent' / f'{R.RLN}.json').write_text(json.dumps({'idle_timeout': None, 'exam': exam}))
    return path


class RecordingRunner(R.FakeRunner):
    """A fake runner noting its calls in a shared *order* list too."""

    def __init__(self, order: list, fail=()):
        super().__init__(fail)
        self.order = order

    async def run(self, user, args, **kw):
        self.order.append(args[0])
        return await super().run(user, args, **kw)


class FakeTerminal:
    def __init__(self, order: list):
        self.order = order
        self.closing = False

    async def close(self):
        self.closing = True
        self.order.append('closed')


# ---------------------------------------------------------------------------------------------
# the module
# ---------------------------------------------------------------------------------------------

class TestExamModule:
    def test_parse_normalises_and_validates(self):
        exam, skew = X.parse_exam({'id': 'e1', 'title': 'T', 'started_at': '2026-11-04T09:00:00Z',
                                   'end_at': '2026-11-04T11:30:00+01:00', 'eval_interval': 60})
        assert exam == {'id': 'e1', 'title': 'T', 'started_at': '2026-11-04T09:00:00+00:00',
                        'end_at': '2026-11-04T10:30:00+00:00', 'eval_interval': 60}
        assert skew is None
        # the clock has not started: no times; a title missing or null is ''
        exam, _ = X.parse_exam({'id': 'e1', 'title': None, 'started_at': None, 'end_at': None})
        assert exam == {'id': 'e1', 'title': '', 'started_at': None, 'end_at': None, 'eval_interval': 0}
        # the skew of the portal's clock
        _, skew = X.parse_exam({'id': 'e1', 'now': iso(10)})
        assert 9 <= skew <= 11
        for bad in [{'id': 'e1', 'started_at': '2026-11-04T09:00:00'},                  # naive
                    {'id': 'e1', 'started_at': 'yesterday'},
                    {'id': 'e1', 'started_at': '2026-11-04T09:00:00Z', 'end_at': '2026-11-04T08:00:00Z'},
                    {'id': 'e1', 'end_at': '2026-11-04T09:00:00Z'},                     # an end alone
                    {'id': 'e1', 'eval_interval': -1}, {'id': 'e1', 'eval_interval': 'x'},
                    {'id': 'e1', 'eval_interval': X.MAX_EVAL_INTERVAL + 1}, {'id': 'e1', 'eval_interval': True},
                    {'id': 'a b'}, {'id': ''}, {'id': 12}, {'id': 'e1', 'title': 'x' * 201},
                    {'id': 'e1', 'now': '2026-11-04T09:00:00'}, [], 'e1']:
            with pytest.raises(AccessError) as e:
                X.parse_exam(bad)
            assert e.value.status == 400, bad

    def test_exam_json_data_matches_the_cli(self):
        """The exam fields of the answers (SRE.answers.exam_fields on an exam.json-shaped dict)
        give the remaining time of the exam to the second, whatever the length of the exam."""
        now = datetime.now().replace(microsecond=0)
        origin = now.astimezone(timezone.utc)
        for length in (3600, 90 * 60 + 30, 179):
            exam, _ = X.parse_exam({'id': 'e1', 'started_at': iso(-120, origin), 'end_at': iso(length - 120, origin)})
            data = X.exam_json_data(exam)
            fields = exam_fields(data, now)
            assert fields[params.sysreseval_exam_mode] is True
            assert fields[params.sysreseval_exam_started_at] == exam['started_at']
            assert fields[params.sysreseval_exam_duration] == -(-length // 60)
            assert fields[params.sysreseval_exam_time_remaining] == length - 120 == X.remaining(exam, now.timestamp())
        unstarted, _ = X.parse_exam({'id': 'e1'})
        assert X.exam_json_data(unstarted) == {} and exam_fields({}, now) == {params.sysreseval_exam_mode: True}
        assert X.remaining(unstarted) is None

    def test_load_exam_is_lenient(self):
        stored = {'id': 'e1', 'title': 'T', 'started_at': '2026-11-04T09:00:00+00:00',
                  'end_at': '2026-11-04T10:00:00+00:00', 'eval_interval': 30,
                  'ended_at': '2026-11-04T10:00:01+00:00', 'final_eval_at': '2026-11-04T10:00:40+00:00'}
        assert X.load_exam(stored) == stored
        assert X.load_exam({**stored, 'ended_at': 'junk', 'final_eval_at': None}) == {
            k: v for k, v in stored.items() if k not in ('ended_at', 'final_eval_at')}
        assert X.load_exam({'id': 'bad id'}) is None and X.load_exam('x') is None and X.load_exam(None) is None

    def test_view_and_predicates(self):
        exam, _ = X.parse_exam(exam_body(start=-60, end=600))
        assert X.view(None) is None
        view = X.view(exam)
        assert view['id'] == EXAM_ID and view['ended'] is False and view['ended_at'] is None
        assert view['final_eval_at'] is None and 598 <= view['remaining'] <= 600
        assert X.is_running(exam) and not X.is_over(exam)
        exam['ended_at'] = X.now_iso()
        assert X.is_over(exam) and X.view(exam)['ended'] is True and X.view(exam)['remaining'] == 0
        assert not X.is_running(exam) and not X.is_running(None)

    def test_flavor_preset(self):
        assert X.check_flavor_preset('hard_2') == 'hard_2'
        for bad in ('2hard', 'a-b', '', None, 3, 'x y'):
            with pytest.raises(AccessError) as e:
                X.check_flavor_preset(bad)
            assert e.value.status == 400


# ---------------------------------------------------------------------------------------------
# the schedulers
# ---------------------------------------------------------------------------------------------

class TestExamSchedulers:
    def test_exam_interval_wins(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(eval_interval=1), eval_interval_without_exam_mode=0)
        reg = R.registry()
        runner = R.FakeRunner()
        sched = Schedulers(reg, runner, exam_mode=lambda: False)

        async def go():
            await reg.tick()
            p = reg.get(R.RLN)
            assert p.exam['id'] == EXAM_ID and p.exam_running and p.next_eval_at is not None
            assert p.to_dict()['exam']['id'] == EXAM_ID
            p.next_eval_at = time.monotonic() - 1
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == [('alice', ['eval', '--', R.RLN])]
            # the clock of the student not started: no periodic evaluation yet
            p.exam['started_at'] = p.exam['end_at'] = None
            sched.arm(p)
            assert p.next_eval_at is None and Schedulers.eval_interval(p) == 0
        run(go())

    def test_exam_end_cuts_then_evaluates(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(end=-1, eval_interval=0))
        reg = R.registry()
        order = []
        runner = RecordingRunner(order)
        evaluated = []

        async def on_exam_ended(project):
            order.append('exam_ended')

        async def on_evaluated(project):
            evaluated.append(project.rln)

        Schedulers(reg, runner, exam_mode=lambda: False, on_evaluated=on_evaluated, on_exam_ended=on_exam_ended)

        async def go():
            await reg.tick()
            p = reg.get(R.RLN)
            p.terminals['t1'] = FakeTerminal(order)
            p.last_activity = time.monotonic() - 1000
            await reg.tick()
            await asyncio.sleep(0.1)
            assert order == ['closed', 'exam_ended', 'eval'] and evaluated == [R.RLN]
            assert p.exam_over and p.exam['final_eval_at'] and p.terminals == {}
            assert p.idle_seconds() < 5                     # the idle clock counts from the end
            state = json.loads((tmp_pub_dir / 'web-agent' / f'{R.RLN}.json').read_text())
            assert state['exam']['ended_at'] == p.exam['ended_at'] and state['exam']['final_eval_at']
            await reg.tick()
            await asyncio.sleep(0.05)
            assert order == ['closed', 'exam_ended', 'eval']   # once
        run(go())

    def test_exam_end_waits_for_the_lock(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(end=-1, eval_interval=0))
        reg = R.registry()
        runner = R.FakeRunner()
        Schedulers(reg, runner, exam_mode=lambda: False)

        async def go():
            await reg.tick()
            p = reg.get(R.RLN)
            async with p.lock:                     # an evaluation of the student in flight
                await reg.tick()
                await asyncio.sleep(0.05)
                assert p.exam_over and runner.calls == [] and 'final_eval_at' not in p.exam
            await asyncio.sleep(0.05)
            assert runner.calls == [('alice', ['eval', '--', R.RLN])] and p.exam['final_eval_at']
        run(go())

    def test_failed_final_eval_is_retried(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(end=-1, eval_interval=0))
        reg = R.registry()
        runner = R.FakeRunner(fail={'eval'})
        Schedulers(reg, runner, exam_mode=lambda: False)

        async def go():
            await reg.tick()
            p = reg.get(R.RLN)
            await reg.tick()
            await asyncio.sleep(0.05)
            assert p.exam_over and 'final_eval_at' not in p.exam and len(runner.calls) == 1
            assert p.exam_retry_at is not None and p.exam_retry_at - time.monotonic() <= FINAL_EVAL_RETRY
            await reg.tick()
            await asyncio.sleep(0.05)
            assert len(runner.calls) == 1                   # not before the retry delay
            runner.fail.clear()
            p.exam_retry_at = time.monotonic() - 1
            await reg.tick()
            await asyncio.sleep(0.05)
            assert len(runner.calls) == 2 and p.exam['final_eval_at'] and p.exam_retry_at is None
        run(go())

    def test_never_reaped_before_the_end_and_reaped_after(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(end=3600, eval_interval=0))
        reg = R.registry()
        runner = R.FakeRunner()
        Schedulers(reg, runner, exam_mode=lambda: False, default_idle_timeout=10)

        async def go():
            await reg.tick()
            p = reg.get(R.RLN)
            p.last_activity = time.monotonic() - 100
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == []                       # running: never
            p.exam['ended_at'] = p.exam['final_eval_at'] = X.now_iso()
            p.last_activity = time.monotonic() - 100
            reg.subscribe(p, lambda e: None, ALICE)        # the owner's page keeps nothing alive now
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == [('alice', ['stop', '--', R.RLN])]
        run(go())

    def test_instructor_page_keeps_an_ended_exam_project(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, {**exam_body(end=3600, eval_interval=0), 'ended_at': iso(-100),
                                   'final_eval_at': iso(-90)})
        reg = R.registry()
        runner = R.FakeRunner()
        Schedulers(reg, runner, exam_mode=lambda: False, default_idle_timeout=10)

        async def go():
            await reg.tick()
            p = reg.get(R.RLN)
            p.last_activity = time.monotonic() - 100
            reg.subscribe(p, lambda e: None, PROF)
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == []
        run(go())

    def test_close_project_of_an_exam(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(end=3600), eval_before_exit=False)
        reg = R.registry()
        runner = R.FakeRunner()
        sched = Schedulers(reg, runner, exam_mode=lambda: False)
        run(reg.tick())
        run(sched.close_project(reg.get(R.RLN)))
        assert runner.calls == [('alice', ['eval', '--', R.RLN]), ('alice', ['stop', '--', R.RLN])]   # in progress: evaluated
        import shutil
        shutil.rmtree(tmp_pub_dir / 'projects' / R.RLN)
        exam_project(tmp_pub_dir, {**exam_body(end=-10), 'ended_at': iso(-9), 'final_eval_at': iso(-5)},
                     eval_before_exit=True)
        reg = R.registry()
        runner = R.FakeRunner()
        sched = Schedulers(reg, runner, exam_mode=lambda: False)
        run(reg.tick())
        run(sched.close_project(reg.get(R.RLN)))
        assert runner.calls == [('alice', ['stop', '--', R.RLN])]                                # over: stop only

    def test_restart_after_the_end_evaluates_late(self, tmp_pub_dir):
        """The agent restarted between the end and the final evaluation (the state file holds
        ended_at without final_eval_at): the evaluation runs at the first tick, nothing is cut
        again."""
        exam_project(tmp_pub_dir, {**exam_body(start=-200, end=-100), 'ended_at': iso(-99)})
        reg = R.registry()
        runner = R.FakeRunner()
        ended = []

        async def on_exam_ended(project):
            ended.append(project.rln)

        Schedulers(reg, runner, exam_mode=lambda: False, on_exam_ended=on_exam_ended)

        async def go():
            await reg.tick()
            await asyncio.sleep(0.05)
            p = reg.get(R.RLN)
            assert runner.calls == [('alice', ['eval', '--', R.RLN])] and p.exam['final_eval_at'] and ended == []
        run(go())

    def test_state_file_keeps_the_exam(self, tmp_pub_dir):
        exam = exam_body()
        exam_project(tmp_pub_dir, exam)
        reg = R.registry()
        run(reg.tick())
        p = reg.get(R.RLN)
        p.exam['title'] = 'Changed'
        reg.write_state(p, force=True)
        again = R.registry()
        run(again.tick())
        assert again.get(R.RLN).exam == {**exam, 'title': 'Changed'}
        # an unusable exam in the file: ignored, the project is a plain one
        (tmp_pub_dir / 'web-agent' / f'{R.RLN}.json').write_text(json.dumps({'idle_timeout': None, 'exam': {'id': 'x y'}}))
        third = R.registry()
        run(third.tick())
        assert third.get(R.RLN).exam is None and third.get(R.RLN).managed


# ---------------------------------------------------------------------------------------------
# the answers metadata
# ---------------------------------------------------------------------------------------------

class TestExamAnswers:
    def test_exam_fields_of_an_exam_project(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(start=-120, end=3480))
        reg = R.registry()
        store = AnswersStore(reg, hostname='pool1', pub_dir=str(tmp_pub_dir))
        run(reg.tick())
        p = reg.get(R.RLN)
        data = run(store.rewrite(p, ALICE))
        assert data[params.sysreseval_exam_mode] is True and data[params.sysreseval_exam_started_at] == p.exam['started_at']
        assert data[params.sysreseval_exam_duration] == 60 and 3470 <= data[params.sysreseval_exam_time_remaining] <= 3480
        assert data[params.login_keyword] == 'alice' and data[params.fullname_keyword] == 'Alice A'
        # the end moved: rewrite_kept keeps the identity and refreshes the exam fields
        p.exam['end_at'] = iso(7080)
        data = run(store.rewrite_kept(p))
        assert data[params.sysreseval_exam_duration] == 120 and data[params.fullname_keyword] == 'Alice A'
        assert data[params.language_keyword] == 'fr'
        # over: nothing remains
        p.exam['ended_at'] = X.now_iso()
        data = run(store.rewrite_kept(p))
        assert data[params.sysreseval_exam_mode] is True and data[params.sysreseval_exam_time_remaining] >= 0
        # the host-wide exam.json wins
        (tmp_pub_dir / params.exam_json_name).write_text(json.dumps({'duration': 5, 'started_at': p.exam['started_at']}))
        assert run(store.rewrite(p, ALICE))[params.sysreseval_exam_duration] == 5

    def test_unstarted_exam_and_plain_project(self, tmp_pub_dir):
        exam_project(tmp_pub_dir, exam_body(start=None, end=None))
        reg = R.registry()
        store = AnswersStore(reg, hostname='pool1', pub_dir=str(tmp_pub_dir))
        run(reg.tick())
        p = reg.get(R.RLN)
        data = run(store.rewrite(p, ALICE))
        assert data[params.sysreseval_exam_mode] is True and params.sysreseval_exam_started_at not in data
        p.exam = None
        assert run(store.rewrite_kept(p))[params.sysreseval_exam_mode] is False


# ---------------------------------------------------------------------------------------------
# the API
# ---------------------------------------------------------------------------------------------

async def terminal_gone(ws, timeout=5.0):
    """Whether a terminal WebSocket got the exit of its session (or a close)."""
    async with asyncio.timeout(timeout):
        while True:
            msg = await ws.receive()
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                return True
            if msg.type == aiohttp.WSMsgType.TEXT and json.loads(msg.data).get('t') == 'exit':
                return True


def start_by_hand(h: Harness, lab: str = 'sre/dhcp.py', login: str = 'alice') -> str:
    """A project started outside the agent (the Qt GUI of the student): not managed."""
    env = {'PATH': '/usr/bin:/bin', 'SRE_PUB_DIR': str(h.pub), 'LOGNAME': 'root', 'SUDO_USER': login,
           'USER_USERNAME': login}
    completed = subprocess.run([sys.executable, '-W', 'ignore', str(A.MOCK), '--user', 'start', lab],
                               capture_output=True, env=env, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode()
    for line in completed.stderr.decode().splitlines():
        event = json.loads(line)
        if event.get('phase') == 'project':
            return event['running_lab_name']
    raise AssertionError("no project created")


class TestExamApi:
    def test_exam_start_is_privileged_with_preset_and_exam_only_lab(self, tmp_path):
        async def go():
            async with Harness(tmp_path, {'MOCK_FLAVOR_FORM': 'x', 'MOCK_FLAVOR_PRESETS': '["hard"]'}) as h:
                lines, result = await h.start(ALICE, lab=EXAM_LAB, exam=exam_body(), flavor='hard', idle_timeout=600)
                assert result['status'] == 'created', result
                rln = result['running_lab_name']
                assert rln.endswith('@@@sre@_EXAM_@exam1.py@@@alice')
                A.privileged_call(h.entries()[-1], ['start', '--set-flavor-name', 'hard', '--', EXAM_LAB], 'alice')
                deploys = [l for l in lines if l.get('phase') == 'deploy' and l.get('status') == 'progress']
                assert len(deploys) == 3 and all('machine' not in l for l in deploys)   # the hidden machines stay hidden
                flavor = json.loads((h.pub / 'projects' / rln / '.private' / 'flavor.json').read_text())
                assert flavor == {'@preset': 'hard'}
                state = json.loads((tmp_path / 'web-agent' / f'{rln}.json').read_text())
                assert state['exam']['id'] == EXAM_ID and state['exam']['started_at'].endswith('+00:00')
                assert state['idle_timeout'] == 600.0
                rows = await (await h.client.get('/v1/projects', headers=headers())).json()
                assert rows[0]['exam']['id'] == EXAM_ID and 3500 < rows[0]['exam']['remaining'] <= 3660
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['exam_projects'] == 1
                # the owner gets the exam-mode tabs, an instructor keeps the Evaluation tab
                view = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert 'evaluation' not in view['tabs'] and 'apply_config' not in view['tabs']
                assert view['exam']['id'] == EXAM_ID and view['exam']['ended'] is False
                view = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).json())['project']
                assert 'evaluation' in view['tabs'] and 'apply_config' in view['tabs']
                answers = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert answers[params.sysreseval_exam_mode] is True and answers[params.sysreseval_exam_duration] == 61
                assert answers[params.login_keyword] == 'alice' and answers[params.fullname_keyword] == 'Alice A'
                # an exam project of a plain lab, without preset, the clock not started yet
                rln2 = await h.started(BOB, exam=exam_body(start=None, end=None))
                A.privileged_call(h.entries()[-1], ['start', '--', 'sre/dhcp.py'], 'bob')
                row = (await (await h.client.get('/v1/projects', headers=headers(BOB))).json())[0]
                assert row['running_lab_name'] == rln2 and row['exam']['remaining'] is None
        run(go())

    def test_start_refusals(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                async def refused(status, **body):
                    resp = await h.client.post('/v1/projects', json={'lab': 'sre/dhcp.py', **body}, headers=headers())
                    assert resp.status == status, (body, await resp.text())
                    return (await resp.json())['error']
                assert 'unknown lab' in await refused(404, lab=EXAM_LAB)                   # exam-only: with an exam only
                assert 'preset' in await refused(400, flavor='hard')
                assert 'exclusive' in await refused(400, flavor='hard', flavor_json={'a': 1}, exam=exam_body())
                assert 'preset' in await refused(400, flavor='2x', exam=exam_body())
                assert 'timezone' in await refused(400, exam=exam_body(started_at='2026-11-04T09:00:00'))
                assert 'object' in await refused(400, exam='e1')
                assert 'bad id' in await refused(400, exam={'id': ''})
        run(go())

    def test_labs_all(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await h.client.get('/v1/labs?all=1', headers=headers(PROF))
                names = [lab['name'] for lab in await resp.json()]
                assert resp.status == 200 and 'sre/_EXAM_' in names and EXAM_LAB in names and 'sre/dhcp.py' in names
                A.privileged_call(h.entries()[-1], ['list', '--with-titles', '--include-exam-only'], 'prof')
                assert (await h.client.get('/v1/labs?all=1', headers=headers())).status == 403
                names = [lab['name'] for lab in await (await h.client.get('/v1/labs', headers=headers())).json()]
                assert EXAM_LAB not in names and 'sre/dhcp.py' in names
                await h.client.get('/v1/labs?all=1', headers=headers(PROF))
                await h.client.get('/v1/labs', headers=headers(BOB))
                assert sum(1 for c in h.calls() if 'list' in c) == 2   # one call per list, cached
        run(go())

    def test_owner_refusals_during_the_exam(self, tmp_path):
        async def go():
            async with Harness(tmp_path, {'MOCK_COOLDOWN': '60'}) as h:
                rln = await h.started(ALICE, exam=exam_body())
                for suffix in ('/eval', '/states/final'):
                    resp = await h.client.post(f'/v1/projects/{rln}{suffix}', headers=headers())
                    assert resp.status == 409 and (await resp.json())['error'] == "exam in progress", suffix
                resp = await h.client.delete(f'/v1/projects/{rln}', headers=headers())
                assert resp.status == 409 and (h.pub / 'projects' / rln).exists()
                resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {A.TEXT_HASH: 'gw'}},
                                          headers=headers())
                assert resp.status == 200
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                               protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await ws.receive_json())['t'] == 'ready'
                await ws.close()
                # an instructor on it: the privileged evaluation and the states still run
                resp = await h.client.post(f'/v1/projects/{rln}/eval', headers=headers(PROF))
                assert resp.status == 200 and (await resp.json())['result']['grades']
                A.privileged_call(h.entries()[-1], ['eval', '--', rln], 'prof')
                assert (await h.client.post(f'/v1/projects/{rln}/states/final', headers=headers(PROF))).status == 200
        run(go())

    def test_periodic_evaluation_every_exam_interval(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started(ALICE, exam=exam_body(eval_interval=1))
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF))
                await receive_event(ws, 'evaluated', timeout=5)
                entry = h.entries()[-1]
                assert (entry['argv'], entry['user_mode'], entry['username']) == (['--user', 'eval', '--', rln], True, 'alice')
                await receive_event(ws, 'evaluated', timeout=5)
                await ws.close()
        run(go())

    def test_end_of_the_exam(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started(ALICE, exam=exam_body(start=-10, end=2, eval_interval=0))
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                term = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await term.receive_json())['t'] == 'ready'
                event = await receive_event(ws, EVENT_EXAM, timeout=10)
                assert event['ended'] is True and event['exam']['ended_at'] and event['exam']['remaining'] == 0
                info = await receive_event(ws, EVENT_INFO, timeout=5)
                assert info['project']['exam']['ended'] is True
                assert await terminal_gone(term)
                await receive_event(ws, 'evaluated', timeout=10)      # the final evaluation
                assert ['--user', 'eval', '--', rln] in h.calls()
                row = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]
                assert row['exam']['ended'] is True and row['exam']['final_eval_at'] and row['last_eval'] is not None
                records = (await (await h.client.get('/v1/archives', headers=headers(None))).json())['archives']
                assert records and records[-1]['exam'] is True
                state = json.loads((tmp_path / 'web-agent' / f'{rln}.json').read_text())
                assert state['exam']['ended_at'] and state['exam']['final_eval_at']
                # the owner is cut off, an instructor is not
                resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {A.TEXT_HASH: 'late'}},
                                          headers=headers())
                assert resp.status == 409 and (await resp.json())['error'] == "the exam is over"
                assert (await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())).status == 409
                assert (await h.client.post(f'/v1/projects/{rln}/touch', headers=headers())).status == 204
                term = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await term.receive_json())['t'] == 'error'
                closing = await term.receive()
                assert closing.type == aiohttp.WSMsgType.CLOSE and closing.data == 4403 and b'over' in closing.extra.encode()
                assert (await h.client.post(f'/v1/projects/{rln}/eval', headers=headers(PROF))).status == 200
                term = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(PROF),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await term.receive_json())['t'] == 'ready'
                await term.close()
                assert (await h.client.delete(f'/v1/projects/{rln}', headers=headers())).status == 409
                assert (await h.client.delete(f'/v1/projects/{rln}', headers=headers(PROF))).status == 200
                assert h.calls()[-1] == ['--user', 'stop', '--', rln] and h.calls()[-2] != ['--user', 'eval', '--', rln]
                assert not (h.pub / 'projects' / rln).exists()
                await ws.close()
        run(go())

    def test_extend_resume_and_cancel(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started(ALICE, exam=exam_body(start=-60, end=600, eval_interval=0))
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                assert (await h.client.put(f'/v1/projects/{rln}/exam', json=exam_body(end=1200), headers=headers())).status == 403
                later = exam_body(start=-60, end=7200, eval_interval=0)
                resp = await h.client.put(f'/v1/projects/{rln}/exam', json=later, headers=headers(PROF))
                assert resp.status == 200 and (await resp.json())['exam']['end_at'] == later['end_at']
                event = await receive_event(ws, EVENT_EXAM, timeout=5)
                assert event['ended'] is False and event['exam']['end_at'] == later['end_at']
                assert (await receive_event(ws, EVENT_INFO, timeout=5))['project']['exam']['end_at'] == later['end_at']
                state = json.loads((tmp_path / 'web-agent' / f'{rln}.json').read_text())
                assert state['exam']['end_at'] == later['end_at']
                answers = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert answers[params.sysreseval_exam_duration] == 121
                # a project this agent does not manage (the Qt GUI's) cannot carry an exam
                other = start_by_hand(h)
                await asyncio.sleep(0.2)
                resp = await h.client.put(f'/v1/projects/{other}/exam', json=later, headers=headers(PROF))
                assert resp.status == 409 and 'managed' in (await resp.json())['error']
                # ended by the instructor (the end moved to the past), then resumed
                resp = await h.client.put(f'/v1/projects/{rln}/exam', json=exam_body(start=-60, end=-1, eval_interval=0),
                                          headers=headers(PROF))
                assert resp.status == 200
                event = await receive_event(ws, EVENT_EXAM, timeout=5)   # the change itself
                assert event['ended'] is False
                event = await receive_event(ws, EVENT_EXAM, timeout=5)   # the end, at the next tick
                assert event['ended'] is True
                await receive_event(ws, 'evaluated', timeout=10)
                resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {A.TEXT_HASH: 'x'}},
                                          headers=headers())
                assert resp.status == 409
                resp = await h.client.put(f'/v1/projects/{rln}/exam', json=exam_body(start=-60, end=3600, eval_interval=0),
                                          headers=headers(PROF))
                data = await resp.json()
                assert resp.status == 200 and data['exam']['ended'] is False and data['exam']['ended_at'] is None
                assert (await receive_event(ws, EVENT_EXAM, timeout=5))['ended'] is False
                resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {A.TEXT_HASH: 'x'}},
                                          headers=headers())
                assert resp.status == 200
                # the exam removed: a plain project again
                resp = await h.client.delete(f'/v1/projects/{rln}/exam', headers=headers(PROF))
                assert resp.status == 200 and (await resp.json()) == {'ok': True, 'exam': None}
                assert (await receive_event(ws, EVENT_EXAM, timeout=5))['exam'] is None
                assert 'evaluation' in (await receive_event(ws, EVENT_INFO, timeout=5))['project']['tabs']
                assert (await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())).status == 200
                assert h.calls()[-1] == ['--user', 'eval', '--auto-eval', '--', rln]
                assert 'exam' not in json.loads((tmp_path / 'web-agent' / f'{rln}.json').read_text())
                assert (await h.client.delete(f'/v1/projects/{rln}/exam', headers=headers(PROF))).status == 200   # idempotent
                assert (await h.client.delete(f'/v1/projects/{rln}/exam', headers=headers())).status == 403
                await ws.close()
        run(go())

    def test_agent_restart_resumes_the_exam(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started(ALICE, exam=exam_body(start=-60, end=1.5, eval_interval=0))
                assert ['--user', 'eval', '--', rln] not in h.calls()
            await asyncio.sleep(1.6)
            async with Harness(tmp_path) as h:
                async with asyncio.timeout(10):
                    while ['--user', 'eval', '--', rln] not in h.calls():
                        await asyncio.sleep(0.1)
                row = (await (await h.client.get('/v1/projects', headers=headers())).json())[0]
                assert row['managed'] is True and row['exam']['ended'] is True
                async with asyncio.timeout(5):
                    while not row['exam']['final_eval_at']:
                        await asyncio.sleep(0.1)
                        row = (await (await h.client.get('/v1/projects', headers=headers())).json())[0]
        run(go())

    def test_restart_of_the_agent_keeps_the_exam_projects(self, tmp_path):
        async def go():
            async with Harness(tmp_path, close_projects_on_stop='always') as h:
                exam_rln = await h.started(ALICE, exam=exam_body(end=3600))
                plain_rln = await h.started(BOB)
                h.agent.system_stopping = lambda: False
                await h.agent.close_managed_projects()
                assert (h.pub / 'projects' / exam_rln).exists() and not (h.pub / 'projects' / plain_rln).exists()
                h.agent.system_stopping = lambda: True
                await h.agent.close_managed_projects()
                assert not (h.pub / 'projects' / exam_rln).exists()
                assert h.calls()[-2:] == [['--user', 'eval', '--', exam_rln], ['--user', 'stop', '--', exam_rln]]
        run(go())

    def test_skew_warning(self, tmp_path):
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        logger = logging.getLogger('sreweb.agent')
        logger.addHandler(handler)
        try:
            async def go():
                async with Harness(tmp_path) as h:
                    await h.started(ALICE, exam=exam_body(now=iso(30)))
                    await h.started(BOB, exam=exam_body(now=iso(1)))
            run(go())
        finally:
            logger.removeHandler(handler)
        warnings = [r.getMessage() for r in records if 'clock' in r.getMessage()]
        assert len(warnings) == 1 and 'off this host' in warnings[0]
