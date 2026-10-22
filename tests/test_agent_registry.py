"""Tests of sreweb.agent.registry, answers store, schedulers and projectview on hand-made project
directories (no sre, no Docker)."""
import asyncio
import json
import os
import time

import pytest
from pathlib import Path

from SRE import params
from SRE.common import InfoLab, InfoMachine, InfoSwitch, InfoInterface, QuestionText, QuestionForm
from sreweb.agent.answers import AnswersStore
from sreweb.agent.registry import Registry, EVENT_LOG, EVENT_REMOVED, EVENT_ANSWERS, EVENT_INFO
from sreweb.agent.schedulers import Schedulers
from sreweb.agent.access import AccessError
from sreweb.identity import Identity
from sreweb import projectview

ALICE = Identity(login='alice', fullname='Alice A', email='a@example.org', language='fr')
BOB = Identity(login='bob')
PROF = Identity(login='prof', role='instructor', view='instructor')
RLN = '20260910100000@@@sre@dhcp.py@@@alice'


def make_info(**over) -> dict:
    questions = [QuestionText(title={'en': 'Why?', 'fr': 'Pourquoi ?'}, order=1),
                 QuestionForm(title='Form', description='IP: @@{ip:[0-9.]+}@@ ok @@{ok:?}@@', order=2)]
    lab = InfoLab(
        lab_name='sre/dhcp.py', lab_hash='abc', title={'en': 'DHCP', 'fr': 'Le DHCP'},
        informations={'en': '# Hello\n\n' + params.instructor_begin_mark + ';' + params.instructor_args_end_mark
                      + 'secret' + params.instructor_end_mark, 'fr': '# Bonjour'},
        machines=[InfoMachine(name='pc1', status='running', allow_connection=True, hidden=False,
                              interfaces=[InfoInterface(network='lan', interface_name='eth0')], ports=['8080:80/tcp'],
                              bridged=True),
                  InfoMachine(name='srv', status='running', allow_connection=False, hidden=False,
                              interfaces=[InfoInterface(network='lan', interface_name='eth0')], ports=[], bridged=False),
                  InfoMachine(name='probe', status='running', allow_connection=True, hidden=True,
                              interfaces=[InfoInterface(network='secret', interface_name='eth0')], ports=[],
                              bridged=False)],
        switches=[InfoSwitch(name='lan', mode='managed', allow_connection=True)],
        questions=questions, user_allowed_states={'final': {'en': 'Solution', 'fr': 'La solution'}, 'fault': ''},
        admin_only_states=['fault'], allow_self_grade=True, default_language='fr',
        export_kathara_project=True, delay_between_self_grade=5, eval_interval_without_exam_mode=0,
        eval_before_exit=False,
    )
    d = json.loads(lab.to_json())
    d.update(over)
    return d


def make_project(pub, rln=RLN, managed=True, **over):
    """A project directory; *managed*: with the state file the agent writes for the projects it
    created (the schedulers act on those only)."""
    path = pub / 'projects' / rln
    (path / params.answer_dir_name).mkdir(parents=True)
    (path / params.private_dir_name).mkdir()
    (path / params.info_json_name).write_text(json.dumps(make_info(**over)))
    if managed:
        (pub / 'web-agent').mkdir(exist_ok=True)
        (pub / 'web-agent' / f'{rln}.json').write_text(json.dumps({'idle_timeout': None}))
    return path


def registry(**kw):
    return Registry(params.sre_projects_dir, state_dir=str(Path(params.sre_pub_dir) / 'web-agent'), **kw)


def run(coro):
    return asyncio.run(coro)


class TestRegistry:
    def test_discovery_and_removal(self, tmp_pub_dir):
        path = make_project(tmp_pub_dir)
        reg = registry()
        added = []
        reg.on_added.append(added.append)
        run(reg.tick())
        assert [p.rln for p in added] == [RLN]
        p = reg.get(RLN)
        assert p.owner == 'alice' and p.lab_name == 'sre/dhcp.py' and p.started == '20260910100000'
        assert reg.require(RLN) is p and p.managed and (tmp_pub_dir / 'web-agent' / f'{RLN}.json').exists()
        assert [q.rln for q in reg.visible_to(ALICE)] == [RLN] and reg.visible_to(BOB) == []
        assert [q.rln for q in reg.visible_to(PROF)] == [RLN]
        events = []
        reg.subscribe(p, lambda e: _collect(events, e), ALICE)
        import shutil
        shutil.rmtree(path)
        run(reg.tick())
        assert reg.get(RLN) is None and events == [{'t': EVENT_REMOVED}]
        assert not (tmp_pub_dir / 'web-agent' / f'{RLN}.json').exists()
        with pytest.raises(AccessError):
            reg.require(RLN)

    def test_ignores_junk_directories(self, tmp_pub_dir):
        (tmp_pub_dir / 'projects' / 'no-marker').mkdir(parents=True)
        (tmp_pub_dir / 'projects' / '20260910100000@@@x@@@u').mkdir()   # no info.json yet
        reg = registry()
        run(reg.tick())
        assert reg.count() == 0

    def test_info_reload_and_event(self, tmp_pub_dir):
        path = make_project(tmp_pub_dir)
        reg = registry()
        reg.info_event = lambda project, identity: {'t': EVENT_INFO, 'login': identity.login,
                                                    'title': project.info['title']}
        run(reg.tick())
        p = reg.get(RLN)
        events = []
        reg.subscribe(p, lambda e: _collect(events, e), ALICE)
        info = make_info(title='Changed')
        (path / params.info_json_name).write_text(json.dumps(info))
        os.utime(path / params.info_json_name, (time.time() + 5, time.time() + 5))
        run(reg.tick())
        assert p.info['title'] == 'Changed' and events == [{'t': EVENT_INFO, 'login': 'alice', 'title': 'Changed'}]

    def test_log_tail_for_debug_projects_only(self, tmp_pub_dir):
        path = make_project(tmp_pub_dir)
        reg = registry()
        run(reg.tick())
        p = reg.get(RLN)
        events = []
        reg.subscribe(p, lambda e: _collect(events, e), ALICE)
        (path / params.operations_log_name).write_text('=== state final\n')
        run(reg.tick())
        assert events == []          # not a debug project: no tail
        (path / params.private_dir_name / 'debug_project').write_text('')
        p.debug = True
        run(reg.tick())
        assert events == [{'t': EVENT_LOG, 'data': '=== state final\n', 'reset': False}]
        with open(path / params.operations_log_name, 'a') as f:
            f.write('step1 - on pc1 : ls\n')
        run(reg.tick())
        assert events[-1] == {'t': EVENT_LOG, 'data': 'step1 - on pc1 : ls\n', 'reset': False}
        (path / params.operations_log_name).write_text('new\n')   # truncated: starts again
        run(reg.tick())
        assert events[-1] == {'t': EVENT_LOG, 'data': 'new\n', 'reset': True}

    def test_dead_subscriber_is_dropped(self, tmp_pub_dir):
        make_project(tmp_pub_dir)
        reg = registry()
        run(reg.tick())
        p = reg.get(RLN)

        async def dead(event):
            raise ConnectionResetError()
        reg.subscribe(p, dead, ALICE)
        run(reg.broadcast(p, {'t': 'x'}))
        assert p.subscribers == []

    def test_state_file_keeps_the_idle_clock(self, tmp_pub_dir):
        make_project(tmp_pub_dir)
        state_dir = tmp_pub_dir / 'web-agent'
        reg = registry()
        run(reg.tick())
        p = reg.get(RLN)
        p.idle_timeout = 120.0
        p.last_activity = time.monotonic() - 50
        reg.write_state(p, force=True)
        reg2 = registry()
        run(reg2.tick())
        p2 = reg2.get(RLN)
        assert p2.idle_timeout == 120.0 and 49 < p2.idle_seconds() < 55

    def test_adopt(self, tmp_pub_dir):
        reg = registry()
        run(reg.tick())
        make_project(tmp_pub_dir, managed=False)
        p = run(reg.adopt(RLN))
        assert p.rln == RLN and p.managed and (tmp_pub_dir / 'web-agent' / f'{RLN}.json').exists()
        assert run(reg.adopt('nope')) is None

    def test_foreign_project_is_listed_but_not_managed(self, tmp_pub_dir):
        """A project started by the Qt GUI on the same host: visible to its owner, never scheduled."""
        make_project(tmp_pub_dir, managed=False, eval_interval_without_exam_mode=1)
        reg = registry()
        runner = FakeRunner()
        Schedulers(reg, runner, exam_mode=lambda: False, default_idle_timeout=1)

        async def go():
            await reg.tick()
            p = reg.get(RLN)
            assert not p.managed and p.next_eval_at is None
            assert [q.rln for q in reg.visible_to(ALICE)] == [RLN]
            p.last_activity = time.monotonic() - 100
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == []
            assert not (tmp_pub_dir / 'web-agent' / f'{RLN}.json').exists()
        run(go())


async def _collect(events, e):
    events.append(e)


class FakeRunner:
    def __init__(self, fail=()):
        self.calls = []
        self.fail = set(fail)

    async def run(self, user, args, **kw):
        self.calls.append((user, list(args)))
        if args[0] in self.fail:
            from sreweb.agent.runner import CommandError
            raise CommandError(1, f"sre: {args[0]} failed")
        await asyncio.sleep(0)


class TestAnswersStore:
    def test_put_merges_and_writes_metadata(self, tmp_pub_dir):
        path = make_project(tmp_pub_dir)
        reg = registry()
        store = AnswersStore(reg, hostname='pool1', pub_dir=str(tmp_pub_dir), owner=None)
        run(reg.tick())
        p = reg.get(RLN)
        text_hash, form_hash = [q['question_hash'] for q in p.info['questions']]
        data = run(store.put(p, {text_hash: 'because'}, ALICE))
        assert data[text_hash] == 'because' and data[params.login_keyword] == 'alice'
        assert data[params.hostname_keyword] == 'pool1' and data[params.fullname_keyword] == 'Alice A'
        assert data[params.email_keyword] == 'a@example.org' and data[params.language_keyword] == 'fr'
        assert data[params.sysreseval_exam_mode] is False and len(data[params.sysreseval_answers_updated_at]) == 14
        on_disk = json.loads((path / params.answer_dir_name / params.answers_filename(RLN).rsplit('/', 1)[1]).read_text())
        assert on_disk[text_hash] == 'because'
        data = run(store.put(p, {form_hash: {'ip': '10.0.0.1', 'ok': True, 'junk': 1}}, ALICE))
        assert json.loads(data[form_hash]) == {'ip': '10.0.0.1', 'ok': True} and data[text_hash] == 'because'
        data = run(store.put(p, {form_hash: json.dumps({'ip': '1.2.3.4'})}, ALICE))   # a string form is fine too
        assert json.loads(data[form_hash]) == {'ip': '1.2.3.4', 'ok': False}
        public = AnswersStore.public(data, p)
        assert set(public) == {text_hash, form_hash}

    def test_put_refuses_unknown_questions(self, tmp_pub_dir):
        make_project(tmp_pub_dir)
        reg = registry()
        store = AnswersStore(reg, hostname='pool1', pub_dir=str(tmp_pub_dir), owner=None)
        run(reg.tick())
        p = reg.get(RLN)
        text_hash = p.info['questions'][0]['question_hash']
        for patch in ({'x' * 64: 'a'}, {text_hash: 5}, {p.info['questions'][1]['question_hash']: 'not json'}):
            with pytest.raises(AccessError) as e:
                run(store.put(p, patch, ALICE))
            assert e.value.status == 400

    def test_cheat_is_consumed_at_the_tick(self, tmp_pub_dir):
        path = make_project(tmp_pub_dir)
        reg = registry()
        store = AnswersStore(reg, hostname='pool1', pub_dir=str(tmp_pub_dir), owner=None)
        run(reg.tick())
        p = reg.get(RLN)
        text_hash = p.info['questions'][0]['question_hash']
        run(store.put(p, {text_hash: 'mine'}, ALICE))
        events = []
        reg.subscribe(p, lambda e: _collect(events, e), ALICE)
        cheat = path / params.answer_dir_name / 'cheat.json'
        cheat.write_text(json.dumps({text_hash: '42'}))
        run(reg.tick())
        assert not cheat.exists()
        assert events == [{'t': EVENT_ANSWERS, 'answers': {text_hash: '42'}}]
        assert store.read(p)[text_hash] == '42' and store.read(p)[params.login_keyword] == 'alice'


class TestSchedulers:
    def test_periodic_eval(self, tmp_pub_dir):
        make_project(tmp_pub_dir, eval_interval_without_exam_mode=1)
        reg = registry()
        runner = FakeRunner()
        sched = Schedulers(reg, runner, exam_mode=lambda: False)

        async def go():
            await reg.tick()
            p = reg.get(RLN)
            assert p.next_eval_at is not None
            p.next_eval_at = time.monotonic() - 1
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == [('alice', ['eval', RLN])]
            # a locked project is skipped, not queued
            p.next_eval_at = time.monotonic() - 1
            async with p.lock:
                await reg.tick()
            await asyncio.sleep(0.05)
            assert len(runner.calls) == 1
            # interval set to 0: disarmed
            p.info['eval_interval_without_exam_mode'] = 0
            sched.arm(p)
            assert p.next_eval_at is None
        run(go())

    def test_no_eval_in_exam_mode(self, tmp_pub_dir):
        make_project(tmp_pub_dir, eval_interval_without_exam_mode=1)
        reg = registry()
        runner = FakeRunner()
        Schedulers(reg, runner, exam_mode=lambda: True)

        async def go():
            await reg.tick()
            reg.get(RLN).next_eval_at = time.monotonic() - 1
            await reg.tick()
            await asyncio.sleep(0.05)
        run(go())
        assert runner.calls == []

    def test_close_project_evaluates_first(self, tmp_pub_dir):
        make_project(tmp_pub_dir, eval_before_exit=True)
        reg = registry()
        runner = FakeRunner()
        sched = Schedulers(reg, runner, exam_mode=lambda: False)
        run(reg.tick())
        run(sched.close_project(reg.get(RLN)))
        assert runner.calls == [('alice', ['eval', RLN]), ('alice', ['stop', RLN])]

    def test_close_project_failed_stop(self, tmp_pub_dir):
        make_project(tmp_pub_dir)
        reg = registry()
        runner = FakeRunner(fail={'stop'})
        sched = Schedulers(reg, runner, exam_mode=lambda: False)
        run(reg.tick())
        from sreweb.agent.runner import CommandError
        with pytest.raises(CommandError):
            run(sched.close_project(reg.get(RLN)))
        assert reg.get(RLN).closing is False

    def test_idle_reaper(self, tmp_pub_dir):
        make_project(tmp_pub_dir)
        reg = registry()
        runner = FakeRunner()
        Schedulers(reg, runner, exam_mode=lambda: False, default_idle_timeout=10)

        async def go():
            await reg.tick()
            p = reg.get(RLN)
            p.last_activity = time.monotonic() - 20
            p.terminals['pc1'] = [object()]      # an open terminal keeps it alive
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == []
            p.terminals.clear()
            p.idle_timeout = 0                    # never, for this project
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == []
            p.idle_timeout = None
            await reg.tick()
            await asyncio.sleep(0.05)
            assert runner.calls == [('alice', ['stop', RLN])]
        run(go())


class TestProjectView:
    def test_student_view(self):
        view = projectview.sanitise(make_info(), ALICE)
        assert view['title'] == 'Le DHCP' and view['lab_name'] == 'sre/dhcp.py'
        assert [m['name'] for m in view['machines']] == ['pc1', 'srv']
        assert view['machines'][0]['x11_host'] is False and 'lab_hash' not in view
        assert view['display'] == {'available': False} and 'display' not in view['tabs']
        assert view['machines'][0]['ports_text'] == '8080 -> 80 (tcp)'
        assert view['terminal_devices'] == [
            {'name': 'pc1', 'kind': 'machine', 'allow_connection': True, 'hidden': False},
            {'name': 'srv', 'kind': 'machine', 'allow_connection': False, 'hidden': False},
            {'name': 'lan', 'kind': 'switch', 'allow_connection': True, 'hidden': False}]
        assert '<h1>Bonjour</h1>' in view['informations_html'] and 'secret' not in view['informations_html']
        assert [q['title'] for q in view['questions']] == ['Pourquoi ?', 'Form']
        assert view['questions'][1]['chunks'][1] == {'type': 'field', 'name': 'ip', 'kind': 'line', 'options': [],
                                                     'lines': None, 'regex': '[0-9.]+', 'default': False, 'label': ''}
        assert view['states'] == [{'name': 'final', 'label': 'La solution', 'admin_only': False}]
        assert view['tabs'] == ['schema', 'informations', 'machines', 'networks', 'questions', 'evaluation',
                                'terminals', 'apply_config']
        assert view['instructor_view'] is False and view['has_instructor_texts'] is False
        assert view['languages'] == ['en', 'fr']

    def test_english_fallback_and_exam(self):
        view = projectview.sanitise(make_info(), Identity(login='alice', language='de'), exam_mode=True)
        assert view['title'] == 'Le DHCP'          # the default language of the lab before English
        assert 'evaluation' not in view['tabs'] and 'apply_config' not in view['tabs']

    def test_instructor_view_of_an_instructor_project(self):
        info = make_info(instructor_mode=True)
        view = projectview.sanitise(info, Identity(login='prof', role='instructor', view='instructor', language='en'))
        assert 'secret' in view['informations_html'] and view['instructor_view'] is True
        assert [s['name'] for s in view['states']] == ['final', 'fault'] and view['states'][1]['admin_only']
        assert 'log' in view['tabs']
        # the view is refused on a plain project, even for an instructor
        plain = projectview.sanitise(make_info(), Identity(login='prof', role='instructor', view='instructor'))
        assert 'secret' not in plain['informations_html'] and plain['instructor_view'] is False
        # hidden machines: shown to instructors, never to students
        assert [m['name'] for m in projectview.sanitise(info, PROF)['machines']] == ['pc1', 'srv', 'probe']

    def test_schema_svg(self):
        import shutil
        if not shutil.which('neato'):
            pytest.skip('graphviz not installed')
        info = make_info(debug_project=True)
        svg = projectview.schema_svg(info, ALICE, {'curved': '1', 'sep': '4', 'icons': '0'})
        assert '<svg' in svg and 'pc1' in svg and 'probe' not in svg
        full = projectview.schema_svg(info, PROF, {'hidden': '1'})
        assert 'probe' in full
        with pytest.raises(ValueError):
            projectview.schema_svg(info, ALICE, {'order': 'random'})


class TestDisplayView:
    def test_display_needs_the_host_and_a_visible_x11_machine(self):
        info = make_info()
        info['machines'][0]['x11_host'] = True
        view = projectview.sanitise(info, ALICE, display_enabled=True)
        assert view['display'] == {'available': True} and view['machines'][0]['x11_host'] is True
        assert view['tabs'].index('display') == view['tabs'].index('terminals') + 1
        # the host runs no display, or the lab has no x11 machine, or only a hidden one
        assert projectview.sanitise(info, ALICE)['display'] == {'available': False}
        assert projectview.sanitise(make_info(), ALICE, display_enabled=True)['display'] == {'available': False}
        hidden = make_info()
        hidden['machines'][2]['x11_host'] = True
        for identity in (ALICE, PROF):
            view = projectview.sanitise(hidden, identity, display_enabled=True)
            assert view['display'] == {'available': False} and 'display' not in view['tabs']

    def test_state_file_keeps_the_display(self, tmp_pub_dir):
        make_project(tmp_pub_dir)
        reg = registry()
        run(reg.tick())
        p = reg.get(RLN)
        assert p.display is None and p.display_clients == []
        p.display = {'number': 12, 'cookie': 'ab' * 16}
        reg.write_state(p, force=True)
        state = json.loads((tmp_pub_dir / 'web-agent' / f'{RLN}.json').read_text())
        assert state['display'] == {'number': 12, 'cookie': 'ab' * 16}
        reg2 = registry()
        run(reg2.tick())
        assert reg2.get(RLN).display == {'number': 12, 'cookie': 'ab' * 16}
        # a malformed entry is ignored
        for bad in ({'number': '12', 'cookie': 'ab' * 16}, {'number': 12, 'cookie': 'xyz'}, {'number': True, 'cookie': 'ab'}, 12):
            state['display'] = bad
            (tmp_pub_dir / 'web-agent' / f'{RLN}.json').write_text(json.dumps(state))
            reg3 = registry()
            run(reg3.tick())
            assert reg3.get(RLN).display is None, bad

    def test_removed_hooks(self, tmp_pub_dir):
        async def go():
            path = make_project(tmp_pub_dir)
            reg = registry()
            seen = []

            async def hook(project):
                seen.append(project.rln)

            reg.on_removed.append(hook)
            await reg.tick()
            assert seen == []
            import shutil
            shutil.rmtree(path)
            await reg.tick()
            assert seen == [RLN]
            make_project(tmp_pub_dir)
            await reg.tick()
            await reg.stop()
            assert seen == [RLN, RLN]
        run(go())
