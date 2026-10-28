"""Tests of ``tests/mock_sre.py``, the mock of the ``sre`` CLI used by the offline tests of the web
agent: every subcommand is run as a subprocess (``<python> tests/mock_sre.py --user ...``) with a
temporary ``SRE_PUB_DIR``, the way the agent spawns ``sre``.  ``connect`` on a machine is driven
through a pty.  No Docker, no Kathara, no root."""
import fcntl
import importlib.util
import json
import os
import pty
import re
import select
import stat
import subprocess
import sys
import termios
import time
import zipfile
from base64 import b64decode
from io import BytesIO
from pathlib import Path

import pytest

from SRE import params
from SRE.archive_summary import read_archive
from SRE.common import InfoLab, QuestionType

MOCK = Path(__file__).resolve().parent / 'mock_sre.py'
STUDENT = 'dupont'
INSTRUCTOR = 'instructor'
USER_ENV = {'LOGNAME': 'root', 'SUDO_USER': STUDENT, 'USER_USERNAME': STUDENT}
PRIVILEGED_ENV = {'LOGNAME': INSTRUCTOR}
# the student path (--user) on a project started with PRIVILEGED_ENV, i.e. by its owner: another
# user's project is refused in user mode (params.check_project_owner)
AS_OWNER = {'SUDO_USER': INSTRUCTOR, 'USER_USERNAME': INSTRUCTOR}
FIRST_LAB = 'sre/dhcp.py'
PATH_LAB = '/labs/x/dhcp.py'     # --debug-project makes the lab argument a path (like start.py)

EXPECTED_START_EVENTS = [('pull', 'start'), ('pull', 'downloading'), ('pull', 'end'), ('deploy', 'start'),
                         ('deploy', 'progress'), ('deploy', 'progress'), ('deploy', 'progress'),
                         ('deploy', 'end'), ('project', 'created')]


def _env(pub, user, extra=None):
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(pub), 'TERM': 'xterm',
           'SRE_PUB_DIR': str(pub)}
    env.update(USER_ENV if user else PRIVILEGED_ENV)
    if extra:
        env.update(extra)
    return env


def _argv(*args, user=True):
    return [sys.executable, '-W', 'ignore', str(MOCK)] + (['--user'] if user else []) + list(args)


def run_mock(pub, *args, user=True, extra_env=None, input=None, stdin=None, timeout=60):
    feed = {'input': input} if input is not None else {'stdin': stdin if stdin is not None else subprocess.DEVNULL}
    return subprocess.run(_argv(*args, user=user), capture_output=True, timeout=timeout,
                          env=_env(pub, user, extra_env), **feed)


def events(completed) -> list:
    """The JSON events of stderr, in order (the other lines are left out)."""
    result = []
    for line in completed.stderr.decode().splitlines():
        try:
            result.append(json.loads(line))
        except ValueError:
            pass
    return result


def phases(completed) -> list:
    return [(e.get('phase'), e.get('status')) for e in events(completed)]


def start_project(pub, *args, user=True, extra_env=None) -> str:
    completed = run_mock(pub, 'start', *args, user=user, extra_env=extra_env)
    assert completed.returncode == 0, completed.stderr.decode()
    created = [e for e in events(completed) if e.get('phase') == 'project']
    assert len(created) == 1
    return created[0]['running_lab_name']


def project_dir(pub, running_lab_name) -> Path:
    return pub / 'projects' / running_lab_name


def info_of(pub, running_lab_name) -> dict:
    return json.loads((project_dir(pub, running_lab_name) / params.info_json_name).read_text())


def question_hashes(pub, running_lab_name) -> dict:
    """``{question_type: hash}`` of the questions of a project."""
    return {q['question_type']: q['question_hash'] for q in info_of(pub, running_lab_name)['questions']}


@pytest.fixture
def pub(tmp_path):
    d = tmp_path / 'pub'
    d.mkdir()
    return d


@pytest.fixture
def project(pub):
    return start_project(pub, FIRST_LAB)


# ---------------------------------------------------------------------------------------------
# entry checks
# ---------------------------------------------------------------------------------------------

class TestEntry:
    def test_unknown_subcommand_exits_2_like_argparse(self, pub):
        completed = run_mock(pub, 'bogus')
        assert completed.returncode == 2
        assert b'invalid choice' in completed.stderr

    def test_no_subcommand_prints_the_help_and_exits_1(self, pub):
        completed = run_mock(pub)
        assert completed.returncode == 1
        assert b'usage:' in completed.stdout

    def test_version(self, pub):
        completed = run_mock(pub, '--version')
        assert completed.returncode == 0
        assert completed.stdout.decode().strip() == params.sre_version

    def test_user_and_debug_are_mutually_exclusive(self, pub):
        completed = subprocess.run(_argv('--debug', 'list'), capture_output=True, env=_env(pub, True))
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == 'sre: --user and --debug are mutually exclusive'

    def test_username_comes_from_sudo_user_in_user_mode(self, pub):
        env = _env(pub, True)
        del env['SUDO_USER']   # USER_USERNAME alone is not enough (params.use_sudo_user_for_username)
        completed = subprocess.run(_argv('list'), capture_output=True, env=env)
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == "sre: invalid username: ''"

    def test_username_comes_from_logname_in_privileged_mode(self, pub):
        env = _env(pub, False)
        env['LOGNAME'] = 'not valid!'
        completed = subprocess.run(_argv('list', user=False), capture_output=True, env=env)
        assert completed.returncode == 1
        assert b"invalid username: 'not valid!'" in completed.stderr

    def test_sre_pub_dir_is_required(self, pub):
        env = _env(pub, True)
        del env['SRE_PUB_DIR']
        completed = subprocess.run(_argv('list'), capture_output=True, env=env)
        assert completed.returncode == 1
        assert b'SRE_PUB_DIR' in completed.stderr

    def test_mock_fail_makes_one_subcommand_fail(self, pub, project):
        completed = run_mock(pub, 'stop', project, extra_env={'MOCK_FAIL': 'stop'})
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == 'sre: mock failure'
        assert project_dir(pub, project).is_dir()
        assert run_mock(pub, 'list', extra_env={'MOCK_FAIL': 'stop'}).returncode == 0

    def test_exam_mode_refuses_user_mode_commands(self, pub):
        (pub / params.exam_json_name).write_text('{}')
        completed = run_mock(pub, 'list')
        assert completed.returncode == 1
        assert b'exam mode' in completed.stderr
        assert run_mock(pub, 'list', user=False).returncode == 0

    def test_invocation_log(self, pub):
        log = pub / 'calls.log'
        run_mock(pub, 'list', '--with-titles', extra_env={'MOCK_SRE_LOG': str(log)})
        run_mock(pub, 'bogus', extra_env={'MOCK_SRE_LOG': str(log), 'SRE_IN_RECORDER': '1'})
        lines = [json.loads(line) for line in log.read_text().splitlines()]
        assert [entry['argv'] for entry in lines] == [['--user', 'list', '--with-titles'], ['--user', 'bogus']]
        assert lines[0]['env'] == {'SUDO_USER': STUDENT, 'USER_USERNAME': STUDENT, 'LOGNAME': 'root',
                                   'TERM': 'xterm'}
        assert 'SUDO_COMMAND' not in lines[0]['env']
        assert lines[1]['env']['SRE_IN_RECORDER'] == '1'
        assert (lines[0]['username'], lines[0]['user_mode']) == (STUDENT, True)
        run_mock(pub, 'list', user=False, extra_env={'MOCK_SRE_LOG': str(log)})
        last = json.loads(log.read_text().splitlines()[-1])
        assert (last['username'], last['user_mode']) == (last['env']['LOGNAME'], False)

    def test_main_function_in_process(self, pub, capsys):
        spec = importlib.util.spec_from_file_location('mock_sre_module', MOCK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        before = params.sre_pub_dir, params.sre_projects_dir
        env = {'SRE_PUB_DIR': str(pub), 'LOGNAME': 'root'}
        assert module.main(['list'], env) == 0
        assert json.loads(capsys.readouterr().out) == module.DEFAULT_LAB_LIST
        assert module.main(['bogus'], env) == 2
        assert module.main(['--user', 'list'], env) == 1   # no SUDO_USER
        assert 'invalid username' in capsys.readouterr().err
        assert (params.sre_pub_dir, params.sre_projects_dir) == before   # the patched paths are restored


# ---------------------------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------------------------

class TestList:
    def test_default_labs(self, pub):
        completed = run_mock(pub, 'list')
        assert completed.returncode == 0
        assert json.loads(completed.stdout) == ['sre/dhcp.py', 's4/tp_ssh']
        assert completed.stderr == b''

    def test_with_titles(self, pub):
        completed = run_mock(pub, 'list', '--with-titles')
        assert json.loads(completed.stdout) == [
            {'name': 'sre/dhcp.py', 'title': {'en': 'DHCP lab', 'fr': 'TP DHCP'}},
            {'name': 's4/tp_ssh', 'title': None},
        ]

    def test_mock_lab_list(self, pub):
        labs = ['a/b.py', 'c', 'd/e']
        completed = run_mock(pub, 'list', '--with-titles', extra_env={'MOCK_LAB_LIST': json.dumps(labs)})
        data = json.loads(completed.stdout)
        assert [entry['name'] for entry in data] == labs
        assert data[0]['title'] == {'en': 'DHCP lab', 'fr': 'TP DHCP'}
        assert [entry['title'] for entry in data[1:]] == [None, None]


# ---------------------------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------------------------

class TestStart:
    def test_events_stdout_and_exit_code(self, pub):
        completed = run_mock(pub, 'start', FIRST_LAB)
        assert completed.returncode == 0
        assert completed.stdout == b''
        assert phases(completed) == EXPECTED_START_EVENTS
        evs = events(completed)
        assert evs[1]['overall_percent'] == 50
        assert evs[3]['total'] == 3
        assert [e['current'] for e in evs[4:7]] == [1, 2, 3]
        assert all('machine' not in e for e in evs[4:7])   # user mode: no machine names
        assert re.fullmatch(params.running_lab_name_match_pattern, evs[-1]['running_lab_name'])

    def test_privileged_start_names_the_machines(self, pub):
        completed = run_mock(pub, 'start', FIRST_LAB, user=False)
        assert completed.returncode == 0
        assert [e['machine'] for e in events(completed) if e.get('status') == 'progress'] == ['m1', 'm2', 'probe']
        assert params.get_username_from_running_lab_name(events(completed)[-1]['running_lab_name']) == INSTRUCTOR

    def test_project_layout(self, pub, project):
        assert params.get_lab_name_from_running_lab_name(project) == 'sre@dhcp.py'
        assert params.get_username_from_running_lab_name(project) == STUDENT
        d = project_dir(pub, project)
        assert (d / params.info_json_name).is_file()
        assert stat.S_IMODE((d / params.answer_dir_name).stat().st_mode) == 0o777
        assert stat.S_IMODE((d / params.private_dir_name).stat().st_mode) == 0o700
        assert (d / params.private_dir_name / params.files_dir_name).is_dir()
        assert not (d / params.private_dir_name / params.debug_project_marker_name).exists()
        assert not (d / params.private_dir_name / params.instructor_mode_marker_name).exists()
        assert not (d / params.private_dir_name / 'flavor.json').exists()
        link = d / params.private_dir_name / params.user_public_dir_name
        assert link.is_symlink() and link.resolve() == (pub / 'home' / 'dhcp').resolve()

    def test_info_json_is_a_complete_info_lab(self, pub, project):
        text = (project_dir(pub, project) / params.info_json_name).read_text()
        info = InfoLab.from_json(text)   # every key of a real info.json, the real classes read it back
        raw = json.loads(text)
        assert set(raw) >= {'lab_name', 'lab_hash', 'title', 'informations', 'export_kathara_project',
                            'allow_self_grade', 'machines', 'questions', 'delay_between_self_grade',
                            'eval_interval_without_exam_mode', 'eval_before_exit', 'user_allowed_states',
                            'debug_project', 'instructor_mode', 'allow_save_restore', 'export_schema_pdf', 'admin_only_states',
                            'default_language', 'network_colors', 'network_shapes', 'show_nat_network',
                            'nat_network_name', 'nat_network_color', 'host_network_exploded',
                            'host_network_edge_relative_length', 'schema_splines', 'schema_overlap', 'switches'}
        assert info.lab_name == 'sre@dhcp.py'
        assert info.title == {'en': 'DHCP lab', 'fr': 'TP DHCP'}
        assert set(info.informations) == {'en', 'fr'}
        assert [(m.name, m.hidden, m.allow_connection) for m in info.machines] == [('m1', False, True),
                                                                                   ('m2', False, False)]
        # InfoLab.from_json keeps the interfaces as dicts
        assert [(i['network'], i['interface_name']) for i in info.machines[0].interfaces] == [('lan', 'eth0'), ('dmz', 'eth1')]
        assert [(s.name, s.mode, s.allow_connection) for s in info.switches] == [
            ('lan', params.network_mode_managed, True), ('dmz', params.network_mode_switch, True)]
        assert [q.question_type for q in info.questions] == [QuestionType.TEXT.value, QuestionType.FORM.value]
        assert [q.order for q in info.questions] == [100, 200]
        form = info.questions[1]
        assert '@@{ip:[0-9.]+}@@' in form.description['en'] and '@@{ok:?}@@' in form.description['fr']
        assert form.fields == [{'name': 'ip', 'regex': '[0-9.]+'}, {'name': 'ok', 'checkbox': False}]
        assert info.user_allowed_states == {'final': {'en': 'Solution', 'fr': 'Solution'}}
        assert info.admin_only_states == []
        assert (info.allow_self_grade, info.eval_interval_without_exam_mode, info.eval_before_exit,
                info.delay_between_self_grade, info.allow_save_restore, info.export_kathara_project) == (
                   True, 0, False, 5, True, True)
        assert (info.debug_project, info.instructor_mode) == (False, False)
        assert info.default_language == 'en'

    def test_title_of_the_other_labs_is_the_lab_name(self, pub):
        running_lab_name = start_project(pub, 's4/tp_ssh')
        assert info_of(pub, running_lab_name)['title'] == {'en': 's4@tp_ssh'}

    def test_unknown_lab(self, pub):
        completed = run_mock(pub, 'start', 'nowhere/lab.py')
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == "sre: lab 'nowhere/lab.py' does not exist"
        assert not (pub / 'projects').exists()

    @pytest.mark.parametrize('args, message', [
        (['-p', PATH_LAB], '--user and --path options are mutually exclusive'),
        (['--debug-project', FIRST_LAB], '--debug-project is not available in user mode'),
        (['--instructor-mode', FIRST_LAB], '--instructor-mode is not available in user mode'),
        (['--set-flavor-name', 'hard', FIRST_LAB], '--set-flavor-name is not available in user mode'),
        (['--xauth-file', '/tmp/x', FIRST_LAB], '--xauth-file is only available to privileged users'),
        ([FIRST_LAB, '2'], 'data_version argument is only available to privileged users'),
    ])
    def test_privileged_options_refused_in_user_mode(self, pub, args, message):
        completed = run_mock(pub, 'start', *args)
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == f'sre: {message}'
        assert events(completed) == []

    def test_debug_project_in_privileged_mode(self, pub):
        running_lab_name = start_project(pub, '--debug-project', PATH_LAB, user=False)
        assert params.get_lab_name_from_running_lab_name(running_lab_name) == '@labs@x@dhcp.py'
        d = project_dir(pub, running_lab_name) / params.private_dir_name
        assert (d / params.debug_project_marker_name).is_file()
        assert not (d / params.instructor_mode_marker_name).exists()
        info = info_of(pub, running_lab_name)
        assert info['debug_project'] is True and info['instructor_mode'] is False
        assert [(m['name'], m['hidden']) for m in info['machines']] == [('m1', False), ('m2', False), ('probe', True)]

    def test_instructor_mode_in_privileged_mode(self, pub):
        running_lab_name = start_project(pub, '--instructor-mode', FIRST_LAB, user=False)
        d = project_dir(pub, running_lab_name) / params.private_dir_name
        assert (d / params.instructor_mode_marker_name).is_file()
        assert not (d / params.debug_project_marker_name).exists()
        info = info_of(pub, running_lab_name)
        assert info['instructor_mode'] is True and info['debug_project'] is False
        assert [m['name'] for m in info['machines']] == ['m1', 'm2']   # hidden machines stay hidden

    def test_flavor_form_needed(self, pub):
        form = 'Clients: @@{nb:[0-9]+}@@'
        completed = run_mock(pub, 'start', FIRST_LAB, extra_env={'MOCK_FLAVOR_FORM': form})
        assert completed.returncode == params.exit_code_flavor_form_needed
        assert events(completed) == [{'phase': 'flavor_form', 'status': 'needed', 'form': form,
                                      'form_size': [640, 480]}]
        assert not (pub / 'projects').exists()

    def test_flavor_form_is_never_asked_in_privileged_mode(self, pub):
        completed = run_mock(pub, 'start', FIRST_LAB, user=False, extra_env={'MOCK_FLAVOR_FORM': 'x'})
        assert completed.returncode == 0
        assert phases(completed) == EXPECTED_START_EVENTS

    def test_flavor_refused(self, pub):
        completed = run_mock(pub, 'start', '--flavor-json', '{"nb": 9}', FIRST_LAB,
                             extra_env={'MOCK_FLAVOR_REFUSE': 'Max 5', 'MOCK_FLAVOR_FORM': 'x'})
        assert completed.returncode == params.exit_code_flavor_not_allowed
        assert events(completed) == [{'phase': 'flavor_error', 'message': 'Max 5'}]
        assert not (pub / 'projects').exists()

    def test_flavor_json_is_stored_and_skips_the_form(self, pub):
        running_lab_name = start_project(pub, '--flavor-json', '{"nb": 2, "mode": "easy"}', FIRST_LAB,
                                         extra_env={'MOCK_FLAVOR_FORM': 'x'})
        flavor_file = project_dir(pub, running_lab_name) / params.private_dir_name / 'flavor.json'
        assert json.loads(flavor_file.read_text()) == {'nb': 2, 'mode': 'easy'}

    def test_flavor_key_values(self, pub):
        # --flavor takes every following word (nargs='+', like the real parser): the lab comes first
        running_lab_name = start_project(pub, FIRST_LAB, '--flavor', 'nb:2', 'mode:easy')
        flavor_file = project_dir(pub, running_lab_name) / params.private_dir_name / 'flavor.json'
        assert json.loads(flavor_file.read_text()) == {'nb': '2', 'mode': 'easy'}

    def test_invalid_flavor_json(self, pub):
        completed = run_mock(pub, 'start', '--flavor-json', '{nb', FIRST_LAB)
        assert completed.returncode == 1
        assert b'--flavor-json' in completed.stderr

    def test_start_delay(self, pub):
        t0 = time.monotonic()
        completed = run_mock(pub, 'start', FIRST_LAB, extra_env={'MOCK_START_DELAY': '0.05'})
        assert completed.returncode == 0
        assert time.monotonic() - t0 >= 7 * 0.05
        assert phases(completed) == EXPECTED_START_EVENTS

    def test_two_instances_of_the_same_lab(self, pub):
        first = start_project(pub, FIRST_LAB)
        second = start_project(pub, FIRST_LAB)
        assert first != second
        assert project_dir(pub, first).is_dir() and project_dir(pub, second).is_dir()
        assert sorted(p.name for p in (pub / 'home').iterdir()) == ['dhcp', 'dhcp_1']


# ---------------------------------------------------------------------------------------------
# eval
# ---------------------------------------------------------------------------------------------

class TestEval:
    def test_unknown_running_lab(self, pub, project):
        for name in ('20200101000000@@@sre@dhcp.py@@@nobody', project[4:], 'dhcp'):   # no substring resolution
            completed = run_mock(pub, 'eval', '--auto-eval', name)
            assert completed.returncode == 1
            assert completed.stderr.decode().startswith('sre: unknown running lab')
        assert not (pub / 'archives').exists()

    def test_auto_eval_prints_the_grades_and_archives(self, pub, project):
        completed = run_mock(pub, 'eval', '--auto-eval', project)
        assert completed.returncode == 0
        result = json.loads(completed.stdout)
        assert result[params.running_lab_name_keyword] == project
        assert result[params.login_keyword] == STUDENT
        assert result[params.hostname_keyword]
        assert result[params.eval_date_keyword]
        grades = result['grades']
        assert [(g['title'], g['grade'], g['max_grade'], g['grade_part'], g['bonus']) for g in grades] == [
            ('Default route of m1', 2, 2, 'Routing', False),
            ('Address of m2', 1.5, 3, 'Routing', False),
            ('IPv6 route of m1', 1, 1, None, True)]
        assert set(grades[0]) == {'title', 'max_grade', 'grade', 'grade_letter', 'description', 'scope',
                                  'grade_part', 'bonus'}
        assert [p['title'] for p in result['grade_parts']] == ['Routing']
        assert result['mark'] == 18.0 and result['maximum_mark'] == params.default_maximum_mark
        assert result['delay_before_self_grade'] == 0
        archives = list((pub / 'archives').iterdir())
        assert len(archives) == 1
        assert re.fullmatch(params.archive_name_match_pattern, archives[0].name).group(2) == project
        # a real archive (zstandard + msgpack), with the keys of Grade0.save_tests_on_file
        raw = read_archive(str(archives[0]))
        assert raw[params.running_lab_name_keyword] == project
        assert raw[params.eval_date_keyword] == result[params.eval_date_keyword]
        assert raw['answers'][params.login_keyword] == STUDENT
        assert raw['answers'][params.auto_eval_count_keyword] == 1
        assert [g['title'] for g in raw['grade_list']] == [g['title'] for g in grades]
        assert (raw['total_grade_exo_eval'], raw['total_max_exo_eval'], raw['mark_exo_eval']) == (4.5, 5, 18.0)
        assert raw['errors'] == [] and raw['maximum_mark'] == params.default_maximum_mark
        assert not (project_dir(pub, project) / params.private_dir_name / params.eval_in_progress_name).exists()
        assert not (pub / 'last_self_grades').exists()   # no cooldown without MOCK_COOLDOWN

    def test_archive_errors_from_the_environment(self, pub, project):
        completed = run_mock(pub, 'eval', project, extra_env={'MOCK_EVAL_ERRORS': '[["ERROR", "m1 down"], ["WARNING", "slow"]]'})
        assert completed.returncode == 0
        raw = read_archive(str(next((pub / 'archives').iterdir())))
        assert raw['errors'] == [['ERROR', 'm1 down'], ['WARNING', 'slow']]

    def test_eval_without_auto_eval_prints_nothing_but_archives(self, pub, project):
        completed = run_mock(pub, 'eval', project)
        assert completed.returncode == 0
        assert completed.stdout == b''
        assert len(list((pub / 'archives').iterdir())) == 1

    def test_privileged_eval_prints_the_grades(self, pub, project):
        completed = run_mock(pub, 'eval', project, user=False)
        assert completed.returncode == 0
        assert json.loads(completed.stdout)['grades']

    def test_lock_file_while_evaluating(self, pub, project):
        lock = project_dir(pub, project) / params.private_dir_name / params.eval_in_progress_name
        proc = subprocess.Popen(_argv('eval', '--auto-eval', project), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, env=_env(pub, True, {'MOCK_EVAL_DELAY': '2'}))
        try:
            deadline = time.monotonic() + 10
            while not lock.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert lock.exists(), 'the lock file was never created'
            assert int(lock.read_text()) == proc.pid
            assert proc.poll() is None   # still evaluating
            out, _ = proc.communicate(timeout=30)
        finally:
            proc.kill()
        assert proc.returncode == 0
        assert json.loads(out)['grades']
        assert not lock.exists()

    def test_cooldown(self, pub, project):
        env = {'MOCK_COOLDOWN': '60'}
        first = run_mock(pub, 'eval', '--auto-eval', project, extra_env=env)
        assert first.returncode == 0
        assert json.loads(first.stdout)['delay_before_self_grade'] == 60
        ts_file = pub / 'last_self_grades' / f'sre@dhcp.py@@@{STUDENT}'
        assert ts_file.is_file()
        second = run_mock(pub, 'eval', '--auto-eval', project, extra_env=env)
        assert second.returncode == 0
        answer = json.loads(second.stdout)
        assert answer['grades'] is None
        assert 0 < answer['delay_before_self_grade'] <= 60
        assert len(list((pub / 'archives').iterdir())) == 1   # the second call did not evaluate
        # an older timestamp lets the next evaluation through
        os.utime(ts_file, (time.time() - 120, time.time() - 120))
        third = run_mock(pub, 'eval', '--auto-eval', project, extra_env=env)
        result = json.loads(third.stdout)
        assert result['grades']
        # the archive of this evaluation (same name as the first one's when both ran in the same second)
        archives = list((pub / 'archives').iterdir())
        assert result[params.eval_date_keyword] in {read_archive(str(a))[params.eval_date_keyword] for a in archives}

    def test_cooldown_is_per_lab_and_owner(self, pub, project):
        env = {'MOCK_COOLDOWN': '60'}
        run_mock(pub, 'eval', '--auto-eval', project, extra_env=env)
        other = start_project(pub, FIRST_LAB, extra_env={'SUDO_USER': 'durand', 'USER_USERNAME': 'durand'})
        completed = run_mock(pub, 'eval', '--auto-eval', other,
                             extra_env={**env, 'SUDO_USER': 'durand', 'USER_USERNAME': 'durand'})
        assert json.loads(completed.stdout)['grades']
        assert sorted(p.name for p in (pub / 'last_self_grades').iterdir()) == [
            f'sre@dhcp.py@@@{STUDENT}', 'sre@dhcp.py@@@durand']

    def test_no_cooldown_without_auto_eval_nor_in_privileged_mode(self, pub, project):
        env = {'MOCK_COOLDOWN': '60'}
        assert run_mock(pub, 'eval', project, extra_env=env).returncode == 0
        assert run_mock(pub, 'eval', '--auto-eval', project, user=False, extra_env=env).returncode == 0
        assert not (pub / 'last_self_grades').exists()


# ---------------------------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------------------------

class TestState:
    def test_final_writes_the_cheat_answers(self, pub, project):
        completed = run_mock(pub, 'state', project, 'final')
        assert completed.returncode == 0
        assert completed.stdout == b'' and completed.stderr == b''
        cheat_file = project_dir(pub, project) / params.answer_dir_name / params.cheat_file_name
        cheat = json.loads(cheat_file.read_text())
        hashes = question_hashes(pub, project)
        assert cheat == {hashes[QuestionType.TEXT.value]: '42',
                         hashes[QuestionType.FORM.value]: json.dumps({'ip': '10.0.0.1', 'ok': True})}
        umask = os.umask(0)
        os.umask(umask)
        assert stat.S_IMODE(cheat_file.stat().st_mode) == 0o666 & ~umask

    def test_question_hashes_are_those_of_the_real_classes(self, pub, project):
        hashes = question_hashes(pub, project)
        assert hashes[QuestionType.TEXT.value] == 'cfc140584d209e6d8ed82f6db72c91a210cb1f2ded6a6b66f81c17e16ac2b857'
        assert hashes[QuestionType.FORM.value] == 'e87736964454b2a575c2eb84df9bcb7440abd31fd2a722c99a0e20a8f2c3b4f2'

    def test_initial_removes_the_cheat_answers(self, pub, project):
        run_mock(pub, 'state', project, 'final')
        completed = run_mock(pub, 'state', project, params.initial_state_name)
        assert completed.returncode == 0
        assert not (project_dir(pub, project) / params.answer_dir_name / params.cheat_file_name).exists()

    def test_unknown_state(self, pub, project):
        completed = run_mock(pub, 'state', project, 'bogus')
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == "sre: unknown state 'bogus'"
        assert run_mock(pub, 'state', '20200101000000@@@x@@@y', 'final').returncode == 1

    def test_operations_log_of_a_debug_project(self, pub):
        running_lab_name = start_project(pub, '--debug-project', PATH_LAB, user=False)
        log = project_dir(pub, running_lab_name) / params.operations_log_name
        assert not log.exists()
        # user mode (the owner), debug project
        assert run_mock(pub, 'state', running_lab_name, 'final', extra_env=AS_OWNER).returncode == 0
        text = log.read_text()
        assert re.match(r'=== \d{4}-\d\d-\d\d \d\d:\d\d:\d\d  state final\n', text)
        assert 'step1 - on m1 : hostname\n    m1\n    exit code 0\n' in text
        run_mock(pub, 'eval', '--auto-eval', running_lab_name, extra_env=AS_OWNER)
        text = log.read_text()
        assert '\n\n=== ' in text and '  evaluation\n' in text
        assert 'grade - [Routing] Default route of m1 : 2 / 2\n' in text

    def test_operations_log_of_an_instructor_mode_project_holds_states_only(self, pub):
        running_lab_name = start_project(pub, '--instructor-mode', FIRST_LAB, user=False)
        log = project_dir(pub, running_lab_name) / params.operations_log_name
        run_mock(pub, 'eval', '--auto-eval', running_lab_name, extra_env=AS_OWNER)
        assert not log.exists()
        run_mock(pub, 'state', running_lab_name, 'final', extra_env=AS_OWNER)
        assert '  state final\n' in log.read_text()

    def test_no_operations_log_for_a_plain_project(self, pub, project):
        run_mock(pub, 'state', project, 'final')
        run_mock(pub, 'eval', '--auto-eval', project)
        assert not (project_dir(pub, project) / params.operations_log_name).exists()


# ---------------------------------------------------------------------------------------------
# connect
# ---------------------------------------------------------------------------------------------

class TestConnect:
    def test_machine_needs_a_tty(self, pub, project):
        completed = run_mock(pub, 'connect', project, 'm1')   # stdin is /dev/null
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == 'sre: Machine not running'

    def test_closed_machine_is_not_refused_by_sre(self, pub, project):
        # allow_connection is enforced by the GUI / the agent, not by sre
        completed = run_mock(pub, 'connect', project, 'm2')
        assert completed.stderr.decode().strip() == 'sre: Machine not running'

    @pytest.mark.parametrize('device, message', [
        ('m9', 'device m9 is unknown'),
        ('probe', 'device probe is unknown'),           # hidden machine, user mode
        ('dmz', 'device dmz is a switch: it has no console'),
    ])
    def test_unknown_devices(self, pub, project, device, message):
        completed = run_mock(pub, 'connect', project, device)
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == f'sre: {message}'

    def test_hidden_machine_is_known_in_a_debug_project(self, pub):
        running_lab_name = start_project(pub, '--debug-project', PATH_LAB, user=False)
        completed = run_mock(pub, 'connect', running_lab_name, 'probe', extra_env=AS_OWNER)
        assert completed.stderr.decode().strip() == 'sre: Machine not running'

    def test_unknown_running_lab(self, pub, project):
        completed = run_mock(pub, 'connect', 'dhcp', 'm1')
        assert completed.returncode == 1
        assert completed.stderr.decode().startswith('sre: unknown running lab')

    def test_privileged_options_refused_in_user_mode(self, pub, project):
        for args in (['--shell', '/bin/bash', project, 'm1'], ['--no-records', project, 'm1'],
                     [project, 'm1', '--exec', 'ls'], [project, 'lan', '--exec', 'help']):
            completed = run_mock(pub, 'connect', *args)
            assert completed.returncode == 1
            assert b'not allowed in user mode' in completed.stderr

    def test_privileged_exec_runs_the_command(self, pub, project):
        completed = run_mock(pub, 'connect', project, 'm1', '--exec', 'echo', 'hello', user=False)
        assert completed.returncode == 0
        assert completed.stdout == b'hello\n'

    def test_switch_console_over_pipes(self, pub, project):
        completed = run_mock(pub, 'connect', project, 'lan', input=b'help\n\nvlan/print 10\necho hi\nexit\nhelp\n')
        assert completed.returncode == 0
        out = completed.stdout.decode()
        assert out.startswith('Switch lan: management console')
        assert out.count('switch> ') == 5          # help, empty line, vlan/print, echo, exit
        assert out.count('\nok\n') + out.count(' ok\n') == 2   # help and vlan/print; echo is refused
        assert "error: command 'echo' is not allowed" in completed.stderr.decode()

    def test_switch_console_ends_at_the_end_of_input(self, pub, project):
        completed = run_mock(pub, 'connect', project, 'lan', input=b'help\n')
        assert completed.returncode == 0
        assert completed.stdout.decode().count('ok') == 1

    def test_switch_console_accepts_any_command_in_privileged_mode(self, pub, project):
        completed = run_mock(pub, 'connect', project, 'lan', user=False, input=b'port/create 7\nquit\n')
        assert completed.returncode == 0
        assert 'ok' in completed.stdout.decode()
        assert completed.stderr == b''

    @pytest.mark.skipif(not os.path.exists('/bin/sh'), reason='no /bin/sh')
    def test_machine_shell_on_a_pty(self, pub, project):
        master, slave = pty.openpty()

        def controlling_tty():
            try:
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            except OSError:
                pass

        proc = subprocess.Popen(_argv('connect', project, 'm1'), stdin=slave, stdout=slave, stderr=slave,
                                start_new_session=True, preexec_fn=controlling_tty, env=_env(pub, True))
        os.close(slave)
        output = b''
        try:
            os.write(master, b'echo hi\n')
            os.write(master, b'exit\n')
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                readable, _, _ = select.select([master], [], [], 0.2)
                if readable:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:   # EIO: the slave side is closed (Linux)
                        break
                    if not chunk:
                        break
                    output += chunk
                elif proc.poll() is not None:
                    break
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
            os.close(master)
        assert proc.returncode == 0, output
        # bash: "hi" on its own line; dash (Debian's /bin/sh): after the prompt, "mock$ hi"
        assert re.search(rb'(?:^|\$ )hi\r?$', output, re.M), output


# ---------------------------------------------------------------------------------------------
# stop, wipe
# ---------------------------------------------------------------------------------------------

class TestStop:
    def test_stop_removes_the_project_and_its_home_dir(self, pub, project):
        other = start_project(pub, FIRST_LAB)
        assert (pub / 'home' / 'dhcp').is_dir() and (pub / 'home' / 'dhcp_1').is_dir()
        completed = run_mock(pub, 'stop', project)
        assert completed.returncode == 0
        assert completed.stdout == b'' and completed.stderr == b''
        assert not project_dir(pub, project).exists()
        assert not (pub / 'home' / 'dhcp').exists()
        assert project_dir(pub, other).is_dir() and (pub / 'home' / 'dhcp_1').is_dir()

    def test_stop_unknown_running_lab(self, pub, project):
        completed = run_mock(pub, 'stop', 'dhcp')
        assert completed.returncode == 1
        assert completed.stderr.decode().startswith('sre: unknown running lab')
        assert project_dir(pub, project).is_dir()

    def test_wipe_removes_every_project(self, pub, project):
        start_project(pub, 's4/tp_ssh')
        assert run_mock(pub, 'wipe', user=False).returncode == 0
        assert list((pub / 'projects').iterdir()) == []
        assert list((pub / 'home').iterdir()) == []

    def test_wipe_is_refused_in_user_mode(self, pub, project):
        completed = run_mock(pub, 'wipe')
        assert completed.returncode == 1 and b'not allowed to run this command' in completed.stderr
        assert project_dir(pub, project).is_dir()

    def test_stop_of_another_users_project_is_refused(self, pub, project):
        """The ownership check of the real resolver (user mode; a privileged caller is not checked)."""
        completed = run_mock(pub, 'stop', project, extra_env={'SUDO_USER': 'durand', 'USER_USERNAME': 'durand'})
        assert completed.returncode == 1 and b'not allowed to access project' in completed.stderr
        assert project_dir(pub, project).is_dir()
        assert run_mock(pub, 'stop', project, user=False).returncode == 0
        assert not project_dir(pub, project).exists()

    def test_stop_all_removes_the_callers_projects(self, pub, project):
        other = start_project(pub, FIRST_LAB, extra_env={'SUDO_USER': 'durand', 'USER_USERNAME': 'durand'})
        assert run_mock(pub, 'stop-all').returncode == 0
        assert not project_dir(pub, project).exists() and project_dir(pub, other).is_dir()
        assert run_mock(pub, 'stop-all', user=False).returncode == 0
        assert list((pub / 'projects').iterdir()) == []


# ---------------------------------------------------------------------------------------------
# save, restore
# ---------------------------------------------------------------------------------------------

def _save(pub, running_lab_name, user=True) -> bytes:
    completed = run_mock(pub, 'save', running_lab_name, user=user)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


class TestSaveRestore:
    def test_save_writes_the_save_stream_to_stdout(self, pub, project):
        data = _save(pub, project)
        assert data.startswith(params.save_file_magic)
        header_line, payload = data[len(params.save_file_magic):].split(b'\n', 1)
        header = json.loads(header_line)
        assert header[params.save_meta_running_lab_name] == project
        assert header[params.save_meta_lab_name] == 'sre@dhcp.py'
        assert header[params.save_meta_username] == STUDENT
        assert header[params.save_meta_debug_project] is False
        assert header[params.save_meta_format_version] == params.save_format_version
        assert len(payload) == 1024

    def test_save_options_are_privileged(self, pub, project, tmp_path):
        assert run_mock(pub, 'save', '-o', str(tmp_path / 'x.sre'), project).returncode == 1
        assert run_mock(pub, 'save', '--full-images', project).returncode == 1
        out = tmp_path / 'p.sre'
        completed = run_mock(pub, 'save', '-o', str(out), '--full-images', project, user=False)
        assert completed.returncode == 0 and completed.stdout == b''
        assert out.read_bytes().startswith(params.save_file_magic)

    def test_save_unknown_running_lab(self, pub, project):
        assert run_mock(pub, 'save', 'dhcp').returncode == 1

    def test_restore_from_stdin_creates_a_new_project(self, pub, project):
        data = _save(pub, project)
        completed = run_mock(pub, 'restore', params.save_stdio_arg, input=data)
        assert completed.returncode == 0
        assert completed.stdout == b''   # user mode: nothing on stdout
        assert phases(completed) == EXPECTED_START_EVENTS
        new = events(completed)[-1]['running_lab_name']
        assert new != project
        assert params.get_lab_name_from_running_lab_name(new) == 'sre@dhcp.py'
        assert params.get_username_from_running_lab_name(new) == STUDENT
        assert project_dir(pub, project).is_dir() and project_dir(pub, new).is_dir()
        assert info_of(pub, new)['lab_name'] == 'sre@dhcp.py'

    def test_restore_by_another_user(self, pub, project):
        data = _save(pub, project)
        completed = run_mock(pub, 'restore', '-', input=data, extra_env={'SUDO_USER': 'durand', 'USER_USERNAME': 'durand'})
        assert completed.returncode == 0
        assert params.get_username_from_running_lab_name(events(completed)[-1]['running_lab_name']) == 'durand'

    def test_privileged_restore_prints_the_new_name(self, pub, project, tmp_path):
        save_file = tmp_path / 'p.sre'
        save_file.write_bytes(_save(pub, project))
        completed = run_mock(pub, 'restore', str(save_file), user=False)
        assert completed.returncode == 0
        new = completed.stdout.decode().strip()
        assert new == events(completed)[-1]['running_lab_name']
        assert params.get_username_from_running_lab_name(new) == INSTRUCTOR

    def test_restore_refusals_in_user_mode(self, pub, project, tmp_path):
        save_file = tmp_path / 'p.sre'
        save_file.write_bytes(_save(pub, project))
        completed = run_mock(pub, 'restore', str(save_file))
        assert completed.returncode == 1
        assert b"read from stdin (use '-')" in completed.stderr
        completed = run_mock(pub, 'restore', '--instructor-mode', '-', stdin=open(save_file, 'rb'))
        assert completed.returncode == 1
        assert b'--instructor-mode is not available in user mode' in completed.stderr
        assert len(list((pub / 'projects').iterdir())) == 1

    def test_restore_of_a_path_lab_needs_privileges(self, pub):
        debug = start_project(pub, '--debug-project', PATH_LAB, user=False)
        data = _save(pub, debug, user=False)
        assert json.loads(data[len(params.save_file_magic):].split(b'\n', 1)[0])[params.save_meta_debug_project] is True
        completed = run_mock(pub, 'restore', '-', input=data)
        assert completed.returncode == 1
        assert b'requires privileges' in completed.stderr
        completed = run_mock(pub, 'restore', '-', input=data, user=False)
        assert completed.returncode == 0
        new = completed.stdout.decode().strip()
        assert info_of(pub, new)['debug_project'] is True   # the debug flag of the save file, privileged only

    def test_restore_instructor_mode_privileged(self, pub, project):
        completed = run_mock(pub, 'restore', '--instructor-mode', '-', input=_save(pub, project), user=False)
        assert completed.returncode == 0
        new = completed.stdout.decode().strip()
        assert info_of(pub, new)['instructor_mode'] is True
        assert (project_dir(pub, new) / params.private_dir_name / params.instructor_mode_marker_name).is_file()

    def test_restore_rejects_what_is_not_a_save_file(self, pub):
        completed = run_mock(pub, 'restore', '-', input=b'garbage\n' * 10)
        assert completed.returncode == 1
        assert completed.stderr.decode().strip() == 'sre: not an SRE save file'
        truncated = run_mock(pub, 'restore', '-', input=params.save_file_magic + b'{"x": 1')
        assert truncated.returncode == 1
        assert b'truncated save file header' in truncated.stderr
        assert not (pub / 'projects').exists()

    def test_restore_of_an_unknown_lab(self, pub, project):
        data = _save(pub, project)
        completed = run_mock(pub, 'restore', '-', input=data, extra_env={'MOCK_LAB_LIST': '["other.py"]'})
        assert completed.returncode == 1
        assert b"lab 'sre/dhcp.py' does not exist" in completed.stderr


# ---------------------------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------------------------

class TestExport:
    def test_export_prints_a_base64_zip_with_lab_conf(self, pub, project):
        completed = run_mock(pub, 'export', project, '--curved', '--sep', '4', '--shapes', '--reverse',
                             '--random-seed', '7')
        assert completed.returncode == 0
        assert completed.stderr == b''
        with zipfile.ZipFile(BytesIO(b64decode(completed.stdout))) as zf:
            assert zf.namelist() == ['dhcp/lab.conf']
            lab_conf = zf.read('dhcp/lab.conf').decode()
        assert 'm1[0]="lan"' in lab_conf and 'm1[1]="dmz"' in lab_conf
        assert f'CD_MODE[lan]="{params.network_mode_managed}"' in lab_conf
        assert f'CD_MODE[dmz]="{params.network_mode_switch}"' in lab_conf

    def test_export_unknown_running_lab(self, pub, project):
        assert run_mock(pub, 'export', 'dhcp').returncode == 1


class TestX11Flag:
    def test_mock_x11_marks_the_open_machine(self, pub):
        rln = start_project(pub, FIRST_LAB, extra_env={'MOCK_X11': '1'})
        machines = {m['name']: m for m in info_of(pub, rln)['machines']}
        assert machines['m1']['x11_host'] is True and machines['m2']['x11_host'] is False
        plain = start_project(pub, FIRST_LAB)
        assert all(m['x11_host'] is False for m in info_of(pub, plain)['machines'])

    def test_x11_variables_logged(self, pub):
        log = pub / 'calls.log'
        start_project(pub, FIRST_LAB, extra_env={'MOCK_SRE_LOG': str(log), 'SRE_XAUTH_COOKIE': 'ab' * 16,
                                                 'SRE_X11_DISPLAY': '12'})
        entry = json.loads(log.read_text().splitlines()[0])
        assert entry['env']['SRE_XAUTH_COOKIE'] == 'ab' * 16 and entry['env']['SRE_X11_DISPLAY'] == '12'
