"""A host with two container engines: each project is created with one, records it, and every
later command asks the engine of its project.

The two engines of these tests are the stubbed Kathara engine of the unit tests under two
names (`Named`): what is checked is which one each command asks, not what an engine does.
"""
import datetime
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from SRE import engine as engine_package
from SRE import origin, params
from SRE.command import eval as eval_cmd
from SRE.command import start as start_cmd
from SRE.command import status
from SRE.command.eval import do_eval
from SRE.command.eval_all import action_eval_all
from SRE.command.start import do_action_start
from SRE.command.stop import stop_running_lab
from SRE.command.stop_all import action_stop_all
from SRE.engine.kathara_engine import KatharaEngine
from SRE.lib_sre import Grade0
from test_functional import (  # noqa: F401  (functional_env: a fixture)
    _LAB_PATH, _fake_run_tests_on_machine, _read_archive, functional_env)

KATHARA, PODMAN = params.container_engine_kathara, params.container_engine_podman


class Named(KatharaEngine):
    """The stubbed Kathara engine under the name of an engine: it notes what it is asked."""

    def __init__(self, name, calls, needs_root):
        super().__init__()
        self.name, self.calls, self._needs_root = name, calls, needs_root

    needs_root = property(lambda self: self._needs_root)

    def _noted(method):     # noqa: N805
        def call(self, *args, **kwargs):
            self.calls.append((self.name, method))
            return getattr(KatharaEngine, method)(self, *args, **kwargs)
        return call

    deploy = _noted('deploy')
    undeploy = _noted('undeploy')
    remove_leftovers = _noted('remove_leftovers')
    get_lab = _noted('get_lab')
    capture_root_privileges = _noted('capture_root_privileges')


@pytest.fixture
def engines(functional_env, monkeypatch, mock_sre_args):
    """A host whose default engine is Podman and which also allows Kathara; `engines.calls` is
    what each engine was asked, `engines.host(...)` changes the parameters of the host."""
    calls = []
    monkeypatch.setattr(engine_package, '_engines', {KATHARA: Named(KATHARA, calls, True),
                                                     PODMAN: Named(PODMAN, calls, False)})
    mock_sre_args.debug_project = False     # a child mock would make every project a debug one

    class Host:
        def host(self, default=PODMAN, allowed=(PODMAN, KATHARA)):
            monkeypatch.setattr(params, 'container_engine', default)
            monkeypatch.setattr(params, 'container_engines_allowed', allowed)

        def asked(self, method):
            return [name for name, asked in calls if asked == method]

    host = Host()
    host.calls = calls
    host.host()
    return host


def _start(**kwargs) -> str:
    """Start the test lab and return the name of the new project.  Two projects of one lab
    started in the same second would have one name: the clock of the name is moved."""
    before = set(os.listdir(params.sre_projects_dir)) if os.path.isdir(params.sre_projects_dir) else set()
    name_of = params.get_running_lab_name

    def later(lab_name, instance_start_date):
        return name_of(lab_name=lab_name,
                       instance_start_date=instance_start_date + datetime.timedelta(seconds=len(before)))
    with patch.object(params, 'get_running_lab_name', later):
        do_action_start(lab_cli_arg=str(kwargs.pop('lab', _LAB_PATH)), lab_cli_arg_is_path=True, **kwargs)
    (name,) = set(os.listdir(params.sre_projects_dir)) - before
    return name


def _recorded(running_lab_name):
    return origin.recorded_engine(params.origin_filename(running_lab_name))


def _info(running_lab_name) -> dict:
    return json.loads(Path(params.info_filename(running_lab_name)).read_text())


def _eval(running_lab_name) -> dict:
    """Evaluate the project and return its newest archive."""
    with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
        do_eval(running_lab_name=running_lab_name, print_result=False)
    archives = sorted(Path(params.archive_dirs[0]).iterdir(), key=lambda path: path.stat().st_mtime)
    return _read_archive(archives[-1])


def _lab_accepting(tmp_path, monkeypatch, engines_text: str) -> Path:
    """A copy of the test lab that says which engines it accepts."""
    lab = tmp_path / 'restricted_lab.py'
    lab.write_text(_LAB_PATH.read_text() + f"\ncontainer_engines = {engines_text}\n")
    monkeypatch.setattr(params, 'authorized_src_dir', [str(tmp_path)])
    return lab


class TestTheEngineOfANewProject:
    def test_the_default_engine_of_the_host(self, engines):
        project = _start()
        assert _recorded(project) == PODMAN and engines.asked('deploy') == [PODMAN]

    def test_the_engine_a_privileged_caller_asks_for(self, engines):
        project = _start(engine=KATHARA)
        assert _recorded(project) == KATHARA and engines.asked('deploy') == [KATHARA]

    def test_a_host_with_one_engine_records_it_too(self, engines):
        """So that the project keeps its engine if the host is given another default later."""
        engines.host(default=KATHARA, allowed=None)
        assert _recorded(_start()) == KATHARA

    def test_a_lab_that_does_not_accept_the_default_engine(self, engines, tmp_path, monkeypatch):
        project = _start(lab=_lab_accepting(tmp_path, monkeypatch, '("kathara",)'))
        assert _recorded(project) == KATHARA and engines.asked('deploy') == [KATHARA]

    def test_no_engine_for_the_lab_on_this_host(self, engines, tmp_path, monkeypatch, capsys):
        engines.host(default=PODMAN, allowed=None)
        lab = _lab_accepting(tmp_path, monkeypatch, '("kathara",)')
        with pytest.raises(SystemExit):
            _start(lab=lab)
        assert "this lab accepts only kathara; this host allows only podman" in capsys.readouterr().err
        assert engines.calls == [] and not os.path.exists(params.sre_projects_dir)

    def test_a_student_is_not_told_the_engines(self, engines, tmp_path, monkeypatch, capsys, mock_sre_args):
        engines.host(default=PODMAN, allowed=None)
        lab = _lab_accepting(tmp_path, monkeypatch, '("kathara",)')
        mock_sre_args.user = True
        with pytest.raises(SystemExit):
            start_cmd.engine_of_new_project(start_cmd.set_lab_dir_and_import_module(
                start_projet=True, lab_cli_arg=None, path=lab)[0])
        error = capsys.readouterr().err
        assert "this lab cannot be started on this host" in error
        assert 'kathara' not in error and 'podman' not in error

    def test_an_engine_the_host_does_not_allow(self, engines, capsys):
        engines.host(default=PODMAN, allowed=None)
        with pytest.raises(SystemExit):
            _start(engine=KATHARA)
        assert "this host does not allow the engine kathara (it allows: podman)" in capsys.readouterr().err
        assert engines.calls == []

    def test_an_engine_the_lab_does_not_accept(self, engines, tmp_path, monkeypatch, capsys):
        lab = _lab_accepting(tmp_path, monkeypatch, '["kathara"]')
        with pytest.raises(SystemExit):
            _start(lab=lab, engine=PODMAN)
        assert "this lab does not accept the engine podman (it accepts: kathara)" in capsys.readouterr().err

    def test_a_lab_whose_attribute_is_not_a_list_of_engines(self, engines, tmp_path, monkeypatch, capsys):
        lab = _lab_accepting(tmp_path, monkeypatch, '"kathara"')
        with pytest.raises(SystemExit):
            _start(lab=lab)
        assert "container_engines = 'kathara': a list of container engines is expected" in capsys.readouterr().err

    def test_the_option_is_for_privileged_callers(self, engines, mock_sre_args, capsys):
        mock_sre_args.engine = KATHARA
        assert start_cmd.requested_engine() == KATHARA
        mock_sre_args.user = True
        with pytest.raises(SystemExit):
            start_cmd.requested_engine()
        assert "--engine is not available in user mode" in capsys.readouterr().err

    def test_no_option_is_no_engine_asked(self, engines, mock_sre_args):
        mock_sre_args.user = True
        assert start_cmd.requested_engine() is None


class TestEveryCommandAsksTheEngineOfItsProject:
    def test_stop(self, engines):
        with_podman, with_kathara = _start(), _start(engine=KATHARA)
        del engines.calls[:]
        assert stop_running_lab(running_lab_name=with_kathara, multi_project=True) == []
        assert set(engines.asked('undeploy')) == {KATHARA} and set(engines.asked('remove_leftovers')) == {KATHARA}
        del engines.calls[:]
        assert stop_running_lab(running_lab_name=with_podman, multi_project=True) == []
        assert set(engines.asked('undeploy')) == {PODMAN} and set(engines.asked('remove_leftovers')) == {PODMAN}
        assert os.listdir(params.sre_projects_dir) == []

    def test_stop_all(self, engines):
        _start(), _start(engine=KATHARA)
        del engines.calls[:]
        action_stop_all()
        assert set(engines.asked('undeploy')) == {PODMAN, KATHARA}
        assert os.listdir(params.sre_projects_dir) == []

    def test_a_project_keeps_its_engine_when_the_host_changes_its_mind(self, engines):
        """The host no longer allows the engine of a running project, and has another default:
        the project is still evaluated and stopped by the engine that runs it."""
        project = _start()
        engines.host(default=KATHARA, allowed=None)
        del engines.calls[:]
        assert _eval(project)[params.archive_engine_keyword] == PODMAN
        assert set(engines.asked('get_lab')) == {PODMAN}
        stop_running_lab(running_lab_name=project, multi_project=True)
        assert set(engines.asked('undeploy')) == {PODMAN}

    def test_a_project_of_before_has_the_default_engine_of_the_host(self, engines):
        project = _start()
        record = Path(params.origin_filename(project))
        content = json.loads(record.read_text())
        del content[params.origin_engine_keyword]
        record.write_text(json.dumps(content))
        engines.host(default=KATHARA, allowed=None)
        del engines.calls[:]
        stop_running_lab(running_lab_name=project, multi_project=True)
        assert set(engines.asked('undeploy')) == {KATHARA}

    def test_status(self, engines):
        with_podman, with_kathara = _start(), _start(engine=KATHARA)
        assert status.project_rows() == [(params.origin_local, 'testuser', PODMAN, with_podman),
                                         (params.origin_local, 'testuser', KATHARA, with_kathara)]


class TestWhatIsToldOfTheEngine:
    def test_the_archive_of_an_evaluation(self, engines):
        assert _eval(_start())[params.archive_engine_keyword] == PODMAN
        assert _eval(_start(engine=KATHARA))[params.archive_engine_keyword] == KATHARA

    def test_info_json_does_not_tell_a_student(self, engines):
        """info.json is what the interface of the student reads."""
        project = _start(engine=KATHARA)
        assert _info(project)['container_engine'] == ''
        _eval(project)
        assert _info(project)['container_engine'] == ''

    def test_info_json_of_a_debug_project_does(self, engines, mock_sre_args):
        mock_sre_args.debug_project = True
        project = _start(engine=KATHARA)
        assert _info(project)['debug_project'] is True and _info(project)['container_engine'] == KATHARA


    def test_the_log_of_a_debug_project_starts_with_it(self, engines, mock_sre_args):
        """The Log tab of both interfaces: the first lines of a debug project."""
        mock_sre_args.debug_project = True
        project = _start(engine=KATHARA)
        lines = Path(params.operations_log_filename(project)).read_text().splitlines()
        assert lines[0].endswith("state initial") and lines[1] == "container engine: kathara"
        _eval(project)
        assert Path(params.operations_log_filename(project)).read_text().count("container engine:") == 1

    def test_no_log_says_it_for_another_project(self, engines, mock_sre_args):
        """An instructor-mode project has a log too, and students may be shown it."""
        project = _start(engine=KATHARA, instructor_mode=True)
        log = Path(params.operations_log_filename(project))
        assert log.exists() and "container engine" not in log.read_text()


class TestSeveralProjectsEvaluatedInOneProcess:
    def test_the_projects_of_an_engine_that_needs_root_come_first(self, engines):
        first, second, third = _start(), _start(engine=KATHARA), _start()
        assert eval_cmd.evaluation_groups([first, second, third]) == [[second], [first, third]]

    def test_one_group_on_a_host_with_one_engine(self, engines):
        engines.host(default=KATHARA, allowed=None)
        first, second = _start(), _start()
        assert eval_cmd.evaluation_groups([first, second]) == [[first, second]]
        assert eval_cmd.evaluation_groups([]) == []

    def test_a_project_whose_engine_cannot_be_told_is_left_to_its_own_evaluation(self, engines, monkeypatch):
        project = _start()
        Path(params.origin_filename(project)).unlink()
        monkeypatch.setattr(params, 'container_engine', 'lxc')
        assert eval_cmd.evaluation_groups([project]) == [[project]]

    def test_eval_all_never_mixes_the_two_groups(self, engines, mock_sre_args, monkeypatch):
        """`eval-all` evaluates in threads and the uids are those of the process: no project of
        the engine that needs no root starts while one of the other engine is evaluated."""
        with_podman, with_kathara, other_podman = _start(), _start(engine=KATHARA), _start()
        running, order = set(), []

        def evaluation(running_lab_name, multiples_evals=False, print_result=False):
            engine = engine_package.engine_name_of_project(running_lab_name)
            assert not (engine == PODMAN and KATHARA in running), "a Podman project evaluated beside a Kathara one"
            running.add(engine)
            order.append(running_lab_name)
            running.discard(engine)

        from SRE.command import eval_all
        monkeypatch.setattr(eval_all, 'do_eval', evaluation)
        mock_sre_args.display_grades = False
        action_eval_all()
        assert order[0] == with_kathara and set(order[1:]) == {with_podman, other_podman}
