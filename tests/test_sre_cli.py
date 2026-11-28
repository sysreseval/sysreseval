"""
src/sre.py is a script: user check, argument parsing, privilege drop, then dispatch to the
action_*() of the command modules.  These tests run it in-process (runpy) for the instructor-mode
commands and options: what the parser accepts, which action is called, that the two commands on
a running project keep root available for privileged labs (the "temporary drop" list), and that
the refusals (admins, user mode) hold from the real entry point.

The effective uid, the privilege drops and the actions are replaced by recorders; nothing is
started.
"""
import importlib
import os
import re
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from SRE import params, utils_privileges

SRE_PY = Path(__file__).parent.parent / 'src' / 'sre.py'
_ACTION_IMPORT_RE = re.compile(r'^from (SRE\.command\.\w+) import (.+)$', re.MULTILINE)

SET, REMOVE = 'set-instructor-mode', 'remove-instructor-mode'
UPDATE = 'update'


@pytest.fixture
def sre_cli(monkeypatch):
    """``run(argv, uid=0, real=())`` executes src/sre.py and returns what happened: ``events`` (the
    privilege drops and the actions, in order), ``args`` (the parsed namespace seen by the
    action), ``kwargs`` (the keyword arguments of the last action called) and ``code`` (exit
    status).  The actions named in *real* are not replaced."""
    monkeypatch.setattr(params.SRE, 'username', None, raising=False)
    for name in ('SUDO_COMMAND', 'SUDO_USER', 'USER_USERNAME'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('LOGNAME', 'root')
    monkeypatch.setenv('LANGUAGE', 'en')
    # loaded by sre.py when it runs as root
    monkeypatch.setitem(sys.modules, 'Kathara.auth', MagicMock())
    monkeypatch.setitem(sys.modules, 'Kathara.auth.PrivilegeHandler', MagicMock())

    def run(argv, uid=0, real=()):
        result = SimpleNamespace(events=[], args=None, kwargs=None, code=0)
        with monkeypatch.context() as patches:
            patches.setattr(utils_privileges, 'drop_privileges_temporarily',
                            lambda: result.events.append('temporary drop'))
            patches.setattr(utils_privileges, 'drop_privileges_permanently',
                            lambda: result.events.append('permanent drop'))
            for module_name, names in _ACTION_IMPORT_RE.findall(SRE_PY.read_text()):
                module = importlib.import_module(module_name)
                for name in (n.strip() for n in names.split(',')):
                    if name in real:
                        continue

                    def recorder(*args, _name=name, **kwargs):
                        result.events.append(_name)
                        result.args = params.SRE.args
                        result.kwargs = kwargs
                    patches.setattr(module, name, recorder)
            patches.setattr(os, 'geteuid', lambda: uid)
            patches.setattr(os, 'getegid', lambda: uid)
            patches.setattr(os, 'getgroups', lambda: [uid])
            patches.setattr(sys, 'argv', ['sre', *argv])
            try:
                runpy.run_path(str(SRE_PY), run_name='__main__')
            except SystemExit as e:
                result.code = e.code
        return result

    return run


class TestParsing:
    def test_start_option(self, sre_cli):
        result = sre_cli(['start', '--instructor-mode', 'mylab'])
        assert result.code == 0 and result.events[-1] == 'action_start'
        assert result.args.instructor_mode is True and result.args.lab == 'mylab'

    def test_start_without_the_option(self, sre_cli):
        result = sre_cli(['start', 'mylab'])
        assert result.args.instructor_mode is False and result.args.debug_web_project is False

    @pytest.mark.parametrize('command', [['start', 'mylab'], ['restore', '-'], ['preload-images', 'labs']])
    def test_the_engine_option(self, sre_cli, command):
        result = sre_cli([command[0], '--engine', 'podman', *command[1:]])
        assert result.code == 0 and result.args.engine == 'podman'
        assert sre_cli(command).args.engine is None

    def test_an_engine_option_that_names_no_engine(self, sre_cli, capsys):
        result = sre_cli(['start', '--engine', 'lxc', 'mylab'])
        assert result.code == 2 and result.events == []
        assert "invalid choice: 'lxc'" in capsys.readouterr().err

    def test_start_option_does_not_imply_a_path(self, sre_cli):
        """Unlike --debug-project, the lab argument stays a lab name."""
        result = sre_cli(['start', '--instructor-mode', 'mylab'])
        assert result.args.path is False and result.args.debug_project is False

    def test_debug_web_project_option(self, sre_cli):
        """The debug project by lab name (what the web agent runs): neither --path nor
        --debug-project is implied."""
        result = sre_cli(['start', '--debug-web-project', 'mylab'])
        assert result.code == 0 and result.events[-1] == 'action_start'
        assert result.args.debug_web_project is True and result.args.lab == 'mylab'
        assert result.args.path is False and result.args.debug_project is False

    def test_restore_option(self, sre_cli):
        result = sre_cli(['restore', '--instructor-mode', '-'])
        assert result.code == 0 and result.events[-1] == 'action_restore'
        assert result.args.instructor_mode is True and result.args.save_file == '-'

    def test_restore_without_the_option(self, sre_cli):
        assert sre_cli(['restore', 'p.sre']).args.instructor_mode is False

    @pytest.mark.parametrize('command', [SET, REMOVE])
    def test_running_lab_argument(self, sre_cli, command):
        result = sre_cli([command, 'PROJECT'])
        assert result.code == 0
        assert result.args.action == command and result.args.running_lab == 'PROJECT'

    @pytest.mark.parametrize('command', [SET, REMOVE])
    def test_running_lab_is_required(self, sre_cli, capsys, command):
        result = sre_cli([command])
        assert result.code == 2 and result.events == []
        assert 'running_lab' in capsys.readouterr().err

    def test_stop_all_takes_no_argument(self, sre_cli, capsys):
        result = sre_cli(['stop-all'])
        assert result.code == 0 and result.events == ['temporary drop', 'action_stop_all']
        result = sre_cli(['stop-all', 'PROJECT'])
        assert result.code == 2 and result.events == []
        assert 'unrecognized arguments' in capsys.readouterr().err

    def test_wipe_local_takes_no_argument(self, sre_cli, capsys):
        result = sre_cli(['wipe-local'])
        assert result.code == 0 and result.events == ['temporary drop', 'action_wipe_local']
        result = sre_cli(['wipe-local', 'PROJECT'])
        assert result.code == 2 and result.events == []
        assert 'unrecognized arguments' in capsys.readouterr().err

    def test_status_takes_no_argument(self, sre_cli, capsys):
        """Read-only: root is dropped for good (the origin files are the sre user's)."""
        result = sre_cli(['status'])
        assert result.code == 0 and result.events == ['permanent drop', 'action_status']
        result = sre_cli(['status', 'PROJECT'])
        assert result.code == 2 and result.events == []
        assert 'unrecognized arguments' in capsys.readouterr().err

    def test_status_json_option(self, sre_cli):
        """--json (one JSON document for scripts) is off unless asked, and reaches the action."""
        result = sre_cli(['status'])
        assert result.args.json is False and result.kwargs == {'as_json': False}
        result = sre_cli(['status', '--json'])
        assert result.code == 0 and result.events == ['permanent drop', 'action_status']
        assert result.args.json is True and result.kwargs == {'as_json': True}

    def test_preload_images_progress_option(self, sre_cli):
        """--progress (the JSON steps on stderr the web agent reads) is off unless asked."""
        result = sre_cli(['preload-images', '/opt/sre/lab'])
        assert result.code == 0 and result.events == ['permanent drop', 'action_preload_images']
        assert result.args.progress is False and result.args.paths == ['/opt/sre/lab']
        result = sre_cli(['preload-images', '--progress', '--random-delay', '5', 'a.py', 'b'])
        assert result.args.progress is True and result.args.random_delay == 5
        assert result.args.paths == ['a.py', 'b']

    @pytest.mark.parametrize('argv', [['stop', '--instructor-mode', 'PROJECT'],
                                      ['state', '--instructor-mode', 'PROJECT', 'final'],
                                      [SET, '--instructor-mode', 'PROJECT']])
    def test_option_exists_on_start_and_restore_only(self, sre_cli, capsys, argv):
        result = sre_cli(argv)
        assert result.code == 2 and result.events == []
        assert '--instructor-mode' in capsys.readouterr().err

    def test_help_lists_the_commands(self, sre_cli, capsys):
        assert sre_cli(['--help']).code == 0
        text = ' '.join(capsys.readouterr().out.split())
        assert 'Put a running project in instructor mode (privileged only)' in text
        assert 'Take a running project out of instructor mode (privileged only)' in text
        assert 'Stop every running project the caller may access' in text
        assert 'Remove all files and stop kathara (privileged only)' in text
        assert 'Show the version, the state of sre-agent and the running projects (privileged only)' in text

    @pytest.mark.parametrize('command', ['start', 'restore'])
    def test_help_of_the_option(self, sre_cli, capsys, command):
        assert sre_cli([command, '--help']).code == 0
        text = ' '.join(capsys.readouterr().out.split())
        assert '--instructor-mode' in text and 'in instructor mode (privileged only)' in text

    def test_french_help(self, sre_cli, capsys, monkeypatch):
        monkeypatch.setenv('LANGUAGE', 'fr')
        assert sre_cli(['--help']).code == 0
        text = ' '.join(capsys.readouterr().out.split())
        assert 'Passer un projet en cours en mode enseignant' in text
        assert 'Sortir un projet en cours du mode enseignant' in text
        assert 'Arrêter tous les projets en cours accessibles' in text
        assert "Afficher la version, l'état de sre-agent et les projets en cours" in text
        assert sre_cli(['start', '--help']).code == 0
        assert 'en mode enseignant' in ' '.join(capsys.readouterr().out.split())

    def test_german_help(self, sre_cli, capsys, monkeypatch):
        """The German catalog (locale/de/LC_MESSAGES/sre.mo) chosen by LANGUAGE like the French one."""
        monkeypatch.setenv('LANGUAGE', 'de')
        assert sre_cli(['--help']).code == 0
        text = ' '.join(capsys.readouterr().out.split())
        assert 'Ein laufendes Projekt in den Lehrkraftmodus versetzen' in text
        assert 'Alle laufenden Projekte stoppen, auf die der Aufrufer zugreifen darf' in text
        assert 'Die Installation von GitHub aktualisieren' in text
        assert 'Version, Zustand von sre-agent und laufende Projekte anzeigen' in text
        assert sre_cli(['start', '--help']).code == 0
        assert 'im Lehrkraftmodus starten' in ' '.join(capsys.readouterr().out.split())

    def test_update_options(self, sre_cli):
        result = sre_cli([UPDATE])
        assert result.code == 0 and result.events[-1] == 'action_update'
        args = result.args
        assert (args.main, args.ref, args.check, args.force, args.yes, args.venv) == (False, None, False, False,
                                                                                     False, False)
        result = sre_cli([UPDATE, '--main', '--force', '-y', '--venv'])
        assert (result.args.main, result.args.force, result.args.yes, result.args.venv) == (True, True, True, True)
        assert sre_cli([UPDATE, '--ref', '0.10.0', '--check', '--yes']).args.ref == '0.10.0'
        assert sre_cli([UPDATE, '--ref', '0.10.0', '--check']).args.check is True

    @pytest.mark.parametrize('argv', [[UPDATE, '--main', '--ref', 'x'], [UPDATE, '--check', '--force'],
                                      [UPDATE, 'extra']])
    def test_update_exclusive_options(self, sre_cli, capsys, argv):
        result = sre_cli(argv)
        assert result.code == 2 and result.events == []

    def test_update_help(self, sre_cli, capsys, monkeypatch):
        assert sre_cli(['--help']).code == 0
        assert 'Update the installation from GitHub (privileged only' in ' '.join(capsys.readouterr().out.split())
        assert sre_cli([UPDATE, '--help']).code == 0
        text = ' '.join(capsys.readouterr().out.split())
        assert '--main' in text and '--ref' in text and '--check' in text and '--venv' in text
        monkeypatch.setenv('LANGUAGE', 'fr')
        assert sre_cli(['--help']).code == 0
        assert 'Mettre à jour l\'installation depuis GitHub' in ' '.join(capsys.readouterr().out.split())
        assert sre_cli([UPDATE, '--help']).code == 0
        assert 'dernière version publiée' in ' '.join(capsys.readouterr().out.split())

    def test_re_eval_update_web_option(self, sre_cli, capsys, monkeypatch):
        """`sre re-eval --update-web`: a flag of that command alone; run by root it writes as the
        sre user (the permanent drop comes before the action: the queue for the web portal
        belongs to sre)."""
        base = ['re-eval', '-s', 'lab.py', '-p', 'corrected']
        result = sre_cli([*base, '--update-web', 'a.zst', 'b.zst'])
        assert result.code == 0 and result.events == ['permanent drop', 'action_re_eval']
        assert result.args.update_web is True and result.args.files == ['a.zst', 'b.zst']
        assert sre_cli([*base, 'a.zst']).args.update_web is False
        assert sre_cli(['check-eval', '--update-web', 'a.zst']).code == 2
        capsys.readouterr()
        assert sre_cli(['re-eval', '--help']).code == 0
        text = ' '.join(capsys.readouterr().out.split())
        assert '--update-web' in text and 'also queue the new results for the web portal' in text
        monkeypatch.setenv('LANGUAGE', 'fr')
        assert sre_cli(['re-eval', '--help']).code == 0
        assert 'en attente pour le portail web' in ' '.join(capsys.readouterr().out.split())

    def test_re_eval_update_web_from_the_command_line(self, sre_cli, capsys, tmp_path, tmp_pub_dir, monkeypatch):
        """The real action behind the real parser: an archive re-graded and its new results
        queued for the portal under its own name."""
        import test_re_eval as T
        from SRE import web_updates
        monkeypatch.setattr(params, 'agent_config_file', str(tmp_path / 'no-agent.toml'))
        # root (the euid the fixture gives) has dropped to the sre user, who owns what is written:
        # here the user running the tests
        monkeypatch.setattr(params, 'sre_uid', os.getuid())
        srelab = tmp_path / 'srelab.py'
        srelab.write_text(T._AUTO_EVAL_COUNT_SRELAB)
        module, _ = T._load_srelab(str(srelab))
        archive = tmp_path / f'{T._ARCHIVE_STEM}.zst'
        T._make_archive(archive, module, archived_count=4, stored_grade=0, current_srelab_file=str(srelab))
        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        result = sre_cli(['re-eval', '-s', str(srelab), '-p', 'corrected', '-d', str(out_dir), '--update-web',
                          str(archive)], real=('action_re_eval',))
        assert result.code == 0 and (out_dir / f'corrected{T._ARCHIVE_STEM}.zst').exists()
        [entry] = web_updates.pending(params.web_updates_dir)[0]
        assert entry['record'][params.archive_keyword] == archive.name and entry['record']['grade'] == 4.0
        assert "queued for the web portal: 1 evaluation(s)" in capsys.readouterr().out

    def test_make_titles_directories_option(self, sre_cli, capsys, monkeypatch):
        """`sre make-titles -d` / `--directories`: off unless asked, with -r, -o or neither."""
        result = sre_cli(['make-titles', '-r', '/opt/sre/lab'])
        assert result.code == 0 and result.events[-1] == 'action_make_titles'
        assert result.args.directories is False and result.args.recursive is True
        result = sre_cli(['make-titles', '-r', '-d', '/opt/sre/lab'])
        assert result.args.directories is True and result.args.recursive is True
        result = sre_cli(['make-titles', '--directories', '-o', 'out.json', 'lab'])
        assert result.args.directories is True and result.args.output_file == 'out.json'
        assert sre_cli(['make-titles', '-d', 'lab']).args.directories is True
        assert sre_cli(['make-titles', '-d', '-r', '-o', 'out.json', 'lab']).code == 2
        capsys.readouterr()
        assert sre_cli(['make-titles', '--help']).code == 0
        text = ' '.join(capsys.readouterr().out.split())
        assert '--directories' in text and 'also list the sub-directories of each directory' in text
        monkeypatch.setenv('LANGUAGE', 'fr')
        assert sre_cli(['make-titles', '--help']).code == 0
        assert 'lister aussi les sous-répertoires de chaque répertoire' in ' '.join(capsys.readouterr().out.split())

    def test_make_titles_directories_from_the_command_line(self, sre_cli, tmp_path):
        """The real action behind the real parser: the sub-directories are listed with -d only."""
        import json
        for name in ('s4/x.py', 'sre/y.py'):
            (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / name).write_text('title = "A lab"\n')
        result = sre_cli(['make-titles', '-r', str(tmp_path)], real=('action_make_titles',))
        assert result.code == 0 and not (tmp_path / 'titles.json').exists()
        assert json.loads((tmp_path / 's4' / 'titles.json').read_text()) == {"x.py": "A lab"}
        result = sre_cli(['make-titles', '-r', '-d', str(tmp_path)], real=('action_make_titles',))
        assert result.code == 0
        assert json.loads((tmp_path / 'titles.json').read_text()) == {"s4": None, "sre": None}


class TestDispatch:
    def test_set(self, sre_cli):
        assert sre_cli([SET, 'PROJECT']).events[-1:] == ['action_set_instructor_mode']

    def test_remove(self, sre_cli):
        assert sre_cli([REMOVE, 'PROJECT']).events[-1:] == ['action_remove_instructor_mode']

    @pytest.mark.parametrize('argv', [[SET, 'PROJECT'], [REMOVE, 'PROJECT'],
                                      ['start', '--instructor-mode', 'mylab'],
                                      ['restore', '--instructor-mode', '-']])
    def test_exactly_one_action_after_the_privilege_drop(self, sre_cli, argv):
        events = sre_cli(argv).events
        assert len(events) == 2 and events[0].endswith('drop') and events[1].startswith('action_')

    def test_sre_user_may_run_them(self, sre_cli):
        """The sre user (not root) is the other privileged caller."""
        result = sre_cli([SET, 'PROJECT'], uid=params.sre_uid)
        assert result.code == 0 and result.events[-1] == 'action_set_instructor_mode'

    def test_update(self, sre_cli):
        assert sre_cli([UPDATE, '--check']).events == ['temporary drop', 'action_update']


class TestPrivilegeList:
    """`sre.py` only drops root for good when the action never needs it again.  Writing
    info.json again queries Kathara, which needs root for the labs with privileged machines:
    the two commands are in the list of the temporary drop, like `eval` and `state`."""

    @pytest.mark.parametrize('argv', [[SET, 'PROJECT'], [REMOVE, 'PROJECT'],
                                      ['start', '--instructor-mode', 'mylab'],
                                      ['restore', '--instructor-mode', '-'],
                                      ['eval', 'PROJECT'], ['state', 'PROJECT', 'final'], ['stop-all'],
                                      ['wipe-local']])
    def test_temporary_drop(self, sre_cli, argv):
        assert sre_cli(argv).events[0] == 'temporary drop'

    def test_stop_all_drops_for_good_without_privileged_machines(self, sre_cli, monkeypatch):
        monkeypatch.setattr(params, 'allow_privileged_machines', False)
        assert sre_cli(['stop-all']).events == ['permanent drop', 'action_stop_all']

    def test_wipe_local_drops_for_good_without_privileged_machines(self, sre_cli, monkeypatch):
        monkeypatch.setattr(params, 'allow_privileged_machines', False)
        assert sre_cli(['wipe-local']).events == ['permanent drop', 'action_wipe_local']

    @pytest.mark.parametrize('argv', [['list'], ['export', 'PROJECT'], ['status'], ['set-drain'], ['remove-drain']])
    def test_other_actions_drop_for_good(self, sre_cli, argv):
        assert sre_cli(argv).events[0] == 'permanent drop'

    @pytest.mark.parametrize('command', ['set-drain', 'remove-drain'])
    def test_the_drain_of_the_host(self, sre_cli, command):
        """The request is a file of the public directory, the sre user's: written after the drop."""
        result = sre_cli([command])
        assert result.code == 0 and result.events == ['permanent drop', f"action_{command.replace('-', '_')}"]
        assert sre_cli([command, 'now']).code == 2          # no argument

    @pytest.mark.parametrize('command', [SET, REMOVE])
    def test_permanent_drop_without_privileged_machines(self, sre_cli, monkeypatch, command):
        monkeypatch.setattr(params, 'allow_privileged_machines', False)
        assert sre_cli([command, 'PROJECT']).events == [
            'permanent drop', f"action_{command.replace('-', '_')}"]

    def test_update_keeps_root_whatever_the_setting(self, sre_cli, monkeypatch):
        """`update` writes the root-owned tree: the temporary drop even without privileged machines."""
        assert sre_cli([UPDATE]).events[0] == 'temporary drop'
        monkeypatch.setattr(params, 'allow_privileged_machines', False)
        assert sre_cli([UPDATE]).events == ['temporary drop', 'action_update']


class TestRefusals:
    @pytest.mark.parametrize('command', [SET, REMOVE, UPDATE, 'wipe-local'])
    def test_admin_users_are_refused(self, sre_cli, capsys, monkeypatch, command):
        """Admins only run the read-only archive tools (access.ADMIN_ACTIONS)."""
        monkeypatch.setattr(params, 'admin_uids', [4242])
        assert sre_cli(['cat', 'x.zst'], uid=4242).events == ['permanent drop', 'action_cat']
        result = sre_cli([command] + ([] if command in (UPDATE, 'wipe-local') else ['PROJECT']), uid=4242)
        assert result.code == 1 and result.events == []
        assert 'illegal userid' in capsys.readouterr().err

    def test_other_users_are_refused(self, sre_cli, capsys, monkeypatch):
        monkeypatch.setattr(params, 'admin_uids', [])
        monkeypatch.setattr(params, 'admin_gids', [])
        result = sre_cli([SET, 'PROJECT'], uid=5555)
        assert result.code == 1 and result.events == []
        assert 'illegal userid' in capsys.readouterr().err

    @pytest.mark.parametrize('argv, action, message', [
        ([SET, 'PROJECT'], 'action_set_instructor_mode', "you're not allowed to run this command"),
        ([REMOVE, 'PROJECT'], 'action_remove_instructor_mode', "you're not allowed to run this command"),
        (['start', '--instructor-mode', 'mylab'], 'action_start',
         '--instructor-mode is not available in user mode'),
        (['restore', '--instructor-mode', '-'], 'action_restore',
         '--instructor-mode is not available in user mode'),
        ([UPDATE], 'action_update', "you're not allowed to run this command"),
        (['wipe'], 'action_wipe', "you're not allowed to run this command"),
        (['wipe-local'], 'action_wipe_local', "you're not allowed to run this command"),
    ])
    def test_user_mode_is_refused_by_the_action(self, sre_cli, capsys, monkeypatch, tmp_pub_dir,
                                                argv, action, message):
        """The student path (`sre --user ...` through sre-wrapper), with the real action."""
        monkeypatch.setenv('SUDO_USER', 'etudiant')
        monkeypatch.setenv('USER_USERNAME', 'etudiant')
        result = sre_cli(['--user', *argv], real=(action,))
        assert result.code == 1 and result.events == ['temporary drop']
        assert result.args is None
        assert message in capsys.readouterr().err
        assert not Path(params.sre_projects_dir).exists()

    def test_status_is_refused_in_user_mode(self, sre_cli, capsys, monkeypatch, tmp_pub_dir):
        """`sre --user status` through sre-wrapper, with the real action: nothing is printed."""
        monkeypatch.setenv('SUDO_USER', 'etudiant')
        monkeypatch.setenv('USER_USERNAME', 'etudiant')
        result = sre_cli(['--user', 'status'], real=('action_status',))
        assert result.code == 1 and result.events == ['permanent drop']
        captured = capsys.readouterr()
        assert "you're not allowed to run this command" in captured.err and captured.out == ''

    @pytest.mark.parametrize('command', ['set-drain', 'remove-drain'])
    def test_the_drain_of_the_host_is_refused_in_user_mode(self, sre_cli, capsys, monkeypatch, tmp_pub_dir, command):
        """A student never drains the workstation through sre-wrapper: nothing is written."""
        Path(params.sre_pub_dir).mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv('SUDO_USER', 'etudiant')
        monkeypatch.setenv('USER_USERNAME', 'etudiant')
        result = sre_cli(['--user', command], real=(f"action_{command.replace('-', '_')}",))
        assert result.code == 1 and result.events == ['permanent drop']
        captured = capsys.readouterr()
        assert "you're not allowed to run this command" in captured.err and captured.out == ''
        assert list(Path(params.sre_pub_dir).iterdir()) == []

    def test_stop_all_is_refused_in_exam_mode(self, sre_cli, capsys, monkeypatch, tmp_pub_dir):
        """`stop-all` (the GUI's Close All Projects) follows `stop`: not during an exam."""
        Path(params.sre_pub_dir).mkdir(parents=True, exist_ok=True)
        (Path(params.sre_pub_dir) / params.exam_json_name).write_text('{}')
        monkeypatch.setenv('SUDO_USER', 'etudiant')
        monkeypatch.setenv('USER_USERNAME', 'etudiant')
        result = sre_cli(['--user', 'stop-all'], real=('action_stop_all',))
        assert result.code == 1 and result.events == ['temporary drop']
        assert 'not allowed to run this command in exam mode' in capsys.readouterr().err


class TestEngineErrors:
    """What the container engine cannot do ends a command with one line, like the other errors
    of the CLI, not with a traceback."""

    def test_an_engine_error_raised_by_an_action(self, sre_cli, capsys, monkeypatch):
        from SRE.command import stop
        from SRE.engine import EngineError

        def action_stop():
            raise EngineError("save / restore is not available with the Podman engine yet")

        monkeypatch.setattr(stop, 'action_stop', action_stop)
        result = sre_cli(['stop', 'some-project'], real=('action_stop',))
        assert result.code == 1
        assert capsys.readouterr().err == "sre: save / restore is not available with the Podman engine yet\n"

    def test_any_other_exception_still_goes_up(self, sre_cli, monkeypatch):
        from SRE.command import stop

        def action_stop():
            raise RuntimeError("a bug")

        monkeypatch.setattr(stop, 'action_stop', action_stop)
        with pytest.raises(RuntimeError, match="a bug"):
            sre_cli(['stop', 'some-project'], real=('action_stop',))

    def test_an_engine_that_does_not_exist(self, sre_cli, capsys, monkeypatch):
        import SRE.engine as engine_package

        monkeypatch.setattr(engine_package, '_engines', {})
        monkeypatch.setattr(params, 'container_engine', 'lxc')
        result = sre_cli(['list'])
        assert result.code == 1 and result.events == []
        assert capsys.readouterr().err == ("sre: container_engine = 'lxc' in params.py: not a container engine "
                                           "(kathara, podman)\n")


class TestEveryEngineSeesRootAtEntry:
    """An engine notes that the process is root before the effective uid is lowered (Kathara
    could never raise it again otherwise): every engine the command may ask does, those the
    host allows and those the projects still there record."""

    @pytest.fixture
    def noted(self, monkeypatch):
        import SRE.engine as engine_package
        seen = []
        monkeypatch.setattr(engine_package, '_engines', {
            name: SimpleNamespace(capture_root_privileges=lambda name=name: seen.append(name))
            for name in params.container_engines})
        return seen

    def test_the_default_engine_of_the_host(self, sre_cli, noted):
        assert sre_cli(['list']).code == 0 and noted == ['kathara']

    def test_every_engine_the_host_allows(self, sre_cli, noted, monkeypatch):
        monkeypatch.setattr(params, 'container_engine', 'podman')
        monkeypatch.setattr(params, 'container_engines_allowed', ('kathara', 'podman'))
        assert sre_cli(['list']).code == 0 and noted == ['podman', 'kathara']

    def test_the_engine_of_a_project_the_host_no_longer_allows(self, sre_cli, noted, tmp_pub_dir):
        from SRE import origin
        project = '20261118091203@@@sre@dhcp.py@@@alice'
        (tmp_pub_dir / 'projects' / project / params.private_dir_name).mkdir(parents=True)
        origin.write_origin(params.origin_filename(project), params.origin_local, 'alice', engine='podman')
        assert sre_cli(['list']).code == 0 and noted == ['kathara', 'podman']

    def test_not_for_a_caller_that_is_not_root(self, sre_cli, noted):
        sre_cli(['list'], uid=params.sre_uid)
        assert noted == []

    def test_allowed_engines_that_leave_the_default_out(self, sre_cli, noted, monkeypatch, capsys):
        monkeypatch.setattr(params, 'container_engines_allowed', ('podman',))
        result = sre_cli(['list'])
        assert result.code == 1 and result.events == [] and noted == []
        assert capsys.readouterr().err == ("sre: container_engines_allowed = ('podman',) in params.py: the default "
                                           "engine of this host, 'kathara', is not among them\n")
