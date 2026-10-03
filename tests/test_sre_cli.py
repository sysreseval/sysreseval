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


@pytest.fixture
def sre_cli(monkeypatch):
    """``run(argv, uid=0, real=())`` executes src/sre.py and returns what happened: ``events`` (the
    privilege drops and the actions, in order), ``args`` (the parsed namespace seen by the
    action) and ``code`` (exit status).  The actions named in *real* are not replaced."""
    monkeypatch.setattr(params.SRE, 'username', None, raising=False)
    for name in ('SUDO_COMMAND', 'SUDO_USER', 'USER_USERNAME'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('LOGNAME', 'root')
    monkeypatch.setenv('LANGUAGE', 'en')
    # loaded by sre.py when it runs as root
    monkeypatch.setitem(sys.modules, 'Kathara.auth', MagicMock())
    monkeypatch.setitem(sys.modules, 'Kathara.auth.PrivilegeHandler', MagicMock())

    def run(argv, uid=0, real=()):
        result = SimpleNamespace(events=[], args=None, code=0)
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
        assert result.args.instructor_mode is False

    def test_start_option_does_not_imply_a_path(self, sre_cli):
        """Unlike --debug-project, the lab argument stays a lab name."""
        result = sre_cli(['start', '--instructor-mode', 'mylab'])
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
        assert sre_cli(['start', '--help']).code == 0
        assert 'en mode enseignant' in ' '.join(capsys.readouterr().out.split())


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


class TestPrivilegeList:
    """`sre.py` only drops root for good when the action never needs it again.  Writing
    info.json again queries Kathara, which needs root for the labs with privileged machines:
    the two commands are in the list of the temporary drop, like `eval` and `state`."""

    @pytest.mark.parametrize('argv', [[SET, 'PROJECT'], [REMOVE, 'PROJECT'],
                                      ['start', '--instructor-mode', 'mylab'],
                                      ['restore', '--instructor-mode', '-'],
                                      ['eval', 'PROJECT'], ['state', 'PROJECT', 'final']])
    def test_temporary_drop(self, sre_cli, argv):
        assert sre_cli(argv).events[0] == 'temporary drop'

    @pytest.mark.parametrize('argv', [['list'], ['export', 'PROJECT']])
    def test_other_actions_drop_for_good(self, sre_cli, argv):
        assert sre_cli(argv).events[0] == 'permanent drop'

    @pytest.mark.parametrize('command', [SET, REMOVE])
    def test_permanent_drop_without_privileged_machines(self, sre_cli, monkeypatch, command):
        monkeypatch.setattr(params, 'allow_privileged_machines', False)
        assert sre_cli([command, 'PROJECT']).events == [
            'permanent drop', f"action_{command.replace('-', '_')}"]


class TestRefusals:
    @pytest.mark.parametrize('command', [SET, REMOVE])
    def test_admin_users_are_refused(self, sre_cli, capsys, monkeypatch, command):
        """Admins only run the read-only archive tools (access.ADMIN_ACTIONS)."""
        monkeypatch.setattr(params, 'admin_uids', [4242])
        assert sre_cli(['cat', 'x.zst'], uid=4242).events == ['permanent drop', 'action_cat']
        result = sre_cli([command, 'PROJECT'], uid=4242)
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
