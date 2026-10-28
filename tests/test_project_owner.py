"""
The ownership check of user mode (`params.check_project_owner`): `utils.resolve_running_lab_name`
(every command taking a project goes through it), `sre stop-all`, the privileged-only `sre wipe`,
and the project list of the GUI (`sysreseval.util.visible_projects`, Qt-free).  A fake projects
directory of four owners; nothing is deployed, the stops are recorded.
"""
import json
import os
import pwd
from pathlib import Path

import pytest

from SRE import params
from SRE import utils
from SRE.command import stop_all
from SRE.command import wipe as wipe_cmd
from sysreseval import util as gui_util

ALICE = '20260101000000@@@lab@@@alice'
BOB = '20260101000001@@@lab@@@bob'
ROOT = '20260101000002@@@lab@@@root'
SRE_USER = f'20260101000003@@@other@@@{params.sre_user}'
ALL = [ALICE, BOB, ROOT, SRE_USER]


@pytest.fixture
def projects(tmp_pub_dir):
    base = Path(params.sre_projects_dir)
    for name in ALL:
        (base / name).mkdir(parents=True)
        (base / name / params.info_json_name).write_text(json.dumps({
            'lab_name': params.get_lab_name_from_running_lab_name(name), 'lab_hash': f'hash-{name}'}))
    (base / 'stray').write_text('')
    return base


def _user(mock_sre_args, monkeypatch, username):
    mock_sre_args.user = True
    monkeypatch.setattr(params.SRE, 'username', username)


class TestResolveRunningLabName:
    def test_privileged_caller_sees_every_project(self, projects, mock_sre_args, capsys):
        assert utils.resolve_running_lab_name(BOB) == BOB
        assert utils.resolve_running_lab_name('bob') == BOB
        with pytest.raises(SystemExit):
            utils.resolve_running_lab_name('lab')
        err = capsys.readouterr().err
        assert ALICE in err and BOB in err and ROOT in err

    def test_user_mode_own_and_shared_projects(self, projects, mock_sre_args, monkeypatch):
        _user(mock_sre_args, monkeypatch, 'alice')
        assert utils.resolve_running_lab_name(ALICE) == ALICE
        assert utils.resolve_running_lab_name('alice') == ALICE
        assert utils.resolve_running_lab_name(ROOT) == ROOT
        assert utils.resolve_running_lab_name(SRE_USER) == SRE_USER
        assert utils.resolve_running_lab_name('other') == SRE_USER

    def test_user_mode_refuses_another_users_project(self, projects, mock_sre_args, monkeypatch, capsys):
        _user(mock_sre_args, monkeypatch, 'alice')
        with pytest.raises(SystemExit) as e:
            utils.resolve_running_lab_name(BOB)
        assert e.value.code == 1
        assert f"not allowed to access project '{BOB}'" in capsys.readouterr().err

    def test_user_mode_never_matches_nor_lists_another_users_project(self, projects, mock_sre_args,
                                                                     monkeypatch, capsys):
        _user(mock_sre_args, monkeypatch, 'alice')
        with pytest.raises(SystemExit):
            utils.resolve_running_lab_name('bob')
        assert "no running lab matches 'bob'" in capsys.readouterr().err
        with pytest.raises(SystemExit):
            utils.resolve_running_lab_name('lab')      # ambiguous between alice's and root's only
        err = capsys.readouterr().err
        assert ALICE in err and ROOT in err and BOB not in err

    def test_check_off_restores_the_old_behaviour(self, projects, mock_sre_args, monkeypatch):
        _user(mock_sre_args, monkeypatch, 'alice')
        monkeypatch.setattr(params, 'check_project_owner', False)
        assert utils.resolve_running_lab_name(BOB) == BOB
        assert utils.resolve_running_lab_name('bob') == BOB

    def test_user_mode_without_username_reaches_the_shared_projects_only(self, projects, mock_sre_args,
                                                                         monkeypatch):
        _user(mock_sre_args, monkeypatch, None)
        assert utils.resolve_running_lab_name(ROOT) == ROOT
        with pytest.raises(SystemExit):
            utils.resolve_running_lab_name(ALICE)


@pytest.fixture
def stopped(monkeypatch):
    """The `stop_running_lab` calls of stop-all as (name, lab_hash, multi_project), then 'drop'."""
    calls = []

    def fake_stop(running_lab_name, lab_hash=None, multi_project=False):
        calls.append((running_lab_name, lab_hash, multi_project))
        return []

    monkeypatch.setattr(stop_all, 'stop_running_lab', fake_stop)
    monkeypatch.setattr(stop_all, 'drop_privileges_permanently', lambda: calls.append('drop'))
    return calls


class TestStopAll:
    def test_privileged_caller_stops_every_project(self, projects, mock_sre_args, stopped):
        stop_all.action_stop_all()
        assert stopped == [(name, f'hash-{name}', True) for name in ALL] + ['drop']

    def test_user_mode_stops_own_and_shared_projects(self, projects, mock_sre_args, monkeypatch, stopped):
        _user(mock_sre_args, monkeypatch, 'bob')
        stop_all.action_stop_all()
        assert [c[0] for c in stopped[:-1]] == [BOB, ROOT, SRE_USER] and stopped[-1] == 'drop'

    def test_check_off_stops_every_project(self, projects, mock_sre_args, monkeypatch, stopped):
        _user(mock_sre_args, monkeypatch, 'bob')
        monkeypatch.setattr(params, 'check_project_owner', False)
        stop_all.action_stop_all()
        assert [c[0] for c in stopped[:-1]] == ALL

    def test_project_without_info_json_is_left_alone(self, projects, mock_sre_args, stopped):
        (projects / ALICE / params.info_json_name).unlink()
        stop_all.action_stop_all()
        assert [c[0] for c in stopped[:-1]] == [BOB, ROOT, SRE_USER]

    def test_errors_are_reported_after_the_drop(self, projects, mock_sre_args, monkeypatch, stopped, capsys):
        def failing_stop(running_lab_name, lab_hash=None, multi_project=False):
            stopped.append((running_lab_name, lab_hash, multi_project))
            return [f'{running_lab_name}/shared: busy']

        monkeypatch.setattr(stop_all, 'stop_running_lab', failing_stop)
        with pytest.raises(SystemExit) as e:
            stop_all.action_stop_all()
        assert e.value.code == 1 and stopped[-1] == 'drop' and len(stopped) == len(ALL) + 1
        err = capsys.readouterr().err
        assert 'cannot remove' in err and f'{ALICE}/shared: busy' in err and f'{SRE_USER}/shared: busy' in err

    def test_refused_in_exam_mode_for_users(self, projects, mock_sre_args, monkeypatch, stopped, capsys):
        _user(mock_sre_args, monkeypatch, 'alice')
        (Path(params.sre_pub_dir) / params.exam_json_name).write_text('{}')
        with pytest.raises(SystemExit):
            stop_all.action_stop_all()
        assert stopped == [] and 'in exam mode' in capsys.readouterr().err


class TestWipe:
    def test_privileged_only(self, mock_sre_args, monkeypatch, capsys):
        calls = []
        monkeypatch.setattr(wipe_cmd, 'wipe', lambda: calls.append('wipe'))
        mock_sre_args.user = True
        with pytest.raises(SystemExit):
            wipe_cmd.action_wipe()
        assert calls == [] and "not allowed to run this command" in capsys.readouterr().err
        mock_sre_args.user = False
        wipe_cmd.action_wipe()
        assert calls == ['wipe']


class TestVisibleProjects:
    """The project list of the GUI (`load_projects()` itself stays unfiltered: the web agent)."""

    def test_own_and_shared_projects(self, projects, monkeypatch):
        monkeypatch.setattr(params, 'check_project_owner', True)
        assert [p.name for p in gui_util.visible_projects('alice')] == [ALICE, ROOT, SRE_USER]
        assert [p.name for p in gui_util.visible_projects('')] == [ROOT, SRE_USER]
        assert [p.name for p in gui_util.load_projects()] == ALL

    def test_check_off(self, projects, monkeypatch):
        monkeypatch.setattr(params, 'check_project_owner', False)
        assert [p.name for p in gui_util.visible_projects('alice')] == ALL

    def test_local_username_is_the_passwd_name_of_the_uid(self, monkeypatch):
        assert gui_util.local_username() == pwd.getpwuid(os.getuid()).pw_name
        monkeypatch.setenv('LOGNAME', 'somebody-else')      # the environment is not consulted
        monkeypatch.setenv('USER', 'somebody-else')
        assert gui_util.local_username() == pwd.getpwuid(os.getuid()).pw_name
