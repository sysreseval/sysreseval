"""`sre wipe-local` (SRE/command/wipe_local.py): the local projects are closed, the web projects
and those of unknown origin are left running.  A fake projects directory; nothing is deployed, the
stops are recorded."""
import json
from pathlib import Path

import pytest

from SRE import origin, params
from SRE.command import wipe_local

WEB = '20261118091203@@@sre@dhcp.py@@@alice'
LOCAL = '20261118091540@@@sre@nftables-filter1.py@@@bob'
ROOT = '20261118100111@@@sre@static_routing.py@@@root'
OLD = '20261118101500@@@sre@dns.py@@@carol'


def make_project(name: str, origin_value: str | None = None, info: bool = True):
    """A project directory; *origin_value* ``None`` = no origin file (a project older than it)."""
    directory = Path(params.sre_projects_dir) / name
    (directory / params.private_dir_name).mkdir(parents=True)
    if info:
        (directory / params.info_json_name).write_text(json.dumps(
            {'lab_name': params.get_lab_name_from_running_lab_name(name), 'lab_hash': f'hash-{name}'}))
    if origin_value is not None:
        origin.write_origin(params.origin_filename(name), origin_value,
                            params.get_username_from_running_lab_name(name))


@pytest.fixture
def host(tmp_pub_dir):
    """A pool host: a web project, two local ones (a student's and root's)."""
    make_project(ROOT, params.origin_local)
    make_project(WEB, params.origin_web)
    make_project(LOCAL, params.origin_local)


@pytest.fixture
def stopped(monkeypatch):
    """The `stop_running_lab` calls as (name, lab_hash, multi_project), then 'drop'."""
    calls = []

    def fake_stop(running_lab_name, lab_hash=None, multi_project=False):
        calls.append((running_lab_name, lab_hash, multi_project))
        return []

    monkeypatch.setattr(wipe_local, 'stop_running_lab', fake_stop)
    monkeypatch.setattr(wipe_local, 'drop_privileges_permanently', lambda: calls.append('drop'))
    return calls


class TestLocalProjects:
    def test_local_ones_in_start_order(self, host):
        assert wipe_local.local_projects() == ([(LOCAL, f'hash-{LOCAL}'), (ROOT, f'hash-{ROOT}')], [])

    def test_no_origin_file(self, host):
        make_project(OLD)
        assert wipe_local.local_projects() == ([(LOCAL, f'hash-{LOCAL}'), (ROOT, f'hash-{ROOT}')], [OLD])

    def test_broken_origin_file(self, host):
        make_project(OLD)
        Path(params.origin_filename(OLD)).write_text('{"origin": "moon"}')
        assert wipe_local.local_projects()[1] == [OLD]

    def test_only_the_running_projects(self, host):
        """A directory without info.json (a start in progress or failed) and a stray file are not projects."""
        make_project(OLD, params.origin_local, info=False)
        (Path(params.sre_projects_dir) / 'stray').write_text('')
        assert [name for name, _ in wipe_local.local_projects()[0]] == [LOCAL, ROOT]

    def test_no_projects_directory(self, tmp_pub_dir):
        assert wipe_local.local_projects() == ([], [])


class TestWipeLocal:
    def test_local_projects_are_stopped_and_web_ones_left(self, host, stopped, capsys):
        wipe_local.action_wipe_local()
        assert stopped == [(LOCAL, f'hash-{LOCAL}', True), (ROOT, f'hash-{ROOT}', True), 'drop']
        captured = capsys.readouterr()
        assert captured.out == 'local projects closed: 2\n' and captured.err == ''

    def test_nothing_to_close(self, tmp_pub_dir, stopped, capsys):
        make_project(WEB, params.origin_web)
        wipe_local.action_wipe_local()
        assert stopped == ['drop']
        assert capsys.readouterr().out == 'local projects closed: none\n'

    def test_no_projects_directory(self, tmp_pub_dir, stopped, capsys):
        wipe_local.action_wipe_local()
        assert stopped == ['drop'] and capsys.readouterr().out == 'local projects closed: none\n'

    def test_unknown_origin_is_left_running_with_a_warning(self, host, stopped, capsys):
        """It cannot be told from a web project: not closed, and not an error."""
        make_project(OLD)
        wipe_local.action_wipe_local()
        assert [call[0] for call in stopped[:-1]] == [LOCAL, ROOT]
        captured = capsys.readouterr()
        assert captured.out == 'local projects closed: 2\n'
        assert captured.err == f'warning: {OLD}: unknown origin (no origin file), left running\n'

    def test_project_without_info_json_is_left_alone(self, host, stopped):
        (Path(params.sre_projects_dir) / LOCAL / params.info_json_name).unlink()
        wipe_local.action_wipe_local()
        assert [call[0] for call in stopped[:-1]] == [ROOT]

    def test_privileged_only(self, host, mock_sre_args, stopped, capsys):
        mock_sre_args.user = True
        with pytest.raises(SystemExit) as e:
            wipe_local.action_wipe_local()
        assert e.value.code == 1 and stopped == []
        captured = capsys.readouterr()
        assert "you're not allowed to run this command" in captured.err and captured.out == ''

    def test_errors_are_reported_after_the_drop(self, host, monkeypatch, stopped, capsys):
        """One project whose directory stays: the next one is still closed, exit 1."""
        def failing_stop(running_lab_name, lab_hash=None, multi_project=False):
            stopped.append((running_lab_name, lab_hash, multi_project))
            return [f'{running_lab_name}/shared: busy'] if running_lab_name == LOCAL else []

        monkeypatch.setattr(wipe_local, 'stop_running_lab', failing_stop)
        with pytest.raises(SystemExit) as e:
            wipe_local.action_wipe_local()
        assert e.value.code == 1 and [call[0] for call in stopped[:-1]] == [LOCAL, ROOT] and stopped[-1] == 'drop'
        captured = capsys.readouterr()
        assert captured.out == 'local projects closed: 1\n'
        assert 'cannot remove' in captured.err and f'{LOCAL}/shared: busy' in captured.err

    def test_not_refused_in_exam_mode(self, host, stopped):
        """Like `sre wipe`: the exam check is the one of user mode."""
        (Path(params.sre_pub_dir) / params.exam_json_name).write_text('{}')
        wipe_local.action_wipe_local()
        assert [call[0] for call in stopped[:-1]] == [LOCAL, ROOT]
