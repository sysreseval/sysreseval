"""The origin file of a project (SRE/origin.py): who started it, locally or from the web, and its
writing by ``start.create_project_directories`` (``sre start``, ``sre restore``, ``sre pre-start-exam``)."""
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from SRE import origin, params
from SRE.command import start

WEB_ENV = {params.sre_origin_env_variable: params.origin_web}
RLN = '20261118091203@@@sre@dhcp.py@@@alice'


class TestProjectOrigin:
    def test_web_when_the_caller_says_so(self):
        assert origin.project_origin(WEB_ENV, by_sudo=False) == params.origin_web

    def test_the_variable_is_not_trusted_through_sudo(self):
        """The student path (sre-wrapper → sudo): the environment is the student's."""
        assert origin.project_origin(WEB_ENV, by_sudo=True) == params.origin_local

    @pytest.mark.parametrize('env', [{}, {params.sre_origin_env_variable: params.origin_local},
                                     {params.sre_origin_env_variable: 'WEB'},
                                     {params.sre_origin_env_variable: ''}])
    def test_local_otherwise(self, env):
        assert origin.project_origin(env, by_sudo=False) == params.origin_local
        assert origin.project_origin(env, by_sudo=True) == params.origin_local


class TestFile:
    def test_round_trip(self, tmp_path):
        path = tmp_path / params.origin_json_name
        origin.write_origin(path, params.origin_web, 'alice')
        assert json.loads(path.read_text()) == {'origin': 'web', 'user': 'alice'}
        assert origin.read_origin(path) == {params.origin_keyword: params.origin_web,
                                            params.origin_user_keyword: 'alice'}

    def test_private_to_its_owner(self, tmp_path):
        path = tmp_path / params.origin_json_name
        origin.write_origin(path, params.origin_local, 'root')
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_written_once(self, tmp_path):
        path = tmp_path / params.origin_json_name
        origin.write_origin(path, params.origin_local, 'bob')
        with pytest.raises(FileExistsError):
            origin.write_origin(path, params.origin_web, 'alice')
        assert origin.read_origin(path)[params.origin_user_keyword] == 'bob'

    @pytest.mark.parametrize('content', [None, '', 'not json', '[]', '"web"',
                                         '{"origin": "moon", "user": "alice"}',
                                         '{"origin": "web"}', '{"user": "alice"}',
                                         '{"origin": "web", "user": 3}', '{"origin": ["web"], "user": "alice"}'])
    def test_unusable_file_reads_as_none(self, tmp_path, content):
        """Missing (a project older than the file), empty, broken, or not what is written."""
        path = tmp_path / params.origin_json_name
        if content is not None:
            path.write_text(content)
        assert origin.read_origin(path) is None

    def test_unknown_keys_are_dropped(self, tmp_path):
        path = tmp_path / params.origin_json_name
        path.write_text('{"origin": "local", "user": "bob", "extra": 1}')
        assert origin.read_origin(path) == {'origin': 'local', 'user': 'bob'}


class TestCreateProjectDirectories:
    """`sre start` writes the file with the rest of the private directory."""

    @pytest.fixture
    def create(self, tmp_pub_dir, tmp_path, monkeypatch):
        monkeypatch.setattr(params, 'sre_user_public_dir', str(tmp_path / 'home'))
        monkeypatch.setattr(params.SRE, 'username', 'alice', raising=False)
        for name in ('SUDO_USER', 'SUDO_COMMAND', params.sre_origin_env_variable):
            monkeypatch.delenv(name, raising=False)

        def run() -> dict:
            start.create_project_directories(start.ProjectSetup(running_lab_name=RLN), SimpleNamespace(),
                                             '/opt/sre/lab/sre/dhcp.py', debug_project=False)
            path = Path(params.origin_filename(RLN))
            assert path.parent == Path(params.private_lab_dir(RLN)) and path.name == params.origin_json_name
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            return json.loads(path.read_text())

        return run

    def test_local(self, create):
        assert create() == {'origin': 'local', 'user': 'alice'}

    def test_web(self, create, monkeypatch):
        """What the web agent runs: its own environment, no sudo."""
        monkeypatch.setenv(params.sre_origin_env_variable, params.origin_web)
        assert create() == {'origin': 'web', 'user': 'alice'}

    def test_a_student_cannot_claim_the_web(self, create, monkeypatch):
        """sre-wrapper → sudo: SUDO_COMMAND names sre itself, the variable is the student's."""
        monkeypatch.setenv(params.sre_origin_env_variable, params.origin_web)
        monkeypatch.setenv('SUDO_USER', 'alice')
        monkeypatch.setenv('SUDO_COMMAND', f'{params.sre_exe} --user start sre/dhcp.py')
        assert create() == {'origin': 'local', 'user': 'alice'}

    def test_root_shell_of_an_admin(self, create, monkeypatch):
        """`sudo -i` then `sre start`: SUDO_COMMAND is the shell, the project is root's and local."""
        monkeypatch.setattr(params.SRE, 'username', 'root')
        monkeypatch.setenv('SUDO_USER', 'admin')
        monkeypatch.setenv('SUDO_COMMAND', '/bin/bash')
        assert create() == {'origin': 'local', 'user': 'root'}
