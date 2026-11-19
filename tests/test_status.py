"""`sre status` (SRE/command/status.py): the version, the state of sre-agent, the running projects
with their origin and user."""
import json
from pathlib import Path

import pytest

from SRE import origin, params
from SRE.command import status

ALICE = '20261118091203@@@sre@dhcp.py@@@alice'
BOB = '20261118091540@@@sre@nftables-filter1.py@@@bob'
CAROL = '20261118100111@@@sre@static_routing.py@@@carol'

PYTHON = '/opt/sre/venv/bin/python3'


def make_project(name: str, origin_value: str | None = None, user: str | None = None, info: bool = True):
    """A project directory; *origin_value* ``None`` = no origin file (a project older than it)."""
    directory = Path(params.sre_projects_dir) / name
    (directory / params.private_dir_name).mkdir(parents=True)
    if info:
        (directory / params.info_json_name).write_text(json.dumps(
            {'lab_name': params.get_lab_name_from_running_lab_name(name), 'lab_hash': f'hash-{name}'}))
    if origin_value is not None:
        origin.write_origin(params.origin_filename(name), origin_value,
                            user or params.get_username_from_running_lab_name(name))


def fake_proc(root: Path, procs: dict) -> str:
    """A /proc tree: pid → argv (``None``: a directory without ``cmdline``, a process that ended)."""
    root.mkdir()
    for pid, argv in procs.items():
        (root / str(pid)).mkdir()
        if argv is not None:
            (root / str(pid) / 'cmdline').write_bytes(b''.join(arg.encode() + b'\0' for arg in argv))
    (root / 'self').mkdir()
    (root / 'meminfo').write_text('')
    return str(root)


class TestProjectRows:
    def test_origin_and_user_of_each_project(self, tmp_pub_dir):
        make_project(BOB, params.origin_local)
        make_project(ALICE, params.origin_web)
        make_project(CAROL)
        assert status.project_rows() == [('web', 'alice', ALICE), ('local', 'bob', BOB), ('?', 'carol', CAROL)]

    def test_the_user_is_the_one_of_the_file(self, tmp_pub_dir):
        make_project(ALICE, params.origin_web, user='prof')
        assert status.project_rows() == [('web', 'prof', ALICE)]

    def test_broken_origin_file(self, tmp_pub_dir):
        make_project(ALICE)
        Path(params.origin_filename(ALICE)).write_text('{"origin": "moon"}')
        assert status.project_rows() == [('?', 'alice', ALICE)]

    def test_only_the_running_projects(self, tmp_pub_dir):
        """A directory without info.json (a start in progress or failed) and a stray file are not projects."""
        make_project(ALICE, params.origin_web)
        make_project(BOB, params.origin_local, info=False)
        (Path(params.sre_projects_dir) / 'stray').write_text('')
        assert status.project_rows() == [('web', 'alice', ALICE)]

    def test_no_projects_directory(self, tmp_pub_dir):
        assert status.project_rows() == []


class TestAgentPids:
    @pytest.mark.parametrize('argv', [
        [PYTHON, '-W', 'ignore', '/opt/sre/sbin/../src/sre_agent.py'],                      # sbin/sre-agent
        ['/usr/bin/python3', '-W', 'ignore', '/usr/lib/sysreseval/sre_agent.py'],           # the Debian launcher
        ['python3.13', 'src/sre_agent.py', '--config', '/tmp/agent.toml', '--pub-dir', '/tmp/pub'],
        ['python3', '-m', 'sreweb.agent', '--debug'],
    ])
    def test_the_agent(self, tmp_path, argv):
        assert status.agent_pids(fake_proc(tmp_path / 'proc', {812: argv})) == [812]

    @pytest.mark.parametrize('argv', [
        ['/bin/bash', '/opt/sre/sbin/sre-agent'],                # the wrapper before its exec
        ['vim', 'src/sre_agent.py'],
        ['grep', '-r', 'x', 'sre_agent.py'],
        [PYTHON, '-W', 'ignore', '/opt/sre/src/sre_web.py'],     # the portal
        ['python3', '-m', 'sreweb.portal'],
        ['python3', 'sreweb.agent', '-m'],
        ['python3', '/opt/sre/src/not_sre_agent.py'],
        [],                                                      # a kernel thread: empty cmdline
        None,                                                    # ended meanwhile
    ])
    def test_not_the_agent(self, tmp_path, argv):
        assert status.agent_pids(fake_proc(tmp_path / 'proc', {812: argv})) == []

    def test_sorted_among_the_other_processes(self, tmp_path):
        agent = [PYTHON, '-W', 'ignore', '/opt/sre/src/sre_agent.py']
        proc = fake_proc(tmp_path / 'proc', {1: ['/sbin/init'], 9000: agent, 77: ['sshd'], 812: agent})
        assert status.agent_pids(proc) == [812, 9000]

    def test_no_proc(self, tmp_path):
        assert status.agent_pids(str(tmp_path / 'missing')) is None


class TestAgentLine:
    def test_running(self):
        assert status.agent_line([812], True) == 'sre-agent: running (pid 812)'
        assert status.agent_line([812, 9000], True) == 'sre-agent: running (pids 812, 9000)'
        assert status.agent_line([812], False) == 'sre-agent: running (pid 812)'     # started by hand

    def test_not_running(self):
        assert status.agent_line([], True) == 'sre-agent: not running'

    def test_not_a_pool_host(self, monkeypatch):
        monkeypatch.setattr(params, 'agent_config_file', '/etc/sreweb/agent.toml')
        assert status.agent_line([], False) == 'sre-agent: not running (no /etc/sreweb/agent.toml)'

    def test_unknown_without_proc(self):
        assert status.agent_line(None, True) == 'sre-agent: unknown (no /proc)'


class TestStatusDict:
    ROWS = [('web', 'alice', ALICE), ('local', 'bob', BOB), ('?', 'carol', CAROL)]

    @pytest.fixture(autouse=True)
    def version(self, monkeypatch):
        monkeypatch.setattr(params, 'sre_version', '0.17.0')
        monkeypatch.setattr(params, 'agent_config_file', '/etc/sreweb/agent.toml')

    def test_running_agent_and_projects(self):
        assert status.status_dict([812], True, self.ROWS) == {
            'sre_version': '0.17.0',
            'agent': {'running': True, 'pids': [812], 'configured': True, 'config_file': '/etc/sreweb/agent.toml'},
            'projects': [
                {'running_lab_name': ALICE, 'lab_name': 'sre@dhcp.py', 'origin': 'web', 'user': 'alice'},
                {'running_lab_name': BOB, 'lab_name': 'sre@nftables-filter1.py', 'origin': 'local', 'user': 'bob'},
                {'running_lab_name': CAROL, 'lab_name': 'sre@static_routing.py', 'origin': None, 'user': 'carol'},
            ]}

    def test_agent_not_running(self):
        agent = status.status_dict([], False, [])['agent']
        assert agent == {'running': False, 'pids': [], 'configured': False, 'config_file': '/etc/sreweb/agent.toml'}
        assert status.status_dict([], True, [])['agent']['configured'] is True

    def test_unknown_without_proc(self):
        agent = status.status_dict(None, True, [])['agent']
        assert agent['running'] is None and agent['pids'] is None

    def test_no_project(self):
        assert status.status_dict([812], True, [])['projects'] == []


class TestAction:
    @pytest.fixture
    def host(self, tmp_pub_dir, tmp_path, monkeypatch):
        """A pool host: an agent.toml, the agent running as pid 812."""
        config = tmp_path / 'agent.toml'
        config.write_text('')
        monkeypatch.setattr(params, 'agent_config_file', str(config))
        monkeypatch.setattr(params, 'sre_version', '0.17.0')
        monkeypatch.setattr(status, 'agent_pids', lambda: [812])
        return config

    def test_output(self, host, capsys):
        make_project(ALICE, params.origin_web)
        make_project(BOB, params.origin_local)
        make_project(CAROL)
        status.action_status()
        assert capsys.readouterr().out == (
            "sre 0.17.0\n"
            "sre-agent: running (pid 812)\n"
            "running projects: 3\n"
            "ORIGIN  USER   PROJECT\n"
            f"web     alice  {ALICE}\n"
            f"local   bob    {BOB}\n"
            f"?       carol  {CAROL}\n")

    def test_columns_follow_the_longest_user(self, host, capsys):
        make_project(ALICE, params.origin_web, user='guest-0123abcd')
        status.action_status()
        assert capsys.readouterr().out.splitlines()[3:] == ["ORIGIN  USER            PROJECT",
                                                            f"web     guest-0123abcd  {ALICE}"]

    def test_no_project(self, host, capsys, monkeypatch):
        host.unlink()
        monkeypatch.setattr(status, 'agent_pids', lambda: [])
        status.action_status()
        assert capsys.readouterr().out == ("sre 0.17.0\n"
                                           f"sre-agent: not running (no {host})\n"
                                           "running projects: none\n")

    def test_json_output(self, host, capsys):
        """One line of JSON: the table without its placeholders (``?`` becomes null)."""
        make_project(ALICE, params.origin_web)
        make_project(CAROL)
        status.action_status(as_json=True)
        out = capsys.readouterr().out
        assert out.count('\n') == 1
        assert json.loads(out) == {
            'sre_version': '0.17.0',
            'agent': {'running': True, 'pids': [812], 'configured': True, 'config_file': str(host)},
            'projects': [
                {'running_lab_name': ALICE, 'lab_name': 'sre@dhcp.py', 'origin': 'web', 'user': 'alice'},
                {'running_lab_name': CAROL, 'lab_name': 'sre@static_routing.py', 'origin': None, 'user': 'carol'},
            ]}

    def test_json_no_project(self, host, capsys, monkeypatch):
        host.unlink()
        monkeypatch.setattr(status, 'agent_pids', lambda: [])
        status.action_status(as_json=True)
        document = json.loads(capsys.readouterr().out)
        assert document['agent'] == {'running': False, 'pids': [], 'configured': False, 'config_file': str(host)}
        assert document['projects'] == []

    @pytest.mark.parametrize('as_json', [False, True])
    def test_privileged_only(self, host, capsys, mock_sre_args, as_json):
        make_project(ALICE, params.origin_web)
        mock_sre_args.user = True
        with pytest.raises(SystemExit) as exit_info:
            status.action_status(as_json=as_json)
        captured = capsys.readouterr()
        assert exit_info.value.code == 1 and captured.out == ''
        assert "not allowed to run this command" in captured.err
