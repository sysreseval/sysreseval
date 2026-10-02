"""Tests for do_action_state(): exetests batching of cmd() ops, single- vs multi-pass
state methods, result feedback and host commands.  No Docker: containers are stand-ins
whose exec_run answers exetests batches with canned results."""
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, sre_state
from SRE.command import state as state_cmd

RUNNING_LAB = '20260101000000@@@test/test1@@@user'


def _exetests_output(*commands):
    """Fake exetests.py stdout for (timeout, cmd, result, code) tuples."""
    sep = "FAKE-EXETESTS-UUID-SEPARATOR"
    parts = []
    for timeout, cmd, result, code in commands:
        parts.append(f"{timeout}:{cmd}\n2024-01-01T00:00:00\n{result}")
        parts.append(f"2024-01-01T00:00:01\n{code}")
    return (sep + "\n" + ("\n" + sep + "\n").join(parts)).encode()


class FakeMachine:
    """Container stand-in: records every exetests batch and answers per command."""

    def __init__(self, answers=None):
        self.answers = answers or {}  # cmd -> (result, code)
        self.batches = []             # [[cmd, ...], ...] one entry per exetests invocation
        self.timeouts = {}            # cmd -> timeout seen in the batch
        self.api_object = MagicMock()
        self.api_object.exec_run.side_effect = self._exec_run

    def _exec_run(self, cmd, **kwargs):
        env = kwargs.get('environment') or {}
        if params.exetests_env_name not in env:
            return 0, b''  # e.g. chown after put_archive
        assert cmd == [params.exetests_machines_path]
        assert kwargs.get('workdir') == '/'
        cmds = []
        for entry in env[params.exetests_env_name].split(params.exetests_separator):
            timeout_s, command = entry.split(':', 1)
            cmds.append((int(timeout_s), command))
            self.timeouts[command] = int(timeout_s)
        self.batches.append([c for _, c in cmds])
        return 0, _exetests_output(*[(t, c, *self.answers.get(c, ('', 0))) for t, c in cmds])


@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


class ApplyScheme(NetScheme0):
    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)
        self.calls = {'single': 0, 'multi': 0, 'hostmulti': 0, 'hostallowed': 0}
        self.seen = []

    @sre_state
    def single(self):
        self.calls['single'] += 1
        self.cmd('m1', 'echo a')
        self.cmd('m1', 'echo b', timeout=7)
        self.file('m1', '/etc/x', 'x')
        self.cmd('m1', 'echo c')
        self.cmd('m2', 'exit 3')
        self.cmd('m2', 'false', allow_error=True)
        self.cmd('m2', 'echo d', step=2)

    @sre_state(multi_pass=True)
    def multi(self):
        self.calls['multi'] += 1
        host, _ = self.cmd('m1', 'cat /etc/hostname', step=1)
        self.seen.append(host)
        self.cmd('m2', f'echo {host.strip()}', step=2)

    @sre_state(multi_pass=True)
    def hostmulti(self):
        self.calls['hostmulti'] += 1
        out, code = self.host_cmd('hostname', step=1)
        self.seen.append((out, code))
        self.cmd('m1', f'echo {out.strip()}', step=2)

    @sre_state
    def hostallowed(self):
        self.calls['hostallowed'] += 1
        self.host_cmd('false', allow_error=True)

    @sre_state
    def hostcb(self):
        self.host_callback(self._cb)

    def _cb(self):
        self.seen.append('cb')

    @sre_state
    def fileops(self):
        self.file('m1', '/etc/x', 'xy', permissions=0o600, owner='sre:sre')
        self.append_to_file('m1', '/etc/hosts', 'abc')
        self.idempotent_append_to_file('m1', '/etc/hosts', 'abcd', permissions=0o644)


def _run(scheme, state, machines):
    lab = MagicMock()
    lab.machines = machines
    with patch.object(state_cmd, 'log_error') as log_error:
        state_cmd.do_action_state(lab=lab, state=state, net_scheme=scheme, project_has_directory=False)
    return [c.args[0] for c in log_error.call_args_list]


class TestSinglePassApply:
    def test_state_method_runs_once(self, tmp_pub_dir):
        s = ApplyScheme(MockData())
        _run(s, 'single', {'m1': FakeMachine(), 'm2': FakeMachine()})
        assert s.calls['single'] == 1

    def test_consecutive_cmds_batched_and_split_by_file_op(self, tmp_pub_dir):
        m1, m2 = FakeMachine(), FakeMachine()
        _run(ApplyScheme(MockData()), 'single', {'m1': m1, 'm2': m2})
        assert m1.batches == [['echo a', 'echo b'], ['echo c']]
        m1.api_object.put_archive.assert_called_once()

    def test_steps_applied_in_order(self, tmp_pub_dir):
        m2 = FakeMachine()
        _run(ApplyScheme(MockData()), 'single', {'m1': FakeMachine(), 'm2': m2})
        assert m2.batches == [['exit 3', 'false'], ['echo d']]

    def test_timeouts_forwarded(self, tmp_pub_dir):
        m1 = FakeMachine()
        _run(ApplyScheme(MockData()), 'single', {'m1': m1, 'm2': FakeMachine()})
        assert m1.timeouts['echo b'] == 7
        assert m1.timeouts['echo a'] == params.default_state_cmd_timeout

    def test_results_recorded(self, tmp_pub_dir):
        m1 = FakeMachine({'echo a': ('a\n', 0)})
        s = ApplyScheme(MockData())
        _run(s, 'single', {'m1': m1, 'm2': FakeMachine({'exit 3': ('', 3)})})
        assert s._cmd_results[('m1', 1)][('echo a', params.default_state_cmd_timeout)] == ('a\n', 0)
        assert s._cmd_results[('m2', 1)][('exit 3', params.default_state_cmd_timeout)] == ('', 3)

    def test_nonzero_exit_warns_unless_allowed(self, tmp_pub_dir):
        m2 = FakeMachine({'exit 3': ('', 3), 'false': ('', 1)})
        msgs = _run(ApplyScheme(MockData()), 'single', {'m1': FakeMachine(), 'm2': m2})
        assert any('exit 3' in m and 'code=3' in m for m in msgs)
        assert not any('false' in m for m in msgs)

    def test_no_warning_when_all_succeed(self, tmp_pub_dir):
        msgs = _run(ApplyScheme(MockData()), 'single', {'m1': FakeMachine(), 'm2': FakeMachine()})
        assert msgs == []

    def test_missing_result_warns(self, tmp_pub_dir):
        m1 = FakeMachine()
        m1.api_object.exec_run.side_effect = None
        m1.api_object.exec_run.return_value = (0, _exetests_output(
            (params.default_state_cmd_timeout, 'echo a', '', 0)))
        msgs = _run(ApplyScheme(MockData()), 'single', {'m1': m1, 'm2': FakeMachine()})
        assert any('echo b' in m and 'no result' in m for m in msgs)

    def test_exetests_failure_warns(self, tmp_pub_dir):
        m1 = FakeMachine()
        m1.api_object.exec_run.side_effect = None
        m1.api_object.exec_run.return_value = (1, b'')
        msgs = _run(ApplyScheme(MockData()), 'single', {'m1': m1, 'm2': FakeMachine()})
        assert any('exetests error on m1' in m for m in msgs)

    def test_machines_without_ops_untouched(self, tmp_pub_dir):
        m3 = FakeMachine()
        _run(ApplyScheme(MockData()), 'single', {'m1': FakeMachine(), 'm2': FakeMachine(), 'm3': m3})
        assert m3.batches == []
        m3.api_object.exec_run.assert_not_called()


class TestMultiPassApply:
    def test_step2_command_uses_step1_result(self, tmp_pub_dir):
        m1 = FakeMachine({'cat /etc/hostname': ('h1\n', 0)})
        m2 = FakeMachine()
        s = ApplyScheme(MockData())
        _run(s, 'multi', {'m1': m1, 'm2': m2})
        assert s.calls['multi'] == 3
        assert s.seen == ['', 'h1\n', 'h1\n']
        assert m2.batches == [['echo h1']]

    def test_already_applied_step_not_rerun(self, tmp_pub_dir):
        m1 = FakeMachine({'cat /etc/hostname': ('h1\n', 0)})
        _run(ApplyScheme(MockData()), 'multi', {'m1': m1, 'm2': FakeMachine()})
        assert m1.batches == [['cat /etc/hostname']]


class TestHostCmdApply:
    def test_result_recorded_and_used_at_next_step(self, tmp_pub_dir, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'shell')
        m1 = FakeMachine()
        s = ApplyScheme(MockData())
        lab = MagicMock()
        lab.machines = {'m1': m1}
        with patch.object(state_cmd, 'run_host_command', return_value=('hosty\n', 0)) as rhc, \
                patch.object(state_cmd, 'log_error') as log_error:
            state_cmd.do_action_state(lab=lab, state='hostmulti', net_scheme=s, project_has_directory=False)
        rhc.assert_called_once_with('hostname', params.default_state_cmd_timeout,
                                    cwd=params.files_dir(RUNNING_LAB))
        assert s.seen == [('', 0), ('hosty\n', 0), ('hosty\n', 0)]
        assert m1.batches == [['echo hosty']]
        log_error.assert_not_called()
        import os
        assert os.path.isdir(params.files_dir(RUNNING_LAB))

    def test_nonzero_exit_warns(self, tmp_pub_dir, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'shell')
        s = ApplyScheme(MockData())
        lab = MagicMock()
        lab.machines = {'m1': FakeMachine()}
        with patch.object(state_cmd, 'run_host_command', return_value=('', 2)), \
                patch.object(state_cmd, 'log_error') as log_error:
            state_cmd.do_action_state(lab=lab, state='hostmulti', net_scheme=s, project_has_directory=False)
        msgs = [c.args[0] for c in log_error.call_args_list]
        assert any('host cmd error' in m and 'hostname' in m and 'code=2' in m for m in msgs)

    def test_allow_error_suppresses_warning(self, tmp_pub_dir, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'shell')
        s = ApplyScheme(MockData())
        lab = MagicMock()
        lab.machines = {}
        with patch.object(state_cmd, 'run_host_command', return_value=('', 1)), \
                patch.object(state_cmd, 'log_error') as log_error:
            state_cmd.do_action_state(lab=lab, state='hostallowed', net_scheme=s, project_has_directory=False)
        log_error.assert_not_called()
        assert s._host_cmd_results[1][('false', params.default_state_cmd_timeout)] == ('', 1)


class TestOperationsLogApply:
    """do_action_state() appends what it executed to the operations log of a debug project
    (`.private/debug_project` marker), one `stepN - on <machine|host> : ...` entry per operation."""

    @staticmethod
    def _debug_scheme():
        from test_operations_log import make_debug_project
        log_path = make_debug_project(RUNNING_LAB)
        return ApplyScheme(MockData()), log_path   # the scheme sees the marker at construction

    def test_no_marker_no_file(self, tmp_pub_dir):
        Path(params.private_lab_dir(RUNNING_LAB)).mkdir(parents=True)
        _run(ApplyScheme(MockData()), 'single', {'m1': FakeMachine(), 'm2': FakeMachine()})
        assert not Path(params.operations_log_filename(RUNNING_LAB)).exists()

    def test_single_pass_entries(self, tmp_pub_dir):
        s, log_path = self._debug_scheme()
        m1 = FakeMachine({'echo a': ('a\n', 0)})
        m2 = FakeMachine({'exit 3': ('', 3), 'false': ('', 1)})
        _run(s, 'single', {'m1': m1, 'm2': m2})
        lines = log_path.read_text().split('\n')
        assert lines[0].startswith('=== ') and lines[0].endswith('  state single')
        i = lines.index('step1 - on m1 : echo a')
        assert lines[i:i + 5] == ['step1 - on m1 : echo a', '    a', '    exit code 0',
                                  'step1 - on m1 : echo b', '    exit code 0']
        assert 'step1 - on m1 : file /etc/x (0o644 root:root, 1 B)' in lines
        assert lines.index('step1 - on m1 : file /etc/x (0o644 root:root, 1 B)') < lines.index('step1 - on m1 : echo c')
        j = lines.index('step1 - on m2 : exit 3')
        assert lines[j:j + 4] == ['step1 - on m2 : exit 3', '    exit code 3', 'step1 - on m2 : false', '    exit code 1']
        step1 = [k for k, l in enumerate(lines) if l.startswith('step1 ')]
        step2 = [k for k, l in enumerate(lines) if l.startswith('step2 ')]
        assert step2 == [len(lines) - 3] and max(step1) < min(step2)
        assert lines[-3:] == ['step2 - on m2 : echo d', '    exit code 0', '']

    def test_file_ops_described(self, tmp_pub_dir):
        s, log_path = self._debug_scheme()
        _run(s, 'fileops', {'m1': FakeMachine()})
        lines = log_path.read_text().split('\n')
        assert lines[1:4] == ['step1 - on m1 : file /etc/x (0o600 sre:sre, 2 B)',
                              'step1 - on m1 : append /etc/hosts (3 B)',
                              'step1 - on m1 : idempotent append /etc/hosts (0o644, 4 B)']

    def test_host_cmd_and_callback(self, tmp_pub_dir):
        s, log_path = self._debug_scheme()
        with patch.object(state_cmd, 'run_host_command', return_value=('hosty\n', 0)):
            _run(s, 'hostmulti', {'m1': FakeMachine()})
        lines = log_path.read_text().split('\n')
        assert lines[1:4] == ['step1 - on host : hostname', '    hosty', '    exit code 0']
        assert lines[4:6] == ['step2 - on m1 : echo hosty', '    exit code 0']
        _run(s, 'hostcb', {'m1': FakeMachine()})
        lines = log_path.read_text().split('\n')
        assert lines[-3:] == ['=== ' + lines[-3][4:], 'step1 - on host : callback _cb', '']
        assert s.seen[-1] == 'cb'

    def test_missing_result_and_exetests_failure(self, tmp_pub_dir):
        s, log_path = self._debug_scheme()
        m1 = FakeMachine()
        m1.api_object.exec_run.side_effect = None
        m1.api_object.exec_run.return_value = (1, _exetests_output(
            (params.default_state_cmd_timeout, 'echo a', '', 0)))
        _run(s, 'single', {'m1': m1, 'm2': FakeMachine()})
        lines = log_path.read_text().split('\n')
        assert 'step1 - on m1 : exetests error: return code 1' in lines
        i = lines.index('step1 - on m1 : echo b')
        assert lines[i + 1] == '    no result'

    def test_state_files_logged(self, tmp_pub_dir, tmp_lab_dir, monkeypatch):
        s, log_path = self._debug_scheme()
        srelab_dir = tmp_lab_dir / 'test' / 'test1'
        (srelab_dir / 'single' / 'm1').mkdir(parents=True)
        (srelab_dir / 'single' / 'm1' / 'f').write_text('f')
        (srelab_dir / 'single' / 'all').mkdir()
        (srelab_dir / 'single' / 'all' / 'g').write_text('g')
        monkeypatch.setattr(params, 'get_srelab_dir', lambda running_lab_name: str(srelab_dir))
        lab = MagicMock()
        lab.machines = {'m1': FakeMachine(), 'm2': FakeMachine(), 'm3': FakeMachine()}
        with patch.object(state_cmd, 'log_error'):
            state_cmd.do_action_state(lab=lab, state='single', net_scheme=s, project_has_directory=True)
        lines = log_path.read_text().split('\n')
        m1_dir, all_dir = (srelab_dir / 'single' / 'm1').resolve(), (srelab_dir / 'single' / 'all').resolve()
        assert lines[1:3] == [f'step0 - on m1 : state files {m1_dir}, {all_dir}',
                              f'step0 - on m2 : state files {all_dir}']
        assert lines[3] == f'step0 - on m3 : state files {all_dir}'
        assert lines[4].startswith('step1 ')


class TestCopyStateFilesReturn:
    def test_returns_pushed_dirs_per_machine(self, tmp_lab_dir):
        from SRE.files_transfert import copy_state_files
        srelab_dir = tmp_lab_dir / 'lab'
        (srelab_dir / 'final' / 'm1').mkdir(parents=True)
        (srelab_dir / 'final' / 'm1' / 'f').write_text('f')
        lab = MagicMock()
        lab.machines = {'m1': FakeMachine(), 'm2': FakeMachine()}
        assert copy_state_files(lab=lab, state='final', srelab_dir=str(srelab_dir)) == {
            'm1': [str((srelab_dir / 'final' / 'm1').resolve())]}
        assert lab.machines['m2'].api_object.put_archive.call_count == 0

    def test_initial_without_dirs_gives_empty_lists(self, tmp_lab_dir):
        from SRE.files_transfert import copy_state_files
        lab = MagicMock()
        lab.machines = {'m1': FakeMachine()}
        assert copy_state_files(lab=lab, state='initial', srelab_dir=str(tmp_lab_dir)) == {'m1': []}
        lab.machines['m1'].api_object.put_archive.assert_called_once()
