"""Tests for do_action_state(): exetests batching of cmd() ops, single- vs multi-pass
state methods, result feedback and host commands.  No Docker: containers are stand-ins
whose exec_run answers exetests batches with canned results."""
from dataclasses import dataclass
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
