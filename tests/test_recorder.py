"""Tests for the session-recorder selection in SRE.command.connect._exec_recorder.

The helper picks `asciinema rec` when the asciinema binary is on PATH and
falls back to `script(1)` otherwise. Both branches end with `os.execvpe`,
which we mock so the test process is not actually replaced.
"""
import os
import re

import pytest

from SRE import params
from SRE.command import connect


@pytest.fixture
def captured_exec(monkeypatch):
    """Capture os.execvpe calls instead of replacing the test process."""
    calls = []

    def fake_execvpe(file, args, env):
        calls.append({'file': file, 'args': list(args), 'env': dict(env)})

    monkeypatch.setattr(connect.os, 'execvpe', fake_execvpe)
    return calls


@pytest.fixture(autouse=True)
def tmp_recorder_config_dir(monkeypatch, tmp_path):
    """Redirect params.recorder_config_dir to a writable per-test path so the
    asciinema branch's mkdirs does not try to touch /var/lib/sre/asciinema."""
    cfg = tmp_path / 'asciinema_config'
    monkeypatch.setattr(params, 'recorder_config_dir', str(cfg))
    return cfg


def _parse_record_file(args):
    """Locate the record file in either recorder's argv by its extension."""
    for a in args:
        if a.endswith('.cast') or a.endswith('.typescript'):
            return a
    raise AssertionError(f"no record file in argv: {args}")


class TestExecRecorderAsciinema:
    def test_invokes_asciinema_when_available(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which',
                            lambda name: '/usr/bin/asciinema' if name == 'asciinema' else None)

        connect._exec_recorder(str(tmp_path), 'router1', {'FOO': 'bar'},
                               ['sre', 'connect', 'lab', 'router1'])

        assert len(captured_exec) == 1
        call = captured_exec[0]
        assert call['file'] == 'asciinema'
        assert call['args'][0] == 'asciinema'
        assert call['args'][1] == 'rec'
        assert '-q' in call['args']
        # The caller's FOO=bar must survive; the recorder may add ASCIINEMA_CONFIG_HOME on top.
        assert call['env']['FOO'] == 'bar'

    def test_record_file_uses_cast_extension_and_device_prefix(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: '/usr/bin/asciinema')

        connect._exec_recorder(str(tmp_path), 'router1', {}, ['sre'])

        record_file = _parse_record_file(captured_exec[0]['args'])
        assert record_file.endswith('.cast')
        # Filename format: {device}_{YYYYmmddHHMMSS}.cast inside record_dir
        assert re.fullmatch(rf'{tmp_path}/router1_\d{{14}}\.cast', record_file)

    def test_passes_idle_time_limit_from_params(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: '/usr/bin/asciinema')
        monkeypatch.setattr(params, 'recorder_idle_time_limit', 7)

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        args = captured_exec[0]['args']
        assert '--idle-time-limit' in args
        assert args[args.index('--idle-time-limit') + 1] == '7'

    def test_wraps_inner_cmd_via_dash_c(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: '/usr/bin/asciinema')

        connect._exec_recorder(str(tmp_path), 'r1', {},
                               ['sre', 'connect', 'my lab', 'r1'])

        args = captured_exec[0]['args']
        assert '-c' in args
        # The token after -c is the shlex-joined inner command (single string).
        inner = args[args.index('-c') + 1]
        assert inner == "sre connect 'my lab' r1"

    def test_sets_asciinema_config_home_env(self, monkeypatch, captured_exec, tmp_path,
                                            tmp_recorder_config_dir):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: '/usr/bin/asciinema')

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        env = captured_exec[0]['env']
        assert env['ASCIINEMA_CONFIG_HOME'] == str(tmp_recorder_config_dir)

    def test_creates_asciinema_config_dir(self, monkeypatch, captured_exec, tmp_path,
                                          tmp_recorder_config_dir):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: '/usr/bin/asciinema')
        assert not tmp_recorder_config_dir.exists()  # precondition

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        assert tmp_recorder_config_dir.is_dir()
        # Config home must not be world-readable since records may include sensitive data.
        assert (os.stat(tmp_recorder_config_dir).st_mode & 0o777) == 0o700

    def test_existing_config_dir_is_reused(self, monkeypatch, captured_exec, tmp_path,
                                           tmp_recorder_config_dir):
        """exist_ok=True path: a pre-existing config dir is fine."""
        tmp_recorder_config_dir.mkdir(mode=0o700)
        (tmp_recorder_config_dir / 'install-id').write_text('preexisting')
        monkeypatch.setattr(connect.shutil, 'which', lambda name: '/usr/bin/asciinema')

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        # The pre-existing install-id file is left untouched.
        assert (tmp_recorder_config_dir / 'install-id').read_text() == 'preexisting'


class TestExecRecorderScriptFallback:
    def test_invokes_script_when_asciinema_missing(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: None)

        connect._exec_recorder(str(tmp_path), 'router1', {'BAR': 'baz'},
                               ['sre', 'connect', 'lab', 'router1'])

        assert len(captured_exec) == 1
        call = captured_exec[0]
        assert call['file'] == 'script'
        assert call['args'][0] == 'script'
        assert '-q' in call['args']
        assert '-f' in call['args']
        # Script branch must not leak asciinema-specific env vars.
        assert call['env'] == {'BAR': 'baz'}

    def test_record_file_uses_typescript_extension(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: None)

        connect._exec_recorder(str(tmp_path), 'router1', {}, ['sre'])

        record_file = _parse_record_file(captured_exec[0]['args'])
        assert record_file.endswith('.typescript')
        assert re.fullmatch(rf'{tmp_path}/router1_\d{{14}}\.typescript', record_file)

    def test_does_not_pass_idle_time_limit(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: None)

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        args = captured_exec[0]['args']
        assert '--idle-time-limit' not in args

    def test_wraps_inner_cmd_via_dash_c(self, monkeypatch, captured_exec, tmp_path):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: None)

        connect._exec_recorder(str(tmp_path), 'r1', {},
                               ['sre', 'connect', 'my lab', 'r1'])

        args = captured_exec[0]['args']
        assert '-c' in args
        inner = args[args.index('-c') + 1]
        assert inner == "sre connect 'my lab' r1"

    def test_does_not_create_asciinema_config_dir(self, monkeypatch, captured_exec, tmp_path,
                                                  tmp_recorder_config_dir):
        monkeypatch.setattr(connect.shutil, 'which', lambda name: None)

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        assert not tmp_recorder_config_dir.exists()


class TestActionConnectNoRecords:
    """The ``--no-records`` flag on ``sre connect`` skips the recorder branch
    entirely and is rejected in user mode."""

    @pytest.fixture
    def mocked_action_connect(self, monkeypatch, tmp_path):
        """Patch out every heavyweight dependency of ``action_connect`` so the
        test only exercises the recording-gate logic.

        Returns a dict containing handles the test can poke at:
          - ``recorder_calls``: list populated by the patched ``_exec_recorder``
          - ``set_args``: helper to install a SRE.args namespace
        """
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from SRE import params as _params
        from SRE.params import SRE
        from SRE.command import connect as _connect

        recorder_calls = []

        def fake_exec_recorder(record_dir, device, env, cmd):
            recorder_calls.append({'record_dir': record_dir, 'device': device,
                                   'env': dict(env), 'cmd': list(cmd)})

        monkeypatch.setattr(_connect, '_exec_recorder', fake_exec_recorder)

        # Skip lab-name resolution and srelab loading.
        monkeypatch.setattr(_connect, 'resolve_running_lab_name', lambda name: name)

        machine = MagicMock(name='Machine')
        machine.name = 'm1'
        machine.hidden = False
        machine.shell = None

        net_scheme = MagicMock(name='NetScheme')
        net_scheme.get_machine.return_value = machine
        net_scheme.get_machines.return_value = iter([machine])
        net_scheme.get_lab_hash.return_value = 'fakehash'

        module_rvlab = SimpleNamespace(record_sessions=True)

        monkeypatch.setattr(_connect, 'set_all_variables_for_action',
                            lambda running_lab_name: (module_rvlab, net_scheme))

        # Privilege helpers — make them no-ops.
        monkeypatch.setattr(_connect, 'drop_privileges_permanently_if_not_needed', lambda ns: None)
        monkeypatch.setattr(_connect, 'set_sudo_uid_for_username', lambda u: None)
        monkeypatch.setattr(_connect, 'drop_privileges_temporarily', lambda: None)
        monkeypatch.setattr(_connect, 'gain_privileges_if_needed', lambda ns: None)
        monkeypatch.setattr(_params, 'get_username_from_running_lab_name', lambda n: 'student')

        # Recording is enabled at the project level — only --no-records / SRE_IN_RECORDER
        # should be able to suppress it.
        monkeypatch.setattr(_connect, 'should_record_sessions', lambda mod: True)

        # Force the asciinema branch to be deterministic for the records_dir mkdir.
        monkeypatch.setattr(_params, 'records_dir', lambda n: str(tmp_path / 'records'))

        # Kathara: pretend the machine is running and connect_tty is a no-op so
        # action_connect can return cleanly when recording is skipped.
        kathara = MagicMock(name='Kathara')
        kathara.get_machine_stats.return_value = iter([SimpleNamespace(status='running')])
        kathara.connect_tty.return_value = None
        monkeypatch.setattr(_connect.Kathara, 'get_instance', staticmethod(lambda: kathara))

        # Make sure the recorder re-entry guard is not set.
        monkeypatch.delenv('SRE_IN_RECORDER', raising=False)

        def set_args(**overrides):
            ns = SimpleNamespace(
                running_lab='lab1', device='m1',
                shell=None, exec_cmd=None,
                no_records=False, user=False,
            )
            for k, v in overrides.items():
                setattr(ns, k, v)
            SRE.args = ns
            return ns

        return {'recorder_calls': recorder_calls, 'set_args': set_args,
                'kathara': kathara, 'connect': _connect}

    def test_records_by_default(self, mocked_action_connect):
        """Without --no-records, recording is invoked as before."""
        mocked_action_connect['set_args'](no_records=False, user=False)
        mocked_action_connect['connect'].action_connect()
        assert len(mocked_action_connect['recorder_calls']) == 1
        call = mocked_action_connect['recorder_calls'][0]
        assert call['device'] == 'm1'
        # The recorder receives the SRE_IN_RECORDER guard so a re-entrant exec
        # would not record again.
        assert call['env'].get('SRE_IN_RECORDER') == '1'

    def test_no_records_skips_recorder(self, mocked_action_connect):
        """With --no-records, _exec_recorder must not be called."""
        mocked_action_connect['set_args'](no_records=True, user=False)
        mocked_action_connect['connect'].action_connect()
        assert mocked_action_connect['recorder_calls'] == []
        # connect_tty still runs — the session itself is not blocked, only the recording.
        assert mocked_action_connect['kathara'].connect_tty.called

    def test_no_records_rejected_in_user_mode(self, mocked_action_connect, capsys):
        """In user mode, --no-records must be refused (privileged-only)."""
        mocked_action_connect['set_args'](no_records=True, user=True)
        with pytest.raises(SystemExit) as exc_info:
            mocked_action_connect['connect'].action_connect()
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert '--no-records' in err
        # And of course no recording happened either.
        assert mocked_action_connect['recorder_calls'] == []

    def test_user_mode_without_no_records_still_records(self, mocked_action_connect):
        """Sanity check: in user mode without --no-records, recording still runs."""
        mocked_action_connect['set_args'](no_records=False, user=True)
        mocked_action_connect['connect'].action_connect()
        assert len(mocked_action_connect['recorder_calls']) == 1


class TestExecRecorderSelection:
    """The branch is decided strictly by shutil.which('asciinema')."""

    def test_other_binaries_being_present_does_not_affect_choice(self, monkeypatch, captured_exec, tmp_path):
        # Pretend `script` exists but `asciinema` does not.
        def which(name):
            return '/usr/bin/script' if name == 'script' else None

        monkeypatch.setattr(connect.shutil, 'which', which)

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        assert captured_exec[0]['file'] == 'script'

    def test_only_asciinema_lookup_is_consulted(self, monkeypatch, captured_exec, tmp_path):
        looked_up = []

        def which(name):
            looked_up.append(name)
            return '/usr/bin/asciinema' if name == 'asciinema' else None

        monkeypatch.setattr(connect.shutil, 'which', which)

        connect._exec_recorder(str(tmp_path), 'r1', {}, ['sre'])

        assert looked_up == ['asciinema']
