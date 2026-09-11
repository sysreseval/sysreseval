"""Tests for NetScheme0: topology wiring and compute_state_ops."""
import io
import os
import stat as _stat
import subprocess
import tarfile
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from SRE import params
from SRE.lib_sre import (Data0, NetScheme0, Machine, Network, NetAdapter, sre_state,
                         _CmdOp, _FileOp, _AppendOp, _IdempotentAppendOp, _HostCmdOp, _CpToHostOp)
from SRE.files_transfert import idempotent_append_to_file_in_container


def _flat_ops(scheme, state):
    """Flatten {step: {machine: [ops]}} returned by compute_state_ops into {machine: [ops]}."""
    ops_by_step, _ = scheme.compute_state_ops(state)
    flat: dict = {}
    for step in sorted(ops_by_step):
        for machine, op_list in ops_by_step[step].items():
            flat.setdefault(machine, []).extend(op_list)
    return flat


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


RUNNING_LAB = '20260101000000@@@test/test1@@@user'


class FullScheme(NetScheme0):
    """A scheme with two networks and three machines for topology tests."""

    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)
        self.net1 = Network(name='net1')
        self.net2 = Network(name='net2')
        self.m1 = Machine(name='m1')
        self.m2 = Machine(name='m2')
        self.m3 = Machine(name='m3', allow_connection=False)
        NetAdapter(machine=self.m1, network=self.net1, interface=0)
        NetAdapter(machine=self.m2, network=self.net1, interface=0)
        NetAdapter(machine=self.m1, network=self.net2, interface=1)
        NetAdapter(machine=self.m3, network=self.net2, interface=0)

    def initial(self):
        self.cmd('m1', 'echo hello')
        self.cmd('m1', 'echo world')
        self.cmd('m2', 'touch /root/flag')
        self.file('m1', '/etc/config', content='key=value\n', permissions=0o644)
        self.file('m2', '/root/secret', content=b'topsecret', permissions=0o600,
                  owner='root:root')
        self.append_to_file('m1', '/etc/hosts', content='10.0.0.1 m1\n')
        self.append_to_file('m1', '/etc/hosts', content='10.0.0.2 m2\n')

    def state2(self):
        self.cmd('m1', 'reboot')


def make_scheme():
    return FullScheme(MockData(x=1))


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

class TestTopology:
    def test_get_machines_returns_all(self):
        s = make_scheme()
        names = {m.name for m in s.get_machines()}
        assert names == {'m1', 'm2', 'm3'}

    def test_get_networks_returns_all(self):
        s = make_scheme()
        names = {n.name for n in s.get_networks()}
        assert names == {'net1', 'net2'}

    def test_net_adapters_wired_correctly(self):
        s = make_scheme()
        assert s.net1 in s.m1.net_adapters
        assert s.net1 in s.m2.net_adapters
        assert s.net2 in s.m1.net_adapters
        assert s.net2 in s.m3.net_adapters
        assert s.net2 not in s.m2.net_adapters

    def test_interface_numbers(self):
        s = make_scheme()
        assert s.m1.net_adapters[s.net1].interface == 0
        assert s.m1.net_adapters[s.net2].interface == 1
        assert s.m2.net_adapters[s.net1].interface == 0

    def test_get_visibles_excludes_hidden(self):
        s = make_scheme()
        # m3 has allow_connection=False but is not hidden by default
        visible = list(s.get_visibles_machines())
        assert len(visible) == 3  # hidden=False for all

    def test_machine_not_found_returns_none(self):
        s = make_scheme()
        assert s.get_machine('nonexistent') is None

    def test_network_not_found_returns_none(self):
        s = make_scheme()
        assert s.get_network('nonexistent') is None


# ---------------------------------------------------------------------------
# compute_state_ops
# ---------------------------------------------------------------------------

class TestComputeStateOps:
    def test_cmd_ops_recorded(self):
        ops = _flat_ops(make_scheme(), 'initial')
        str_ops = [op for op in ops.get('m1', []) if isinstance(op, str)]
        assert 'echo hello' in str_ops
        assert 'echo world' in str_ops

    def test_cmd_op_different_machine(self):
        ops = _flat_ops(make_scheme(), 'initial')
        assert 'touch /root/flag' in ops.get('m2', [])

    def test_file_op_content_and_permissions(self):
        ops = _flat_ops(make_scheme(), 'initial')
        file_ops = [op for op in ops.get('m1', []) if isinstance(op, _FileOp)]
        assert len(file_ops) == 1
        assert file_ops[0].filename == '/etc/config'
        assert file_ops[0].content == b'key=value\n'
        assert file_ops[0].permissions == 0o644

    def test_file_op_bytes_content(self):
        ops = _flat_ops(make_scheme(), 'initial')
        file_ops = [op for op in ops.get('m2', []) if isinstance(op, _FileOp)]
        assert file_ops[0].content == b'topsecret'
        assert file_ops[0].permissions == 0o600

    def test_file_op_mtime_set(self):
        ops = _flat_ops(make_scheme(), 'initial')
        file_ops = [op for op in ops.get('m1', []) if isinstance(op, _FileOp)]
        assert file_ops[0].mtime is not None
        assert isinstance(file_ops[0].mtime, float)

    def test_append_ops_recorded(self):
        ops = _flat_ops(make_scheme(), 'initial')
        append_ops = [op for op in ops.get('m1', []) if isinstance(op, _AppendOp)]
        assert len(append_ops) == 2
        contents = [op.content for op in append_ops]
        assert b'10.0.0.1 m1\n' in contents
        assert b'10.0.0.2 m2\n' in contents

    def test_compute_resets_between_calls(self):
        s = make_scheme()
        ops1 = _flat_ops(s, 'initial')
        ops2 = _flat_ops(s, 'initial')
        # Must not accumulate: counts must be identical
        count1 = sum(len(v) for v in ops1.values())
        count2 = sum(len(v) for v in ops2.values())
        assert count1 == count2

    def test_missing_state_exits(self):
        with pytest.raises(SystemExit):
            make_scheme().compute_state_ops('nonexistent_state')

    def test_string_encoding(self):
        """str content passed to file() is encoded to bytes."""
        ops = _flat_ops(make_scheme(), 'initial')
        file_ops = [op for op in ops.get('m1', []) if isinstance(op, _FileOp)]
        assert isinstance(file_ops[0].content, bytes)

    def test_append_none_permissions_and_owner(self):
        """append_to_file without permissions/owner stores None."""
        ops = _flat_ops(make_scheme(), 'initial')
        append_ops = [op for op in ops.get('m1', []) if isinstance(op, _AppendOp)]
        for op in append_ops:
            assert op.permissions is None
            assert op.owner is None


# ---------------------------------------------------------------------------
# host_cmd() — execute_commands_on_host parameter
# ---------------------------------------------------------------------------

class HostCmdScheme(NetScheme0):
    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)

    def initial(self):
        self.host_cmd('echo hello')


class TestHostCmdParam:
    def test_shell_registers_op(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'shell')
        s = HostCmdScheme(MockData())
        _, host_ops = s.compute_state_ops('initial')
        ops = [op for step_ops in host_ops.values() for op in step_ops
               if isinstance(op, _HostCmdOp)]
        assert len(ops) == 1
        assert ops[0].command == 'echo hello'

    def test_split_registers_op(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'split')
        s = HostCmdScheme(MockData())
        _, host_ops = s.compute_state_ops('initial')
        ops = [op for step_ops in host_ops.values() for op in step_ops
               if isinstance(op, _HostCmdOp)]
        assert len(ops) == 1
        assert ops[0].command == 'echo hello'

    def test_false_exits(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', False)
        s = HostCmdScheme(MockData())
        with pytest.raises(SystemExit):
            s.compute_state_ops('initial')


# ---------------------------------------------------------------------------
# cp_to_host() — registration
# ---------------------------------------------------------------------------

def _make_tar_bytes(filename, content):
    """Build an in-memory tar archive containing a single file."""
    buf = io.BytesIO()
    raw = content if isinstance(content, bytes) else content.encode()
    with tarfile.open(fileobj=buf, mode='w:') as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


class CpToHostScheme(NetScheme0):
    """Scheme that uses cp_to_host in its initial state."""

    def __init__(self, data, dest='output/result.txt', permissions=None):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)
        self._dest = dest
        self._permissions = permissions

    def initial(self):
        if self._permissions is None:
            self.cp_to_host('m1', '/etc/passwd', self._dest)
        else:
            self.cp_to_host('m1', '/etc/passwd', self._dest,
                            permissions=self._permissions)


class TestCpToHostRegistration:
    def test_op_registered_in_machine_ops(self, tmp_pub_dir):
        s = CpToHostScheme(MockData())
        ops, _ = s.compute_state_ops('initial')
        flat = [op for step_ops in ops.values()
                for machine_ops in step_ops.values()
                for op in machine_ops
                if isinstance(op, _CpToHostOp)]
        assert len(flat) == 1

    def test_op_registered_for_correct_machine(self, tmp_pub_dir):
        s = CpToHostScheme(MockData())
        ops, _ = s.compute_state_ops('initial')
        for step_ops in ops.values():
            assert 'm1' in step_ops

    def test_op_src_path(self, tmp_pub_dir):
        s = CpToHostScheme(MockData())
        ops, _ = s.compute_state_ops('initial')
        flat = [op for step_ops in ops.values()
                for machine_ops in step_ops.values()
                for op in machine_ops
                if isinstance(op, _CpToHostOp)]
        assert flat[0].src_path == '/etc/passwd'

    def test_op_dest_path_inside_files_dir(self, tmp_pub_dir):
        s = CpToHostScheme(MockData(), dest='output/result.txt')
        ops, _ = s.compute_state_ops('initial')
        flat = [op for step_ops in ops.values()
                for machine_ops in step_ops.values()
                for op in machine_ops
                if isinstance(op, _CpToHostOp)]
        files_dir = params.files_dir(RUNNING_LAB)
        assert flat[0].dest_path.startswith(files_dir)
        assert flat[0].dest_path.endswith('output/result.txt')

    def test_op_not_in_host_ops(self, tmp_pub_dir):
        s = CpToHostScheme(MockData())
        _, host_ops = s.compute_state_ops('initial')
        assert not any(isinstance(op, _CpToHostOp)
                       for step_ops in host_ops.values()
                       for op in step_ops)

    def test_path_traversal_rejected(self, tmp_pub_dir):
        s = CpToHostScheme(MockData(), dest='../../../etc/shadow')
        with pytest.raises(SystemExit):
            s.compute_state_ops('initial')

    def test_dest_at_files_dir_root(self, tmp_pub_dir):
        """A plain filename (no subdir) is valid."""
        s = CpToHostScheme(MockData(), dest='flat.txt')
        ops, _ = s.compute_state_ops('initial')
        flat = [op for step_ops in ops.values()
                for machine_ops in step_ops.values()
                for op in machine_ops
                if isinstance(op, _CpToHostOp)]
        assert len(flat) == 1

    def test_step_parameter(self, tmp_pub_dir):
        """cp_to_host with step=2 is placed under step 2."""
        class StepScheme(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)

            def initial(self):
                self.cp_to_host('m1', '/tmp/x', 'x.txt', step=2)

        s = StepScheme(MockData())
        ops, _ = s.compute_state_ops('initial')
        assert 2 in ops
        assert 'm1' in ops[2]

    def test_default_permissions_is_none(self, tmp_pub_dir):
        """Omitting permissions leaves the op's permissions at None."""
        s = CpToHostScheme(MockData())
        ops, _ = s.compute_state_ops('initial')
        flat = [op for step_ops in ops.values()
                for machine_ops in step_ops.values()
                for op in machine_ops
                if isinstance(op, _CpToHostOp)]
        assert flat[0].permissions is None

    def test_permissions_argument_stored_on_op(self, tmp_pub_dir):
        """An explicit permissions value is stored on the registered op."""
        class PermScheme(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)

            def initial(self):
                self.cp_to_host('m1', '/tmp/k', 'k', permissions=0o600)

        s = PermScheme(MockData())
        ops, _ = s.compute_state_ops('initial')
        flat = [op for step_ops in ops.values()
                for machine_ops in step_ops.values()
                for op in machine_ops
                if isinstance(op, _CpToHostOp)]
        assert flat[0].permissions == 0o600


# ---------------------------------------------------------------------------
# cp_to_host() — execution
# ---------------------------------------------------------------------------

class TestCpToHostExecution:
    """Test the do_action_state execution path for _CpToHostOp."""

    def _run(self, tmp_pub_dir, dest, file_content, monkeypatch, permissions=None,
             chmod_calls=None):
        """
        Run do_action_state with a scheme that calls cp_to_host, using a fake
        Docker API that returns `file_content` from get_archive.
        """
        from SRE.command.state import do_action_state

        tar_bytes = _make_tar_bytes('passwd', file_content)

        machine_api = MagicMock()
        machine_api.get_archive.return_value = ([tar_bytes], {})

        machine_mock = MagicMock()
        machine_mock.api_object = machine_api

        lab_mock = MagicMock()
        lab_mock.machines = {'m1': machine_mock}

        scheme = CpToHostScheme(MockData(), dest=dest, permissions=permissions)

        monkeypatch.setattr(params, 'get_srelab_dir', lambda running_lab_name: None)
        monkeypatch.setattr('SRE.command.state.deploy_exetests', lambda lab: None)
        chown_calls = []
        monkeypatch.setattr(os, 'chown', lambda path, uid, gid: chown_calls.append((path, uid, gid)))
        if chmod_calls is not None:
            real_chmod = os.chmod
            monkeypatch.setattr(os, 'chmod',
                                lambda path, mode: chmod_calls.append((path, mode)))

        do_action_state(lab=lab_mock, state='initial', net_scheme=scheme,
                        project_has_directory=False)
        return chown_calls

    def test_file_written_with_correct_content(self, tmp_pub_dir, monkeypatch):
        content = b'root:x:0:0:root:/root:/bin/bash\n'
        self._run(tmp_pub_dir, 'passwd_copy.txt', content, monkeypatch)
        dest = params.files_dir(RUNNING_LAB) + '/passwd_copy.txt'
        assert open(dest, 'rb').read() == content

    def test_subdirectory_created(self, tmp_pub_dir, monkeypatch):
        self._run(tmp_pub_dir, 'subdir/nested/out.txt', b'data', monkeypatch)
        dest = params.files_dir(RUNNING_LAB) + '/subdir/nested/out.txt'
        assert os.path.isfile(dest)

    def test_chown_called_with_sre_uid_gid(self, tmp_pub_dir, monkeypatch):
        chown_calls = self._run(tmp_pub_dir, 'f.txt', b'x', monkeypatch)
        assert len(chown_calls) == 1
        _, uid, gid = chown_calls[0]
        assert uid == params.sre_uid
        assert gid == -1

    def test_chown_called_on_correct_path(self, tmp_pub_dir, monkeypatch):
        chown_calls = self._run(tmp_pub_dir, 'f.txt', b'x', monkeypatch)
        expected = params.files_dir(RUNNING_LAB) + '/f.txt'
        assert chown_calls[0][0] == expected

    def test_get_archive_called_with_src_path(self, tmp_pub_dir, monkeypatch):
        from SRE.command.state import do_action_state

        tar_bytes = _make_tar_bytes('x', b'hello')
        machine_api = MagicMock()
        machine_api.get_archive.return_value = ([tar_bytes], {})
        machine_mock = MagicMock()
        machine_mock.api_object = machine_api
        lab_mock = MagicMock()
        lab_mock.machines = {'m1': machine_mock}

        scheme = CpToHostScheme(MockData(), dest='out.txt')
        monkeypatch.setattr(params, 'get_srelab_dir', lambda running_lab_name: None)
        monkeypatch.setattr('SRE.command.state.deploy_exetests', lambda lab: None)
        monkeypatch.setattr(os, 'chown', lambda *a: None)

        do_action_state(lab=lab_mock, state='initial', net_scheme=scheme,
                        project_has_directory=False)

        machine_api.get_archive.assert_called_once_with('/etc/passwd')

    def test_no_chmod_when_permissions_omitted(self, tmp_pub_dir, monkeypatch):
        """Default behaviour: cp_to_host without permissions leaves file mode untouched."""
        chmod_calls = []
        self._run(tmp_pub_dir, 'f.txt', b'x', monkeypatch,
                  permissions=None, chmod_calls=chmod_calls)
        dest = params.files_dir(RUNNING_LAB) + '/f.txt'
        assert all(path != dest for path, _ in chmod_calls)

    def test_chmod_called_with_requested_permissions(self, tmp_pub_dir, monkeypatch):
        """An explicit permissions value triggers os.chmod(dest, mode)."""
        chmod_calls = []
        self._run(tmp_pub_dir, 'key', b'priv', monkeypatch,
                  permissions=0o600, chmod_calls=chmod_calls)
        dest = params.files_dir(RUNNING_LAB) + '/key'
        assert (dest, 0o600) in chmod_calls

    def test_chmod_applied_on_disk(self, tmp_pub_dir, monkeypatch):
        """Without mocking chmod, the file on disk ends up with the requested mode."""
        self._run(tmp_pub_dir, 'key', b'priv', monkeypatch, permissions=0o600)
        dest = params.files_dir(RUNNING_LAB) + '/key'
        mode = _stat.S_IMODE(os.stat(dest).st_mode)
        assert mode == 0o600


# ---------------------------------------------------------------------------
# idempotent_append_to_file() — registration
# ---------------------------------------------------------------------------

class TestIdempotentAppendRegistration:
    def _scheme(self, content, **kwargs):
        class S(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)
            def initial(self):
                self.idempotent_append_to_file('m1', '/etc/hosts', content, **kwargs)
        return S(MockData())

    def test_op_is_idempotent_append_type(self):
        ops = _flat_ops(self._scheme('hello\n'), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert len(iops) == 1

    def test_not_a_plain_append_op(self):
        ops = _flat_ops(self._scheme('hello\n'), 'initial')
        assert not any(isinstance(op, _AppendOp) for op in ops.get('m1', []))

    def test_string_content_encoded_to_bytes(self):
        ops = _flat_ops(self._scheme('hello\n'), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert iops[0].content == b'hello\n'

    def test_bytes_content_preserved(self):
        ops = _flat_ops(self._scheme(b'\x00\xff'), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert iops[0].content == b'\x00\xff'

    def test_default_permissions_owner_mtime_are_none(self):
        ops = _flat_ops(self._scheme('x'), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert iops[0].permissions is None
        assert iops[0].owner is None
        assert iops[0].mtime is None

    def test_permissions_stored(self):
        ops = _flat_ops(self._scheme('x', permissions=0o600), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert iops[0].permissions == 0o600

    def test_owner_stored(self):
        ops = _flat_ops(self._scheme('x', owner='www-data:www-data'), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert iops[0].owner == 'www-data:www-data'

    def test_mtime_stored(self):
        ops = _flat_ops(self._scheme('x', mtime=1700000000.0), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert iops[0].mtime == 1700000000.0

    def test_step_parameter(self):
        class S(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)
            def initial(self):
                self.idempotent_append_to_file('m1', '/tmp/x', 'x', step=3)
        ops, _ = S(MockData()).compute_state_ops('initial')
        assert 3 in ops
        assert 'm1' in ops[3]
        assert any(isinstance(op, _IdempotentAppendOp) for op in ops[3]['m1'])

    def test_multiple_calls_registered_independently(self):
        class S(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)
            def initial(self):
                self.idempotent_append_to_file('m1', '/etc/hosts', 'line1\n')
                self.idempotent_append_to_file('m1', '/etc/hosts', 'line2\n')
        ops = _flat_ops(S(MockData()), 'initial')
        iops = [op for op in ops.get('m1', []) if isinstance(op, _IdempotentAppendOp)]
        assert len(iops) == 2
        assert iops[0].content == b'line1\n'
        assert iops[1].content == b'line2\n'


# ---------------------------------------------------------------------------
# idempotent_append_to_file() — execution (shell logic via subprocess)
# ---------------------------------------------------------------------------

def _get_shell_cmd(content, tmpfile, **kwargs):
    """Call idempotent_append_to_file_in_container with a mock and return (cmd_str, machine_api).

    Does NOT execute the command — use this to inspect the generated shell command.
    """
    raw = content if isinstance(content, bytes) else content.encode()
    op = _IdempotentAppendOp(str(tmpfile), raw,
                             kwargs.get('permissions'), kwargs.get('owner'), kwargs.get('mtime'))
    machine_api = MagicMock()
    idempotent_append_to_file_in_container(machine_api, op)
    args, kw = machine_api.exec_run.call_args
    cmd = args[0]
    assert cmd[:2] == ["sh", "-c"], "exec_run must be called with ['sh', '-c', ...]"
    assert kw.get('workdir') == '/'
    return cmd[2], machine_api


def _invoke(content, tmpfile, **kwargs):
    """Call the function and run the captured shell command against tmpfile via subprocess."""
    cmd, machine_api = _get_shell_cmd(content, tmpfile, **kwargs)
    subprocess.run(["sh", "-c", cmd], check=True)
    return machine_api


class TestIdempotentAppendExecution:
    """Test idempotent_append_to_file_in_container via a mock machine_api.

    Content-behaviour tests run the captured shell command against real temp files.
    Command-string tests only inspect the generated command without executing it.
    """

    # --- content behaviour (shell executed against real files) ---

    def test_appends_when_file_does_not_exist(self, tmp_path):
        target = tmp_path / 'f.txt'
        _invoke('hello\n', target)
        assert target.read_bytes() == b'hello\n'

    def test_appends_when_file_is_empty(self, tmp_path):
        target = tmp_path / 'f.txt'
        target.write_bytes(b'')
        _invoke('hello\n', target)
        assert target.read_bytes() == b'hello\n'

    def test_appends_when_file_does_not_end_with_content(self, tmp_path):
        target = tmp_path / 'f.txt'
        target.write_bytes(b'existing\n')
        _invoke('new\n', target)
        assert target.read_bytes() == b'existing\nnew\n'

    def test_does_not_append_when_file_ends_with_content(self, tmp_path):
        target = tmp_path / 'f.txt'
        target.write_bytes(b'existing\nnew\n')
        _invoke('new\n', target)
        assert target.read_bytes() == b'existing\nnew\n'

    def test_does_not_double_append(self, tmp_path):
        """Calling twice on the same file leaves exactly one copy of the content."""
        target = tmp_path / 'f.txt'
        target.write_bytes(b'')
        _invoke('entry\n', target)
        _invoke('entry\n', target)
        assert target.read_bytes() == b'entry\n'

    def test_appends_binary_content(self, tmp_path):
        target = tmp_path / 'f.bin'
        target.write_bytes(b'prefix')
        _invoke(b'\x00\x01\x02', target)
        assert target.read_bytes() == b'prefix\x00\x01\x02'

    def test_does_not_append_binary_already_present(self, tmp_path):
        target = tmp_path / 'f.bin'
        target.write_bytes(b'prefix\x00\x01\x02')
        _invoke(b'\x00\x01\x02', target)
        assert target.read_bytes() == b'prefix\x00\x01\x02'

    def test_content_that_is_exact_suffix_not_appended(self, tmp_path):
        """Content matching the last N bytes exactly must not be re-appended."""
        target = tmp_path / 'f.txt'
        target.write_bytes(b'abcdef')
        _invoke(b'cdef', target)
        assert target.read_bytes() == b'abcdef'

    def test_permissions_applied(self, tmp_path):
        target = tmp_path / 'f.txt'
        target.write_bytes(b'')
        _invoke('x', target, permissions=0o600)
        mode = _stat.S_IMODE(os.stat(str(target)).st_mode)
        assert mode == 0o600

    def test_permissions_applied_even_when_content_already_present(self, tmp_path):
        """chmod must run even when no content was appended."""
        target = tmp_path / 'f.txt'
        target.write_bytes(b'x')
        _invoke('x', target, permissions=0o640)
        mode = _stat.S_IMODE(os.stat(str(target)).st_mode)
        assert mode == 0o640

    # --- command-string inspection (no shell execution) ---

    def test_exec_run_called_exactly_once(self, tmp_path):
        _, machine_api = _get_shell_cmd('x', tmp_path / 'f.txt')
        assert machine_api.exec_run.call_count == 1

    def test_no_chmod_in_cmd_when_permissions_none(self, tmp_path):
        # Use a fixed path so the temp dir name cannot accidentally contain 'chmod'
        cmd, _ = _get_shell_cmd('x', '/tmp/test_file.txt')
        assert 'chmod' not in cmd

    def test_no_chown_in_cmd_when_owner_none(self, tmp_path):
        cmd, _ = _get_shell_cmd('x', '/tmp/test_file.txt')
        assert 'chown' not in cmd

    def test_no_touch_in_cmd_when_mtime_none(self, tmp_path):
        cmd, _ = _get_shell_cmd('x', '/tmp/test_file.txt')
        assert 'touch' not in cmd

    def test_chown_in_cmd_when_owner_set(self, tmp_path):
        cmd, _ = _get_shell_cmd('x', '/tmp/test_file.txt', owner='root:root')
        assert 'chown' in cmd

    def test_mtime_in_cmd_when_set(self, tmp_path):
        """touch -d '@<epoch>' must appear in the command when mtime is provided."""
        mtime_val = 1700000000.0
        cmd, _ = _get_shell_cmd('x', '/tmp/test_file.txt', mtime=mtime_val)
        assert f"touch -d '@{int(mtime_val)}'" in cmd

    def test_chmod_in_cmd_when_permissions_set(self, tmp_path):
        cmd, _ = _get_shell_cmd('x', '/tmp/test_file.txt', permissions=0o755)
        assert 'chmod 755' in cmd


# ---------------------------------------------------------------------------
# cmd() / host_cmd() — registration and results (mirror of Grade0.test / test_host)
# ---------------------------------------------------------------------------

class CmdScheme(NetScheme0):
    """Records how many times each state method ran and what cmd() returned."""

    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)
        self.calls = 0
        self.seen = []

    def initial(self):
        self.calls += 1
        out, code = self.cmd('m1', 'date')
        self.seen.append((out, code))
        self.cmd('m1', 'date')  # duplicate: two ops, one result key
        self.cmd('m2', 'false', allow_error=True, timeout=5)
        self.file('m1', '/etc/x', 'y', step=3)

    @sre_state(user_allowed=True)
    def single(self):
        self.calls += 1
        self.cmd('m1', 'a', step=1)
        self.cmd('m2', 'b', step=3)

    @sre_state(multi_pass=True)
    def multi(self):
        self.calls += 1
        out, code = self.cmd('m1', 'cat /etc/hostname', step=1)
        self.seen.append((out, code))
        self.cmd('m1', f'echo {out.strip()}', step=3)


def _record_all(scheme, step, ops, output_for_step=None):
    """Record a fake result for every _CmdOp of *ops* (as the state applier would)."""
    for machine, machine_ops in ops.items():
        for op in machine_ops:
            if isinstance(op, _CmdOp):
                out = output_for_step(step) if output_for_step else 'real\n'
                scheme.record_cmd_result(machine, step, str(op), op.timeout, out, 0)


class TestCmdRegistration:
    def test_returns_placeholder_first(self):
        s = CmdScheme(MockData())
        assert s.cmd('m1', 'date') == ('', 0)

    def test_custom_default_value_and_code(self):
        s = CmdScheme(MockData())
        assert s.cmd('m1', 'date', default_value='x', default_code=7) == ('x', 7)

    def test_returns_recorded_result(self):
        s = CmdScheme(MockData())
        s.cmd('m1', 'date')
        s.record_cmd_result('m1', 1, 'date', params.default_state_cmd_timeout, 'Mon\n', 0)
        assert s.cmd('m1', 'date') == ('Mon\n', 0)

    def test_result_keyed_by_timeout(self):
        s = CmdScheme(MockData())
        s.record_cmd_result('m1', 1, 'date', 5, 'Mon\n', 0)
        assert s.cmd('m1', 'date', timeout=5) == ('Mon\n', 0)
        assert s.cmd('m1', 'date', timeout=6) == ('', 0)

    def test_result_keyed_by_step_and_machine(self):
        s = CmdScheme(MockData())
        s.record_cmd_result('m1', 1, 'date', 5, 'one\n', 0)
        assert s.cmd('m1', 'date', timeout=5, step=2) == ('', 0)
        assert s.cmd('m2', 'date', timeout=5) == ('', 0)

    def test_op_is_a_str_carrying_timeout(self):
        s = CmdScheme(MockData())
        ops = _flat_ops(s, 'initial')
        m1 = [op for op in ops['m1'] if isinstance(op, str)]
        assert m1 == ['date', 'date']
        assert all(isinstance(op, _CmdOp) for op in m1)
        assert m1[0].timeout == params.default_state_cmd_timeout
        m2 = [op for op in ops['m2'] if isinstance(op, _CmdOp)]
        assert m2 == ['false']
        assert m2[0].timeout == 5

    def test_duplicate_cmd_appends_twice_but_one_result_key(self):
        s = CmdScheme(MockData())
        s.compute_state_ops('initial')
        assert len(s._cmd_results[('m1', 1)]) == 1

    def test_allow_error_recorded(self):
        s = CmdScheme(MockData())
        s.compute_state_ops('initial')
        assert s.is_cmd_error_allowed('m2', 1, 'false', 5)
        assert not s.is_cmd_error_allowed('m1', 1, 'date', params.default_state_cmd_timeout)

    def test_max_step_bumped_by_cmd(self):
        s = CmdScheme(MockData())
        s.cmd('m1', 'x', step=4)
        assert s.max_step == 4

    def test_max_step_bumped_by_file_via_compute_state_ops(self):
        s = CmdScheme(MockData())
        s.compute_state_ops('initial')
        assert s.max_step == 3

    def test_compute_state_ops_without_ops_keeps_max_step(self):
        class Empty(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)

            def initial(self):
                pass

        s = Empty(MockData())
        s.compute_state_ops('initial')
        assert s.max_step == 1

    def test_reset_clears_results_and_counters(self):
        s = CmdScheme(MockData())
        s.record_cmd_result('m1', 1, 'date', 1, 'x', 0)
        s.cmd('m1', 'y', step=5, allow_error=True)
        s.reset_state_results()
        assert s.cmd('m1', 'date', timeout=1) == ('', 0)
        assert s.max_step == 1
        assert s.step == 0
        assert not s.is_cmd_error_allowed('m1', 5, 'y', params.default_state_cmd_timeout)


class TestHostCmdRegistration:
    def test_returns_placeholder_then_result(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'shell')
        s = CmdScheme(MockData())
        assert s.host_cmd('uname') == ('', 0)
        s.record_host_cmd_result(1, 'uname', params.default_state_cmd_timeout, 'Linux\n', 0)
        assert s.host_cmd('uname') == ('Linux\n', 0)

    def test_op_carries_timeout_and_allow_error(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'shell')
        s = CmdScheme(MockData())
        s.host_cmd('false', timeout=3, allow_error=True, step=2)
        op = s._host_ops[2][0]
        assert isinstance(op, _HostCmdOp)
        assert op.command == 'false'
        assert op.timeout == 3
        assert s.is_host_cmd_error_allowed(2, 'false', 3)
        assert not s.is_host_cmd_error_allowed(2, 'false', 4)
        assert s.max_step == 2

    def test_disabled_exits(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', False)
        s = CmdScheme(MockData())
        with pytest.raises(SystemExit):
            s.host_cmd('echo')


class TestOnce:
    def test_same_object_across_calls(self):
        s = CmdScheme(MockData())
        calls = []

        def factory():
            calls.append(1)
            return {}

        d1 = s.once('k', factory)
        d2 = s.once('k', factory)
        assert d1 is d2
        assert calls == [1]

    def test_distinct_keys(self):
        s = CmdScheme(MockData())
        assert s.once(('a', 1), dict) is not s.once(('a', 2), dict)

    def test_cleared_by_reset(self):
        s = CmdScheme(MockData())
        d1 = s.once('k', dict)
        s.reset_state_results()
        assert s.once('k', dict) is not d1


class TestMultiPassFlag:
    def test_default_false(self):
        assert CmdScheme.is_state_multi_pass('initial') is False
        assert CmdScheme.is_state_multi_pass('single') is False

    def test_true_when_decorated(self):
        assert CmdScheme.is_state_multi_pass('multi') is True

    def test_inherited_through_mro_when_override_is_undecorated(self):
        class Child(CmdScheme):
            def multi(self):
                super().multi()

            def initial(self):
                super().initial()

        assert Child.is_state_multi_pass('multi') is True
        assert Child.is_state_multi_pass('initial') is False

    def test_unknown_state_false(self):
        assert CmdScheme.is_state_multi_pass('nope') is False

    def test_bare_decorator_still_works(self):
        class S(NetScheme0):
            @sre_state
            def s1(self):
                pass

        assert 's1' in S.get_state_methods()
        assert S.is_state_multi_pass('s1') is False
        assert S.is_state_user_allowed('s1') is False


class TestIterStateSteps:
    def test_single_pass_calls_method_once_and_yields_registered_steps(self):
        s = CmdScheme(MockData())
        steps = list(s.iter_state_steps('single'))
        assert s.calls == 1
        assert [st for st, _, _ in steps] == [1, 3]
        assert list(steps[0][1]) == ['m1']
        assert list(steps[1][1]) == ['m2']

    def test_single_pass_sets_step_to_current_step(self):
        s = CmdScheme(MockData())
        seen = [s.step for _ in s.iter_state_steps('single')]
        assert seen == [1, 3]

    def test_single_pass_only_sees_placeholder(self):
        s = CmdScheme(MockData())
        for step, ops, _host in s.iter_state_steps('initial'):
            _record_all(s, step, ops)
        assert s.calls == 1
        assert s.seen == [('', 0)]

    def test_single_pass_flag_false(self):
        s = CmdScheme(MockData())
        flags = [s._multi_pass for _ in s.iter_state_steps('single')]
        assert flags == [False, False]

    def test_multi_pass_runs_once_per_step_and_feeds_results(self):
        s = CmdScheme(MockData())
        for step, ops, _host in s.iter_state_steps('multi'):
            _record_all(s, step, ops, output_for_step=lambda st: f'out{st}\n')
        assert s.calls == 4  # max_step == 3 → three passes plus the final one
        assert s.seen == [('', 0), ('out1\n', 0), ('out1\n', 0), ('out1\n', 0)]

    def test_multi_pass_later_step_uses_earlier_result(self):
        s = CmdScheme(MockData())
        yielded = {}
        for step, ops, _host in s.iter_state_steps('multi'):
            yielded[step] = {m: [str(op) for op in mops] for m, mops in ops.items()}
            _record_all(s, step, ops, output_for_step=lambda st: 'h1\n')
        assert yielded == {1: {'m1': ['cat /etc/hostname']}, 2: {}, 3: {'m1': ['echo h1']}}
        assert s.calls == 4

    def test_multi_pass_flag_true_during_run(self):
        s = CmdScheme(MockData())
        flags = [s._multi_pass for _ in s.iter_state_steps('multi')]
        assert flags == [True, True, True]

    def test_multi_pass_single_step_runs_twice(self):
        class M(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)
                self.calls = 0
                self.seen = []

            @sre_state(multi_pass=True)
            def initial(self):
                self.calls += 1
                self.seen.append(self.cmd('m1', 'x'))

        s = M(MockData())
        for step, ops, _host in s.iter_state_steps('initial'):
            _record_all(s, step, ops)
        assert s.calls == 2  # register, then a final call that sees the result
        assert s.seen == [('', 0), ('real\n', 0)]

    def test_op_registered_in_final_pass_extends_loop(self):
        # Like a late self.test(step=N) in grade(): a step-2 op that only exists once the
        # step-1 result is known is registered by the final call, which extends the loop.
        class M(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)
                self.calls = 0

            @sre_state(multi_pass=True)
            def initial(self):
                self.calls += 1
                out, _ = self.cmd('m1', 'x')
                if out == 'go\n':
                    self.cmd('m1', 'y', step=2)

        s = M(MockData())
        yielded = []
        for step, ops, _host in s.iter_state_steps('initial'):
            yielded.append(step)
            _record_all(s, step, ops, output_for_step=lambda st: 'go\n')
        assert yielded == [1, 2]
        assert s.calls == 3
        assert s.cmd('m1', 'y', step=2) == ('go\n', 0)

    def test_unconditional_later_step_op_can_depend_on_result(self):
        class M(NetScheme0):
            def __init__(self, data):
                super().__init__(data=data, running_lab_name=RUNNING_LAB)
                self.calls = 0

            @sre_state(multi_pass=True)
            def initial(self):
                self.calls += 1
                out, _ = self.cmd('m1', 'x')
                self.cmd('m1', 'y' if out == 'go\n' else 'true', step=2)

        s = M(MockData())
        yielded = {}
        for step, ops, _host in s.iter_state_steps('initial'):
            yielded[step] = [str(op) for op in ops.get('m1', [])]
            _record_all(s, step, ops, output_for_step=lambda st: 'go\n')
        assert s.calls == 3
        assert yielded == {1: ['x'], 2: ['y']}

    def test_resets_previous_results(self):
        s = CmdScheme(MockData())
        s.record_cmd_result('m1', 1, 'cat /etc/hostname', params.default_state_cmd_timeout, 'old\n', 0)
        for step, ops, _host in s.iter_state_steps('multi'):
            _record_all(s, step, ops, output_for_step=lambda st: 'new\n')
        assert s.seen[0] == ('', 0)


class TestDebugOpLogging:
    def test_multi_pass_prints_each_op_once_with_final_content(self, mock_sre_args, capsys):
        mock_sre_args.debug = True
        s = CmdScheme(MockData())
        for step, ops, _host in s.iter_state_steps('multi'):
            _record_all(s, step, ops, output_for_step=lambda st: 'h1\n')
        err = capsys.readouterr().err
        assert err.count('CMD (step=1') == 1
        assert err.count('CMD (step=3') == 1
        assert 'echo h1' in err

    def test_single_pass_prints_every_registration(self, mock_sre_args, capsys):
        mock_sre_args.debug = True
        s = CmdScheme(MockData())
        list(s.iter_state_steps('initial'))
        err = capsys.readouterr().err
        assert err.count('CMD (step=1') == 3   # date, date, false
        assert err.count('FILE (step=3') == 1

    def test_nothing_printed_without_debug(self, capsys):
        s = CmdScheme(MockData())
        list(s.iter_state_steps('multi'))
        assert capsys.readouterr().err == ''
