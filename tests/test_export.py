"""Tests for export.py: lab.conf generation and file collection logic."""
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from SRE.lib_sre import Data0, NetScheme0, Machine, Network, NetAdapter, _FileOp, _AppendOp
from SRE.command.export import _build_lab_conf, _lab_display_name, _random_token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


RUNNING_LAB = '20260101000000@@@test/mylab@@@user'


class TwoMachineScheme(NetScheme0):
    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)
        self.net1 = Network(name='net1')
        self.net2 = Network(name='net2')
        self.m1 = Machine(name='m1', image='ubuntu:22.04')
        self.m2 = Machine(name='m2')
        NetAdapter(machine=self.m1, network=self.net1, interface=0)
        NetAdapter(machine=self.m2, network=self.net1, interface=0)
        NetAdapter(machine=self.m1, network=self.net2, interface=1)

    def initial(self):
        self.cmd('m1', 'echo hi')
        self.file('m1', '/etc/config', content=b'hello')
        self.append_to_file('m2', '/etc/hosts', content=b'10.0.0.2 m2\n')
        self.append_to_file('m2', '/etc/hosts', content=b'10.0.0.1 m1\n')


def make_scheme():
    return TwoMachineScheme(MockData(x=0))


# ---------------------------------------------------------------------------
# _lab_display_name
# ---------------------------------------------------------------------------

class TestLabDisplayName:
    def test_last_path_component(self):
        assert _lab_display_name('20260101@@@test/mylab@@@user') == 'mylab'

    def test_strips_py_suffix(self):
        assert _lab_display_name('20260101@@@test/mylab.py@@@user') == 'mylab'

    def test_top_level_lab(self):
        assert _lab_display_name('20260101@@@standalone@@@user') == 'standalone'


# ---------------------------------------------------------------------------
# _build_lab_conf
# ---------------------------------------------------------------------------

def _flatten_ops(scheme, state):
    """Return flat {machine: [ops]} from compute_state_ops, in step order."""
    ops_by_step, _ = scheme.compute_state_ops(state)
    ops: dict = {}
    for step in sorted(ops_by_step):
        for machine, op_list in ops_by_step[step].items():
            ops.setdefault(machine, []).extend(op_list)
    return ops


class TestBuildLabConf:
    def _conf(self, extra_cmds=None):
        s = make_scheme()
        ops = _flatten_ops(s, 'initial')
        return s, ops, _build_lab_conf(s, ops, extra_cmds or {})

    def test_interface_lines_present(self):
        _, _, conf = self._conf()
        assert 'm1[0]="net1"' in conf
        assert 'm1[1]="net2"' in conf
        assert 'm2[0]="net1"' in conf

    def test_image_line(self):
        _, _, conf = self._conf()
        assert 'm1[image]="ubuntu:22.04"' in conf

    def test_exec_from_cmd_op(self):
        _, _, conf = self._conf()
        assert 'm1[exec]="echo hi"' in conf

    def test_file_and_append_ops_do_not_produce_exec(self):
        """_FileOp and _AppendOp are not emitted as [exec] lines."""
        _, _, conf = self._conf()
        # No exec line for /etc/config or /etc/hosts writes
        assert '/etc/config' not in conf
        assert '/etc/hosts' not in conf

    def test_extra_cmds_appended_after_regular(self):
        extra = {'m2': ['cat /tmp/x >> /etc/hosts', 'rm /tmp/x']}
        _, _, conf = self._conf(extra_cmds=extra)
        assert 'm2[exec]="cat /tmp/x >> /etc/hosts"' in conf
        assert 'm2[exec]="rm /tmp/x"' in conf

    def test_blank_line_between_machines(self):
        _, _, conf = self._conf()
        assert '\n\n' in conf

    def test_machines_sorted_alphabetically(self):
        _, _, conf = self._conf()
        m1_pos = conf.index('m1[')
        m2_pos = conf.index('m2[')
        assert m1_pos < m2_pos

    def test_escaped_double_quotes_in_exec(self):
        s = make_scheme()
        ops = _flatten_ops(s, 'initial')
        ops.setdefault('m1', []).append('echo "hello world"')
        conf = _build_lab_conf(s, ops, {})
        assert r'echo \"hello world\"' in conf


# ---------------------------------------------------------------------------
# Append temp file naming
# ---------------------------------------------------------------------------

class TestAppendTempFile:
    def _collect_append_info(self, scheme):
        """Run the _AppendOp pre-processing and return (append_files, append_cmds)."""
        import random
        random.seed(42)
        from SRE import params
        ops = _flatten_ops(scheme, params.initial_state_name)
        append_files = {}
        append_cmds = {}
        for machine, op_list in ops.items():
            for op in op_list:
                if not isinstance(op, _AppendOp):
                    continue
                rel = op.filename.lstrip('/')
                token = _random_token()
                temp_name = f"-{Path(rel).name}_{token}_temp"
                temp_rel = str(Path(rel).parent / temp_name)
                temp_abs = '/' + temp_rel
                append_files.setdefault(machine, {})[temp_rel] = op.content
                cmds = [f"cat {temp_abs} >> /{rel}"]
                if op.permissions is not None:
                    cmds.append(f"chmod {op.permissions:o} /{rel}")
                if op.owner is not None:
                    cmds.append(f"chown {op.owner} /{rel}")
                if op.mtime is not None:
                    cmds.append(f"touch -d '@{int(op.mtime)}' /{rel}")
                cmds.append(f"rm {temp_abs}")
                append_cmds.setdefault(machine, []).extend(cmds)
        return append_files, append_cmds

    def test_temp_file_same_directory_as_target(self):
        af, _ = self._collect_append_info(make_scheme())
        temp_paths = list(af.get('m2', {}).keys())
        assert len(temp_paths) == 2  # two appends to /etc/hosts
        for tp in temp_paths:
            assert tp.startswith('etc/')          # same dir as /etc/hosts

    def test_temp_file_name_starts_with_dash(self):
        af, _ = self._collect_append_info(make_scheme())
        for temp_rel in af.get('m2', {}):
            assert Path(temp_rel).name.startswith('-')

    def test_temp_file_ends_with_temp(self):
        af, _ = self._collect_append_info(make_scheme())
        for temp_rel in af.get('m2', {}):
            assert Path(temp_rel).name.endswith('_temp')

    def test_temp_file_content_matches_append(self):
        af, _ = self._collect_append_info(make_scheme())
        contents = set(af.get('m2', {}).values())
        assert b'10.0.0.2 m2\n' in contents
        assert b'10.0.0.1 m1\n' in contents

    def test_exec_cmds_cat_then_rm(self):
        _, ac = self._collect_append_info(make_scheme())
        cmds = ac.get('m2', [])
        # For each append: a cat >> line and a rm line
        cat_cmds = [c for c in cmds if c.startswith('cat ')]
        rm_cmds  = [c for c in cmds if c.startswith('rm ')]
        assert len(cat_cmds) == 2
        assert len(rm_cmds) == 2

    def test_cat_cmd_targets_correct_file(self):
        _, ac = self._collect_append_info(make_scheme())
        cmds = ac.get('m2', [])
        cat_cmds = [c for c in cmds if c.startswith('cat ')]
        for cmd in cat_cmds:
            assert '>> /etc/hosts' in cmd


# ---------------------------------------------------------------------------
# Directory file collection (machine/ and all/)
# ---------------------------------------------------------------------------

class TestDirectoryFiles:
    def _collect_dir_files(self, initial_dir, machine_names):
        """Replicate the directory-scanning logic from action_export."""
        machine_files = {}
        if initial_dir.is_dir():
            for path in sorted(initial_dir.rglob('*')):
                if not path.is_file():
                    continue
                parts = path.relative_to(initial_dir).parts
                if len(parts) < 2:
                    continue
                first, rel = parts[0], str(Path(*parts[1:]))
                if first == 'all':
                    for mname in machine_names:
                        machine_files.setdefault(mname, {})[rel] = path.read_bytes()
                else:
                    machine_files.setdefault(first, {})[rel] = path.read_bytes()
        return machine_files

    def test_machine_specific_file(self, tmp_path):
        initial = tmp_path / 'initial'
        (initial / 'm1' / 'etc').mkdir(parents=True)
        (initial / 'm1' / 'etc' / 'motd').write_bytes(b'Welcome')
        files = self._collect_dir_files(initial, ['m1', 'm2'])
        assert 'etc/motd' in files.get('m1', {})
        assert files['m1']['etc/motd'] == b'Welcome'
        assert 'etc/motd' not in files.get('m2', {})

    def test_all_dir_goes_to_all_machines(self, tmp_path):
        initial = tmp_path / 'initial'
        (initial / 'all').mkdir(parents=True)
        (initial / 'all' / 'shared.conf').write_bytes(b'shared')
        files = self._collect_dir_files(initial, ['m1', 'm2'])
        assert files['m1']['shared.conf'] == b'shared'
        assert files['m2']['shared.conf'] == b'shared'

    def test_nested_path_preserved(self, tmp_path):
        initial = tmp_path / 'initial'
        (initial / 'm1' / 'usr' / 'local' / 'bin').mkdir(parents=True)
        (initial / 'm1' / 'usr' / 'local' / 'bin' / 'script').write_bytes(b'#!/bin/sh')
        files = self._collect_dir_files(initial, ['m1'])
        assert 'usr/local/bin/script' in files.get('m1', {})

    def test_top_level_files_in_initial_ignored(self, tmp_path):
        """Files directly under initial/ (no machine dir) are skipped."""
        initial = tmp_path / 'initial'
        initial.mkdir()
        (initial / 'orphan.txt').write_bytes(b'ignored')
        files = self._collect_dir_files(initial, ['m1'])
        assert files == {}
