"""Tests for SRE.operations_log: the per-project operations log of debug projects (what `sre state`
and `sre eval` executed), written to <project dir>/operations.log and tailed by the GUI Log tab."""
import os
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from SRE import params, operations_log
from SRE.lib_sre import Data0, NetScheme0
from SRE.operations_log import (OperationsLog, describe_file, format_cmd, format_content, format_grade,
                                format_total)

RUNNING = '20260101000000@@@test/test1@@@user'


def make_debug_project(running_lab_name=RUNNING) -> Path:
    """Create the project dir and its debug marker; return the operations log path."""
    marker = Path(params.debug_project_marker_filename(running_lab_name))
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    return Path(params.operations_log_filename(running_lab_name))


@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


class Scheme(NetScheme0):
    def __init__(self, data, running_lab_name=RUNNING):
        super().__init__(data=data, running_lab_name=running_lab_name)


class TestEnabling:
    def test_disabled_instance_writes_nothing(self, tmp_pub_dir):
        log_path = make_debug_project()
        log = OperationsLog(RUNNING, enabled=False)
        log.begin("state x")
        log.op(1, 'm1', 'file /a (1 B)')
        log.cmd(1, 'm1', 'true', '', 0)
        assert not log.enabled
        assert not log_path.exists()

    def test_disabled_singleton(self):
        assert OperationsLog.disabled() is OperationsLog.disabled()
        assert OperationsLog.disabled().enabled is False
        assert OperationsLog.disabled().path is None

    def test_enabled_but_unused_creates_no_file(self, tmp_pub_dir):
        log_path = make_debug_project()
        log = OperationsLog(RUNNING, enabled=True)
        assert log.enabled and log.path == str(log_path)
        assert not log_path.exists()

    def test_netscheme_enabled_with_marker(self, tmp_pub_dir):
        make_debug_project()
        assert Scheme(MockData()).ops_log.enabled is True

    def test_netscheme_disabled_without_marker(self, tmp_pub_dir):
        Path(params.private_lab_dir(RUNNING)).mkdir(parents=True)
        assert Scheme(MockData()).ops_log.enabled is False


EXAMPLE = """\
=== 2026-10-02 15:01:02  state final
step1 - on m1 : ip addr add 10.0.0.1/24 dev eth0
    exit code 0
step1 - on m1 : cat /etc/hostname
    m1
    exit code 0
step1 - on m2 : file /etc/hosts (0o644 root:root, 230 B)
step2 - on host : ./gen.sh
    exit code 0

=== 2026-10-02 15:03:10  evaluation
step1 - on m1 : ip -j addr
    [{"ifindex":1,...}]
    exit code 0
"""


class TestContent:
    def test_example(self, tmp_pub_dir):
        log_path = make_debug_project()
        log = OperationsLog(RUNNING, enabled=True)
        with patch.object(operations_log, '_now', return_value=datetime(2026, 10, 2, 15, 1, 2)):
            log.begin("state final")
        log.cmds(1, 'm1', [('ip addr add 10.0.0.1/24 dev eth0', '', 0), ('cat /etc/hostname', 'm1\n', 0)])
        log.op(1, 'm2', describe_file('file', '/etc/hosts', 0o644, 'root:root', 230))
        log.cmd(2, OperationsLog.HOST, './gen.sh', '', 0)
        with patch.object(operations_log, '_now', return_value=datetime(2026, 10, 2, 15, 3, 10)):
            log.begin("evaluation")
        log.cmd(1, 'm1', 'ip -j addr', '[{"ifindex":1,...}]\n', 0)
        assert log_path.read_text() == EXAMPLE

    def test_new_instance_on_non_empty_file_separates_headers(self, tmp_pub_dir):
        log_path = make_debug_project()
        OperationsLog(RUNNING, enabled=True).begin("state a")
        OperationsLog(RUNNING, enabled=True).begin("state b")
        lines = log_path.read_text().split('\n')
        assert lines[0].endswith("  state a")
        assert lines[1] == ''
        assert lines[2].endswith("  state b")

    def test_first_header_has_no_leading_blank_line(self, tmp_pub_dir):
        log_path = make_debug_project()
        OperationsLog(RUNNING, enabled=True).begin("state a")
        assert log_path.read_text().startswith("=== ")

    def test_empty_cmds_writes_nothing(self, tmp_pub_dir):
        log_path = make_debug_project()
        OperationsLog(RUNNING, enabled=True).cmds(1, 'm1', [])
        assert not log_path.exists()

    def test_file_mode_is_0644_whatever_the_umask(self, tmp_pub_dir):
        log_path = make_debug_project()
        old = os.umask(0o077)
        try:
            OperationsLog(RUNNING, enabled=True).begin("state a")
        finally:
            os.umask(old)
        assert log_path.stat().st_mode & 0o777 == 0o644

    def test_batches_stay_contiguous_across_threads(self, tmp_pub_dir):
        log_path = make_debug_project()
        log = OperationsLog(RUNNING, enabled=True)

        def worker(machine):
            for i in range(50):
                log.cmds(1, machine, [(f'cmd{i}a', f'{machine}\n', 0), (f'cmd{i}b', '', 0),
                                      (f'cmd{i}c', 'x\ny\n', 1)])

        threads = [threading.Thread(target=worker, args=(m,)) for m in ('m1', 'm2', 'm3')]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        lines = log_path.read_text().split('\n')[:-1]
        assert len(lines) == 3 * 50 * (3 + 1 + 1 + 2 + 2)
        i = 0
        while i < len(lines):
            machine = lines[i].split(' - on ')[1].split(' : ')[0]
            batch = lines[i:i + 9]
            assert [l for l in batch if l.startswith('step')] == [
                f'step1 - on {machine} : {batch[0].split(" : ")[1]}',
                batch[3], batch[5]]
            assert all(l.split(' - on ')[1].split(' : ')[0] == machine
                       for l in batch if l.startswith('step'))
            i += 9

    def test_os_error_disables_after_one_message(self, tmp_pub_dir):
        make_debug_project()
        log = OperationsLog(RUNNING, enabled=True)
        with patch.object(operations_log.os, 'open', side_effect=PermissionError("denied")), \
                patch.object(operations_log, 'log_error') as log_error:
            log.begin("state a")
            log.cmd(1, 'm1', 'true', '', 0)
            log.op(1, 'm1', 'x')
        assert log_error.call_count == 1
        assert 'operations.log' in log_error.call_args.args[0]
        assert log.enabled is False


class TestFormatCmd:
    def test_output_indented_and_trailing_newline_stripped(self):
        assert format_cmd(1, 'm1', 'c', 'a\nb\n\n', 0) == (
            "step1 - on m1 : c\n    a\n    b\n    exit code 0\n")

    def test_empty_output_only_exit_code(self):
        assert format_cmd(3, 'host', 'c', '', 7) == "step3 - on host : c\n    exit code 7\n"

    @pytest.mark.parametrize('code, text', [
        (-1, 'exit code -1 (timeout)'), (-2, 'exit code -2 (error)'), (None, 'no result'), (255, 'exit code 255'),
    ])
    def test_exit_code_annotations(self, code, text):
        assert format_cmd(1, 'm1', 'c', '', code).split('\n')[1] == f"    {text}"

    def test_bytes_output_decoded(self):
        assert '    caf\xe9\n' in format_cmd(1, 'm1', 'c', 'caf\xe9\n'.encode(), 0)

    def test_truncation(self, monkeypatch):
        monkeypatch.setattr(params, 'operations_log_max_output_chars', 10)
        out = format_cmd(1, 'm1', 'c', 'abcdefghij' + 'K' * 5, 0)
        assert out == ("step1 - on m1 : c\n    abcdefghij\n    ... (5 more characters truncated)\n"
                       "    exit code 0\n")

    def test_truncation_disabled_with_none(self):
        out = format_cmd(1, 'm1', 'c', 'x' * 100000, 0, max_chars=None if False else 10 ** 9)
        assert 'truncated' not in out


@pytest.mark.parametrize('args, expected', [
    (('file', '/etc/hosts', 0o644, 'root:root', 230), 'file /etc/hosts (0o644 root:root, 230 B)'),
    (('append', '/etc/hosts', None, 'root:root', 12), 'append /etc/hosts (root:root, 12 B)'),
    (('append', '/etc/hosts', 0o600, None, 12), 'append /etc/hosts (0o600, 12 B)'),
    (('idempotent append', '/etc/hosts', None, None, 12), 'idempotent append /etc/hosts (12 B)'),
    (('copy to host /a ->', '/b', None, None, 4096), 'copy to host /a -> /b (4096 B)'),
])
def test_describe_file(args, expected):
    assert describe_file(*args) == expected


class TestFormatContent:
    """Content of a file operation, written below its line."""

    def test_text_bytes_indented_trailing_newline_stripped(self):
        assert format_content(b'a\nb\n') == '    a\n    b\n'

    def test_str_and_utf8(self):
        assert format_content('x') == '    x\n'
        assert format_content('caf\xe9\n'.encode()) == '    caf\xe9\n'

    def test_inner_blank_lines_kept(self):
        assert format_content(b'a\n\nb') == '    a\n    \n    b\n'

    @pytest.mark.parametrize('content', [b'', '', b'\n'])
    def test_empty_gives_nothing(self, content):
        assert format_content(content) == ''

    @pytest.mark.parametrize('content', [b'\xff\xfe\x01', b'abc\x00def', b'\x80', 'a\x00b'])
    def test_binary_not_shown(self, content):
        assert format_content(content) == '    (binary content not shown)\n'

    def test_truncation(self, monkeypatch):
        monkeypatch.setattr(params, 'operations_log_max_output_chars', 10)
        assert format_content(b'abcdefghij' + b'K' * 5) == (
            '    abcdefghij\n    ... (5 more characters truncated)\n')


class TestOpContent:
    def test_content_written_below_the_line(self, tmp_pub_dir):
        log_path = make_debug_project()
        log = OperationsLog(RUNNING, enabled=True)
        log.op(1, 'm1', describe_file('file', '/a', 0o644, 'root:root', 4), content=b'a\nb\n')
        log.op(1, 'm1', describe_file('file', '/bin/x', 0o755, 'root:root', 3), content=b'\x00\x01\xff')
        assert log_path.read_text() == ('step1 - on m1 : file /a (0o644 root:root, 4 B)\n    a\n    b\n'
                                        'step1 - on m1 : file /bin/x (0o755 root:root, 3 B)\n'
                                        '    (binary content not shown)\n')

    def test_without_or_with_empty_content_single_line(self, tmp_pub_dir):
        log_path = make_debug_project()
        log = OperationsLog(RUNNING, enabled=True)
        log.op(1, 'host', 'callback cb')
        log.op(1, 'm1', 'file /empty (0 B)', content=b'')
        assert log_path.read_text() == 'step1 - on host : callback cb\nstep1 - on m1 : file /empty (0 B)\n'


class TestGradeLines:
    @pytest.mark.parametrize('args, kwargs, expected', [
        (('/root/secret', 0, 2), {}, 'grade - /root/secret : 0 / 2\n'),
        (('ttl', 3.0, 3), {'part': 'Routing', 'scope': 'self-eval only'},
         'grade - [Routing] ttl : 3 / 3 (self-eval only)\n'),
        (('half', 1.5, 2), {'part': None, 'scope': None}, 'grade - half : 1.5 / 2\n'),
        (('two\nlines', None, None), {}, 'grade - two lines : ? / ?\n'),
    ])
    def test_format_grade(self, args, kwargs, expected):
        assert format_grade(*args, **kwargs) == expected

    @pytest.mark.parametrize('args, expected', [
        (('self-eval', 3, 5, 12.0, 20), 'total - self-eval : 3 / 5, mark 12 / 20\n'),
        (('exo-eval', 4.5, 5, 13.4, 20), 'total - exo-eval : 4.5 / 5, mark 13.4 / 20\n'),
        (('exo-eval', 0, 0, None, 20), 'total - exo-eval : 0 / 0, no mark\n'),
        (('self-eval', 9, 10, 'A+', None), 'total - self-eval : 9 / 10, mark A+\n'),
    ])
    def test_format_total(self, args, expected):
        assert format_total(*args) == expected

    def test_lines_written_as_one_block(self, tmp_pub_dir):
        log_path = make_debug_project()
        log = OperationsLog(RUNNING, enabled=True)
        log.lines([format_grade('a', 1, 2), format_total('self-eval', 1, 2, 10.0, 20)])
        assert log_path.read_text() == 'grade - a : 1 / 2\ntotal - self-eval : 1 / 2, mark 10 / 20\n'

    def test_empty_lines_write_nothing(self, tmp_pub_dir):
        log_path = make_debug_project()
        OperationsLog(RUNNING, enabled=True).lines([])
        assert not log_path.exists()
