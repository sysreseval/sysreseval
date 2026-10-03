"""
The GUI "Log" tab of a debug project tails <project>/operations.log, the file where `sre state` /
`sre eval` append what they executed: LogView reads only the bytes written since its last refresh
(every 1 s tick), starts over when the file shrinks, decodes UTF-8 split across two reads, and the
tab is visible only when info.json says `debug_project: true`.  Offscreen Qt.
"""
import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval.view.log_view import LogView  # noqa: E402

_app = QApplication.instance() or QApplication([])

RUNNING = '20260101000000@@@test@@@user'


def _append(path: Path, data: bytes):
    with open(path, 'ab') as f:
        f.write(data)


class TestLogView:
    def test_missing_file_shows_nothing(self, tmp_path):
        view = LogView(tmp_path / 'operations.log')
        assert view.plain_text() == ''
        assert view.refresh() is False

    def test_existing_content_loaded_at_creation(self, tmp_path):
        path = tmp_path / 'operations.log'
        path.write_text("=== t  state initial\nstep1 - on m1 : true\n    exit code 0\n")
        view = LogView(path)
        assert view.plain_text() == "=== t  state initial\nstep1 - on m1 : true\n    exit code 0\n"

    def test_incremental_tail(self, tmp_path):
        path = tmp_path / 'operations.log'
        path.write_text("a\n")
        view = LogView(path)
        assert view.refresh() is False
        _append(path, b"b\n")
        assert view.refresh() is True
        assert view.plain_text() == "a\nb\n"
        _append(path, b"c\n")
        view.refresh()
        assert view.plain_text() == "a\nb\nc\n"

    def test_utf8_split_across_two_reads(self, tmp_path):
        path = tmp_path / 'operations.log'
        view = LogView(path)
        _append(path, 'caf\xe9'.encode()[:4])  # 'caf' + first byte of 'é'
        view.refresh()
        _append(path, 'caf\xe9'.encode()[4:] + b'\n')
        view.refresh()
        assert view.plain_text() == 'caf\xe9\n'
        assert '�' not in view.plain_text()

    def test_truncated_file_reloads_from_start(self, tmp_path):
        path = tmp_path / 'operations.log'
        path.write_text("old content\nmore\n")
        view = LogView(path)
        path.write_text("new\n")
        assert view.refresh() is True
        assert view.plain_text() == "new\n"

    def test_removed_file_clears(self, tmp_path):
        path = tmp_path / 'operations.log'
        path.write_text("x\n")
        view = LogView(path)
        path.unlink()
        assert view.refresh() is True
        assert view.plain_text() == ''
        path.write_text("y\n")
        view.refresh()
        assert view.plain_text() == 'y\n'

    def test_clear_only_affects_display(self, tmp_path):
        path = tmp_path / 'operations.log'
        path.write_text("a\n")
        view = LogView(path)
        view.clear()
        assert view.plain_text() == ''
        assert path.read_text() == "a\n"
        _append(path, b"b\n")
        view.refresh()
        assert view.plain_text() == "b\n"


def _write_info(project_dir: Path, debug_project: bool, instructor_mode: bool = False):
    (project_dir / params.info_json_name).write_text(json.dumps({
        "lab_name": "test", "machines": [], "questions": [], "debug_project": debug_project,
        "instructor_mode": instructor_mode}))


@pytest.mark.skipif(sys.platform != 'linux', reason="ProjectWidget's sibling views load libc.so.6: Linux only")
class TestProjectWidgetLogTab:
    @pytest.fixture
    def project_dir(self, tmp_pub_dir):
        d = Path(params.sre_projects_dir) / RUNNING
        d.mkdir(parents=True)
        return d

    def _log_tab_visible(self, widget) -> bool:
        return widget._tabs.isTabVisible(widget._tabs.indexOf(widget._log_view))

    def test_debug_project_shows_filled_log_tab(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, True)
        (project_dir / params.operations_log_name).write_text("=== t  state initial\n")
        widget = ProjectWidget(project_dir)
        assert self._log_tab_visible(widget)
        assert widget._log_view.plain_text() == "=== t  state initial\n"
        _append(project_dir / params.operations_log_name, b"step1 - on m1 : true\n    exit code 0\n")
        widget.refresh()
        assert widget._log_view.plain_text().endswith("    exit code 0\n")

    def test_normal_project_hides_log_tab(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, False)
        widget = ProjectWidget(project_dir)
        assert not self._log_tab_visible(widget)
        # info.json rewritten as a debug project (new mtime) → the tab appears on refresh
        os.utime(project_dir / params.info_json_name, (1, 1))
        _write_info(project_dir, True)
        assert widget.refresh() is True
        assert self._log_tab_visible(widget)

    def test_instructor_project_shows_log_tab_while_the_button_is_on(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, False, instructor_mode=True)
        (project_dir / params.operations_log_name).write_text("=== t  state initial\n")
        widget = ProjectWidget(project_dir)
        assert not self._log_tab_visible(widget)
        widget.set_instructor_view(True)
        assert self._log_tab_visible(widget)
        assert widget._log_view.plain_text() == "=== t  state initial\n"
        _append(project_dir / params.operations_log_name, b"step1 - on m1 : true\n    exit code 0\n")
        widget.refresh()
        assert widget._log_view.plain_text().endswith("    exit code 0\n")
        widget.set_instructor_view(False)
        assert not self._log_tab_visible(widget)

    def test_button_does_nothing_on_a_normal_project(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, False)
        widget = ProjectWidget(project_dir)
        widget.set_instructor_view(True)
        assert not self._log_tab_visible(widget)
        # info.json rewritten by `sre set-instructor-mode` → the tab appears, the button being on
        os.utime(project_dir / params.info_json_name, (1, 1))
        _write_info(project_dir, False, instructor_mode=True)
        assert widget.refresh() is True
        assert self._log_tab_visible(widget)
        # ... and disappears with `sre remove-instructor-mode`
        os.utime(project_dir / params.info_json_name, (1, 1))
        _write_info(project_dir, False)
        assert widget.refresh() is True
        assert not self._log_tab_visible(widget)
