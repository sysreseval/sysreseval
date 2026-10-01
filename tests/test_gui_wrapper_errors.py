"""
The GUI runs `sre-wrapper stop` / `sre-wrapper wipe` in the background.  Since `sre stop` and
`sre wipe` exit 1 with `sre: cannot remove: ...` when a directory is left behind, that failure
must reach the user in a message box instead of being silently dropped (the tab just stayed).
Offscreen Qt; the wrapper is replaced by a shell script; QMessageBox.critical is recorded.
"""
import os
import time
from pathlib import Path
from types import SimpleNamespace

import sys

import pytest

if sys.platform != 'linux':
    pytest.skip("the GUI loads libc.so.6: Linux only", allow_module_level=True)
pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval import main_window  # noqa: E402

_app = QApplication.instance() or QApplication([])

FAILURE_MESSAGE = "sre: cannot remove:\n  /home/sre/x/shared/rep_root: Permission denied"


def _fake_wrapper(tmp_path, exit_code: int, stderr: str = '', marker: Path | None = None) -> str:
    lines = ['#!/bin/sh']
    if stderr:
        lines += ["cat >&2 <<'MSG'", stderr, 'MSG']
    if marker is not None:
        lines.append(f'touch "{marker}"')
    lines.append(f'exit {exit_code}')
    script = tmp_path / f'sre-wrapper-{exit_code}'
    script.write_text('\n'.join(lines) + '\n')
    script.chmod(0o755)
    return str(script)


def _pump(predicate, timeout=5.0):
    """Process Qt events until *predicate* holds (or the timeout passes); return its last value."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _app.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


@pytest.fixture
def window(tmp_pub_dir, monkeypatch):
    Path(params.sre_projects_dir).mkdir()
    recorded = []
    monkeypatch.setattr(main_window.QMessageBox, 'critical',
                        lambda parent, title, text: recorded.append((title, text)))
    win = main_window.MainWindow()
    yield win, recorded
    win._timer.stop()
    win.close()
    win.deleteLater()
    _app.processEvents()


class TestBackgroundWrapperErrors:
    def test_wipe_failure_is_shown(self, window, tmp_path, monkeypatch):
        win, recorded = window
        monkeypatch.setattr(params, 'sre_wrapper', _fake_wrapper(tmp_path, 1, FAILURE_MESSAGE))
        win._close_all_projects()
        assert _pump(lambda: recorded), "no message box after the failing wipe"
        title, text = recorded[0]
        assert title == 'Close All Projects'
        assert "'sre wipe' failed (exit code 1)" in text
        assert '/home/sre/x/shared/rep_root: Permission denied' in text

    def test_stop_failure_names_the_project(self, window, tmp_path, monkeypatch):
        win, recorded = window
        monkeypatch.setattr(params, 'sre_wrapper', _fake_wrapper(tmp_path, 1, FAILURE_MESSAGE))
        widget = SimpleNamespace(project_dir=Path(params.sre_projects_dir) / '20260101000000@@@lab@@@em')
        win._stop_project(widget)
        assert _pump(lambda: recorded)
        title, text = recorded[0]
        assert title == 'Close Project'
        assert "'sre stop 20260101000000@@@lab@@@em' failed (exit code 1)" in text

    def test_failure_without_output_says_so(self, window, tmp_path, monkeypatch):
        win, recorded = window
        monkeypatch.setattr(params, 'sre_wrapper', _fake_wrapper(tmp_path, 3))
        win._close_all_projects()
        assert _pump(lambda: recorded)
        assert "(exit code 3)" in recorded[0][1] and '(no output)' in recorded[0][1]

    def test_missing_wrapper_is_reported(self, window, tmp_path, monkeypatch):
        win, recorded = window
        monkeypatch.setattr(params, 'sre_wrapper', str(tmp_path / 'no-such-wrapper'))
        win._close_all_projects()
        assert _pump(lambda: recorded)
        assert "'sre wipe' failed (exit code -1)" in recorded[0][1]

    def test_success_is_silent(self, window, tmp_path, monkeypatch):
        win, recorded = window
        marker = tmp_path / 'wrapper-ran'
        monkeypatch.setattr(params, 'sre_wrapper', _fake_wrapper(tmp_path, 0, marker=marker))
        win._close_all_projects()
        assert _pump(lambda: marker.exists())
        _pump(lambda: False, timeout=0.5)   # let finished() be delivered
        assert recorded == []
