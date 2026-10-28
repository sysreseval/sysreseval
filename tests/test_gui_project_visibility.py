"""
The project tabs of the GUI are the projects the logged-in user may act on through sre-wrapper
(`util.visible_projects`: their own and those started by root or the sre user, every project
when `params.check_project_owner` is off), and Close All Projects runs `sre stop-all`.
Offscreen Qt; the login is patched; the wrapper is replaced by a shell script recording its
arguments.
"""
import json
import os
import sys
import time
from pathlib import Path

import pytest

if sys.platform != 'linux':
    pytest.skip("the GUI loads libc.so.6: Linux only", allow_module_level=True)
pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval import main_window  # noqa: E402
from sysreseval.project_widget import ProjectWidget  # noqa: E402

_app = QApplication.instance() or QApplication([])

USER = '20260101000000@@@lab@@@user'
OTHER = '20260101000001@@@lab@@@other'
ROOT = '20260101000002@@@lab@@@root'
MACHINE = {"name": "m1", "status": "running", "allow_connection": True, "hidden": False,
           "interfaces": [{"network": "lan", "interface_name": "eth0"}], "ports": [], "bridged": False}


def _project(name: str) -> Path:
    project_dir = Path(params.sre_projects_dir) / name
    project_dir.mkdir()
    (project_dir / params.info_json_name).write_text(json.dumps({
        "lab_name": "lab", "machines": [MACHINE], "informations": "Public text.", "questions": []}))
    return project_dir


def _tabs(win) -> list[str]:
    return sorted(win.tabs.widget(i).project_dir.name for i in range(win.tabs.count())
                  if isinstance(win.tabs.widget(i), ProjectWidget))


@pytest.fixture
def projects(tmp_pub_dir, monkeypatch):
    Path(params.sre_projects_dir).mkdir()
    monkeypatch.setattr(main_window.util, 'local_username', lambda: 'user')
    return [_project(name) for name in (USER, OTHER, ROOT)]


@pytest.fixture
def window(projects):
    win = main_window.MainWindow()
    win._timer.stop()
    yield win
    win.close()
    win.deleteLater()
    _app.processEvents()


class TestVisibleProjects:
    def test_own_and_root_started_projects_only(self, window):
        assert _tabs(window) == [USER, ROOT]
        _project('20260101000003@@@lab@@@other')
        window._scan_projects()
        assert _tabs(window) == [USER, ROOT]
        mine = _project('20260101000004@@@lab@@@user')
        window._scan_projects()
        assert _tabs(window) == [USER, ROOT, mine.name]

    def test_check_off_lists_every_project(self, projects, monkeypatch):
        monkeypatch.setattr(params, 'check_project_owner', False)
        win = main_window.MainWindow()
        win._timer.stop()
        try:
            assert _tabs(win) == [USER, OTHER, ROOT]
        finally:
            win.close()
            win.deleteLater()
            _app.processEvents()

    def test_close_all_runs_stop_all(self, window, tmp_path, monkeypatch):
        log = tmp_path / 'argv'
        script = tmp_path / 'sre-wrapper'
        script.write_text(f'#!/bin/sh\necho "$@" > "{log}"\nexit 0\n')
        script.chmod(0o755)
        monkeypatch.setattr(params, 'sre_wrapper', str(script))
        window._close_all_projects()
        deadline = time.monotonic() + 5
        while not log.exists() and time.monotonic() < deadline:
            _app.processEvents()
            time.sleep(0.02)
        assert log.read_text().split() == ['stop-all']
        _app.processEvents()
