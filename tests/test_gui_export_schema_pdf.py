"""
File → Export Schema to PDF: the Schema tab's drawing in a PDF the GUI writes itself (graphviz,
from info.json, no wrapper call), without the hidden machines whatever the view; on by default,
greyed when the lab sets export_schema_pdf = False and in exam mode.
Offscreen Qt; the file dialog and the message boxes are replaced.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

if sys.platform != 'linux':
    pytest.skip("the GUI loads libc.so.6: Linux only", allow_module_level=True)
pytest.importorskip('PySide6')
pytest.importorskip('graphviz')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QTranslator  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval import main_window  # noqa: E402
from sysreseval.project_widget import ProjectWidget  # noqa: E402

_app = QApplication.instance() or QApplication([])

FR_QM = Path(__file__).parent.parent / 'translations' / 'sysreseval_fr.qm'
NEEDS_NEATO = pytest.mark.skipif(shutil.which("neato") is None, reason="graphviz binaries not installed")
FAKE_PDF = b"%PDF-1.7 fake"


def _machine(name, networks, hidden=False):
    return {"name": name, "status": "running", "allow_connection": True, "hidden": hidden,
            "interfaces": [{"network": net, "interface_name": f"eth{i}"} for i, net in enumerate(networks)],
            "ports": [], "bridged": False}


MACHINES = [_machine("m1", ["lan"]), _machine("probe", ["lan", "hidden_net"], hidden=True)]


@pytest.fixture
def window(tmp_pub_dir, monkeypatch):
    """A MainWindow whose message boxes are recorded as (kind, title, text)."""
    Path(params.sre_projects_dir).mkdir()
    monkeypatch.setattr(main_window.util, 'local_username', lambda: 'user')   # the owner of the test projects
    boxes = []
    monkeypatch.setattr(main_window.QMessageBox, 'critical',
                        lambda parent, title, text: boxes.append(('critical', title, text)))
    monkeypatch.setattr(main_window.QMessageBox, 'information',
                        lambda parent, title, text: boxes.append(('information', title, text)))
    win = main_window.MainWindow()
    yield win, boxes
    win._timer.stop()
    win.close()
    win.deleteLater()
    _app.processEvents()


def _add(window, name: str, **fields) -> ProjectWidget:
    """A project tab from an info.json listing a hidden machine (as a debug project's would)."""
    project_dir = Path(params.sre_projects_dir) / name
    project_dir.mkdir()
    (project_dir / params.info_json_name).write_text(json.dumps({
        "lab_name": "test", "machines": MACHINES, "informations": "Public text.", "questions": [], **fields}))
    window.add_project(project_dir)
    return window.tabs.currentWidget()


def _choose(monkeypatch, path: str) -> list:
    """QFileDialog.getSaveFileName answers *path* ('' = cancelled) and records its arguments."""
    asked = []

    def get_save_file_name(parent, title, default, filter_):
        asked.append((title, default, filter_))
        return path, filter_

    monkeypatch.setattr(main_window.QFileDialog, 'getSaveFileName', get_save_file_name)
    return asked


def _fake_render(monkeypatch, data=FAKE_PDF) -> list:
    calls = []
    monkeypatch.setattr(ProjectWidget, 'render_schema_pdf', lambda self: calls.append(self) or data)
    return calls


class TestMenuItem:
    def test_right_after_the_kathara_export(self, window):
        win, _ = window
        actions = win._file_menu.actions()
        assert actions[actions.index(win._export_action) + 1] == win._export_schema_pdf_action
        assert win._export_schema_pdf_action.text() == "Export Schema to PDF"

    def test_enabled_by_default_and_disabled_by_the_lab(self, window):
        win, _ = window
        action = win._export_schema_pdf_action
        assert not action.isEnabled()                       # no project
        allowed = _add(win, '20260101000000@@@allowed@@@user')
        assert action.isEnabled() and win._export_action.isEnabled()
        refused = _add(win, '20260101000001@@@refused@@@user', export_schema_pdf=False)
        assert not action.isEnabled()
        assert win._export_action.isEnabled()               # the Kathara export has its own flag
        win.tabs.setCurrentWidget(allowed)
        assert action.isEnabled()
        win.tabs.setCurrentWidget(refused)
        assert not action.isEnabled()
        assert action.isVisible()                           # greyed, never hidden (unlike Save Project)

    def test_disabled_in_exam_mode(self, window):
        win, _ = window
        _add(win, '20260101000000@@@lab@@@user')
        win._refresh_file_menu_actions(True)
        assert not win._export_schema_pdf_action.isEnabled()
        win._refresh_file_menu_actions(False)
        assert win._export_schema_pdf_action.isEnabled()

    @pytest.mark.skipif(not FR_QM.exists(), reason="translations not compiled")
    def test_french_text(self, window):
        win, _ = window
        translator = QTranslator()
        assert translator.load(str(FR_QM))
        _app.installTranslator(translator)
        try:
            win._retranslate()
            assert win._export_schema_pdf_action.text() == "Exporter le schéma en PDF"
        finally:
            _app.removeTranslator(translator)
            win._retranslate()


class TestExport:
    def test_writes_the_pdf_chosen_in_the_dialog(self, window, tmp_path, monkeypatch):
        win, boxes = window
        project = _add(win, '20260101000000@@@test@@@user')
        rendered = _fake_render(monkeypatch)
        out = tmp_path / 'out.pdf'
        asked = _choose(monkeypatch, str(out))
        win._export_schema_pdf()
        assert out.read_bytes() == FAKE_PDF
        assert rendered == [project]
        assert asked == [("Export Schema to PDF", str(Path.home() / "test_schema.pdf"), "PDF files (*.pdf)")]
        assert boxes == [('information', 'Export', 'Schema exported to ' + str(out))]

    @NEEDS_NEATO
    def test_a_real_pdf_is_drawn_from_info_json(self, window, tmp_path, monkeypatch):
        win, boxes = window
        _add(win, '20260101000000@@@test@@@user', debug_project=True)
        out = tmp_path / 'real.pdf'
        _choose(monkeypatch, str(out))
        win._export_schema_pdf()
        assert out.read_bytes().startswith(b"%PDF")
        assert [kind for kind, _, _ in boxes] == ['information']

    def test_appends_the_pdf_suffix(self, window, tmp_path, monkeypatch):
        win, _ = window
        _add(win, '20260101000000@@@test@@@user')
        _fake_render(monkeypatch)
        _choose(monkeypatch, str(tmp_path / 'schema'))
        win._export_schema_pdf()
        assert (tmp_path / 'schema.pdf').read_bytes() == FAKE_PDF

    def test_cancel_renders_nothing(self, window, monkeypatch):
        win, boxes = window
        _add(win, '20260101000000@@@test@@@user')
        rendered = _fake_render(monkeypatch)
        _choose(monkeypatch, '')
        win._export_schema_pdf()
        assert rendered == [] and boxes == []

    def test_nothing_without_a_project_tab(self, window, monkeypatch):
        win, boxes = window
        asked = _choose(monkeypatch, '/nowhere/out.pdf')
        win._export_schema_pdf()
        assert asked == [] and boxes == []

    def test_rendering_failure_is_reported(self, window, tmp_path, monkeypatch):
        win, boxes = window
        _add(win, '20260101000000@@@test@@@user')

        def boom(self):
            raise subprocess.CalledProcessError(1, ['neato', '-Tpdf'], stderr=b'Error: boom')

        monkeypatch.setattr(ProjectWidget, 'render_schema_pdf', boom)
        out = tmp_path / 'out.pdf'
        _choose(monkeypatch, str(out))
        win._export_schema_pdf()
        assert not out.exists()
        assert [(kind, title) for kind, title, _ in boxes] == [('critical', 'Export Error')]
        assert boxes[0][2].startswith("Export failed:\n")

    def test_write_failure_is_reported(self, window, tmp_path, monkeypatch):
        win, boxes = window
        _add(win, '20260101000000@@@test@@@user')
        _fake_render(monkeypatch)
        _choose(monkeypatch, str(tmp_path / 'no_such_dir' / 'out.pdf'))
        win._export_schema_pdf()
        assert [(kind, title) for kind, title, _ in boxes] == [('critical', 'Export Error')]
        assert boxes[0][2].startswith("Failed to save file:\n")
