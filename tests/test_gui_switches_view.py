"""
Switches tab of the GUI: one row per network of info.json `switches` with its type (hub, switch,
manageable switch) and a Connect button on the manageable switches students may use, which opens
`sre-wrapper connect <project> <switch>` in an external terminal.  The tab is shown only when a
network is not a hub.
Offscreen Qt; no terminal is started (subprocess.Popen is recorded).
"""
import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QTranslator  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval import util  # noqa: E402
from sysreseval.view.machines_view import MachinesView  # noqa: E402
from sysreseval.view.switches_view import SwitchesView  # noqa: E402

_app = QApplication.instance() or QApplication([])

RUNNING = '20260101000000@@@test@@@user'
LINUX_ONLY = pytest.mark.skipif(sys.platform != 'linux',
                                reason="ProjectWidget's sibling views load libc.so.6: Linux only")
FR_QM = Path(__file__).parent.parent / 'translations' / 'sysreseval_fr.qm'

SWITCHES = [
    {"name": "lan", "mode": "managed", "allow_connection": True},
    {"name": "dmz", "mode": "switch", "allow_connection": True},
    {"name": "old", "mode": "hub", "allow_connection": True},
    {"name": "closed", "mode": "managed", "allow_connection": False},
]
HUBS = [{"name": "net1", "mode": "hub", "allow_connection": True},
        {"name": "net2", "mode": "hub", "allow_connection": True}]
RED = "#f0c8c8"


class FakeProc:
    def __init__(self, cmd):
        self.cmd = cmd
        self.killed = False

    def poll(self):
        return 1 if self.killed else None

    def kill(self):
        self.killed = True


@pytest.fixture
def started(monkeypatch):
    """Terminals the views start: [FakeProc, ...]."""
    procs = []

    def popen(cmd, **kwargs):
        procs.append(FakeProc(cmd))
        return procs[-1]

    monkeypatch.setattr(util.subprocess, 'Popen', popen)
    monkeypatch.setattr(params, 'terminal_cmd_prefix', ['/usr/bin/term', '--'])
    monkeypatch.setattr(params, 'terminal_title_opt', '--title')
    monkeypatch.setattr(params, 'sre_wrapper', '/opt/sre/bin/sre-wrapper')
    return procs


def _column(view, column):
    return [view.item(row, column).text() if view.item(row, column) else None for row in range(view.rowCount())]


def _button(view, row):
    widget = view.cellWidget(row, 2)
    return widget if isinstance(widget, QPushButton) else None


class TestSwitchesView:
    def test_one_row_per_network_with_its_type(self):
        view = SwitchesView(RUNNING, SWITCHES)
        assert view.rowCount() == 4
        assert _column(view, 0) == ['lan', 'dmz', 'old', 'closed']
        assert _column(view, 1) == ['Manageable switch', 'Switch', 'Hub', 'Manageable switch']

    def test_headers(self):
        view = SwitchesView(RUNNING, SWITCHES)
        assert [view.horizontalHeaderItem(i).text() for i in range(3)] == ['Name', 'Type', 'Connection']

    def test_connect_button_only_on_an_open_manageable_switch(self):
        view = SwitchesView(RUNNING, SWITCHES)
        assert _button(view, 0) is not None and _button(view, 0).text() == 'Connect'
        assert [_button(view, row) for row in (1, 2, 3)] == [None, None, None]

    def test_closed_manageable_switch_is_marked_red(self):
        view = SwitchesView(RUNNING, SWITCHES)
        assert view.item(3, 2).background().color().name() == RED
        # a hub or a plain switch has no console at all: nothing to mark
        assert view.item(1, 2).background().color().name() != RED
        assert view.item(2, 2).background().color().name() != RED

    def test_unknown_or_missing_mode_is_a_hub(self):
        view = SwitchesView(RUNNING, [{"name": "x"}])
        assert _column(view, 1) == ['Hub']
        assert _button(view, 0) is None
        assert not view.has_switches()

    def test_has_switches(self):
        assert SwitchesView(RUNNING, SWITCHES).has_switches()
        assert SwitchesView(RUNNING, [SWITCHES[1]]).has_switches()
        assert not SwitchesView(RUNNING, HUBS).has_switches()
        assert not SwitchesView(RUNNING, []).has_switches()

    def test_connect_opens_the_console_of_the_switch(self, started):
        view = SwitchesView(RUNNING, SWITCHES)
        _button(view, 0).click()
        assert [p.cmd for p in started] == [
            ['/usr/bin/term', '--title', 'test lan', '--', '/opt/sre/bin/sre-wrapper', 'connect', RUNNING, 'lan']]

    def test_each_click_opens_a_terminal_and_kill_closes_them(self, started):
        view = SwitchesView(RUNNING, SWITCHES)
        _button(view, 0).click()
        _button(view, 0).click()
        assert len(started) == 2
        view.kill_terminals()
        assert all(p.killed for p in started)

    def test_update_data(self):
        view = SwitchesView(RUNNING, HUBS)
        view.update_data(SWITCHES)
        assert view.rowCount() == 4 and view.has_switches()
        assert _button(view, 0) is not None
        # the console of lan gets closed: the button goes away
        view.update_data([dict(SWITCHES[0], allow_connection=False)])
        assert view.rowCount() == 1
        assert _button(view, 0) is None
        assert view.item(0, 2).background().color().name() == RED

    @pytest.mark.skipif(not FR_QM.exists(), reason="translations not compiled")
    def test_french(self):
        translator = QTranslator()
        assert translator.load(str(FR_QM))
        _app.installTranslator(translator)
        try:
            view = SwitchesView(RUNNING, SWITCHES)
            assert [view.horizontalHeaderItem(i).text() for i in range(3)] == ['Nom', 'Type', 'Connexion']
            assert _column(view, 1) == ['Commutateur administrable', 'Commutateur', 'Concentrateur (hub)',
                                        'Commutateur administrable']
            assert _button(view, 0).text() == 'Connecter'
        finally:
            _app.removeTranslator(translator)


class TestMachinesViewStillConnects:
    """The Machines tab shares the terminal launcher with the Switches tab."""

    MACHINES = [{"name": "m1", "allow_connection": True, "bridged": False, "x11_host": False, "ports": []},
                {"name": "m2", "allow_connection": False, "bridged": False, "x11_host": False, "ports": []}]

    def test_connect_button(self, started):
        view = MachinesView(RUNNING, self.MACHINES)
        view.cellWidget(0, 3).click()
        assert [p.cmd for p in started] == [
            ['/usr/bin/term', '--title', 'test m1', '--', '/opt/sre/bin/sre-wrapper', 'connect', RUNNING, 'm1']]
        assert view.cellWidget(1, 3) is None

    def test_kill_terminals(self, started):
        view = MachinesView(RUNNING, self.MACHINES)
        view.cellWidget(0, 3).click()
        view.kill_terminals()
        assert started[0].killed


def _write_info(project_dir: Path, **fields):
    (project_dir / params.info_json_name).write_text(json.dumps({
        "lab_name": "test", "machines": [], "informations": "Public text.", "questions": [], **fields}))


@LINUX_ONLY
class TestProjectWidget:
    @pytest.fixture
    def project_dir(self, tmp_pub_dir):
        d = Path(params.sre_projects_dir) / RUNNING
        d.mkdir(parents=True)
        return d

    def _tab_visible(self, widget) -> bool:
        return widget._tabs.isTabVisible(widget._tabs.indexOf(widget._switches_view))

    def test_tab_hidden_without_switches_key(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir)  # info.json written before the switch types existed
        assert not self._tab_visible(ProjectWidget(project_dir))

    def test_tab_hidden_with_hubs_only(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, switches=HUBS)
        assert not self._tab_visible(ProjectWidget(project_dir))

    def test_tab_shown_with_a_switch_and_lists_every_network(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, switches=SWITCHES)
        widget = ProjectWidget(project_dir)
        assert self._tab_visible(widget)
        assert widget._switches_view.rowCount() == 4
        assert widget._tabs.indexOf(widget._switches_view) == widget._tabs.indexOf(widget._machines_view) + 1

    def test_refresh_follows_info_json(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, switches=HUBS)
        widget = ProjectWidget(project_dir)
        os.utime(project_dir / params.info_json_name, (1, 1))
        _write_info(project_dir, switches=SWITCHES)
        assert widget.refresh() is True
        assert self._tab_visible(widget)

    def test_terminals_tab_has_the_open_manageable_switches(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        machines = [{"name": "m1", "allow_connection": True, "hidden": False, "interfaces": [], "ports": [],
                     "bridged": False}]
        _write_info(project_dir, machines=machines, switches=SWITCHES)
        widget = ProjectWidget(project_dir)
        terminals = widget._terminals_view
        assert [terminals.tabText(i) for i in range(terminals.count())] == ['m1', 'lan']

    def test_terminals_tab_of_a_debug_project_has_every_manageable_switch(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, switches=SWITCHES, debug_project=True)
        widget = ProjectWidget(project_dir)
        terminals = widget._terminals_view
        assert [terminals.tabText(i) for i in range(terminals.count())] == ['lan', 'closed']
