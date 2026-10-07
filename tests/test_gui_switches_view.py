"""
Networks tab of the GUI: one row per network of info.json `switches` with its type (hub, switch,
manageable switch) and a Connect button on the manageable switches students may use, which opens
`sre-wrapper connect <project> <switch>` in an external terminal.  The type of a manageable
switch closed to the students is on a red background; a debug project can connect to it all the
same (orange button, orange title in the Terminals tab).  The tab is always shown, hubs only or
not.
Offscreen Qt; no terminal is started (subprocess.Popen is recorded).
"""
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QTranslator  # noqa: E402
from PySide6.QtGui import QColor  # noqa: E402
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
GREEN = "#c8f0c8"
ORANGE = "#ffd9a0"


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

    # only the launcher of the terminals: graphviz (schema of a ProjectWidget) starts processes too
    monkeypatch.setattr(util, 'subprocess', SimpleNamespace(Popen=popen))
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

    def _type_color(self, view, row):
        return view.item(row, 1).background().color().name()

    def test_type_of_a_closed_manageable_switch_is_red(self):
        view = SwitchesView(RUNNING, SWITCHES)
        assert self._type_color(view, 3) == RED
        # an open one, a plain switch and a hub are not marked
        assert [self._type_color(view, row) != RED for row in (0, 1, 2)] == [True, True, True]

    def test_connection_column_is_not_coloured(self):
        view = SwitchesView(RUNNING, SWITCHES)
        for row in (1, 2, 3):
            assert view.item(row, 2).background().color().name() != RED
            assert view.item(row, 2).text() == ''

    def test_connect_button_of_an_open_switch_is_green(self):
        view = SwitchesView(RUNNING, SWITCHES)
        assert GREEN in _button(view, 0).styleSheet()

    def test_unknown_or_missing_mode_is_a_hub(self):
        view = SwitchesView(RUNNING, [{"name": "x"}])
        assert _column(view, 1) == ['Hub']
        assert _button(view, 0) is None

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
        assert view.rowCount() == 4
        assert _button(view, 0) is not None
        # the console of lan gets closed: the button goes away and its type turns red
        view.update_data([dict(SWITCHES[0], allow_connection=False)])
        assert view.rowCount() == 1
        assert _button(view, 0) is None
        assert view.item(0, 1).background().color().name() == RED
        # and back
        view.update_data([SWITCHES[0]])
        assert _button(view, 0) is not None
        assert view.item(0, 1).background().color().name() != RED

    @pytest.mark.skipif(not FR_QM.exists(), reason="translations not compiled")
    def test_french(self):
        translator = QTranslator()
        assert translator.load(str(FR_QM))
        _app.installTranslator(translator)
        try:
            view = SwitchesView(RUNNING, SWITCHES)
            assert [view.horizontalHeaderItem(i).text() for i in range(3)] == ['Nom', 'Type', 'Connexion']
            assert _column(view, 1) == ['Switch administrable', 'Switch', 'Hub', 'Switch administrable']
            assert _button(view, 0).text() == 'Connecter'
        finally:
            _app.removeTranslator(translator)


class TestSwitchesViewOfADebugProject:
    """A debug project may open the console of the manageable switches the lab closed."""

    def test_closed_manageable_switch_gets_a_connect_button(self, started):
        view = SwitchesView(RUNNING, SWITCHES, debug_project=True)
        button = _button(view, 3)
        assert button is not None and button.text() == 'Connect'
        button.click()
        assert [p.cmd[-4:] for p in started] == [['/opt/sre/bin/sre-wrapper', 'connect', RUNNING, 'closed']]

    def test_that_button_is_orange_and_the_type_stays_red(self):
        view = SwitchesView(RUNNING, SWITCHES, debug_project=True)
        assert ORANGE in _button(view, 3).styleSheet()
        assert view.item(3, 1).background().color().name() == RED

    def test_open_switch_keeps_its_green_button(self):
        view = SwitchesView(RUNNING, SWITCHES, debug_project=True)
        assert GREEN in _button(view, 0).styleSheet()
        assert view.item(0, 1).background().color().name() != RED

    def test_hub_and_plain_switch_still_have_no_button(self):
        view = SwitchesView(RUNNING, SWITCHES, debug_project=True)
        assert [_button(view, row) for row in (1, 2)] == [None, None]

    def test_not_a_debug_project_by_default(self):
        assert _button(SwitchesView(RUNNING, SWITCHES), 3) is None


class TestMachinesViewStillConnects:
    """The Machines tab shares the terminal launcher with the Networks tab."""

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

    def test_tab_shown_empty_without_switches_key(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir)  # info.json written before the switch types existed
        widget = ProjectWidget(project_dir)
        assert self._tab_visible(widget)
        assert widget._switches_view.rowCount() == 0

    def test_tab_shown_with_hubs_only(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, switches=HUBS)
        widget = ProjectWidget(project_dir)
        assert self._tab_visible(widget)
        assert _column(widget._switches_view, 1) == ['Hub', 'Hub']

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
        assert widget._switches_view.rowCount() == 4

    def test_terminals_tab_has_the_open_manageable_switches(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        machines = [{"name": "m1", "allow_connection": True, "hidden": False, "interfaces": [], "ports": [],
                     "bridged": False}]
        _write_info(project_dir, machines=machines, switches=SWITCHES)
        widget = ProjectWidget(project_dir)
        terminals = widget._terminals_view
        assert [terminals.tabText(i) for i in range(terminals.count())] == ['m1', 'lan']

    def test_terminals_tab_of_a_debug_project_has_every_manageable_switch(self, project_dir):
        """The closed one too, its title in orange like a machine students cannot connect to."""
        from sysreseval.project_widget import ProjectWidget
        machines = [{"name": "m1", "allow_connection": True, "hidden": False, "interfaces": [], "ports": [],
                     "bridged": False},
                    {"name": "m2", "allow_connection": False, "hidden": False, "interfaces": [], "ports": [],
                     "bridged": False}]
        _write_info(project_dir, machines=machines, switches=SWITCHES, debug_project=True)
        widget = ProjectWidget(project_dir)
        terminals = widget._terminals_view
        titles = [terminals.tabText(i) for i in range(terminals.count())]
        assert titles == ['m1', 'm2', 'lan', 'closed']
        color = {title: terminals.tabBar().tabTextColor(i) for i, title in enumerate(titles)}
        assert color['closed'] == QColor("orange") == color['m2']
        assert color['lan'] == color['m1'] != QColor("orange")

    def test_switches_tab_of_a_debug_project_connects_to_a_closed_switch(self, project_dir, started):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, switches=SWITCHES, debug_project=True)
        widget = ProjectWidget(project_dir)
        _button(widget._switches_view, 3).click()
        assert started[0].cmd[-2:] == [RUNNING, 'closed']

    def test_switches_tab_of_a_normal_project_does_not(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, switches=SWITCHES)
        widget = ProjectWidget(project_dir)
        assert _button(widget._switches_view, 3) is None
        assert widget._switches_view.item(3, 1).background().color().name() == RED
