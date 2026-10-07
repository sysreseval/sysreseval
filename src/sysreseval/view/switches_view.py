from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QPushButton, QHeaderView

from SRE import params
from sysreseval import util


CLOSED_COLOR = "#f0c8c8"        # type of a manageable switch whose console is closed to the students
CONNECT_COLOR = "#c8f0c8"       # Connect button
DEBUG_CONNECT_COLOR = "#ffd9a0"  # Connect button a student would not have (debug project)


class SwitchesView(QTableWidget):
    """The Networks tab: the networks of a project seen as switches (``switches`` of info.json):
    name, type (hub, switch, manageable switch) and, for a manageable switch the students may
    use, a button opening its management console in a terminal.  The type of a manageable switch
    the lab closed to the students is on a red background; in a debug project such a switch gets
    a Connect button all the same (orange: `sre connect` lets a debug project in)."""

    def __init__(self, project_name: str, switches: list, debug_project: bool = False, parent=None):
        super().__init__(parent)
        self._project_name = project_name
        self._debug_project = debug_project
        self._terminals = util.ExternalTerminals(project_name)
        self.setColumnCount(3)
        header = self.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        bold = QFont()
        bold.setBold(True)
        header.setFont(bold)
        self.verticalHeader().setVisible(False)
        self._switches: list = []
        self._set_headers()
        self.update_data(switches)

    def _set_headers(self):
        self.setHorizontalHeaderLabels([
            self.tr("Name"),
            self.tr("Type"),
            self.tr("Connection"),
        ])

    def changeEvent(self, event):
        if event.type() == QEvent.Type.LanguageChange:
            self._set_headers()
            self.update_data(self._switches)
        super().changeEvent(event)

    def _mode_label(self, mode: str) -> str:
        if mode == params.network_mode_managed:
            return self.tr("Manageable switch")
        if mode == params.network_mode_switch:
            return self.tr("Switch")
        return self.tr("Hub")

    def update_data(self, switches: list):
        self._switches = switches
        self.setRowCount(len(switches))
        for row, switch in enumerate(switches):
            name = switch.get("name", "")
            mode = switch.get("mode", params.network_mode_hub)
            managed = mode == params.network_mode_managed
            allowed = bool(switch.get("allow_connection", False))

            self.setItem(row, 0, QTableWidgetItem(name))
            type_item = QTableWidgetItem(self._mode_label(mode))
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if managed and not allowed:
                type_item.setBackground(QColor(CLOSED_COLOR))
            self.setItem(row, 1, type_item)

            # a hub or a plain switch has no console; a manageable one may be closed to the
            # students, which a debug project ignores
            if managed and (allowed or self._debug_project):
                btn = QPushButton(self.tr("Connect"))
                btn.setStyleSheet(f"background-color: {CONNECT_COLOR if allowed else DEBUG_CONNECT_COLOR};")
                btn.clicked.connect(
                    lambda _checked, n=name: self._launch_terminal(n)
                )
                self.setCellWidget(row, 2, btn)
            else:
                self.removeCellWidget(row, 2)
                self.setItem(row, 2, QTableWidgetItem(""))

    def _launch_terminal(self, switch_name: str):
        self._terminals.launch(switch_name)

    def kill_terminals(self):
        self._terminals.kill()
