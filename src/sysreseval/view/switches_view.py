from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QPushButton, QHeaderView

from SRE import params
from sysreseval import util


class SwitchesView(QTableWidget):
    """The networks of a project seen as switches (``switches`` of info.json): name, type (hub,
    switch, manageable switch) and, for a manageable switch the students may use, a button
    opening its management console in a terminal."""

    def __init__(self, project_name: str, switches: list, parent=None):
        super().__init__(parent)
        self._project_name = project_name
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

    def has_switches(self) -> bool:
        """True when a network is not a hub: the tab is only shown then."""
        return any(s.get("mode", params.network_mode_hub) != params.network_mode_hub for s in self._switches)

    def update_data(self, switches: list):
        self._switches = switches
        self.setRowCount(len(switches))
        for row, switch in enumerate(switches):
            name = switch.get("name", "")
            mode = switch.get("mode", params.network_mode_hub)
            managed = mode == params.network_mode_managed

            self.setItem(row, 0, QTableWidgetItem(name))
            type_item = QTableWidgetItem(self._mode_label(mode))
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setItem(row, 1, type_item)

            if managed and switch.get("allow_connection", False):
                btn = QPushButton(self.tr("Connect"))
                btn.setStyleSheet("background-color: #c8f0c8;")
                btn.clicked.connect(
                    lambda _checked, n=name: self._launch_terminal(n)
                )
                self.setCellWidget(row, 2, btn)
            else:
                # a hub or a plain switch has no console; a manageable one may be closed to students
                self.removeCellWidget(row, 2)
                item = QTableWidgetItem("")
                if managed:
                    item.setBackground(QColor("#f0c8c8"))
                self.setItem(row, 2, item)

    def _launch_terminal(self, switch_name: str):
        self._terminals.launch(switch_name)

    def kill_terminals(self):
        self._terminals.kill()
