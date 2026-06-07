import os
import subprocess

from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QPushButton, QHeaderView

from SRE import params
from sysreseval import util


def _format_port(entry: str) -> str:
    """Format 'host:machine/proto' → 'host -> machine (proto)'."""
    proto = "tcp"
    if "/" in entry:
        entry, proto = entry.rsplit("/", 1)
    host_port, _, machine_port = entry.partition(":")
    return f"{host_port} -> {machine_port} ({proto})"


def _format_ports(ports: list) -> str:
    return "  -  ".join(_format_port(p) for p in ports)


class MachinesView(QTableWidget):
    def __init__(self, project_name: str, machines: list, parent=None):
        super().__init__(parent)
        self._project_name = project_name
        self._terminal_procs: list[subprocess.Popen] = []
        self.setColumnCount(5)
        header = self.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Ports
        bold = QFont()
        bold.setBold(True)
        header.setFont(bold)
        self.verticalHeader().setVisible(False)
        self._machines: list = []
        self._set_headers()
        self.update_data(machines)

    def _set_headers(self):
        self.setHorizontalHeaderLabels([
            self.tr("Name"),
            self.tr("NAT network to host"),
            self.tr("X11 host"),
            self.tr("Connection"),
            self.tr("Ports"),
        ])

    def changeEvent(self, event):
        if event.type() == QEvent.Type.LanguageChange:
            self._set_headers()
            self.update_data(self._machines)
        super().changeEvent(event)

    def update_data(self, machines: list):
        self._machines = machines
        self.setRowCount(len(machines))
        for row, machine in enumerate(machines):
            name = machine.get("name", "")
            allow = machine.get("allow_connection", False)

            bridged = machine.get("bridged", False)
            x11_host = machine.get("x11_host", False)
            ports = machine.get("ports", []) or []

            self.setItem(row, 0, QTableWidgetItem(name))
            yes = QCoreApplication.translate("MachinesView", "Yes")
            no  = QCoreApplication.translate("MachinesView", "No")
            nat_item = QTableWidgetItem(yes if bridged else no)
            nat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            nat_item.setBackground(QColor("#c8f0c8") if bridged else QColor("#f0c8c8"))
            self.setItem(row, 1, nat_item)
            x11_item = QTableWidgetItem(yes if x11_host else no)
            x11_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            x11_item.setBackground(QColor("#c8f0c8") if x11_host else QColor("#f0c8c8"))
            self.setItem(row, 2, x11_item)

            if allow:
                btn = QPushButton(self.tr("Connect"))
                btn.setStyleSheet("background-color: #c8f0c8;")
                btn.clicked.connect(
                    lambda _checked, n=name: self._launch_terminal(n)
                )
                self.setCellWidget(row, 3, btn)
            else:
                self.removeCellWidget(row, 3)
                item = QTableWidgetItem("")
                item.setBackground(QColor("#f0c8c8"))
                self.setItem(row, 3, item)
            self.setItem(row, 4, QTableWidgetItem(_format_ports(ports)))

    def _launch_terminal(self, machine_name: str):
        self._terminal_procs = [p for p in self._terminal_procs if p.poll() is None]
        abb_lab_name = params.get_abbreviated_lab_name_from_running_lab_name(self._project_name)
        title = f"{abb_lab_name} {machine_name}"
        cmd = (
            params.terminal_cmd_prefix[:-1]
            + [params.terminal_title_opt, title]
            + params.terminal_cmd_prefix[-1:]
            + [params.sre_wrapper, "connect", self._project_name, machine_name]
        )
        util.log_wrapper_cmd(cmd)
        proc = subprocess.Popen(cmd)
        self._terminal_procs.append(proc)

    def kill_terminals(self):
        for proc in self._terminal_procs:
            if proc.poll() is None:
                proc.kill()
        self._terminal_procs.clear()
