import subprocess

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHeaderView, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
)

from SRE import params
from SRE.common import TranslatedText
from sysreseval import settings, util


class _StateWorker(QThread):
    finished = Signal()
    error = Signal(str)

    def __init__(self, running_lab_name: str, state: str):
        super().__init__()
        self._running_lab_name = running_lab_name
        self._state = state

    def run(self):
        try:
            cmd = [params.sre_wrapper, "state", self._running_lab_name, self._state]
            util.log_wrapper_cmd(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                self.error.emit(result.stderr.strip() or f"exit {result.returncode}")
            else:
                self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))


class ApplyConfigView(QWidget):
    def __init__(self, user_allowed_states: dict, running_lab_name: str,
                 admin_only_states: list | None = None, parent=None):
        super().__init__(parent)
        self._running_lab_name = running_lab_name
        self._workers = []
        self._buttons: dict[str, QPushButton] = {}

        self._table = QTableWidget(0, 2)
        self._table.horizontalHeader().setVisible(False)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)

        layout = QVBoxLayout(self)
        layout.addWidget(self._table)

        self._lang_priority = settings.get_language_priority()
        self._user_allowed_states = user_allowed_states
        self._admin_only_states = set(admin_only_states or [])
        self._populate(user_allowed_states)

    def _populate(self, user_allowed_states: dict):
        self._table.setRowCount(0)
        self._buttons.clear()

        for state, description in user_allowed_states.items():
            row = self._table.rowCount()
            self._table.insertRow(row)
            resolved = TranslatedText.from_value(description).resolve_priority(self._lang_priority) if description else ''
            label = resolved if resolved else state
            label_item = QTableWidgetItem(label)
            if state in self._admin_only_states:
                label_item.setForeground(QColor("red"))
            self._table.setItem(row, 0, label_item)
            btn = QPushButton(self.tr("Apply"))
            btn.clicked.connect(lambda checked=False, s=state: self._apply(s))
            self._table.setCellWidget(row, 1, btn)
            self._buttons[state] = btn

    def _apply(self, state: str):
        btn = self._buttons.get(state)
        if btn:
            btn.setEnabled(False)
            btn.setToolTip("")
        worker = _StateWorker(self._running_lab_name, state)
        worker.finished.connect(lambda s=state: self._on_done(s))
        worker.error.connect(lambda msg, s=state: self._on_error(s, msg))
        self._workers.append(worker)
        worker.start()

    def _on_done(self, state: str):
        btn = self._buttons.get(state)
        if btn:
            btn.setEnabled(True)

    def _on_error(self, state: str, msg: str):
        btn = self._buttons.get(state)
        if btn:
            btn.setEnabled(True)
            btn.setToolTip(msg)

    def set_language_priority(self, priority: list):
        self._lang_priority = priority
        self._populate(self._user_allowed_states)

    def update_data(self, user_allowed_states: dict, admin_only_states: list | None = None):
        self._user_allowed_states = user_allowed_states
        if admin_only_states is not None:
            self._admin_only_states = set(admin_only_states)
        self._populate(user_allowed_states)
