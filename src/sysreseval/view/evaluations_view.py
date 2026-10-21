import json
import subprocess
import time

from PySide6.QtCore import QEvent, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QHeaderView, QLabel, QTableWidget, QTableWidgetItem,
    QPushButton, QVBoxLayout, QWidget
)

from SRE import params
from SRE.evaluation_table import (
    KIND_SEPARATOR, SEPARATOR_HEIGHT, build_evaluation_rows, header_labels,
)
from sysreseval import settings, util


# Shared registry: canonical_lab_name -> (monotonic_start, total_seconds)
# Written by whichever view triggers an eval; read by all views with the same lab name.
_delay_registry: dict[str, tuple[float, int]] = {}


class _EvalWorker(QThread):
    finished = Signal(object)   # emits the parsed dict
    error = Signal(str)

    def __init__(self, running_lab_name: str):
        super().__init__()
        self._running_lab_name = running_lab_name

    def run(self):
        try:
            cmd = [params.sre_wrapper, "eval", "--auto-eval", self._running_lab_name]
            util.log_wrapper_cmd(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0 or not result.stdout.strip():
                detail = result.stderr.strip() or "(no output)"
                self.error.emit(f"exit {result.returncode}: {detail}")
                return
            self.finished.emit(json.loads(result.stdout))
        except Exception as e:
            self.error.emit(str(e))


class EvaluationView(QWidget):
    def __init__(self, evaluations: list, running_lab_name: str,
                 canonical_lab_name: str, debug_project: bool = False, parent=None):
        super().__init__(parent)

        self._running_lab_name = running_lab_name
        self._canonical_lab_name = canonical_lab_name
        self._debug_project = debug_project
        self._worker = None
        self._lang_priority = settings.get_language_priority()
        self._last_elements: list = []
        self._last_grade_parts: list = []

        layout = QVBoxLayout(self)

        self.start_button = QPushButton(self.tr("Start evaluation"))
        self.start_button.clicked.connect(self._start_eval)
        layout.addWidget(self.start_button)

        self._countdown_label = QLabel()
        self._countdown_label.hide()
        layout.addWidget(self._countdown_label)

        if self._debug_project:
            self._table = QTableWidget(0, 5)
            self._table.setHorizontalHeaderLabels(self._header_labels())
            self._table.verticalHeader().setVisible(False)
            self._table.verticalHeader().setMinimumSectionSize(1)
            hh = self._table.horizontalHeader()
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            for col, width in ((1, 60), (2, 80), (3, 80), (4, 80)):
                hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
                hh.resizeSection(col, width)
        else:
            self._table = QTableWidget(0, 3)
            self._table.setHorizontalHeaderLabels(self._header_labels())
            self._table.verticalHeader().setVisible(False)
            self._table.verticalHeader().setMinimumSectionSize(1)
            hh = self._table.horizontalHeader()
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            hh.resizeSection(1, 80)
            hh.resizeSection(2, 80)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self._table)

        # Always-running 1 s timer: syncs display with the shared registry.
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1000)
        self._poll_timer.timeout.connect(self._sync_delay_display)
        self._poll_timer.start()

        self.update_data(evaluations)

    # ------------------------------------------------------------------
    # Evaluation launch
    # ------------------------------------------------------------------

    def _start_eval(self):
        self.start_button.setEnabled(False)
        self._worker = _EvalWorker(self._running_lab_name)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_finished(self, data):
        if isinstance(data, dict):
            grades = data.get("grades") or []
            grade_parts = data.get("grade_parts") or []
            delay = int(data.get("delay_before_self_grade", 0))
            mark = data.get("mark")
            maximum_mark = data.get("maximum_mark")
        else:
            grades = data or []
            grade_parts = []
            delay = 0
            mark = None
            maximum_mark = None

        self._populate_table(grades, grade_parts=grade_parts, mark=mark, maximum_mark=maximum_mark)

        if delay > 0:
            _delay_registry[self._canonical_lab_name] = (time.monotonic(), delay)
            self._sync_delay_display()
        else:
            _delay_registry.pop(self._canonical_lab_name, None)
            self.start_button.setEnabled(True)

    def _on_error(self, msg: str):
        self.start_button.setEnabled(True)
        self._table.setRowCount(1)
        self._table.setItem(0, 0, QTableWidgetItem(self.tr("Error: {error}").format(error=msg)))
        self._table.setItem(0, 1, QTableWidgetItem(""))
        self._table.setItem(0, 2, QTableWidgetItem(""))

    # ------------------------------------------------------------------
    # Shared delay display (called every second by _poll_timer)
    # ------------------------------------------------------------------

    def _sync_delay_display(self):
        entry = _delay_registry.get(self._canonical_lab_name)
        if entry:
            start, total = entry
            remaining = total - int(time.monotonic() - start)
            if remaining > 0:
                self._countdown_label.setText(
                    self.tr("Next evaluation allowed in {n} s").format(n=remaining)
                )
                self.start_button.hide()
                self._countdown_label.show()
                return
            else:
                _delay_registry.pop(self._canonical_lab_name, None)

        # No active delay: show button if it was hidden.
        if not self.start_button.isVisible():
            self._countdown_label.hide()
            self.start_button.show()
            self.start_button.setEnabled(True)

    # ------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------

    def update_data(self, evaluations: list):
        self._populate_table(evaluations)
        self._sync_delay_display()

    def set_language_priority(self, priority: list):
        self._lang_priority = priority
        self._populate_table(self._last_elements, grade_parts=self._last_grade_parts)

    def _translator(self):
        """A ``translate`` callable for ``SRE.evaluation_table``: the catalog of the GUI through
        literals kept here, which pyside6-lupdate reads with this view as their context."""
        texts = {
            "Element": self.tr("Element"),
            "Scope": self.tr("Scope"),
            "Grade": self.tr("Grade"),
            "self Grade": self.tr("self Grade"),
            "exo Grade": self.tr("exo Grade"),
            "Max grade": self.tr("Max grade"),
            "OK": self.tr("OK"),
            "MEH": self.tr("MEH"),
            "FAIL": self.tr("FAIL"),
            "Bonus": self.tr("Bonus"),
            "Total for {part}": self.tr("Total for {part}"),
            "Total": self.tr("Total"),
            "Total (self)": self.tr("Total (self)"),
            "Total (exo)": self.tr("Total (exo)"),
            "Mark": self.tr("Mark"),
        }
        return lambda text: texts.get(text, text)

    def _header_labels(self) -> list:
        return header_labels(debug=self._debug_project, translate=self._translator())

    def changeEvent(self, event):
        if event.type() == QEvent.Type.LanguageChange:
            self.start_button.setText(self.tr("Start evaluation"))
            self._table.setHorizontalHeaderLabels(self._header_labels())
            self._populate_table(self._last_elements, grade_parts=self._last_grade_parts)
        super().changeEvent(event)

    def _populate_table(self, elements: list, grade_parts: list = None, mark=None, maximum_mark=None):
        self._last_elements = elements
        self._last_grade_parts = grade_parts or []
        rows = build_evaluation_rows(elements, self._last_grade_parts, mark=mark,
                                     maximum_mark=maximum_mark, debug=self._debug_project,
                                     lang_priority=self._lang_priority,
                                     translate=self._translator())
        self._table.setRowCount(len(rows))
        self._table.clearSpans()
        col_count = self._table.columnCount()
        bold_font = QFont()
        bold_font.setBold(True)
        for row_idx, row in enumerate(rows):
            for col, cell in enumerate(row.cells):
                item = QTableWidgetItem(cell.text)
                if cell.color:
                    item.setBackground(QColor(cell.color))
                if row.bold:
                    item.setFont(bold_font)
                if cell.align == "center":
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if row.kind == KIND_SEPARATOR:
                    item.setFlags(Qt.ItemFlag.NoItemFlags)
                self._table.setItem(row_idx, col, item)
            if row.span:
                self._table.setSpan(row_idx, 0, 1, col_count)
            if row.kind == KIND_SEPARATOR:
                self._table.setRowHeight(row_idx, SEPARATOR_HEIGHT)
