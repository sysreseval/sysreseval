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
from SRE.common import TranslatedText
from sysreseval import settings, util

def _fmt_num(v: float) -> str:
    """Format a numeric grade value: omit the decimal point when the value is a whole number."""
    return str(int(v)) if v == int(v) else str(v)


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

    def _header_labels(self) -> list:
        if self._debug_project:
            return [
                self.tr("Element"),
                self.tr("Scope"),
                self.tr("self Grade"),
                self.tr("exo Grade"),
                self.tr("Max grade"),
            ]
        return [
            self.tr("Element"),
            self.tr("Grade"),
            self.tr("Max grade"),
        ]

    def changeEvent(self, event):
        if event.type() == QEvent.Type.LanguageChange:
            self.start_button.setText(self.tr("Start evaluation"))
            self._table.setHorizontalHeaderLabels(self._header_labels())
            self._populate_table(self._last_elements, grade_parts=self._last_grade_parts)
        super().changeEvent(event)

    def _populate_table(self, elements: list, grade_parts: list = None, mark=None, maximum_mark=None):
        self._last_elements = elements
        self._last_grade_parts = grade_parts or []
        if self._debug_project:
            self._populate_table_debug(elements, grade_parts=self._last_grade_parts,
                                       mark=mark, maximum_mark=maximum_mark)
            return

        has_any_letter = any(e.get("grade_letter") is not None for e in elements)
        total_bg = QColor("#dde8f5")
        bold_font = QFont()
        bold_font.setBold(True)

        def _row_item(text: str, row_idx: int) -> QTableWidgetItem:
            item = QTableWidgetItem(text)
            if row_idx % 2 == 1:
                item.setBackground(QColor("#f0f0f0"))
            return item

        def _total_item(text: str) -> QTableWidgetItem:
            item = QTableWidgetItem(text)
            item.setBackground(total_bg)
            item.setFont(bold_font)
            return item

        def _grade_color(grade_letter, grade, max_grade) -> QColor | None:
            if grade_letter is not None:
                return {"OK": QColor("#a8f0a8"),
                        "MEH": QColor("#f0e8a8"),
                        "FAIL": QColor("#f0a8a8")}.get(grade_letter)
            if grade is not None and max_grade is not None:
                if grade == 0 and max_grade == 0:
                    return QColor("#a8f0a8")  # penalty not triggered
                if grade >= max_grade:
                    return QColor("#a8f0a8")
                if grade > 0:
                    return QColor("#f0e8a8")
                return QColor("#f0a8a8")
            return None

        # Group elements by part title (preserving the registration order of
        # ``grade_parts``). The trailing ``None`` bucket holds ungrouped
        # elements, displayed after the last part with no subtotal row.
        parts = list(grade_parts or [])
        part_titles = [p.get("title", "") for p in parts]
        groups: dict[str | None, list] = {pt: [] for pt in part_titles}
        groups[None] = []
        for e in elements:
            gp = e.get("grade_part") if isinstance(e, dict) else None
            if gp in groups:
                groups[gp].append(e)
            else:
                # Element references an unknown part: degrade to ungrouped
                groups[None].append(e)

        ordered_groups: list[tuple[dict | None, list]] = []
        for part in parts:
            ordered_groups.append((part, groups[part.get("title", "")]))
        ordered_groups.append((None, groups[None]))

        # Per-group subtotal is only meaningful and only emitted when (a) the
        # group has at least one element and (b) at least one numeric grade is
        # present. We never emit a subtotal for the trailing ungrouped bucket.
        def _group_has_numeric(items: list) -> bool:
            return any(it.get("grade_letter") is None and it.get("grade") is not None
                       for it in items)

        subtotal_rows = sum(
            1 for part, items in ordered_groups[:-1]
            if items and _group_has_numeric(items)
        )
        header_rows = sum(1 for part, items in ordered_groups[:-1] if items)
        non_empty_groups = sum(1 for _, items in ordered_groups if items)
        separator_rows = max(0, non_empty_groups - 1)
        total_rows = (len(elements) + header_rows + subtotal_rows + separator_rows
                      + 1 + (1 if mark is not None else 0))
        self._table.setRowCount(total_rows)
        self._table.clearSpans()
        col_count = self._table.columnCount()
        separator_color = QColor("#000000")
        separator_height = 2

        def _emit_part_header(part_dict: dict, row_idx: int):
            desc_tt = TranslatedText.from_value(part_dict.get("description", ""))
            title_tt = TranslatedText.from_value(part_dict.get("title", ""))
            text = (desc_tt.resolve_priority(self._lang_priority)
                    or title_tt.resolve_priority(self._lang_priority)
                    or part_dict.get("title", ""))
            item = QTableWidgetItem(text)
            item.setBackground(total_bg)
            item.setFont(bold_font)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row_idx, 0, item)
            self._table.setSpan(row_idx, 0, 1, col_count)

        def _emit_separator(row_idx: int):
            item = QTableWidgetItem("")
            item.setBackground(separator_color)
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._table.setItem(row_idx, 0, item)
            self._table.setSpan(row_idx, 0, 1, col_count)
            self._table.setRowHeight(row_idx, separator_height)

        # Index of the last non-empty group, used to suppress the trailing
        # separator that would otherwise sit just before the grand total.
        non_empty_idx = [i for i, (_, items) in enumerate(ordered_groups) if items]
        last_non_empty = non_empty_idx[-1] if non_empty_idx else -1

        total_grade = 0.0
        total_max = 0.0
        row = 0
        alt_idx = 0  # only zebra-stripe element rows, not header/subtotal/sep rows
        for idx, (part, items) in enumerate(ordered_groups):
            if part is not None and items:
                _emit_part_header(part, row)
                row += 1
                alt_idx = 0
            part_grade = 0.0
            part_max = 0.0
            part_has_numeric = False
            for e in items:
                grade_letter = e.get("grade_letter")
                grade = e.get("grade")
                max_grade = e.get("max_grade")

                if grade_letter is not None:
                    grade_display = {
                        "OK": self.tr("OK"),
                        "MEH": self.tr("MEH"),
                        "FAIL": self.tr("FAIL"),
                    }.get(grade_letter, grade_letter)
                    max_display = ""
                else:
                    grade_display = "" if grade is None else _fmt_num(grade)
                    max_display = "" if max_grade is None else _fmt_num(max_grade)
                    if grade is not None:
                        total_grade += grade
                        part_grade += grade
                        part_has_numeric = True
                    if max_grade is not None:
                        total_max += max_grade
                        part_max += max_grade

                desc_tt = TranslatedText.from_value(e.get("description", ""))
                title_tt = TranslatedText.from_value(e.get("title", ""))
                label = (desc_tt.resolve_priority(self._lang_priority)
                         or title_tt.resolve_priority(self._lang_priority))

                self._table.setItem(row, 0, _row_item(label, alt_idx))

                grade_item = _row_item(grade_display, alt_idx)
                color = _grade_color(grade_letter, grade, max_grade)
                if color:
                    grade_item.setBackground(color)
                self._table.setItem(row, 1, grade_item)

                self._table.setItem(row, 2, _row_item(max_display, alt_idx))

                row += 1
                alt_idx += 1

            # Emit a subtotal row for non-trailing groups with numeric items.
            if part is not None and items and part_has_numeric:
                desc_tt = TranslatedText.from_value(part.get("description", ""))
                title_tt = TranslatedText.from_value(part.get("title", ""))
                part_label = (desc_tt.resolve_priority(self._lang_priority)
                              or title_tt.resolve_priority(self._lang_priority)
                              or part.get("title", ""))
                self._table.setItem(row, 0,
                                    _total_item(self.tr("Total for {part}").format(part=part_label)))
                self._table.setItem(row, 1, _total_item(_fmt_num(part_grade)))
                self._table.setItem(row, 2, _total_item(_fmt_num(part_max)))
                row += 1
                alt_idx = 0  # restart zebra striping fresh after a subtotal

            # Bold horizontal separator between this group and the next non-empty one.
            if items and idx != last_non_empty:
                _emit_separator(row)
                row += 1
                alt_idx = 0

        # Grand total + (optional) mark row.
        has_numbers = not has_any_letter and elements
        self._table.setItem(row, 0, _total_item(self.tr("Total")))
        if has_numbers:
            self._table.setItem(row, 1, _total_item(_fmt_num(total_grade)))
            self._table.setItem(row, 2, _total_item(_fmt_num(total_max)))
        else:
            self._table.setItem(row, 1, _total_item(""))
            self._table.setItem(row, 2, _total_item(""))
        row += 1

        if mark is not None:
            mark_display = str(mark) if maximum_mark is None else f"{mark} / {maximum_mark}"
            self._table.setItem(row, 0, _total_item(self.tr("Mark")))
            self._table.setItem(row, 1, _total_item(mark_display))
            self._table.setItem(row, 2, _total_item(""))

    def _populate_table_debug(self, elements: list, grade_parts: list = None,
                              mark=None, maximum_mark=None):
        scope_labels = {
            params.SELF_EVAL_SCOPE: "self",
            params.EXO_EVAL_SCOPE: "exo",
            params.BOTH_EVAL_SCOPE: "both",
        }

        total_bg = QColor("#dde8f5")
        bold_font = QFont()
        bold_font.setBold(True)

        def _shade(item, row_idx):
            if row_idx % 2 == 1:
                item.setBackground(QColor("#f0f0f0"))

        def _grade_color(grade, max_grade):
            if grade is None or max_grade is None:
                return None
            if grade == 0 and max_grade == 0:
                return QColor("#a8f0a8")  # penalty not triggered
            if grade >= max_grade and max_grade > 0:
                return QColor("#a8f0a8")
            if grade > 0:
                return QColor("#f0e8a8")
            return QColor("#f0a8a8")

        def _total_item(text):
            item = QTableWidgetItem(text)
            item.setBackground(total_bg)
            item.setFont(bold_font)
            return item

        # Group elements by part title — same logic as the non-debug branch.
        parts = list(grade_parts or [])
        part_titles = [p.get("title", "") for p in parts]
        groups: dict[str | None, list] = {pt: [] for pt in part_titles}
        groups[None] = []
        for e in elements:
            gp = e.get("grade_part") if isinstance(e, dict) else None
            if gp in groups:
                groups[gp].append(e)
            else:
                groups[None].append(e)

        ordered_groups: list[tuple[dict | None, list]] = []
        for part in parts:
            ordered_groups.append((part, groups[part.get("title", "")]))
        ordered_groups.append((None, groups[None]))

        def _group_has_numeric_in(items: list, scope_bit: int) -> bool:
            for e in items:
                scope = int(e.get("scope", params.BOTH_EVAL_SCOPE) or params.BOTH_EVAL_SCOPE)
                if scope & scope_bit and e.get("grade") is not None:
                    return True
            return False

        # Sub-row per non-trailing group when at least one of self/exo has a numeric grade.
        subtotal_rows = sum(
            1 for part, items in ordered_groups[:-1]
            if items and (_group_has_numeric_in(items, params.SELF_EVAL_SCOPE)
                          or _group_has_numeric_in(items, params.EXO_EVAL_SCOPE))
        )
        header_rows = sum(1 for part, items in ordered_groups[:-1] if items)
        non_empty_groups = sum(1 for _, items in ordered_groups if items)
        separator_rows = max(0, non_empty_groups - 1)
        total_rows = (len(elements) + header_rows + subtotal_rows + separator_rows + 2
                      + (1 if mark is not None else 0))
        self._table.setRowCount(total_rows)
        self._table.clearSpans()
        col_count = self._table.columnCount()
        separator_color = QColor("#000000")
        separator_height = 2
        non_empty_idx = [i for i, (_, items) in enumerate(ordered_groups) if items]
        last_non_empty = non_empty_idx[-1] if non_empty_idx else -1

        def _emit_part_header(part_dict: dict, row_idx: int):
            desc_tt = TranslatedText.from_value(part_dict.get("description", ""))
            title_tt = TranslatedText.from_value(part_dict.get("title", ""))
            text = (desc_tt.resolve_priority(self._lang_priority)
                    or title_tt.resolve_priority(self._lang_priority)
                    or part_dict.get("title", ""))
            item = QTableWidgetItem(text)
            item.setBackground(total_bg)
            item.setFont(bold_font)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row_idx, 0, item)
            self._table.setSpan(row_idx, 0, 1, col_count)

        def _emit_separator(row_idx: int):
            item = QTableWidgetItem("")
            item.setBackground(separator_color)
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._table.setItem(row_idx, 0, item)
            self._table.setSpan(row_idx, 0, 1, col_count)
            self._table.setRowHeight(row_idx, separator_height)

        total_self_grade = 0.0
        total_self_max = 0.0
        total_exo_grade = 0.0
        total_exo_max = 0.0
        row = 0
        alt_idx = 0
        for idx, (part, items) in enumerate(ordered_groups):
            if part is not None and items:
                _emit_part_header(part, row)
                row += 1
                alt_idx = 0
            part_self_grade = 0.0
            part_self_max = 0.0
            part_exo_grade = 0.0
            part_exo_max = 0.0
            part_has_self = False
            part_has_exo = False
            for e in items:
                scope = int(e.get("scope", params.BOTH_EVAL_SCOPE) or params.BOTH_EVAL_SCOPE)
                grade = e.get("grade")
                max_grade = e.get("max_grade")

                in_self = bool(scope & params.SELF_EVAL_SCOPE)
                in_exo = bool(scope & params.EXO_EVAL_SCOPE)

                if in_self:
                    if grade is not None:
                        total_self_grade += grade
                        part_self_grade += grade
                        part_has_self = True
                    if max_grade is not None:
                        total_self_max += max_grade
                        part_self_max += max_grade
                if in_exo:
                    if grade is not None:
                        total_exo_grade += grade
                        part_exo_grade += grade
                        part_has_exo = True
                    if max_grade is not None:
                        total_exo_max += max_grade
                        part_exo_max += max_grade

                desc_tt = TranslatedText.from_value(e.get("description", ""))
                title_tt = TranslatedText.from_value(e.get("title", ""))
                label = (desc_tt.resolve_priority(self._lang_priority)
                         or title_tt.resolve_priority(self._lang_priority))

                label_item = QTableWidgetItem(label)
                _shade(label_item, alt_idx)
                self._table.setItem(row, 0, label_item)

                scope_item = QTableWidgetItem(scope_labels.get(scope, str(scope)))
                _shade(scope_item, alt_idx)
                self._table.setItem(row, 1, scope_item)

                self_text = _fmt_num(grade) if (in_self and grade is not None) else ""
                self_item = QTableWidgetItem(self_text)
                _shade(self_item, alt_idx)
                color = _grade_color(grade, max_grade) if in_self else None
                if color:
                    self_item.setBackground(color)
                self._table.setItem(row, 2, self_item)

                exo_text = _fmt_num(grade) if (in_exo and grade is not None) else ""
                exo_item = QTableWidgetItem(exo_text)
                _shade(exo_item, alt_idx)
                color = _grade_color(grade, max_grade) if in_exo else None
                if color:
                    exo_item.setBackground(color)
                self._table.setItem(row, 3, exo_item)

                max_item = QTableWidgetItem("" if max_grade is None else _fmt_num(max_grade))
                _shade(max_item, alt_idx)
                self._table.setItem(row, 4, max_item)

                row += 1
                alt_idx += 1

            if part is not None and items and (part_has_self or part_has_exo):
                desc_tt = TranslatedText.from_value(part.get("description", ""))
                title_tt = TranslatedText.from_value(part.get("title", ""))
                part_label = (desc_tt.resolve_priority(self._lang_priority)
                              or title_tt.resolve_priority(self._lang_priority)
                              or part.get("title", ""))
                label_txt = self.tr("Total for {part}").format(part=part_label)
                self._table.setItem(row, 0, _total_item(label_txt))
                self._table.setItem(row, 1, _total_item(""))
                self._table.setItem(row, 2,
                                    _total_item(_fmt_num(part_self_grade) if part_has_self else ""))
                self._table.setItem(row, 3,
                                    _total_item(_fmt_num(part_exo_grade) if part_has_exo else ""))
                max_text = ""
                if part_has_self and part_has_exo:
                    max_text = (_fmt_num(part_self_max)
                                if part_self_max == part_exo_max
                                else f"{_fmt_num(part_self_max)} / {_fmt_num(part_exo_max)}")
                elif part_has_self:
                    max_text = _fmt_num(part_self_max)
                elif part_has_exo:
                    max_text = _fmt_num(part_exo_max)
                self._table.setItem(row, 4, _total_item(max_text))
                row += 1
                alt_idx = 0

            if items and idx != last_non_empty:
                _emit_separator(row)
                row += 1
                alt_idx = 0

        self._table.setItem(row, 0, _total_item(self.tr("Total (self)")))
        self._table.setItem(row, 1, _total_item(""))
        self._table.setItem(row, 2, _total_item(_fmt_num(total_self_grade)))
        self._table.setItem(row, 3, _total_item(""))
        self._table.setItem(row, 4, _total_item(_fmt_num(total_self_max)))
        row += 1

        self._table.setItem(row, 0, _total_item(self.tr("Total (exo)")))
        self._table.setItem(row, 1, _total_item(""))
        self._table.setItem(row, 2, _total_item(""))
        self._table.setItem(row, 3, _total_item(_fmt_num(total_exo_grade)))
        self._table.setItem(row, 4, _total_item(_fmt_num(total_exo_max)))
        row += 1

        if mark is not None:
            mark_display = str(mark) if maximum_mark is None else f"{mark} / {maximum_mark}"
            self._table.setItem(row, 0, _total_item(self.tr("Mark")))
            self._table.setItem(row, 1, _total_item(""))
            self._table.setItem(row, 2, _total_item(mark_display))
            self._table.setItem(row, 3, _total_item(""))
            self._table.setItem(row, 4, _total_item(""))
