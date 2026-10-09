"""Offscreen tests of the GUI Evaluations tab (src/sysreseval/view/evaluations_view.py):
bonus elements show "2 (Bonus)" in the Max column and their maximum is left out of the
part subtotals and of the total, in the student table and in the debug table."""
import os
from pathlib import Path

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QTranslator  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval.view.evaluations_view import EvaluationView  # noqa: E402

_app = QApplication.instance() or QApplication([])

RUNNING = '20260101000000@@@test@@@user'
FR_QM = Path(__file__).parent.parent / 'translations' / 'sysreseval_fr.qm'

PARTS = [{'title': 'p1', 'description': 'Part one'}]
ELEMENTS = [
    {'title': 'plain', 'description': 'Plain element', 'grade': 3, 'max_grade': 4, 'grade_part': 'p1',
     'scope': params.BOTH_EVAL_SCOPE, 'bonus': False},
    {'title': 'extra', 'description': 'Extra element', 'grade': 2, 'max_grade': 2, 'grade_part': 'p1',
     'scope': params.BOTH_EVAL_SCOPE, 'bonus': True},
    {'title': 'legacy', 'description': 'Legacy element', 'grade': 1, 'max_grade': 1, 'grade_part': None,
     'scope': params.BOTH_EVAL_SCOPE},   # an element dict without the bonus key
]


def _rows(view) -> list[list[str]]:
    table = view._table
    return [[table.item(r, c).text() if table.item(r, c) else None for c in range(table.columnCount())]
            for r in range(table.rowCount())]


def _row(view, label):
    return next(r for r in _rows(view) if r[0] == label)


@pytest.fixture
def view():
    v = EvaluationView([], RUNNING, 'test')
    v._populate_table(ELEMENTS, grade_parts=PARTS, mark=20.0, maximum_mark=20)
    return v


@pytest.fixture
def debug_view():
    v = EvaluationView([], RUNNING, 'test', debug_project=True)
    v._populate_table(ELEMENTS, grade_parts=PARTS, mark=20.0, maximum_mark=20)
    return v


class TestStudentTable:
    def test_bonus_in_the_max_column(self, view):
        assert _row(view, 'Plain element') == ['Plain element', '3', '4']
        assert _row(view, 'Extra element') == ['Extra element', '2', '2 (Bonus)']
        assert _row(view, 'Legacy element') == ['Legacy element', '1', '1']

    def test_bonus_max_left_out_of_the_subtotal_and_the_total(self, view):
        assert _row(view, 'Total for Part one') == ['Total for Part one', '5', '4']
        assert _row(view, 'Total') == ['Total', '6', '5']
        assert _row(view, 'Mark') == ['Mark', '20.0 / 20', '']

    def test_letter_mode(self):
        v = EvaluationView([], RUNNING, 'test')
        letters = [dict(e, grade=None, max_grade=None, grade_letter='OK') for e in ELEMENTS]
        v._populate_table(letters, grade_parts=PARTS)
        assert _row(v, 'Extra element') == ['Extra element', 'OK', '(Bonus)']
        assert _row(v, 'Plain element') == ['Plain element', 'OK', '']

    def test_french(self):
        translator = QTranslator()
        assert translator.load(str(FR_QM))
        _app.installTranslator(translator)
        try:
            v = EvaluationView([], RUNNING, 'test')
            v._populate_table(ELEMENTS, grade_parts=PARTS)
            assert _row(v, 'Extra element') == ['Extra element', '2', '2 (Bonus)']
            assert _row(v, 'Total pour Part one') == ['Total pour Part one', '5', '4']
        finally:
            _app.removeTranslator(translator)


class TestDebugTable:
    def test_bonus_in_the_max_column(self, debug_view):
        assert _row(debug_view, 'Extra element') == ['Extra element', 'both', '2', '2', '2 (Bonus)']
        assert _row(debug_view, 'Plain element') == ['Plain element', 'both', '3', '3', '4']

    def test_bonus_max_left_out_of_the_totals(self, debug_view):
        assert _row(debug_view, 'Total for Part one') == ['Total for Part one', '', '5', '5', '4']
        assert _row(debug_view, 'Total (self)') == ['Total (self)', '', '6', '', '5']
        assert _row(debug_view, 'Total (exo)') == ['Total (exo)', '', '', '6', '5']

    def test_bonus_of_one_scope_only(self):
        v = EvaluationView([], RUNNING, 'test', debug_project=True)
        elements = [dict(ELEMENTS[0]), dict(ELEMENTS[1], scope=params.SELF_EVAL_SCOPE)]
        v._populate_table(elements, grade_parts=PARTS)
        assert _row(v, 'Extra element') == ['Extra element', 'self', '2', '', '2 (Bonus)']
        assert _row(v, 'Total (self)') == ['Total (self)', '', '5', '', '4']
        assert _row(v, 'Total (exo)') == ['Total (exo)', '', '', '3', '4']
