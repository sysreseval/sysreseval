"""
Multi-line fields of the form questions: @@{name:+N}@@ gives a QPlainTextEdit of N lines
(params.default_form_field_lines without N) holding free text, in the Questions tab and in the
Flavor form dialog; the answer keeps its newlines.
Offscreen Qt.
"""
import json
import os

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QPlainTextEdit  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval.flavor_form_dialog import FlavorFormDialog  # noqa: E402
from sysreseval.view.form_question_widget import FormQuestionWidget  # noqa: E402

_app = QApplication.instance() or QApplication([])

FORM = "Notes: @@{notes:+3}@@ N: @@{n:[0-9]+}@@ End."


def _lines_height(edit: QPlainTextEdit, lines: int) -> int:
    return (lines * edit.fontMetrics().lineSpacing()
            + int(2 * edit.document().documentMargin()) + 2 * edit.frameWidth())


class TestFormQuestionWidget:
    def test_multiline_field_is_a_fixed_box_of_n_lines(self):
        widget = FormQuestionWidget(FORM, [], {}, font_size=12)
        edit = widget._multiline_fields['notes']
        assert isinstance(edit, QPlainTextEdit) and edit.tabChangesFocus()
        assert edit.minimumHeight() == edit.maximumHeight() == edit.height() == _lines_height(edit, 3)
        assert isinstance(widget._text_fields['n'], QLineEdit)
        assert [b.toPlainText() for b in widget._browsers] == ["Notes:", "N:", "End."]

    def test_default_height(self):
        widget = FormQuestionWidget("@@{notes:+}@@", [], {}, font_size=12)
        edit = widget._multiline_fields['notes']
        assert edit.height() == _lines_height(edit, params.default_form_field_lines)

    def test_answers_round_trip_and_signal(self):
        widget = FormQuestionWidget(FORM, [], {'notes': 'a\nb', 'n': '1'}, font_size=12)
        assert widget.get_answers() == {'notes': 'a\nb', 'n': '1'}
        emitted = []
        widget.answer_changed.connect(emitted.append)
        widget.set_answers({'notes': 'c\nd'})          # programmatic: nothing emitted
        assert emitted == [] and widget.get_answers()['notes'] == 'c\nd'
        widget._multiline_fields['notes'].setPlainText('x\ny')   # the student types
        assert [json.loads(s) for s in emitted] == [{'notes': 'x\ny', 'n': ''}]

    def test_font_size_changes_the_height(self):
        widget = FormQuestionWidget(FORM, [], {}, font_size=12)
        edit = widget._multiline_fields['notes']
        h12 = edit.height()
        widget.apply_font_size(24)
        assert edit.height() == _lines_height(edit, 3) > h12


class TestFlavorFormDialog:
    def test_multiline_field(self):
        dialog = FlavorFormDialog("Notes: @@{notes:+2}@@ N: @@{n:[0-9]+}@@",
                                  previous_answers={'notes': 'a\nb', 'n': '1'})
        edit = dialog._multiline_fields['notes']
        assert isinstance(edit, QPlainTextEdit) and edit.height() == _lines_height(edit, 2)
        assert json.loads(dialog.get_flavor_json()) == {'notes': 'a\nb', 'n': '1'}
        dialog._on_submit(None)   # free text: nothing to validate
        assert dialog.result() == QDialog.DialogCode.Accepted
