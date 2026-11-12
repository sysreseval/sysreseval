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

from PySide6.QtCore import QPoint  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QPlainTextEdit  # noqa: E402

from SRE import params  # noqa: E402
from SRE.instructor_text import instructor, set_instructor_context  # noqa: E402
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


# ---------------------------------------------------------------------------
# inline fields: @@{name~N:spec}@@ on the row of their label (SRE.form_spec.layout_rows)
# ---------------------------------------------------------------------------

INLINE_FORM = ("- Hops: @@{routers:[0-9]+}@@\n"
               "- ICMP message: type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@\n"
               "- Protocol: @@{proto~:>UDP|TCP}@@ @@{port~12:[0-9]+}@@ on the wan\n")
QWIDGETSIZE_MAX = 16777215


def settle():
    """Let the layouts run: a size change of a label goes up to its row, then to the form, then
    to the scroll area, one posted event each."""
    for _ in range(5):
        _app.processEvents()


def shown(widget, width: int = 700):
    """*widget* laid out at *width* pixels."""
    widget.resize(width, 400)
    widget.show()
    settle()
    return widget


def box(widget, child):
    """``(left, top, right, bottom)`` of *child* inside *widget*."""
    origin = child.mapTo(widget, QPoint(0, 0))
    return origin.x(), origin.y(), origin.x() + child.width(), origin.y() + child.height()


def browser_of(widget, text: str):
    return next(b for b in widget._browsers if b.toPlainText() == text)


class TestInlineFields:
    def test_two_fields_on_the_row_of_their_label(self):
        widget = shown(FormQuestionWidget(INLINE_FORM, [], {}, font_size=12))
        assert [b.toPlainText() for b in widget._browsers] == [
            "Hops:", "ICMP message: type", ", code", "Protocol:", "on the wan"]
        label, comma = browser_of(widget, "ICMP message: type"), browser_of(widget, ", code")
        icmp_type, icmp_code = widget._text_fields['icmp_type'], widget._text_fields['icmp_code']
        row = [box(widget, item) for item in (label, icmp_type, comma, icmp_code)]
        # side by side, in the order of the text, on one bottom line
        assert all(left[2] <= right[0] for left, right in zip(row, row[1:]))
        assert len({item[3] for item in row}) == 1
        assert len({item.parentWidget() for item in (label, icmp_type, comma, icmp_code)}) == 1
        # a label takes the room of its text, a field that of its characters
        assert label.width() < 250 and comma.width() < 100
        assert icmp_type.width() == icmp_code.width() < 100
        assert icmp_type.minimumWidth() == icmp_type.maximumWidth()
        assert label.height() < 2 * icmp_type.height()            # one line of text, not wrapped

    def test_width_in_characters(self):
        widget = shown(FormQuestionWidget(INLINE_FORM, [], {}, font_size=12))
        four, twelve = widget._text_fields['icmp_type'], widget._text_fields['port']

        def digits(count: int) -> int:
            return four.fontMetrics().horizontalAdvance('0' * count)

        assert four.width() > digits(4) and twelve.width() > digits(12)
        assert twelve.width() - four.width() == digits(12) - digits(4)     # the same frame around
        other = FormQuestionWidget("N: @@{n~:}@@", [], {}, font_size=12)
        default = other._text_fields['n']
        assert default.width() - four.width() == digits(params.default_inline_field_width) - digits(4)

    def test_select_and_end_of_line(self):
        widget = shown(FormQuestionWidget(INLINE_FORM, [], {}, font_size=12))
        proto, port = widget._combo_fields['proto'], widget._text_fields['port']
        label, tail = browser_of(widget, "Protocol:"), browser_of(widget, "on the wan")
        row = [box(widget, item) for item in (label, proto, port, tail)]
        assert all(left[2] <= right[0] for left, right in zip(row, row[1:]))
        assert len({item[3] for item in row}) == 1
        assert proto.width() < 200                                    # the width of its options

    def test_a_field_without_the_suffix_keeps_its_row(self):
        widget = shown(FormQuestionWidget(INLINE_FORM, [], {}, font_size=12))
        label, routers = browser_of(widget, "Hops:"), widget._text_fields['routers']
        assert box(widget, routers)[1] >= box(widget, label)[3]       # below its text
        assert routers.width() > 600 and label.width() > 600          # both as wide as the form
        assert routers.maximumWidth() == QWIDGETSIZE_MAX
        assert box(widget, widget._text_fields['icmp_type'])[1] > box(widget, routers)[3]

    def test_answers_under_the_names_without_suffix(self):
        widget = FormQuestionWidget(INLINE_FORM, [], {'icmp_type': '11', 'proto': 'TCP'}, font_size=12)
        assert widget.get_answers() == {'routers': '', 'icmp_type': '11', 'icmp_code': '', 'port': '',
                                        'proto': 'TCP'}
        emitted = []
        widget.answer_changed.connect(emitted.append)
        widget._text_fields['icmp_code'].setText('0')
        assert json.loads(emitted[-1])['icmp_code'] == '0'
        widget._text_fields['icmp_code'].setText('')
        QTest.keyClicks(widget._text_fields['icmp_code'], '1x2')      # the regex is still the validator
        assert widget.get_answers()['icmp_code'] == '12'

    def test_font_size_changes_the_width(self):
        widget = shown(FormQuestionWidget(INLINE_FORM, [], {}, font_size=12))
        edit, label = widget._text_fields['icmp_type'], browser_of(widget, "ICMP message: type")
        edit_width, label_width = edit.width(), label.sizeHint().width()
        widget.apply_font_size(24)
        settle()
        assert edit.minimumWidth() == edit.maximumWidth() > edit_width
        assert label.sizeHint().width() > label_width

    # one row alone: nothing else gives the form its width
    ONE_ROW = "- ICMP message: type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@"

    def test_a_narrow_form_wraps_the_label(self):
        wide = shown(FormQuestionWidget(self.ONE_ROW, [], {}, font_size=12))
        one_line = browser_of(wide, "ICMP message: type").height()
        widget = shown(FormQuestionWidget(self.ONE_ROW, [], {}, font_size=12), width=300)
        label, edit = browser_of(widget, "ICMP message: type"), widget._text_fields['icmp_type']
        assert label.width() < label.sizeHint().width() and label.height() > one_line   # on several lines
        assert box(widget, label)[3] == box(widget, edit)[3]          # the field on its last line
        assert box(widget, widget._text_fields['icmp_code'])[2] <= widget.width()

    def test_without_word_wrap_a_label_keeps_its_width(self):
        wide = shown(FormQuestionWidget(self.ONE_ROW, [], {}, font_size=12))
        one_line = browser_of(wide, "ICMP message: type").height()
        widget = shown(FormQuestionWidget(self.ONE_ROW, [], {}, font_size=12, word_wrap=False), width=300)
        label = browser_of(widget, "ICMP message: type")
        assert label.width() == label.sizeHint().width() and label.height() == one_line
        widget.set_word_wrap(True)
        settle()
        assert label.width() < label.sizeHint().width() and label.height() > one_line

    def test_instructor_text_of_a_row(self):
        set_instructor_context(True)
        try:
            form = "T: @@{t~4:}@@" + instructor(" (answer: 11)") + "\nend"
        finally:
            set_instructor_context(False)
        student = FormQuestionWidget(form, [], {}, font_size=12)
        assert [b.toPlainText() for b in student._browsers] == ["T:", "end"]
        teacher = FormQuestionWidget(form, [], {}, font_size=12, show_instructor=True)
        assert [b.toPlainText() for b in teacher._browsers] == ["T:", "(answer: 11)", "end"]

    def test_flavor_dialog(self):
        dialog = shown(FlavorFormDialog("Clients: @@{nb~3:[0-9]+}@@ mode: @@{mode~:>easy|hard}@@\n\n"
                                        "@@{go::Start}@@", previous_answers={'nb': '2', 'mode': 'hard'}))
        nb, mode, go = dialog._text_fields['nb'], dialog._combo_fields['mode'], dialog._submit_fields['go']
        assert nb.parentWidget() is mode.parentWidget() is not go.parentWidget()
        assert box(dialog, nb)[3] == box(dialog, mode)[3] and box(dialog, nb)[2] <= box(dialog, mode)[0]
        assert nb.minimumWidth() == nb.maximumWidth() < 100
        assert box(dialog, go)[1] >= box(dialog, nb)[3]
        dialog._on_submit('go')
        assert json.loads(dialog.get_flavor_json()) == {'nb': '2', 'mode': 'hard', 'go': True}
