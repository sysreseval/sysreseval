"""
The documents drawn from lab markdown (Informations, Questions, form questions) get
params.content_style_sheet as default stylesheet: Qt draws the tables without cell padding
otherwise, and the columns touch each other. Offscreen Qt.
"""
import os

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtGui import QTextTable  # noqa: E402
from PySide6.QtWidgets import QApplication, QTextBrowser  # noqa: E402

from SRE.instructor_text import markdown_to_html  # noqa: E402
from sysreseval.view.form_question_widget import FormQuestionWidget  # noqa: E402
from sysreseval.view.information_view import InformationsView  # noqa: E402
from sysreseval.view.questions_view import QuestionsView  # noqa: E402

_app = QApplication.instance() or QApplication([])

RUNNING = '20260101000000@@@test@@@user'
TABLE = """
| field | content |
|-------|---------|
| `op` | direction of the message |
| `xid` | transaction identifier |
"""


def _cell_padding(browser) -> tuple:
    """(left, right) padding of the first cell of the first table of a browser's document."""
    for frame in browser.document().rootFrame().childFrames():
        if isinstance(frame, QTextTable):
            fmt = frame.cellAt(0, 0).format().toTableCellFormat()
            return fmt.leftPadding(), fmt.rightPadding()
    raise AssertionError("no table in the document")


def _padded(browser):
    left, right = _cell_padding(browser)
    return left > 0 and right > 0


def test_a_bare_browser_has_no_cell_padding():
    """The control: without the stylesheet the cells have no padding (hence the fix)."""
    browser = QTextBrowser()
    browser.setHtml(markdown_to_html(TABLE))
    assert _cell_padding(browser) == (0, 0)


def test_informations_view():
    view = InformationsView(TABLE)
    assert _padded(view)
    view.update_data(TABLE + "\nMore text.\n")   # setHtml() again
    assert _padded(view)
    view._on_font_size_changed(14)               # setHtml() again, other default font
    assert _padded(view)
    view.set_instructor_view(True)
    assert _padded(view)


def test_questions_view(tmp_pub_dir):
    questions = [{"title": "Fields", "description": TABLE, "question_hash": "h1",
                  "order": 100, "question_type": 1}]
    view = QuestionsView(questions, RUNNING)
    assert _padded(view.question_text)
    view.set_instructor_view(True)
    assert _padded(view.question_text)


def test_form_question_widget():
    widget = FormQuestionWidget(TABLE + "\n@@{a:[0-9]+}@@ end", [{"name": "a", "regex": "[0-9]+"}],
                                {}, font_size=12)
    browser = widget._browsers[0]
    assert _padded(browser)
    browser.update_font_size(14)
    assert _padded(browser)
