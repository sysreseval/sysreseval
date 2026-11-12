import json
import math

from PySide6.QtCore import Signal, QEvent, QSize
from PySide6.QtGui import Qt, QFont, QPalette, QRegularExpressionValidator
from PySide6.QtCore import QRegularExpression
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, QCheckBox,
    QScrollArea, QTextBrowser, QFrame, QSizePolicy, QPlainTextEdit,
)

from SRE.form_spec import FIELD_RE, TextChunk, layout_rows, parse_form_description
from SRE.instructor_text import markdown_to_html
from sysreseval import settings, util

_FIELD_RE = FIELD_RE  # the one regex of the @@{field:spec}@@ grammar (SRE.form_spec)

# The inline rows (fields named name~N, SRE.form_spec.layout_rows): the room between two items
# of a row, what is added to the width of a label (a browser exactly as wide as its text wraps
# it on a rounding) and the width a label may be squeezed to before the form scrolls
INLINE_SPACING = 4
INLINE_ROW_MARGINS = (0, 2, 4, 4)   # left, top, right, bottom: with them a row is as high as a text
FIT_WIDTH_SLACK = 2
FIT_MIN_WIDTH = 80
TEXT_BOTTOM_ROOM = 6          # below the text of a browser that has a row of its own
_LINE_EDIT_HINT_CHARS = 17   # QLineEdit.sizeHint() is the width of 17 'x' plus its frame


def set_inline_width(edit: QLineEdit, chars: int):
    """Fix the width of an inline line field to *chars* characters of its current font."""
    metrics = edit.fontMetrics()
    frame = max(edit.sizeHint().width() - _LINE_EDIT_HINT_CHARS * metrics.horizontalAdvance('x'), 0)
    edit.setFixedWidth(metrics.horizontalAdvance('0' * chars) + frame)


def inline_row_widget(row, new_browser, new_field, show_instructor: bool = False) -> QWidget:
    """The widget of an inline row (``SRE.form_spec.FormRow``): each text in a browser of the
    width of its text (*new_browser(text_chunk, fit_width=True)*), each field (*new_field(chunk)*)
    next to it, the room left at the end of the row.

    The row is a band of the colour of the texts, as high as a text row, and its items stand on
    one bottom line: a field follows the last line of a label that had to wrap."""
    band = QWidget()
    band.setAutoFillBackground(True)
    band.setBackgroundRole(QPalette.ColorRole.Base)
    layout = QHBoxLayout(band)
    layout.setContentsMargins(*INLINE_ROW_MARGINS)
    layout.setSpacing(INLINE_SPACING)
    for chunk in row.items:
        if isinstance(chunk, TextChunk):
            if chunk.has_text(show_instructor):
                layout.addWidget(new_browser(chunk, fit_width=True), 0, Qt.AlignmentFlag.AlignBottom)
        else:
            layout.addWidget(new_field(chunk), 0, Qt.AlignmentFlag.AlignBottom)
    layout.addStretch(1)
    return band


class _AutoBrowser(QTextBrowser):
    """QTextBrowser that auto-sizes its height to fit its content.  With *fit_width* (a label of
    an inline row) it also asks for the width of its text, not for all the room of its row."""

    def __init__(self, parent=None, fit_width: bool = False):
        super().__init__(parent)
        self._markdown_text = ""
        self._show_instructor = False
        self._fit_width = fit_width
        self._natural_width = 0
        util.style_content_document(self)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Maximum if fit_width else QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Minimum)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.document().documentLayout().documentSizeChanged.connect(
            lambda _: self.updateGeometry()
        )

    def _measure(self):
        """Keep the width of the text drawn on one line (a copy of the document without wrapping:
        the ideal width of the document itself is that of its text as wrapped now)."""
        if not self._fit_width:
            return
        document = self.document().clone()
        document.setTextWidth(-1)
        self._natural_width = math.ceil(document.idealWidth()) + 2 * self.frameWidth() + FIT_WIDTH_SLACK
        self.updateGeometry()

    def set_word_wrap(self, wrap: bool):
        self.setLineWrapMode(QTextBrowser.LineWrapMode.WidgetWidth if wrap
                             else QTextBrowser.LineWrapMode.NoWrap)
        if self._fit_width:
            # never a scroll bar of its own: without wrapping it keeps the width of its text
            # (minimumSizeHint) and the form scrolls
            self.updateGeometry()
            return
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff if wrap
                                          else Qt.ScrollBarPolicy.ScrollBarAsNeeded)

    def set_markdown(self, text: str, font_size: int, show_instructor: bool = False):
        self._markdown_text = text
        self._show_instructor = show_instructor
        font = self.document().defaultFont()
        font.setPointSize(font_size)
        self.document().setDefaultFont(font)
        self.setHtml(markdown_to_html(text, show_instructor=show_instructor))
        self._measure()

    def update_font_size(self, size: int):
        font = self.document().defaultFont()
        font.setPointSize(size)
        self.document().setDefaultFont(font)
        self.setHtml(markdown_to_html(self._markdown_text, show_instructor=self._show_instructor))
        self._measure()

    def sizeHint(self):
        height = self.document().size().height()
        if self._fit_width:
            # no room below: the fields of the row stand on the line of the text
            return QSize(self._natural_width, max(math.ceil(height), 10))
        return QSize(super().sizeHint().width(), max(int(height) + TEXT_BOTTOM_ROOM, 10))

    def minimumSizeHint(self):
        hint = self.sizeHint()
        if self._fit_width and self.lineWrapMode() != QTextBrowser.LineWrapMode.NoWrap:
            # a label may be squeezed: its text wraps
            return QSize(min(hint.width(), FIT_MIN_WIDTH), hint.height())
        return hint


class FormQuestionWidget(QWidget):
    answer_changed = Signal(str)  # JSON-encoded {field_name: value}

    def __init__(self, description: str, fields: list, current_answers: dict,
                 font_size: int, word_wrap: bool = True, show_instructor: bool = False, parent=None):
        super().__init__(parent)
        self._font_size = font_size
        self._text_fields: dict[str, QLineEdit] = {}
        self._multiline_fields: dict[str, QPlainTextEdit] = {}
        self._multiline_lines: dict[str, int] = {}
        self._combo_fields: dict[str, QComboBox] = {}
        self._combo_values: dict[str, list[str]] = {}
        self._checkbox_fields: dict[str, QCheckBox] = {}
        self._inline_widths: dict[str, int] = {}   # inline line fields: their width in characters
        self._browsers: list[_AutoBrowser] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(6)
        layout.setContentsMargins(4, 4, 4, 4)

        font = QFont()
        font.setPointSize(font_size)

        def new_browser(text_chunk: TextChunk, fit_width: bool = False) -> _AutoBrowser:
            browser = _AutoBrowser(fit_width=fit_width)
            browser.setOpenExternalLinks(True)
            browser.set_markdown(text_chunk.text, font_size, show_instructor)
            browser.set_word_wrap(word_wrap)
            self._browsers.append(browser)
            return browser

        # the rows of SRE.form_spec.layout_rows(): a text (possibly empty) and the field that
        # follows it, the last text alone, or the texts and the inline fields (name~N) of one
        # source line; every text chunk is rendered on its own (an instructor fragment going
        # across a field is closed and reopened around it)
        for row in layout_rows(parse_form_description(description)):
            if row.inline:
                layout.addWidget(inline_row_widget(
                    row, new_browser, lambda chunk: self._new_field(chunk, font), show_instructor))
                continue
            text_chunk = row.items[0]
            if len(row.items) == 1:
                # A text with no following field
                if text_chunk.has_text(show_instructor):
                    layout.addWidget(new_browser(text_chunk))
                continue
            chunk = row.items[1]
            widget = self._new_field(chunk, font)
            if chunk.kind == 'checkbox' and text_chunk.has_text(show_instructor):
                # Checkbox: render inline with the preceding text in an HBox
                box_row = QHBoxLayout()
                box_row.setContentsMargins(0, 0, 0, 0)
                box_row.addWidget(new_browser(text_chunk), 1)
                box_row.addWidget(widget)
                layout.addLayout(box_row)
            else:
                # Non-checkbox: text above, widget below
                if text_chunk.has_text(show_instructor):
                    layout.addWidget(new_browser(text_chunk))
                layout.addWidget(widget)

        layout.addStretch()
        scroll.setWidget(container)
        outer.addWidget(scroll)

        self.set_answers(current_answers)

    # ------------------------------------------------------------------

    def _new_field(self, chunk, font: QFont) -> QWidget:
        """The input of the field *chunk*, kept under its name and wired to the answer signal."""
        name = chunk.name
        if chunk.kind == 'checkbox':
            cb = QCheckBox()
            cb.setFont(font)
            cb.setChecked(chunk.default)
            cb.stateChanged.connect(self._emit_changed)
            self._checkbox_fields[name] = cb
            return cb
        if chunk.kind == 'select':
            combo = QComboBox()
            combo.setFont(font)
            combo.addItems(chunk.labels)
            combo.currentIndexChanged.connect(self._emit_changed)
            if chunk.inline:
                combo.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
            self._combo_fields[name] = combo
            self._combo_values[name] = chunk.values
            return combo
        if chunk.kind == 'multiline':
            # Multi-line free text: a box of N lines, the text scrolls beyond
            edit = QPlainTextEdit()
            edit.setFont(font)
            edit.setTabChangesFocus(True)  # Tab moves to the next field, as in a QLineEdit
            edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            self._set_multiline_height(edit, chunk.lines)
            edit.textChanged.connect(self._emit_changed)
            edit.installEventFilter(self)
            self._multiline_fields[name] = edit
            self._multiline_lines[name] = chunk.lines
            return edit
        edit = QLineEdit()
        edit.setFont(font)
        if chunk.regex:
            edit.setValidator(
                QRegularExpressionValidator(QRegularExpression(chunk.regex))
            )
        edit.textChanged.connect(self._emit_changed)
        edit.installEventFilter(self)
        if chunk.inline:
            set_inline_width(edit, chunk.width)
            self._inline_widths[name] = chunk.width
        self._text_fields[name] = edit
        return edit

    def _emit_changed(self):
        self.answer_changed.emit(json.dumps(self.get_answers(), ensure_ascii=False))

    @staticmethod
    def _set_multiline_height(edit: QPlainTextEdit, lines: int):
        """Fix the height of a multi-line field to `lines` lines of its current font."""
        edit.setFixedHeight(lines * edit.fontMetrics().lineSpacing()
                            + int(2 * edit.document().documentMargin()) + 2 * edit.frameWidth())

    def get_answers(self) -> dict:
        result = {name: edit.text() for name, edit in self._text_fields.items()}
        result.update({name: edit.toPlainText() for name, edit in self._multiline_fields.items()})
        result.update({
            name: (self._combo_values[name][combo.currentIndex()]
                   if combo.currentIndex() >= 0 else "")
            for name, combo in self._combo_fields.items()
        })
        result.update({name: cb.isChecked() for name, cb in self._checkbox_fields.items()})
        return result

    def set_answers(self, answers: dict):
        for name, edit in self._text_fields.items():
            edit.blockSignals(True)
            edit.setText(answers.get(name, ""))
            edit.blockSignals(False)
        for name, edit in self._multiline_fields.items():
            edit.blockSignals(True)
            edit.setPlainText(answers.get(name, ""))
            edit.blockSignals(False)
        for name, combo in self._combo_fields.items():
            combo.blockSignals(True)
            saved = answers.get(name, "")
            values = self._combo_values.get(name, [])
            if saved in values:
                combo.setCurrentIndex(values.index(saved))
            else:
                idx = combo.findText(saved)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            combo.blockSignals(False)
        for name, cb in self._checkbox_fields.items():
            cb.blockSignals(True)
            cb.setChecked(bool(answers.get(name, cb.isChecked())))
            cb.blockSignals(False)

    def set_word_wrap(self, wrap: bool):
        for browser in self._browsers:
            browser.set_word_wrap(wrap)

    def apply_font_size(self, size: int):
        self._font_size = size
        font = QFont()
        font.setPointSize(size)
        for browser in self._browsers:
            browser.update_font_size(size)
        for name, edit in self._text_fields.items():
            edit.setFont(font)
            if name in self._inline_widths:
                set_inline_width(edit, self._inline_widths[name])
        for name, edit in self._multiline_fields.items():
            edit.setFont(font)
            self._set_multiline_height(edit, self._multiline_lines[name])
        for combo in self._combo_fields.values():
            combo.setFont(font)
        for cb in self._checkbox_fields.values():
            cb.setFont(font)
        for label in self.findChildren(QLabel):
            label.setFont(font)

    def eventFilter(self, obj, event):
        if isinstance(obj, (QLineEdit, QPlainTextEdit)):
            if event.type() == QEvent.Type.KeyPress:
                if event.modifiers() & Qt.ControlModifier:
                    key = event.key()
                    if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
                        settings.set_content_font_size(self._font_size + 1)
                        return True
                    if key in (Qt.Key.Key_Minus, Qt.Key.Key_Underscore):
                        settings.set_content_font_size(self._font_size - 1)
                        return True
            elif event.type() == QEvent.Type.Wheel:
                if event.modifiers() & Qt.ControlModifier:
                    settings.set_content_font_size(
                        self._font_size + (1 if event.angleDelta().y() > 0 else -1)
                    )
                    return True
        return super().eventFilter(obj, event)
