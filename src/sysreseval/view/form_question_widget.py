import json
import re

from PySide6.QtCore import Signal, QEvent, QSize
from PySide6.QtGui import Qt, QFont, QRegularExpressionValidator
from PySide6.QtCore import QRegularExpression
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, QCheckBox,
    QScrollArea, QTextBrowser, QFrame, QSizePolicy,
)

from SRE.instructor_text import markdown_to_html, rebalance_fragments, strip_instructor, unwrap_instructor
from sysreseval import settings

_FIELD_RE = re.compile(r'@@\{([^:}]+):([^}]*)\}@@')


class _AutoBrowser(QTextBrowser):
    """QTextBrowser that auto-sizes its height to fit its content."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._markdown_text = ""
        self._show_instructor = False
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.document().documentLayout().documentSizeChanged.connect(
            lambda _: self.updateGeometry()
        )

    def set_word_wrap(self, wrap: bool):
        self.setLineWrapMode(QTextBrowser.LineWrapMode.WidgetWidth if wrap
                             else QTextBrowser.LineWrapMode.NoWrap)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff if wrap
                                          else Qt.ScrollBarPolicy.ScrollBarAsNeeded)

    def set_markdown(self, text: str, font_size: int, show_instructor: bool = False):
        self._markdown_text = text
        self._show_instructor = show_instructor
        font = self.document().defaultFont()
        font.setPointSize(font_size)
        self.document().setDefaultFont(font)
        self.setHtml(markdown_to_html(text, show_instructor=show_instructor))

    def update_font_size(self, size: int):
        font = self.document().defaultFont()
        font.setPointSize(size)
        self.document().setDefaultFont(font)
        self.setHtml(markdown_to_html(self._markdown_text, show_instructor=self._show_instructor))

    def sizeHint(self):
        h = int(self.document().size().height()) + 6
        return QSize(super().sizeHint().width(), max(h, 10))

    def minimumSizeHint(self):
        return self.sizeHint()


class FormQuestionWidget(QWidget):
    answer_changed = Signal(str)  # JSON-encoded {field_name: value}

    def __init__(self, description: str, fields: list, current_answers: dict,
                 font_size: int, word_wrap: bool = True, show_instructor: bool = False, parent=None):
        super().__init__(parent)
        self._font_size = font_size
        self._text_fields: dict[str, QLineEdit] = {}
        self._combo_fields: dict[str, QComboBox] = {}
        self._combo_values: dict[str, list[str]] = {}
        self._checkbox_fields: dict[str, QCheckBox] = {}
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

        # re.split with capturing groups gives:
        #   [text, name, regex, text, name, regex, ..., text]
        segments = _FIELD_RE.split(description)
        # every text chunk is rendered on its own: an instructor fragment going across a field
        # is closed and reopened around it
        segments[0::3] = rebalance_fragments(segments[0::3])

        def has_text(chunk: str) -> bool:
            return bool((unwrap_instructor(chunk) if show_instructor else strip_instructor(chunk)).strip())

        i = 0
        while i < len(segments):
            text_chunk = segments[i]

            if i + 2 < len(segments):
                name = segments[i + 1]
                spec = segments[i + 2]

                if spec.startswith('?'):
                    # Checkbox: render inline with the preceding text in an HBox
                    default = spec[1:].strip().lower() not in ('', 'false')
                    cb = QCheckBox()
                    cb.setFont(font)
                    cb.setChecked(default)
                    cb.stateChanged.connect(self._emit_changed)
                    self._checkbox_fields[name] = cb
                    if has_text(text_chunk):
                        row = QHBoxLayout()
                        row.setContentsMargins(0, 0, 0, 0)
                        browser = _AutoBrowser()
                        browser.setOpenExternalLinks(True)
                        browser.set_markdown(text_chunk, font_size, show_instructor)
                        browser.set_word_wrap(word_wrap)
                        row.addWidget(browser, 1)
                        row.addWidget(cb)
                        layout.addLayout(row)
                        self._browsers.append(browser)
                    else:
                        layout.addWidget(cb)
                else:
                    # Non-checkbox: text above, widget below
                    if has_text(text_chunk):
                        browser = _AutoBrowser()
                        browser.setOpenExternalLinks(True)
                        browser.set_markdown(text_chunk, font_size, show_instructor)
                        browser.set_word_wrap(word_wrap)
                        layout.addWidget(browser)
                        self._browsers.append(browser)

                    if spec.startswith('>') or '>>>' in spec:
                        raw = spec[1:] if spec.startswith('>') else spec
                        pairs = []
                        for c in raw.split('|'):
                            c = c.strip()
                            if '>>>' in c:
                                label, value = c.split('>>>', 1)
                                pairs.append((label.strip(), value.strip()))
                            else:
                                pairs.append((c, c))
                        combo = QComboBox()
                        combo.setFont(font)
                        combo.addItems([label for label, _ in pairs])
                        combo.currentIndexChanged.connect(self._emit_changed)
                        layout.addWidget(combo)
                        self._combo_fields[name] = combo
                        self._combo_values[name] = [value for _, value in pairs]
                    else:
                        edit = QLineEdit()
                        edit.setFont(font)
                        if spec:
                            edit.setValidator(
                                QRegularExpressionValidator(QRegularExpression(spec))
                            )
                        edit.textChanged.connect(self._emit_changed)
                        edit.installEventFilter(self)
                        layout.addWidget(edit)
                        self._text_fields[name] = edit
            else:
                # Last text chunk with no following field
                if has_text(text_chunk):
                    browser = _AutoBrowser()
                    browser.setOpenExternalLinks(True)
                    browser.set_markdown(text_chunk, font_size, show_instructor)
                    browser.set_word_wrap(word_wrap)
                    layout.addWidget(browser)
                    self._browsers.append(browser)

            i += 3

        layout.addStretch()
        scroll.setWidget(container)
        outer.addWidget(scroll)

        self.set_answers(current_answers)

    # ------------------------------------------------------------------

    def _emit_changed(self):
        self.answer_changed.emit(json.dumps(self.get_answers(), ensure_ascii=False))

    def get_answers(self) -> dict:
        result = {name: edit.text() for name, edit in self._text_fields.items()}
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
        for edit in self._text_fields.values():
            edit.setFont(font)
        for combo in self._combo_fields.values():
            combo.setFont(font)
        for cb in self._checkbox_fields.values():
            cb.setFont(font)
        for label in self.findChildren(QLabel):
            label.setFont(font)

    def eventFilter(self, obj, event):
        if isinstance(obj, QLineEdit):
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
