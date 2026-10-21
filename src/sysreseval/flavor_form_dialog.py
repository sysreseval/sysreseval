import json

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QFont, QRegularExpressionValidator, QValidator
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, QCheckBox, QPushButton,
    QScrollArea, QWidget, QFrame, QPlainTextEdit, QSizePolicy,
)

from SRE.form_spec import TextChunk, parse_form_description
from sysreseval import settings
from sysreseval.view.form_question_widget import _AutoBrowser, FormQuestionWidget


class FlavorFormDialog(QDialog):
    """Modal dialog that renders a flavor form described with @@{...}@@ syntax.

    Field types:
      @@{name:regex}@@      — QLineEdit with optional regex validator
      @@{name:+N}@@         — QPlainTextEdit of N lines, free text ('+' alone: default height)
      @@{name:>A|B|C}@@     — QComboBox with choices (a choice 'Label>>>value' shows the label)
      @@{name:?}@@          — QCheckBox ('?true': checked by default)
      @@{name::Label}@@     — QPushButton that submits the form (spec starts with ':')

    If no submit button is present in the form text, a default "Submit" button is
    added automatically. A "Cancel" button is always shown.
    """

    def __init__(self, form_text: str, form_size: list | None = None,
                 previous_answers: dict | None = None,
                 error_message: str | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Lab configuration"))
        self.setModal(True)
        w, h = form_size if form_size and len(form_size) == 2 else [640, 480]
        self.resize(w, h)

        self._text_fields: dict[str, QLineEdit] = {}
        self._multiline_fields: dict[str, QPlainTextEdit] = {}
        self._combo_fields: dict[str, QComboBox] = {}
        self._combo_values: dict[str, list[str]] = {}
        self._checkbox_fields: dict[str, QCheckBox] = {}
        self._submit_fields: dict[str, QPushButton] = {}
        self._pressed_button: str | None = None

        font_size = settings.get_content_font_size()
        font = QFont()
        font.setPointSize(font_size)

        outer = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(6)
        layout.setContentsMargins(4, 4, 4, 4)

        def new_browser(text_chunk: TextChunk) -> _AutoBrowser:
            browser = _AutoBrowser()
            browser.setOpenExternalLinks(True)
            browser.set_markdown(text_chunk.text, font_size)
            return browser

        # the chunks alternate: a text (possibly empty) before every field, one after the last
        has_submit = False
        text_chunk = None
        for chunk in parse_form_description(form_text, allow_submit=True):
            if isinstance(chunk, TextChunk):
                text_chunk = chunk
                continue
            name = chunk.name

            if chunk.kind == 'checkbox':
                # Checkbox: render inline with the preceding text in an HBox
                cb = QCheckBox()
                cb.setFont(font)
                cb.setChecked(chunk.default)
                self._checkbox_fields[name] = cb
                if text_chunk.has_text():
                    row = QHBoxLayout()
                    row.setContentsMargins(0, 0, 0, 0)
                    row.addWidget(new_browser(text_chunk), 1)
                    row.addWidget(cb)
                    layout.addLayout(row)
                else:
                    layout.addWidget(cb)
            else:
                # Non-checkbox: text above, widget below
                if text_chunk.has_text():
                    layout.addWidget(new_browser(text_chunk))

                if chunk.kind == 'submit':
                    # Submit button
                    btn = QPushButton(chunk.label)
                    btn.setFont(font)
                    btn.clicked.connect(lambda checked, n=name: self._on_submit(n))
                    layout.addWidget(btn)
                    self._submit_fields[name] = btn
                    has_submit = True
                elif chunk.kind == 'select':
                    combo = QComboBox()
                    combo.setFont(font)
                    combo.addItems(chunk.labels)
                    layout.addWidget(combo)
                    self._combo_fields[name] = combo
                    self._combo_values[name] = chunk.values
                elif chunk.kind == 'multiline':
                    # Multi-line free text, never validated
                    edit = QPlainTextEdit()
                    edit.setFont(font)
                    edit.setTabChangesFocus(True)
                    edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                    FormQuestionWidget._set_multiline_height(edit, chunk.lines)
                    layout.addWidget(edit)
                    self._multiline_fields[name] = edit
                else:
                    edit = QLineEdit()
                    edit.setFont(font)
                    if chunk.regex:
                        edit.setValidator(
                            QRegularExpressionValidator(QRegularExpression(chunk.regex))
                        )
                        edit.textChanged.connect(lambda _, e=edit: self._clear_error(e))
                    layout.addWidget(edit)
                    self._text_fields[name] = edit
            text_chunk = None

        # Last text chunk with no following field
        if text_chunk is not None and text_chunk.has_text():
            layout.addWidget(new_browser(text_chunk))

        layout.addStretch()
        scroll.setWidget(container)
        outer.addWidget(scroll)

        # Error message label (shown when allowed_by_user() rejects the flavor)
        if error_message:
            error_font = QFont()
            error_font.setPointSize(font_size + 1)
            error_font.setBold(True)
            self._error_label = QLabel(error_message)
            self._error_label.setFont(error_font)
            self._error_label.setStyleSheet("color: red;")
            self._error_label.setWordWrap(True)
            outer.addWidget(self._error_label)

        # Bottom button row
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton(self.tr("Cancel"))
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        if not has_submit:
            submit_btn = QPushButton(self.tr("Submit"))
            submit_btn.setFont(font)
            submit_btn.setDefault(True)
            submit_btn.clicked.connect(lambda: self._on_submit(None))
            btn_row.addWidget(submit_btn)

        outer.addLayout(btn_row)

        # Pre-fill fields from previous submission
        if previous_answers:
            self._set_answers(previous_answers)

    # ------------------------------------------------------------------

    def _set_answers(self, answers: dict):
        for name, edit in self._text_fields.items():
            edit.blockSignals(True)
            edit.setText(str(answers.get(name, "")))
            edit.blockSignals(False)
        for name, edit in self._multiline_fields.items():
            edit.blockSignals(True)
            edit.setPlainText(str(answers.get(name, "")))
            edit.blockSignals(False)
        for name, combo in self._combo_fields.items():
            saved = str(answers.get(name, ""))
            values = self._combo_values.get(name, [])
            if saved in values:
                combo.setCurrentIndex(values.index(saved))
            else:
                idx = combo.findText(saved)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
        for name, cb in self._checkbox_fields.items():
            cb.blockSignals(True)
            cb.setChecked(bool(answers.get(name, cb.isChecked())))
            cb.blockSignals(False)

    def _clear_error(self, edit: QLineEdit):
        edit.setStyleSheet("")

    def _on_submit(self, button_name: str | None):
        all_valid = True
        for edit in self._text_fields.values():
            v = edit.validator()
            if v is not None:
                state, _, _ = v.validate(edit.text(), len(edit.text()))
                if state != QValidator.State.Acceptable:
                    edit.setStyleSheet("QLineEdit { border: 1px solid red; }")
                    all_valid = False
                else:
                    edit.setStyleSheet("")
        if not all_valid:
            return
        self._pressed_button = button_name
        self.accept()

    def get_flavor_json(self) -> str:
        answers: dict = {}
        answers.update({name: edit.text() for name, edit in self._text_fields.items()})
        answers.update({name: edit.toPlainText() for name, edit in self._multiline_fields.items()})
        answers.update({
            name: (self._combo_values[name][combo.currentIndex()]
                   if combo.currentIndex() >= 0 else "")
            for name, combo in self._combo_fields.items()
        })
        answers.update({name: cb.isChecked() for name, cb in self._checkbox_fields.items()})
        for name in self._submit_fields:
            answers[name] = (name == self._pressed_button)
        return json.dumps(answers, ensure_ascii=False)
