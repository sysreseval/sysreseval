import json

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QFont, QRegularExpressionValidator, QValidator
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, QCheckBox, QPushButton,
    QScrollArea, QWidget, QFrame,
)

from sysreseval import settings
from sysreseval.view.form_question_widget import _FIELD_RE, _AutoBrowser


class FlavorFormDialog(QDialog):
    """Modal dialog that renders a flavor form described with @@{...}@@ syntax.

    Field types:
      @@{name:regex}@@      — QLineEdit with optional regex validator
      @@{name:>A|B|C}@@     — QComboBox with choices
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

        # re.split with capturing groups gives:
        #   [text, name, spec, text, name, spec, ..., text]
        segments = _FIELD_RE.split(form_text)
        has_submit = False
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
                    self._checkbox_fields[name] = cb
                    if text_chunk.strip():
                        row = QHBoxLayout()
                        row.setContentsMargins(0, 0, 0, 0)
                        browser = _AutoBrowser()
                        browser.setOpenExternalLinks(True)
                        browser.set_markdown(text_chunk, font_size)
                        row.addWidget(browser, 1)
                        row.addWidget(cb)
                        layout.addLayout(row)
                    else:
                        layout.addWidget(cb)
                else:
                    # Non-checkbox: text above, widget below
                    if text_chunk.strip():
                        browser = _AutoBrowser()
                        browser.setOpenExternalLinks(True)
                        browser.set_markdown(text_chunk, font_size)
                        layout.addWidget(browser)

                    if spec.startswith(':'):
                        # Submit button
                        label = spec[1:].strip() or name
                        btn = QPushButton(label)
                        btn.setFont(font)
                        btn.clicked.connect(lambda checked, n=name: self._on_submit(n))
                        layout.addWidget(btn)
                        self._submit_fields[name] = btn
                        has_submit = True
                    elif spec.startswith('>') or '>>>' in spec:
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
                            edit.textChanged.connect(lambda _, e=edit: self._clear_error(e))
                        layout.addWidget(edit)
                        self._text_fields[name] = edit
            else:
                # Last text chunk with no following field
                if text_chunk.strip():
                    browser = _AutoBrowser()
                    browser.setOpenExternalLinks(True)
                    browser.set_markdown(text_chunk, font_size)
                    layout.addWidget(browser)

            i += 3

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
        answers.update({
            name: (self._combo_values[name][combo.currentIndex()]
                   if combo.currentIndex() >= 0 else "")
            for name, combo in self._combo_fields.items()
        })
        answers.update({name: cb.isChecked() for name, cb in self._checkbox_fields.items()})
        for name in self._submit_fields:
            answers[name] = (name == self._pressed_button)
        return json.dumps(answers, ensure_ascii=False)
