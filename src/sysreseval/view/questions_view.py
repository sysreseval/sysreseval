import getpass
import json
import pwd
import re
import socket
import textwrap
from datetime import datetime
from pathlib import Path

import markdown as _md
from PySide6.QtCore import QEvent
from PySide6.QtGui import Qt, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QSplitter, QListWidget, QTextEdit,
    QTextBrowser, QStackedWidget,
)

from SRE import params
from SRE.common import TranslatedText
from SRE.utils import exam_remaining_seconds
from sysreseval import settings
from sysreseval.view.form_question_widget import FormQuestionWidget

_FORM_TYPE = 2   # QuestionType.FORM.value
_DUMMY_TYPE = 0  # QuestionType.DUMMY.value

_SESSION_LOGIN    = getpass.getuser()
_SESSION_HOSTNAME = socket.gethostname()
try:
    _gecos = pwd.getpwnam(_SESSION_LOGIN).pw_gecos
except Exception:
    _gecos = ''
_SESSION_FULLNAME = re.sub(r'[\x00-\x1f\x7f,]', '', _gecos.split(',')[0]).strip() if _gecos else ''
_SESSION_EMAIL    = re.sub(r'[\x00-\x1f\x7f]', '', _gecos.split(',')[-1]).strip() if _gecos else ''


def _get_exam_fields() -> dict:
    """Return exam answer fields from exam.json. Always includes exam_mode (bool)."""
    path = Path(params.sre_pub_dir) / params.exam_json_name
    try:
        with open(path) as f:
            exam_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {params.sysreseval_exam_mode: False}
    result = {params.sysreseval_exam_mode: True}
    if params.exam_started_at in exam_data:
        result[params.sysreseval_exam_started_at] = exam_data[params.exam_started_at]
    if params.exam_duration in exam_data:
        result[params.sysreseval_exam_duration] = exam_data[params.exam_duration]
    return result


def _get_exam_remaining_seconds() -> int | None:
    """Return remaining exam seconds if the exam is active, else None."""
    path = Path(params.sre_pub_dir) / params.exam_json_name
    try:
        with open(path) as f:
            exam_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return exam_remaining_seconds(exam_data)


def _to_html(text: str) -> str:
    return _md.markdown(textwrap.dedent(text).strip(), extensions=["fenced_code", "tables"])


class QuestionsView(QWidget):
    def __init__(self, questions: list, running_lab_name: str, parent=None):
        super().__init__(parent)

        self._running_lab_name = running_lab_name
        self._answers: dict[str, str] = {}
        self._current_hash: str | None = None
        self._loading = False  # guard: don't save while setting text programmatically
        self._font_size = settings.get_content_font_size()
        self._current_form_widget: FormQuestionWidget | None = None
        self._lang_priority = settings.get_language_priority()

        self._load_answers()
        self._save_answers()
        self._word_wrap = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)

        self.list_widget = QListWidget()

        # Right panel: stacked widget with two pages
        #   index 0 — text/dummy: question_text + answer_text splitter
        #   index 1 — form: FormQuestionWidget (swapped dynamically)
        self._right_panel = QStackedWidget()

        right_splitter = QSplitter(Qt.Vertical)
        self.question_text = QTextBrowser()
        self.question_text.setOpenExternalLinks(True)

        self.answer_text = QTextEdit()
        self.answer_text.setPlaceholderText(self.tr("Write your answer here..."))
        self.answer_text.textChanged.connect(self._on_answer_changed)

        right_splitter.addWidget(self.question_text)
        right_splitter.addWidget(self.answer_text)

        self._right_panel.addWidget(right_splitter)   # index 0

        splitter.addWidget(self.list_widget)
        splitter.addWidget(self._right_panel)
        outer.addWidget(splitter)

        self.question_text.installEventFilter(self)
        self.answer_text.installEventFilter(self)
        self.list_widget.installEventFilter(self)

        self._questions = []
        self.list_widget.currentRowChanged.connect(self._display_current_question)

        self._apply_font_size()
        self.update_data(questions)

        settings.add_content_font_size_listener(self._on_font_size_changed)

    # ------------------------------------------------------------------
    # Font size
    # ------------------------------------------------------------------

    def set_word_wrap(self, checked: bool):
        self._word_wrap = checked
        row = self.list_widget.currentRow()
        if row >= 0:
            if (self._right_panel.currentIndex() == 1
                    and self._current_form_widget is not None):
                self._current_form_widget.set_word_wrap(checked)
            else:
                self._display_current_question(row)

    def _on_font_size_changed(self, size: int):
        self._font_size = size
        self._apply_font_size()
        if self._right_panel.currentIndex() == 1 and self._current_form_widget is not None:
            self._current_form_widget.apply_font_size(size)
        else:
            row = self.list_widget.currentRow()
            if 0 <= row < len(self._questions):
                q = self._questions[row]
                self.question_text.setHtml(_to_html(self._resolve(q.get("description", ""))))

    def _apply_font_size(self):
        font = QFont(self.answer_text.font())
        font.setPointSize(self._font_size)
        self.answer_text.setFont(font)
        self.list_widget.setFont(font)
        font2 = self.question_text.document().defaultFont()
        font2.setPointSize(self._font_size)
        self.question_text.document().setDefaultFont(font2)

    def eventFilter(self, obj, event):
        if obj in (self.question_text, self.answer_text, self.list_widget):
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
                    delta = 1 if event.angleDelta().y() > 0 else -1
                    settings.set_content_font_size(self._font_size + delta)
                    return True
        return super().eventFilter(obj, event)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_answers(self):
        path = Path(params.answers_filename(self._running_lab_name))
        try:
            self._answers = json.loads(path.read_text())
        except Exception:
            self._answers = {}
        self._answers[params.hostname_keyword] = _SESSION_HOSTNAME
        self._answers[params.login_keyword]    = _SESSION_LOGIN
        self._answers[params.fullname_keyword] = _SESSION_FULLNAME
        if params.email_in_gecos_last_field:
            self._answers[params.email_keyword] = _SESSION_EMAIL

    def save_answers(self):
        """Public entry point — force-write answers.json (e.g. on exam start)."""
        self._save_answers()

    def _save_answers(self):
        path = Path(params.answers_filename(self._running_lab_name))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = dict(self._answers)
            data[params.sysreseval_answers_updated_at] = params.datetime_to_string(datetime.now())
            data[params.language_keyword] = self._lang_priority[0] if self._lang_priority else 'en'
            data.update(_get_exam_fields())
            remaining = _get_exam_remaining_seconds()
            if remaining is not None:
                data[params.sysreseval_exam_time_remaining] = remaining
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        except Exception:
            pass

    def _on_answer_changed(self):
        if self._loading or self._current_hash is None:
            return
        self._answers[self._current_hash] = self.answer_text.toPlainText()
        self._save_answers()

    def _on_form_answer_changed(self, q_hash: str, json_str: str):
        self._answers[q_hash] = json_str
        self._save_answers()

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def _resolve(self, v) -> str:
        return TranslatedText.from_value(v).resolve_priority(self._lang_priority)

    def update_data(self, questions: list):
        current_hash = None
        row = self.list_widget.currentRow()
        if 0 <= row < len(self._questions):
            current_hash = self._questions[row].get("question_hash")

        self._questions = questions
        self.list_widget.clear()
        for q in questions:
            self.list_widget.addItem(self._resolve(q.get("title", self.tr("Untitled"))))

        restored = False
        if current_hash:
            for i, q in enumerate(questions):
                if q.get("question_hash") == current_hash:
                    self.list_widget.setCurrentRow(i)
                    restored = True
                    break
        if not restored and questions:
            self.list_widget.setCurrentRow(0)

    def set_language_priority(self, priority: list):
        self._lang_priority = priority
        self._save_answers()
        self.update_data(self._questions)

    def apply_cheat(self, cheat: dict):
        """Populate answers from cheat dict (question_hash -> answer) and persist."""
        for q_hash, answer in cheat.items():
            self._answers[q_hash] = answer
        self._save_answers()
        row = self.list_widget.currentRow()
        if 0 <= row < len(self._questions):
            q = self._questions[row]
            q_hash = q.get("question_hash")
            if q_hash not in cheat:
                return
            if q.get("question_type") == _FORM_TYPE:
                if self._current_form_widget is not None:
                    try:
                        d = json.loads(cheat[q_hash])
                    except Exception:
                        d = {}
                    self._current_form_widget.set_answers(d)
            else:
                self._loading = True
                self.answer_text.setPlainText(self._answers.get(q_hash, ""))
                self._loading = False

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _switch_to_form(self, q: dict):
        # Remove previous form widget if any
        if self._current_form_widget is not None:
            self._right_panel.removeWidget(self._current_form_widget)
            self._current_form_widget.deleteLater()
            self._current_form_widget = None

        q_hash = q.get("question_hash")
        try:
            current = json.loads(self._answers.get(q_hash, "{}") or "{}")
        except Exception:
            current = {}

        fw = FormQuestionWidget(
            description=self._resolve(q.get("description", "")),
            fields=q.get("fields", []),
            current_answers=current,
            font_size=self._font_size,
            word_wrap=self._word_wrap,
        )
        fw.answer_changed.connect(lambda s, h=q_hash: self._on_form_answer_changed(h, s))
        self._current_form_widget = fw
        self._right_panel.addWidget(fw)   # always becomes index 1
        self._right_panel.setCurrentIndex(1)
        self._current_hash = q_hash

    def _display_current_question(self, index):
        if index < 0 or index >= len(self._questions):
            return
        q = self._questions[index]

        if q.get("question_type") == _FORM_TYPE:
            self._switch_to_form(q)
            return

        self._right_panel.setCurrentIndex(0)
        self.question_text.setHtml(_to_html(self._resolve(q.get("description", ""))))

        is_dummy = q.get("question_type") == _DUMMY_TYPE
        self.question_text.setLineWrapMode(
            QTextEdit.LineWrapMode.WidgetWidth if self._word_wrap else QTextEdit.LineWrapMode.NoWrap
        )
        self.answer_text.setVisible(not is_dummy)

        self._loading = True
        self._current_hash = None if is_dummy else q.get("question_hash")
        self.answer_text.setPlainText(
            self._answers.get(self._current_hash, "") if self._current_hash else ""
        )
        self._loading = False
