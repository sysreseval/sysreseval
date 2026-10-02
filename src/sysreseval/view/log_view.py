"""GUI "Log" tab of a debug project: a live tail of the project's ``operations.log``.

The file is written by the CLI (``sre state`` / ``sre eval``, see ``SRE/operations_log.py``) and
polled by :meth:`LogView.refresh` on the 1 s tick of :class:`ProjectWidget`; only the bytes
written since the last call are read and appended.  *Clear* empties the display only (the
student uid cannot truncate the file).
"""
import codecs
from pathlib import Path

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QFontDatabase, QTextCursor
from PySide6.QtWidgets import QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from SRE import params
from sysreseval import settings


class _LogTextEdit(QPlainTextEdit):
    """Read-only monospace text area; Ctrl+wheel / Ctrl+plus/minus change the content font size."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setMaximumBlockCount(params.operations_log_view_max_lines)
        self._font_size = settings.get_content_font_size()
        self._apply_font()
        settings.add_content_font_size_listener(self._on_font_size_changed)

    def _apply_font(self):
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(self._font_size)
        self.setFont(font)

    def _on_font_size_changed(self, size: int):
        self._font_size = size
        self._apply_font()

    def _adjust(self, delta: int):
        settings.set_content_font_size(self._font_size + delta)

    def keyPressEvent(self, event):
        if event.modifiers() & Qt.ControlModifier:
            key = event.key()
            if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
                self._adjust(1)
                return
            if key in (Qt.Key.Key_Minus, Qt.Key.Key_Underscore):
                self._adjust(-1)
                return
        super().keyPressEvent(event)

    def wheelEvent(self, event):
        if event.modifiers() & Qt.ControlModifier:
            self._adjust(1 if event.angleDelta().y() > 0 else -1)
            return
        super().wheelEvent(event)


class LogView(QWidget):
    def __init__(self, log_path: Path, parent=None):
        super().__init__(parent)
        self._path = Path(log_path)
        self._offset = 0  # bytes of the file already shown
        self._decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')

        self._clear_button = QPushButton(self.tr("Clear"))
        self._clear_button.clicked.connect(self.clear)
        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self._clear_button)

        self._text = _LogTextEdit()

        layout = QVBoxLayout(self)
        layout.addLayout(buttons)
        layout.addWidget(self._text)

        self.refresh()

    def changeEvent(self, event):
        if event.type() == QEvent.Type.LanguageChange:
            self._clear_button.setText(self.tr("Clear"))
        super().changeEvent(event)

    def refresh(self) -> bool:
        """Append what was written to the file since the last call.  Starts over when the file
        shrank or was recreated.  Returns True when the display changed."""
        try:
            size = self._path.stat().st_size
        except OSError:
            if self._offset:
                self._reset()
                return True
            return False
        if size < self._offset:
            self._reset()
        if size == self._offset:
            return False
        try:
            with open(self._path, 'rb') as f:
                f.seek(self._offset)
                data = f.read()
        except OSError:
            return False
        if not data:
            return False
        self._offset += len(data)
        self._append(self._decoder.decode(data))
        return True

    def clear(self):
        """Empty the display; the file is untouched and only new content appears afterwards."""
        self._text.clear()

    def plain_text(self) -> str:
        return self._text.toPlainText()

    def _reset(self):
        self._offset = 0
        self._decoder.reset()
        self._text.clear()

    def _append(self, text: str):
        if not text:
            return
        scrollbar = self._text.verticalScrollBar()
        at_bottom = scrollbar.value() >= scrollbar.maximum() - 2
        cursor = QTextCursor(self._text.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        if at_bottom:
            scrollbar.setValue(scrollbar.maximum())
