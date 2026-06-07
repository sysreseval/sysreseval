import markdown as _md

from PySide6.QtGui import Qt
from PySide6.QtWidgets import QTextBrowser, QTextEdit

from sysreseval import settings


def _to_html(text: str) -> str:
    import textwrap
    return _md.markdown(textwrap.dedent(text).strip(), extensions=["fenced_code", "tables"])


class InformationsView(QTextBrowser):
    def __init__(self, markdown_text: str, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self._markdown_text = markdown_text
        self._font_size = settings.get_content_font_size()
        self._render()
        settings.add_content_font_size_listener(self._on_font_size_changed)

    def _render(self):
        font = self.document().defaultFont()
        font.setPointSize(self._font_size)
        self.document().setDefaultFont(font)
        self.setHtml(_to_html(self._markdown_text))

    def _on_font_size_changed(self, size: int):
        self._font_size = size
        self._render()

    def _adjust(self, delta: int):
        settings.set_content_font_size(self._font_size + delta)

    def update_data(self, markdown_text: str):
        self._markdown_text = markdown_text
        self._render()

    def set_word_wrap(self, checked: bool):
        self.setLineWrapMode(
            QTextEdit.LineWrapMode.WidgetWidth if checked else QTextEdit.LineWrapMode.NoWrap
        )

    def set_language(self, lang: str):
        pass  # language resolution is done by the caller (project_widget)

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
