from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFormLayout, QSpinBox, QComboBox, QLabel, QSlider
)
from PySide6.QtCore import Qt

from sysreseval import settings


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Settings"))
        self.setMinimumWidth(320)

        layout = QFormLayout(self)

        # --- Interface section ---
        layout.addRow(QLabel(f"<b>{self.tr('Interface')}</b>"))

        self._system_font_size = QSpinBox()
        self._system_font_size.setRange(6, 48)
        self._system_font_size.setValue(settings.get_system_font_size())
        self._system_font_size.setSuffix(" pt")
        layout.addRow(self.tr("Font size:"), self._system_font_size)

        # --- Terminal section ---
        layout.addRow(QLabel(f"<b>{self.tr('Terminal')}</b>"))

        self._font_size = QSpinBox()
        self._font_size.setRange(6, 48)
        self._font_size.setValue(settings.get_font_size())
        self._font_size.setSuffix(" pt")
        layout.addRow(self.tr("Font size:"), self._font_size)

        self._color_scheme = QComboBox()
        self._color_scheme.addItem(self.tr("White on Black"), "white_on_black")
        self._color_scheme.addItem(self.tr("Black on White"), "black_on_white")
        idx = self._color_scheme.findData(settings.get_color_scheme())
        if idx >= 0:
            self._color_scheme.setCurrentIndex(idx)
        layout.addRow(self.tr("Color scheme:"), self._color_scheme)

        note = QLabel(self.tr("(Changes apply to terminals opened after this point.)"))
        note.setWordWrap(True)
        layout.addRow(note)

        # --- Schema section ---
        layout.addRow(QLabel(f"<b>{self.tr('Schema')}</b>"))

        self._schema_lines = QComboBox()
        self._schema_lines.addItem(self.tr("Straight"), False)
        self._schema_lines.addItem(self.tr("Curved"), True)
        idx = self._schema_lines.findData(settings.get_schema_curved())
        self._schema_lines.setCurrentIndex(idx if idx >= 0 else 0)
        layout.addRow(self.tr("Lines:"), self._schema_lines)

        self._schema_sep = QSlider(Qt.Horizontal)
        self._schema_sep.setRange(0, 9)
        self._schema_sep.setValue(settings.get_schema_sep())
        self._schema_sep.setTickPosition(QSlider.TicksBelow)
        self._schema_sep.setTickInterval(1)
        layout.addRow(self.tr("Spacing:"), self._schema_sep)

        self._schema_nodes = QComboBox()
        self._schema_nodes.addItem(self.tr("Icons"), True)
        self._schema_nodes.addItem(self.tr("Shapes"), False)
        idx = self._schema_nodes.findData(settings.get_schema_use_icons())
        self._schema_nodes.setCurrentIndex(idx if idx >= 0 else 0)
        layout.addRow(self.tr("Nodes:"), self._schema_nodes)

        # --- Content section ---
        layout.addRow(QLabel(f"<b>{self.tr('Content')}</b>"))

        self._content_font_size = QSpinBox()
        self._content_font_size.setRange(6, 48)
        self._content_font_size.setValue(settings.get_content_font_size())
        self._content_font_size.setSuffix(" pt")
        layout.addRow(self.tr("Font size:"), self._content_font_size)

        # --- Buttons ---
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _save(self):
        settings.set_system_font_size(self._system_font_size.value())
        settings.save(self._font_size.value(), self._color_scheme.currentData())
        settings.save_schema(
            self._schema_lines.currentData(),
            self._schema_sep.value(),
            self._schema_nodes.currentData(),
        )
        settings.set_content_font_size(self._content_font_size.value())
        self.accept()
