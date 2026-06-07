import json
import subprocess

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QMessageBox
)
from PySide6.QtGui import Qt

from SRE import params
from SRE.common import TranslatedText
from sysreseval import settings, util


def _populate_tree(root: QTreeWidgetItem | QTreeWidget, entries: list[dict], lang_priority: list):
    """Build a hierarchy from entries of the form ``{"name": "a/b/c.py", "title": dict|None}``.

    Non-leaf segments use the raw segment as label (directories). Leaf segments
    show the translated title resolved against *lang_priority* when available,
    falling back to the segment with ``.py`` stripped. The raw segment is kept
    in ``Qt.UserRole`` so the full path can be reconstructed for ``sre start``.
    """
    def find_or_create(parent, segment, label):
        for i in range(parent.childCount() if hasattr(parent, 'childCount') else parent.topLevelItemCount()):
            item = parent.child(i) if hasattr(parent, 'child') else parent.topLevelItem(i)
            if item.data(0, Qt.UserRole) == segment:
                return item
        child = QTreeWidgetItem([label])
        child.setData(0, Qt.UserRole, segment)
        if hasattr(parent, 'addChild'):
            parent.addChild(child)
        else:
            parent.addTopLevelItem(child)
        return child

    for entry in sorted(entries, key=lambda e: e["name"]):
        parts = entry["name"].split("/")
        title_dict = entry.get("title")
        leaf_label = None
        if title_dict:
            leaf_label = TranslatedText.from_value(title_dict).resolve_priority(lang_priority)
        node = root
        for i, segment in enumerate(parts):
            is_leaf = (i == len(parts) - 1)
            if is_leaf:
                label = leaf_label or segment.removesuffix('.py')
            else:
                label = segment
            node = find_or_create(node, segment, label)


def _full_path(item: QTreeWidgetItem) -> str:
    """Reconstruct the full slash-separated path from a tree item."""
    parts = []
    while item is not None:
        parts.append(item.data(0, Qt.UserRole) or item.text(0))
        item = item.parent()
    return "/".join(reversed(parts))


def _is_leaf(item: QTreeWidgetItem) -> bool:
    return item.childCount() == 0


class OpenProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Open project"))
        self.resize(500, 500)
        self.selected_project = None

        layout = QVBoxLayout(self)

        self.status_label = QLabel(self.tr("Loading available projects…"))
        layout.addWidget(self.status_label)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        self.tree.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self.tree)

        buttons = QHBoxLayout()
        self.open_button = QPushButton(self.tr("Open"))
        self.open_button.setEnabled(False)
        self.open_button.clicked.connect(self.accept)
        cancel_button = QPushButton(self.tr("Cancel"))
        cancel_button.clicked.connect(self.reject)
        buttons.addStretch()
        buttons.addWidget(cancel_button)
        buttons.addWidget(self.open_button)
        layout.addLayout(buttons)

        self._load_projects()

    def _load_projects(self):
        try:
            cmd = [params.sre_wrapper, "list", "--with-titles"]
            util.log_wrapper_cmd(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0 or not result.stdout.strip():
                detail = result.stderr.strip() or self.tr("(no output)")
                self.status_label.setText(
                    self.tr("Error running 'sre list' (exit {code}): {detail}").format(
                        code=result.returncode, detail=detail
                    )
                )
                return
            entries = json.loads(result.stdout)
        except Exception as e:
            self.status_label.setText(self.tr("Error: {error}").format(error=e))
            return

        self.status_label.hide()
        _populate_tree(self.tree, entries, settings.get_language_priority())
        self.tree.collapseAll()

    def _on_selection_changed(self):
        items = self.tree.selectedItems()
        self.open_button.setEnabled(bool(items) and _is_leaf(items[0]))

    def _on_double_click(self, item, _column):
        if _is_leaf(item):
            self.accept()

    def accept(self):
        items = self.tree.selectedItems()
        if not items or not _is_leaf(items[0]):
            return
        self.selected_project = _full_path(items[0])
        super().accept()
