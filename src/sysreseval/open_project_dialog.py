import json
import subprocess

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QMessageBox, QSplitter, QTextBrowser
)
from PySide6.QtGui import Qt

from SRE import params
from SRE.common import TranslatedText, order_tree_entries, resolve_readme
from SRE.instructor_text import markdown_to_html
from sysreseval import settings, util

#: The roles of the items of the tree: the raw segment of the path (rebuilt from it for
#: ``sre start``), the kind of the entry (dir / lab), its arrival index, on a parent the sort
#: mode its children are placed by, and on a directory (the invisible root item for the top of
#: the lab directory) the markdown of its README in the user's language, ``''`` without one.
ROLE_SEGMENT = Qt.UserRole
ROLE_KIND = Qt.UserRole + 1
ROLE_INDEX = Qt.UserRole + 2
ROLE_CHILD_SORT = Qt.UserRole + 3
ROLE_README = Qt.UserRole + 4

#: The size of the dialog: the one it always had, and the one it opens with when a directory
#: of the tree has a README to show under the tree.
DIALOG_SIZE = (500, 500)
DIALOG_SIZE_WITH_README = (640, 720)


def _populate_tree(root: QTreeWidgetItem | QTreeWidget, entries: list[dict], lang_priority: list):
    """Build the lab tree from the entries of ``sre list --with-titles``, in their order, the
    display order of the CLI (a directory entry right before its content, the sub-directories of
    a directory before its labs, each group in the ``name`` or ``manual`` order of its
    ``titles.json``): ``{"name": "a/b/c.py", "title": dict|str|None, "kind": "dir"|"lab",
    "sort": mode}``.

    A ``dir`` entry labels its node with the title resolved against *lang_priority*, else the
    raw segment; a ``lab`` entry (or an entry without kind, the output of an older CLI, whose
    directories are then created on the fly) is a leaf labelled with its title, else the segment
    without ``.py``. The children of a directory whose mode is ``title`` are reordered by label
    afterwards (``order_tree_entries``, sub-directories first); the other modes keep the order
    of the CLI. The raw segment is kept in ``ROLE_SEGMENT`` so the full path can be
    reconstructed for ``sre start``.

    With ``--with-readmes`` a ``dir`` entry may carry ``"readme": {"": markdown, lang: markdown}``:
    the text of the user's language (``resolve_readme``) is kept in ``ROLE_README`` of its node.
    The entry without name is the top of the lab directory: no node, its README goes on the
    root item.
    """
    root_item = root.invisibleRootItem() if isinstance(root, QTreeWidget) else root

    def resolved(title) -> str:
        return TranslatedText.from_value(title).resolve_priority(lang_priority) if title else ''

    def readme(entry) -> str:
        return resolve_readme(entry.get(params.lab_list_readme_key), lang_priority)

    def find_or_create(parent, segment, label, kind):
        for i in range(parent.childCount()):
            item = parent.child(i)
            if item.data(0, ROLE_SEGMENT) == segment:
                return item
        child = QTreeWidgetItem([label])
        child.setData(0, ROLE_SEGMENT, segment)
        child.setData(0, ROLE_KIND, kind)
        child.setData(0, ROLE_INDEX, parent.childCount())
        parent.addChild(child)
        return child

    for entry in entries:
        if not entry["name"]:
            root_item.setData(0, ROLE_README, readme(entry))
            continue
        parts = entry["name"].split("/")
        kind = entry.get(params.lab_list_kind_key) or params.lab_list_kind_lab
        node = root_item
        for i, segment in enumerate(parts):
            if i < len(parts) - 1:
                node = find_or_create(node, segment, segment, params.lab_list_kind_dir)
                continue
            node.setData(0, ROLE_CHILD_SORT, entry.get(params.lab_list_sort_key))
            if kind == params.lab_list_kind_dir:
                item = find_or_create(node, segment, segment, params.lab_list_kind_dir)
                item.setText(0, resolved(entry.get("title")) or segment)
                item.setData(0, ROLE_README, readme(entry))
            else:
                label = resolved(entry.get("title")) or segment.removesuffix('.py')
                find_or_create(node, segment, label, params.lab_list_kind_lab)
    _reorder(root_item)


def _reorder(item: QTreeWidgetItem):
    """Reorder the children of *item* by label when their mode is ``title`` (sub-directories
    first, then the labs), then those of every sub-directory."""
    if item.data(0, ROLE_CHILD_SORT) == params.titles_sort_title:
        children = item.takeChildren()
        ordered = order_tree_entries(
            [{"item": child, "kind": child.data(0, ROLE_KIND), "name": child.data(0, ROLE_SEGMENT),
              "label": child.text(0), "index": child.data(0, ROLE_INDEX)} for child in children],
            params.titles_sort_title)
        item.addChildren([child["item"] for child in ordered])
    for i in range(item.childCount()):
        _reorder(item.child(i))


def _full_path(item: QTreeWidgetItem) -> str:
    """Reconstruct the full slash-separated path from a tree item."""
    parts = []
    while item is not None:
        parts.append(item.data(0, ROLE_SEGMENT) or item.text(0))
        item = item.parent()
    return "/".join(reversed(parts))


def _is_leaf(item: QTreeWidgetItem) -> bool:
    """A lab (a file, or a directory holding srelab.py), never a directory of the tree."""
    return item.data(0, ROLE_KIND) == params.lab_list_kind_lab


def _readme_directory(item: QTreeWidgetItem | None) -> QTreeWidgetItem | None:
    """The directory a user is browsing when *item* is opened or selected: itself for a
    directory, the directory holding it for a lab; ``None`` is the top of the lab directory
    (no item, or a lab at the top)."""
    if item is None or not _is_leaf(item):
        return item
    return item.parent()


def _readme_of(tree: QTreeWidget, item: QTreeWidgetItem | None) -> str:
    """The markdown of the README shown for *item* (``_readme_directory``): the one of that
    directory only, ``''`` when it has none (never the README of an ancestor)."""
    directory = _readme_directory(item)
    holder = directory if directory is not None else tree.invisibleRootItem()
    return holder.data(0, ROLE_README) or ''


def _has_readme(item: QTreeWidgetItem) -> bool:
    """*item* or a directory below it has a README."""
    return bool(item.data(0, ROLE_README)) or any(_has_readme(item.child(i)) for i in range(item.childCount()))


class OpenProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Open project"))
        self.resize(*DIALOG_SIZE)
        self.selected_project = None
        self._readme_text = ''          # the markdown shown in readme_view ('' = the pane is hidden)
        self._readme_sized = False      # the pane was given its share of the splitter once

        layout = QVBoxLayout(self)

        self.status_label = QLabel(self.tr("Loading available projects…"))
        layout.addWidget(self.status_label)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        self.tree.itemDoubleClicked.connect(self._on_double_click)

        # the README of the directory being browsed, under the tree (as on the Open page of the
        # web front-end); hidden while that directory has none
        self.readme_view = QTextBrowser()
        self.readme_view.setOpenExternalLinks(True)
        util.style_content_document(self.readme_view)
        font = self.readme_view.document().defaultFont()
        font.setPointSize(settings.get_content_font_size())
        self.readme_view.document().setDefaultFont(font)
        self.readme_view.hide()

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.addWidget(self.tree)
        self.splitter.addWidget(self.readme_view)
        layout.addWidget(self.splitter)

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
            cmd = [params.sre_wrapper, "list", "--with-titles", "--with-readmes"]
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
        if _has_readme(self.tree.invisibleRootItem()):
            self.resize(*DIALOG_SIZE_WITH_README)
        # connected once the tree is built and closed: only what the user opens and closes counts
        self.tree.itemExpanded.connect(self._show_readme)
        self.tree.itemCollapsed.connect(self._on_collapsed)
        self.tree.itemClicked.connect(self._on_clicked)
        self._show_readme(None)

    def _show_readme(self, item):
        """Show the README of the directory browsed through *item* (a directory opened or
        selected, the directory of a lab selected, ``None`` = the top of the lab directory)
        under the tree, or hide the pane when that directory has none."""
        text = _readme_of(self.tree, item)
        if text == self._readme_text:
            return                      # the same text stays as it is, its scroll position too
        self._readme_text = text
        if text:
            self.readme_view.setHtml(markdown_to_html(text))
        self.readme_view.setVisible(bool(text))
        if text and not self._readme_sized:
            self._readme_sized = True
            total = sum(self.splitter.sizes()) or self.splitter.height()
            self.splitter.setSizes([total // 2, total - total // 2])

    def _on_collapsed(self, item):
        """A directory closed: the user is back in the directory holding it."""
        self._show_readme(item.parent())

    def _on_clicked(self, item, _column):
        """A click on the item already selected changes no selection: back to its directory
        after another one was opened by its arrow."""
        self._show_readme(item)

    def _on_selection_changed(self):
        items = self.tree.selectedItems()
        self.open_button.setEnabled(bool(items) and _is_leaf(items[0]))
        self._show_readme(items[0] if items else None)

    def _on_double_click(self, item, _column):
        if _is_leaf(item):
            self.accept()

    def accept(self):
        items = self.tree.selectedItems()
        if not items or not _is_leaf(items[0]):
            return
        self.selected_project = _full_path(items[0])
        super().accept()
