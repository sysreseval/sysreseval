"""
The lab tree of the Open project dialog: the entries of `sre list --with-titles` in their order
(the display order of the CLI: a directory entry before its content, the sub-directories of a
directory first), the titles resolved against the language priority (the directories' too), the
children of a directory in the "title" mode reordered by label, the raw path rebuilt from the
segments; and the README of the directory being browsed (`--with-readmes`), shown under the
tree by the dialog, built here on a fake `sre-wrapper`.  Offscreen Qt.
"""
import json
import os

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication, QTreeWidget  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval import settings  # noqa: E402
from sysreseval.open_project_dialog import (  # noqa: E402
    _populate_tree, _full_path, _is_leaf, _readme_of, _has_readme, OpenProjectDialog,
    ROLE_SEGMENT, ROLE_README, DIALOG_SIZE, DIALOG_SIZE_WITH_README)

_app = QApplication.instance() or QApplication([])


def _entry(name, title=None, kind='lab', sort='name'):
    return {'name': name, 'title': title, 'kind': kind, 'sort': sort}


def _flatten(item):
    """``(label, segment, children)`` of every child of *item*, in order."""
    return [(child.text(0), child.data(0, ROLE_SEGMENT), _flatten(child))
            for child in (item.child(i) for i in range(item.childCount()))]


def _tree(entries, lang_priority=('en',)):
    widget = QTreeWidget()
    _populate_tree(widget, entries, list(lang_priority))
    return widget, _flatten(widget.invisibleRootItem())


class TestPopulateTree:
    def test_arrival_order_kept_in_name_mode(self):
        """The CLI gives the order: never sorted again (here a manual order)."""
        entries = [_entry('z', kind='dir'), _entry('z/b.py'), _entry('z/a.py'),
                   _entry('m.py'), _entry('a.py')]
        _, tree = _tree(entries)
        assert tree == [('z', 'z', [('b', 'b.py', []), ('a', 'a.py', [])]),
                        ('m', 'm.py', []), ('a', 'a.py', [])]

    def test_titles_resolved_by_priority_directories_too(self):
        entries = [_entry('s4', {'en': 'Semester 4', 'fr': 'Semestre 4'}, kind='dir'),
                   _entry('s4/x.py', {'en': 'X lab', 'fr': 'TP X'}), _entry('s4/y.py', 'Plain'),
                   _entry('s4/z.py')]
        _, tree = _tree(entries, ('fr', 'en'))
        assert tree == [('Semestre 4', 's4', [('TP X', 'x.py', []), ('Plain', 'y.py', []),
                                               ('z', 'z.py', [])])]
        _, tree = _tree(entries, ('de',))                      # unknown language: the first value
        assert tree[0][0] == 'Semester 4' and tree[0][2][0][0] == 'X lab'

    def test_title_mode_reorders_by_label_directories_first(self):
        entries = [_entry('tp10.py', 'TP 10', sort='title'),
                   _entry('s', {'en': 'Zone'}, kind='dir', sort='title'),
                   _entry('s/b.py', 'beta', sort='title'), _entry('s/a.py', 'Alpha', sort='title'),
                   _entry('tp2.py', 'TP 2', sort='title'), _entry('e.py', 'Étude', sort='title'),
                   _entry('a.py', 'arp', sort='title')]
        _, tree = _tree(entries)
        assert [label for label, _, _ in tree] == ['Zone', 'arp', 'Étude', 'TP 2', 'TP 10']
        assert [label for label, _, _ in tree[0][2]] == ['Alpha', 'beta']

    def test_the_mode_of_each_level_is_its_own(self):
        entries = [_entry('z', kind='dir'), _entry('z/b.py', 'Beta', sort='title'),
                   _entry('z/a.py', 'alpha', sort='title'), _entry('b.py'), _entry('a.py')]
        _, tree = _tree(entries)
        assert [segment for _, segment, _ in tree] == ['z', 'b.py', 'a.py']     # the root: arrival order
        assert [label for label, _, _ in tree[0][2]] == ['alpha', 'Beta']       # z: by label

    def test_entries_of_an_older_cli_without_kind(self):
        entries = [{'name': 'a/b/c.py', 'title': None}, {'name': 'a/d.py', 'title': {'en': 'D'}}]
        _, tree = _tree(entries)
        assert tree == [('a', 'a', [('b', 'b', [('c', 'c.py', [])]), ('D', 'd.py', [])])]

    def test_full_path_and_is_leaf(self):
        entries = [_entry('s4', {'en': 'Semester 4'}, kind='dir'), _entry('s4/tp_ssh', {'en': 'SSH'}),
                   _entry('s4/x.py')]
        widget, _ = _tree(entries)
        s4 = widget.topLevelItem(0)
        assert not _is_leaf(s4) and _full_path(s4) == 's4'
        tp_ssh = s4.child(0)
        assert _is_leaf(tp_ssh) and _full_path(tp_ssh) == 's4/tp_ssh'      # a directory lab is a leaf
        assert _is_leaf(s4.child(1)) and _full_path(s4.child(1)) == 's4/x.py'


def _dir(name, readme=None, title=None):
    entry = _entry(name, title, kind='dir')
    if readme is not None:
        entry['readme'] = readme
    return entry


#: A tree with READMEs: the top directory (two languages), s4 (README.md only), s4/r401 (a French
#: variant only), s5 without any.
README_ENTRIES = [
    _dir('', {'': '# Welcome\n\nPick your course.', 'fr': '# Bienvenue'}),
    _dir('s4', {'': '# Semester 4\n\n| Lab | Week |\n|---|---|\n| x | 12 |\n'}, {'en': 'Semester 4'}),
    _dir('s4/r401', {'fr': '# R4.01'}),
    _entry('s4/r401/c.py'),
    _entry('s4/x.py'),
    _dir('s5'),
    _entry('s5/y.py'),
    _entry('root.py'),
]
#: The same tree as a CLI without `--with-readmes` (or a lab directory without README) gives it.
PLAIN_ENTRIES = [{key: value for key, value in entry.items() if key != 'readme'}
                 for entry in README_ENTRIES if entry['name']]


class TestReadmeOfTheTree:
    """`_populate_tree` keeps the README of each directory, in the user's language, on its
    node, and the one of the top directory on the root item: the entry without name is no node."""

    def test_the_top_entry_is_no_node(self):
        widget, tree = _tree(README_ENTRIES)
        assert [segment for _, segment, _ in tree] == ['s4', 's5', 'root.py']
        assert _tree(PLAIN_ENTRIES)[1] == tree
        assert widget.invisibleRootItem().data(0, ROLE_README) == '# Welcome\n\nPick your course.'

    def test_readme_by_directory_and_language(self):
        widget, _ = _tree(README_ENTRIES, lang_priority=('fr', 'en'))
        s4, s5, root_lab = (widget.topLevelItem(i) for i in range(3))
        r401, x = s4.child(0), s4.child(1)
        assert _readme_of(widget, None) == '# Bienvenue'
        assert _readme_of(widget, s4).startswith('# Semester 4')        # README.md: no French variant
        assert _readme_of(widget, r401) == '# R4.01'
        assert _readme_of(widget, s5) == ''                             # never the one of an ancestor
        assert _readme_of(widget, x) == _readme_of(widget, s4)          # a lab: its directory
        assert _readme_of(widget, r401.child(0)) == '# R4.01'
        assert _readme_of(widget, root_lab) == '# Bienvenue'            # a lab at the top
        assert _readme_of(widget, s5.child(0)) == ''

    def test_has_readme(self):
        widget, _ = _tree(README_ENTRIES)
        assert _has_readme(widget.invisibleRootItem())
        assert _has_readme(widget.topLevelItem(0)) and not _has_readme(widget.topLevelItem(1))
        widget, _ = _tree(PLAIN_ENTRIES)
        assert not _has_readme(widget.invisibleRootItem())
        widget, _ = _tree([_dir('a'), _dir('a/b', {'': 'deep'}), _entry('a/b/c.py')])
        assert _has_readme(widget.invisibleRootItem())                  # only a sub-directory has one


@pytest.fixture
def dialog_of(tmp_path, monkeypatch):
    """Build the dialog on a fake `sre-wrapper` printing *entries*: ``(dialog, argv)``, *argv*
    the arguments the wrapper was run with."""
    def make(entries, languages=('en',)):
        listing = tmp_path / 'list.json'
        listing.write_text(json.dumps(entries))
        log = tmp_path / 'argv'
        script = tmp_path / 'sre-wrapper'
        script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{log}"\ncat "{listing}"\n')
        script.chmod(0o755)
        monkeypatch.setattr(params, 'sre_wrapper', str(script))
        monkeypatch.setattr(settings, 'get_language_priority', lambda: list(languages))
        dialog = OpenProjectDialog()
        return dialog, log.read_text().split()
    return make


def _shown(dialog) -> str:
    """The text of the README pane, ``None`` when the pane is hidden."""
    return None if dialog.readme_view.isHidden() else dialog.readme_view.toPlainText()


class TestReadmeInTheDialog:
    """The README of the directory being browsed under the tree: the top directory at first, a
    directory opened or selected, its parent once it is closed, the directory of a lab selected;
    the pane hidden when that directory has none."""

    def test_the_list_is_asked_with_the_readmes(self, dialog_of):
        _, argv = dialog_of(README_ENTRIES)
        assert argv == ['list', '--with-titles', '--with-readmes']

    def test_top_readme_at_first(self, dialog_of):
        dialog, _ = dialog_of(README_ENTRIES)
        assert _shown(dialog).startswith('Welcome') and 'Pick your course.' in _shown(dialog)
        assert (dialog.width(), dialog.height()) == DIALOG_SIZE_WITH_README
        assert not dialog.open_button.isEnabled()
        assert all(not dialog.tree.topLevelItem(i).isExpanded() for i in range(dialog.tree.topLevelItemCount()))

    def test_language_of_the_user(self, dialog_of):
        dialog, _ = dialog_of(README_ENTRIES, languages=('fr', 'en'))
        assert _shown(dialog) == 'Bienvenue'

    def test_directory_selected_then_lab(self, dialog_of):
        dialog, _ = dialog_of(README_ENTRIES)
        s4 = dialog.tree.topLevelItem(0)
        dialog.tree.setCurrentItem(s4)
        assert _shown(dialog).startswith('Semester 4') and 'Week' in _shown(dialog)     # the table too
        assert not dialog.open_button.isEnabled()
        dialog.tree.setCurrentItem(s4.child(1))                    # s4/x.py
        assert _shown(dialog).startswith('Semester 4') and dialog.open_button.isEnabled()
        dialog.tree.setCurrentItem(dialog.tree.topLevelItem(2))    # root.py: the top directory
        assert _shown(dialog).startswith('Welcome')

    def test_directory_opened_and_closed(self, dialog_of):
        """Opening a directory by its arrow shows its README without changing the selection;
        closing it shows the README of the directory holding it."""
        dialog, _ = dialog_of(README_ENTRIES)
        s4 = dialog.tree.topLevelItem(0)
        s4.setExpanded(True)
        assert _shown(dialog).startswith('Semester 4') and not dialog.tree.selectedItems()
        s4.child(0).setExpanded(True)                              # s4/r401: a French variant only
        assert _shown(dialog) == 'R4.01'
        s4.child(0).setExpanded(False)
        assert _shown(dialog).startswith('Semester 4')
        s4.setExpanded(False)
        assert _shown(dialog).startswith('Welcome')

    def test_directory_without_readme_hides_the_pane(self, dialog_of):
        dialog, _ = dialog_of(README_ENTRIES)
        s5 = dialog.tree.topLevelItem(1)
        dialog.tree.setCurrentItem(s5)
        assert _shown(dialog) is None
        dialog.tree.setCurrentItem(s5.child(0))
        assert _shown(dialog) is None and dialog.open_button.isEnabled()
        dialog.tree.setCurrentItem(dialog.tree.topLevelItem(0))
        assert _shown(dialog).startswith('Semester 4')

    def test_click_on_the_selected_item_comes_back_to_its_directory(self, dialog_of):
        dialog, _ = dialog_of(README_ENTRIES)
        s4, s5 = dialog.tree.topLevelItem(0), dialog.tree.topLevelItem(1)
        dialog.tree.setCurrentItem(s4.child(1))                    # s4/x.py selected
        s5.setExpanded(True)                                       # another directory opened by its arrow
        assert _shown(dialog) is None
        dialog.tree.itemClicked.emit(s4.child(1), 0)               # no selection change
        assert _shown(dialog).startswith('Semester 4')

    def test_scroll_kept_while_the_readme_stays(self, dialog_of):
        """Selecting another lab of the directory does not render its README again."""
        dialog, _ = dialog_of([_dir('s4', {'': '\n\n'.join(f'line {i}' for i in range(200))}),
                               _entry('s4/a.py'), _entry('s4/b.py')])
        s4 = dialog.tree.topLevelItem(0)
        dialog.tree.setCurrentItem(s4.child(0))
        revision = dialog.readme_view.document().revision()        # setHtml() would raise it
        dialog.tree.setCurrentItem(s4.child(1))
        s4.setExpanded(True)
        dialog.tree.itemClicked.emit(s4.child(1), 0)
        assert dialog.readme_view.document().revision() == revision
        assert 'line 199' in _shown(dialog)
        dialog.readme_view.setHtml('changed')                       # the check itself: a render is seen
        assert dialog.readme_view.document().revision() != revision

    def test_no_readme_anywhere(self, dialog_of):
        """A lab tree without README: the dialog of before, the pane never shown."""
        dialog, _ = dialog_of(PLAIN_ENTRIES)
        assert _shown(dialog) is None and (dialog.width(), dialog.height()) == DIALOG_SIZE
        s4 = dialog.tree.topLevelItem(0)
        s4.setExpanded(True)
        dialog.tree.setCurrentItem(s4)
        dialog.tree.setCurrentItem(s4.child(1))
        s4.setExpanded(False)
        assert _shown(dialog) is None

    def test_selection_and_accept_unchanged(self, dialog_of):
        dialog, _ = dialog_of(README_ENTRIES)
        s4 = dialog.tree.topLevelItem(0)
        dialog.tree.setCurrentItem(s4)
        dialog.accept()                                            # a directory is never opened
        assert dialog.selected_project is None
        dialog.tree.setCurrentItem(s4.child(0).child(0))
        dialog.accept()
        assert dialog.selected_project == 's4/r401/c.py'

    def test_list_failure_shows_no_pane(self, dialog_of, tmp_path, monkeypatch):
        script = tmp_path / 'failing'
        script.write_text('#!/bin/sh\necho "sre: nope" >&2\nexit 1\n')
        script.chmod(0o755)
        monkeypatch.setattr(params, 'sre_wrapper', str(script))
        dialog = OpenProjectDialog()
        assert 'nope' in dialog.status_label.text() and _shown(dialog) is None
