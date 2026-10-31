"""
The lab tree of the Open project dialog: the entries of `sre list --with-titles` in their order
(the display order of the CLI: a directory entry before its content, the sub-directories of a
directory first), the titles resolved against the language priority (the directories' too), the
children of a directory in the "title" mode reordered by label, the raw path rebuilt from the
segments.  Offscreen Qt.
"""
import os

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication, QTreeWidget  # noqa: E402

from sysreseval.open_project_dialog import _populate_tree, _full_path, _is_leaf, ROLE_SEGMENT  # noqa: E402

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
