"""Tests for ``sre make-titles``: title extraction, output layout, error tolerance, the rerun
on an existing titles.json (its options, its order and its sub-directory entries kept, the labs
no longer there dropped, the new ones appended), and ``--directories`` (the sub-directories of
the lab tree listed in the titles.json of their parent)."""
import json
from pathlib import Path

import pytest

from SRE import utils
from SRE.command.make_titles import action_make_titles
from SRE.utils import get_lab_list_with_titles


def _write(path: Path, body: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def _read_titles(path: Path) -> dict:
    return json.loads(path.read_text())


class TestNonRecursive:
    def test_plain_string_title(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        data = _read_titles(tmp_lab_dir / 'titles.json')
        assert data == {"a.py": "Lab A"}

    def test_default_language_respected(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'default_language = "fr"\ntitle = "Mon TP"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "Mon TP"}

    def test_translated_text_title(self, tmp_lab_dir):
        body = (
            'from SRE.common import TranslatedText\n'
            'title = TranslatedText({"en": "Static routing", "fr": "Routage statique"})\n'
        )
        _write(tmp_lab_dir / 'a.py', body)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {
            "a.py": {"en": "Static routing", "fr": "Routage statique"}}

    def test_single_language_translated_text_collapses_to_string(self, tmp_lab_dir):
        body = (
            'from SRE.common import TranslatedText\n'
            'title = TranslatedText({"fr": "DNS 1"})\n'
        )
        _write(tmp_lab_dir / 'a.py', body)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "DNS 1"}

    def test_directory_lab_title(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'tp_ssh' / 'srelab.py', 'title = "SSH lab"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"tp_ssh": "SSH lab"}

    def test_missing_title_attr_is_skipped(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        _write(tmp_lab_dir / 'b.py', '# no title here\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "Lab A"}

    def test_broken_module_is_logged_and_skipped(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'good.py', 'title = "Good"\n')
        _write(tmp_lab_dir / 'broken.py', 'raise RuntimeError("boom")\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"good.py": "Good"}
        err = capsys.readouterr().err
        assert "broken.py" in err

    def test_does_not_recurse_into_subdirs(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        _write(tmp_lab_dir / 'sub' / 'b.py', 'title = "Lab B"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "Lab A"}
        assert not (tmp_lab_dir / 'sub' / 'titles.json').exists()


class TestRecursive:
    def test_one_titles_file_per_directory(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'sre' / 'a.py', 'title = "Lab A"\n')
        _write(tmp_lab_dir / 's4' / 'b.py', 'title = "Lab B"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        assert _read_titles(tmp_lab_dir / 'sre' / 'titles.json') == {"a.py": "Lab A"}
        assert _read_titles(tmp_lab_dir / 's4' / 'titles.json') == {"b.py": "Lab B"}


class TestOutputFile:
    def test_writes_to_override_path(self, tmp_lab_dir, tmp_path):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        target = tmp_path / 'custom.json'
        action_make_titles(str(tmp_lab_dir), output_file=str(target), recursive=False)
        assert _read_titles(target) == {"a.py": "Lab A"}
        assert not (tmp_lab_dir / 'titles.json').exists()


class TestRerun:
    """A second run merges into the existing titles.json instead of replacing it."""

    def test_options_and_manual_order_kept_new_labs_appended(self, tmp_lab_dir):
        for name, title in (('a', 'A'), ('b', 'B'), ('c', 'C')):
            _write(tmp_lab_dir / f'{name}.py', f'title = "{title}"\n')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"@sort": "manual", "c.py": "Old C", "a.py": "A"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        data = _read_titles(tmp_lab_dir / 'titles.json')
        assert list(data) == ['@sort', 'c.py', 'a.py', 'b.py']
        assert data == {"@sort": "manual", "c.py": "C", "a.py": "A", "b.py": "B"}

    def test_removed_lab_dropped_subdirectories_kept(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "A"\n')
        _write(tmp_lab_dir / 's4' / 'x.py', 'title = "X"\n')
        (tmp_lab_dir / 's2').mkdir()                                  # a directory without lab
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"ghost.py": "Ghost", "s4": {"en": "Semester 4"}, "s2": None, "a.py": "A",
             "nowhere": None}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        data = _read_titles(tmp_lab_dir / 'titles.json')
        assert list(data) == ['s4', 's2', 'a.py']
        assert data == {"s4": {"en": "Semester 4"}, "s2": None, "a.py": "A"}
        assert not (tmp_lab_dir / 's4' / 'titles.json').exists()

    def test_lab_without_title_keeps_the_hand_written_one(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'b.py', '# no title here\n')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps({"b.py": "Hand"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"b.py": "Hand"}

    def test_fresh_file_in_name_order_languages_sorted(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'z.py', 'from SRE.common import TranslatedText\n'
                                     'title = TranslatedText({"fr": "Zed", "en": "Z"})\n')
        _write(tmp_lab_dir / 'a.py', 'title = "A"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        data = _read_titles(tmp_lab_dir / 'titles.json')
        assert list(data) == ['a.py', 'z.py'] and list(data['z.py']) == ['en', 'fr']

    def test_output_file_merges_the_existing_one(self, tmp_lab_dir, tmp_path):
        _write(tmp_lab_dir / 'a.py', 'title = "A"\n')
        _write(tmp_lab_dir / 'b.py', 'title = "B"\n')
        target = tmp_path / 'custom.json'
        target.write_text(json.dumps({"@sort": "title", "a.py": "Old"}))
        action_make_titles(str(tmp_lab_dir), output_file=str(target), recursive=False)
        data = _read_titles(target)
        assert list(data) == ['@sort', 'a.py', 'b.py']
        assert data == {"@sort": "title", "a.py": "A", "b.py": "B"}

    def test_invalid_sort_value_warned_and_kept(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'a.py', 'title = "A"\n')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps({"@sort": "bogus"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"@sort": "bogus", "a.py": "A"}
        err = capsys.readouterr().err
        assert "@sort" in err and "bogus" in err and "manual" in err

    def test_malformed_existing_file_warned_and_replaced(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'a.py', 'title = "A"\n')
        (tmp_lab_dir / 'titles.json').write_text("{not json")
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "A"}
        assert "unreadable" in capsys.readouterr().err

    def test_recursive_updates_a_directory_without_titled_lab(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'sre' / 'a.py', 'title = "A"\n')
        _write(tmp_lab_dir / 's4' / 'b.py', '# no title here\n')
        (tmp_lab_dir / 's4' / 'titles.json').write_text(json.dumps(
            {"@sort": "title", "ghost.py": "G", "b.py": "Hand"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        assert _read_titles(tmp_lab_dir / 's4' / 'titles.json') == {"@sort": "title", "b.py": "Hand"}
        assert _read_titles(tmp_lab_dir / 'sre' / 'titles.json') == {"a.py": "A"}

    def test_recursive_creates_no_empty_file(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 's4' / 'b.py', '# no title here\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        assert not (tmp_lab_dir / 's4' / 'titles.json').exists()
        assert not (tmp_lab_dir / 'titles.json').exists()
        assert "no title found" in capsys.readouterr().err


def _tree_of(tmp_lab_dir):
    """The lab tree as `sre list --with-titles` gives it, the exam-only entries included, read
    afresh (the titles.json files are cached per process)."""
    utils._titles_cache.clear()
    try:
        return get_lab_list_with_titles(include_exam_only_labs=True)
    finally:
        utils._titles_cache.clear()


class TestDirectories:
    """``-d`` / ``--directories``: the sub-directories of the lab tree are listed in the
    titles.json of their parent, without title (null) until one is written by hand.  Without the
    option nothing changes: the tests above run without it."""

    def test_fresh_file_lists_the_subdirectories_first(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'b.py', 'title = "Lab B"\n')
        _write(tmp_lab_dir / 'a.py', '# no title here\n')
        _write(tmp_lab_dir / 's4' / 'x.py', 'title = "X"\n')
        _write(tmp_lab_dir / 'archive' / 'old' / 'y.py', '# no title here\n')   # a lab deeper
        _write(tmp_lab_dir / '_DRAFT_x' / 'z.py', 'title = "Z"\n')             # exam-only: listed
        _write(tmp_lab_dir / 'tp_ssh' / 'srelab.py', 'title = "SSH lab"\n')     # a lab, not a directory
        _write(tmp_lab_dir / 'tp_ssh' / 'initial' / 'all' / 'motd', 'hello\n')
        (tmp_lab_dir / 'empty' / 'deeper').mkdir(parents=True)                  # no lab below
        _write(tmp_lab_dir / '__pycache__' / 'b.cpython-313.pyc', '')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False, directories=True)
        data = _read_titles(tmp_lab_dir / 'titles.json')
        assert list(data) == ['_DRAFT_x', 'archive', 's4', 'b.py', 'tp_ssh']
        assert data == {"_DRAFT_x": None, "archive": None, "s4": None, "b.py": "Lab B",
                        "tp_ssh": "SSH lab"}
        assert not (tmp_lab_dir / 's4' / 'titles.json').exists()             # not recursive

    def test_without_the_option_no_subdirectory_is_listed(self, tmp_lab_dir):
        _write(tmp_lab_dir / 's4' / 'week1' / 'x.py', 'title = "X"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        assert not (tmp_lab_dir / 'titles.json').exists()
        assert not (tmp_lab_dir / 's4' / 'titles.json').exists()
        assert _read_titles(tmp_lab_dir / 's4' / 'week1' / 'titles.json') == {"x.py": "X"}

    def test_recursive_writes_every_level_with_its_direct_children(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 's4' / 'week1' / 'x.py', 'title = "X"\n')
        _write(tmp_lab_dir / 's4' / 'week2' / 'y.py', '# no title here\n')
        _write(tmp_lab_dir / 'sre' / 'a.py', 'title = "A"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True, directories=True)
        # the root and s4 hold directories only: they get their file too
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"s4": None, "sre": None}
        assert _read_titles(tmp_lab_dir / 's4' / 'titles.json') == {"week1": None, "week2": None}
        assert _read_titles(tmp_lab_dir / 's4' / 'week1' / 'titles.json') == {"x.py": "X"}
        assert _read_titles(tmp_lab_dir / 'sre' / 'titles.json') == {"a.py": "A"}
        assert not (tmp_lab_dir / 's4' / 'week2' / 'titles.json').exists()   # nothing to write
        err = capsys.readouterr().err
        assert f"wrote 2 title(s) to {tmp_lab_dir / 'titles.json'} " \
               "(sub-directories without a title: s4, sre)" in err
        assert f"wrote 1 title(s) to {tmp_lab_dir / 'sre' / 'titles.json'}\n" in err

    def test_rerun_keeps_the_entries_and_places_the_new_directories(self, tmp_lab_dir, capsys):
        for name in ('a', 'b'):
            _write(tmp_lab_dir / f'{name}.py', f'title = "{name.upper()}"\n')
        for name in ('s1', 's2', 's3', 's4'):
            _write(tmp_lab_dir / name / 'x.py', 'title = "X"\n')
        (tmp_lab_dir / 'gone').mkdir()                                # listed, no lab any more
        target = tmp_lab_dir / 'titles.json'
        target.write_text(json.dumps(
            {"@sort": "manual", "b.py": "Old B", "s3": {"fr": "Semestre 3", "en": "Semester 3"},
             "gone": None, "a.py": "A", "ghost": "Ghost"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False, directories=True)
        data = _read_titles(target)
        # the new directories by name after the last directory entry, nothing else moved
        assert list(data) == ['@sort', 'b.py', 's3', 'gone', 's1', 's2', 's4', 'a.py']
        assert data == {"@sort": "manual", "b.py": "B", "s3": {"en": "Semester 3", "fr": "Semestre 3"},
                        "gone": None, "s1": None, "s2": None, "s4": None, "a.py": "A"}
        assert "(sub-directories without a title: s1, s2, s4)" in capsys.readouterr().err
        # a title written by hand afterwards, a second run: the file is left as it is
        data["s1"] = "Semester 1"
        target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
        before = target.read_bytes()
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False, directories=True)
        assert target.read_bytes() == before
        assert "(sub-directories without a title: s2, s4)" in capsys.readouterr().err
        # and a run without the option keeps the directory entries, adding none
        _write(tmp_lab_dir / 's5' / 'x.py', 'title = "X"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert target.read_bytes() == before
        assert "sub-directories" not in capsys.readouterr().err

    def test_new_directories_come_first_in_a_file_listing_labs_only(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "A"\n')
        _write(tmp_lab_dir / 's4' / 'x.py', 'title = "X"\n')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps({"@sort": "title", "a.py": "A"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False, directories=True)
        data = _read_titles(tmp_lab_dir / 'titles.json')
        assert list(data) == ['@sort', 's4', 'a.py'] and data["s4"] is None

    def test_output_file(self, tmp_lab_dir, tmp_path):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        _write(tmp_lab_dir / 's4' / 'x.py', 'title = "X"\n')
        target = tmp_path / 'custom.json'
        action_make_titles(str(tmp_lab_dir), output_file=str(target), recursive=False,
                           directories=True)
        assert _read_titles(target) == {"s4": None, "a.py": "Lab A"}
        assert not (tmp_lab_dir / 'titles.json').exists()

    @pytest.mark.parametrize('mode', ['name', 'manual', 'title'])
    def test_the_lab_tree_is_the_same_afterwards(self, tmp_lab_dir, mode):
        """The null entries change nothing in what `sre list --with-titles` gives."""
        for name in ('m.py', 'c.py', 's4/x.py', 's4/deep/y.py', 'a1/x.py', 'late/x.py'):
            _write(tmp_lab_dir / name, f'title = "{name}"\n')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"@sort": mode, "m.py": "M", "late": {"en": "Late"}, "c.py": "C"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        before = _tree_of(tmp_lab_dir)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True, directories=True)
        assert _read_titles(tmp_lab_dir / 'titles.json')["a1"] is None
        assert _read_titles(tmp_lab_dir / 's4' / 'titles.json')["deep"] is None
        assert _tree_of(tmp_lab_dir) == before
