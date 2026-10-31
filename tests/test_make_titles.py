"""Tests for ``sre make-titles``: title extraction, output layout, error tolerance, and the
rerun on an existing titles.json (its options, its order and its sub-directory entries kept,
the labs no longer there dropped, the new ones appended)."""
import json
from pathlib import Path

import pytest

from SRE.command.make_titles import action_make_titles


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
