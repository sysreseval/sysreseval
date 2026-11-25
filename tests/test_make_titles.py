"""Tests for ``sre make-titles``: title extraction, output layout, error tolerance, the rerun
on an existing titles.json (its options, its order and its sub-directory entries kept, the labs
no longer there dropped, the new ones appended), and ``--directories`` (the sub-directories of
the lab tree listed in the titles.json of their parent)."""
import json
import sys
from pathlib import Path

import pytest

from SRE import params, utils
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


class TestSubtitles:
    """The subtitles of the manual order ("@subtitle…" keys written among the entries) are
    positional: a rerun keeps each one where it is, unlike the options, which come first."""

    ROUTING = {"fr": "Routage", "en": "Routing"}

    def _labs(self, tmp_lab_dir, *names):
        for name in names:
            _write(tmp_lab_dir / name, f'title = "{Path(name).stem.upper()}"\n')

    def test_subtitles_stay_in_place(self, tmp_lab_dir, capsys):
        self._labs(tmp_lab_dir, 'dhcp.py', 'dns.py', 'ospf.py', 'rip.py')
        target = tmp_lab_dir / 'titles.json'
        target.write_text(json.dumps(
            {"@subtitle addressing": "Addressing", "dns.py": "Old", "dhcp.py": "DHCP", "@sort": "manual",
             "@subtitle routing": self.ROUTING, "rip.py": "RIP", "gone.py": "Gone", "@future": 1}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        data = _read_titles(target)
        # the options first, as before; the subtitles among the entries; the new lab at the end
        assert list(data) == ['@sort', '@future', '@subtitle addressing', 'dns.py', 'dhcp.py',
                              '@subtitle routing', 'rip.py', 'ospf.py']
        assert data["@subtitle addressing"] == "Addressing" and data["dns.py"] == "DNS"
        assert data["@subtitle routing"] == {"en": "Routing", "fr": "Routage"}
        assert list(data["@subtitle routing"]) == ['en', 'fr']         # languages sorted, as a title
        assert "wrote 4 title(s)" in capsys.readouterr().err           # the subtitles are no titles
        before = target.read_bytes()
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert target.read_bytes() == before                           # a second run changes nothing

    def test_the_subtitle_of_a_group_gone_is_kept(self, tmp_lab_dir):
        self._labs(tmp_lab_dir, 'a.py')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"@sort": "manual", "@subtitle 1": "One", "gone.py": "Gone", "@subtitle 2": "Two", "a.py": "A"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert list(_read_titles(tmp_lab_dir / 'titles.json')) == ['@sort', '@subtitle 1', '@subtitle 2', 'a.py']

    def test_the_tree_shown_is_the_same_after_a_rerun(self, tmp_lab_dir):
        self._labs(tmp_lab_dir, 'a.py', 'b.py', 'c.py', 's4/x.py')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"@sort": "manual", "@subtitle 1": "One", "c.py": "C", "s4": "Semester 4",
             "@subtitle 2": self.ROUTING, "a.py": "A"}))
        def shown():        # the names in their order, each with the subtitle before it
            return [(e["name"], e.get("subtitle")) for e in _tree_of(tmp_lab_dir)]

        before = shown()
        assert before == [('s4', "One"), ('s4/x.py', None), ('c.py', None), ('a.py', self.ROUTING), ('b.py', None)]
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        assert shown() == before                        # the run only wrote the titles of the labs

    def test_a_subtitle_without_text_is_kept_and_warned_about(self, tmp_lab_dir, capsys):
        self._labs(tmp_lab_dir, 'a.py', 'b.py')
        target = tmp_lab_dir / 'titles.json'
        target.write_text(json.dumps({"@sort": "manual", "@subtitle 1": None, "b.py": "B",
                                      "@subtitle 2": {"en": ""}, "a.py": "A"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        data = _read_titles(target)
        assert list(data) == ['@sort', '@subtitle 1', 'b.py', '@subtitle 2', 'a.py']
        assert data["@subtitle 1"] is None and data["@subtitle 2"] == {"en": ""}
        err = capsys.readouterr().err
        assert f"{target}: the subtitle '@subtitle 1' has no text" in err
        assert f"{target}: the subtitle '@subtitle 2' has no text" in err

    def test_a_key_written_twice_is_warned_about(self, tmp_lab_dir, capsys):
        """JSON keeps the last value of a repeated key, at the place of the first: two subtitles
        under one key are one, and the command says so."""
        self._labs(tmp_lab_dir, 'a.py', 'b.py')
        target = tmp_lab_dir / 'titles.json'
        target.write_text('{"@sort": "manual", "@subtitle": "One", "b.py": {"en": "B", "en": "B again"},\n'
                          ' "@subtitle": "Two", "a.py": "A"}\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        err = capsys.readouterr().err
        assert f"{target}: the key '@subtitle' is written more than once, only its last value is read " \
               '(each subtitle needs a key of its own: "@subtitle 1", "@subtitle 2"…)' in err
        assert f"{target}: the key 'en' is written more than once, only its last value is read\n" in err
        assert _read_titles(target) == {"@sort": "manual", "@subtitle": "Two", "b.py": "B", "a.py": "A"}

    def test_no_warning_on_a_plain_file(self, tmp_lab_dir, capsys):
        self._labs(tmp_lab_dir, 'a.py', 'b.py')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"@sort": "manual", "@subtitle 1": "One", "b.py": "B", "@subtitle 2": self.ROUTING, "a.py": "A"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert capsys.readouterr().err == f"wrote 2 title(s) to {tmp_lab_dir / 'titles.json'}\n"

    def test_new_directories_go_into_the_last_group(self, tmp_lab_dir):
        """``-d``: the lab tree shows an unlisted sub-directory in the last group of the file,
        after the sub-directories listed there: that is where its entry is written."""
        self._labs(tmp_lab_dir, 'a.py', 'b.py', 's1/x.py', 's2/x.py', 's3/x.py', 's4/x.py')
        target = tmp_lab_dir / 'titles.json'
        target.write_text(json.dumps(
            {"@sort": "manual", "@subtitle 1": "One", "s1": "First", "a.py": "A",
             "@subtitle 2": "Two", "b.py": "B", "s3": None}))
        before = _tree_of(tmp_lab_dir)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False, directories=True)
        assert list(_read_titles(target)) == ['@sort', '@subtitle 1', 's1', 'a.py',
                                              '@subtitle 2', 'b.py', 's3', 's2', 's4']
        assert _tree_of(tmp_lab_dir) == before

    def test_new_directories_start_a_last_group_without_any(self, tmp_lab_dir):
        self._labs(tmp_lab_dir, 'a.py', 'b.py', 's1/x.py', 's2/x.py')
        target = tmp_lab_dir / 'titles.json'
        target.write_text(json.dumps(
            {"@sort": "manual", "@subtitle 1": "One", "s1": None, "a.py": "A", "@subtitle 2": "Two", "b.py": "B"}))
        before = _tree_of(tmp_lab_dir)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False, directories=True)
        assert list(_read_titles(target)) == ['@sort', '@subtitle 1', 's1', 'a.py', '@subtitle 2', 's2', 'b.py']
        assert _tree_of(tmp_lab_dir) == before

    def test_a_subtitle_without_text_starts_no_group_for_the_directories(self, tmp_lab_dir):
        """``sre list`` ignores it, so the last group begins before it."""
        self._labs(tmp_lab_dir, 'a.py', 'b.py', 's1/x.py', 's2/x.py')
        target = tmp_lab_dir / 'titles.json'
        target.write_text(json.dumps(
            {"@sort": "manual", "@subtitle 1": "One", "s1": None, "a.py": "A", "@subtitle 2": None, "b.py": "B"}))
        before = _tree_of(tmp_lab_dir)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False, directories=True)
        assert list(_read_titles(target)) == ['@sort', '@subtitle 1', 's1', 's2', 'a.py', '@subtitle 2', 'b.py']
        assert _tree_of(tmp_lab_dir) == before

    @pytest.mark.parametrize('mode', ['name', 'manual', 'title'])
    def test_the_lab_tree_is_the_same_after_directories(self, tmp_lab_dir, mode):
        self._labs(tmp_lab_dir, 'm.py', 'c.py', 'n.py', 's4/x.py', 's4/deep/y.py', 'a1/x.py', 'late/x.py')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"@sort": mode, "@subtitle 1": "One", "m.py": "M", "late": {"en": "Late"},
             "@subtitle 2": "Two", "c.py": "C"}))
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        before = _tree_of(tmp_lab_dir)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True, directories=True)
        assert _read_titles(tmp_lab_dir / 'titles.json')["a1"] is None
        assert _tree_of(tmp_lab_dir) == before


# --- the weights of the labs ("@weights") -------------------------------------------------------

_FIXTURE_LAB = (Path(__file__).parent / 'labs' / 'functional_test_lab.py').read_text()
_FIXTURE_SPECS = "_machine_specs = {'router': {}, 'client': {}}"
SHIPPED_LABS = Path(__file__).parent.parent / 'lab' / 'sre'


def _lab(specs: str | None = None, head: str = '') -> str:
    """The text of a real lab of two machines (the fixture lab of the functional tests), with
    other machine specs and lines added at the top of the module."""
    assert _FIXTURE_SPECS in _FIXTURE_LAB
    text = _FIXTURE_LAB if specs is None else _FIXTURE_LAB.replace(_FIXTURE_SPECS, f"_machine_specs = {specs}")
    return head + text


def _make(directory, **options):
    action_make_titles(str(directory), output_file=options.pop('output_file', None),
                       recursive=options.pop('recursive', False), **options)


class TestWeights:
    """`sre make-titles` stores the weight of every lab it can build under the "@weights" option
    of titles.json: what `sre list --with-titles` gives the web portal as the first estimate of
    the cost of a project."""

    @pytest.fixture(autouse=True)
    def _table(self, monkeypatch):
        monkeypatch.setattr(params, 'default_machine_weight', 1.0)
        monkeypatch.setattr(params, 'image_weights', {'routing-frr13': 3})

    def test_written_among_the_options(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', _lab(head='title = "A"\n'))
        _write(tmp_lab_dir / 'b.py', 'title = "B"\n')           # no NetScheme: not a lab, no weight
        _make(tmp_lab_dir)
        path = tmp_lab_dir / 'titles.json'
        assert _read_titles(path) == {"@weights": {"a.py": 2}, "a.py": "A", "b.py": "B"}
        assert list(_read_titles(path)) == ["@weights", "a.py", "b.py"]

    def test_no_key_without_a_lab_to_weigh(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'b.py', 'title = "B"\n')
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"b.py": "B"}
        assert "weight" not in capsys.readouterr().err

    def test_the_spec_and_the_image_of_each_machine(self, tmp_lab_dir):
        frr = params.sre_docker_image('routing-frr13')
        _write(tmp_lab_dir / 'a.py', _lab(
            f"{{'router': {{'image': {frr!r}}}, 'client': {{'weight': 0.25}}, 'probe': {{'hidden': True}}}}"))
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"@weights": {"a.py": 4.25}}

    def test_the_default_image_of_the_lab(self, tmp_lab_dir):
        """The machines without image take the `default_image` of their lab: the module is the
        lab being built while its NetScheme is."""
        frr = params.sre_docker_image('routing-frr13')
        _write(tmp_lab_dir / 'a.py', _lab(head=f"default_image = {frr!r}\n"))
        _write(tmp_lab_dir / 'b.py', _lab())
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"@weights": {"a.py": 6, "b.py": 2}}

    def test_directory_lab(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'tp' / 'srelab.py', _lab(head='title = "TP"\n'))
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"@weights": {"tp": 2}, "tp": "TP"}

    def test_the_weight_the_module_declares_wins(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'a.py', _lab(head='lab_weight = 13\n'))
        # declared: the lab is not even built (it could not be)
        _write(tmp_lab_dir / 'b.py', _lab(head='lab_weight = 7.126\n').replace(
            'return cls(value=42)', 'raise RuntimeError("no generation here")'))
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"@weights": {"a.py": 13, "b.py": 7.13}}
        assert capsys.readouterr().err.count("no weight") == 0

    def test_a_bad_declared_weight_is_warned_about(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'a.py', _lab(head='lab_weight = "heavy"\ntitle = "A"\n'))
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "A"}
        err = capsys.readouterr().err
        assert "no weight for" in err and "lab_weight = 'heavy'" in err

    def test_a_lab_that_cannot_be_built_has_no_weight(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'a.py', _lab(head='title = "A"\n').replace(
            'return cls(value=42)', 'raise RuntimeError("no generation here")'))
        # error_quit() of the core library: ports without the bridged mode
        _write(tmp_lab_dir / 'b.py', _lab("{'router': {'ports': ['80:80']}, 'client': {}}"))
        _write(tmp_lab_dir / 'c.py', _lab())
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"@weights": {"c.py": 2}, "a.py": "A"}
        err = capsys.readouterr().err
        assert "a.py: RuntimeError: no generation here" in err
        assert "b.py: the lab cannot be built here" in err

    def test_the_weights_of_the_file_are_replaced(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', _lab())
        (tmp_lab_dir / 'titles.json').write_text(json.dumps(
            {"@sort": "manual", "@weights": {"a.py": 99, "ghost.py": 5}, "a.py": "Hand"}))
        _make(tmp_lab_dir)
        path = tmp_lab_dir / 'titles.json'
        assert _read_titles(path) == {"@sort": "manual", "@weights": {"a.py": 2}, "a.py": "Hand"}
        assert list(_read_titles(path)) == ["@sort", "@weights", "a.py"]

    def test_the_weights_of_the_file_go_with_the_last_lab(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'b.py', 'title = "B"\n')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps({"@weights": {"gone.py": 5}, "b.py": "B"}))
        _make(tmp_lab_dir)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"b.py": "B"}

    def test_a_second_run_changes_nothing(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'z.py', _lab(head='title = "Z"\n'))
        _write(tmp_lab_dir / 'a.py', _lab(head='lab_weight = 2.5\n'))
        _write(tmp_lab_dir / 's4' / 'x.py', _lab())
        _make(tmp_lab_dir, recursive=True, directories=True)
        first = {p: p.read_bytes() for p in tmp_lab_dir.rglob('titles.json')}
        assert len(first) == 2
        _make(tmp_lab_dir, recursive=True, directories=True)
        assert {p: p.read_bytes() for p in tmp_lab_dir.rglob('titles.json')} == first

    def test_recursive_writes_the_weights_of_untitled_labs(self, tmp_lab_dir):
        _write(tmp_lab_dir / 's4' / 'x.py', _lab())
        _make(tmp_lab_dir, recursive=True)
        assert _read_titles(tmp_lab_dir / 's4' / 'titles.json') == {"@weights": {"x.py": 2}}
        assert not (tmp_lab_dir / 'titles.json').exists()

    def test_the_new_directories_stay_after_the_options(self, tmp_lab_dir):
        """`--directories` places the missing sub-directories right after the options: the
        weights are one of them."""
        _write(tmp_lab_dir / 'a.py', _lab(head='title = "A"\n'))
        _write(tmp_lab_dir / 's4' / 'x.py', '# a lab\n')
        (tmp_lab_dir / 'titles.json').write_text(json.dumps({"@sort": "manual", "a.py": "A"}))
        _make(tmp_lab_dir, directories=True)
        assert list(_read_titles(tmp_lab_dir / 'titles.json')) == ["@sort", "@weights", "s4", "a.py"]

    def test_output_file(self, tmp_lab_dir, tmp_path):
        _write(tmp_lab_dir / 'a.py', _lab())
        out = tmp_path / 'elsewhere.json'
        _make(tmp_lab_dir, output_file=str(out))
        assert _read_titles(out) == {"@weights": {"a.py": 2}}
        assert not (tmp_lab_dir / 'titles.json').exists()

    def test_the_lab_module_of_the_process_is_left_as_it_was(self, tmp_lab_dir, monkeypatch):
        _write(tmp_lab_dir / 'a.py', _lab())
        monkeypatch.delitem(sys.modules, 'srelab', raising=False)
        _make(tmp_lab_dir)
        assert 'srelab' not in sys.modules
        mine = object()
        monkeypatch.setitem(sys.modules, 'srelab', mine)
        _make(tmp_lab_dir)
        assert sys.modules['srelab'] is mine

    def test_the_lab_list_carries_the_weights(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', _lab(head='title = "A"\n'))
        _write(tmp_lab_dir / 'b.py', 'title = "B"\n')
        _write(tmp_lab_dir / 's4' / 'x.py', _lab(head='lab_weight = 40\n'))
        _make(tmp_lab_dir, recursive=True)
        utils._titles_cache.clear()
        entries = {e['name']: e for e in get_lab_list_with_titles()}
        assert entries['a.py'] == {'name': 'a.py', 'title': 'A', 'kind': 'lab', 'sort': 'name', 'weight': 2}
        assert entries['s4/x.py']['weight'] == 40
        assert 'weight' not in entries['b.py'] and 'weight' not in entries['s4']


class TestShippedWeights:
    """The weights committed with the shipped labs are still those `sre make-titles` computes: a
    lab that gained machines, or a changed `params.image_weights`, asks for a new run of
    `sre make-titles <directory>` on the directories named here.  A lab that has no weight yet (a
    new one) is no failure: the web portal counts it for its default until the next run."""

    def test_the_stored_weights_are_not_stale(self, tmp_path):
        files = sorted(SHIPPED_LABS.rglob(params.titles_file_name)) if SHIPPED_LABS.is_dir() else []
        if not files:
            pytest.skip(f"no titles.json readable under {SHIPPED_LABS}")
        stale = {}
        for number, path in enumerate(files):
            out = tmp_path / f'{number}.json'
            action_make_titles(str(path.parent), output_file=str(out), recursive=False)
            stored = _read_titles(path).get(params.titles_weights_key, {})
            computed = _read_titles(out).get(params.titles_weights_key, {})
            changed = {name: (weight, computed.get(name)) for name, weight in stored.items()
                       if computed.get(name) != weight}
            if changed:
                stale[str(path.parent.relative_to(SHIPPED_LABS.parent.parent))] = changed
        assert not stale, f"weights (stored, computed) to refresh with `sre make-titles`: {stale}"
