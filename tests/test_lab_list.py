"""Tests for get_lab_list: lab discovery, filtering, and sorting."""
import json

import pytest
from SRE import utils
from SRE.utils import get_lab_list, get_lab_list_with_titles


@pytest.fixture(autouse=True)
def _clear_titles_cache():
    utils._titles_cache.clear()
    yield
    utils._titles_cache.clear()


class TestDirectoryLabs:
    def test_directory_with_srelab_found(self, tmp_lab_dir):
        (tmp_lab_dir / 's4' / 'tp_ssh').mkdir(parents=True)
        (tmp_lab_dir / 's4' / 'tp_ssh' / 'srelab.py').touch()
        assert 's4/tp_ssh' in get_lab_list()

    def test_srelab_py_itself_not_listed(self, tmp_lab_dir):
        (tmp_lab_dir / 'tp').mkdir()
        (tmp_lab_dir / 'tp' / 'srelab.py').touch()
        result = get_lab_list()
        assert 'tp' in result
        assert 'tp/srelab.py' not in result

    def test_no_recursion_below_srelab_dir(self, tmp_lab_dir):
        (tmp_lab_dir / 'tp').mkdir()
        (tmp_lab_dir / 'tp' / 'srelab.py').touch()
        (tmp_lab_dir / 'tp' / 'subdir').mkdir()
        (tmp_lab_dir / 'tp' / 'subdir' / 'extra.py').touch()
        result = get_lab_list()
        assert 'tp' in result
        assert 'tp/subdir/extra.py' not in result

    def test_nested_directory_lab(self, tmp_lab_dir):
        (tmp_lab_dir / 'class1' / 'week3' / 'tp_arp').mkdir(parents=True)
        (tmp_lab_dir / 'class1' / 'week3' / 'tp_arp' / 'srelab.py').touch()
        assert 'class1/week3/tp_arp' in get_lab_list()


class TestFileLabs:
    def test_py_file_in_subdir_found(self, tmp_lab_dir):
        (tmp_lab_dir / 'test').mkdir()
        (tmp_lab_dir / 'test' / 'mylab.py').touch()
        assert 'test/mylab.py' in get_lab_list()

    def test_py_file_at_root_found(self, tmp_lab_dir):
        (tmp_lab_dir / 'standalone.py').touch()
        assert 'standalone.py' in get_lab_list()

    def test_non_py_file_ignored(self, tmp_lab_dir):
        (tmp_lab_dir / 'README.md').touch()
        result = get_lab_list()
        assert 'README.md' not in result


class TestExamOnlyFiltering:
    def test_exam_dir_excluded_by_default(self, tmp_lab_dir):
        (tmp_lab_dir / '_EXAM_tp').mkdir()
        (tmp_lab_dir / '_EXAM_tp' / 'srelab.py').touch()
        assert '_EXAM_tp' not in get_lab_list()

    def test_old_dir_excluded_by_default(self, tmp_lab_dir):
        (tmp_lab_dir / '_OLD_tp').mkdir()
        (tmp_lab_dir / '_OLD_tp' / 'srelab.py').touch()
        assert '_OLD_tp' not in get_lab_list()

    def test_draft_dir_excluded_by_default(self, tmp_lab_dir):
        (tmp_lab_dir / '_DRAFT_tp').mkdir()
        (tmp_lab_dir / '_DRAFT_tp' / 'srelab.py').touch()
        assert '_DRAFT_tp' not in get_lab_list()

    def test_exam_file_excluded_by_default(self, tmp_lab_dir):
        (tmp_lab_dir / 'lab_EXAM_.py').touch()
        assert 'lab_EXAM_.py' not in get_lab_list()

    def test_exam_dir_included_with_flag(self, tmp_lab_dir):
        (tmp_lab_dir / '_EXAM_tp').mkdir()
        (tmp_lab_dir / '_EXAM_tp' / 'srelab.py').touch()
        assert '_EXAM_tp' in get_lab_list(include_exam_only_labs=True)

    def test_exam_not_recursed_into(self, tmp_lab_dir):
        """Even a regular lab nested inside an exam dir is excluded."""
        (tmp_lab_dir / '_EXAM_' / 'inner').mkdir(parents=True)
        (tmp_lab_dir / '_EXAM_' / 'inner' / 'srelab.py').touch()
        assert 'inner' not in get_lab_list()
        assert '_EXAM_/inner' not in get_lab_list()


class TestSorting:
    def test_result_is_sorted(self, tmp_lab_dir):
        (tmp_lab_dir / 'z.py').touch()
        (tmp_lab_dir / 'm.py').touch()
        (tmp_lab_dir / 'a.py').touch()
        result = get_lab_list()
        assert result == sorted(result)

    def test_empty_lab_dir(self, tmp_lab_dir):
        assert get_lab_list() == []


class TestGetLabListWithTitles:
    def test_titles_picked_up_from_titles_json(self, tmp_lab_dir):
        (tmp_lab_dir / 'sre').mkdir()
        (tmp_lab_dir / 'sre' / 'static_routing.py').touch()
        (tmp_lab_dir / 'sre' / 'dns1.py').touch()
        (tmp_lab_dir / 'sre' / 'titles.json').write_text(json.dumps({
            "static_routing.py": {"en": "Static routing", "fr": "Routage statique"},
        }))
        result = get_lab_list_with_titles()
        by_name = {e["name"]: e for e in result}
        assert by_name["sre/static_routing.py"]["title"] == {
            "en": "Static routing", "fr": "Routage statique"}
        assert by_name["sre/dns1.py"]["title"] is None

    def test_plain_string_title_accepted(self, tmp_lab_dir):
        (tmp_lab_dir / 'sre').mkdir()
        (tmp_lab_dir / 'sre' / 'dns1.py').touch()
        (tmp_lab_dir / 'sre' / 'titles.json').write_text(json.dumps({
            "dns1.py": "DNS 1",
        }))
        result = get_lab_list_with_titles()
        by_name = {e["name"]: e for e in result}
        assert by_name["sre/dns1.py"]["title"] == "DNS 1"

    def test_directory_lab_title(self, tmp_lab_dir):
        (tmp_lab_dir / 's4' / 'tp_ssh').mkdir(parents=True)
        (tmp_lab_dir / 's4' / 'tp_ssh' / 'srelab.py').touch()
        (tmp_lab_dir / 's4' / 'titles.json').write_text(json.dumps({
            "tp_ssh": {"en": "SSH lab"},
        }))
        result = get_lab_list_with_titles()
        by_name = {e["name"]: e for e in result}
        assert by_name["s4/tp_ssh"]["title"] == {"en": "SSH lab"}

    def test_stale_entry_in_titles_json_is_ignored(self, tmp_lab_dir):
        """titles.json entries without a matching file/dir on disk are dropped."""
        (tmp_lab_dir / 'sre').mkdir()
        (tmp_lab_dir / 'sre' / 'real.py').touch()
        (tmp_lab_dir / 'sre' / 'titles.json').write_text(json.dumps({
            "real.py": {"en": "Real"},
            "ghost.py": {"en": "Ghost"},
        }))
        names = [e["name"] for e in get_lab_list_with_titles()]
        assert names == ["sre/real.py"]

    def test_no_titles_file_yields_none_titles(self, tmp_lab_dir):
        (tmp_lab_dir / 'a.py').touch()
        result = get_lab_list_with_titles()
        assert result == [{"name": "a.py", "title": None}]

    def test_malformed_titles_json_treated_as_empty(self, tmp_lab_dir):
        (tmp_lab_dir / 'a.py').touch()
        (tmp_lab_dir / 'titles.json').write_text("{not json")
        result = get_lab_list_with_titles()
        assert result == [{"name": "a.py", "title": None}]

    def test_result_sorted_by_name(self, tmp_lab_dir):
        for name in ('z.py', 'm.py', 'a.py'):
            (tmp_lab_dir / name).touch()
        names = [e["name"] for e in get_lab_list_with_titles()]
        assert names == sorted(names)
