"""Tests for get_lab_list: lab discovery, filtering, and sorting; and for the lab tree of
get_lab_list_with_titles (`sre list --with-titles`): the directory entries, the titles and the
sort modes of titles.json."""
import json
import os

import pytest
from SRE import params, utils
from SRE.utils import get_lab_list, get_lab_list_with_titles, canonical_lab_name


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
        assert names == ["sre", "sre/real.py"]

    def test_no_titles_file_yields_none_titles(self, tmp_lab_dir):
        (tmp_lab_dir / 'a.py').touch()
        result = get_lab_list_with_titles()
        assert result == [{"name": "a.py", "title": None, "kind": "lab", "sort": "name"}]

    def test_malformed_titles_json_treated_as_empty(self, tmp_lab_dir):
        (tmp_lab_dir / 'a.py').touch()
        (tmp_lab_dir / 'titles.json').write_text("{not json")
        result = get_lab_list_with_titles()
        assert result == [{"name": "a.py", "title": None, "kind": "lab", "sort": "name"}]

    def test_result_sorted_by_name(self, tmp_lab_dir):
        for name in ('z.py', 'm.py', 'a.py'):
            (tmp_lab_dir / name).touch()
        names = [e["name"] for e in get_lab_list_with_titles()]
        assert names == sorted(names)


def _touch(tmp_lab_dir, *names):
    for name in names:
        path = tmp_lab_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()


def _titles(tmp_lab_dir, rel, data):
    (tmp_lab_dir / rel / 'titles.json').write_text(json.dumps(data))


class TestLabTree:
    """`sre list --with-titles` is the lab tree flattened in display order: a directory entry
    right before its content, the sub-directories of a directory before its labs, each group in
    the order of the effective "@sort" of the directory's titles.json (its own, else the nearest
    ancestor's, else by name), and every entry carries that mode."""

    @staticmethod
    def _names(result):
        return [e["name"] for e in result]

    def test_params(self):
        assert params.titles_sort_key.startswith(params.titles_reserved_prefix)
        assert set(params.titles_sort_modes) == {params.titles_sort_name, params.titles_sort_title,
                                                 params.titles_sort_manual}

    def test_directory_entries_before_their_content(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/tp_ssh/srelab.py', 's4/arp.py', 'root.py')
        (tmp_lab_dir / 'empty' / 'deeper').mkdir(parents=True)     # no lab below: not listed
        result = get_lab_list_with_titles()
        assert self._names(result) == ['s4', 's4/arp.py', 's4/tp_ssh', 'root.py']
        assert [e["kind"] for e in result] == ['dir', 'lab', 'lab', 'lab']
        assert {e["sort"] for e in result} == {'name'}

    def test_name_mode_directories_first_then_codepoint_order(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'b.py', 'Z.py', 'a.py', 'z/x.py', 'A/x.py')
        assert self._names(get_lab_list_with_titles()) == [
            'A', 'A/x.py', 'z', 'z/x.py', 'Z.py', 'a.py', 'b.py']

    def test_manual_mode(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'c.py', 'late/x.py', 'first/x.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "c.py": "C", "late": {"en": "Late"},
                                  "ghost.py": "Ghost", "a.py": None})
        result = get_lab_list_with_titles()
        # the listed entries in their order (a null title lists an entry too), the others by name
        assert self._names(result) == ['late', 'late/x.py', 'first', 'first/x.py',
                                       'c.py', 'a.py', 'b.py']
        by_name = {e["name"]: e for e in result}
        assert by_name['late']["title"] == {"en": "Late"} and by_name['late']["kind"] == 'dir'
        assert by_name['c.py']["title"] == "C" and by_name['a.py']["title"] is None
        assert {e["sort"] for e in result} == {'manual'}           # late/x.py inherits it

    def test_weights_of_the_labs(self, tmp_lab_dir):
        """The "@weights" option of a titles.json (`sre make-titles`) gives its labs a `weight`:
        the lab entries only, and only those it names with a weight."""
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'c.py', 'd.py', 'e.py', 's4/x.py', 's4/tp/srelab.py')
        _titles(tmp_lab_dir, '', {"@weights": {"a.py": 12, "b.py": 2.5, "c.py": "heavy", "d.py": -1,
                                               "e.py": True, "s4": 9, "ghost.py": 4}, "a.py": "A"})
        _titles(tmp_lab_dir, 's4', {"@weights": {"tp": 35.0, "x.py": 0}})
        entries = {e["name"]: e for e in get_lab_list_with_titles()}
        assert entries['a.py'] == {"name": "a.py", "title": "A", "kind": "lab", "sort": "name", "weight": 12}
        assert entries['b.py']["weight"] == 2.5
        assert entries['s4/tp']["weight"] == 35 and isinstance(entries['s4/tp']["weight"], int)
        assert entries['s4/x.py']["weight"] == 0
        for name in ('c.py', 'd.py', 'e.py', 's4'):                 # not a weight; a directory
            assert params.lab_list_weight_key not in entries[name], name

    def test_engines_of_the_labs(self, tmp_lab_dir):
        """The "@engines" option of a titles.json (`sre make-titles`) gives the labs that
        restrict their container engines an `engines` list: the lab entries only, and only
        those it names with a list of engines."""
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'c.py', 'd.py', 'e.py', 'f.py', 's4/x.py', 's4/tp/srelab.py')
        _titles(tmp_lab_dir, '', {"@engines": {"a.py": ["kathara"], "b.py": ["podman", "kathara", "podman"],
                                               "c.py": "kathara", "d.py": ["lxc"], "e.py": [], "s4": ["kathara"],
                                               "ghost.py": ["podman"]}, "a.py": "A"})
        _titles(tmp_lab_dir, 's4', {"@engines": {"tp": ["podman"]}})
        entries = {e["name"]: e for e in get_lab_list_with_titles()}
        assert entries['a.py'] == {"name": "a.py", "title": "A", "kind": "lab", "sort": "name", "engines": ["kathara"]}
        assert entries['b.py']["engines"] == ["podman", "kathara"]
        assert entries['s4/tp']["engines"] == ["podman"]
        for name in ('c.py', 'd.py', 'e.py', 'f.py', 's4', 's4/x.py'):    # not a list of engines; no entry; a directory
            assert params.lab_list_engines_key not in entries[name], name

    @pytest.mark.parametrize('engines', [None, 7, "all", ["kathara"], {"a.py": {"en": ["kathara"]}}])
    def test_an_engines_option_that_is_not_a_table_is_ignored(self, tmp_lab_dir, engines):
        _touch(tmp_lab_dir, 'a.py')
        _titles(tmp_lab_dir, '', {"@engines": engines})
        assert get_lab_list_with_titles() == [{"name": "a.py", "title": None, "kind": "lab", "sort": "name"}]

    def test_no_weight_without_the_option(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py', 'b.py')
        _titles(tmp_lab_dir, '', {"a.py": "A"})
        assert get_lab_list_with_titles() == [
            {"name": "a.py", "title": "A", "kind": "lab", "sort": "name"},
            {"name": "b.py", "title": None, "kind": "lab", "sort": "name"}]

    @pytest.mark.parametrize('weights', [None, 7, "all", [1, 2], {"a.py": {"en": 3}}])
    def test_weights_that_are_no_table_are_ignored(self, tmp_lab_dir, weights):
        _touch(tmp_lab_dir, 'a.py')
        _titles(tmp_lab_dir, '', {"@weights": weights, "a.py": "A"})
        assert get_lab_list_with_titles() == [{"name": "a.py", "title": "A", "kind": "lab", "sort": "name"}]

    def test_weights_leave_the_manual_order_alone(self, tmp_lab_dir):
        """An option is no entry: the table of the weights names labs without listing them."""
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'c.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@weights": {"a.py": 1, "b.py": 2, "c.py": 3},
                                  "c.py": "C", "a.py": None})
        result = get_lab_list_with_titles()
        assert self._names(result) == ['c.py', 'a.py', 'b.py']
        assert [e["weight"] for e in result] == [3, 1, 2]

    def test_title_mode_is_name_order_with_the_mode(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py', 'b.py')
        _titles(tmp_lab_dir, '', {"@sort": "title", "b.py": "A lab", "a.py": "Z lab"})
        result = get_lab_list_with_titles()
        assert self._names(result) == ['a.py', 'b.py']               # the consumers sort by label
        assert [e["sort"] for e in result] == ['title', 'title']

    def test_inheritance_override_and_invalid_value(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's1/b.py', 's1/a.py', 's2/b.py', 's2/a.py', 's2/deep/x.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "s2": None, "s1": None})
        _titles(tmp_lab_dir, 's1', {"@sort": "title"})
        _titles(tmp_lab_dir, 's2/deep', {"@sort": "bogus"})
        result = get_lab_list_with_titles()
        assert self._names(result) == ['s2', 's2/deep', 's2/deep/x.py', 's2/a.py', 's2/b.py',
                                       's1', 's1/a.py', 's1/b.py']
        sorts = {e["name"]: e["sort"] for e in result}
        assert sorts['s2'] == sorts['s1'] == 'manual'                 # placed by the root's mode
        assert sorts['s2/a.py'] == sorts['s2/deep'] == 'manual'       # s2 inherits it
        assert sorts['s2/deep/x.py'] == 'manual'                      # the invalid value is ignored
        assert sorts['s1/a.py'] == 'title'                            # s1 overrides it

    def test_option_keys_are_never_entries(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@future": {"x": 1}, "a.py": "A"})
        assert self._names(get_lab_list_with_titles()) == ['a.py']

    def test_subdirectory_titles(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/x.py', 'sre/y.py', 'em/z.py')
        _titles(tmp_lab_dir, '', {"s4": {"en": "Semester 4", "fr": "Semestre 4"}, "sre": "Shipped",
                                  "em": 5})
        titles = {e["name"]: e["title"] for e in get_lab_list_with_titles() if e["kind"] == 'dir'}
        assert titles == {'s4': {"en": "Semester 4", "fr": "Semestre 4"}, 'sre': "Shipped",
                          'em': None}

    def test_exam_only_entries_filtered_as_before(self, tmp_lab_dir):
        _touch(tmp_lab_dir, '_DRAFT_x/a.py', 's4/b_EXAM_.py', 's4/c.py')
        assert self._names(get_lab_list_with_titles()) == ['s4', 's4/c.py']
        assert self._names(get_lab_list_with_titles(include_exam_only_labs=True)) == [
            '_DRAFT_x', '_DRAFT_x/a.py', 's4', 's4/b_EXAM_.py', 's4/c.py']

    def test_lab_tree_keeps_the_directories_a_lab_lies_below(self, tmp_lab_dir):
        """`_lab_tree`: the directories `sre list --with-titles` lists and `sre make-titles -d`
        names, each with its sub-directories of the tree and its labs."""
        _touch(tmp_lab_dir, 'root.py', 's4/tp_ssh/srelab.py', 's4/tp_ssh/initial/all/motd',
               'a/b/c/deep.py', '_DRAFT_x/d.py', 'notes/README.md')
        (tmp_lab_dir / 'empty' / 'deeper').mkdir(parents=True)
        root = str(tmp_lab_dir)
        tree = utils._lab_tree(root, include_exam_only_labs=False)
        relative = {os.path.relpath(dirpath, root): (sorted(subdirs), sorted(labs))
                    for dirpath, (subdirs, labs) in tree.items()}
        assert relative == {'.': (['a', 's4'], ['root.py']), 's4': ([], ['tp_ssh']),
                            'a': (['b'], []), 'a/b': (['c'], []), 'a/b/c': ([], ['deep.py'])}
        tree = utils._lab_tree(root, include_exam_only_labs=True)
        assert sorted(tree[root][0]) == ['_DRAFT_x', 'a', 's4']
        assert utils._lab_tree(str(tmp_lab_dir / 'empty'), include_exam_only_labs=True) == {}


class TestSubtitles:
    """The subtitles of the manual order: a key of titles.json starting with "@subtitle",
    written among the entries, heads those that follow it up to the next one.  `sre list
    --with-titles` gives its text as the `subtitle` of the first entry shown of the group."""

    ROUTING = {"en": "Routing", "fr": "Routage"}

    @staticmethod
    def _shown(result):
        """The list as a user reads it: the subtitles (in brackets) and the names."""
        shown = []
        for entry in result:
            if params.lab_list_subtitle_key in entry:
                subtitle = entry[params.lab_list_subtitle_key]
                shown.append(f"[{subtitle if isinstance(subtitle, str) else subtitle['en']}]")
            shown.append(entry["name"])
        return shown

    def test_params(self):
        assert params.titles_subtitle_prefix.startswith(params.titles_reserved_prefix)
        assert utils.is_subtitle_key("@subtitle") and utils.is_subtitle_key("@subtitle routing")
        assert not utils.is_subtitle_key("@sort") and not utils.is_subtitle_key("subtitle.py")
        assert not utils.is_subtitle_key(None)

    def test_groups_of_labs(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'dhcp.py', 'dns.py', 'ospf.py', 'rip.py', 'intro.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "intro.py": "Introduction",
                                  "@subtitle addressing": "Addressing", "dhcp.py": "DHCP", "dns.py": None,
                                  "@subtitle routing": self.ROUTING, "rip.py": "RIP", "ospf.py": "OSPF"})
        result = get_lab_list_with_titles()
        # the entries written before the first subtitle form a group without one
        assert self._shown(result) == ['intro.py', '[Addressing]', 'dhcp.py', 'dns.py',
                                       '[Routing]', 'rip.py', 'ospf.py']
        by_name = {e["name"]: e for e in result}
        assert by_name['dhcp.py'] == {"name": "dhcp.py", "title": "DHCP", "kind": "lab", "sort": "manual",
                                      "subtitle": "Addressing"}
        assert by_name['rip.py']["subtitle"] == self.ROUTING           # a text by language, as a title
        assert by_name['dns.py'] == {"name": "dns.py", "title": None, "kind": "lab", "sort": "manual"}

    def test_without_subtitle_nothing_changes(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'c.py', 'late/x.py', 'first/x.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "c.py": "C", "late": None, "a.py": None})
        result = get_lab_list_with_titles()
        assert [e["name"] for e in result] == ['late', 'late/x.py', 'first', 'first/x.py', 'c.py', 'a.py', 'b.py']
        assert all(params.lab_list_subtitle_key not in e for e in result)

    def test_unlisted_entries_end_the_last_group(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'z.py', 'new2.py', 'new1.py', 'extra/x.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@subtitle 1": "One", "z.py": None,
                                  "@subtitle 2": "Two", "b.py": None, "a.py": None})
        # the last group: its sub-directories (the unlisted one), then its labs, the unlisted by name
        assert self._shown(get_lab_list_with_titles()) == [
            '[One]', 'z.py', '[Two]', 'extra', 'extra/x.py', 'b.py', 'a.py', 'new1.py', 'new2.py']

    def test_directories_and_labs_group_by_group(self, tmp_lab_dir):
        """A directory with both: each group shows its sub-directories then its labs, whatever
        their order inside the group in the file."""
        _touch(tmp_lab_dir, 'lab1.py', 'lab2.py', 'lab3.py', 'dir1/x.py', 'dir2/y.py', 'dir3/z.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual",
                                  "@subtitle a": "Group A", "lab1.py": None, "dir1": "First",
                                  "@subtitle b": "Group B", "dir3": None, "lab3.py": None, "dir2": None,
                                  "lab2.py": None})
        result = get_lab_list_with_titles()
        assert self._shown(result) == ['[Group A]', 'dir1', 'dir1/x.py', 'lab1.py',
                                       '[Group B]', 'dir3', 'dir3/z.py', 'dir2', 'dir2/y.py', 'lab3.py', 'lab2.py']
        by_name = {e["name"]: e for e in result}
        # the subtitle is on the directory entry, the first one of its group, not on its content
        assert by_name['dir1']["subtitle"] == "Group A" and by_name['dir1']["kind"] == 'dir'
        assert params.lab_list_subtitle_key not in by_name['dir1/x.py']
        assert params.lab_list_subtitle_key not in by_name['lab1.py']

    def test_a_group_with_nothing_to_show_has_no_subtitle(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py', 'draft_DRAFT_.py', 'b.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@subtitle ready": "Ready", "a.py": None,
                                  "@subtitle drafts": "Drafts", "draft_DRAFT_.py": None, "gone.py": "Gone",
                                  "@subtitle more": "More", "b.py": None})
        assert self._shown(get_lab_list_with_titles()) == ['[Ready]', 'a.py', '[More]', 'b.py']
        assert self._shown(get_lab_list_with_titles(include_exam_only_labs=True)) == [
            '[Ready]', 'a.py', '[Drafts]', 'draft_DRAFT_.py', '[More]', 'b.py']

    def test_the_subtitle_follows_the_first_entry_shown(self, tmp_lab_dir):
        """The first entry of a group in the file may be hidden: the next one carries the text."""
        _touch(tmp_lab_dir, 'first_EXAM_.py', 'second.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@subtitle": "Group", "first_EXAM_.py": None,
                                  "second.py": None})
        assert self._shown(get_lab_list_with_titles()) == ['[Group]', 'second.py']
        assert self._shown(get_lab_list_with_titles(include_exam_only_labs=True)) == [
            '[Group]', 'first_EXAM_.py', 'second.py']

    @pytest.mark.parametrize('value', [None, "", "   ", 3, True, [], ["Text"], {}, {"en": ""}, {"en": 5}])
    def test_a_subtitle_without_text_starts_no_group(self, tmp_lab_dir, value):
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'c.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@subtitle 1": "One", "b.py": None,
                                  "@subtitle 2": value, "a.py": None})
        result = get_lab_list_with_titles()
        assert self._shown(result) == ['[One]', 'b.py', 'a.py', 'c.py']
        assert utils.subtitle_of("@subtitle 2", value) is None

    def test_only_the_texts_of_a_table_are_kept(self):
        assert utils.subtitle_of("@subtitle x", {"en": "Routing", "fr": "", "de": 4}) == {"en": "Routing"}
        assert utils.subtitle_of("@subtitle x", "Routing") == "Routing"
        assert utils.subtitle_of("@sort", "Routing") is None            # not a subtitle key
        assert utils.subtitle_of("x.py", "Routing") is None

    @pytest.mark.parametrize('mode', ["name", "title", None])
    def test_ignored_outside_the_manual_mode(self, tmp_lab_dir, mode):
        _touch(tmp_lab_dir, 'a.py', 'b.py', 'sub/x.py')
        titles = {"@subtitle 1": "One", "b.py": "B", "@subtitle 2": "Two", "sub": None, "a.py": "A"}
        if mode is not None:
            titles["@sort"] = mode
        _titles(tmp_lab_dir, '', titles)
        result = get_lab_list_with_titles()
        assert self._shown(result) == ['sub', 'sub/x.py', 'a.py', 'b.py']
        assert {e["sort"] for e in result} == {mode or 'name'}

    def test_inherited_manual_mode(self, tmp_lab_dir):
        """The mode may come from an ancestor: the subtitles of the directory count all the same."""
        _touch(tmp_lab_dir, 's4/a.py', 's4/b.py', 's5/a.py', 's5/b.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@subtitle year 2": "Second year", "s4": None, "s5": None})
        _titles(tmp_lab_dir, 's4', {"@subtitle 1": "Basics", "b.py": None, "@subtitle 2": "More", "a.py": None})
        _titles(tmp_lab_dir, 's5', {"@sort": "name", "@subtitle 1": "Never shown", "b.py": None})
        assert self._shown(get_lab_list_with_titles()) == [
            '[Second year]', 's4', '[Basics]', 's4/b.py', '[More]', 's4/a.py', 's5', 's5/a.py', 's5/b.py']

    def test_subtitles_are_no_entries_and_keep_the_weights(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 'a.py', 'b.py')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@weights": {"a.py": 4, "b.py": 9},
                                  "@subtitle 1": "One", "b.py": "B", "a.py": "A"})
        assert get_lab_list_with_titles() == [
            {"name": "b.py", "title": "B", "kind": "lab", "sort": "manual", "weight": 9, "subtitle": "One"},
            {"name": "a.py", "title": "A", "kind": "lab", "sort": "manual", "weight": 4}]

    def test_readme_and_subtitle_on_a_directory_entry(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/a.py')
        (tmp_lab_dir / 's4' / 'README.md').write_text('# S4')
        _titles(tmp_lab_dir, '', {"@sort": "manual", "@subtitle 1": "Year 2", "s4": "Semester 4"})
        result = get_lab_list_with_titles(with_readmes=True)
        assert result[0] == {"name": "s4", "title": "Semester 4", "kind": "dir", "sort": "manual",
                             "readme": {"": "# S4"}, "subtitle": "Year 2"}


class TestSymbolicLinks:
    """The Debian package links its labs into the lab directory: /var/lib/sre/lab/sre."""

    def test_symlinked_subdirectory_is_walked(self, tmp_lab_dir, tmp_path):
        shipped = tmp_path / 'shipped' / 'sre'
        shipped.mkdir(parents=True)
        (shipped / 'dhcp.py').touch()
        (shipped / 'tp').mkdir()
        (shipped / 'tp' / 'srelab.py').touch()
        (tmp_lab_dir / 'sre').symlink_to(shipped)
        (tmp_lab_dir / 'site').mkdir()
        (tmp_lab_dir / 'site' / 'own.py').touch()
        assert get_lab_list() == ['site/own.py', 'sre/dhcp.py', 'sre/tp']

    def test_symlink_loop_ends(self, tmp_lab_dir):
        (tmp_lab_dir / 'a').mkdir()
        (tmp_lab_dir / 'a' / 'x.py').touch()
        (tmp_lab_dir / 'a' / 'loop').symlink_to(tmp_lab_dir)
        assert get_lab_list() == ['a/x.py']


class TestActionList:
    """`sre list [--with-titles] [--include-exam-only]`: the exam-only labs for the privileged
    callers only (the web agent lists them to an instructor programming an exam)."""

    def test_include_exam_only_is_privileged(self, tmp_lab_dir, mock_sre_args, capsys):
        from SRE.command.list import action_list
        _touch(tmp_lab_dir, '_EXAM_x/a.py', 's4/c.py')
        with pytest.raises(SystemExit) as e:
            action_list()
        assert e.value.code == 0 and json.loads(capsys.readouterr().out) == ['s4/c.py']
        with pytest.raises(SystemExit) as e:
            action_list(include_exam_only=True)
        assert e.value.code == 0 and json.loads(capsys.readouterr().out) == ['_EXAM_x/a.py', 's4/c.py']
        with pytest.raises(SystemExit) as e:
            action_list(with_titles=True, include_exam_only=True)
        names = [entry['name'] for entry in json.loads(capsys.readouterr().out)]
        assert names == ['_EXAM_x', '_EXAM_x/a.py', 's4', 's4/c.py']
        mock_sre_args.user = True
        with pytest.raises(SystemExit) as e:
            action_list(include_exam_only=True)
        assert e.value.code == 1 and "not allowed" in capsys.readouterr().err
        with pytest.raises(SystemExit) as e:
            action_list()
        assert e.value.code == 0 and json.loads(capsys.readouterr().out) == ['s4/c.py']


    def test_with_readmes_needs_with_titles(self, tmp_lab_dir, capsys):
        from SRE.command.list import action_list
        _touch(tmp_lab_dir, 's4/c.py')
        (tmp_lab_dir / 's4' / 'README.md').write_text("# Semester 4\n")
        with pytest.raises(SystemExit) as e:
            action_list(with_readmes=True)
        assert e.value.code == 1 and "--with-titles" in capsys.readouterr().err
        with pytest.raises(SystemExit) as e:
            action_list(with_titles=True, with_readmes=True)
        assert e.value.code == 0
        assert json.loads(capsys.readouterr().out) == [
            {"name": "s4", "title": None, "kind": "dir", "sort": "name", "readme": {"": "# Semester 4\n"}},
            {"name": "s4/c.py", "title": None, "kind": "lab", "sort": "name"}]

    def test_readmes_in_user_mode(self, tmp_lab_dir, mock_sre_args, capsys):
        """A student reads the README of the directories they are listed, no other."""
        from SRE.command.list import action_list
        _touch(tmp_lab_dir, 's4/c.py', '_DRAFT_x/a.py')
        (tmp_lab_dir / 's4' / 'README.md').write_text("for everybody")
        (tmp_lab_dir / '_DRAFT_x' / 'README.md').write_text("for the instructors")
        mock_sre_args.user = True
        with pytest.raises(SystemExit) as e:
            action_list(with_titles=True, with_readmes=True)
        out = capsys.readouterr().out
        assert e.value.code == 0 and "for everybody" in out and "for the instructors" not in out


class TestReadmes:
    """`sre list --with-titles --with-readmes`: the README.md / README.<lang>.md of the
    directories of the lab tree, as raw markdown by language on their `dir` entry, the top
    directory as an entry of its own; nothing without the flag."""

    def _readmes(self, **kwargs):
        return {e["name"]: e["readme"] for e in get_lab_list_with_titles(with_readmes=True, **kwargs)
                if "readme" in e}

    def test_nothing_without_the_flag(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/c.py', 'root.py')
        (tmp_lab_dir / 'README.md').write_text("top")
        (tmp_lab_dir / 's4' / 'README.md').write_text("s4")
        assert get_lab_list_with_titles() == [
            {"name": "s4", "title": None, "kind": "dir", "sort": "name"},
            {"name": "s4/c.py", "title": None, "kind": "lab", "sort": "name"},
            {"name": "root.py", "title": None, "kind": "lab", "sort": "name"}]
        assert get_lab_list() == ['root.py', 's4/c.py']

    def test_the_flag_only_adds(self, tmp_lab_dir):
        """A tree without any README is listed the same with the flag."""
        _touch(tmp_lab_dir, 's4/tp_ssh/srelab.py', 's4/arp.py', 'root.py')
        _titles(tmp_lab_dir, 's4', {"@sort": "title", "arp.py": {"en": "ARP"}})
        assert get_lab_list_with_titles(with_readmes=True) == get_lab_list_with_titles()

    def test_readme_of_a_directory(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/r401/c.py', 's4/d.py', 's5/e.py')
        (tmp_lab_dir / 's4' / 'README.md').write_text("# Semester 4\n\nÉté: *labs*\n")
        (tmp_lab_dir / 's4' / 'r401' / 'README.md').write_text("R4.01")
        result = get_lab_list_with_titles(with_readmes=True)
        assert [e["name"] for e in result] == ['s4', 's4/r401', 's4/r401/c.py', 's4/d.py', 's5', 's5/e.py']
        assert result[0] == {"name": "s4", "title": None, "kind": "dir", "sort": "name",
                             "readme": {"": "# Semester 4\n\nÉté: *labs*\n"}}
        assert result[1]["readme"] == {"": "R4.01"}
        assert all("readme" not in e for e in result[2:])      # the labs, and a directory without README

    def test_language_variants(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/c.py', 's5/c.py')
        (tmp_lab_dir / 's4' / 'README.md').write_text("default")
        (tmp_lab_dir / 's4' / 'README.fr.md').write_text("français")
        (tmp_lab_dir / 's4' / 'README.en.md').write_text("english")
        (tmp_lab_dir / 's5' / 'README.fr.md').write_text("sans défaut")
        assert self._readmes() == {'s4': {"": "default", "en": "english", "fr": "français"},
                                   's5': {"fr": "sans défaut"}}

    def test_top_directory_first(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/c.py', 'root.py')
        _titles(tmp_lab_dir, '.', {"@sort": "manual"})
        (tmp_lab_dir / 'README.md').write_text("welcome")
        (tmp_lab_dir / 'README.fr.md').write_text("bienvenue")
        result = get_lab_list_with_titles(with_readmes=True)
        assert result[0] == {"name": "", "title": None, "kind": "dir", "sort": "name",
                             "readme": {"": "welcome", "fr": "bienvenue"}}
        assert [e["name"] for e in result[1:]] == ['s4', 's4/c.py', 'root.py']
        assert [e["sort"] for e in result[1:]] == ['manual', 'manual', 'manual']

    def test_no_top_entry_without_readme_nor_without_lab(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/c.py')
        assert [e["name"] for e in get_lab_list_with_titles(with_readmes=True)] == ['s4', 's4/c.py']
        (tmp_lab_dir / 's4' / 'c.py').unlink()
        (tmp_lab_dir / 'README.md').write_text("welcome")
        assert get_lab_list_with_titles(with_readmes=True) == []

    def test_only_the_directories_listed(self, tmp_lab_dir):
        """Never the README of an exam-only directory (unless they are listed), of a directory
        without any lab below, nor of the inside of a directory lab."""
        _touch(tmp_lab_dir, 's4/c.py', '_DRAFT_x/a.py', 's4/_EXAM_y/b.py', 's4/tp_ssh/srelab.py')
        (tmp_lab_dir / 'notes').mkdir()
        for rel in ('s4', '_DRAFT_x', 's4/_EXAM_y', 's4/tp_ssh', 'notes'):
            (tmp_lab_dir / rel / 'README.md').write_text(rel)
        assert self._readmes() == {'s4': {"": "s4"}}
        assert self._readmes(include_exam_only_labs=True) == {
            's4': {"": "s4"}, '_DRAFT_x': {"": "_DRAFT_x"}, 's4/_EXAM_y': {"": "s4/_EXAM_y"}}

    def test_files_not_shown(self, tmp_lab_dir, monkeypatch):
        """Other names (the pattern is exact), an empty file, a directory, a file over the size
        cap; a file of the cap exactly is shown, bytes that are not UTF-8 are replaced."""
        monkeypatch.setattr(params, 'lab_readme_max_size', 20)
        for d in ('names', 'empty', 'isdir', 'big', 'fits', 'latin1'):
            _touch(tmp_lab_dir, f'{d}/c.py')
        for name in ('README', 'README.txt', 'README.FR.md', 'README.francais.md', 'NOTES.md', 'XREADME.md',
                     'README.md.bak'):
            (tmp_lab_dir / 'names' / name).write_text("not a README")
        (tmp_lab_dir / 'empty' / 'README.md').write_text("  \n\n")
        (tmp_lab_dir / 'isdir' / 'README.md').mkdir()
        (tmp_lab_dir / 'big' / 'README.md').write_text("x" * 21)
        (tmp_lab_dir / 'big' / 'README.fr.md').write_text("court")
        (tmp_lab_dir / 'fits' / 'README.md').write_text("x" * 20)
        (tmp_lab_dir / 'latin1' / 'README.md').write_bytes("été".encode('latin-1'))
        assert self._readmes() == {'big': {"fr": "court"}, 'fits': {"": "x" * 20},
                                   'latin1': {"": "�t�"}}

    @pytest.mark.skipif(os.path.exists(os.path.join(os.path.dirname(__file__), 'TEST_LAB_LIST.PY')),
                        reason="a case-insensitive file system: readme.md is README.md")
    def test_case_matters(self, tmp_lab_dir):
        _touch(tmp_lab_dir, 's4/c.py')
        (tmp_lab_dir / 's4' / 'readme.md').write_text("lower case")
        assert self._readmes() == {}

    def test_load_readmes_of_a_missing_directory(self, tmp_lab_dir):
        assert utils.load_readmes(str(tmp_lab_dir / 'gone')) == {}


class TestCanonicalLabName:
    """canonical_lab_name: the lab file a lab name really designates (symlinks resolved), in the
    @ form, relative to the lab directory, the shipped tree as sre@... in both layouts."""

    @pytest.fixture
    def labs(self, tmp_lab_dir, monkeypatch):
        """A lab tree: the shipped sre/ with a file lab and a directory lab, a course directory
        s3/r306 linking both, a lab of its own; the checkout layout (shipped_lab_dir = lab_dir)."""
        monkeypatch.setattr(params, 'shipped_lab_dir', str(tmp_lab_dir))
        (tmp_lab_dir / 'sre' / 'tp_ssh').mkdir(parents=True)
        (tmp_lab_dir / 'sre' / 'dns1.py').write_text('')
        (tmp_lab_dir / 'sre' / 'tp_ssh' / 'srelab.py').write_text('')
        (tmp_lab_dir / 's3' / 'r306').mkdir(parents=True)
        (tmp_lab_dir / 's3' / 'r306' / 'dns1.py').symlink_to('../../sre/dns1.py')
        (tmp_lab_dir / 's3' / 'r306' / 'tp_ssh').symlink_to('../../sre/tp_ssh')
        (tmp_lab_dir / 's3' / 'r306' / 'own.py').write_text('')
        return tmp_lab_dir

    def test_plain_names_unchanged(self, labs):
        assert canonical_lab_name('sre@dns1.py') == 'sre@dns1.py'
        assert canonical_lab_name('sre@tp_ssh') == 'sre@tp_ssh'
        assert canonical_lab_name('s3@r306@own.py') == 's3@r306@own.py'

    def test_symbolic_links_resolve_to_the_lab(self, labs):
        assert canonical_lab_name('s3@r306@dns1.py') == 'sre@dns1.py'
        assert canonical_lab_name('s3@r306@tp_ssh') == 'sre@tp_ssh'      # a linked directory lab

    def test_missing_path_unchanged(self, labs):
        assert canonical_lab_name('s3@r306@gone.py') == 's3@r306@gone.py'
        assert canonical_lab_name('') == ''
        assert canonical_lab_name('bad\x00name') == 'bad\x00name'

    def test_absolute_path_of_a_p_project(self, labs, tmp_path):
        """A lab started by its path (-p) has an absolute lab name: its real path comes back."""
        home = tmp_path / 'home' / 'etudiant'
        home.mkdir(parents=True)
        (home / 'x.py').write_text('')
        (home / 'link.py').symlink_to('x.py')
        real = str((home / 'x.py').resolve()).replace('/', '@')
        assert canonical_lab_name(str(home / 'link.py').replace('/', '@')) == real
        assert canonical_lab_name(str(home / 'x.py').replace('/', '@')) == real

    def test_fhs_layout_shipped_tree_linked_as_sre(self, tmp_path, monkeypatch):
        """The Debian layout: lab_dir/sre is a symlink to shipped_lab_dir elsewhere; a shipped lab
        reached through it, or through a course directory, is sre@... like on a checkout."""
        shipped = tmp_path / 'usr' / 'share' / 'sysreseval' / 'lab'
        shipped.mkdir(parents=True)
        (shipped / 'dns1.py').write_text('')
        lab_dir = tmp_path / 'var' / 'lib' / 'sre' / 'lab'
        lab_dir.mkdir(parents=True)
        (lab_dir / 'sre').symlink_to(shipped)
        (lab_dir / 'cours').mkdir()
        (lab_dir / 'cours' / 'dns1.py').symlink_to('../sre/dns1.py')
        (lab_dir / 'cours' / 'local.py').write_text('')
        monkeypatch.setattr(params, 'lab_dir', str(lab_dir))
        monkeypatch.setattr(params, 'shipped_lab_dir', str(shipped))
        assert canonical_lab_name('sre@dns1.py') == 'sre@dns1.py'
        assert canonical_lab_name('cours@dns1.py') == 'sre@dns1.py'
        assert canonical_lab_name('cours@local.py') == 'cours@local.py'
        assert params.shipped_lab_link_name == 'sre'
