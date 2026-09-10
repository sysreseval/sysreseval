"""Tests for the `sre watch` interactive dashboard.

Covers:
- `_aggregate_grade_lists`: per-grade-element aggregation across users
  (numeric vs letter mode, label resolution, distribution formatting/ordering,
  uneven element counts, missing grades).
- `_render`: tagged-union `selectable_rows` output now includes lab title
  entries alongside project entries, in the correct interleaved order.
- `_group_archives_by_instance` / `_scan`: the first time an instance is
  seen only its newest archive is decompressed (the previous one is a
  fallback when the newest is unreadable), afterwards each new archive is
  decompressed once; records persist in `_INDEX`, `_CACHE` is pruned to the
  archives displayed, and two machines sharing a running_lab_name both show.
"""
import os
import re
import types
from datetime import datetime
from pathlib import Path

import pytest

from archive_helpers import LAB, archive_name as _archive_name, rln as _rln, write_archive as _write_archive
from SRE import params
from SRE.command import watch
from SRE.command.watch import (
    Record,
    _aggregate_grade_lists,
    _aggregate_part_subtotals,
    _group_archives_by_instance,
    _render,
    _scan,
)


# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_watch_globals():
    """Each test starts with empty dismissal sets and no hostname filter."""
    watch._DISMISSED_PROJECTS.clear()
    watch._DISMISSED_HOSTS.clear()
    watch._DISMISSED_ALERTS.clear()
    watch._host_filter_pattern = ''
    watch._host_filter_re = None
    watch._CACHE.clear()
    watch._INDEX.clear()
    watch._starting_time = None
    yield
    watch._DISMISSED_PROJECTS.clear()
    watch._DISMISSED_HOSTS.clear()
    watch._DISMISSED_ALERTS.clear()
    watch._host_filter_pattern = ''
    watch._host_filter_re = None
    watch._CACHE.clear()
    watch._INDEX.clear()
    watch._starting_time = None


def _ge(*, title='', description='', grade=None, max_grade=None, grade_letter=None,
        grade_part=None) -> dict:
    """Build a grade-element dict matching the archive serialization."""
    return {
        'title': title,
        'description': description,
        'grade': grade,
        'max_grade': max_grade,
        'grade_letter': grade_letter,
        'grade_part': grade_part,
    }


def _gp(title: str, description: str = '') -> dict:
    """Build a grade-part dict matching the archive serialization."""
    return {'title': title, 'description': description}


def _rec(hostname='host1', login='alice', lab_name='lab/x', grade=10.0,
         max_grade=10.0, path='/tmp/archive.zst') -> Record:
    return Record(
        hostname=hostname, login=login, lab_name=lab_name,
        grade=grade, max_grade=max_grade,
        errors=0, warnings=0,
        eval_time=datetime(2026, 5, 16, 12, 0, 0),
        file_mtime=1747400000.0,
        time_remaining=None, auto_eval_count=None,
        path=path,
    )


# ---------------------------------------------------------------------------
# _aggregate_grade_lists
# ---------------------------------------------------------------------------

class TestAggregateBasic:
    def test_empty_input_returns_empty(self):
        assert _aggregate_grade_lists([]) == []

    def test_empty_users_returns_empty(self):
        assert _aggregate_grade_lists([[], [], []]) == []

    def test_single_numeric_element_single_user(self):
        out = _aggregate_grade_lists([[_ge(title='A', grade=5.0, max_grade=10.0)]])
        assert len(out) == 1
        a = out[0]
        assert a['mode'] == 'numeric'
        assert a['label'] == 'A'
        assert a['tot'] == 10.0
        assert a['max'] == 5.0
        assert a['min'] == 5.0
        assert a['avg'] == 5.0
        assert a['dist'] == '5(1)'


class TestAggregateNumeric:
    def test_multi_user_stats(self):
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=0.0,  max_grade=10.0)],
            [_ge(title='A', grade=10.0, max_grade=10.0)],
            [_ge(title='A', grade=5.0,  max_grade=10.0)],
        ])
        a = out[0]
        assert a['tot'] == 10.0
        assert a['max'] == 10.0
        assert a['min'] == 0.0
        assert a['avg'] == pytest.approx(5.0)

    def test_distribution_counts_and_sorts_ascending(self):
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=2.0, max_grade=10.0)],
            [_ge(title='A', grade=1.5, max_grade=10.0)],
            [_ge(title='A', grade=2.0, max_grade=10.0)],
            [_ge(title='A', grade=1.0, max_grade=10.0)],
        ])
        assert out[0]['dist'] == '1(1) 1.5(1) 2(2)'

    def test_distribution_integers_render_without_trailing_zero(self):
        """`f"{1.0:g}"` -> '1', `f"{1.5:g}"` -> '1.5'."""
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=1.0, max_grade=5.0)],
            [_ge(title='A', grade=1.5, max_grade=5.0)],
        ])
        assert out[0]['dist'] == '1(1) 1.5(1)'

    def test_skips_users_missing_this_index(self):
        """User2's list is shorter — element[1] aggregates only user1."""
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=5.0, max_grade=10.0),
             _ge(title='B', grade=3.0, max_grade=5.0)],
            [_ge(title='A', grade=7.0, max_grade=10.0)],
        ])
        assert out[0]['avg'] == pytest.approx(6.0)
        # Element 1 only seen by user1
        assert out[1]['avg'] == 3.0
        assert out[1]['dist'] == '3(1)'

    def test_none_grade_excluded_from_stats_and_dist(self):
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=5.0,  max_grade=10.0)],
            [_ge(title='A', grade=None, max_grade=10.0)],
            [_ge(title='A', grade=7.0,  max_grade=10.0)],
        ])
        assert out[0]['tot'] == 10.0
        assert out[0]['avg'] == pytest.approx(6.0)
        assert out[0]['max'] == 7.0
        assert out[0]['min'] == 5.0
        assert out[0]['dist'] == '5(1) 7(1)'

    def test_all_none_grades(self):
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=None, max_grade=10.0)],
            [_ge(title='A', grade=None, max_grade=10.0)],
        ])
        a = out[0]
        assert a['tot'] == 10.0
        assert a['max'] is None
        assert a['min'] is None
        assert a['avg'] is None
        assert a['dist'] == ''

    def test_missing_max_grade(self):
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=3.0, max_grade=None)],
            [_ge(title='A', grade=4.0, max_grade=None)],
        ])
        assert out[0]['tot'] is None
        assert out[0]['avg'] == pytest.approx(3.5)


class TestAggregateLetter:
    def test_basic_letter_aggregation(self):
        out = _aggregate_grade_lists([
            [_ge(title='B', grade_letter='OK')],
            [_ge(title='B', grade_letter='OK')],
            [_ge(title='B', grade_letter='FAIL')],
        ])
        a = out[0]
        assert a['mode'] == 'letter'
        assert a['tot'] is None
        assert a['max'] is None
        assert a['min'] is None
        assert a['avg'] is None
        assert a['dist'] == 'OK(2) FAIL(1)'

    def test_letter_distribution_in_canonical_order(self):
        """Order is OK, MEH, FAIL regardless of insertion order."""
        out = _aggregate_grade_lists([
            [_ge(title='B', grade_letter='FAIL')],
            [_ge(title='B', grade_letter='MEH')],
            [_ge(title='B', grade_letter='OK')],
            [_ge(title='B', grade_letter='MEH')],
            [_ge(title='B', grade_letter='OK')],
        ])
        assert out[0]['dist'] == 'OK(2) MEH(2) FAIL(1)'

    def test_unknown_letter_appended_after_known(self):
        out = _aggregate_grade_lists([
            [_ge(title='B', grade_letter='OK')],
            [_ge(title='B', grade_letter='WAT')],
        ])
        assert out[0]['dist'].startswith('OK(1)')
        assert 'WAT(1)' in out[0]['dist']


class TestAggregateLabel:
    def test_description_takes_priority_over_title(self):
        out = _aggregate_grade_lists([
            [_ge(title='short', description='the long description', grade=1.0, max_grade=2.0)],
        ])
        assert out[0]['label'] == 'the long description'

    def test_falls_back_to_title_when_description_empty(self):
        out = _aggregate_grade_lists([
            [_ge(title='only-title', description='', grade=1.0, max_grade=2.0)],
        ])
        assert out[0]['label'] == 'only-title'

    def test_resolves_translated_text_dict(self):
        out = _aggregate_grade_lists([
            [_ge(title='', description={'en': 'English label', 'fr': 'Étiquette'},
                 grade=1.0, max_grade=2.0)],
        ])
        assert out[0]['label'] == 'English label'

    def test_first_user_with_non_empty_label_wins(self):
        """Aggregation searches users in order until it finds a non-empty label."""
        out = _aggregate_grade_lists([
            [_ge(title='', description='', grade=1.0, max_grade=2.0)],
            [_ge(title='from-user-2', description='', grade=2.0, max_grade=2.0)],
        ])
        assert out[0]['label'] == 'from-user-2'


class TestAggregateMixedElements:
    def test_numeric_then_letter(self):
        out = _aggregate_grade_lists([
            [_ge(title='A', grade=3.0, max_grade=5.0),
             _ge(title='B', grade_letter='OK')],
            [_ge(title='A', grade=5.0, max_grade=5.0),
             _ge(title='B', grade_letter='FAIL')],
        ])
        assert out[0]['mode'] == 'numeric'
        assert out[0]['avg'] == pytest.approx(4.0)
        assert out[1]['mode'] == 'letter'
        assert out[1]['dist'] == 'OK(1) FAIL(1)'


# ---------------------------------------------------------------------------
# _aggregate_part_subtotals
# ---------------------------------------------------------------------------

class TestAggregatePartSubtotals:
    def test_no_grade_parts_returns_all_none_titles_no_subtotals(self):
        gls = [[_ge(title='A', grade=2.0, max_grade=5.0),
                _ge(title='B', grade=3.0, max_grade=5.0)]]
        titles, subs = _aggregate_part_subtotals(gls, [])
        assert titles == [None, None]
        assert subs == {}

    def test_basic_grouping_subtotal_across_users(self):
        gls = [
            [_ge(title='A', grade=2.0, max_grade=5.0, grade_part='Part1'),
             _ge(title='B', grade=4.0, max_grade=5.0, grade_part='Part1'),
             _ge(title='C', grade=1.0, max_grade=10.0, grade_part='Part2')],
            [_ge(title='A', grade=5.0, max_grade=5.0, grade_part='Part1'),
             _ge(title='B', grade=5.0, max_grade=5.0, grade_part='Part1'),
             _ge(title='C', grade=10.0, max_grade=10.0, grade_part='Part2')],
        ]
        parts = [_gp('Part1', 'First half'), _gp('Part2', 'Second half')]
        titles, subs = _aggregate_part_subtotals(gls, parts)
        assert titles == ['Part1', 'Part1', 'Part2']

        # Part1: per-user totals are 6 and 10 → tot=10, max=10, min=6, avg=8
        p1 = subs['Part1']
        assert p1['tot'] == 10.0
        assert p1['max'] == 10.0
        assert p1['min'] == 6.0
        assert p1['avg'] == pytest.approx(8.0)
        assert p1['label'] == 'Subtotal for First half'
        assert p1['dist'] == '6(1) 10(1)'

        # Part2: per-user totals are 1 and 10
        p2 = subs['Part2']
        assert p2['tot'] == 10.0
        assert p2['max'] == 10.0
        assert p2['min'] == 1.0
        assert p2['avg'] == pytest.approx(5.5)

    def test_element_with_unknown_part_is_ungrouped(self):
        """An element whose ``grade_part`` is not in ``grade_parts`` falls
        through as ungrouped (title=None) and does not get a subtotal."""
        gls = [[_ge(title='A', grade=2.0, max_grade=5.0, grade_part='Other'),
                _ge(title='B', grade=3.0, max_grade=5.0, grade_part='Part1')]]
        parts = [_gp('Part1')]
        titles, subs = _aggregate_part_subtotals(gls, parts)
        assert titles == [None, 'Part1']
        assert set(subs.keys()) == {'Part1'}

    def test_part_with_only_none_grades_is_skipped(self):
        """A part with elements but no non-None grades produces no subtotal."""
        gls = [[_ge(title='A', grade=None, max_grade=5.0, grade_part='P')]]
        parts = [_gp('P')]
        titles, subs = _aggregate_part_subtotals(gls, parts)
        assert titles == ['P']
        assert 'P' not in subs

    def test_label_falls_back_to_title_when_description_empty(self):
        gls = [[_ge(title='A', grade=1.0, max_grade=2.0, grade_part='Only')]]
        parts = [_gp('Only', description='')]
        _titles, subs = _aggregate_part_subtotals(gls, parts)
        assert subs['Only']['label'] == 'Subtotal for Only'

    def test_grade_part_taken_from_first_user_that_has_one(self):
        """If user1's element lacks grade_part but user2's has one, the helper
        picks it up from user2 (so ordering of users doesn't drop grouping)."""
        gls = [
            [_ge(title='A', grade=2.0, max_grade=5.0, grade_part=None)],
            [_ge(title='A', grade=4.0, max_grade=5.0, grade_part='P')],
        ]
        parts = [_gp('P')]
        titles, subs = _aggregate_part_subtotals(gls, parts)
        assert titles == ['P']
        # Per-user totals: user1=2, user2=4 → both users contribute
        assert subs['P']['avg'] == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# _render: selectable_rows tagged-union output
# ---------------------------------------------------------------------------

class TestRenderSelectableRows:
    def test_no_archives_empty_rows(self):
        rows, _alerts, _buf, _cursor = _render(
            best={}, dirs=['/tmp'], timeout=60, read_errors=[],
            focus='projects', proj_cursor=0, alert_cursor=0, show_help=False,
        )
        assert rows == []

    def test_one_lab_one_user_emits_lab_then_project(self):
        rec = _rec(hostname='h1', lab_name='lab/x', path='/p1.zst')
        rows, *_ = _render(
            best={('h1', 'lab/x'): rec},
            dirs=['/tmp'], timeout=60, read_errors=[],
            focus='projects', proj_cursor=0, alert_cursor=0, show_help=False,
        )
        assert len(rows) == 2
        assert rows[0] == ('lab', 'lab/x', [rec])
        assert rows[1] == ('project', rec)

    def test_one_lab_multiple_users_one_lab_entry_followed_by_projects(self):
        r1 = _rec(hostname='h1', lab_name='lab/x', path='/p1.zst')
        r2 = _rec(hostname='h2', lab_name='lab/x', path='/p2.zst')
        rows, *_ = _render(
            best={('h1', 'lab/x'): r1, ('h2', 'lab/x'): r2},
            dirs=['/tmp'], timeout=60, read_errors=[],
            focus='projects', proj_cursor=0, alert_cursor=0, show_help=False,
        )
        assert [r[0] for r in rows] == ['lab', 'project', 'project']
        assert rows[0][0] == 'lab'
        # Projects are sorted by hostname inside the lab group
        assert rows[1][1].hostname == 'h1'
        assert rows[2][1].hostname == 'h2'

    def test_two_labs_emit_interleaved_lab_and_project_entries(self):
        ra = _rec(hostname='h1', lab_name='lab/a', path='/a.zst')
        rb = _rec(hostname='h1', lab_name='lab/b', path='/b.zst')
        rows, *_ = _render(
            best={('h1', 'lab/a'): ra, ('h1', 'lab/b'): rb},
            dirs=['/tmp'], timeout=60, read_errors=[],
            focus='projects', proj_cursor=0, alert_cursor=0, show_help=False,
        )
        # Labs are sorted alphabetically: a then b
        assert [r[0] for r in rows] == ['lab', 'project', 'lab', 'project']
        assert rows[0][1] == 'lab/a'
        assert rows[2][1] == 'lab/b'

    def test_lab_entry_carries_its_full_record_list(self):
        r1 = _rec(hostname='h1', lab_name='lab/x', path='/p1.zst')
        r2 = _rec(hostname='h2', lab_name='lab/x', path='/p2.zst')
        rows, *_ = _render(
            best={('h1', 'lab/x'): r1, ('h2', 'lab/x'): r2},
            dirs=['/tmp'], timeout=60, read_errors=[],
            focus='projects', proj_cursor=0, alert_cursor=0, show_help=False,
        )
        _, lab_name, recs = rows[0]
        assert lab_name == 'lab/x'
        assert sorted(recs, key=lambda r: r.hostname) == [r1, r2]

    def test_cursor_on_lab_entry_renders_marker_arrow(self):
        rec = _rec(hostname='h1', lab_name='lab/x', path='/p1.zst')
        _rows, _alerts, buf, _cursor = _render(
            best={('h1', 'lab/x'): rec},
            dirs=['/tmp'], timeout=60, read_errors=[],
            focus='projects', proj_cursor=0, alert_cursor=0, show_help=False,
        )
        # The "Lab: ..." line should appear with the selected-cursor marker
        # ("►") because proj_cursor=0 points at the lab entry.
        lab_lines = [l for l in buf if 'Lab: lab/x' in l]
        assert len(lab_lines) == 1
        assert '►' in lab_lines[0]


# ---------------------------------------------------------------------------
# Archive scanning: _group_archives_by_instance / _scan
# ---------------------------------------------------------------------------

_LAB = LAB
_BASE_MTIME = 1_747_400_000.0


def _populate(root: Path, n_instances=3, n_files=5) -> dict[str, list[str]]:
    """Create n_instances instances (one host each, in its own sub-directory)
    with n_files archives each, one per minute, mtimes increasing with time.
    Returns {running_lab_name: [paths oldest .. newest]}."""
    files: dict[str, list[str]] = {}
    for i in range(n_instances):
        rln = _rln(start_ts=f'2026051610000{i}')
        paths = []
        for j in range(n_files):
            eval_date = f'2026051610{j:02d}00'
            paths.append(_write_archive(
                root / f'host{i}' / _archive_name(rln, eval_date),
                hostname=f'host{i}', login='alice', running_lab_name=rln,
                eval_date=eval_date, grade=float(j),
                mtime=_BASE_MTIME + j * 60 + i))
        files[rln] = paths
    return files


class TestGroupArchivesByInstance:
    def test_empty(self):
        assert _group_archives_by_instance([]) == {}

    def test_two_instances_two_groups(self):
        rln_a, rln_b = _rln(start_ts='20260516100000'), _rln(start_ts='20260516100005')
        a = f'/d/{_archive_name(rln_a, "20260516100100")}'
        b = f'/d/{_archive_name(rln_b, "20260516100100")}'
        assert _group_archives_by_instance([a, b]) == {rln_a: [a], rln_b: [b]}

    def test_one_instance_sorted_newest_first_by_prefix_not_by_path(self):
        rln = _rln()
        # Newer archives deliberately live in directories that sort *before*
        # the older ones, so path order and date order disagree.
        older = f'/z/{_archive_name(rln, "20260516100100")}'
        middle = f'/m/{_archive_name(rln, "20260516100300")}'
        newer = f'/a/{_archive_name(rln, "20260516100500")}'
        groups = _group_archives_by_instance([middle, older, newer])
        assert groups == {rln: [newer, middle, older]}

    def test_lab_name_with_special_characters(self):
        rln = _rln(lab='em@em_EXAM_@CC-2026-03-24.py')
        old = f'/d/{_archive_name(rln, "20260516100100")}'
        new = f'/d/{_archive_name(rln, "20260516100200")}'
        assert _group_archives_by_instance([old, new]) == {rln: [new, old]}

    def test_non_matching_name_is_its_own_singleton_group(self):
        groups = _group_archives_by_instance(['/d/foo.zst', '/d/bar.zst'])
        assert groups == {'/d/foo.zst': ['/d/foo.zst'], '/d/bar.zst': ['/d/bar.zst']}

    def test_same_filename_in_two_dirs_one_group_deterministic(self):
        rln = _rln()
        name = _archive_name(rln, '20260516100100')
        g1 = _group_archives_by_instance([f'/a/{name}', f'/b/{name}'])
        g2 = _group_archives_by_instance([f'/b/{name}', f'/a/{name}'])
        assert g1 == g2
        assert list(g1) == [rln]
        assert sorted(g1[rln]) == [f'/a/{name}', f'/b/{name}']


class TestScan:
    @pytest.fixture
    def reads(self, monkeypatch):
        """Record every path handed to `_read_archive` (i.e. every decompression)."""
        calls: list[str] = []
        real = watch._read_archive

        def recording(path):
            calls.append(path)
            return real(path)

        monkeypatch.setattr(watch, '_read_archive', recording)
        return calls

    def test_only_newest_per_instance_is_decompressed(self, tmp_path, reads):
        files = _populate(tmp_path, n_instances=3, n_files=5)
        newest = {paths[-1] for paths in files.values()}

        best, errors = _scan([str(tmp_path)])

        assert errors == []
        assert set(reads) == newest and len(reads) == 3
        assert set(best) == {(f'host{i}', _LAB) for i in range(3)}
        for i, (rln, paths) in enumerate(files.items()):
            rec = best[(f'host{i}', _LAB)]
            assert rec.path == paths[-1]
            assert rec.login == 'alice'
            assert rec.grade == 4.0
            assert rec.eval_time == datetime(2026, 5, 16, 10, 4, 0)

    def test_second_scan_hits_cache(self, tmp_path, reads):
        _populate(tmp_path, n_instances=2, n_files=3)
        best1, _ = _scan([str(tmp_path)])
        reads.clear()
        best2, _ = _scan([str(tmp_path)])
        assert reads == []
        assert {k: r.path for k, r in best2.items()} == {k: r.path for k, r in best1.items()}

    def test_new_archive_replaces_previous_and_evicts_it(self, tmp_path, reads):
        files = _populate(tmp_path, n_instances=1, n_files=2)
        rln, paths = next(iter(files.items()))
        _scan([str(tmp_path)])
        reads.clear()

        newer = _write_archive(tmp_path / 'host0' / _archive_name(rln, '20260516100900'),
                               hostname='host0', login='alice', running_lab_name=rln,
                               eval_date='20260516100900', grade=9.0,
                               mtime=_BASE_MTIME + 9 * 60)
        best, errors = _scan([str(tmp_path)])

        assert errors == []
        assert reads == [newer]
        assert best[('host0', _LAB)].path == newer
        assert best[('host0', _LAB)].grade == 9.0
        assert set(watch._CACHE) == {newer}
        assert paths[-1] not in watch._CACHE

    def test_restart_on_same_host_keeps_newest_mtime(self, tmp_path):
        rln_old, rln_new = _rln(start_ts='20260516100000'), _rln(start_ts='20260516103000')
        _write_archive(tmp_path / _archive_name(rln_old, '20260516102900'),
                       hostname='h1', login='alice', running_lab_name=rln_old,
                       grade=3.0, mtime=_BASE_MTIME)
        p_new = _write_archive(tmp_path / _archive_name(rln_new, '20260516103100'),
                               hostname='h1', login='alice', running_lab_name=rln_new,
                               grade=7.0, mtime=_BASE_MTIME + 120)

        best, errors = _scan([str(tmp_path)])

        assert errors == []
        assert list(best) == [('h1', _LAB)]
        assert best[('h1', _LAB)].path == p_new
        assert best[('h1', _LAB)].grade == 7.0

    def test_corrupt_newest_falls_back_to_previous(self, tmp_path, reads):
        rln = _rln()
        good = _write_archive(tmp_path / _archive_name(rln, '20260516100100'),
                              hostname='h1', login='alice', running_lab_name=rln, grade=5.0)
        bad = tmp_path / _archive_name(rln, '20260516100200')
        bad.write_bytes(b'not a zstd archive')

        best, errors = _scan([str(tmp_path)])

        assert errors == [f"cannot read: {bad}"]
        assert reads == [str(bad), good]
        assert best[('h1', _LAB)].path == good
        assert set(watch._CACHE) == {good}

    def test_fallback_is_bounded(self, tmp_path, reads):
        """With the two newest archives unreadable, older ones are not tried."""
        rln = _rln()
        _write_archive(tmp_path / _archive_name(rln, '20260516100100'),
                       hostname='h1', login='alice', running_lab_name=rln)
        bad1 = tmp_path / _archive_name(rln, '20260516100200')
        bad2 = tmp_path / _archive_name(rln, '20260516100300')
        bad1.write_bytes(b'garbage')
        bad2.write_bytes(b'garbage')

        best, errors = _scan([str(tmp_path)])

        assert best == {}
        assert errors == [f"cannot read: {bad2}", f"cannot read: {bad1}"]
        assert reads == [str(bad2), str(bad1)]
        assert watch._CACHE == {}

    def test_cache_pruned_to_parsed_paths(self, tmp_path):
        _populate(tmp_path, n_instances=2, n_files=3)
        watch._CACHE['/stale/path.zst'] = (0.0, {})

        best, _ = _scan([str(tmp_path)])

        assert set(watch._CACHE) == {r.path for r in best.values()}
        assert len(watch._CACHE) == 2

    def test_same_instance_in_two_dirs_parsed_once(self, tmp_path, reads):
        rln = _rln()
        name = _archive_name(rln, '20260516100100')
        for d in ('a', 'b'):
            _write_archive(tmp_path / d / name, hostname='h1', login='alice',
                           running_lab_name=rln, mtime=_BASE_MTIME)

        best, errors = _scan([str(tmp_path / 'a'), str(tmp_path / 'b')])

        assert errors == []
        assert len(reads) == 1
        assert list(best) == [('h1', _LAB)]

    def test_non_matching_filename_still_parsed(self, tmp_path):
        rln = _rln()
        odd = _write_archive(tmp_path / 'renamed.zst', hostname='h1', login='alice',
                             running_lab_name=rln, grade=2.0)
        best, errors = _scan([str(tmp_path)])
        assert errors == []
        assert best[('h1', _LAB)].path == odd

    def test_missing_directory_reported(self, tmp_path):
        missing = tmp_path / 'nope'
        best, errors = _scan([str(missing)])
        assert best == {}
        assert errors == [f"directory not found: {missing}"]


    def test_two_hosts_sharing_an_instance_both_show_after_next_save(self, tmp_path, reads):
        """Same lab started the same second under the same account on two
        machines: the archives of both land in one instance group."""
        rln = _rln()
        # Interleaved history: hostA at :05, hostB at :20, every minute.
        for j, (host, sec) in enumerate([('hostA', '05'), ('hostB', '20')] * 2):
            minute = j // 2
            _write_archive(tmp_path / _archive_name(rln, f'2026051610{minute:02d}{sec}'),
                           hostname=host, login='x', running_lab_name=rln,
                           mtime=_BASE_MTIME + minute * 60 + int(sec))
        newest_b = str(tmp_path / _archive_name(rln, '20260516100120'))

        best, errors = _scan([str(tmp_path)])
        # First sight: only the newest archive of the group is decompressed.
        assert errors == [] and reads == [newest_b]
        assert set(best) == {('hostB', _LAB)}

        # hostA saves again: only that new file is decompressed, hostA appears.
        reads.clear()
        new_a = _write_archive(tmp_path / _archive_name(rln, '20260516100205'),
                               hostname='hostA', login='x', running_lab_name=rln,
                               mtime=_BASE_MTIME + 125)
        best, errors = _scan([str(tmp_path)])
        assert errors == [] and reads == [new_a]
        assert set(best) == {('hostA', _LAB), ('hostB', _LAB)}
        assert best[('hostA', _LAB)].path == new_a
        assert best[('hostB', _LAB)].path == newest_b
        assert set(watch._CACHE) == {new_a, newest_b}

        # A quiet refresh decompresses nothing and keeps both rows.
        reads.clear()
        best, _ = _scan([str(tmp_path)])
        assert reads == [] and set(best) == {('hostA', _LAB), ('hostB', _LAB)}

    def test_skipped_older_archives_are_never_decompressed_later(self, tmp_path, reads):
        files = _populate(tmp_path, n_instances=1, n_files=4)
        rln, paths = next(iter(files.items()))
        _scan([str(tmp_path)])
        reads.clear()
        # A new archive arrives; the three skipped older ones stay skipped.
        newer = _write_archive(tmp_path / 'host0' / _archive_name(rln, '20260516101000'),
                               hostname='host0', login='alice', running_lab_name=rln,
                               mtime=_BASE_MTIME + 600)
        _scan([str(tmp_path)])
        _scan([str(tmp_path)])
        assert reads == [newer]
        assert all(watch._INDEX[p] is None for p in paths[:-1])

    def test_vanished_archives_drop_their_row(self, tmp_path):
        files = _populate(tmp_path, n_instances=2, n_files=2)
        best, _ = _scan([str(tmp_path)])
        assert set(best) == {('host0', _LAB), ('host1', _LAB)}
        for path in next(iter(files.values())):
            os.unlink(path)

        best, errors = _scan([str(tmp_path)])

        assert errors == []
        assert set(best) == {('host1', _LAB)}
        assert set(watch._INDEX) == set(files[_rln(start_ts='20260516100001')])
        assert set(watch._CACHE) == {best[('host1', _LAB)].path}

    def test_unreadable_new_archive_is_retried(self, tmp_path, reads):
        files = _populate(tmp_path, n_instances=1, n_files=1)
        rln, (first,) = next(iter(files.items()))
        _scan([str(tmp_path)])
        reads.clear()
        bad = tmp_path / 'host0' / _archive_name(rln, '20260516100500')
        bad.write_bytes(b'still being written')

        best, errors = _scan([str(tmp_path)])
        assert errors == [f"cannot read: {bad}"]
        assert best[('host0', _LAB)].path == first
        assert str(bad) not in watch._INDEX

        # Once complete, it is picked up.
        _write_archive(bad, hostname='host0', login='alice', running_lab_name=rln,
                       grade=5.0, mtime=_BASE_MTIME + 300)
        best, errors = _scan([str(tmp_path)])
        assert errors == []
        assert best[('host0', _LAB)].path == str(bad)
        assert reads == [str(bad), str(bad)]


# ---------------------------------------------------------------------------
# Hostname filter: _compile_host_filter and the -H/--hostname-filter option
# ---------------------------------------------------------------------------

class TestCompileHostFilter:
    def test_empty_means_show_all(self):
        assert watch._compile_host_filter('') == ('', None)

    def test_valid_pattern(self):
        pattern, regex = watch._compile_host_filter('^pc-1[0-9]$')
        assert pattern == '^pc-1[0-9]$'
        assert regex.search('pc-12') and not regex.search('pc-2')

    def test_invalid_pattern_raises(self):
        with pytest.raises(re.error):
            watch._compile_host_filter('pc-(')


def _row_hostnames(out: str) -> list[str]:
    """Hostnames of the project rows printed by the dashboard."""
    return [m.group(1) for m in
            (re.match(r'^(?: ► |   )(host\d+)\s', line) for line in out.splitlines())
            if m]


class TestActionWatchHostnameFilter:
    @pytest.fixture
    def run_watch(self, tmp_path, monkeypatch, capsys):
        """Run action_watch non-interactively for a single refresh (the sleep
        between refreshes raises KeyboardInterrupt) and return its stdout."""
        from SRE import params
        _populate(tmp_path, n_instances=2, n_files=1)

        def interrupt(_seconds):
            raise KeyboardInterrupt
        monkeypatch.setattr(watch.time, 'sleep', interrupt)
        monkeypatch.setattr(watch.sys, 'stdin', types.SimpleNamespace(isatty=lambda: False))

        def run(hostname_filter: str) -> str:
            args = params.SRE.args
            args.dirs = [str(tmp_path)]
            args.timeout = 90
            args.interval = 1
            args.hostname_filter = hostname_filter
            args.starting_time = ''
            watch.action_watch()
            return capsys.readouterr().out
        return run

    def test_option_sets_filter_and_hides_other_hosts(self, run_watch):
        out = run_watch('^host1$')
        assert watch._host_filter_pattern == '^host1$'
        assert watch._host_filter_re.pattern == '^host1$'
        assert 'filter:/^host1$/' in out
        assert _row_hostnames(out) == ['host1']
        assert '1 project(s) hidden' in out

    def test_no_option_shows_all(self, run_watch):
        out = run_watch('')
        assert watch._host_filter_re is None
        assert 'filter:' not in out
        assert _row_hostnames(out) == ['host0', 'host1']

    def test_invalid_regexp_exits_with_message(self, run_watch, capsys):
        with pytest.raises(SystemExit) as exc:
            run_watch('host(')
        assert exc.value.code == 1
        assert "invalid hostname filter 'host('" in capsys.readouterr().err
        assert watch._host_filter_re is None


# ---------------------------------------------------------------------------
# Starting time: label, filtering, -S option, prompts
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 9, 10, 16, 30, 0)


class TestStartingTimeLabel:
    def test_same_day_shows_time_only(self):
        assert watch._starting_time_label(datetime(2026, 9, 10, 15, 1), _NOW) == '15:01'

    def test_seconds_kept_when_non_zero(self):
        assert watch._starting_time_label(datetime(2026, 9, 10, 15, 1, 30), _NOW) == '15:01:30'

    def test_other_day_shows_date(self):
        assert watch._starting_time_label(datetime(2026, 9, 9, 15, 1), _NOW) == '2026-09-09 15:01'


class TestFilterBestStartingTime:
    @staticmethod
    def _best() -> dict:
        old = _rec(hostname='h-old', lab_name='lab/x', path='/old.zst')
        new = _rec(hostname='h-new', lab_name='lab/x', path='/new.zst')
        old.file_mtime = datetime(2026, 9, 10, 14, 0).timestamp()
        new.file_mtime = datetime(2026, 9, 10, 15, 30).timestamp()
        return {('h-old', 'lab/x'): old, ('h-new', 'lab/x'): new}

    def test_no_limit_keeps_all(self):
        assert set(watch._filter_best(self._best())) == {('h-old', 'lab/x'), ('h-new', 'lab/x')}

    def test_limit_hides_projects_updated_before_it(self):
        watch._starting_time = datetime(2026, 9, 10, 15, 1)
        assert set(watch._filter_best(self._best())) == {('h-new', 'lab/x')}

    def test_limit_is_inclusive(self):
        watch._starting_time = datetime(2026, 9, 10, 15, 30)
        assert set(watch._filter_best(self._best())) == {('h-new', 'lab/x')}

    def test_render_shows_since_hidden_count_and_no_alert_for_hidden(self):
        watch._starting_time = datetime(2026, 9, 10, 15, 1)
        rows, alerts, buf, _ = _render(
            best=self._best(), dirs=['/tmp'], timeout=1, read_errors=[],
            focus='projects', proj_cursor=0, alert_cursor=0, show_help=False)
        assert 'since:' in buf[0]
        assert [r[1].hostname for r in rows if r[0] == 'project'] == ['h-new']
        assert '1 project(s) hidden' in '\n'.join(buf)
        assert all('h-old' not in msg for _, msg in alerts)


class TestActionWatchStartingTime:
    @pytest.fixture
    def run_watch(self, tmp_path, monkeypatch, capsys):
        """Two projects whose archives arrived today at 14:00 (host0) and
        15:30 (host1); run action_watch for a single refresh."""
        from SRE import params
        today = datetime.now().date()
        for i, (hour, minute) in enumerate([(14, 0), (15, 30)]):
            rln = _rln(start_ts=f'2026051610000{i}')
            _write_archive(tmp_path / f'host{i}' / _archive_name(rln, '20260516100000'),
                           hostname=f'host{i}', login='alice', running_lab_name=rln,
                           mtime=datetime(today.year, today.month, today.day, hour, minute).timestamp())

        def interrupt(_seconds):
            raise KeyboardInterrupt
        monkeypatch.setattr(watch.time, 'sleep', interrupt)
        monkeypatch.setattr(watch.sys, 'stdin', types.SimpleNamespace(isatty=lambda: False))

        def run(starting_time: str) -> str:
            args = params.SRE.args
            args.dirs = [str(tmp_path)]
            args.timeout = 90
            args.interval = 1
            args.hostname_filter = ''
            args.starting_time = starting_time
            watch.action_watch()
            return capsys.readouterr().out
        return run

    def test_option_hides_projects_updated_before(self, run_watch):
        out = run_watch('15:01')
        today = datetime.now().date()
        assert watch._starting_time == datetime(today.year, today.month, today.day, 15, 1)
        assert 'since:15:01' in out
        assert _row_hostnames(out) == ['host1']
        assert '1 project(s) hidden' in out

    def test_no_option_keeps_all(self, run_watch):
        out = run_watch('')
        assert watch._starting_time is None
        assert 'since:' not in out
        assert _row_hostnames(out) == ['host0', 'host1']

    def test_invalid_value_exits_with_message(self, run_watch, capsys):
        with pytest.raises(SystemExit) as exc:
            run_watch('15h01')
        assert exc.value.code == 1
        assert "invalid starting time '15h01'" in capsys.readouterr().err
        assert watch._starting_time is None


class TestPromptValue:
    @pytest.fixture(autouse=True)
    def no_terminal(self, monkeypatch):
        """Stub the terminal handling so the prompts run under pytest."""
        monkeypatch.setattr(watch.termios, 'tcsetattr', lambda *a: None)
        monkeypatch.setattr(watch.tty, 'setcbreak', lambda *a: None)
        monkeypatch.setattr(watch.readline, 'set_pre_input_hook', lambda *a: None)
        monkeypatch.setattr(watch.sys, 'stdin', types.SimpleNamespace(fileno=lambda: 0))
        monkeypatch.setattr(watch.select, 'select', lambda *a: ([], [], []))

    @staticmethod
    def _typed(monkeypatch, text):
        monkeypatch.setattr('builtins.input', lambda _prompt='': text)

    def test_returns_parsed_value(self, monkeypatch):
        self._typed(monkeypatch, ' 42 ')
        assert watch._prompt_value(None, "Title", ["help"], 'cur', "Value", int) == 42

    def test_empty_input_is_passed_to_parse(self, monkeypatch):
        self._typed(monkeypatch, '')
        assert watch._prompt_value(None, "Title", [], '', "Value", lambda raw: ('set', raw)) == ('set', '')

    def test_parse_error_returns_none_and_shows_message(self, monkeypatch, capsys):
        self._typed(monkeypatch, 'x')
        assert watch._prompt_value(None, "Title", [], '', "Value", int) is None
        assert 'Invalid value' in capsys.readouterr().out

    def test_cancel_returns_none(self, monkeypatch):
        def interrupt(_prompt=''):
            raise KeyboardInterrupt
        monkeypatch.setattr('builtins.input', interrupt)
        assert watch._prompt_value(None, "Title", [], '', "Value", int) is None

    def test_regexp_prompt(self, monkeypatch):
        self._typed(monkeypatch, '^pc')
        pattern, regex = watch._prompt_regexp(None)
        assert pattern == '^pc' and regex.search('pc-1')
        self._typed(monkeypatch, 'pc(')
        assert watch._prompt_regexp(None) is None

    def test_starting_time_prompt(self, monkeypatch):
        self._typed(monkeypatch, '15:01')
        (dt,) = watch._prompt_starting_time(None)
        assert (dt.date(), dt.hour, dt.minute) == (datetime.now().date(), 15, 1)
        self._typed(monkeypatch, '')
        assert watch._prompt_starting_time(None) == (None,)
        self._typed(monkeypatch, '15h01')
        assert watch._prompt_starting_time(None) is None
