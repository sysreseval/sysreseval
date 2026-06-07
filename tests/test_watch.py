"""Tests for the `sre watch` interactive dashboard.

Covers:
- `_aggregate_grade_lists`: per-grade-element aggregation across users
  (numeric vs letter mode, label resolution, distribution formatting/ordering,
  uneven element counts, missing grades).
- `_render`: tagged-union `selectable_rows` output now includes lab title
  entries alongside project entries, in the correct interleaved order.
"""
from datetime import datetime

import pytest

from SRE.command import watch
from SRE.command.watch import (
    Record,
    _aggregate_grade_lists,
    _aggregate_part_subtotals,
    _render,
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
    yield
    watch._DISMISSED_PROJECTS.clear()
    watch._DISMISSED_HOSTS.clear()
    watch._DISMISSED_ALERTS.clear()
    watch._host_filter_pattern = ''
    watch._host_filter_re = None


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
