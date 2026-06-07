"""Tests for the auto_eval_count log file and Grade0.auto_eval_count attribute.

Covers:
- `_read_auto_eval_count` and `_append_auto_eval_timestamp` helpers in
  `src/SRE/command/eval.py`
- the incrementation invariant: each append grows the read count by one
- the round-trip through `params.auto_eval_log_filename`
- accuracy of `Grade0.auto_eval_count`: visible inside `grade()`, unaffected by
  `reset_before_grade`, properly initialised by the constructor
"""
import datetime
from dataclasses import dataclass
from pathlib import Path

import pytest

from SRE import params
from SRE.command.eval import _append_auto_eval_timestamp, _read_auto_eval_count
from SRE.lib_sre import Data0, Grade0, NetScheme0


_RUNNING_LAB_NAME = '20260101000000@@@auto_eval_count_lab@@@user'


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def log_path(tmp_path):
    return tmp_path / params.auto_eval_log_name


def _make_grade():
    """Construct a Grade0 instance with a minimal NetScheme stub. We can't use
    a real NetScheme0 here because it requires Kathara; but Grade0.__init__
    only stores net_scheme as an attribute, so a placeholder is enough for the
    attribute tests."""
    class _StubNetScheme:
        running_lab_name = _RUNNING_LAB_NAME
    return Grade0(net_scheme=_StubNetScheme())


# ---------------------------------------------------------------------------
# _read_auto_eval_count
# ---------------------------------------------------------------------------

class TestReadAutoEvalCount:
    def test_missing_file_returns_zero(self, log_path):
        assert not log_path.exists()
        assert _read_auto_eval_count(log_path) == 0

    def test_empty_file_returns_zero(self, log_path):
        log_path.write_text('')
        assert _read_auto_eval_count(log_path) == 0

    def test_single_line(self, log_path):
        log_path.write_text('2026-05-12T10:00:00\n')
        assert _read_auto_eval_count(log_path) == 1

    def test_multiple_lines(self, log_path):
        log_path.write_text('2026-05-12T10:00:00\n2026-05-12T10:01:00\n2026-05-12T10:02:00\n')
        assert _read_auto_eval_count(log_path) == 3

    def test_trailing_newline_irrelevant(self, log_path):
        """A file ending without '\\n' still counts the final line."""
        log_path.write_text('2026-05-12T10:00:00\n2026-05-12T10:01:00')
        assert _read_auto_eval_count(log_path) == 2


# ---------------------------------------------------------------------------
# _append_auto_eval_timestamp
# ---------------------------------------------------------------------------

class TestAppendAutoEvalTimestamp:
    def test_creates_file_with_one_line(self, log_path):
        assert not log_path.exists()
        _append_auto_eval_timestamp(log_path)
        assert log_path.exists()
        lines = log_path.read_text().splitlines()
        assert len(lines) == 1

    def test_line_is_iso_timestamp(self, log_path):
        before = datetime.datetime.now()
        _append_auto_eval_timestamp(log_path)
        after = datetime.datetime.now()
        line = log_path.read_text().splitlines()[0]
        parsed = datetime.datetime.fromisoformat(line)
        assert before <= parsed <= after

    def test_line_ends_with_newline(self, log_path):
        _append_auto_eval_timestamp(log_path)
        text = log_path.read_text()
        assert text.endswith('\n')

    def test_appends_without_overwriting(self, log_path):
        log_path.write_text('previous-line\n')
        _append_auto_eval_timestamp(log_path)
        lines = log_path.read_text().splitlines()
        assert lines[0] == 'previous-line'
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# Incrementation invariant: append + read together
# ---------------------------------------------------------------------------

class TestIncrementation:
    def test_each_append_grows_count_by_one(self, log_path):
        """The contract: after N appends, _read_auto_eval_count == N."""
        assert _read_auto_eval_count(log_path) == 0
        for expected in range(1, 6):
            _append_auto_eval_timestamp(log_path)
            assert _read_auto_eval_count(log_path) == expected

    def test_count_before_append_is_previous_total(self, log_path):
        """Models the eval.py contract: ``auto_eval_count`` captured *before*
        the append represents the number of *previous* auto-evaluations."""
        previous_counts = []
        for _ in range(4):
            previous_counts.append(_read_auto_eval_count(log_path))
            _append_auto_eval_timestamp(log_path)
        assert previous_counts == [0, 1, 2, 3]

    def test_path_resolution_via_params_helper(self, tmp_pub_dir):
        """End-to-end: `params.auto_eval_log_filename(running_lab_name)`
        resolves under the patched sre_projects_dir, and the helpers work
        against that resolved path. Increments must survive across two
        independent read/append cycles (a second `do_eval`)."""
        private = Path(params.private_lab_dir(_RUNNING_LAB_NAME))
        private.mkdir(parents=True, exist_ok=True)
        log_path = Path(params.auto_eval_log_filename(_RUNNING_LAB_NAME))

        # First simulated auto-eval cycle.
        assert _read_auto_eval_count(log_path) == 0
        _append_auto_eval_timestamp(log_path)

        # Second simulated auto-eval cycle, separate read.
        assert _read_auto_eval_count(log_path) == 1
        _append_auto_eval_timestamp(log_path)
        assert _read_auto_eval_count(log_path) == 2


# ---------------------------------------------------------------------------
# Grade0.auto_eval_count accuracy
# ---------------------------------------------------------------------------

class TestGradeAutoEvalCount:
    def test_default_is_zero(self):
        g = _make_grade()
        assert g.auto_eval_count == 0

    def test_assignment_survives_full_reset_pattern(self):
        """``Grade0.__init__`` already calls ``full_reset()``; subsequent
        manual ``full_reset()`` calls (used internally before re-runs) must
        not reset auto_eval_count, since the live evaluation flow sets it
        after construction and expects it to stick."""
        g = _make_grade()
        g.auto_eval_count = 7
        g.full_reset()
        assert g.auto_eval_count == 7

    def test_assignment_survives_reset_before_grade(self):
        """``reset_before_grade`` runs once per step inside ``run_tests``
        and must not clear auto_eval_count."""
        g = _make_grade()
        g.auto_eval_count = 3
        g.reset_before_grade()
        assert g.auto_eval_count == 3

    def test_value_visible_inside_grade(self, tmp_path):
        """``grade()`` must see whatever count the caller assigned. Models
        the eval.py contract where eval.py sets ``grade.auto_eval_count``
        before calling ``run_tests`` which calls ``grade``."""
        @dataclass(slots=True)
        class _Data(Data0):
            value: int = 0

        class _NetScheme(NetScheme0):
            _machine_specs = {'router': {}}
            _network_specs = {'lan': {}}
            _topology = {'lan': ['router']}

            def __init__(self, data, running_lab_name):
                super().__init__(data=data, running_lab_name=running_lab_name)

        seen = []

        class _Grade(Grade0):
            def grade(_self):
                super().grade()
                seen.append(_self.auto_eval_count)
                _self.add_grade_element(
                    title='count', grade=_self.auto_eval_count, max_grade=100)

        data = _Data(value=42)
        ns = _NetScheme(data=data, running_lab_name=_RUNNING_LAB_NAME)
        g = _Grade(net_scheme=ns)
        g.auto_eval_count = 9
        g.reset_before_grade()
        g.grade()
        g.compute_total()

        assert seen == [9]
        assert g._total_grade_exo_eval == 9
        assert g._grade_list[0].grade == 9

    def test_simulated_consecutive_evals(self, tmp_pub_dir):
        """Full pattern: log-read → set on Grade → grade() sees correct
        value → log-append. Repeated for a sequence of auto-evals to
        confirm each cycle sees the incrementing 'previous count'."""
        private = Path(params.private_lab_dir(_RUNNING_LAB_NAME))
        private.mkdir(parents=True, exist_ok=True)
        log_path = Path(params.auto_eval_log_filename(_RUNNING_LAB_NAME))

        observed = []
        for _ in range(4):
            count = _read_auto_eval_count(log_path)
            g = _make_grade()
            g.auto_eval_count = count
            observed.append(g.auto_eval_count)
            _append_auto_eval_timestamp(log_path)

        assert observed == [0, 1, 2, 3]
