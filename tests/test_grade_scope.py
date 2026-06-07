"""Tests for GradeElement.scope and the per-scope totals in Grade0."""
import json
from unittest.mock import MagicMock

import pytest

from SRE import params
from SRE.common import GradeElement
from SRE.lib_sre import Grade0


SELF = params.SELF_EVAL_SCOPE
EXO = params.EXO_EVAL_SCOPE
BOTH = params.BOTH_EVAL_SCOPE


class ConcreteGrade(Grade0):
    def grade(self):
        super().grade()


def make_grade():
    ns = MagicMock()
    ns.running_lab_name = '20260101000000@@@test@@@user'
    return ConcreteGrade(ns)


# ---------------------------------------------------------------------------
# Scope constants
# ---------------------------------------------------------------------------

class TestScopeConstants:
    def test_values(self):
        assert params.SELF_EVAL_SCOPE == 1
        assert params.EXO_EVAL_SCOPE == 2
        assert params.BOTH_EVAL_SCOPE == 3

    def test_both_is_union(self):
        assert params.BOTH_EVAL_SCOPE == params.SELF_EVAL_SCOPE | params.EXO_EVAL_SCOPE

    def test_grade_scopes_tuple(self):
        assert set(params.grade_scopes) == {SELF, EXO, BOTH}


# ---------------------------------------------------------------------------
# GradeElement serialisation with scope
# ---------------------------------------------------------------------------

class TestGradeElementScope:
    def test_default_scope_is_both(self):
        e = GradeElement(title='t', max_grade=1, grade=1)
        assert e.scope == BOTH

    def test_to_dict_includes_scope(self):
        e = GradeElement(title='t', max_grade=1, grade=1, scope=SELF)
        d = e.to_dict()
        assert d['scope'] == SELF

    def test_from_dict_preserves_scope(self):
        d = {'title': 't', 'max_grade': 1, 'grade': 1, 'scope': EXO,
             'grade_letter': None, 'description': ''}
        e = GradeElement.from_dict(d)
        assert e.scope == EXO

    def test_legacy_dict_without_scope_defaults_to_both(self):
        # archives written before this change have no scope key
        d = {'title': 't', 'max_grade': 1, 'grade': 1,
             'grade_letter': None, 'description': ''}
        e = GradeElement.from_dict(d)
        assert e.scope == BOTH

    def test_round_trip_pack_unpack(self):
        e = GradeElement(title='t', max_grade=2, grade=1, scope=EXO)
        e2 = GradeElement.unpack(e.pack())
        assert e2.scope == EXO

    def test_round_trip_json(self):
        e = GradeElement(title='t', max_grade=2, grade=1, scope=SELF)
        e2 = GradeElement.from_json(e.to_json())
        assert e2.scope == SELF

    def test_to_grade_letter_preserves_scope(self):
        e = GradeElement(title='t', max_grade=5, grade=3, scope=SELF)
        letter = e.to_grade_letter()
        assert letter.scope == SELF
        assert letter.grade_letter == 'MEH'


# ---------------------------------------------------------------------------
# add_grade_element scope parameter
# ---------------------------------------------------------------------------

class TestAddGradeElementScope:
    def test_default_scope_is_both(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t', max_grade=1, grade=1)
        assert g.get_grade_list()[0].scope == BOTH

    def test_explicit_self_eval_scope(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t', max_grade=1, grade=1, scope=SELF)
        assert g.get_grade_list()[0].scope == SELF

    def test_explicit_exo_eval_scope(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t', max_grade=1, grade=1, scope=EXO)
        assert g.get_grade_list()[0].scope == EXO

    @pytest.mark.parametrize("bad_scope", [0, 4, -1, 5, "both"])
    def test_invalid_scope_raises(self, bad_scope):
        g = make_grade()
        g.grade()
        with pytest.raises(ValueError):
            g.add_grade_element('t', max_grade=1, grade=1, scope=bad_scope)


# ---------------------------------------------------------------------------
# compute_total / mark_self_eval / mark_exo_eval
# ---------------------------------------------------------------------------

class TestPerScopeTotals:
    def _make_lab_with_all_three_scopes(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('A', max_grade=2, grade=2, scope=SELF)
        g.add_grade_element('B', max_grade=4, grade=3, scope=EXO)
        g.add_grade_element('C', max_grade=10, grade=5, scope=BOTH)
        g.compute_total()
        return g

    def test_self_eval_totals_include_self_and_both(self):
        g = self._make_lab_with_all_three_scopes()
        # SELF=2/2 + BOTH=5/10
        assert g._total_grade_self_eval == 7
        assert g._total_max_self_eval == 12

    def test_exo_eval_totals_include_exo_and_both(self):
        g = self._make_lab_with_all_three_scopes()
        # EXO=3/4 + BOTH=5/10
        assert g._total_grade_exo_eval == 8
        assert g._total_max_exo_eval == 14

    def test_self_eval_excludes_exo_only(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('only_exo', max_grade=5, grade=5, scope=EXO)
        g.compute_total()
        assert g._total_grade_self_eval == 0
        assert g._total_max_self_eval == 0

    def test_exo_eval_excludes_self_only(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('only_self', max_grade=5, grade=5, scope=SELF)
        g.compute_total()
        assert g._total_grade_exo_eval == 0
        assert g._total_max_exo_eval == 0

    def test_mark_self_eval_returns_none_when_total_max_is_zero(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('exo_only', max_grade=5, grade=5, scope=EXO)
        g.compute_total()
        assert g.mark_self_eval() is None

    def test_mark_exo_eval_returns_none_when_total_max_is_zero(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('self_only', max_grade=5, grade=5, scope=SELF)
        g.compute_total()
        assert g.mark_exo_eval() is None

    def test_mark_scaled_to_maximum_mark(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t', max_grade=10, grade=5, scope=BOTH)
        g._maximum_mark = 20
        g.compute_total()
        # 5/10 of 20 = 10
        assert g.mark_self_eval() == 10
        assert g.mark_exo_eval() == 10

    def test_letter_mode_marks(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t', max_grade=10, grade=9, scope=BOTH)
        g._use_numerical_marks = False
        g.compute_total()
        # 9/10 >= 18/20 → A+
        assert g.mark_self_eval() == 'A+'
        assert g.mark_exo_eval() == 'A+'

    def test_compute_total_called_twice_resets_to_correct_values(self):
        g = self._make_lab_with_all_three_scopes()
        g.compute_total()  # second call must not double-count
        assert g._total_grade_self_eval == 7
        assert g._total_grade_exo_eval == 8


# ---------------------------------------------------------------------------
# outline/sheet legacy archive compatibility
# ---------------------------------------------------------------------------

class TestLegacyArchiveFallback:
    """An archive written before this change has no scope, no *_exo_eval keys.
    The reader code in outline.py / sheet.py must fall back to legacy keys."""

    def test_legacy_archive_dict_falls_back(self):
        legacy = {
            'total_grade': 12,
            'total_max': 15,
            'mark': 16.0,
            'grade_list': [
                {'title': 't', 'max_grade': 1, 'grade': 1,
                 'grade_letter': None, 'description': ''},
            ],
        }
        # mirror the fallback chain used by outline.py / sheet.py
        total = legacy.get('total_grade_exo_eval', legacy.get('total_grade')) or 0
        max_ = legacy.get('total_max_exo_eval', legacy.get('total_max')) or 0
        mark = legacy.get('mark_exo_eval', legacy.get('mark'))
        gl = [e for e in legacy['grade_list']
              if e.get('scope', BOTH) & EXO]
        assert total == 12
        assert max_ == 15
        assert mark == 16.0
        assert len(gl) == 1  # legacy element with no scope → treated as BOTH
