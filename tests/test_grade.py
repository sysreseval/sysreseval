"""Tests for Grade0: grading logic, question registration, test registration."""
import hashlib
import json
import shlex
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from SRE import params
from SRE.lib_sre import Grade0, ErrorCategory
from SRE.common import GradeElement, GradePart, _tt_hash_str


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_net_scheme():
    ns = MagicMock()
    ns.running_lab_name = '20260101000000@@@test@@@user'
    return ns


class ConcreteGrade(Grade0):
    def grade(self):
        super().grade()


def make_grade():
    return ConcreteGrade(make_net_scheme())


# ---------------------------------------------------------------------------
# add_grade_element / set_grade
# ---------------------------------------------------------------------------

class TestGradeElements:
    def test_add_element_appears_in_list(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('task1', max_grade=10, grade=5)
        assert len(g.get_grade_list()) == 1
        assert g.get_grade_list()[0].title == 'task1'
        assert g.get_grade_list()[0].grade == 5

    def test_multiple_elements(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t1', max_grade=5, grade=3)
        g.add_grade_element('t2', max_grade=10, grade=10)
        assert len(g.get_grade_list()) == 2

    def test_set_grade_updates_value(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t', max_grade=4, grade=0)
        g.set_grade('t', 3)
        assert g.get_grade_list()[0].grade == 3

    def test_grade_list_empty_before_grade(self):
        g = make_grade()
        g.grade()
        assert g.get_grade_list() == []

    def test_grade_list_reset_on_new_grade_call(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t', max_grade=4, grade=2)
        g.grade()   # reset
        assert g.get_grade_list() == []


# ---------------------------------------------------------------------------
# GradeElement letter conversion
# ---------------------------------------------------------------------------

class TestGradeElementLetters:
    def test_ok_when_full_score(self):
        e = GradeElement(title='t', max_grade=5, grade=5)
        assert e.to_grade_letter().grade_letter == 'OK'

    def test_meh_when_partial_score(self):
        e = GradeElement(title='t', max_grade=5, grade=3)
        assert e.to_grade_letter().grade_letter == 'MEH'

    def test_fail_when_zero(self):
        e = GradeElement(title='t', max_grade=5, grade=0)
        assert e.to_grade_letter().grade_letter == 'FAIL'

    def test_fail_when_none(self):
        e = GradeElement(title='t', max_grade=5, grade=None)
        assert e.to_grade_letter().grade_letter == 'FAIL'

    def test_letter_hides_numeric_grade(self):
        e = GradeElement(title='t', max_grade=5, grade=5)
        letter = e.to_grade_letter()
        assert letter.grade is None
        assert letter.max_grade is None
        assert letter.grade_letter == 'OK'


# ---------------------------------------------------------------------------
# question_text
# ---------------------------------------------------------------------------

class TestQuestionText:
    def test_returns_default_when_no_answer(self):
        g = make_grade()
        g.grade()
        answer = g.question_text(title='What is IP?', default_answer='unknown')
        assert answer == 'unknown'

    def test_returns_stored_answer(self):
        g = make_grade()
        h = hashlib.sha256(_tt_hash_str('What is IP?').encode()).hexdigest()
        g._answers[h] = 'a protocol'
        g.grade()
        answer = g.question_text(title='What is IP?', default_answer='unknown')
        assert answer == 'a protocol'

    def test_question_registered(self):
        g = make_grade()
        g.grade()
        g.question_text(title='Q1')
        assert len(g.get_questions_ordered()) == 1
        assert g.get_questions_ordered()[0].title.resolve('en') == 'Q1'

    def test_explicit_hash(self):
        g = make_grade()
        g._answers['myhash'] = 'stored'
        g.grade()
        answer = g.question_text(title='Anything', hash='myhash')
        assert answer == 'stored'


# ---------------------------------------------------------------------------
# question_dummy
# ---------------------------------------------------------------------------

class TestQuestionDummy:
    def test_registered_and_ordered(self):
        g = make_grade()
        g.grade()
        g.question_dummy(title='Info', description='Read carefully')
        questions = g.get_questions_ordered()
        assert len(questions) == 1
        assert questions[0].title.resolve('en') == 'Info'


# ---------------------------------------------------------------------------
# question_form
# ---------------------------------------------------------------------------

class TestQuestionForm:
    def test_returns_empty_dict_when_no_answer(self):
        g = make_grade()
        g.grade()
        result = g.question_form(
            title='Config',
            description='IP: @@{ip_addr:\\d+\\.\\d+\\.\\d+\\.\\d+}@@'
        )
        assert result == {}

    def test_returns_stored_answer(self):
        desc = 'IP: @@{ip_addr:\\d+}@@'
        h = hashlib.sha256(
            (_tt_hash_str('Config') + '--' + _tt_hash_str(desc)).encode()
        ).hexdigest()
        g = make_grade()
        g._answers[h] = json.dumps({'ip_addr': '10.0.0.1'})
        g.grade()
        result = g.question_form(title='Config', description=desc)
        assert result == {'ip_addr': '10.0.0.1'}

    def test_fields_extracted_from_description(self):
        g = make_grade()
        g.grade()
        g.question_form(
            title='F',
            description='A: @@{field1:.*}@@ B: @@{field2:\\d+}@@'
        )
        q = g.get_questions_ordered()[0]
        names = [f['name'] for f in q.fields]
        assert names == ['field1', 'field2']

    def test_translatedtext_description_extracts_fields(self):
        # A tr()-wrapped description is a TranslatedText; the @@{...}@@ markers
        # are language-independent and must still be extracted (was a TypeError).
        from SRE.common import TranslatedText
        g = make_grade()
        g.grade()
        desc = TranslatedText({'fr': 'IP: @@{ip:\\d+}@@', 'en': 'IP: @@{ip:\\d+}@@'})
        g.question_form(title='Config', description=desc)
        q = g.get_questions_ordered()[0]
        assert [f['name'] for f in q.fields] == ['ip']


# ---------------------------------------------------------------------------
# Question ordering
# ---------------------------------------------------------------------------

class TestQuestionOrdering:
    def test_explicit_order_respected(self):
        g = make_grade()
        g.grade()
        g.question_text(title='Q1', order=200)
        g.question_text(title='Q2', order=100)
        titles = [q.title.resolve('en') for q in g.get_questions_ordered()]
        assert titles == ['Q2', 'Q1']

    def test_auto_order_increments(self):
        g = make_grade()
        g.grade()
        g.question_text(title='First')
        g.question_text(title='Second')
        titles = [q.title.resolve('en') for q in g.get_questions_ordered()]
        assert titles.index('First') < titles.index('Second')


# ---------------------------------------------------------------------------
# test() registration
# ---------------------------------------------------------------------------

class TestTestRegistration:
    def test_returns_default_value_and_code(self):
        g = make_grade()
        g.grade()
        result, code = g.test('m1', 'ip a')
        assert result == ''
        assert code == 0

    def test_idempotent_returns_same_value(self):
        g = make_grade()
        g.grade()
        g.test('m1', 'ip a')
        r2, c2 = g.test('m1', 'ip a')
        assert r2 == ''
        assert c2 == 0

    def test_max_step_tracking(self):
        g = make_grade()
        g.grade()
        g.test('m1', 'cmd1', step=1)
        g.test('m1', 'cmd2', step=3)
        assert g.max_step == 3

    def test_different_machines_stored_separately(self):
        g = make_grade()
        g.grade()
        g.test('m1', 'ip a')
        g.test('m2', 'ip a')
        # Both (m1,1) and (m2,1) keys must exist
        assert ('m1', 1) in g._tests
        assert ('m2', 1) in g._tests

    def test_custom_default_value(self):
        g = make_grade()
        g.grade()
        result, code = g.test('m1', 'hostname', default_value='myhost', default_code=0)
        assert result == 'myhost'


# ---------------------------------------------------------------------------
# test_host() — registration phase
# ---------------------------------------------------------------------------

class TestTestHostRegistration:
    def test_returns_default_value_and_code(self):
        g = make_grade()
        g.grade()
        result, code = g.test_host('uname -r')
        assert result == ''
        assert code == 0

    def test_idempotent_returns_same_default(self):
        g = make_grade()
        g.grade()
        g.test_host('uname -r')
        r2, c2 = g.test_host('uname -r')
        assert r2 == ''
        assert c2 == 0

    def test_custom_default_value_and_code(self):
        g = make_grade()
        g.grade()
        result, code = g.test_host('uname -r', default_value='5.15', default_code=1)
        assert result == '5.15'
        assert code == 1

    def test_max_step_updated(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd1', step=1)
        g.test_host('cmd2', step=3)
        assert g.max_step == 3

    def test_stored_in_host_tests(self):
        g = make_grade()
        g.grade()
        g.test_host('uname -r', step=2)
        assert 2 in g._host_tests
        assert ('uname -r', 20) in g._host_tests[2]

    def test_different_steps_stored_separately(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd', step=1)
        g.test_host('cmd', step=2)
        assert 1 in g._host_tests
        assert 2 in g._host_tests

    def test_different_commands_stored_separately(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd1', step=1)
        g.test_host('cmd2', step=1)
        assert ('cmd1', 20) in g._host_tests[1]
        assert ('cmd2', 20) in g._host_tests[1]

    def test_allow_error_registered(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd', step=1, allow_error=True)
        assert g._allow_errors_in_host_tests.get((1, 'cmd', 20)) is True

    def test_allow_error_not_set_by_default(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd', step=1)
        assert (1, 'cmd', 20) not in g._allow_errors_in_host_tests

    def test_custom_timeout_stored(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd', timeout=5)
        assert (('cmd', 5)) in g._host_tests[1]

    def test_does_not_pollute_machine_tests(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd')
        assert len(g._tests) == 0

    def test_full_reset_clears_host_tests(self):
        g = make_grade()
        g.grade()
        g.test_host('cmd')
        g.full_reset()
        assert g._host_tests == {}
        assert g._allow_errors_in_host_tests == {}


# ---------------------------------------------------------------------------
# test_host() — execution phase (run_tests)
# ---------------------------------------------------------------------------

def _make_lab_no_machines():
    """Mock Kathara lab with no machines (so machine tests are skipped)."""
    lab = MagicMock()
    lab.machines = {}
    return lab


class GradeWithHostCmd(Grade0):
    """Concrete grade that registers one host command in grade()."""
    def __init__(self, ns, command, step=1, allow_error=False):
        super().__init__(ns)
        self._cmd = command
        self._step = step
        self._allow_error = allow_error

    def grade(self):
        super().grade()
        self.test_host(self._cmd, step=self._step, allow_error=self._allow_error)


def _run_tests_with_host(command, proc_stdout='output', proc_returncode=0,
                         timeout_exc=False, step=1, allow_error=False):
    """Helper: run run_tests() for a single host command with a mocked subprocess."""
    ns = make_net_scheme()
    ns.get_lab_from_kathara.return_value = _make_lab_no_machines()
    g = GradeWithHostCmd(ns, command, step=step, allow_error=allow_error)

    def fake_run(cmd, shell, capture_output, text, timeout, **kwargs):
        if timeout_exc:
            raise subprocess.TimeoutExpired(cmd, timeout)
        r = MagicMock()
        r.stdout = proc_stdout
        r.returncode = proc_returncode
        return r

    with patch('SRE.lib_sre.subprocess.run', side_effect=fake_run):
        g.run_tests()
    return g


class TestTestHostExecution:
    def test_result_stored_after_run(self):
        g = _run_tests_with_host('uname -r', proc_stdout='6.1.0\n')
        result, code = g._host_tests[1][('uname -r', 20)]
        assert result == '6.1.0\n'
        assert code == 0

    def test_nonzero_code_stored(self):
        g = _run_tests_with_host('false', proc_returncode=1, allow_error=True)
        _, code = g._host_tests[1][('false', 20)]
        assert code == 1

    def test_nonzero_code_adds_error_without_allow_error(self):
        g = _run_tests_with_host('false', proc_returncode=1, allow_error=False)
        assert any('false' in (e[1] if isinstance(e, (list, tuple)) else e) for e in g._errors)

    def test_nonzero_code_no_error_with_allow_error(self):
        g = _run_tests_with_host('false', proc_returncode=1, allow_error=True)
        assert not any('false' in (e[1] if isinstance(e, (list, tuple)) else e) for e in g._errors)

    def test_timeout_stores_minus_one(self):
        g = _run_tests_with_host('sleep 99', timeout_exc=True, allow_error=True)
        _, code = g._host_tests[1][('sleep 99', 20)]
        assert code == -1

    def test_timeout_result_is_empty_string(self):
        g = _run_tests_with_host('sleep 99', timeout_exc=True, allow_error=True)
        result, _ = g._host_tests[1][('sleep 99', 20)]
        assert result == ''

    def test_result_readable_via_test_host_after_run(self):
        """After run_tests(), a second grade() pass returns the real result."""
        ns = make_net_scheme()
        ns.get_lab_from_kathara.return_value = _make_lab_no_machines()
        g = GradeWithHostCmd(ns, 'uname -r')

        def fake_run(cmd, **kw):
            r = MagicMock(); r.stdout = '6.1.0'; r.returncode = 0
            return r

        with patch('SRE.lib_sre.subprocess.run', side_effect=fake_run):
            g.run_tests()

        # Simulate second pass: grade() is called again with real data
        g.reset_before_grade()
        g.grade()
        result, code = g.test_host('uname -r')
        assert result == '6.1.0'
        assert code == 0

    def test_subprocess_called_with_shell_true(self):
        ns = make_net_scheme()
        ns.get_lab_from_kathara.return_value = _make_lab_no_machines()
        g = GradeWithHostCmd(ns, 'echo hi')

        with patch('SRE.lib_sre.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='hi', returncode=0)
            g.run_tests()

        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs.get('shell') is True

    def test_host_tests_independent_of_machine_tests(self):
        """Machine _tests dict must remain empty when only host commands are used."""
        g = _run_tests_with_host('uname -r')
        assert g._tests == {}


# ---------------------------------------------------------------------------
# ErrorCategory / add_error / add_warning
# ---------------------------------------------------------------------------

class TestErrorCategory:
    def test_add_error_stores_tuple_with_error_category(self):
        g = make_grade()
        g.step = 1
        g.add_error("something broke")
        assert g._errors == [("ERROR", "something broke")]

    def test_add_error_default_category_is_error(self):
        g = make_grade()
        g.step = 1
        g.add_error("msg")
        cat, _ = g._errors[0]
        assert cat == ErrorCategory.ERROR.value

    def test_add_error_explicit_warning_category(self):
        g = make_grade()
        g.step = 1
        g.add_error("low disk", category=ErrorCategory.WARNING)
        assert g._errors == [("WARNING", "low disk")]

    def test_add_warning_stores_warning_category(self):
        g = make_grade()
        g.step = 1
        g.add_warning("low disk")
        assert g._errors == [("WARNING", "low disk")]

    def test_add_warning_not_an_error(self):
        g = make_grade()
        g.step = 1
        g.add_warning("low disk")
        cat, _ = g._errors[0]
        assert cat != ErrorCategory.ERROR.value

    def test_get_errors_returns_all_entries(self):
        g = make_grade()
        g.step = 1
        g.add_error("e1")
        g.add_warning("w1")
        g.add_error("e2")
        assert g.get_errors() == [
            ("ERROR", "e1"),
            ("WARNING", "w1"),
            ("ERROR", "e2"),
        ]

    def test_errors_persist_across_reset_before_grade(self):
        """_errors is NOT cleared by reset_before_grade(); only run_tests() clears it."""
        g = make_grade()
        g.step = 1
        g.add_error("stale error")
        g.reset_before_grade()
        assert len(g._errors) == 1

    def test_multiple_errors_and_warnings_mixed(self):
        g = make_grade()
        g.step = 1
        g.add_error("err1")
        g.add_warning("warn1")
        g.add_warning("warn2")
        g.add_error("err2")
        errors   = [e for e in g._errors if e[0] == "ERROR"]
        warnings = [e for e in g._errors if e[0] == "WARNING"]
        assert len(errors) == 2
        assert len(warnings) == 2

    # -- step filtering --

    def test_add_error_filtered_when_step_mismatch(self):
        g = make_grade()
        g.step = 1
        g.add_error("only in step 2", step=2)
        assert g._errors == []

    def test_add_error_added_when_step_matches(self):
        g = make_grade()
        g.step = 2
        g.add_error("step 2 error", step=2)
        assert g._errors == [("ERROR", "step 2 error")]

    def test_add_warning_filtered_when_step_mismatch(self):
        g = make_grade()
        g.step = 1
        g.add_warning("only in step 3", step=3)
        assert g._errors == []

    def test_add_warning_added_when_step_matches(self):
        g = make_grade()
        g.step = 3
        g.add_warning("step 3 warning", step=3)
        assert g._errors == [("WARNING", "step 3 warning")]

    def test_step_default_is_1(self):
        """Default step=1: error added when self.step==1, ignored otherwise."""
        g = make_grade()
        g.step = 2
        g.add_error("should be ignored")
        assert g._errors == []
        g.step = 1
        g.add_error("should be added")
        assert g._errors == [("ERROR", "should be added")]

    def test_errors_from_different_steps_collected(self):
        """Errors added at matching steps accumulate in order."""
        g = make_grade()
        g.step = 1
        g.add_error("step1 err")
        g.step = 2
        g.add_error("step2 err", step=2)
        assert g._errors == [("ERROR", "step1 err"), ("ERROR", "step2 err")]


# ---------------------------------------------------------------------------
# execute_commands_on_host parameter
# ---------------------------------------------------------------------------

class TestExecuteCommandsOnHost:
    """test_host() and run_tests() honour params.execute_commands_on_host."""

    def test_false_exits_on_test_host(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', False)
        g = make_grade()
        g.grade()
        with pytest.raises(SystemExit):
            g.test_host('uname -r')

    def test_shell_calls_subprocess_with_shell_true(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'shell')
        ns = make_net_scheme()
        ns.get_lab_from_kathara.return_value = _make_lab_no_machines()
        g = GradeWithHostCmd(ns, 'echo hi')

        with patch('SRE.lib_sre.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='hi', returncode=0)
            g.run_tests()

        args, kwargs = mock_run.call_args
        assert kwargs.get('shell') is True
        assert args[0] == 'echo hi'

    def test_split_calls_subprocess_with_shell_false(self, monkeypatch):
        monkeypatch.setattr(params, 'execute_commands_on_host', 'split')
        ns = make_net_scheme()
        ns.get_lab_from_kathara.return_value = _make_lab_no_machines()
        g = GradeWithHostCmd(ns, 'echo hi')

        with patch('SRE.lib_sre.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='hi', returncode=0)
            g.run_tests()

        args, kwargs = mock_run.call_args
        assert kwargs.get('shell') is False
        assert args[0] == shlex.split('echo hi')


# ---------------------------------------------------------------------------
# GradePart
# ---------------------------------------------------------------------------

class TestGradePart:
    def test_add_grade_part_returns_object_stored_in_list(self):
        g = make_grade()
        g.grade()
        part = g.add_grade_part('Part 1', 'description of part 1')
        assert isinstance(part, GradePart)
        assert g.get_grade_parts() == [part]

    def test_add_grade_part_preserves_registration_order(self):
        g = make_grade()
        g.grade()
        p1 = g.add_grade_part('one')
        p2 = g.add_grade_part('two')
        p3 = g.add_grade_part('three')
        assert g.get_grade_parts() == [p1, p2, p3]

    def test_add_grade_element_with_part_stores_title_string(self):
        g = make_grade()
        g.grade()
        part = g.add_grade_part('Part 1')
        g.add_grade_element('t1', max_grade=5, grade=3, grade_part=part)
        elem = g.get_grade_list()[0]
        assert elem.grade_part == 'Part 1'

    def test_add_grade_element_without_part_keeps_none(self):
        g = make_grade()
        g.grade()
        g.add_grade_element('t1', max_grade=5, grade=3)
        assert g.get_grade_list()[0].grade_part is None

    def test_add_grade_element_unregistered_part_writes_error(self, capsys):
        g = make_grade()
        g.grade()
        fake = GradePart(title='Not registered')
        g.add_grade_element('t1', max_grade=5, grade=3, grade_part=fake)
        err = capsys.readouterr().err
        assert 'Unregistered grade part' in err
        # Element is still recorded — we only warn, we don't drop it.
        assert g.get_grade_list()[0].grade_part == 'Not registered'

    def test_add_grade_element_rejects_non_grade_part(self):
        g = make_grade()
        g.grade()
        with pytest.raises(TypeError):
            g.add_grade_element('t1', max_grade=5, grade=3, grade_part='Part 1')

    def test_duplicate_part_title_writes_error(self, capsys):
        g = make_grade()
        g.grade()
        g.add_grade_part('dup')
        g.add_grade_part('dup')
        err = capsys.readouterr().err
        assert 'Duplicate grade part title' in err

    def test_grade_parts_reset_on_new_grade_call(self):
        g = make_grade()
        g.grade()
        g.add_grade_part('Part 1')
        g.grade()
        assert g.get_grade_parts() == []

    def test_reset_before_grade_clears_grade_parts(self):
        g = make_grade()
        g.grade()
        g.add_grade_part('Part 1')
        g.reset_before_grade()
        assert g.get_grade_parts() == []

    def test_grade_parts_initially_empty(self):
        g = make_grade()
        assert g.get_grade_parts() == []


class TestGradePartSerialization:
    def test_to_dict_round_trip(self):
        gp = GradePart(title='Part 1', description='desc')
        d = gp.to_dict()
        assert d == {'title': 'Part 1', 'description': 'desc'}
        restored = GradePart.from_dict(d)
        assert restored.title == 'Part 1'
        assert restored.description == 'desc'

    def test_pack_unpack_round_trip(self):
        gp = GradePart(title='Part 1', description='desc')
        restored = GradePart.unpack(gp.pack())
        assert restored.title == gp.title
        assert restored.description == gp.description

    def test_grade_element_grade_part_round_trip(self):
        e = GradeElement(title='t', max_grade=5, grade=3, grade_part='Part 1')
        d = e.to_dict()
        assert d['grade_part'] == 'Part 1'
        restored = GradeElement.from_dict(d)
        assert restored.grade_part == 'Part 1'

    def test_to_grade_letter_preserves_grade_part(self):
        e = GradeElement(title='t', max_grade=5, grade=5, grade_part='Part 1')
        assert e.to_grade_letter().grade_part == 'Part 1'
