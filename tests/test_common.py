"""Tests for common.py: Question/GradeElement/InfoLab serialization."""
import pytest

from SRE.common import (
    QuestionText, QuestionDummy, QuestionForm,
    GradeElement, InfoLab, InfoMachine, InfoInterface,
    QuestionType, TranslatedText,
)


# ---------------------------------------------------------------------------
# QuestionText
# ---------------------------------------------------------------------------

class TestQuestionText:
    def test_hash_deterministic(self):
        q1 = QuestionText(title='What is IP?')
        q2 = QuestionText(title='What is IP?')
        assert q1.question_hash == q2.question_hash

    def test_different_titles_give_different_hashes(self):
        assert QuestionText(title='Q1').question_hash != QuestionText(title='Q2').question_hash

    def test_explicit_hash_used(self):
        q = QuestionText(title='Q', question_hash='fixed')
        assert q.question_hash == 'fixed'

    def test_question_type(self):
        q = QuestionText(title='Q')
        assert q.question_type == QuestionType.TEXT.value

    def test_json_roundtrip(self):
        q = QuestionText(title='Test?', description='Describe', order=100)
        q2 = QuestionText.from_json(q.to_json())
        assert q2.title == q.title
        assert q2.description == q.description
        assert q2.question_hash == q.question_hash
        assert q2.order == q.order


# ---------------------------------------------------------------------------
# QuestionDummy
# ---------------------------------------------------------------------------

class TestQuestionDummy:
    def test_hash_uses_title_and_description(self):
        q1 = QuestionDummy(title='T', description='D')
        q2 = QuestionDummy(title='T', description='D')
        assert q1.question_hash == q2.question_hash

    def test_different_descriptions_different_hashes(self):
        q1 = QuestionDummy(title='T', description='A')
        q2 = QuestionDummy(title='T', description='B')
        assert q1.question_hash != q2.question_hash

    def test_question_type(self):
        q = QuestionDummy(title='T', description='D')
        assert q.question_type == QuestionType.DUMMY.value

    def test_json_roundtrip(self):
        q = QuestionDummy(title='Note', description='**bold**', order=50)
        q2 = QuestionDummy.from_json(q.to_json())
        assert q2.title == 'Note'
        assert q2.description == '**bold**'


# ---------------------------------------------------------------------------
# QuestionForm
# ---------------------------------------------------------------------------

class TestQuestionForm:
    def test_fields_stored(self):
        fields = [{'name': 'ip', 'regex': r'\d+\.\d+\.\d+\.\d+'}, {'name': 'port', 'regex': r'\d+'}]
        q = QuestionForm(title='Config', description='', fields=fields)
        assert q.fields == fields

    def test_empty_fields_default(self):
        q = QuestionForm(title='F', description='no fields here')
        assert q.fields == []

    def test_question_type(self):
        q = QuestionForm(title='F', description='')
        assert q.question_type == QuestionType.FORM.value

    def test_json_roundtrip(self):
        fields = [{'name': 'a', 'regex': r'\d+'}]
        q = QuestionForm(title='F', description='desc', fields=fields, order=10)
        q2 = QuestionForm.from_json(q.to_json())
        assert q2.fields == fields
        assert q2.title == 'F'


# ---------------------------------------------------------------------------
# GradeElement
# ---------------------------------------------------------------------------

class TestGradeElement:
    def test_ok(self):
        e = GradeElement(title='t', max_grade=5, grade=5)
        assert e.to_grade_letter().grade_letter == 'OK'

    def test_meh(self):
        e = GradeElement(title='t', max_grade=5, grade=2)
        assert e.to_grade_letter().grade_letter == 'MEH'

    def test_fail_zero(self):
        e = GradeElement(title='t', max_grade=5, grade=0)
        assert e.to_grade_letter().grade_letter == 'FAIL'

    def test_fail_none(self):
        e = GradeElement(title='t', max_grade=5, grade=None)
        assert e.to_grade_letter().grade_letter == 'FAIL'

    def test_to_dict_from_dict(self):
        e = GradeElement(title='x', max_grade=10, grade=7, description='desc')
        e2 = GradeElement.from_dict(e.to_dict())
        assert e2.title == 'x'
        assert e2.grade == 7
        assert e2.max_grade == 10

    def test_json_roundtrip(self):
        e = GradeElement(title='y', max_grade=4, grade=4, grade_letter='OK')
        e2 = GradeElement.from_json(e.to_json())
        assert e2.grade_letter == 'OK'

    def test_pack_unpack(self):
        e = GradeElement(title='z', max_grade=3, grade=1)
        e2 = GradeElement.unpack(e.pack())
        assert e2.title == 'z'
        assert e2.grade == 1


# ---------------------------------------------------------------------------
# InfoLab
# ---------------------------------------------------------------------------

def _make_info_lab():
    machine = InfoMachine(
        name='m1', status='running', allow_connection=True,
        hidden=False, interfaces=[], ports=['8080:80'], bridged=True,
    )
    q_text = QuestionText(title='Q1', description='desc', order=100)
    q_dummy = QuestionDummy(title='Note', description='info', order=200)
    return InfoLab(
        lab_name='test/tp1', lab_hash='abc123',
        title=TranslatedText.from_value('TP1'),
        informations=TranslatedText.from_value('A **test** lab'),
        export_kathara_project=True,
        allow_self_grade=True, machines=[machine],
        questions=[q_text, q_dummy], delay_between_self_grade=60,
        eval_interval_without_exam_mode=0,
        eval_before_exit=False,
        user_allowed_states={},
    )


class TestInfoLab:
    def test_to_json_from_json_roundtrip(self):
        lab = _make_info_lab()
        lab2 = InfoLab.from_json(lab.to_json())
        assert lab2.lab_name == 'test/tp1'
        assert lab2.title.resolve('en') == 'TP1'
        assert lab2.allow_self_grade is True
        assert lab2.delay_between_self_grade == 60

    def test_machines_preserved(self):
        lab = _make_info_lab()
        lab2 = InfoLab.from_json(lab.to_json())
        assert len(lab2.machines) == 1
        assert lab2.machines[0].name == 'm1'
        assert lab2.machines[0].ports == ['8080:80']
        assert lab2.machines[0].bridged is True

    def test_questions_type_preserved(self):
        lab = _make_info_lab()
        lab2 = InfoLab.from_json(lab.to_json())
        types = {q.title.resolve('en'): q.question_type for q in lab2.questions}
        assert types['Q1'] == QuestionType.TEXT.value
        assert types['Note'] == QuestionType.DUMMY.value

    def test_description_preserved(self):
        lab = _make_info_lab()
        lab2 = InfoLab.from_json(lab.to_json())
        assert lab2.informations.resolve('en') == 'A **test** lab'
