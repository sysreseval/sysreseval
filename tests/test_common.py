"""Tests for common.py: Question/GradeElement/InfoLab serialization."""
import json

import pytest

from SRE import params
from SRE.common import (
    QuestionText, QuestionDummy, QuestionForm, form_field_lines,
    GradeElement, InfoLab, InfoMachine, InfoInterface, InfoSwitch,
    QuestionType, TranslatedText,
    bonus_texts
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

    def test_bonus_defaults_to_false(self):
        assert GradeElement(title='t', max_grade=5, grade=5).bonus is False

    def test_bonus_round_trips(self):
        e = GradeElement(title='b', max_grade=2, grade=1, bonus=True)
        assert GradeElement.from_dict(e.to_dict()).bonus is True
        assert GradeElement.from_json(e.to_json()).bonus is True
        assert GradeElement.unpack(e.pack()).bonus is True

    def test_legacy_dict_without_bonus(self):
        e = GradeElement.from_dict({'title': 'old', 'max_grade': 2, 'grade': 1})
        assert e.bonus is False

    def test_to_grade_letter_keeps_bonus(self):
        e = GradeElement(title='b', max_grade=2, grade=2, bonus=True)
        letter = e.to_grade_letter()
        assert letter.grade_letter == 'OK'
        assert letter.bonus is True
        assert GradeElement(title='n', max_grade=2, grade=2).to_grade_letter().bonus is False


class TestBonusTexts:
    @pytest.mark.parametrize('args, kwargs, expected', [
        (('label', '2', False), {}, ('label', '2')),                          # not a bonus: untouched
        (('label', '2', False, True), {}, ('label', '2')),
        (('label', '2', True), {}, ('label', '2 (Bonus)')),                   # default: the max column
        (('label', '', True), {}, ('label', '(Bonus)')),                      # letter mode: no maximum
        (('label', '2', True, True), {}, ('Bonus: label', '2')),              # --bonus-in-prefix
        (('label', '1.0/1.0', True), {'word': 'Bonus'}, ('label', '1.0/1.0 (Bonus)')),
        (('label', '2', True, True), {'word': 'Prime'}, ('Prime: label', '2')),  # translated word
    ])
    def test_bonus_texts(self, args, kwargs, expected):
        assert bonus_texts(*args, **kwargs) == expected


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

    def test_allow_save_restore_default_false(self):
        lab = _make_info_lab()
        assert lab.allow_save_restore is False
        assert InfoLab.from_json(lab.to_json()).allow_save_restore is False
        # absent from an older info.json → False
        d = json.loads(lab.to_json())
        del d['allow_save_restore']
        assert InfoLab.from_json(json.dumps(d)).allow_save_restore is False

    def test_instructor_mode_default_false(self):
        lab = _make_info_lab()
        assert lab.instructor_mode is False
        assert InfoLab.from_json(lab.to_json()).instructor_mode is False
        # absent from an older info.json → False
        d = json.loads(lab.to_json())
        del d['instructor_mode']
        assert InfoLab.from_json(json.dumps(d)).instructor_mode is False

    def test_instructor_mode_roundtrip(self):
        lab = _make_info_lab()
        lab.instructor_mode = True
        assert InfoLab.from_json(lab.to_json()).instructor_mode is True

    def test_allow_save_restore_roundtrip(self):
        lab = _make_info_lab()
        lab.allow_save_restore = True
        assert InfoLab.from_json(lab.to_json()).allow_save_restore is True

    def test_export_schema_pdf_default_true(self):
        lab = _make_info_lab()
        assert lab.export_schema_pdf is True
        assert InfoLab.from_json(lab.to_json()).export_schema_pdf is True
        # absent from an older info.json → True (File → Export Schema to PDF is on by default)
        d = json.loads(lab.to_json())
        del d['export_schema_pdf']
        assert InfoLab.from_json(json.dumps(d)).export_schema_pdf is True

    def test_export_schema_pdf_roundtrip(self):
        lab = _make_info_lab()
        lab.export_schema_pdf = False
        assert InfoLab.from_json(lab.to_json()).export_schema_pdf is False

    def test_switches_default_to_none(self):
        lab = _make_info_lab()
        assert lab.switches == []
        assert json.loads(lab.to_json())['switches'] == []

    def test_switches_absent_in_old_json(self):
        d = json.loads(_make_info_lab().to_json())
        del d['switches']
        assert InfoLab.from_json(json.dumps(d)).switches == []

    def test_switches_roundtrip(self):
        lab = _make_info_lab()
        lab.switches = [InfoSwitch(name='lan', mode='managed', allow_connection=False),
                        InfoSwitch(name='dmz', mode='switch'),
                        InfoSwitch(name='old', mode='hub')]
        assert json.loads(lab.to_json())['switches'][0] == {'name': 'lan', 'mode': 'managed',
                                                             'allow_connection': False}
        lab2 = InfoLab.from_json(lab.to_json())
        assert lab2.switches == lab.switches
        assert lab2.switches[1].allow_connection is True


# ---------------------------------------------------------------------------
# Question hashes and instructor() fragments
# ---------------------------------------------------------------------------

class TestInstructorFragmentsInHashes:
    """A question hash ignores the instructor() fragments of its texts: it is the same in and
    out of the instructor mode, so the stored answers stay attached when the mode changes."""

    TITLE = {'en': 'Gateway', 'fr': 'Passerelle'}
    NOTE = {'en': ' (expected: 10.0.0.1)', 'fr': ' (attendu : 10.0.0.1)'}

    def _texts(self, instructor_mode: bool):
        from SRE.instructor_text import instructor, set_instructor_context
        set_instructor_context(instructor_mode)
        title = TranslatedText(self.TITLE) + instructor(TranslatedText(self.NOTE))
        description = instructor('Hint.\n\n') + 'Answer: @@{x:[0-9]+}@@'
        return title, description

    def test_texts_differ_between_the_modes(self):
        assert self._texts(True) != self._texts(False)

    def test_question_text(self):
        hashes = {QuestionText(*self._texts(mode)).question_hash for mode in (True, False)}
        assert hashes == {QuestionText(TranslatedText(self.TITLE), '').question_hash}

    def test_question_form(self):
        hashes = {QuestionForm(*self._texts(mode)).question_hash for mode in (True, False)}
        assert len(hashes) == 1

    def test_question_dummy(self):
        hashes = {QuestionDummy(*self._texts(mode)).question_hash for mode in (True, False)}
        assert len(hashes) == 1

    def test_public_text_still_counts(self):
        title, description = self._texts(True)
        assert QuestionForm(title, description).question_hash != QuestionForm(title, 'other').question_hash


# ---------------------------------------------------------------------------
# form_field_lines: the `+` / `+N` spec of a multi-line form field
# ---------------------------------------------------------------------------

class TestFormFieldLines:
    def test_lines(self):
        assert form_field_lines('+8') == 8
        assert form_field_lines('+ 3') == 3
        assert form_field_lines('+') == params.default_form_field_lines
        assert form_field_lines('+0') == params.default_form_field_lines
        assert form_field_lines('+abc') == params.default_form_field_lines

    def test_other_specs_are_not_multiline(self):
        assert [form_field_lines(s) for s in ('[0-9]+', '>a|b', '?', '?true', '', 'a+')] == [None] * 6


# ---------------------------------------------------------------------------
# Display helpers shared by the GUI and the web front-end
# ---------------------------------------------------------------------------

from SRE.common import (  # noqa: E402
    format_port, format_ports, terminal_devices, info_languages, project_title, listed_states,
    state_rows, visible_tabs, resolve_text, TAB_SCHEMA, TAB_FULL_SCHEMA, TAB_INFORMATIONS,
    TAB_MACHINES, TAB_NETWORKS, TAB_QUESTIONS, TAB_EVALUATION, TAB_TERMINALS, TAB_DISPLAY,
    TAB_APPLY_CONFIG, TAB_LOG, TAB_ORDER,
)


def _info(**over):
    info = {
        "lab_name": "sre/dhcp.py",
        "title": {"en": "DHCP", "fr": "Le DHCP"},
        "informations": {"en": "# Hi", "fr": "# Salut"},
        "machines": [{"name": "pc1", "allow_connection": True}, {"name": "srv", "allow_connection": False}],
        "switches": [{"name": "lan", "mode": "managed", "allow_connection": True},
                     {"name": "dmz", "mode": "switch", "allow_connection": True},
                     {"name": "hub", "mode": "hub", "allow_connection": True}],
        "questions": [{"title": {"en": "Q1", "de": "F1"}, "description": {"es": "d"}}],
        "user_allowed_states": {"final": {"en": "The solution", "fr": "La solution"}, "fault": ""},
        "admin_only_states": ["fault"],
        "allow_self_grade": True,
        "debug_project": False,
    }
    info.update(over)
    return info


class TestDisplayHelpers:
    def test_format_ports(self):
        assert format_port("8080:80/tcp") == "8080 -> 80 (tcp)"
        assert format_port("5353:53/udp") == "5353 -> 53 (udp)"
        assert format_port("2222:22") == "2222 -> 22 (tcp)"
        assert format_ports(["8080:80/tcp", "2222:22"]) == "8080 -> 80 (tcp)  -  2222 -> 22 (tcp)"
        assert format_ports([]) == ""
        assert format_ports(None) == ""

    def test_terminal_devices_machines_then_managed_switches(self):
        devices = terminal_devices(_info())
        assert [d["name"] for d in devices] == ["pc1", "srv", "lan"]
        assert devices[2] == {"name": "lan", "allow_connection": True}
        assert terminal_devices({}) == []

    def test_info_languages(self):
        assert info_languages(_info()) == {"en", "fr", "de", "es"}
        assert info_languages({"title": "plain", "questions": [{"title": "q"}]}) == set()

    def test_project_title(self):
        assert project_title(_info(), ["fr", "en"]) == "Le DHCP"
        assert project_title(_info(), ["de", "en"]) == "DHCP"
        assert project_title({"lab_name": "s4/tp_ssh.py"}, ["en"]) == "s4/tp_ssh"
        assert project_title({}, ["en"], fallback="20260101000000@@@x@@@u") == "20260101000000@@@x@@@u"

    def test_resolve_text(self):
        marked = {"en": "Public " + params.instructor_begin_mark + ";" + params.instructor_args_end_mark
                  + "secret" + params.instructor_end_mark, "fr": "Publique"}
        assert resolve_text(marked, ["en"]) == "Public "
        assert resolve_text(marked, ["en"], show_instructor=True) == "Public secret"
        assert resolve_text(marked, ["fr"]) == "Publique"
        assert resolve_text("plain", ["fr"]) == "plain"

    def test_listed_states_and_rows(self):
        info = _info()
        assert listed_states(info["user_allowed_states"], info["admin_only_states"], show_admin_only=False) == \
            {"final": {"en": "The solution", "fr": "La solution"}}
        assert list(listed_states(info["user_allowed_states"], info["admin_only_states"],
                                  show_admin_only=True)) == ["final", "fault"]
        rows = state_rows(info["user_allowed_states"], info["admin_only_states"],
                          show_admin_only=True, lang_priority=["fr", "en"])
        assert rows == [("final", "La solution", False), ("fault", "fault", True)]
        assert state_rows({}, None, show_admin_only=True, lang_priority=["en"]) == []

    def test_visible_tabs_student(self):
        tabs = visible_tabs(_info(), exam_mode=False, instructor_shown=False)
        assert tabs == [TAB_SCHEMA, TAB_INFORMATIONS, TAB_MACHINES, TAB_NETWORKS, TAB_QUESTIONS,
                        TAB_EVALUATION, TAB_TERMINALS, TAB_APPLY_CONFIG]
        assert [t for t in TAB_ORDER if t in tabs] == tabs

    def test_visible_tabs_exam_mode(self):
        tabs = visible_tabs(_info(), exam_mode=True, instructor_shown=False)
        assert TAB_EVALUATION not in tabs and TAB_APPLY_CONFIG not in tabs and TAB_LOG not in tabs
        # the instructor view lifts the exam restriction of the Apply Configuration tab
        tabs = visible_tabs(_info(), exam_mode=True, instructor_shown=True)
        assert TAB_APPLY_CONFIG in tabs and TAB_LOG in tabs and TAB_EVALUATION not in tabs

    def test_visible_tabs_no_states_no_questions_no_self_grade(self):
        info = _info(user_allowed_states={"fault": ""}, questions=[], allow_self_grade=False)
        tabs = visible_tabs(info, exam_mode=False, instructor_shown=False)
        assert tabs == [TAB_SCHEMA, TAB_INFORMATIONS, TAB_MACHINES, TAB_NETWORKS, TAB_TERMINALS]
        # the admin-only state is listed with the instructor view
        assert TAB_APPLY_CONFIG in visible_tabs(info, exam_mode=False, instructor_shown=True)

    def test_visible_tabs_debug_project(self):
        info = _info(user_allowed_states={}, questions=[])
        info["debug_project"] = True
        tabs = visible_tabs(info, exam_mode=True, instructor_shown=False)
        assert TAB_FULL_SCHEMA in tabs and TAB_APPLY_CONFIG in tabs and TAB_LOG in tabs
        assert tabs.index(TAB_FULL_SCHEMA) == tabs.index(TAB_SCHEMA) + 1

    def test_visible_tabs_display_is_an_opt_in_of_the_web(self):
        # the Qt GUI never passes display=: its lists are unchanged
        for exam_mode, instructor_shown in ((False, False), (True, False), (False, True)):
            tabs = visible_tabs(_info(), exam_mode=exam_mode, instructor_shown=instructor_shown)
            assert TAB_DISPLAY not in tabs
            assert tabs == visible_tabs(_info(), exam_mode=exam_mode, instructor_shown=instructor_shown,
                                        display=False)
            with_display = visible_tabs(_info(), exam_mode=exam_mode, instructor_shown=instructor_shown,
                                        display=True)
            assert with_display.index(TAB_DISPLAY) == with_display.index(TAB_TERMINALS) + 1
            assert [t for t in with_display if t != TAB_DISPLAY] == tabs
            assert [t for t in TAB_ORDER if t in with_display] == with_display
