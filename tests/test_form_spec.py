"""SRE.form_spec: the one parser of the ``@@{field:spec}@@`` grammar of the form questions and
of the Flavor forms, shared by the GUI widgets, ``Grade0.question_form()`` and a web front-end.
The ``form_fields()`` literals below were recorded from ``question_form()`` before it delegated
to the module: they are what ``info.json`` held, and the question hash with them."""
from unittest.mock import MagicMock

import pytest

from SRE import params
from SRE.common import QuestionForm, TranslatedText
from SRE.form_spec import (
    FIELD_RE, FieldChunk, FormRow, TextChunk, chunks_to_json, coerce_answers, default_answers, field_chunks,
    field_to_json, form_fields, layout_rows, parse_field_spec, parse_form_description, split_inline_name,
    validate_answers,
)
from SRE.instructor_text import instructor, set_instructor_context
from SRE.lib_sre import Grade0, make_tr

tr = make_tr('en')

FORM = "Notes: @@{notes:+3}@@ N: @@{n:[0-9]+}@@ End."
EVERY_SPEC = ("A @@{c:?}@@ B @@{d:?true}@@ @@{d2:? False }@@ C @@{e:>a|b}@@ D @@{f:X>>>x| Y >>> y }@@ "
              "E @@{g:+}@@ F @@{h:+3}@@ G @@{i:[0-9]+}@@ H @@{j:}@@ I @@{k::Go}@@ J @@{l:>}@@")
# the Flavor form of lab/sre/static_routing.py (French values)
STATIC_ROUTING_FORM = (
    "# Routage statique\n\n**Taille du réseau :**\n"
    "@@{network_size:>Petit réseau>>>small|Moyen réseau>>>medium|Grand réseau>>>large}@@\n\n"
    "**Adresses IP :**\n@@{ip_choice:>Aléatoires>>>random|Jeu 1>>>set1|Jeu 2>>>set2}@@\n\n"
    "**Inclure la configuration persistante du réseaux sur certaines marchines:**\n"
    "@@{persistent:Demander la configuration persistante du réseau sur certaines machines>>>True|"
    "Ne pas demander de configuration persistante des machines>>>False}@@\n\n"
    "**Démarrage des terminaux :**\n@@{shell:>Shell (/bin/bash)>>>shell|Login>>>login}@@\n\n"
    "**Fichier /etc/hosts :**\n"
    "@@{hosts:>Générer le fichier /etc/hosts>>>True|Ne pas générer le fichier /etc/hosts>>>False}@@\n\n"
    "@@{name::Démarrer le projet}@@")


@pytest.fixture
def instructor_mode():
    set_instructor_context(True)
    yield
    set_instructor_context(False)


def instructor_form():
    """The form question of tests/test_gui_instructor_view.py: a fragment across a field."""
    return instructor("Hint one. @@{a:[0-9]+}@@ Hint two.") + " Public end. @@{b:[0-9]+}@@"


class ConcreteGrade(Grade0):
    def grade(self):
        super().grade()


def stored_question(title, description) -> QuestionForm:
    grade = ConcreteGrade(MagicMock(running_lab_name='20260101000000@@@test@@@user'))
    grade.grade()
    grade.question_form(title=title, description=description)
    return grade.get_questions_ordered()[0]


# ---------------------------------------------------------------------------
# the regex and its aliases
# ---------------------------------------------------------------------------

class TestFieldRe:
    def test_groups(self):
        assert FIELD_RE.findall("a @@{x:[0-9]+}@@ b @@{y:>a|b}@@ @@{z:}@@") == [
            ('x', '[0-9]+'), ('y', '>a|b'), ('z', '')]
        assert FIELD_RE.findall("@@{no spec}@@ @@{x:unclosed") == []

    def test_grade0_alias(self):
        assert Grade0._FORM_FIELD_RE is FIELD_RE

    def test_widget_alias(self):
        pytest.importorskip('PySide6')
        from sysreseval.view import form_question_widget
        assert form_question_widget._FIELD_RE is FIELD_RE


# ---------------------------------------------------------------------------
# one spec
# ---------------------------------------------------------------------------

class TestParseFieldSpec:
    def test_checkbox(self):
        assert parse_field_spec('c', '?') == FieldChunk('c', 'checkbox', default=False)
        assert parse_field_spec('c', '?true') == FieldChunk('c', 'checkbox', default=True)
        assert parse_field_spec('c', '? False ') == FieldChunk('c', 'checkbox', default=False)
        assert parse_field_spec('c', '?yes').default is True

    def test_select(self):
        assert parse_field_spec('s', '>a|b') == FieldChunk('s', 'select', options=[('a', 'a'), ('b', 'b')])
        chunk = parse_field_spec('s', '> X >>> x | Y>>>y ')
        assert chunk.options == [('X', 'x'), ('Y', 'y')]
        assert chunk.labels == ['X', 'Y'] and chunk.values == ['x', 'y']

    def test_select_without_leading_marker(self):
        # a '>>>' anywhere makes a dropdown, as in the persistent field of static_routing.py
        chunk = parse_field_spec('p', 'Ask>>>True|Do not ask>>>False')
        assert chunk.kind == 'select' and chunk.options == [('Ask', 'True'), ('Do not ask', 'False')]

    def test_select_value_keeps_further_markers(self):
        # the widgets split on the first '>>>' only: the value is what they store
        assert parse_field_spec('s', '>L>>>v>>>w').options == [('L', 'v>>>w')]

    def test_multiline(self):
        assert parse_field_spec('m', '+') == FieldChunk('m', 'multiline', lines=params.default_form_field_lines)
        assert parse_field_spec('m', '+3') == FieldChunk('m', 'multiline', lines=3)

    def test_line(self):
        assert parse_field_spec('n', '[0-9]+') == FieldChunk('n', 'line', regex='[0-9]+')
        assert parse_field_spec('n', '') == FieldChunk('n', 'line', regex='')
        assert parse_field_spec('n', 'a+').kind == 'line'   # '+' is multi-line as a prefix only

    def test_submit_only_when_allowed(self):
        # a question form takes ':Label' for a regex, as it always did
        assert parse_field_spec('go', ':Go') == FieldChunk('go', 'line', regex=':Go')
        assert parse_field_spec('go', ':Go', allow_submit=True) == FieldChunk('go', 'submit', label='Go')
        assert parse_field_spec('go', ':', allow_submit=True).label == 'go'
        assert parse_field_spec('go', ': Start project ', allow_submit=True).label == 'Start project'

    def test_checkbox_comes_first(self):
        # the order of the GUI widgets: '?' before the dropdown and the submit markers
        assert parse_field_spec('c', '?x>>>y').kind == 'checkbox'
        assert parse_field_spec('c', '?:x', allow_submit=True).kind == 'checkbox'


# ---------------------------------------------------------------------------
# a whole description
# ---------------------------------------------------------------------------

class TestParseFormDescription:
    def test_text_before_between_and_after(self):
        assert parse_form_description(FORM) == [
            TextChunk("Notes: "), FieldChunk('notes', 'multiline', lines=3),
            TextChunk(" N: "), FieldChunk('n', 'line', regex='[0-9]+'),
            TextChunk(" End.")]

    def test_no_field(self):
        assert parse_form_description("Just text") == [TextChunk("Just text")]
        assert parse_form_description("") == [TextChunk("")]

    def test_chunks_always_alternate(self):
        # an empty text chunk before a field with no text of its own, one after the last field
        chunks = parse_form_description("@@{a:?}@@@@{b:?}@@")
        assert chunks == [TextChunk(''), FieldChunk('a', 'checkbox'), TextChunk(''),
                          FieldChunk('b', 'checkbox'), TextChunk('')]
        assert not chunks[0].has_text() and not chunks[2].has_text()
        assert [chunk.name for chunk in field_chunks(chunks)] == ['a', 'b']

    def test_translated_description(self):
        description = TranslatedText({'fr': "IP : @@{ip:\\d+}@@", 'en': "IP: @@{ip:\\d+}@@"})
        assert parse_form_description(description) == [
            TextChunk("IP : "), FieldChunk('ip', 'line', regex='\\d+'), TextChunk("")]

    def test_submit_only_with_allow_submit(self):
        text = "Go: @@{name::Start}@@"
        assert field_chunks(parse_form_description(text))[0].kind == 'line'
        assert field_chunks(parse_form_description(text, allow_submit=True))[0] == \
            FieldChunk('name', 'submit', label='Start')

    def test_instructor_fragment_across_a_field_is_rebalanced(self, instructor_mode):
        chunks = parse_form_description(instructor_form())
        texts = [chunk for chunk in chunks if isinstance(chunk, TextChunk)]
        assert [chunk.name for chunk in field_chunks(chunks)] == ['a', 'b']
        # the student's view and the instructor's view of the same chunks (the GUI test)
        assert [t.visible_text(False).strip() for t in texts if t.has_text(False)] == ["Public end."]
        assert [t.visible_text(True).strip() for t in texts if t.has_text(True)] == [
            "Hint one.", "Hint two. Public end."]
        # every chunk holds whole fragments: the marks are balanced in each one
        for text in texts:
            assert text.text.count(params.instructor_begin_mark) == text.text.count(params.instructor_end_mark)

    def test_without_instructor_mode_the_fragment_is_gone(self):
        # instructor() returns '' outside the mode: the field inside the fragment does not exist
        chunks = parse_form_description(instructor_form())
        assert chunks == [TextChunk(" Public end. "), FieldChunk('b', 'line', regex='[0-9]+'), TextChunk("")]


# ---------------------------------------------------------------------------
# form_fields(): what QuestionForm.fields holds in info.json
# ---------------------------------------------------------------------------

class TestFormFields:
    INSTRUCTOR_LAB_HASH = "870273ce6cddfd68d2e285b038b483a5b5ff47ad5012307256d7c34c2713164c"

    @pytest.mark.parametrize('mode', [True, False])
    def test_instructor_test_lab_question(self, mode):
        # tests/labs/instructor_test_lab.py: same fields and same hash in and out of the mode
        set_instructor_context(mode)
        try:
            title = tr("Mask")
            description = instructor(tr("The mask is 24.\n\n")) + tr("Prefix length: @@{mask:[0-9]+}@@")
            assert form_fields(description) == [{"name": "mask", "regex": "[0-9]+"}]
            question = stored_question(title, description)
            assert question.fields == [{"name": "mask", "regex": "[0-9]+"}]
            assert question.question_hash == self.INSTRUCTOR_LAB_HASH
            assert QuestionForm(title, description).question_hash == self.INSTRUCTOR_LAB_HASH
        finally:
            set_instructor_context(False)

    def test_example1_questions(self):
        assert form_fields("Copier le contenu du fichier `/root/secret` de `m1` ici:@@{secret:.+}@@") == [
            {"name": "secret", "regex": ".+"}]
        assert form_fields("Copier ici les commandes exécutées sur `m1` :@@{commands:+6}@@") == [
            {"name": "commands", "lines": 6}]

    def test_static_routing_flavor_form(self):
        # a question form has no submit button: the ':Label' spec is a regex there
        assert form_fields(STATIC_ROUTING_FORM) == [
            {"name": "network_size", "choices": ["small", "medium", "large"]},
            {"name": "ip_choice", "choices": ["random", "set1", "set2"]},
            {"name": "persistent", "choices": ["True", "False"]},
            {"name": "shell", "choices": ["shell", "login"]},
            {"name": "hosts", "choices": ["True", "False"]},
            {"name": "name", "regex": ":Démarrer le projet"}]

    def test_every_spec(self):
        assert form_fields(EVERY_SPEC) == [
            {"name": "c", "checkbox": False}, {"name": "d", "checkbox": True}, {"name": "d2", "checkbox": False},
            {"name": "e", "choices": ["a", "b"]}, {"name": "f", "choices": ["x", "y"]},
            {"name": "g", "lines": params.default_form_field_lines}, {"name": "h", "lines": 3},
            {"name": "i", "regex": "[0-9]+"}, {"name": "j", "regex": ""}, {"name": "k", "regex": ":Go"},
            {"name": "l", "choices": [""]}]

    def test_question_form_stores_form_fields(self):
        description = TranslatedText({'fr': EVERY_SPEC, 'en': EVERY_SPEC})
        assert stored_question("Every spec", description).fields == form_fields(EVERY_SPEC)
        assert stored_question("None", "no field").fields == []


# ---------------------------------------------------------------------------
# answers
# ---------------------------------------------------------------------------

class TestAnswers:
    def chunks(self):
        return parse_form_description(EVERY_SPEC, allow_submit=True)

    def test_default_answers(self):
        assert default_answers(self.chunks()) == {
            'c': False, 'd': True, 'd2': False, 'e': 'a', 'f': 'x', 'g': '', 'h': '', 'i': '', 'j': '',
            'k': False, 'l': ''}
        assert default_answers(parse_form_description("@@{s:>}@@")) == {'s': ''}

    def test_coerce_types(self):
        raw = {'c': 'true', 'd': 'false', 'd2': 1, 'e': 'b', 'f': 'y', 'g': 'a\nb', 'h': None, 'i': 12,
               'k': True, 'unknown': 'dropped'}
        assert coerce_answers(self.chunks(), raw) == {
            'c': True, 'd': False, 'd2': True, 'e': 'b', 'f': 'y', 'g': 'a\nb', 'h': '', 'i': '12', 'j': '',
            'k': True, 'l': ''}

    def test_coerce_missing_values(self):
        assert coerce_answers(self.chunks(), {}) == default_answers(self.chunks())
        assert coerce_answers(self.chunks(), None) == default_answers(self.chunks())

    def test_coerce_select(self):
        chunks = parse_form_description("@@{f:>X>>>x|Y>>>y}@@")
        assert coerce_answers(chunks, {'f': 'y'}) == {'f': 'y'}        # a value
        assert coerce_answers(chunks, {'f': 'Y'}) == {'f': 'y'}        # its label, as the combo box
        assert coerce_answers(chunks, {'f': 'zzz'}) == {'f': 'x'}      # unknown: the first option
        assert coerce_answers(chunks, {'f': None}) == {'f': 'x'}

    def test_validate(self):
        chunks = parse_form_description("@@{n:[0-9]+}@@ @@{free:}@@ @@{notes:+}@@ @@{s:>a|b}@@")
        assert validate_answers(chunks, {'n': '12', 'free': 'anything', 'notes': 'x', 's': 'zzz'}) == {}
        errors = validate_answers(chunks, {'n': '12a'})
        assert list(errors) == ['n'] and '[0-9]+' in errors['n']
        # the whole value must match, as the submit button of the Flavor dialog requires
        assert 'n' in validate_answers(chunks, {'n': ''})
        assert 'n' in validate_answers(chunks, {})
        assert validate_answers(chunks, {'n': ''}, allow_empty=True) == {}
        assert 'n' in validate_answers(chunks, {'n': 'x'}, allow_empty=True)

    def test_validate_bad_pattern(self):
        chunks = parse_form_description("@@{n:[0-9}@@")
        assert 'n' in validate_answers(chunks, {'n': '1'})


# ---------------------------------------------------------------------------
# chunks_to_json
# ---------------------------------------------------------------------------

class TestChunksToJson:
    @staticmethod
    def fake_markdown(text: str) -> str:
        return f"<{text.strip()}>"

    def test_texts_and_fields(self):
        chunks = parse_form_description("Intro @@{n:[0-9]+}@@ Agree? @@{ok:?true}@@ Pick @@{s:>A>>>a|b}@@")
        assert chunks_to_json(chunks, show_instructor=False, markdown=self.fake_markdown) == [
            {"type": "text", "html": "<Intro>"},
            {"type": "field", "name": "n", "kind": "line", "options": [], "lines": None, "regex": "[0-9]+",
             "default": False, "label": ""},
            {"type": "text", "html": "<Agree?>"},
            {"type": "field", "name": "ok", "kind": "checkbox", "options": [], "lines": None, "regex": "",
             "default": True, "label": ""},
            {"type": "text", "html": "<Pick>"},
            {"type": "field", "name": "s", "kind": "select", "options": [["A", "a"], ["b", "b"]], "lines": None,
             "regex": "", "default": False, "label": ""},
        ]

    def test_blank_texts_are_left_out(self):
        # the empty chunk before a field is not an item: a checkbox is inline when the item
        # before it is a text, as in the GUI
        items = chunks_to_json(parse_form_description("@@{a:?}@@ @@{b:+2}@@"), show_instructor=False,
                               markdown=self.fake_markdown)
        assert [item["type"] for item in items] == ["field", "field"]
        assert items[1]["lines"] == 2

    def test_submit_and_field_to_json(self):
        chunk = parse_field_spec('go', ':Start', allow_submit=True)
        assert field_to_json(chunk) == {"type": "field", "name": "go", "kind": "submit", "options": [],
                                        "lines": None, "regex": "", "default": False, "label": "Start"}

    def test_instructor_fragment(self, instructor_mode):
        chunks = parse_form_description(instructor_form())
        student = chunks_to_json(chunks, show_instructor=False, markdown=self.fake_markdown)
        assert [item["type"] for item in student] == ["field", "text", "field"]
        assert student[1]["html"].startswith("<") and "Public end." in student[1]["html"]
        instructor_items = chunks_to_json(chunks, show_instructor=True, markdown=self.fake_markdown)
        assert [item["type"] for item in instructor_items] == ["text", "field", "text", "field"]

    def test_default_markdown(self, instructor_mode):
        text = "**bold** " + instructor("secret") + " @@{a:?}@@"
        student = chunks_to_json(parse_form_description(text), show_instructor=False)
        assert student[0] == {"type": "text", "html": "<p><strong>bold</strong></p>"}
        shown = chunks_to_json(parse_form_description(text), show_instructor=True)
        assert "secret" in shown[0]["html"] and params.instructor_text_color in shown[0]["html"]
        assert "secret" not in student[0]["html"]


# ---------------------------------------------------------------------------
# inline fields: @@{name~N:spec}@@
# ---------------------------------------------------------------------------

# the line of lab/sre/traceroute.py the inline fields were made for, between two
# other items of its list
ICMP_FORM = ("**Mesures.**\n\n- Hops: @@{routers:[0-9]+}@@\n"
             "- ICMP message: type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@\n"
             "- Silent hop: @@{silent_hop:[0-9]+}@@\n")


def shape(rows) -> list:
    """The rows as ``(inline, [text or <name>, ...])``: what a renderer draws, in order."""
    return [(row.inline, [chunk.text if isinstance(chunk, TextChunk) else f"<{chunk.name}>"
                          for chunk in row.items]) for row in rows]


class TestInlineName:
    def test_suffix(self):
        assert split_inline_name('mask~4') == ('mask', True, 4)
        assert split_inline_name('mask~') == ('mask', True, params.default_inline_field_width)
        assert split_inline_name('mask~0') == ('mask', True, params.default_inline_field_width)
        assert split_inline_name('mask') == ('mask', False, None)

    def test_only_a_suffix_counts(self):
        assert split_inline_name('a~b') == ('a~b', False, None)
        assert split_inline_name('a~b~12') == ('a~b', True, 12)
        assert split_inline_name('~') == ('~', False, None)       # no name before the mark
        assert split_inline_name('~4') == ('~4', False, None)

    def test_line(self):
        assert parse_field_spec('n~4', '[0-9]+') == FieldChunk('n', 'line', regex='[0-9]+', inline=True, width=4)
        chunk = parse_field_spec('n~', '')
        assert (chunk.name, chunk.inline, chunk.width) == ('n', True, params.default_inline_field_width)

    def test_select_takes_no_width(self):
        chunk = parse_field_spec('s~8', '>a|b')
        assert chunk == FieldChunk('s', 'select', options=[('a', 'a'), ('b', 'b')], inline=True)
        assert chunk.width is None

    @pytest.mark.parametrize('spec, kind', [('?true', 'checkbox'), ('+3', 'multiline'), (':Go', 'submit')])
    def test_other_kinds_lose_the_suffix_and_stay_block(self, spec, kind):
        chunk = parse_field_spec('x~4', spec, allow_submit=True)
        assert (chunk.name, chunk.kind, chunk.inline, chunk.width) == ('x', kind, False, None)

    def test_names_are_clean_everywhere(self):
        chunks = parse_form_description(ICMP_FORM)
        assert [chunk.name for chunk in field_chunks(chunks)] == ['routers', 'icmp_type', 'icmp_code', 'silent_hop']
        assert form_fields(ICMP_FORM) == [
            {"name": "routers", "regex": "[0-9]+"}, {"name": "icmp_type", "regex": "[0-9]+"},
            {"name": "icmp_code", "regex": "[0-9]+"}, {"name": "silent_hop", "regex": "[0-9]+"}]
        assert default_answers(chunks) == {'routers': '', 'icmp_type': '', 'icmp_code': '', 'silent_hop': ''}
        assert coerce_answers(chunks, {'icmp_type': 11, 'icmp_code~4': '0'})['icmp_type'] == '11'
        assert list(validate_answers(chunks, {'routers': '1', 'icmp_type': 'x', 'icmp_code': '0',
                                              'silent_hop': '2'})) == ['icmp_type']

    def test_stored_question(self):
        question = stored_question("ICMP", ICMP_FORM)
        assert [f["name"] for f in question.fields] == ['routers', 'icmp_type', 'icmp_code', 'silent_hop']


class TestLayoutRows:
    def test_without_inline_field_the_rows_are_the_pairs(self):
        chunks = parse_form_description(EVERY_SPEC, allow_submit=True)
        rows = layout_rows(chunks)
        assert all(not row.inline for row in rows)
        # the very chunks, in order: a text and its field, then the last text alone
        assert [chunk for row in rows for chunk in row.items] == chunks
        assert all(isinstance(row.items[0], TextChunk) for row in rows)
        assert [len(row.items) for row in rows] == [2] * len(field_chunks(chunks)) + [1]
        assert layout_rows(parse_form_description("Just text")) == [FormRow([TextChunk("Just text")])]

    def test_two_fields_of_one_source_line_share_a_row(self):
        assert shape(layout_rows(parse_form_description(ICMP_FORM))) == [
            (False, ["**Mesures.**\n\n- Hops: ", "<routers>"]),
            (True, ["- ICMP message: type ", "<icmp_type>", ", code ", "<icmp_code>"]),
            (False, ["- Silent hop: ", "<silent_hop>"]),
            (False, ["\n"]),     # the text after the last field, as the chunks always end
        ]

    def test_the_end_of_the_line_stays_on_the_row(self):
        form = "- hold: @@{hold~4:[0-9]+}@@ s, keepalive: @@{keepalive~4:[0-9]+}@@ s\n- next: @@{n:}@@"
        assert shape(layout_rows(parse_form_description(form))) == [
            (True, ["- hold: ", "<hold>", " s, keepalive: ", "<keepalive>", " s"]),
            (False, ["- next: ", "<n>"]),
            (False, [""]),
        ]
        # the last text of the form, without newline
        assert shape(layout_rows(parse_form_description("T: @@{t~:}@@ seconds"))) == [
            (True, ["T: ", "<t>", " seconds"])]

    def test_the_lines_above_the_label_are_a_block(self):
        form = "Intro.\n\nMore.\nLabel: @@{a~3:}@@\nAfter."
        assert shape(layout_rows(parse_form_description(form))) == [
            (False, ["Intro.\n\nMore."]),
            (True, ["Label: ", "<a>"]),
            (False, ["After."]),
        ]

    def test_a_newline_between_two_inline_fields_starts_a_row(self):
        form = "A: @@{a~3:}@@\nB: @@{b~3:}@@"
        assert shape(layout_rows(parse_form_description(form))) == [
            (True, ["A: ", "<a>"]), (True, ["B: ", "<b>"])]

    def test_blank_texts_are_left_out_of_an_inline_row(self):
        assert shape(layout_rows(parse_form_description("@@{p~:>UDP|TCP}@@ @@{port~5:[0-9]+}@@\n"))) == [
            (True, ["<p>", "<port>"]), (False, [""])]

    def test_a_block_field_after_an_inline_one(self):
        # the text between them, without newline, is the label of the block field
        form = "A: @@{a~3:}@@ notes: @@{notes:+2}@@ B: @@{b~3:}@@"
        assert shape(layout_rows(parse_form_description(form))) == [
            (True, ["A: ", "<a>"]), (False, [" notes: ", "<notes>"]), (True, [" B: ", "<b>"])]

    def test_an_ignored_suffix_is_a_block_row(self):
        assert shape(layout_rows(parse_form_description("Done: @@{ok~:?}@@ N: @@{n~2:}@@"))) == [
            (False, ["Done: ", "<ok>"]), (True, [" N: ", "<n>"])]

    def test_instructor_fragment_across_the_splits(self, instructor_mode):
        form = instructor("Hint above.\nHint: @@{a~3:}@@ end of hint\nhint below") + " public"
        rows = layout_rows(parse_form_description(form))
        assert [row.inline for row in rows] == [False, True, False]
        texts = [chunk for row in rows for chunk in row.items if isinstance(chunk, TextChunk)]
        assert [t.visible_text(True) for t in texts] == [
            "Hint above.", "Hint: ", " end of hint", "hint below public"]
        assert [t.visible_text(False) for t in texts] == ["", "", "", " public"]
        for text in texts:
            assert text.text.count(params.instructor_begin_mark) == text.text.count(params.instructor_end_mark)


class TestInlineChunksToJson:
    fake_markdown = staticmethod(TestChunksToJson.fake_markdown)

    def test_rows_and_widths(self):
        items = chunks_to_json(parse_form_description(ICMP_FORM), show_instructor=False,
                               markdown=self.fake_markdown)
        assert [(item["type"], item.get("name") or item["html"], item.get("row"), item.get("width"))
                for item in items] == [
            ("text", "<**Mesures.**\n\n- Hops:>", None, None),
            ("field", "routers", None, None),
            ("text", "<- ICMP message: type>", 1, None),
            ("field", "icmp_type", 1, 4),
            ("text", "<, code>", 1, None),
            ("field", "icmp_code", 1, 4),
            ("text", "<- Silent hop:>", None, None),
            ("field", "silent_hop", None, None),
        ]
        # the keys exist on the items of an inline row only
        assert "row" not in items[1] and "width" not in items[1]

    def test_two_rows_have_two_numbers(self):
        items = chunks_to_json(parse_form_description("A: @@{a~3:}@@\nB: @@{b~:>x|y}@@"),
                               show_instructor=False, markdown=self.fake_markdown)
        assert [item["row"] for item in items] == [0, 0, 1, 1]
        assert items[1]["width"] == 3 and "width" not in items[3]      # a select has no width

    def test_a_form_without_inline_field_is_unchanged(self):
        items = chunks_to_json(parse_form_description(EVERY_SPEC, allow_submit=True), show_instructor=False,
                               markdown=self.fake_markdown)
        assert all("row" not in item and "width" not in item for item in items)
        assert all(set(item) == {"type", "name", "kind", "options", "lines", "regex", "default", "label"}
                   for item in items if item["type"] == "field")

    def test_default_markdown_of_a_row(self):
        items = chunks_to_json(parse_form_description(ICMP_FORM), show_instructor=False)
        assert items[2] == {"type": "text", "html": "<ul>\n<li>ICMP message: type</li>\n</ul>", "row": 1}
        assert items[4] == {"type": "text", "html": "<p>, code</p>", "row": 1}
