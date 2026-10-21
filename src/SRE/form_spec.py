"""The ``@@{field:spec}@@`` grammar of the form questions and of the Flavor forms.

One Qt-free parser shared by the GUI widgets (``sysreseval.view.form_question_widget``,
``sysreseval.flavor_form_dialog``), by ``Grade0.question_form()`` (the field list stored in
``info.json``) and by a web front-end.  A description is split into text chunks and fields::

    "Notes: @@{notes:+3}@@ Mask: @@{mask:[0-9]+}@@ Done @@{done:?}@@"

gives ``[TextChunk, FieldChunk, TextChunk, FieldChunk, TextChunk, FieldChunk, TextChunk]``: the
chunks always alternate, a text chunk (possibly empty) before every field and one after the last
field, so that a renderer can put a checkbox on the row of the text that precedes it.

The specs, tried in this order:

- ``?`` / ``?true``: a checkbox (``kind='checkbox'``), checked by default unless the word after
  ``?`` is empty or ``false``;
- ``:Label``: a submit button (``kind='submit'``) with *allow_submit* only (the Flavor forms);
  a question form takes it for a regex, as it always did;
- ``>a|b`` or ``Label>>>value|...``: a dropdown (``kind='select'``) whose ``options`` are the
  ``(label, value)`` pairs, the answer being the value;
- ``+`` / ``+N``: a multi-line free text of N visible lines (``kind='multiline'``,
  ``common.form_field_lines()``);
- anything else: a single-line input (``kind='line'``) whose ``regex`` the value must match (an
  empty spec: no constraint).

The text chunks go through ``instructor_text.rebalance_fragments()``: an instructor fragment
running across a field is closed before it and reopened after it, so that every chunk renders on
its own.
"""
import re
from dataclasses import dataclass, field
from typing import Callable, Literal

from .common import TranslatedText, form_field_lines
from .instructor_text import markdown_to_html, rebalance_fragments, strip_instructor, unwrap_instructor

# the one regex of the grammar: group 1 = field name, group 2 = spec
FIELD_RE = re.compile(r'@@\{([^:}]+):([^}]*)\}@@')

FieldKind = Literal['checkbox', 'select', 'multiline', 'line', 'submit']


@dataclass
class TextChunk:
    """A run of markdown between two fields (or before the first / after the last one)."""
    text: str

    def visible_text(self, show_instructor: bool = False) -> str:
        """The text without the instructor marks: the fragments kept with *show_instructor*,
        removed otherwise (what a student sees)."""
        return unwrap_instructor(self.text) if show_instructor else strip_instructor(self.text)

    def has_text(self, show_instructor: bool = False) -> bool:
        """True when something remains to draw once the instructor marks are handled."""
        return bool(self.visible_text(show_instructor).strip())


@dataclass
class FieldChunk:
    """One ``@@{name:spec}@@`` marker."""
    name: str
    kind: FieldKind
    options: list = field(default_factory=list)  # select: [(label, value), ...]
    lines: int | None = None                    # multiline: visible lines
    regex: str = ''                             # line: the pattern the value must fully match
    default: bool = False                       # checkbox: checked at first
    label: str = ''                             # submit: the text of the button

    @property
    def labels(self) -> list:
        return [label for label, _ in self.options]

    @property
    def values(self) -> list:
        return [value for _, value in self.options]

    def default_value(self):
        """The value of the field before the student touches it."""
        if self.kind == 'checkbox':
            return self.default
        if self.kind == 'submit':
            return False
        if self.kind == 'select':
            return self.values[0] if self.options else ''
        return ''


def _checkbox_default(word: str) -> bool:
    return word.strip().lower() not in ('', 'false')


def parse_field_spec(name: str, spec: str, *, allow_submit: bool = False) -> FieldChunk:
    """The :class:`FieldChunk` of one marker ``@@{name:spec}@@``."""
    if spec.startswith('?'):
        return FieldChunk(name, 'checkbox', default=_checkbox_default(spec[1:]))
    if allow_submit and spec.startswith(':'):
        return FieldChunk(name, 'submit', label=spec[1:].strip() or name)
    if spec.startswith('>') or '>>>' in spec:
        raw = spec[1:] if spec.startswith('>') else spec
        options = []
        for choice in raw.split('|'):
            choice = choice.strip()
            if '>>>' in choice:
                label, value = choice.split('>>>', 1)
                options.append((label.strip(), value.strip()))
            else:
                options.append((choice, choice))
        return FieldChunk(name, 'select', options=options)
    if (lines := form_field_lines(spec)) is not None:
        return FieldChunk(name, 'multiline', lines=lines)
    return FieldChunk(name, 'line', regex=spec)


def _as_text(description) -> str:
    """The markers are language-independent: a ``tr()`` description is parsed on one of its
    values (the first one, as ``Grade0.question_form()`` always did)."""
    if isinstance(description, TranslatedText):
        return description.resolve('')
    return description or ''


def parse_form_description(description, *, allow_submit: bool = False) -> list:
    """Split *description* (a ``str`` or a ``TranslatedText``) into chunks: ``[TextChunk,
    FieldChunk, TextChunk, ..., FieldChunk, TextChunk]`` (``[TextChunk]`` without any field).
    The text chunks may be empty; they are re-balanced so that each one holds whole instructor
    fragments.  With *allow_submit* a ``:Label`` spec is a submit button."""
    segments = FIELD_RE.split(_as_text(description))
    # re.split with the two groups gives [text, name, spec, text, name, spec, ..., text]
    texts = rebalance_fragments(segments[0::3])
    chunks = []
    for index, text in enumerate(texts):
        chunks.append(TextChunk(text))
        position = 3 * index + 1
        if position + 1 < len(segments):
            chunks.append(parse_field_spec(segments[position], segments[position + 1],
                                           allow_submit=allow_submit))
    return chunks


def field_chunks(chunks) -> list:
    """The :class:`FieldChunk` items of *chunks*, in order."""
    return [chunk for chunk in chunks if isinstance(chunk, FieldChunk)]


def _info_field(chunk: FieldChunk) -> dict:
    """The dict of one field as ``QuestionForm.fields`` holds it in ``info.json``."""
    if chunk.kind == 'select':
        return {"name": chunk.name, "choices": chunk.values}
    if chunk.kind == 'checkbox':
        return {"name": chunk.name, "checkbox": chunk.default}
    if chunk.kind == 'multiline':
        return {"name": chunk.name, "lines": chunk.lines}
    if chunk.kind == 'submit':
        return {"name": chunk.name, "submit": chunk.label}
    return {"name": chunk.name, "regex": chunk.regex}


def form_fields(description) -> list:
    """The ``fields`` list of a :class:`common.QuestionForm` built from *description*: one dict
    per marker, ``{"name", "regex"}`` / ``{"name", "lines"}`` / ``{"name", "choices"}`` (the
    values) / ``{"name", "checkbox"}`` (the default), in text order.  The question hash never
    depends on it (title and description only)."""
    return [_info_field(chunk) for chunk in field_chunks(parse_form_description(description))]


def default_answers(chunks) -> dict:
    """``{name: value}`` of every field before any answer: empty strings, the first option of a
    select, the default of a checkbox, ``False`` for a submit button."""
    return {chunk.name: chunk.default_value() for chunk in field_chunks(chunks)}


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return _checkbox_default(value)
    return bool(value)


def coerce_answers(chunks, raw: dict) -> dict:
    """*raw* (what a client sent, or an ``answers.json`` entry) typed as the widgets type their
    answers: ``str`` for the line / multiline fields (a missing or ``None`` value is ``''``),
    ``bool`` for the checkboxes (missing: the default) and the submit buttons (missing:
    ``False``; a string is false when empty or ``false``), and for a select one of its values
    (a value given by its label is accepted; anything else gives the first value, as the
    combo box of the GUI stays on it).  Keys of *raw* that are not fields are dropped."""
    raw = raw or {}
    answers = {}
    for chunk in field_chunks(chunks):
        name = chunk.name
        if chunk.kind in ('checkbox', 'submit'):
            answers[name] = _as_bool(raw[name]) if name in raw else chunk.default_value()
        elif chunk.kind == 'select':
            value = raw.get(name)
            value = '' if value is None else str(value)
            if value in chunk.values:
                answers[name] = value
            elif value in chunk.labels:
                answers[name] = chunk.values[chunk.labels.index(value)]
            else:
                answers[name] = chunk.default_value()
        else:
            value = raw.get(name)
            answers[name] = '' if value is None else str(value)
    return answers


def validate_answers(chunks, answers: dict, *, allow_empty: bool = False) -> dict:
    """``{name: message}`` of the line fields of *answers* whose value does not fully match
    their regex (nothing for an empty regex): the rule of the submit button of the Flavor
    dialog.  Empty when every value is fine.  *allow_empty* accepts an empty string whatever
    the regex: the question forms save what the student typed so far, an untouched field
    included."""
    errors = {}
    for chunk in field_chunks(chunks):
        if chunk.kind != 'line' or not chunk.regex:
            continue
        value = answers.get(chunk.name)
        value = '' if value is None else str(value)
        if allow_empty and value == '':
            continue
        try:
            matched = re.fullmatch(chunk.regex, value) is not None
        except re.error:
            errors[chunk.name] = f"invalid field pattern {chunk.regex!r}"
            continue
        if not matched:
            errors[chunk.name] = f"must match {chunk.regex}"
    return errors


def field_to_json(chunk: FieldChunk) -> dict:
    """The JSON object of a field: ``type`` ``field`` plus every attribute of the chunk."""
    return {"type": "field", "name": chunk.name, "kind": chunk.kind,
            "options": [[label, value] for label, value in chunk.options],
            "lines": chunk.lines, "regex": chunk.regex, "default": chunk.default,
            "label": chunk.label}


def chunks_to_json(chunks, *, show_instructor: bool, markdown: Callable | None = None) -> list:
    """The chunks as JSON objects, in order: ``{"type": "text", "html": ...}`` for a text chunk
    with something to draw (the instructor fragments shown with *show_instructor*, left out
    otherwise, like the GUI), rendered by *markdown* (``instructor_text.markdown_to_html`` with
    *show_instructor* by default), and :func:`field_to_json` for a field.  A checkbox whose
    previous item is a text goes on its row, as in the GUI."""
    if markdown is None:
        def markdown(text):
            return markdown_to_html(text, show_instructor=show_instructor)
    result = []
    for chunk in chunks:
        if isinstance(chunk, TextChunk):
            if chunk.has_text(show_instructor):
                result.append({"type": "text", "html": markdown(chunk.text)})
        else:
            result.append(field_to_json(chunk))
    return result
