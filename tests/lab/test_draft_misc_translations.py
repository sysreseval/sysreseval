"""The English of the labs of lab/sre/_DRAFT_misc.

The labs are written in French (`tr = make_tr('fr')`) and translated in the `_TRANSLATIONS['en']` dict
at the end of each file.  For every lab of the directory:

- static checks of the source: every `tr()` literal has a non-empty English entry and no entry is left
  over; an entry keeps what the core or the GUI reads in the text (the `{placeholders}` of
  `.format()`, the doubled braces, the course markers `@@sec/@@tag/@@toc/@@ref@@`, the anchors, the
  fences, the form fields with their regexes and the *values* of the dropdowns: a French option
  becomes `English label>>>French option`, so the stored answers do not depend on the language); the
  `tr()` calls evaluated at import time (module body, class body, decorators such as
  `@sre_state(description=...)`) run before `_TRANSLATIONS` exists and carry their English inline
  (`en=`, equal to the entry), and so does every `tr(f"...")`;
- the lab built without Docker, as `sre check` does (default data, `initial`, one `grade()` pass in
  instructor mode): the course declares the same sections in both languages, and every question,
  grade element, part and state description reads in English, renders as HTML and keeps the form
  fields of its French text.
"""
import ast
import contextlib
import importlib.util
import io
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

from SRE import form_spec, params
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import markdown_to_html
from SRE.utils import generate_default_data, lab_module_as_srelab, offline_net_scheme

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import check_sre_translations as cst  # noqa: E402

_DIR = _REPO / 'lab' / 'sre' / '_DRAFT_misc'
LABS = sorted(p.name for p in _DIR.glob('*.py'))

_PLACEHOLDER_RE = re.compile(
    r'(?<!\{)\{([A-Za-z_][A-Za-z_0-9]*)(?:\.[A-Za-z_0-9]+|\[[^\]]*\])*(?:[!:][^{}]*)?\}(?!\})')
_MARKER_RE = re.compile(r'@@(sec|tag|toc|ref)(?::([^@\s]*))?@@')
_ANCHOR_RE = re.compile(r'<a id="[^"]*"></a>')
# accented letters or two of the commonest French words: the text needs an English version
_FRENCH_RE = re.compile(r"[éèêàùçôîâûœÉÈÀÇ]|\b(?:les|des|une|est|pour|avec|dans|sont|cette|vous|leur|sans)\b")


def _tree(name):
    return ast.parse((_DIR / name).read_text())


def _call_name(node):
    func = node.func
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None


def _english(tree):
    translations = cst.get_translations(tree)
    assert translations is not None, 'no literal _TRANSLATIONS dict'
    return translations.get('en', {})


def _looks_french(text):
    return len(_FRENCH_RE.findall(text)) >= 1 and len(text.split()) >= 3


def _fields(text):
    """(name, kind, regex, values, lines, default, inline, width) of every form marker of *text* (a
    `.format()` template writes them with doubled braces)."""
    if '@@{{' in text:
        text = text.replace('{{', '{').replace('}}', '}')
    out = []
    for m in form_spec.FIELD_RE.finditer(text):
        c = form_spec.parse_field_spec(m.group(1), m.group(2), allow_submit=True)   # a submit label translates
        out.append((c.name, c.kind, c.regex, [v for _, v in c.options] if c.kind == 'select' else None,
                    c.lines, c.default, c.inline, c.width))
    return out


def _markers(text):
    counted, refs = Counter(), set()
    for kind, arg in _MARKER_RE.findall(text):
        if kind == 'ref':
            refs.add(arg)
        else:
            counted[(kind, arg)] += 1
    return counted, refs


def entry_problems(fr, en):
    """What the English *en* of the French *fr* lost or changed of the markup."""
    problems = []
    if set(_PLACEHOLDER_RE.findall(fr)) != set(_PLACEHOLDER_RE.findall(en)):
        problems.append('placeholders')
    if (fr.count('{{'), fr.count('}}')) != (en.count('{{'), en.count('}}')):
        problems.append('doubled braces')
    if _markers(fr) != _markers(en):
        problems.append('course markers')
    if Counter(_ANCHOR_RE.findall(fr)) != Counter(_ANCHOR_RE.findall(en)):
        problems.append('anchors')
    if fr.count('```') != en.count('```'):
        problems.append('fences')
    if _fields(fr) != _fields(en):
        problems.append('form fields')
    if en.strip() == fr.strip() and _looks_french(fr):
        problems.append('not translated')
    return problems


class _Calls(ast.NodeVisitor):
    """Every tr() call, with whether it runs at import time (outside any function body)."""

    def __init__(self):
        self.in_function = False
        self.calls = []

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        saved, self.in_function = self.in_function, True
        for statement in node.body:
            self.visit(statement)
        self.in_function = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        self.visit(node.args)
        saved, self.in_function = self.in_function, True
        self.visit(node.body)
        self.in_function = saved

    def visit_Call(self, node):
        if _call_name(node) == 'tr':
            self.calls.append((node, not self.in_function))
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# the source
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('name', LABS)
def test_every_string_has_its_english(name):
    tree = _tree(name)
    translations = cst.get_translations(tree)
    assert translations is not None and set(translations) == {'en'}, name
    english = translations['en']
    strings = cst.get_tr_strings(tree)
    assert sorted(s.strip()[:60] for s in strings - set(english)) == [], 'missing'
    assert sorted(s.strip()[:60] for s in set(english) - strings) == [], 'left over'
    assert not [k.strip()[:60] for k, v in english.items() if not v or not v.strip()], 'empty'


@pytest.mark.parametrize('name', LABS)
def test_entries_keep_the_markup(name):
    english = _english(_tree(name))
    bad = {fr.strip()[:60]: problems for fr, en in english.items() if en and (problems := entry_problems(fr, en))}
    assert bad == {}


@pytest.mark.parametrize('name', LABS)
def test_import_time_and_fstring_calls_carry_their_english(name):
    tree = _tree(name)
    english = _english(tree)
    walker = _Calls()
    walker.visit(tree)
    bad = []
    for node, import_time in walker.calls:
        first = node.args[0] if node.args else None
        inline = next((k.value for k in node.keywords if k.arg == 'en'), None)
        if isinstance(first, ast.Constant):
            if import_time:
                if not isinstance(inline, ast.Constant):
                    bad.append((node.lineno, 'import-time tr() without en='))
                elif english.get(first.value, inline.value) != inline.value:
                    bad.append((node.lineno, 'en= differs from _TRANSLATIONS'))
        elif inline is None:
            bad.append((node.lineno, 'tr() of a computed text without en='))
    assert bad == []


# ---------------------------------------------------------------------------
# the lab built without Docker
# ---------------------------------------------------------------------------


def _resolve(text, lang):
    return text.resolve(lang) if isinstance(text, TranslatedText) else str(text or '')


def _placeholders(text):
    """The {names} left in a text outside the fences and the form markers."""
    text = re.sub(r'```.*?```', '', re.sub(r'@@\{.*?\}@@', '', text), flags=re.S)
    return set(_PLACEHOLDER_RE.findall(text))


def _built(name, tmp_pub_dir):
    """(module, net_scheme, grade) of the lab *name*: default data, `initial`, one grade() pass in
    instructor mode."""
    spec = importlib.util.spec_from_file_location(f"draft_misc_{re.sub(r'\W', '_', name[:-3])}", _DIR / name)
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()), lab_module_as_srelab(module):
        spec.loader.exec_module(module)
        data = generate_default_data(module)
        ns = offline_net_scheme(module, data, name[:-3])
        marker = Path(params.instructor_mode_marker_filename(ns.running_lab_name))
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
        ns = offline_net_scheme(module, data, name[:-3])
        initial = getattr(ns, params.initial_state_name, None)
        if callable(initial):
            ns._ops, ns._host_ops = {}, {}
            initial()
        grade = module.Grade(net_scheme=ns)
        grade._default_language = module.default_language
        grade.grade()
    return module, ns, grade


@pytest.mark.parametrize('name', LABS)
def test_texts_read_in_english(name, tmp_pub_dir):
    module, ns, grade = _built(name, tmp_pub_dir)
    assert module.default_language == 'fr'
    assert _resolve(module.title, 'en') != _resolve(module.title, 'fr')

    resolved, numbering = resolve_informations(ns.informations)
    sections = {lang: [(s.number, s.tag) for s in numbering.sections(lang)] for lang in ('fr', 'en')}
    assert sections['fr'] == sections['en']
    course = _resolve(resolved, 'en')
    assert course != _resolve(resolved, 'fr') and '@@sec' not in course and '@@ref' not in course
    assert '```' not in markdown_to_html(course)

    untranslated, bad = [], []
    for q in grade.get_questions_ordered():
        title = _resolve(q.title, 'fr')
        texts = {lang: (_resolve(q.title, lang), _resolve(q.description, lang)) for lang in ('fr', 'en')}
        for (fr, en) in zip(texts['fr'], texts['en']):
            if _looks_french(fr) and fr == en:
                untranslated.append(title)
        fr, en = texts['fr'][1], texts['en'][1]
        if "{'" in en or _placeholders(en) - _placeholders(fr):
            bad.append((title, 'unformatted text'))
        if form_spec.form_fields(fr) != form_spec.form_fields(en):
            bad.append((title, 'form fields'))
        shown = _resolve(resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering), 'en')
        if '@@ref' in shown:
            bad.append((title, 'unresolved reference'))
        if '```' in markdown_to_html(shown, show_instructor=True):
            bad.append((title, 'fence not rendered'))
    for element in grade.get_grade_list():
        fr, en = _resolve(element.description, 'fr'), _resolve(element.description, 'en')
        if _looks_french(fr) and fr == en:
            untranslated.append(str(element.title))
        if "{'" in en or _placeholders(en) - _placeholders(fr):
            bad.append((str(element.title), 'unformatted grade element'))
    for part in grade.get_grade_parts():
        fr = _resolve(part.description, 'fr')
        if _looks_french(fr) and fr == _resolve(part.description, 'en'):
            untranslated.append(str(part.title))
    for attribute in dir(module.NetScheme):
        state = getattr(module.NetScheme, attribute)
        if getattr(state, '_is_sre_state', False):
            description = getattr(state, '_sre_state_description', None)
            fr = _resolve(description, 'fr')
            if _looks_french(fr) and fr == _resolve(description, 'en'):
                untranslated.append(attribute)
    assert untranslated == [] and bad == []
