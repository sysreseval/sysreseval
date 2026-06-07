#!/usr/bin/env python3
"""prepare-sre-translations — Migrate a lab .py file to the _TRANSLATIONS dict system.

Usage:
    prepare-sre-translations [--move-tr-strings] [--default-language xx]
                      [--change-default-language xx] [--translations-at-the-end]
                      [--translate-isolated-words] file

Actions performed:
  1. Bare translatable strings are wrapped in tr(). Bare f-strings in the same
     positions are wrapped and lowered, e.g.
     description=f"x {v}" → description=tr("x {v}").format(v=v).
     By default, plain string literals with no whitespace (space/tab/newline)
     are wrapped in no_tr() instead — they look like internal labels, not
     prose. Pass --translate-isolated-words to wrap them in tr() too.
  2. A _TRANSLATIONS dict is inserted/updated immediately after
     tr = make_tr(default_language).
  3. With --move-tr-strings: inline lang kwargs are stripped from existing
     tr() calls and moved into _TRANSLATIONS.

Strings wrapped in no_tr(...) are left untouched: never wrapped in tr() and
never added to _TRANSLATIONS (use it for short internal labels that should not
be translated). no_tr is auto-imported from lib_sre when used.

Translatable positions detected:
  - Module-level assignments:  title, description, informations, lab_name
  - Attribute assignments:     self.informations = ..., self.description = ...
  - Keyword arguments:         title=..., description=..., informations=...
  - Positional args of:        question_dummy(title, _, description),
                               question_text(title, _, description),
                               question_form(title, _, description),
                               add_grade_element(title, _, description),
                               add_grade_part(title, description)

String values inside BinOp (`"x" + var`) or IfExp (`"x" if c else "y"`)
expressions in any of the above positions are recursed into and each bare
string/f-string leaf is wrapped individually.

Options:
  --move-tr-strings          Strip inline lang kwargs from tr() calls and move
                             to _TRANSLATIONS (e.g. tr("x", fr="y") → tr("x"))
  --default-language xx      Declare the default language; error if the file
                             already has a different one
  --change-default-language  Pivot the file's source language to xx: rewrite
                             every tr() literal to its xx translation, re-key
                             _TRANSLATIONS so the inner keys are the new
                             source texts, and preserve the previous default
                             as a regular language. Errors out if any tr()
                             string lacks an xx translation or any
                             translatable string is still bare.
  --translations-at-the-end  Place _TRANSLATIONS at the end of the file. To
                             preserve import-time translations, inline kwargs
                             are kept on (and added to) every tr() call in the
                             module/class body — tr() resolves _TRANSLATIONS
                             from globals at call time, so import-time calls
                             cannot rely on a definition that comes later in
                             the file.
  --translate-isolated-words Also wrap whitespace-free single-token strings in
                             tr() (default: wrap them in no_tr()).
  (missing default_language with no flag → defaults to 'en')

NOTE: AST col_offset/end_col_offset are UTF-8 byte offsets; all position
arithmetic is done on UTF-8-encoded source bytes.
"""

import ast
import argparse
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRANSLATABLE_KWARGS = {'title', 'description', 'informations'}
TRANSLATABLE_VARS   = {'title', 'description', 'informations', 'lab_name'}

# Per-function tuple of translatable positional-argument indices.
# question_*(title, section, description, ...) — section (idx 1) is a numbering
# prefix produced by self.section(), not natural language, so it is skipped.
# add_grade_element(title, max_grade, description, ...) — max_grade is numeric.
QUESTION_FUNC_POSITIONAL = {
    'question_dummy':    (0, 2),   # title, description
    'question_text':     (0, 2),   # title, description
    'question_form':     (0, 2),   # title, description
    'add_grade_element': (0, 2),   # title, description
    'add_grade_part':    (0, 1),   # title, description
}

# ---------------------------------------------------------------------------
# Byte-level position helpers
# ---------------------------------------------------------------------------

def build_line_offsets(source_bytes: bytes) -> list[int]:
    """Return offsets[i] = byte offset of the start of line i+1."""
    offsets = [0]
    for line in source_bytes.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def node_span(offsets: list[int], node: ast.AST) -> tuple[int, int]:
    """Return (start, end) byte offsets for an AST node."""
    start = offsets[node.lineno - 1] + node.col_offset
    end   = offsets[node.end_lineno - 1] + node.end_col_offset
    return start, end


def apply_replacements(data: bytes, replacements: list[tuple[int, int, bytes]]) -> bytes:
    """Apply (start, end, new_bytes) replacements in reverse order (highest offset first)."""
    for start, end, new_bytes in sorted(replacements, key=lambda x: -x[0]):
        data = data[:start] + new_bytes + data[end:]
    return data

# ---------------------------------------------------------------------------
# AST detection helpers
# ---------------------------------------------------------------------------

def detect_multilingual(tree: ast.Module) -> tuple[bool, str | None]:
    """Return (is_multilingual, default_language).

    A file is multilingual when it has both ``default_language = '<code>'``
    and a ``tr = make_tr(...)`` assignment (or an import of tr/make_tr).
    """
    default_lang: str | None = None
    has_tr_setup = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id == 'default_language':
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            default_lang = node.value.value
                    elif target.id == 'tr':
                        has_tr_setup = True
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) in ('tr', 'make_tr'):
                    has_tr_setup = True

    return bool(default_lang and has_tr_setup), default_lang


# Marker functions whose string arguments must never be (re)wrapped in tr():
#   tr(...)    — already translated
#   no_tr(...) — explicitly opted out of translation (identity at runtime)
MARKER_FUNCS = ('tr', 'no_tr')


def _excluded_arg_ids(tree: ast.Module) -> set[int]:
    """Return AST node ids of arguments already inside a tr()/no_tr() call."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in MARKER_FUNCS:
                for arg in node.args:
                    ids.add(id(arg))
                for kw in node.keywords:
                    ids.add(id(kw.value))
    return ids


def _calls_function(tree: ast.Module, name: str) -> bool:
    """True if the tree contains a bare call ``name(...)``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
            return True
    return False


def _iter_translatable_leaves(value_node: ast.AST):
    """Yield translatable leaves — string ``Constant`` and f-string ``JoinedStr``
    nodes — reachable through string-composition nodes.

    Recurses through BinOp (e.g. ``"x" + var`` or ``"a" + "b"``) and IfExp
    (``"x" if cond else "y"``) so that bare string literals/f-strings nested
    inside a concatenation or conditional are still discovered.  An f-string is
    yielded whole; we never recurse into its interpolated expressions.  Stops at
    any other expression kind (Name, Call, Subscript, ...) — we never wrap
    strings that sit inside an unrelated subexpression.
    """
    if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
        yield value_node
    elif isinstance(value_node, ast.JoinedStr):
        yield value_node
    elif isinstance(value_node, ast.BinOp):
        yield from _iter_translatable_leaves(value_node.left)
        yield from _iter_translatable_leaves(value_node.right)
    elif isinstance(value_node, ast.IfExp):
        yield from _iter_translatable_leaves(value_node.body)
        yield from _iter_translatable_leaves(value_node.orelse)


def find_translatable_nodes(tree: ast.Module) -> list[ast.AST]:
    """Return bare string/f-string nodes in translatable positions, excluding tr()/no_tr() args."""
    excluded = _excluded_arg_ids(tree)
    seen: set[int] = set()
    result: list[ast.AST] = []

    def add_value(value_node: ast.AST) -> None:
        for c in _iter_translatable_leaves(value_node):
            if id(c) not in excluded and id(c) not in seen:
                seen.add(id(c))
                result.append(c)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in TRANSLATABLE_VARS:
                    add_value(node.value)
                elif isinstance(target, ast.Attribute) and target.attr in TRANSLATABLE_VARS:
                    add_value(node.value)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        func_name = (func.id if isinstance(func, ast.Name)
                     else func.attr if isinstance(func, ast.Attribute)
                     else None)
        for kw in node.keywords:
            if kw.arg in TRANSLATABLE_KWARGS:
                add_value(kw.value)
        if func_name in QUESTION_FUNC_POSITIONAL:
            for idx in QUESTION_FUNC_POSITIONAL[func_name]:
                if idx < len(node.args):
                    add_value(node.args[idx])

    return result


def find_translations_node(tree: ast.Module) -> ast.Assign | None:
    """Return the ``_TRANSLATIONS = ...`` Assign node, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == '_TRANSLATIONS' for t in node.targets):
                return node
    return None


def find_make_tr_node(tree: ast.Module) -> ast.Assign | None:
    """Return the ``tr = make_tr(...)`` Assign node, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == 'tr':
                    if isinstance(node.value, ast.Call):
                        func = node.value.func
                        if ((isinstance(func, ast.Name) and func.id == 'make_tr') or
                                (isinstance(func, ast.Attribute) and func.attr == 'make_tr')):
                            return node
    return None


def find_default_language_node(tree: ast.Module) -> ast.Assign | None:
    """Return the ``default_language = ...`` Assign node, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == 'default_language':
                    return node
    return None

# ---------------------------------------------------------------------------
# Translation data collectors
# ---------------------------------------------------------------------------

def collect_inline_translations(tree: ast.Module) -> dict[str, dict[str, str | None]]:
    """Return {source_text: {lang: translated}} from tr("text", fr="...", ...) kwargs."""
    result: dict[str, dict[str, str | None]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (func.id if isinstance(func, ast.Name) else
                func.attr if isinstance(func, ast.Attribute) else None)
        if name != 'tr' or not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        text = node.args[0].value
        if not isinstance(text, str):
            continue
        result.setdefault(text, {})
        for kw in node.keywords:
            if kw.arg and isinstance(kw.value, ast.Constant):
                result[text][kw.arg] = kw.value.value
    return result


def get_existing_translations(tree: ast.Module) -> dict:
    """Return the _TRANSLATIONS dict from AST via literal_eval, or {}."""
    node = find_translations_node(tree)
    if node is None:
        return {}
    try:
        return ast.literal_eval(node.value) or {}
    except Exception:
        return {}


def collect_tr_strings(tree: ast.Module) -> set[str]:
    """Return all first-arg string literals from tr() calls."""
    strings: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (func.id if isinstance(func, ast.Name) else
                func.attr if isinstance(func, ast.Attribute) else None)
        if name == 'tr' and node.args and isinstance(node.args[0], ast.Constant):
            strings.add(node.args[0].value)
    return strings


def find_import_time_tr_call_ids(tree: ast.Module) -> set[int]:
    """Return ids of tr() Call nodes evaluated at import time.

    Import-time = module body or class body — anything *not* inside a
    FunctionDef/AsyncFunctionDef. These calls cannot rely on _TRANSLATIONS
    being defined later in the file, so their translations must be carried
    inline as kwargs.
    """
    ids: set[int] = set()

    def visit(node: ast.AST, in_function: bool) -> None:
        if (isinstance(node, ast.Call)
                and not in_function
                and isinstance(node.func, ast.Name)
                and node.func.id == 'tr'):
            ids.add(id(node))
        deeper = in_function or isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for child in ast.iter_child_nodes(node):
            visit(child, deeper)

    visit(tree, False)
    return ids

# ---------------------------------------------------------------------------
# Source transformations — byte replacement builders
# ---------------------------------------------------------------------------

def _wrap_replacements(
    source_bytes: bytes,
    offsets: list[int],
    nodes: list[ast.AST],
    wrapper: bytes = b'tr',
) -> list[tuple[int, int, bytes]]:
    """Wrap each bare string/f-string node with ``wrapper(...)`` (tr or no_tr)."""
    result = []
    for node in nodes:
        start, end = node_span(offsets, node)
        result.append((start, end, wrapper + b'(' + source_bytes[start:end] + b')'))
    return result


def _add_lib_sre_imports(
    source_bytes: bytes,
    tree: ast.Module,
    offsets: list[int],
    names: list[str],
) -> list[tuple[int, int, bytes]]:
    """Return replacements importing each missing *name* from lib_sre.

    Adds the missing names to an existing ``from ...lib_sre import ...`` line, or
    prepends a new import when no lib_sre import exists. Names already imported
    are skipped.
    """
    if not names:
        return []
    lib_sre_node: ast.ImportFrom | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and 'lib_sre' in node.module:
            lib_sre_node = node
            break

    if lib_sre_node is not None:
        imported = {alias.asname or alias.name for alias in lib_sre_node.names}
        missing = [n for n in names if n not in imported]
        if not missing:
            return []
        start, end = node_span(offsets, lib_sre_node)
        stripped = source_bytes[start:end].rstrip()
        add = b', '.join(n.encode('utf-8') for n in missing)
        if stripped.endswith(b')'):
            inner = stripped[:-1]
            inner_rstripped = inner.rstrip()
            if inner_rstripped.endswith(b','):
                # Existing trailing comma — splice new names between it and the
                # whitespace/newline preceding ')' so we don't produce ',,'.
                trailing_ws = inner[len(inner_rstripped):]
                new_import = inner_rstripped + b' ' + add + b',' + trailing_ws + b')'
            else:
                new_import = inner + b', ' + add + b')'
        else:
            new_import = stripped + b', ' + add
        return [(start, end, new_import)]

    add = b', '.join(n.encode('utf-8') for n in names)
    return [(0, 0, b'from SRE.lib_sre import ' + add + b'\n')]


def _import_setup_replacements(
    source_bytes: bytes,
    tree: ast.Module,
    offsets: list[int],
    default_lang: str,
    extra_names: tuple[str, ...] = (),
) -> list[tuple[int, int, bytes]]:
    """Add make_tr (+ any extra_names) to the lib_sre import and insert setup."""
    replacements = []

    # 1. Determine which names to add to the lib_sre import line.
    lib_sre_node: ast.ImportFrom | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and 'lib_sre' in node.module:
            lib_sre_node = node
            break
    imported = ({alias.asname or alias.name for alias in lib_sre_node.names}
                if lib_sre_node is not None else set())

    want: list[str] = []
    if 'make_tr' not in imported and 'tr' not in imported:
        want.append('make_tr')
    for n in extra_names:
        if n not in imported and n not in want:
            want.append(n)

    replacements += _add_lib_sre_imports(source_bytes, tree, offsets, want)

    # 2. Insert setup block after the last top-level import.
    last_import_end = 0
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            _, end = node_span(offsets, node)
            last_import_end = max(last_import_end, end)

    insert_pos = last_import_end
    if insert_pos < len(source_bytes) and source_bytes[insert_pos:insert_pos + 1] == b'\n':
        insert_pos += 1

    setup = (
        f"\ndefault_language = '{default_lang}'\n"
        f"tr = make_tr(default_language)\n"
    ).encode('utf-8')
    replacements.append((insert_pos, insert_pos, setup))
    return replacements


def add_tr_kwargs_replacements(
    source_bytes: bytes,
    offsets: list[int],
    tree: ast.Module,
    target_ids: set[int],
    merged: dict[str, dict[str, str | None]],
    default_lang: str,
) -> list[tuple[int, int, bytes]]:
    """For each tr() Call whose id is in *target_ids*, append missing language
    kwargs from *merged* immediately before the closing ')'. Skips
    *default_lang*, kwargs already present on the call, and None values.

    Used by --translations-at-the-end so import-time tr() calls (module/class
    body) carry their translations inline and don't depend on _TRANSLATIONS
    being defined later in the file.
    """
    result = []
    for node in ast.walk(tree):
        if id(node) not in target_ids:
            continue
        if not isinstance(node, ast.Call) or not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        existing = {kw.arg for kw in node.keywords if kw.arg}
        text = first.value
        missing = [
            (lang, val) for lang, val in merged.get(text, {}).items()
            if lang != default_lang and lang not in existing and val is not None
        ]
        if not missing:
            continue
        _, call_end = node_span(offsets, node)
        addition = b''.join(
            f', {lang}={val!r}'.encode('utf-8') for lang, val in missing
        )
        # call_end is one past the ')'; insert immediately before it.
        result.append((call_end - 1, call_end - 1, addition))
    return result


def strip_tr_kwargs_replacements(
    source_bytes: bytes,
    offsets: list[int],
    tree: ast.Module,
    exclude_ids: frozenset[int] = frozenset(),
) -> list[tuple[int, int, bytes]]:
    """For each tr("text", fr="...", ...) call, remove kwargs → tr("text").

    Calls whose AST node id is in *exclude_ids* are skipped (used when
    fstring_tr_replacements has already handled them).
    """
    result = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if id(node) in exclude_ids:
            continue
        func = node.func
        name = (func.id if isinstance(func, ast.Name) else
                func.attr if isinstance(func, ast.Attribute) else None)
        if name != 'tr' or not node.args or not node.keywords:
            continue
        if not all(kw.arg for kw in node.keywords):   # skip **kwargs
            continue
        call_start, call_end = node_span(offsets, node)
        arg_start, arg_end   = node_span(offsets, node.args[0])
        prefix   = source_bytes[call_start:arg_start]   # e.g. b'tr('
        first_arg = source_bytes[arg_start:arg_end]
        result.append((call_start, call_end, prefix + first_arg + b')'))
    return result


# ---------------------------------------------------------------------------
# F-string transformation helpers
# ---------------------------------------------------------------------------

def _is_simple_fstring(node: ast.JoinedStr) -> bool:
    """True if every FormattedValue in the f-string is a simple ast.Name expression."""
    return all(
        isinstance(part.value, ast.Name)
        for part in node.values
        if isinstance(part, ast.FormattedValue)
    )


def _fstring_vars(node: ast.JoinedStr) -> list[str]:
    """Return variable names (in order, deduplicated) used in a simple f-string."""
    seen: dict[str, None] = {}
    for part in node.values:
        if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
            seen[part.value.id] = None
    return list(seen)


def _fstring_strip_f(fstring_src: bytes) -> bytes:
    """Strip the leading 'f'/'F' from f-string source bytes."""
    return fstring_src[1:]


def _fstring_template_value(fstring_src: bytes) -> str | None:
    """Parse the template string value from f-string source bytes.

    e.g. b'f"Hello {name}"' → "Hello {name}"
    Returns None on parse failure.
    """
    try:
        return ast.literal_eval(_fstring_strip_f(fstring_src).decode('utf-8'))
    except Exception:
        return None


def _render_fstring_template(
    joinedstr: ast.JoinedStr,
    source_bytes: bytes,
    offsets: list[int],
    name_map: dict,
) -> tuple[str, bool]:
    """Build a ``.format()``-compatible template from a JoinedStr f-string.

    *name_map* maps expression-source → placeholder name. It is mutated in
    place so the first-arg and kwarg f-strings of one tr() call share names
    by expression source. Simple ``ast.Name`` expressions reuse the variable
    name as placeholder (matching the prior simple-fstring behaviour); other
    expressions get auto-generated ``_arg0``, ``_arg1``, ... names.

    Returns ``(template, ok)``. ``ok=False`` when the f-string uses a feature
    we cannot safely lower (e.g. an expression inside a format_spec).
    """
    parts: list[str] = []
    for part in joinedstr.values:
        if isinstance(part, ast.Constant):
            if not isinstance(part.value, str):
                return '', False
            parts.append(part.value.replace('{', '{{').replace('}', '}}'))
        elif isinstance(part, ast.FormattedValue):
            spec_text = ''
            if part.format_spec is not None:
                if not isinstance(part.format_spec, ast.JoinedStr):
                    return '', False
                for sp in part.format_spec.values:
                    if isinstance(sp, ast.Constant) and isinstance(sp.value, str):
                        spec_text += sp.value
                    else:
                        return '', False   # dynamic format_spec — give up
            expr_start, expr_end = node_span(offsets, part.value)
            expr_src = source_bytes[expr_start:expr_end].decode('utf-8')
            if expr_src not in name_map:
                if isinstance(part.value, ast.Name):
                    name_map[expr_src] = part.value.id
                else:
                    n = sum(1 for v in name_map.values() if v.startswith('_arg'))
                    name_map[expr_src] = f'_arg{n}'
            placeholder = '{' + name_map[expr_src]
            if part.conversion != -1:
                placeholder += '!' + chr(part.conversion)
            if spec_text:
                placeholder += ':' + spec_text
            placeholder += '}'
            parts.append(placeholder)
        else:
            return '', False
    return ''.join(parts), True


def _quote_string_literal(value: str, fstring_src: bytes) -> str:
    """Render *value* as a Python string literal, reusing *fstring_src*'s quoting when safe."""
    body = fstring_src
    while body and body[:1] in (b'f', b'F', b'r', b'R'):
        body = body[1:]
    style = None
    if body.startswith(b'"""'):
        style = '"""'
    elif body.startswith(b"'''"):
        style = "'''"
    elif body.startswith(b'"'):
        style = '"'
    elif body.startswith(b"'"):
        style = "'"

    if style in ('"""', "'''"):
        if '\\' not in value and style not in value and not value.endswith(style[0]):
            return style + value + style
    elif style in ('"', "'"):
        if '\n' not in value and '\\' not in value and style not in value:
            return style + value + style

    return repr(value)


def fstring_tr_replacements(
    source_bytes: bytes,
    offsets: list[int],
    tree: ast.Module,
    move_tr_strings: bool = False,
) -> tuple[list[tuple[int, int, bytes]], frozenset[int], dict[str, dict[str, str]]]:
    """Transform tr() calls whose first argument is an f-string.

    For ``tr(f"Hello {name}", fr=f"Bonjour {name}")``:
    - ``move_tr_strings=False`` →
        ``tr("Hello {name}", fr="Bonjour {name}").format(name=name)``
    - ``move_tr_strings=True``  →
        ``tr("Hello {name}").format(name=name)``

    Complex expressions inside the f-string (attribute access, method calls,
    arithmetic, ...) are supported via auto-generated ``_arg0``, ``_arg1``, ...
    placeholders:
        ``tr(f"Value {a.b()+1}")`` → ``tr("Value {_arg0}").format(_arg0=a.b()+1)``

    Returns:
        (replacements, handled_ids, extra_translations)

        *handled_ids*: AST node ids of calls handled here — pass to
        ``strip_tr_kwargs_replacements(exclude_ids=...)`` so it skips them.

        *extra_translations*: ``{source_text: {lang: translated_template}}``
        — translations recovered from f-string kwargs, to be merged before
        building ``_TRANSLATIONS`` (important when ``move_tr_strings=True``
        removes the kwargs from the source).
    """
    replacements: list[tuple[int, int, bytes]] = []
    handled_ids: set[int] = set()
    extra_translations: dict[str, dict[str, str]] = {}

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == 'tr'):
            continue
        if not node.args or not isinstance(node.args[0], ast.JoinedStr):
            continue
        first_arg = node.args[0]
        kwarg_fstrings = [kw for kw in node.keywords if isinstance(kw.value, ast.JoinedStr)]

        # Insertion order of name_map drives .format(...) arg order, so we
        # process the first arg first and let kwargs reuse existing names.
        name_map: dict[str, str] = {}
        first_template, ok = _render_fstring_template(first_arg, source_bytes, offsets, name_map)
        if not ok:
            continue
        kwarg_templates: list[tuple[ast.keyword, str]] = []
        for kw in kwarg_fstrings:
            tpl, ok = _render_fstring_template(kw.value, source_bytes, offsets, name_map)
            if not ok:
                break
            kwarg_templates.append((kw, tpl))
        if not ok:
            continue

        # --- Recover translations from f-string kwargs ---
        for kw, tpl in kwarg_templates:
            if kw.arg:
                extra_translations.setdefault(first_template, {})[kw.arg] = tpl

        # --- Build the new call source ---
        call_start, call_end = node_span(offsets, node)
        arg_start, arg_end   = node_span(offsets, first_arg)
        first_src = source_bytes[arg_start:arg_end]
        prefix    = source_bytes[call_start:arg_start]       # b'tr('
        first_literal = _quote_string_literal(first_template, first_src).encode('utf-8')

        if move_tr_strings:
            new_call = prefix + first_literal + b')'
        else:
            # Reconstruct call preserving original spacing between args; for
            # each f-string kwarg, swap in its rebuilt template literal.
            kwarg_tpl_by_id = {id(kw): tpl for kw, tpl in kwarg_templates}
            parts = [prefix, first_literal]
            prev_end = arg_end
            for kw in node.keywords:
                kw_val_start, kw_val_end = node_span(offsets, kw.value)
                separator = source_bytes[prev_end:kw_val_start]   # e.g. b', fr='
                if id(kw) in kwarg_tpl_by_id:
                    kw_src = source_bytes[kw_val_start:kw_val_end]
                    kw_val = _quote_string_literal(kwarg_tpl_by_id[id(kw)], kw_src).encode('utf-8')
                else:
                    kw_val = source_bytes[kw_val_start:kw_val_end]
                parts.append(separator + kw_val)
                prev_end = kw_val_end
            parts.append(b')')
            new_call = b''.join(parts)

        if name_map:
            fmt_args = ', '.join(f'{name}={expr}' for expr, name in name_map.items())
            new_call += f'.format({fmt_args})'.encode('utf-8')

        replacements.append((call_start, call_end, new_call))
        handled_ids.add(id(node))

    return replacements, frozenset(handled_ids), extra_translations


def change_default_language_replacements(
    source_bytes: bytes,
    offsets: list[int],
    tree: ast.Module,
    new_lang: str,
    merged: dict[str, dict[str, str | None]] | None = None,
    old_default: str | None = None,
) -> list[tuple[int, int, bytes]]:
    """Pivot the source language declarations and every tr() call to *new_lang*.

    Rewrites:
      - ``default_language = '...'`` value → ``new_lang``
      - literal first arg of ``make_tr('...')`` → ``new_lang`` (a ``Name`` arg
        like ``make_tr(default_language)`` is left untouched and inherits the
        new value via the ``default_language`` rewrite)
      - every ``tr("old", ...)`` call's first positional arg → its ``new_lang``
        translation (looked up in *merged*)
      - inline language kwargs on those ``tr()`` calls: drop the ``new_lang``
        kwarg (now redundant — it is the default); if the call already had any
        inline kwargs, add ``old_default="old_text"`` so the previous default
        text is preserved in the same inline-kwarg style. Calls with no inline
        kwargs are left without kwargs — the previous default text is carried
        by ``_TRANSLATIONS``.

    *merged* and *old_default* are required to rewrite tr() calls. When either
    is ``None`` only the declarations are rewritten. The caller is expected to
    have run :func:`validate_change_default_language` first; tr() calls without
    a string-Constant first arg, or without a non-None ``new_lang`` translation
    in *merged*, are silently skipped here.
    """
    replacements: list[tuple[int, int, bytes]] = []
    new_lang_bytes = f"'{new_lang}'".encode('utf-8')

    dl_node = find_default_language_node(tree)
    if dl_node and isinstance(dl_node.value, ast.Constant) and isinstance(dl_node.value.value, str):
        start, end = node_span(offsets, dl_node.value)
        replacements.append((start, end, new_lang_bytes))

    make_tr_node = find_make_tr_node(tree)
    if make_tr_node:
        call = make_tr_node.value
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            start, end = node_span(offsets, call.args[0])
            replacements.append((start, end, new_lang_bytes))

    if merged is None or old_default is None:
        return replacements

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == 'tr'):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        old_text = first.value
        xx_text = merged.get(old_text, {}).get(new_lang)
        if not isinstance(xx_text, str):
            continue

        call_start, call_end = node_span(offsets, node)
        arg_start, arg_end = node_span(offsets, first)
        prefix = source_bytes[call_start:arg_start]   # e.g. b'tr('
        new_first = repr(xx_text).encode('utf-8')

        had_inline_kwargs = bool(node.keywords)
        preserved: list[bytes] = []
        for kw in node.keywords:
            if kw.arg == new_lang:
                continue
            # kw.lineno/col_offset point at the start of the kwarg name (or the
            # '**' for **kwargs); kw.value's end is the end of the kwarg.
            kw_start = offsets[kw.lineno - 1] + kw.col_offset
            _, kw_end = node_span(offsets, kw.value)
            preserved.append(source_bytes[kw_start:kw_end])

        if had_inline_kwargs:
            preserved.append(f"{old_default}={old_text!r}".encode('utf-8'))

        parts: list[bytes] = [prefix, new_first]
        for piece in preserved:
            parts.append(b', ')
            parts.append(piece)
        parts.append(b')')
        replacements.append((call_start, call_end, b''.join(parts)))

    return replacements


def validate_change_default_language(
    tree: ast.Module,
    new_lang: str,
    merged: dict[str, dict[str, str | None]],
) -> list[str]:
    """Return human-readable error messages blocking a default-language pivot.

    Empty list means the file is ready. Errors are reported for:
      - ``tr()`` calls whose first arg is not a string ``Constant`` (variables,
        ``JoinedStr`` f-strings, complex expressions cannot be statically
        rewritten — lower or inline them before pivoting).
      - ``tr()`` literal first args without a non-None ``new_lang`` translation
        in *merged* (no inline kwarg AND no ``_TRANSLATIONS`` entry).
      - bare translatable strings still waiting to be wrapped (a sign the file
        has not been prepared yet — run ``prepare-sre-translations`` without
        ``--change-default-language`` first).
    """
    errors: list[str] = []

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == 'tr'):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            kind = type(first).__name__
            errors.append(
                f"line {first.lineno}: tr() first argument is {kind}, "
                f"not a string literal — lower f-strings/inline this call first"
            )
            continue
        text = first.value
        translation = merged.get(text, {}).get(new_lang)
        if not isinstance(translation, str):
            errors.append(
                f"line {first.lineno}: tr({text!r}) has no '{new_lang}' "
                f"translation (not in inline kwargs nor in _TRANSLATIONS)"
            )

    for node in find_translatable_nodes(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            snippet = node.value
        else:
            snippet = '<f-string>'
        errors.append(
            f"line {node.lineno}: bare translatable string {snippet!r} — run "
            f"prepare-sre-translations without --change-default-language first "
            f"to wrap it"
        )

    return errors


def rekey_merged_for_default_swap(
    merged: dict[str, dict[str, str | None]],
    new_lang: str,
    old_default: str,
) -> dict[str, dict[str, str | None]]:
    """Re-key the merged translation dict for a default-language pivot.

    Each old-source-text entry becomes a new-source-text entry. The ``new_lang``
    slot is dropped from each entry (it is the new source). The ``old_default``
    slot is added/overwritten with the old source text.

    Entries whose ``new_lang`` translation is missing or None are dropped (the
    caller is expected to have caught those via
    :func:`validate_change_default_language`).
    """
    out: dict[str, dict[str, str | None]] = {}
    for old_text, langs in merged.items():
        xx_text = langs.get(new_lang)
        if not isinstance(xx_text, str):
            continue
        new_langs = {lang: val for lang, val in langs.items() if lang != new_lang}
        new_langs[old_default] = old_text
        out[xx_text] = new_langs
    return out

# ---------------------------------------------------------------------------
# _TRANSLATIONS source builder
# ---------------------------------------------------------------------------

def _translation_literal(s: str | None) -> str:
    """Render a translation string as Python source.

    Multi-line strings become triple-quoted blocks with real newlines (readable
    markdown); everything else uses repr(). The content is written at column 0
    so the literal evaluates to the exact original string — required because
    source-language keys are matched against tr() arguments by exact equality.
    Falls back to repr() for anything that cannot be proven to round-trip.
    """
    if s is None:
        return 'None'
    if '\n' not in s or '\r' in s:        # single-line, or CR present -> safe repr
        return repr(s)
    body = s.replace('\\', '\\\\').replace('"""', '\\"\\"\\"')
    if body.endswith('"'):
        body = body[:-1] + '\\"'
    lit = '"""' + body + '"""'
    try:
        if ast.literal_eval(lit) == s:    # safety net: guarantee exact round-trip
            return lit
    except Exception:
        pass
    return repr(s)


def build_translations_source(translations: dict[str, dict[str, str | None]]) -> str:
    """Return Python source for a ``_TRANSLATIONS = {...}`` assignment."""
    if not translations:
        return '_TRANSLATIONS = {}'
    lines = ['_TRANSLATIONS = {']
    for lang in sorted(translations):
        lines.append(f'    {lang!r}: {{')
        for text, val in sorted(translations[lang].items()):
            lines.append(f'        {_translation_literal(text)}: {_translation_literal(val)},')
        lines.append('    },')
    lines.append('}')
    return '\n'.join(lines)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Migrate a lab .py file to the _TRANSLATIONS dict system.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('file', help='Path to the lab .py file')
    parser.add_argument(
        '--move-tr-strings', action='store_true',
        help='Strip inline lang kwargs from existing tr() calls, move to _TRANSLATIONS',
    )
    parser.add_argument(
        '--default-language', metavar='xx',
        help='Default language code (error if file already has a different one)',
    )
    parser.add_argument(
        '--change-default-language', metavar='xx',
        help='Pivot the file source language to xx: rewrite every tr() literal '
             'to its xx translation, re-key _TRANSLATIONS, and preserve the '
             'previous default as a regular language. Errors out if any tr() '
             'string lacks an xx translation or any translatable string is bare.',
    )
    parser.add_argument(
        '--translations-at-the-end', action='store_true',
        help='Place _TRANSLATIONS at the end of the file; inline kwargs are '
             'kept/added on import-time tr() calls (module/class body) so they '
             'do not depend on the late _TRANSLATIONS definition',
    )
    parser.add_argument(
        '--translate-isolated-words', action='store_true',
        help='Wrap single-token bare strings (no space/tab/newline) in tr() as '
             'well. By default they are wrapped in no_tr() and not translated.',
    )
    args = parser.parse_args()

    if args.default_language and args.change_default_language:
        print("Error: --default-language and --change-default-language are incompatible.", file=sys.stderr)
        sys.exit(1)

    path = Path(args.file)
    if not path.exists():
        print(f"Error: '{path}' not found.", file=sys.stderr)
        sys.exit(1)

    source = path.read_text(encoding='utf-8')
    source_bytes = source.encode('utf-8')

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Syntax error in '{path}': {e}", file=sys.stderr)
        sys.exit(1)

    is_multilingual, default_lang = detect_multilingual(tree)
    offsets = build_line_offsets(source_bytes)

    # --- Determine effective target (default) language ---
    if args.default_language:
        if default_lang and default_lang != args.default_language:
            print(
                f"Error: file has default_language='{default_lang}', "
                f"conflicts with --default-language '{args.default_language}'.",
                file=sys.stderr,
            )
            sys.exit(1)
        target_lang = args.default_language
    elif args.change_default_language:
        if not is_multilingual or default_lang is None:
            print(
                "Error: --change-default-language requires the file to declare "
                "a default_language and import tr/make_tr.",
                file=sys.stderr,
            )
            sys.exit(1)
        if default_lang == args.change_default_language:
            print(
                f"Error: --change-default-language '{args.change_default_language}' "
                f"matches the file's current default_language.",
                file=sys.stderr,
            )
            sys.exit(1)
        target_lang = args.change_default_language
    elif default_lang:
        target_lang = default_lang
    else:
        target_lang = 'en'   # sensible default when no language is declared

    # --- Collect translations from original source before any modifications ---
    inline_by_text  = collect_inline_translations(tree)   # {text: {lang: val}}
    existing_dict   = get_existing_translations(tree)      # {lang: {text: val}}

    # Merge: existing _TRANSLATIONS wins over inline kwargs on conflict.
    merged: dict[str, dict[str, str | None]] = {}
    for text, langs in inline_by_text.items():
        merged[text] = dict(langs)
    for lang, strings in existing_dict.items():
        for text, val in strings.items():
            merged.setdefault(text, {})[lang] = val   # existing wins

    # --- Validate the change-default-language pivot before any rewrites ---
    if args.change_default_language:
        errors = validate_change_default_language(tree, target_lang, merged)
        if errors:
            print(
                f"Error: cannot pivot '{path}' to default language "
                f"'{target_lang}' ({len(errors)} issue(s)):",
                file=sys.stderr,
            )
            for e in errors:
                print(f"  {e}", file=sys.stderr)
            print(
                f"\nFill in missing '{target_lang}' translations first, e.g.:\n"
                f"  add-sre-translations --language {target_lang} {path}",
                file=sys.stderr,
            )
            sys.exit(1)

    # -----------------------------------------------------------------------
    # Pass A — wrap bare translatable strings/f-strings in tr(); change the
    # default language; add the import/setup block. Computed from the original
    # tree and applied as one batch. Bare f-strings become tr(f"...") here and
    # are lowered to tr("...").format(...) in pass B (which re-parses first, so
    # the freshly-wrapped calls are visible to the f-string handler).
    # -----------------------------------------------------------------------
    replacements_a: list[tuple[int, int, bytes]] = []

    if args.change_default_language:
        replacements_a += change_default_language_replacements(
            source_bytes, offsets, tree, args.change_default_language,
            merged=merged, old_default=default_lang)
        # The pivot path does only the pivot — validation already ensured no
        # bare translatable strings remain, so wrap_replacements would be a
        # no-op and we skip the partitioning bookkeeping.
        tr_nodes: list[ast.AST] = []
        notr_nodes: list[ast.AST] = []
    else:
        bare_nodes = find_translatable_nodes(tree)

        # Partition bare nodes: by default, plain string literals with no
        # whitespace (space/tab/newline) are wrapped in no_tr() rather than tr()
        # so short internal labels (machine names, identifier-like tokens) stay
        # out of _TRANSLATIONS. F-strings always go through tr() — they interpolate
        # runtime values, so "no whitespace in the literal part" is not a useful
        # signal. --translate-isolated-words restores the prior wrap-everything
        # behaviour.
        if args.translate_isolated_words:
            tr_nodes, notr_nodes = bare_nodes, []
        else:
            notr_nodes = [
                n for n in bare_nodes
                if isinstance(n, ast.Constant)
                and isinstance(n.value, str)
                and not any(c in n.value for c in ' \t\n')
            ]
            notr_ids = {id(n) for n in notr_nodes}
            tr_nodes = [n for n in bare_nodes if id(n) not in notr_ids]

        replacements_a += _wrap_replacements(source_bytes, offsets, tr_nodes)
        replacements_a += _wrap_replacements(source_bytes, offsets, notr_nodes, b'no_tr')

    # Ensure no_tr is imported when the file opts strings out via no_tr(...),
    # or when we are about to introduce no_tr() wrappers ourselves.
    # When the setup block is also being added (non-multilingual file) fold it
    # into that single import edit to avoid two replacements touching the same
    # import line.
    uses_no_tr = _calls_function(tree, 'no_tr') or bool(notr_nodes)
    if not is_multilingual:
        replacements_a += _import_setup_replacements(
            source_bytes, tree, offsets, target_lang,
            extra_names=('no_tr',) if uses_no_tr else ())
    elif uses_no_tr:
        replacements_a += _add_lib_sre_imports(source_bytes, tree, offsets, ['no_tr'])

    source_bytes_a = apply_replacements(source_bytes, replacements_a)

    # After the language pivot, re-key the in-memory merged dict so the rest of
    # the pipeline (which runs with target_lang=new_lang) builds _TRANSLATIONS
    # with the right inner keys and the previous default as a regular language.
    if args.change_default_language:
        merged = rekey_merged_for_default_swap(merged, target_lang, default_lang)

    try:
        tree_a = ast.parse(source_bytes_a.decode('utf-8'))
    except SyntaxError as e:
        print(f"Internal error: wrap pass output has syntax error: {e}", file=sys.stderr)
        sys.exit(1)
    offsets_a = build_line_offsets(source_bytes_a)

    # -----------------------------------------------------------------------
    # Pass B — lower every tr(f"...") call (pre-existing and the ones just
    # wrapped in pass A) to tr("...").format(...), and strip inline lang kwargs
    # when --move-tr-strings. Computed from the pass-A tree.
    #   tr(f"x {v}", fr=f"y {v}") → tr("x {v}", fr="y {v}").format(v=v)
    # F-string lowering must run before strip_tr_kwargs so it can handle both in
    # one replacement per call.
    # -----------------------------------------------------------------------
    replacements_b: list[tuple[int, int, bytes]] = []

    fstr_repls, fstr_ids, fstr_extra = fstring_tr_replacements(
        source_bytes_a, offsets_a, tree_a, move_tr_strings=bool(args.move_tr_strings))
    replacements_b += fstr_repls

    # Merge translations recovered from f-string kwargs into merged dict.
    for text, langs in fstr_extra.items():
        for lang, val in langs.items():
            merged.setdefault(text, {}).setdefault(lang, val)

    # When _TRANSLATIONS is parked at the end of the file, every tr() call
    # in the module/class body executes before _TRANSLATIONS exists. Keep its
    # inline kwargs so the translation comes from the call itself.
    import_time_tr_ids = (find_import_time_tr_call_ids(tree_a)
                          if args.translations_at_the_end else set())

    if args.move_tr_strings:
        replacements_b += strip_tr_kwargs_replacements(
            source_bytes_a, offsets_a, tree_a,
            exclude_ids=fstr_ids | frozenset(import_time_tr_ids))

    source_bytes_v1 = apply_replacements(source_bytes_a, replacements_b)

    # -----------------------------------------------------------------------
    # Re-parse after pass B to get accurate positions for the _TRANSLATIONS pass
    # -----------------------------------------------------------------------
    try:
        tree_v1 = ast.parse(source_bytes_v1.decode('utf-8'))
    except SyntaxError as e:
        print(f"Internal error: pass-B output has syntax error: {e}", file=sys.stderr)
        sys.exit(1)
    offsets_v1 = build_line_offsets(source_bytes_v1)

    # Collect all tr() source strings from the modified file.
    all_tr_strings = collect_tr_strings(tree_v1)

    # Ensure every wrapped string has a slot in merged.
    for s in all_tr_strings:
        merged.setdefault(s, {})

    # -----------------------------------------------------------------------
    # Pass B.5 — when --translations-at-the-end is set, inject all known
    # translations as inline kwargs on import-time tr() calls (module/class
    # body). They run before the late _TRANSLATIONS definition, so they must
    # carry their translations themselves.
    # -----------------------------------------------------------------------
    if args.translations_at_the_end:
        import_time_ids_v1 = find_import_time_tr_call_ids(tree_v1)
        inline_repls = add_tr_kwargs_replacements(
            source_bytes_v1, offsets_v1, tree_v1,
            import_time_ids_v1, merged, target_lang,
        )
        if inline_repls:
            source_bytes_v1 = apply_replacements(source_bytes_v1, inline_repls)
            try:
                tree_v1 = ast.parse(source_bytes_v1.decode('utf-8'))
            except SyntaxError as e:
                print(f"Internal error: pass-B.5 output has syntax error: {e}", file=sys.stderr)
                sys.exit(1)
            offsets_v1 = build_line_offsets(source_bytes_v1)

    # Languages to include in _TRANSLATIONS (exclude the default language itself).
    # Seed from merged text-level lang keys AND from existing_dict top-level keys
    # (an empty {'fr': {}} in _TRANSLATIONS still declares 'fr' as a target language).
    known_langs: set[str] = set(existing_dict.keys())
    for langs in merged.values():
        known_langs.update(langs.keys())
    known_langs.discard(target_lang)

    # Build the final _TRANSLATIONS structure: one entry per lang per string,
    # None for missing translations. When no target language is known yet the
    # comprehension yields {}, and we still emit an empty `_TRANSLATIONS = {}`
    # anchor so `add-sre-translations --language XX` has something to fill in.
    final_translations: dict[str, dict[str, str | None]] = {
        lang: {text: merged.get(text, {}).get(lang) for text in sorted(all_tr_strings)}
        for lang in sorted(known_langs)
    }

    translations_src = build_translations_source(final_translations)

    # -----------------------------------------------------------------------
    # Pass 2 — insert or replace _TRANSLATIONS
    # -----------------------------------------------------------------------
    replacements_2: list[tuple[int, int, bytes]] = []
    existing_node = find_translations_node(tree_v1)

    if args.translations_at_the_end:
        already_at_end = (existing_node is not None
                          and tree_v1.body
                          and tree_v1.body[-1] is existing_node)
        if already_at_end:
            start, end = node_span(offsets_v1, existing_node)
            replacements_2.append((start, end, translations_src.encode('utf-8')))
            action = "Updated"
        else:
            if existing_node:
                # Delete the existing block (extend through one trailing
                # newline so we don't leave a blank line behind).
                start, end = node_span(offsets_v1, existing_node)
                while end < len(source_bytes_v1) and source_bytes_v1[end:end + 1] != b'\n':
                    end += 1
                if end < len(source_bytes_v1):
                    end += 1
                replacements_2.append((start, end, b''))
                action = "Moved"
            else:
                action = "Inserted"
            append_pos = len(source_bytes_v1)
            prefix = b'' if source_bytes_v1.endswith(b'\n') else b'\n'
            replacements_2.append(
                (append_pos, append_pos,
                 prefix + translations_src.encode('utf-8') + b'\n'))
    elif existing_node:
        start, end = node_span(offsets_v1, existing_node)
        replacements_2.append((start, end, translations_src.encode('utf-8')))
        action = "Updated"
    else:
        # Insert after tr = make_tr(...) line, or after default_language = ...
        anchor = find_make_tr_node(tree_v1) or find_default_language_node(tree_v1)
        if anchor:
            _, end = node_span(offsets_v1, anchor)
            # Advance to end of line.
            while end < len(source_bytes_v1) and source_bytes_v1[end:end + 1] != b'\n':
                end += 1
            insert_pos = end + 1   # position after the \n
        else:
            insert_pos = 0
        replacements_2.append((insert_pos, insert_pos, (translations_src + '\n').encode('utf-8')))
        action = "Inserted"

    final_bytes = apply_replacements(source_bytes_v1, replacements_2)
    path.write_text(final_bytes.decode('utf-8'), encoding='utf-8')
    _report(tr_nodes, notr_nodes, all_tr_strings, known_langs, action)


def _report(
    tr_nodes: list,
    notr_nodes: list,
    all_tr_strings,
    known_langs: set[str],
    action: str = '',
) -> None:
    if tr_nodes or notr_nodes:
        msg = f"Wrapped {len(tr_nodes)} bare string(s) in tr()"
        if notr_nodes:
            msg += f", {len(notr_nodes)} in no_tr()"
        print(msg + ".")
    if action:
        if known_langs:
            langs_str = ', '.join(sorted(known_langs))
            print(f"{action} _TRANSLATIONS "
                  f"({len(all_tr_strings)} string(s), languages: {langs_str}).")
        else:
            print(f"{action} empty _TRANSLATIONS (no target languages yet — run "
                  f"add-sre-translations --language XX to fill it in).")


if __name__ == '__main__':
    main()
