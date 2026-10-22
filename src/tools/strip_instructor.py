#!/usr/bin/env python3
"""strip-instructor — Write a lab .py file without its instructor() calls, and with --full
without its solution states either.

Usage:
    strip-instructor [--full] project.py output
    strip-instructor [--full] -i project.py

`output` is the file to write, or an existing directory: the file is then written there
under the name of the project file. With -i the project file itself is replaced.

The lab behaves as before outside the instructor mode, where instructor() returns an empty
text; the notes of the instructor are no longer in the file:

  1. Every call of instructor() is removed (also under an alias, `from SRE.lib_sre import
     instructor as note`, and as an attribute, `lib_sre.instructor(...)`).
       instructor(tr("note")) + tr("public")   →  tr("public")
       tr("Q") + instructor(" (answer)")       →  tr("Q")
       a + instructor(b) + c                   →  a + c
     A call that is not an operand of `+` is replaced by an empty string:
       self.informations = instructor(tr("note"))   →  self.informations = ''
  2. The entries of _TRANSLATIONS whose key is a tr() string used only inside the removed
     calls are deleted, in every language.
  3. `instructor` is removed from its `from ... import` statement when nothing uses it
     any more.

With --full (no short form) the states students cannot apply are removed as well, so that
the file holds no solution any more:

  4. Every method decorated with @sre_state is removed, decorator included, unless it is
     `initial`, a lifecycle state (`save`, `restore`: `sre save` / `sre restore` apply them)
     or user-allowed (`@sre_state(user_allowed=True, ...)`). The _TRANSLATIONS entries only
     those methods used go with them (rule 2), and `sre_state` leaves its import when no
     state is left (rule 3).
  5. The `cheat_answers={...}` of the questions lose the entries keyed by a removed state;
     the keyword disappears when no entry is left.
  6. A removed state that a kept method still uses (`self.final()` in `restore`) makes the
     file refused: the result would either fail or keep the solution.

Formatting and comments are kept. The result is checked (it must parse and hold no
instructor() call, nor removed state with --full); on error nothing is written.

Limits:
  - Comments are left alone, except one standing between an operand and the removed `+`.
  - A text kept in a variable is not followed: `note = tr("...")` then `instructor(note)`
    leaves the definition of `note` in the file (a warning names such variables).
  - With --full, the helper methods and the variables that only the removed states (or
    their cheat_answers) used are left in the file as well: a warning names them.
  - Only this file is processed, not the state directories of a directory lab (with --full
    a warning names the directory of a removed state next to a `srelab.py`).
  - A question keeps its hash as long as the removed text has no language that the text it
    was added to lacks (the usual case: both are tr() texts translated alike). Otherwise
    the archives of the stripped lab do not match the original lab in `sre re-eval`.

NOTE: AST col_offset/end_col_offset are UTF-8 byte offsets; all position
arithmetic is done on UTF-8-encoded source bytes.
"""

import argparse
import ast
import builtins
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# prepare_sre_translations lives in the same directory
sys.path.insert(0, str(Path(__file__).parent))
from prepare_sre_translations import (  # noqa: E402
    apply_replacements, build_line_offsets, find_translations_node, node_span,
)

FUNCTION = 'instructor'
STATE_DECORATOR = 'sre_state'
# the states every lab keeps with --full: `initial` and the lifecycle states (the names of
# params.lifecycle_state_names: this tool imports no SRE module), applied by `sre start`,
# `sre save` and `sre restore`
KEPT_STATES = ('initial', 'save', 'restore')
CHEAT_KEYWORD = 'cheat_answers'     # question_text(..., cheat_answers={state: answers}) of Grade0
SRELAB_FILENAME = 'srelab.py'       # the lab file of a directory lab, whose state directories stand next to it
EMPTY_TEXT = b"''"
# the kinds of removed source spans, and how the warnings name them
VOID_INSTRUCTOR, VOID_STATE, VOID_CHEAT = 'instructor', 'state', 'cheat'
_VOID_TEXTS = {VOID_INSTRUCTOR: f'{FUNCTION}()', VOID_STATE: 'the removed states',
               VOID_CHEAT: f'the removed {CHEAT_KEYWORD}'}
# names that say nothing about the instructor texts when they only appear inside the calls
_UNREPORTED_NAMES = {'tr', 'no_tr', 'self', 'cls'} | set(dir(builtins))


class StripError(Exception):
    """The file cannot be stripped (it does not parse, or the result would be wrong)."""


@dataclass
class StripResult:
    data: bytes                 # the stripped source
    calls: int = 0              # instructor() calls removed
    translations: int = 0       # _TRANSLATIONS entries removed
    import_removed: bool = False    # a name (instructor, sre_state) removed from an import
    states: list = field(default_factory=list)  # names of the states removed (--full)
    cheat_entries: int = 0      # cheat_answers entries removed (--full)
    warnings: list = field(default_factory=list)


def _local_names(tree: ast.Module, function: str) -> set:
    """Local names of a function of SRE.lib_sre: its own, and its aliases (`import f as x`)."""
    names = {function}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names |= {alias.asname for alias in node.names if alias.name == function and alias.asname}
    return names


def _instructor_names(tree: ast.Module) -> set:
    """Local names of the function: `instructor`, and its aliases (`import instructor as x`)."""
    return _local_names(tree, FUNCTION)


def _is_instructor_call(node: ast.AST, names: set) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return ((isinstance(func, ast.Name) and func.id in names)
            or (isinstance(func, ast.Attribute) and func.attr == FUNCTION))


def _tr_string(node: ast.AST):
    """The source text of a `tr("...")` call, else None."""
    if not isinstance(node, ast.Call) or not node.args:
        return None
    func = node.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    arg = node.args[0]
    return arg.value if name == 'tr' and isinstance(arg, ast.Constant) and isinstance(arg.value, str) else None


def _state_decorator(fn: ast.FunctionDef, names: set):
    """The @sre_state decorator of a method (`sre_state`, `sre_state(...)` or `x.sre_state(...)`
    node), else None."""
    for decorator in fn.decorator_list:
        func = decorator.func if isinstance(decorator, ast.Call) else decorator
        if ((isinstance(func, ast.Name) and func.id in names)
                or (isinstance(func, ast.Attribute) and func.attr == STATE_DECORATOR)):
            return decorator
    return None


def _state_kept(fn: ast.FunctionDef, decorator: ast.AST, warnings: list) -> bool:
    """Whether a state stays in the stripped file: initial, a lifecycle state, or user-allowed."""
    if fn.name in KEPT_STATES:
        return True
    if isinstance(decorator, ast.Call):
        for keyword in decorator.keywords:
            if keyword.arg == 'user_allowed':
                if isinstance(keyword.value, ast.Constant):
                    return bool(keyword.value.value)
                warnings.append(f"line {fn.lineno}: the user_allowed value of the state '{fn.name}' is not a "
                                "literal: the state is kept")
                return True
    return False


class _Stripper:
    def __init__(self, data: bytes, tree: ast.Module):
        self.data = data
        self.tree = tree
        self.offsets = build_line_offsets(data)
        self.names = _instructor_names(tree)
        self.state_names = _local_names(tree, STATE_DECORATOR)
        self.edits = []         # (start, end, replacement)
        self.void_spans = []    # (start, end, kind): byte spans of the removed source
        self.removed_states = []    # the FunctionDef nodes removed by --full
        self.state_classes = []     # the ClassDef nodes they belong to
        self.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def span(self, node: ast.AST):
        return node_span(self.offsets, node)

    def void_kinds(self, node: ast.AST) -> set:
        """The kinds of the removed spans holding *node* (empty when it stays)."""
        if not hasattr(node, 'lineno'):     # Module, operators, contexts...
            return set()
        start, end = self.span(node)
        return {kind for void_start, void_end, kind in self.void_spans if void_start <= start and end <= void_end}

    def in_void(self, node: ast.AST) -> bool:
        return bool(self.void_kinds(node))

    def _where(self, kinds: set) -> str:
        return ' and '.join(_VOID_TEXTS[kind] for kind in (VOID_INSTRUCTOR, VOID_STATE, VOID_CHEAT) if kind in kinds)

    def _enclosing_function(self, node: ast.AST):
        while node is not None:
            node = self.parents.get(node)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return None

    def _line_end(self, position: int) -> int:
        """Offset right after the newline ending the line holding *position*."""
        newline = self.data.find(b'\n', position)
        return len(self.data) if newline == -1 else newline + 1

    def _skip_blanks(self, position: int) -> int:
        while self.data[position:position + 1] in (b' ', b'\t'):
            position += 1
        return position

    def _alone_on_its_lines(self, start: int, end: int) -> bool:
        """Nothing but whitespace stands before *start* on its line and after *end* on its line."""
        line_start = self.data.rfind(b'\n', 0, start) + 1
        return not self.data[line_start:start].strip() and self.data[end:end + 1] in (b'\n', b'\r', b'')

    # -- the calls -----------------------------------------------------------------------

    def is_void(self, node: ast.AST) -> bool:
        """An instructor() call, or a `+` of two of them: an expression that is entirely an
        instructor text."""
        if _is_instructor_call(node, self.names):
            return True
        return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
                and self.is_void(node.left) and self.is_void(node.right))

    def _operator_gap(self, left: ast.AST, right: ast.AST):
        """For `left + right`: (end of the left operand, its closing parentheses included,
        start of the right operand, its opening parentheses included).  Between the two nodes
        stand only parentheses, whitespace, comments, `\\` and the operator."""
        position, end = self.span(left)[1], self.span(right)[0]
        left_end = position
        operator_seen = False
        while position < end:
            char = self.data[position:position + 1]
            if char == b'#':
                newline = self.data.find(b'\n', position, end)
                if newline == -1:
                    break
                position = newline
                continue
            if not operator_seen:
                if char == b')':
                    left_end = position + 1
                elif char == b'+':
                    operator_seen = True
            elif char not in b' \t\r\n\\':
                return left_end, position
            position += 1
        return left_end, end

    def _remove(self, node: ast.AST, start: int, end: int, replacement: bytes = b''):
        self.void_spans.append((*self.span(node), VOID_INSTRUCTOR))
        self.edits.append((start, end, replacement))

    def visit(self, node: ast.AST):
        if self.in_void(node):      # inside a removed state or cheat_answers: gone already
            return
        if self.is_void(node):
            self._remove(node, *self.span(node), EMPTY_TEXT)
            return
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_void, right_void = self.is_void(node.left), self.is_void(node.right)
            if left_void or right_void:
                left_end, right_start = self._operator_gap(node.left, node.right)
                if left_void:       # `void + right`: the node becomes its right operand
                    self._remove(node.left, self.span(node)[0], right_start)
                    self.visit(node.right)
                else:               # `left + void`: the node becomes its left operand
                    self._remove(node.right, left_end, self.span(node)[1])
                    self.visit(node.left)
                return
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    # -- the states (--full) -------------------------------------------------------------

    def _state_methods(self):
        """(class, method, decorator) for every @sre_state method of the module."""
        for cls in ast.walk(self.tree):
            if isinstance(cls, ast.ClassDef):
                for fn in cls.body:
                    if isinstance(fn, ast.FunctionDef):
                        decorator = _state_decorator(fn, self.state_names)
                        if decorator is not None:
                            yield cls, fn, decorator

    def states_to_remove(self, warnings: list) -> list:
        """(class, method) of the states that are neither initial, lifecycle nor user-allowed."""
        return [(cls, fn) for cls, fn, decorator in self._state_methods() if not _state_kept(fn, decorator, warnings)]

    def _method_edit(self, fn: ast.FunctionDef, as_pass: bool):
        """Deletion of a decorated method: its decorators and body, with the blank lines above
        them; with *as_pass*, `pass` in their place (the class would be left without a body)."""
        first = min(self.span(decorator)[0] for decorator in fn.decorator_list)   # after the `@`
        line_start = self.data.rfind(b'\n', 0, first) + 1
        end = self.span(fn)[1]
        if as_pass:
            at = self.data.find(b'@', line_start, first)
            return (first if at == -1 else at), end, b'pass'
        start = line_start
        while start > 0:        # the blank lines above go with the method
            previous = self.data.rfind(b'\n', 0, start - 1) + 1
            if self.data[previous:start].strip():
                break
            start = previous
        return start, self._line_end(end), b''

    def strip_states(self, warnings: list) -> list:
        """Remove the states that are neither initial, lifecycle nor user-allowed; their names."""
        names = []
        by_class = {}
        for cls, fn in self.states_to_remove(warnings):
            by_class.setdefault(cls, []).append(fn)
        for cls, fns in by_class.items():
            whole_body = len(fns) == len(cls.body)
            for fn in fns:
                self.edits.append(self._method_edit(fn, as_pass=whole_body and fn is cls.body[0]))
                first = min(self.span(decorator)[0] for decorator in fn.decorator_list)
                self.void_spans.append((first, self.span(fn)[1], VOID_STATE))
                self.removed_states.append(fn)
                if fn.name not in names:
                    names.append(fn.name)
            self.state_classes.append(cls)
        return names

    def check_references(self):
        """Refuse a kept method that uses a removed state (`self.final()`): the result would
        either fail or have to keep the solution."""
        removed = {fn.name for fn in self.removed_states}
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Attribute) and node.attr in removed and isinstance(node.value, ast.Name)
                    and node.value.id in ('self', 'cls') and not self.in_void(node)):
                function = self._enclosing_function(node)
                where = f"{function.name}()" if function is not None else "the module"
                raise StripError(f"line {node.lineno}: {where} uses {node.value.id}.{node.attr} while the state "
                                 f"'{node.attr}' is removed: move the shared code to a helper method, or make "
                                 "the state user-allowed")

    def _separator_after(self, position: int, limit: int) -> int:
        """Offset of the first `,` after *position* (before *limit*), comments skipped."""
        while position < limit:
            char = self.data[position:position + 1]
            if char == b'#':
                newline = self.data.find(b'\n', position, limit)
                if newline == -1:
                    break
                position = newline
                continue
            if char == b',':
                return position
            position += 1
        return limit

    def _keyword_edit(self, call: ast.Call, keyword: ast.keyword):
        """Deletion of one keyword argument of a call with its separating comma: of its whole
        lines when it stands alone on them (its trailing comma included)."""
        start, end = self.span(keyword)
        after = self._skip_blanks(end)
        if self.data[after:after + 1] == b',':
            after = self._skip_blanks(after + 1)
        if self._alone_on_its_lines(start, after):
            return self.data.rfind(b'\n', 0, start) + 1, self._line_end(after), b''
        arguments = sorted(call.args + call.keywords, key=lambda node: self.span(node)[0])
        index = arguments.index(keyword)
        if index + 1 < len(arguments):      # up to the next argument
            return start, self.span(arguments[index + 1])[0], b''
        if index > 0:                       # the last one: from the comma after the previous argument
            # (a parenthesised value ends after its node: the `)` stays with it)
            return self._separator_after(self.span(arguments[index - 1])[1], start), end, b''
        return start, end, b''

    def strip_cheat_answers(self, warnings: list) -> int:
        """Remove the cheat_answers entries keyed by a removed state, the whole keyword when
        no entry is left."""
        removed = {fn.name for fn in self.removed_states}
        count = 0
        for call in ast.walk(self.tree):
            if not isinstance(call, ast.Call) or self.in_void(call):
                continue
            for keyword in call.keywords:
                if keyword.arg != CHEAT_KEYWORD:
                    continue
                if not isinstance(keyword.value, ast.Dict):
                    warnings.append(f"line {keyword.lineno}: {CHEAT_KEYWORD} is not a literal dict: the answers "
                                    "of the removed states, if any, are still in the file")
                    continue
                entries = list(zip(keyword.value.keys, keyword.value.values))
                doomed = [(key, value) for key, value in entries
                          if isinstance(key, ast.Constant) and key.value in removed]
                if not doomed:
                    continue
                count += len(doomed)
                if len(doomed) == len(entries):
                    self.edits.append(self._keyword_edit(call, keyword))
                    self.void_spans.append((*self.span(keyword), VOID_CHEAT))
                else:
                    for key, value in doomed:
                        self.edits.append(self._entry_edit(key, value))
                        self.void_spans.append((self.span(key)[0], self.span(value)[1], VOID_CHEAT))
        return count

    def unused_methods(self) -> list:
        """Warnings for the methods that only the removed states (or their cheat answers) use."""
        removed = {id(fn) for fn in self.removed_states}
        warnings = []
        for cls in self.state_classes:
            methods = {node.name: node for node in cls.body
                       if isinstance(node, ast.FunctionDef) and id(node) not in removed
                       and _state_decorator(node, self.state_names) is None}
            inside, outside = {}, set()
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Attribute) and node.attr in methods:
                    kinds = self.void_kinds(node)
                    if kinds:
                        inside.setdefault(node.attr, set()).update(kinds)
                    else:
                        outside.add(node.attr)
            for name in sorted(set(inside) - outside, key=lambda n: methods[n].lineno):
                warnings.append(f"line {methods[name].lineno}: the method '{name}' is only used inside "
                                f"{self._where(inside[name])}: its definition is left in the file")
        return warnings

    # -- _TRANSLATIONS -------------------------------------------------------------------

    def _entry_edit(self, key: ast.AST, value: ast.AST):
        """Deletion of one `key: value,` entry of a dict; of its whole lines when it stands
        alone on them; with the comma before it when it is the last entry of its line."""
        start, end = self.span(key)[0], self.span(value)[1]
        end = self._skip_blanks(end)
        if self.data[end:end + 1] == b',':
            end = self._skip_blanks(end + 1)
        elif self._alone_on_its_lines(start, end):
            pass
        else:       # `{..., key: value}`: the separating comma goes with the entry
            before = start
            while self.data[before - 1:before] in (b' ', b'\t', b'\n', b'\r') and before > 0:
                before -= 1
            if self.data[before - 1:before] == b',':
                start = before - 1
        if self._alone_on_its_lines(start, end):
            start = self.data.rfind(b'\n', 0, start) + 1
            end = self._line_end(end)
        return start, end, b''

    def strip_translations(self, warnings: list) -> int:
        """Remove the entries of _TRANSLATIONS for the tr() strings that only the removed
        calls (and states) used."""
        removed_strings, kept_strings = set(), set()
        for node in ast.walk(self.tree):
            text = _tr_string(node)
            if text is not None:
                (removed_strings if self.in_void(node) else kept_strings).add(text)
        removed_strings -= kept_strings
        translations = find_translations_node(self.tree)
        if not removed_strings or translations is None:
            return 0
        languages = translations.value
        if not isinstance(languages, ast.Dict) or not all(isinstance(v, ast.Dict) for v in languages.values):
            warnings.append(f"line {translations.lineno}: _TRANSLATIONS is not a literal dict of dicts: "
                            "the translations of the removed texts, if any, are still in the file")
            return 0
        count = 0
        for language in languages.values:
            for key, value in zip(language.keys, language.values):
                if isinstance(key, ast.Constant) and key.value in removed_strings:
                    self.edits.append(self._entry_edit(key, value))
                    count += 1
        return count

    # -- the imports ---------------------------------------------------------------------

    def _is_whole_block(self, statement: ast.stmt) -> bool:
        """True when *statement* is the only one of an indented block (which cannot be empty)."""
        for parent in ast.walk(self.tree):
            if isinstance(parent, ast.Module):
                continue
            for _, value in ast.iter_fields(parent):
                if isinstance(value, list) and len(value) == 1 and value[0] is statement:
                    return True
        return False

    def _statement_edit(self, node: ast.stmt):
        """Deletion of a statement: of its lines when it stands alone on them, else `pass`."""
        start, end = self.span(node)
        line_start = self.data.rfind(b'\n', 0, start) + 1
        line_end = self._line_end(end)
        alone_on_its_lines = not self.data[line_start:start].strip() and not self.data[end:line_end].strip()
        if alone_on_its_lines and not self._is_whole_block(node):
            return line_start, line_end, b''
        return start, end, b'pass'

    def strip_import(self, functions: set) -> bool:
        """Remove the given functions of SRE.lib_sre from their `from ... import` statements
        once nothing uses them (under their local names)."""
        used = {node.id for node in ast.walk(self.tree) if isinstance(node, ast.Name) and not self.in_void(node)}
        removed = False
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            indexes = [i for i, alias in enumerate(node.names)
                       if alias.name in functions and (alias.asname or alias.name) not in used]
            if not indexes:
                continue
            removed = True
            if len(indexes) == len(node.names):
                self.edits.append(self._statement_edit(node))
                continue
            i = 0
            while i < len(indexes):     # one edit per run of consecutive names
                j = i
                while j + 1 < len(indexes) and indexes[j + 1] == indexes[j] + 1:
                    j += 1
                first, last = indexes[i], indexes[j]
                if last + 1 < len(node.names):      # up to the next name
                    self.edits.append((self.span(node.names[first])[0], self.span(node.names[last + 1])[0], b''))
                else:                               # the last names: from the end of the previous one
                    self.edits.append((self.span(node.names[first - 1])[1], self.span(node.names[last])[1], b''))
                i = j + 1
        return removed

    # -- names only the removed code used ------------------------------------------------

    def unfollowed_names(self) -> list:
        """Warnings for the variables that only the removed code reads while a value assigned
        to them stays in the file: most likely an instructor text kept in a variable, or the
        answers of a removed state."""
        defined = {}    # name -> line of its first assignment whose value stays
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None or self.in_void(node.value):
                continue
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if isinstance(target, ast.Name):
                    defined.setdefault(target.id, node.lineno)
        inside, outside = {}, set()     # inside: name -> kinds of the removed spans reading it
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                kinds = self.void_kinds(node)
                if kinds:
                    inside.setdefault(node.id, set()).update(kinds)
                else:
                    outside.add(node.id)
        warnings = []
        for name in sorted(set(inside) - outside - self.names - _UNREPORTED_NAMES, key=lambda n: defined.get(n, 0)):
            if name not in defined:
                continue
            if inside[name] == {VOID_INSTRUCTOR}:
                warnings.append(f"line {defined[name]}: '{name}' is only used inside {FUNCTION}() but defined "
                                "outside: its definition is left in the file (wrap the text in "
                                f"{FUNCTION}() where it is assigned to remove it)")
            else:
                warnings.append(f"line {defined[name]}: '{name}' is only used inside {self._where(inside[name])} "
                                "but defined outside: its definition is left in the file")
        return warnings


def strip_source(data: bytes, full: bool = False) -> StripResult:
    """Return the source *data* of a lab file without its instructor() calls; with *full*,
    without the states students cannot apply either (see the module docstring)."""
    try:
        tree = ast.parse(data)
    except SyntaxError as e:
        raise StripError(f"line {e.lineno}: {e.msg}") from e
    stripper = _Stripper(data, tree)
    result = StripResult(data, calls=sum(_is_instructor_call(node, stripper.names) for node in ast.walk(tree)))
    if full:
        result.states = stripper.strip_states(result.warnings)
    if not result.calls and not result.states:
        return result
    if result.states:
        stripper.check_references()
        result.cheat_entries = stripper.strip_cheat_answers(result.warnings)
    stripper.visit(tree)
    result.translations = stripper.strip_translations(result.warnings)
    result.import_removed = stripper.strip_import({FUNCTION, STATE_DECORATOR} if full else {FUNCTION})
    result.warnings += stripper.unfollowed_names()
    if result.states:
        result.warnings += stripper.unused_methods()
    result.data = apply_replacements(data, stripper.edits)

    # never write a file that is not the lab without its instructor() calls (and states)
    try:
        stripped_tree = ast.parse(result.data)
    except SyntaxError as e:
        raise StripError(f"internal error: the stripped source does not parse (line {e.lineno}: {e.msg})") from e
    if any(_is_instructor_call(node, stripper.names) for node in ast.walk(stripped_tree)):
        raise StripError(f"internal error: a {FUNCTION}() call is left in the stripped source")
    if full:
        if _Stripper(result.data, stripped_tree).states_to_remove([]):
            raise StripError("internal error: a removed state is left in the stripped source")
        if any(isinstance(node, ast.keyword) and node.arg == CHEAT_KEYWORD and isinstance(node.value, ast.Dict)
               and any(isinstance(key, ast.Constant) and key.value in result.states for key in node.value.keys)
               for node in ast.walk(stripped_tree)):
            raise StripError(f"internal error: the {CHEAT_KEYWORD} of a removed state are left in the stripped source")
    return result


def _write_in_place(path: Path, data: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        shutil.copymode(path, temp_name)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _state_directory_warnings(project: Path, states: list) -> list:
    """The state directories of a directory lab (`<lab dir>/<state>/`) are not removed."""
    if project.name != SRELAB_FILENAME:
        return []
    return [f"the directory '{project.parent / state}' holds the files of the removed state '{state}': "
            "it is left in place" for state in states if (project.parent / state).is_dir()]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='strip-instructor',
        description='Write a lab .py file without its instructor() calls (and, with --full, its solution states).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('-i', '--in-place', action='store_true',
                        help='replace the project file itself (no output argument)')
    parser.add_argument('--full', action='store_true',
                        help=f'also remove the states students cannot apply (every @{STATE_DECORATOR} method but '
                             f'{", ".join(KEPT_STATES)} and the user_allowed=True ones) and their {CHEAT_KEYWORD}')
    # no short form: -f is caught to point at --full instead of "unrecognized arguments"
    parser.add_argument('-f', dest='short_full', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('project', help='path to the lab .py file')
    parser.add_argument('output', nargs='?',
                        help='file to write, or directory in which a file of the same name is written')
    args = parser.parse_args(argv)
    if args.short_full:
        parser.error("-f is not an option: use --full")
    if args.in_place and args.output is not None:
        parser.error("-i replaces the project file: it takes no output")
    if not args.in_place and args.output is None:
        parser.error("an output file or directory is required (or -i to replace the project file)")

    def fail(message: str) -> int:
        print(f"strip-instructor: {message}", file=sys.stderr)
        return 1

    project = Path(args.project)
    try:
        data = project.read_bytes()
    except OSError as e:
        return fail(f"cannot read '{project}': {e.strerror}")

    destination = project
    if not args.in_place:
        destination = Path(args.output)
        if destination.is_dir():
            destination = destination / project.name
        if destination.exists() and destination.samefile(project):
            return fail(f"'{destination}' is the project file itself: use -i to replace it")

    try:
        result = strip_source(data, full=args.full)
    except StripError as e:
        return fail(f"{project}: {e}")
    result.warnings += _state_directory_warnings(project, result.states)

    try:
        if not args.in_place:
            destination.write_bytes(result.data)
        elif result.data != data:
            _write_in_place(project, result.data)
    except OSError as e:
        return fail(f"cannot write '{destination}': {e.strerror}")

    for warning in result.warnings:
        print(f"strip-instructor: {project}: warning: {warning}", file=sys.stderr)
    summary = []
    if result.calls:
        text = f"{result.calls} {FUNCTION}() call(s) removed"
        if result.translations:
            text += f", {result.translations} _TRANSLATIONS entr{'y' if result.translations == 1 else 'ies'} removed"
        summary.append(text)
    else:
        summary.append(f"no {FUNCTION}() call")
    if args.full:
        if result.states:
            text = f"{len(result.states)} state(s) removed ({', '.join(result.states)})"
            if result.cheat_entries:
                text += (f", {result.cheat_entries} {CHEAT_KEYWORD} "
                         f"entr{'y' if result.cheat_entries == 1 else 'ies'} removed")
            summary.append(text)
        else:
            summary.append("no state to remove")
    print(f"{destination}: {', '.join(summary)}.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
