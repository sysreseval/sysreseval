#!/usr/bin/env python3
"""strip-instructor — Write a lab .py file without its instructor() calls.

Usage:
    strip-instructor project.py output
    strip-instructor -i project.py

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

Formatting and comments are kept. The result is checked (it must parse and hold no
instructor() call); on error nothing is written.

Limits:
  - Comments are left alone, except one standing between an operand and the removed `+`.
  - A text kept in a variable is not followed: `note = tr("...")` then `instructor(note)`
    leaves the definition of `note` in the file (a warning names such variables).
  - Only this file is processed, not the state directories of a directory lab.
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
EMPTY_TEXT = b"''"
# names that say nothing about the instructor texts when they only appear inside the calls
_UNREPORTED_NAMES = {'tr', 'no_tr', 'self', 'cls'} | set(dir(builtins))


class StripError(Exception):
    """The file cannot be stripped (it does not parse, or the result would be wrong)."""


@dataclass
class StripResult:
    data: bytes                 # the stripped source
    calls: int = 0              # instructor() calls removed
    translations: int = 0       # _TRANSLATIONS entries removed
    import_removed: bool = False
    warnings: list = field(default_factory=list)


def _instructor_names(tree: ast.Module) -> set:
    """Local names of the function: `instructor`, and its aliases (`import instructor as x`)."""
    names = {FUNCTION}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names |= {alias.asname for alias in node.names if alias.name == FUNCTION and alias.asname}
    return names


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


class _Stripper:
    def __init__(self, data: bytes, tree: ast.Module):
        self.data = data
        self.tree = tree
        self.offsets = build_line_offsets(data)
        self.names = _instructor_names(tree)
        self.edits = []         # (start, end, replacement)
        self.void_spans = []    # byte spans of the removed expressions

    def span(self, node: ast.AST):
        return node_span(self.offsets, node)

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
        self.void_spans.append(self.span(node))
        self.edits.append((start, end, replacement))

    def visit(self, node: ast.AST):
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

    def in_void(self, node: ast.AST) -> bool:
        start, end = self.span(node)
        return any(void_start <= start and end <= void_end for void_start, void_end in self.void_spans)

    # -- _TRANSLATIONS -------------------------------------------------------------------

    def _entry_edit(self, key: ast.AST, value: ast.AST):
        """Deletion of one `key: value,` entry of a dict; of its whole lines when it stands
        alone on them."""
        start, end = self.span(key)[0], self.span(value)[1]

        def skip_blanks(position):
            while self.data[position:position + 1] in (b' ', b'\t'):
                position += 1
            return position

        end = skip_blanks(end)
        if self.data[end:end + 1] == b',':
            end = skip_blanks(end + 1)
        line_start = self.data.rfind(b'\n', 0, start) + 1
        if not self.data[line_start:start].strip() and self.data[end:end + 1] in (b'\n', b'\r', b''):
            start = line_start
            newline = self.data.find(b'\n', end)
            end = len(self.data) if newline == -1 else newline + 1
        return start, end, b''

    def strip_translations(self, warnings: list) -> int:
        """Remove the entries of _TRANSLATIONS for the tr() strings that only the removed
        calls used."""
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

    # -- the import ----------------------------------------------------------------------

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
        line_end = self.data.find(b'\n', end)
        line_end = len(self.data) if line_end == -1 else line_end + 1
        alone_on_its_lines = not self.data[line_start:start].strip() and not self.data[end:line_end].strip()
        if alone_on_its_lines and not self._is_whole_block(node):
            return line_start, line_end, b''
        return start, end, b'pass'

    def strip_import(self) -> bool:
        """Remove `instructor` from its `from ... import` statements once nothing uses it."""
        used = {node.id for node in ast.walk(self.tree)
                if isinstance(node, ast.Name) and node.id in self.names and not self.in_void(node)}
        removed = False
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            indexes = [i for i, alias in enumerate(node.names)
                       if alias.name == FUNCTION and (alias.asname or FUNCTION) not in used]
            if not indexes:
                continue
            removed = True
            if len(indexes) == len(node.names):
                self.edits.append(self._statement_edit(node))
                continue
            for i in indexes:
                if i + 1 < len(node.names):     # up to the next name
                    self.edits.append((self.span(node.names[i])[0], self.span(node.names[i + 1])[0], b''))
                else:                           # the last name: from the end of the previous one
                    self.edits.append((self.span(node.names[i - 1])[1], self.span(node.names[i])[1], b''))
        return removed

    # -- names only the removed calls used -----------------------------------------------

    def unfollowed_names(self) -> list:
        """Warnings for the variables that only the removed calls read while a value assigned
        to them stays in the file: most likely an instructor text kept in a variable."""
        defined = {}    # name -> line of its first assignment whose value stays
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None or self.in_void(node.value):
                continue
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if isinstance(target, ast.Name):
                    defined.setdefault(target.id, node.lineno)
        inside, outside = set(), set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                (inside if self.in_void(node) else outside).add(node.id)
        return [f"line {defined[name]}: '{name}' is only used inside {FUNCTION}() but defined outside: its "
                f"definition is left in the file (wrap the text in {FUNCTION}() where it is assigned to remove it)"
                for name in sorted(inside - outside - self.names - _UNREPORTED_NAMES, key=lambda n: defined.get(n, 0))
                if name in defined]


def strip_source(data: bytes) -> StripResult:
    """Return the source *data* of a lab file without its instructor() calls."""
    try:
        tree = ast.parse(data)
    except SyntaxError as e:
        raise StripError(f"line {e.lineno}: {e.msg}") from e
    stripper = _Stripper(data, tree)
    calls = sum(_is_instructor_call(node, stripper.names) for node in ast.walk(tree))
    if not calls:
        return StripResult(data)
    stripper.visit(tree)
    result = StripResult(data, calls=calls)
    result.translations = stripper.strip_translations(result.warnings)
    result.import_removed = stripper.strip_import()
    result.warnings += stripper.unfollowed_names()
    result.data = apply_replacements(data, stripper.edits)

    # never write a file that is not the lab without its instructor() calls
    try:
        stripped_tree = ast.parse(result.data)
    except SyntaxError as e:
        raise StripError(f"internal error: the stripped source does not parse (line {e.lineno}: {e.msg})") from e
    if any(_is_instructor_call(node, stripper.names) for node in ast.walk(stripped_tree)):
        raise StripError(f"internal error: a {FUNCTION}() call is left in the stripped source")
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='strip-instructor',
        description='Write a lab .py file without its instructor() calls.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('-i', '--in-place', action='store_true',
                        help='replace the project file itself (no output argument)')
    parser.add_argument('project', help='path to the lab .py file')
    parser.add_argument('output', nargs='?',
                        help='file to write, or directory in which a file of the same name is written')
    args = parser.parse_args(argv)
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
        result = strip_source(data)
    except StripError as e:
        return fail(f"{project}: {e}")

    try:
        if not args.in_place:
            destination.write_bytes(result.data)
        elif result.data != data:
            _write_in_place(project, result.data)
    except OSError as e:
        return fail(f"cannot write '{destination}': {e.strerror}")

    for warning in result.warnings:
        print(f"strip-instructor: {project}: warning: {warning}", file=sys.stderr)
    if result.calls:
        summary = f"{result.calls} {FUNCTION}() call(s) removed"
        if result.translations:
            summary += f", {result.translations} _TRANSLATIONS entr{'y' if result.translations == 1 else 'ies'} removed"
    else:
        summary = f"no {FUNCTION}() call"
    print(f"{destination}: {summary}.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
