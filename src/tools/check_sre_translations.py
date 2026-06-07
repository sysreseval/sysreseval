#!/usr/bin/env python3
"""Check _TRANSLATIONS consistency in a lab file.

Reports three categories for each target language:

  MISSING      — string passed to tr() but absent from _TRANSLATIONS
  UNTRANSLATED — key present in _TRANSLATIONS with a None value
  VANISHED     — key in _TRANSLATIONS but no matching tr() call in the file

Usage:
    check-translations lab/sre/static_routing.py [...]
"""

import ast
import sys
from pathlib import Path


def get_tr_strings(tree: ast.AST) -> set[str]:
    """Collect the first-argument string literals from all tr(...) calls."""
    strings = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            continue
        if name == 'tr' and node.args and isinstance(node.args[0], ast.Constant):
            strings.add(node.args[0].value)
    return strings


def get_translations(tree: ast.AST) -> dict | None:
    """Extract the _TRANSLATIONS dict literal from the AST (best-effort)."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(t, ast.Name) and t.id == '_TRANSLATIONS'
               for t in node.targets):
            try:
                return ast.literal_eval(node.value)
            except Exception:
                return None
    return None


def check_file(path: Path) -> int:
    src = path.read_text()
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        print(f"{path}: SyntaxError: {e}")
        return 1

    tr_strings = get_tr_strings(tree)
    translations = get_translations(tree)

    if translations is None:
        print(f"{path}: no _TRANSLATIONS dict found")
        return 0

    issues = 0
    for lang, strings in translations.items():
        for key, val in strings.items():
            if val is None:
                print(f"{path}: UNTRANSLATED [{lang}] {key!r}")
                issues += 1
            if key not in tr_strings:
                print(f"{path}: VANISHED      [{lang}] {key!r}")
                issues += 1

    for s in tr_strings:
        for lang, strings in translations.items():
            if s not in strings:
                print(f"{path}: MISSING       [{lang}] {s!r}")
                issues += 1

    if issues == 0:
        print(f"{path}: ok ({len(tr_strings)} strings, {list(translations)} languages)")
    return issues


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    total = 0
    for arg in sys.argv[1:]:
        total += check_file(Path(arg))
    sys.exit(1 if total else 0)


if __name__ == '__main__':
    main()
