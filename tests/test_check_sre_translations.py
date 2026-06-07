"""Tests for src/tools/check_sre_translations.py."""
import ast
import sys
import textwrap
from pathlib import Path

import pytest

# The tool lives in src/tools/, outside the normal package tree.
sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))
from check_sre_translations import get_tr_strings, get_translations, check_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse(src: str) -> ast.AST:
    return ast.parse(textwrap.dedent(src))


def _lab(tmp_path: Path, src: str) -> Path:
    """Write dedented source to a temp .py file and return its Path."""
    p = tmp_path / 'lab.py'
    p.write_text(textwrap.dedent(src))
    return p


# ---------------------------------------------------------------------------
# get_tr_strings
# ---------------------------------------------------------------------------

class TestGetTrStrings:
    def test_bare_name_call(self):
        tree = _parse("tr('Hello')")
        assert get_tr_strings(tree) == {'Hello'}

    def test_attribute_call(self):
        # obj.tr("text") — attribute-style, e.g. self.tr(...)
        tree = _parse("self.tr('Hi')")
        assert get_tr_strings(tree) == {'Hi'}

    def test_multiple_calls(self):
        tree = _parse("tr('A')\ntr('B')\ntr('C')")
        assert get_tr_strings(tree) == {'A', 'B', 'C'}

    def test_deduplicates(self):
        tree = _parse("tr('Same')\ntr('Same')")
        assert get_tr_strings(tree) == {'Same'}

    def test_keyword_args_ignored(self):
        # only the positional first arg is collected
        tree = _parse("tr('Hello', fr='Bonjour')")
        assert get_tr_strings(tree) == {'Hello'}

    def test_non_string_first_arg_ignored(self):
        tree = _parse("tr(some_var)")
        assert get_tr_strings(tree) == set()

    def test_other_function_names_ignored(self):
        tree = _parse("make_tr('fr')\nfoo('bar')")
        assert get_tr_strings(tree) == set()

    def test_no_tr_ignored(self):
        # no_tr(...) marks an opted-out string; it must not be collected as a tr string.
        tree = _parse("tr('Hello')\nno_tr('ns2_txt')")
        assert get_tr_strings(tree) == {'Hello'}

    def test_nested_inside_class_and_function(self):
        tree = _parse("""
            class Flavor:
                form = tr('Pick') + tr('Size')
            def build(self):
                tr('Network')
        """)
        assert get_tr_strings(tree) == {'Pick', 'Size', 'Network'}

    def test_empty_file(self):
        assert get_tr_strings(_parse('')) == set()


# ---------------------------------------------------------------------------
# get_translations
# ---------------------------------------------------------------------------

class TestGetTranslations:
    def test_simple_dict(self):
        tree = _parse("_TRANSLATIONS = {'fr': {'Hello': 'Bonjour'}}")
        assert get_translations(tree) == {'fr': {'Hello': 'Bonjour'}}

    def test_none_values_preserved(self):
        tree = _parse("_TRANSLATIONS = {'fr': {'Hello': None}}")
        assert get_translations(tree) == {'fr': {'Hello': None}}

    def test_multiple_languages(self):
        tree = _parse("""
            _TRANSLATIONS = {
                'fr': {'Hello': 'Bonjour'},
                'de': {'Hello': 'Hallo'},
            }
        """)
        result = get_translations(tree)
        assert result == {'fr': {'Hello': 'Bonjour'}, 'de': {'Hello': 'Hallo'}}

    def test_absent_returns_none(self):
        assert get_translations(_parse('x = 1')) is None

    def test_non_literal_returns_none(self):
        # Can't literal_eval a dict containing a variable
        tree = _parse("_TRANSLATIONS = {'fr': some_dict}")
        assert get_translations(tree) is None

    def test_placed_after_code(self):
        tree = _parse("""
            title = tr('Hello')
            _TRANSLATIONS = {'fr': {'Hello': 'Bonjour'}}
        """)
        assert get_translations(tree) == {'fr': {'Hello': 'Bonjour'}}


# ---------------------------------------------------------------------------
# check_file — output and return value
# ---------------------------------------------------------------------------

class TestCheckFile:
    def test_ok_all_present(self, tmp_path, capsys):
        p = _lab(tmp_path, """
            tr('Hello')
            _TRANSLATIONS = {'fr': {'Hello': 'Bonjour'}}
        """)
        assert check_file(p) == 0
        assert 'ok' in capsys.readouterr().out

    def test_no_translations_dict(self, tmp_path, capsys):
        p = _lab(tmp_path, "tr('Hello')")
        assert check_file(p) == 0
        assert 'no _TRANSLATIONS dict found' in capsys.readouterr().out

    def test_no_tr_string_not_flagged(self, tmp_path, capsys):
        # A no_tr() string is opted out — must not be reported MISSING.
        p = _lab(tmp_path, """
            tr('Hello')
            no_tr('ns2_txt')
            _TRANSLATIONS = {'fr': {'Hello': 'Bonjour'}}
        """)
        assert check_file(p) == 0
        out = capsys.readouterr().out
        assert 'ok' in out
        assert 'ns2_txt' not in out

    def test_missing_key(self, tmp_path, capsys):
        # tr() call has no entry in _TRANSLATIONS
        p = _lab(tmp_path, """
            tr('Hello')
            _TRANSLATIONS = {'fr': {}}
        """)
        assert check_file(p) == 1
        out = capsys.readouterr().out
        assert 'MISSING' in out
        assert "'Hello'" in out
        assert '[fr]' in out

    def test_untranslated_none(self, tmp_path, capsys):
        p = _lab(tmp_path, """
            tr('Hello')
            _TRANSLATIONS = {'fr': {'Hello': None}}
        """)
        assert check_file(p) == 1
        out = capsys.readouterr().out
        assert 'UNTRANSLATED' in out
        assert "'Hello'" in out

    def test_vanished_key(self, tmp_path, capsys):
        # Key in _TRANSLATIONS but no tr() call uses it
        p = _lab(tmp_path, """
            _TRANSLATIONS = {'fr': {'Ghost': 'Fantôme'}}
        """)
        assert check_file(p) == 1
        out = capsys.readouterr().out
        assert 'VANISHED' in out
        assert "'Ghost'" in out

    def test_multiple_issues_counted(self, tmp_path, capsys):
        p = _lab(tmp_path, """
            tr('A')
            tr('B')
            _TRANSLATIONS = {'fr': {'A': None, 'Ghost': 'Fantôme'}}
        """)
        # UNTRANSLATED A, VANISHED Ghost, MISSING B → 3 issues
        assert check_file(p) == 3

    def test_syntax_error_returns_1(self, tmp_path, capsys):
        p = tmp_path / 'bad.py'
        p.write_text('def (')
        assert check_file(p) == 1
        assert 'SyntaxError' in capsys.readouterr().out

    def test_multiple_languages_each_checked(self, tmp_path, capsys):
        p = _lab(tmp_path, """
            tr('Hello')
            _TRANSLATIONS = {
                'fr': {'Hello': 'Bonjour'},
                'de': {},
            }
        """)
        # 'Hello' missing from 'de' → 1 issue
        assert check_file(p) == 1
        out = capsys.readouterr().out
        assert 'MISSING' in out
        assert '[de]' in out

    def test_untranslated_and_vanished_are_independent(self, tmp_path, capsys):
        # A key with None is both UNTRANSLATED and, if there's no tr() call, VANISHED
        p = _lab(tmp_path, """
            _TRANSLATIONS = {'fr': {'Ghost': None}}
        """)
        assert check_file(p) == 2
        out = capsys.readouterr().out
        assert 'UNTRANSLATED' in out
        assert 'VANISHED' in out

    def test_ok_message_shows_string_count_and_langs(self, tmp_path, capsys):
        p = _lab(tmp_path, """
            tr('A')
            tr('B')
            _TRANSLATIONS = {'fr': {'A': 'Aa', 'B': 'Bb'}, 'de': {'A': 'Aa', 'B': 'Bb'}}
        """)
        assert check_file(p) == 0
        out = capsys.readouterr().out
        assert '2 strings' in out
        assert 'fr' in out
        assert 'de' in out
