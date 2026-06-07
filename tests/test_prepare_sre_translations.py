"""Tests for src/tools/prepare_sre_translations.py."""
import ast
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))
from prepare_sre_translations import (
    build_line_offsets,
    node_span,
    apply_replacements,
    detect_multilingual,
    find_translatable_nodes,
    find_translations_node,
    find_make_tr_node,
    find_default_language_node,
    find_import_time_tr_call_ids,
    collect_inline_translations,
    get_existing_translations,
    collect_tr_strings,
    _wrap_replacements,
    add_tr_kwargs_replacements,
    strip_tr_kwargs_replacements,
    change_default_language_replacements,
    validate_change_default_language,
    rekey_merged_for_default_swap,
    build_translations_source,
    _translation_literal,
    _is_simple_fstring,
    _fstring_vars,
    _fstring_template_value,
    fstring_tr_replacements,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse(src: str) -> ast.Module:
    return ast.parse(textwrap.dedent(src))


def _offsets(src: str) -> list[int]:
    return build_line_offsets(src.encode('utf-8'))


def _lab(tmp_path: Path, src: str) -> Path:
    p = tmp_path / 'lab.py'
    p.write_text(textwrap.dedent(src), encoding='utf-8')
    return p


def _run(path: Path, *cli_args: str) -> str:
    """Run prepare_sre_translations.main() on *path* and return the file's new content."""
    import prepare_sre_translations as tsl
    old_argv = sys.argv
    sys.argv = ['translate-sre-lab', *cli_args, str(path)]
    try:
        tsl.main()
    except SystemExit as e:
        if e.code != 0:
            raise
    finally:
        sys.argv = old_argv
    return path.read_text(encoding='utf-8')


def _run_expect_error(path: Path, *cli_args: str) -> int:
    """Run main() and return the non-zero exit code."""
    import prepare_sre_translations as tsl
    old_argv = sys.argv
    sys.argv = ['translate-sre-lab', *cli_args, str(path)]
    try:
        with pytest.raises(SystemExit) as exc:
            tsl.main()
        return exc.value.code
    finally:
        sys.argv = old_argv


# ---------------------------------------------------------------------------
# detect_multilingual
# ---------------------------------------------------------------------------

class TestDetectMultilingual:
    def test_multilingual(self):
        tree = _parse("""
            default_language = 'fr'
            tr = make_tr(default_language)
        """)
        is_multi, lang = detect_multilingual(tree)
        assert is_multi is True
        assert lang == 'fr'

    def test_not_multilingual_no_tr(self):
        tree = _parse("default_language = 'fr'")
        is_multi, lang = detect_multilingual(tree)
        assert is_multi is False
        assert lang == 'fr'

    def test_not_multilingual_no_default_lang(self):
        tree = _parse("tr = make_tr('en')")
        is_multi, lang = detect_multilingual(tree)
        assert is_multi is False
        assert lang is None

    def test_bare_file(self):
        is_multi, lang = detect_multilingual(_parse("x = 1"))
        assert is_multi is False
        assert lang is None


# ---------------------------------------------------------------------------
# collect_inline_translations
# ---------------------------------------------------------------------------

class TestCollectInlineTranslations:
    def test_basic(self):
        tree = _parse("tr('Hello', fr='Bonjour')")
        result = collect_inline_translations(tree)
        assert result == {'Hello': {'fr': 'Bonjour'}}

    def test_multiple_langs(self):
        tree = _parse("tr('Hello', fr='Bonjour', de='Hallo')")
        result = collect_inline_translations(tree)
        assert result['Hello'] == {'fr': 'Bonjour', 'de': 'Hallo'}

    def test_no_kwargs(self):
        tree = _parse("tr('Hello')")
        result = collect_inline_translations(tree)
        assert result == {'Hello': {}}

    def test_multiple_calls(self):
        tree = _parse("tr('A', fr='Aa')\ntr('B', fr='Bb')")
        result = collect_inline_translations(tree)
        assert result == {'A': {'fr': 'Aa'}, 'B': {'fr': 'Bb'}}

    def test_no_tr_calls(self):
        assert collect_inline_translations(_parse("x = 1")) == {}


# ---------------------------------------------------------------------------
# get_existing_translations
# ---------------------------------------------------------------------------

class TestGetExistingTranslations:
    def test_simple(self):
        tree = _parse("_TRANSLATIONS = {'fr': {'Hello': 'Bonjour'}}")
        assert get_existing_translations(tree) == {'fr': {'Hello': 'Bonjour'}}

    def test_none_value_preserved(self):
        tree = _parse("_TRANSLATIONS = {'fr': {'Hello': None}}")
        assert get_existing_translations(tree) == {'fr': {'Hello': None}}

    def test_absent(self):
        assert get_existing_translations(_parse("x = 1")) == {}

    def test_non_literal_returns_empty(self):
        tree = _parse("_TRANSLATIONS = {'fr': some_dict}")
        assert get_existing_translations(tree) == {}


# ---------------------------------------------------------------------------
# find_* node locators
# ---------------------------------------------------------------------------

class TestNodeFinders:
    def test_find_translations_node(self):
        tree = _parse("_TRANSLATIONS = {'fr': {}}")
        assert find_translations_node(tree) is not None

    def test_find_translations_node_absent(self):
        assert find_translations_node(_parse("x = 1")) is None

    def test_find_make_tr_node(self):
        tree = _parse("tr = make_tr('fr')")
        assert find_make_tr_node(tree) is not None

    def test_find_make_tr_node_via_variable(self):
        tree = _parse("tr = make_tr(default_language)")
        assert find_make_tr_node(tree) is not None

    def test_find_make_tr_node_absent(self):
        assert find_make_tr_node(_parse("x = 1")) is None

    def test_find_default_language_node(self):
        tree = _parse("default_language = 'en'")
        assert find_default_language_node(tree) is not None

    def test_find_default_language_node_absent(self):
        assert find_default_language_node(_parse("x = 1")) is None


# ---------------------------------------------------------------------------
# build_translations_source
# ---------------------------------------------------------------------------

class TestBuildTranslationsSource:
    def test_basic(self):
        src = build_translations_source({'fr': {'Hello': 'Bonjour'}})
        assert "_TRANSLATIONS = {" in src
        assert "'fr'" in src
        assert "'Hello': 'Bonjour'" in src

    def test_none_value(self):
        src = build_translations_source({'fr': {'Hello': None}})
        assert "'Hello': None" in src

    def test_multiple_languages_sorted(self):
        src = build_translations_source({'fr': {'A': 'Aa'}, 'de': {'A': 'Aa'}})
        assert src.index("'de'") < src.index("'fr'")   # sorted alphabetically

    def test_strings_sorted_within_lang(self):
        src = build_translations_source({'fr': {'B': 'Bb', 'A': 'Aa'}})
        assert src.index("'A'") < src.index("'B'")

    def test_empty_dict_one_line(self):
        assert build_translations_source({}) == '_TRANSLATIONS = {}'

    def test_roundtrip_eval(self):
        t = {'fr': {'Hello': 'Bonjour', 'Bye': None}, 'de': {'Hello': 'Hallo', 'Bye': None}}
        src = build_translations_source(t)
        evaluated = ast.literal_eval(src.split(' = ', 1)[1])
        assert evaluated == t

    def test_multiline_value_uses_triple_quotes(self):
        src = build_translations_source({'fr': {'Title': '## A\n\npara one\npara two\n'}})
        assert '"""' in src
        assert '\\n' not in src          # real newlines, not escaped
        assert 'para one\npara two' in src

    def test_multiline_key_uses_triple_quotes(self):
        key = '\n## Intro\n\nlong markdown\n'
        src = build_translations_source({'fr': {key: 'trad'}})
        assert '"""' in src
        assert '## Intro\n\nlong markdown' in src

    def test_roundtrip_eval_multiline(self):
        t = {'en': {'\n## 1\n\nLe **DNS**\nsuite\n': '\n## 1\n\nThe **DNS**\nmore\n'},
             'de': {'\n## 1\n\nLe **DNS**\nsuite\n': None}}
        src = build_translations_source(t)
        assert ast.literal_eval(src.split(' = ', 1)[1]) == t


# ---------------------------------------------------------------------------
# _translation_literal
# ---------------------------------------------------------------------------

class TestTranslationLiteral:
    @pytest.mark.parametrize('s', [
        'simple',
        'with\nnewline\n',
        '## title\n\nbody line one\nbody line two\n',
        'has """ triple quote inside',
        'ends with a quote\nright here"',
        'back\\slash\nand newline',
        'carriage\r\nreturn',          # \r -> falls back to repr
        '',
    ])
    def test_roundtrips_exactly(self, s):
        assert ast.literal_eval(_translation_literal(s)) == s

    def test_none(self):
        assert _translation_literal(None) == 'None'

    def test_single_line_uses_repr(self):
        assert _translation_literal('short') == repr('short')

    def test_multiline_uses_triple_quotes(self):
        assert _translation_literal('a\nb').startswith('"""')


# ---------------------------------------------------------------------------
# strip_tr_kwargs_replacements
# ---------------------------------------------------------------------------

class TestStripTrKwargs:
    def test_removes_kwargs(self):
        src = "tr('Hello', fr='Bonjour')"
        sb = src.encode()
        tree = ast.parse(src)
        reps = strip_tr_kwargs_replacements(sb, build_line_offsets(sb), tree)
        result = apply_replacements(sb, reps).decode()
        assert result == "tr('Hello')"

    def test_multiple_kwargs(self):
        src = "tr('Hi', fr='Salut', de='Hallo')"
        sb = src.encode()
        tree = ast.parse(src)
        reps = strip_tr_kwargs_replacements(sb, build_line_offsets(sb), tree)
        result = apply_replacements(sb, reps).decode()
        assert result == "tr('Hi')"

    def test_no_kwargs_unchanged(self):
        src = "tr('Hello')"
        sb = src.encode()
        tree = ast.parse(src)
        reps = strip_tr_kwargs_replacements(sb, build_line_offsets(sb), tree)
        assert reps == []

    def test_multiple_calls(self):
        src = "tr('A', fr='Aa')\ntr('B', fr='Bb')"
        sb = src.encode()
        tree = ast.parse(src)
        reps = strip_tr_kwargs_replacements(sb, build_line_offsets(sb), tree)
        result = apply_replacements(sb, reps).decode()
        assert result == "tr('A')\ntr('B')"


# ---------------------------------------------------------------------------
# change_default_language_replacements
# ---------------------------------------------------------------------------

class TestChangeDefaultLanguage:
    def test_changes_default_language_literal(self):
        src = "default_language = 'fr'"
        sb = src.encode()
        tree = ast.parse(src)
        reps = change_default_language_replacements(sb, build_line_offsets(sb), tree, 'en')
        result = apply_replacements(sb, reps).decode()
        assert "default_language = 'en'" in result

    def test_changes_make_tr_literal_arg(self):
        src = "tr = make_tr('fr')"
        sb = src.encode()
        tree = ast.parse(src)
        reps = change_default_language_replacements(sb, build_line_offsets(sb), tree, 'en')
        result = apply_replacements(sb, reps).decode()
        assert "make_tr('en')" in result

    def test_does_not_change_make_tr_variable_arg(self):
        src = "default_language = 'fr'\ntr = make_tr(default_language)"
        sb = src.encode()
        tree = ast.parse(src)
        reps = change_default_language_replacements(sb, build_line_offsets(sb), tree, 'en')
        result = apply_replacements(sb, reps).decode()
        # default_language value changes, make_tr arg is a variable so unchanged
        assert "default_language = 'en'" in result
        assert "make_tr(default_language)" in result

    def test_no_nodes_no_replacements(self):
        src = "x = 1"
        sb = src.encode()
        tree = ast.parse(src)
        reps = change_default_language_replacements(sb, build_line_offsets(sb), tree, 'en')
        assert reps == []

    def test_rewrites_tr_first_arg_and_strips_new_lang_kwarg(self):
        # tr("Bonjour", en="Hello") with fr→en pivot becomes tr('Hello', fr='Bonjour'):
        # the new-default kwarg is dropped and the old default is preserved as kwarg.
        src = "title = tr('Bonjour', en='Hello')"
        sb = src.encode()
        tree = ast.parse(src)
        merged = {'Bonjour': {'en': 'Hello'}}
        reps = change_default_language_replacements(
            sb, build_line_offsets(sb), tree, 'en', merged=merged, old_default='fr')
        result = apply_replacements(sb, reps).decode()
        assert "tr('Hello', fr='Bonjour')" in result

    def test_preserves_other_inline_kwargs(self):
        src = "title = tr('Bonjour', en='Hello', de='Hallo')"
        sb = src.encode()
        tree = ast.parse(src)
        merged = {'Bonjour': {'en': 'Hello', 'de': 'Hallo'}}
        reps = change_default_language_replacements(
            sb, build_line_offsets(sb), tree, 'en', merged=merged, old_default='fr')
        result = apply_replacements(sb, reps).decode()
        # 'en' kwarg dropped; 'de' kwarg preserved verbatim; 'fr' kwarg added at the end.
        assert "tr('Hello', de='Hallo', fr='Bonjour')" in result

    def test_leaves_kwargs_empty_when_call_had_none(self):
        # Call without any inline kwargs (xx text comes from _TRANSLATIONS):
        # the rewrite should not introduce new kwargs.
        src = "title = tr('Bonjour')"
        sb = src.encode()
        tree = ast.parse(src)
        merged = {'Bonjour': {'en': 'Hello'}}  # came from _TRANSLATIONS
        reps = change_default_language_replacements(
            sb, build_line_offsets(sb), tree, 'en', merged=merged, old_default='fr')
        result = apply_replacements(sb, reps).decode()
        assert "tr('Hello')" in result
        assert "fr=" not in result

    def test_skips_tr_calls_without_xx_translation(self):
        # Defensive: validation should have caught this, but if not, skip silently.
        src = "title = tr('Bonjour')"
        sb = src.encode()
        tree = ast.parse(src)
        merged = {'Bonjour': {}}   # no en translation
        reps = change_default_language_replacements(
            sb, build_line_offsets(sb), tree, 'en', merged=merged, old_default='fr')
        result = apply_replacements(sb, reps).decode()
        assert result == src   # unchanged


# ---------------------------------------------------------------------------
# validate_change_default_language
# ---------------------------------------------------------------------------

class TestValidateChangeDefaultLanguage:
    def test_ok_inline_kwarg_provides_xx(self):
        tree = _parse("""
            title = tr('Bonjour', en='Hello')
        """)
        merged = {'Bonjour': {'en': 'Hello'}}
        assert validate_change_default_language(tree, 'en', merged) == []

    def test_ok_translations_dict_provides_xx(self):
        tree = _parse("""
            title = tr('Bonjour')
        """)
        merged = {'Bonjour': {'en': 'Hello'}}   # via _TRANSLATIONS
        assert validate_change_default_language(tree, 'en', merged) == []

    def test_missing_xx_translation_errors(self):
        tree = _parse("""
            title = tr('Bonjour')
        """)
        merged = {'Bonjour': {}}
        errs = validate_change_default_language(tree, 'en', merged)
        assert len(errs) == 1
        assert "'en'" in errs[0]
        assert 'Bonjour' in errs[0]

    def test_none_xx_translation_errors(self):
        tree = _parse("""
            title = tr('Bonjour')
        """)
        merged = {'Bonjour': {'en': None}}   # placeholder, not filled in
        errs = validate_change_default_language(tree, 'en', merged)
        assert len(errs) == 1
        assert 'Bonjour' in errs[0]

    def test_non_literal_first_arg_errors(self):
        tree = _parse("""
            x = 'foo'
            title = tr(x)
        """)
        errs = validate_change_default_language(tree, 'en', {})
        assert any('not a string literal' in e for e in errs)

    def test_fstring_first_arg_errors(self):
        tree = _parse("""
            name = 'x'
            title = tr(f'Bonjour {name}')
        """)
        errs = validate_change_default_language(tree, 'en', {})
        assert any('not a string literal' in e for e in errs)

    def test_bare_translatable_string_errors(self):
        # A bare title= literal that hasn't been wrapped yet should block the pivot.
        tree = _parse("""
            title = 'Bonjour'
        """)
        errs = validate_change_default_language(tree, 'en', {})
        assert any('bare translatable string' in e for e in errs)


# ---------------------------------------------------------------------------
# rekey_merged_for_default_swap
# ---------------------------------------------------------------------------

class TestRekeyMerged:
    def test_basic_swap(self):
        merged = {'Bonjour': {'en': 'Hello', 'de': 'Hallo'}}
        out = rekey_merged_for_default_swap(merged, 'en', 'fr')
        assert out == {'Hello': {'de': 'Hallo', 'fr': 'Bonjour'}}

    def test_drops_new_lang_key(self):
        merged = {'Bonjour': {'en': 'Hello'}}
        out = rekey_merged_for_default_swap(merged, 'en', 'fr')
        assert 'en' not in out['Hello']
        assert out['Hello']['fr'] == 'Bonjour'

    def test_drops_entries_without_xx(self):
        # Defensive: validation catches this case; rekey skips it.
        merged = {'Bonjour': {}}
        out = rekey_merged_for_default_swap(merged, 'en', 'fr')
        assert out == {}

    def test_old_default_overrides_existing_entry(self):
        # If merged already has an entry for the old default, the rekey replaces
        # it with the canonical old-source-text mapping.
        merged = {'Bonjour': {'en': 'Hello', 'fr': 'whatever'}}
        out = rekey_merged_for_default_swap(merged, 'en', 'fr')
        assert out['Hello']['fr'] == 'Bonjour'


# ---------------------------------------------------------------------------
# Integration: _run on tmp files
# ---------------------------------------------------------------------------

class TestIntegration:
    # --- Wrap bare strings ---

    def test_wraps_bare_title(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            title = "My lab"
        """)
        result = _run(p)
        assert 'title = tr("My lab")' in result

    def test_wraps_self_informations(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class N:
                def initial(self):
                    self.informations = "Lab description"
        """)
        result = _run(p)
        assert 'tr("Lab description")' in result

    def test_wraps_question_dummy_first_arg(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.question_dummy("Section title", description="desc")
        """)
        result = _run(p)
        assert 'tr("Section title")' in result

    def test_wraps_question_dummy_description_kwarg(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.question_dummy("T", description="Explain X")
        """)
        result = _run(p)
        assert 'description=tr("Explain X")' in result

    def test_wraps_question_dummy_description_positional(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.question_dummy("T", "I.", "Explain X")
        """)
        result = _run(p)
        assert 'tr("Explain X")' in result
        assert '"I."' in result   # section (index 1) NOT wrapped

    def test_wraps_add_grade_element_description_positional(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.add_grade_element("score", 5, "Points for X")
        """)
        result = _run(p)
        assert 'tr("Points for X")' in result
        assert 'tr(5)' not in result   # max_grade (index 1) NOT wrapped

    def test_wraps_add_grade_part_description_positional(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.add_grade_part("Part A", "About X")
        """)
        result = _run(p)
        assert 'tr("Part A")' in result
        assert 'tr("About X")' in result

    def test_wraps_description_in_binop(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    extra = "..."
                    self.question_dummy("T", description="Head text" + extra)
        """)
        result = _run(p)
        assert 'tr("Head text")' in result

    def test_wraps_both_sides_of_binop_concat(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.question_dummy("T", description="Hello " + "world")
        """)
        result = _run(p)
        assert 'tr("Hello ")' in result
        assert 'tr("world")' in result

    def test_does_not_double_wrap_binop_with_existing_tr(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    extra = "..."
                    self.question_dummy("T", description=tr("Head") + extra)
        """)
        result = _run(p)
        assert result.count('tr("Head")') == 1
        assert 'tr(tr(' not in result

    def test_wraps_ifexp_branches_in_description(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    cond = True
                    self.question_dummy("T", description="Yes" if cond else "No")
        """)
        result = _run(p)
        assert 'tr("Yes")' in result
        assert 'tr("No")' in result

    def test_does_not_double_wrap(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            title = tr("Already wrapped")
        """)
        result = _run(p)
        assert result.count('tr("Already wrapped")') == 1
        assert 'tr(tr(' not in result

    # --- _TRANSLATIONS insertion ---

    def test_inserts_translations_after_make_tr(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("My lab", fr="Mon TP")
        """)
        result = _run(p)
        lines = result.splitlines()
        make_tr_idx = next(i for i, l in enumerate(lines) if 'make_tr' in l)
        trans_idx   = next(i for i, l in enumerate(lines) if '_TRANSLATIONS' in l)
        assert trans_idx > make_tr_idx

    def test_updates_existing_translations(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'Old string': 'Vieille chaîne'}}
            title = tr("New string", fr="Nouvelle chaîne")
        """)
        result = _run(p)
        assert result.count('_TRANSLATIONS') == 1   # not duplicated
        assert "'New string'" in result
        assert "'Nouvelle chaîne'" in result

    def test_translations_none_for_missing(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            title = tr("Untranslated")
        """)
        result = _run(p)
        assert "'Untranslated': None" in result

    # --- No target languages ---

    def test_no_known_languages_inserts_empty_translations(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("Only English")
        """)
        result = _run(p)
        # An empty _TRANSLATIONS anchor is still emitted so that
        # add-sre-translations has something to fill in later.
        assert '_TRANSLATIONS = {}' in result
        lines = result.splitlines()
        make_tr_idx = next(i for i, l in enumerate(lines) if 'make_tr' in l)
        trans_idx = next(i for i, l in enumerate(lines) if '_TRANSLATIONS' in l)
        assert trans_idx > make_tr_idx

    # --- --move-tr-strings ---

    def test_move_tr_strings_strips_kwargs(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("My lab", fr="Mon TP")
        """)
        result = _run(p, '--move-tr-strings')
        assert 'title = tr("My lab")' in result
        assert "'My lab': 'Mon TP'" in result

    def test_move_tr_strings_preserves_translations(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("Hello", fr="Bonjour", de="Hallo")
        """)
        result = _run(p, '--move-tr-strings')
        assert 'title = tr("Hello")' in result
        assert "'Bonjour'" in result
        assert "'Hallo'" in result

    # --- --default-language ---

    def test_default_language_adds_setup_when_absent(self, tmp_path):
        p = _lab(tmp_path, 'title = "My lab"\n')
        result = _run(p, '--default-language', 'en')
        assert 'make_tr' in result
        assert "default_language = 'en'" in result

    def test_default_language_no_error_when_same(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
            title = tr("Bonjour")
        """)
        _run(p, '--default-language', 'fr')   # should not raise

    def test_default_language_error_on_conflict(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
        """)
        code = _run_expect_error(p, '--default-language', 'en')
        assert code != 0

    # --- --change-default-language ---

    def test_change_default_language_updates_value(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
            title = tr("Bonjour", en="Hello")
        """)
        result = _run(p, '--change-default-language', 'en')
        assert "default_language = 'en'" in result
        # tr() literal is pivoted to the English text; the old default is kept as kwarg.
        assert "tr('Hello', fr='Bonjour')" in result

    def test_change_default_language_updates_make_tr_literal(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr('fr')
            title = tr("Bonjour", en="Hello")
        """)
        result = _run(p, '--change-default-language', 'en')
        assert "make_tr('en')" in result

    def test_change_default_language_rekeys_translations(self, tmp_path):
        # _TRANSLATIONS keys flip from old-default text to new-default text,
        # XX disappears, old default appears as a regular language entry.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
            _TRANSLATIONS = {
                'en': {'Bonjour': 'Hello'},
                'de': {'Bonjour': 'Hallo'},
            }
            title = tr("Bonjour")
        """)
        result = _run(p, '--change-default-language', 'en')
        tree = ast.parse(result)
        t = get_existing_translations(tree)
        assert 'en' not in t                 # new default is not in _TRANSLATIONS
        assert 'fr' in t                     # previous default now appears as a language
        assert 'de' in t                     # unrelated languages preserved
        assert t['fr'] == {'Hello': 'Bonjour'}
        assert t['de'] == {'Hello': 'Hallo'}
        # tr() now uses the English text as the source literal.
        assert "tr('Hello')" in result

    def test_change_default_language_excludes_new_lang_from_translations(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
            title = tr("Bonjour", en="Hello")
        """)
        result = _run(p, '--change-default-language', 'en')
        # 'en' is now the default lang, so it must NOT appear as a key in _TRANSLATIONS
        tree = ast.parse(result)
        t = get_existing_translations(tree)
        assert 'en' not in t
        # 'fr' (the old default) is now a regular language in _TRANSLATIONS.
        assert t.get('fr') == {'Hello': 'Bonjour'}

    def test_change_default_language_errors_on_missing_translation(self, tmp_path, capsys):
        # No 'en' translation anywhere → pivot must error and leave the file alone.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
            title = tr("Bonjour")
        """)
        before = p.read_text()
        code = _run_expect_error(p, '--change-default-language', 'en')
        assert code != 0
        err = capsys.readouterr().err
        assert 'Bonjour' in err
        assert "'en'" in err
        assert p.read_text() == before        # file untouched on validation failure

    def test_change_default_language_errors_on_bare_string(self, tmp_path, capsys):
        # File has a bare title= — must run prepare-sre-translations first to wrap.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
            title = "Bonjour"
        """)
        code = _run_expect_error(p, '--change-default-language', 'en')
        assert code != 0
        err = capsys.readouterr().err
        assert 'bare translatable string' in err

    def test_change_default_language_errors_on_non_multilingual_file(self, tmp_path):
        # File doesn't declare default_language / make_tr → can't pivot.
        p = _lab(tmp_path, 'title = "x"\n')
        code = _run_expect_error(p, '--change-default-language', 'en')
        assert code != 0

    def test_change_default_language_errors_when_same_as_current(self, tmp_path):
        # Asking to pivot to the language that is already the default is a no-op
        # by intent — error so users notice the typo.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
        """)
        code = _run_expect_error(p, '--change-default-language', 'fr')
        assert code != 0

    # --- Mutual exclusion ---

    def test_incompatible_flags_error(self, tmp_path):
        p = _lab(tmp_path, "title = 'x'\n")
        code = _run_expect_error(p, '--default-language', 'en', '--change-default-language', 'fr')
        assert code != 0

    # --- Missing default_language defaults to 'en' ---

    def test_no_language_flag_defaults_to_en(self, tmp_path):
        p = _lab(tmp_path, 'title = "Lab"\n')
        result = _run(p)
        assert "default_language = 'en'" in result

    # --- Idempotency ---

    def test_idempotent(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("My lab", fr="Mon TP")
        """)
        first = _run(p)
        # Write back first result and run again
        p.write_text(first)
        second = _run(p)
        assert first == second


# ---------------------------------------------------------------------------
# fstring_tr_replacements — unit tests
# ---------------------------------------------------------------------------

class TestFstringHelpers:

    def test_is_simple_fstring_name_only(self):
        tree = _parse('f"Hello {name}"')
        node = tree.body[0].value
        assert _is_simple_fstring(node)

    def test_is_simple_fstring_multiple_names(self):
        tree = _parse('f"Hello {a} and {b}"')
        node = tree.body[0].value
        assert _is_simple_fstring(node)

    def test_is_simple_fstring_false_on_binop(self):
        tree = _parse('f"Value {x + 1}"')
        node = tree.body[0].value
        assert not _is_simple_fstring(node)

    def test_is_simple_fstring_false_on_attribute(self):
        tree = _parse('f"Name {obj.attr}"')
        node = tree.body[0].value
        assert not _is_simple_fstring(node)

    def test_fstring_vars_deduplicates(self):
        tree = _parse('f"{x} and {x} again"')
        node = tree.body[0].value
        assert _fstring_vars(node) == ['x']

    def test_fstring_vars_preserves_order(self):
        tree = _parse('f"{a} {b} {c}"')
        node = tree.body[0].value
        assert _fstring_vars(node) == ['a', 'b', 'c']

    def test_fstring_template_value_double_quotes(self):
        assert _fstring_template_value(b'f"Hello {name}"') == 'Hello {name}'

    def test_fstring_template_value_single_quotes(self):
        assert _fstring_template_value(b"f'Hello {name}'") == 'Hello {name}'

    def test_fstring_template_value_invalid(self):
        assert _fstring_template_value(b'not_an_fstring') is None


class TestFstringTrReplacements:

    def _apply(self, src: str, move=False) -> str:
        src = textwrap.dedent(src)
        b = src.encode('utf-8')
        tree = ast.parse(src)
        offsets = build_line_offsets(b)
        repls, _, _ = fstring_tr_replacements(b, offsets, tree, move_tr_strings=move)
        return apply_replacements(b, repls).decode('utf-8')

    def _extra(self, src: str, move=False) -> dict:
        src = textwrap.dedent(src)
        b = src.encode('utf-8')
        tree = ast.parse(src)
        offsets = build_line_offsets(b)
        _, _, extra = fstring_tr_replacements(b, offsets, tree, move_tr_strings=move)
        return extra

    def test_strips_f_prefix_from_first_arg(self):
        result = self._apply('title = tr(f"Hello {name}")')
        assert 'tr("Hello {name}").format(name=name)' in result

    def test_keeps_kwargs_when_not_moving(self):
        result = self._apply('title = tr(f"Hello {name}", fr=f"Bonjour {name}")')
        assert 'tr("Hello {name}", fr="Bonjour {name}").format(name=name)' in result

    def test_strips_kwargs_when_moving(self):
        result = self._apply('title = tr(f"Hello {name}", fr=f"Bonjour {name}")', move=True)
        assert 'tr("Hello {name}").format(name=name)' in result
        assert 'fr=' not in result

    def test_multiple_vars(self):
        result = self._apply('x = tr(f"{a} and {b}")')
        assert '.format(a=a, b=b)' in result

    def test_deduplicates_vars_across_langs(self):
        result = self._apply('x = tr(f"Hi {name}", fr=f"Salut {name}")')
        assert result.count('name=name') == 1

    def test_handles_complex_expression(self):
        result = self._apply('x = tr(f"Value {x + 1}")')
        assert 'tr("Value {_arg0}").format(_arg0=x + 1)' in result

    def test_handles_attribute_access(self):
        result = self._apply('x = tr(f"User {u.name}")')
        assert 'tr("User {_arg0}").format(_arg0=u.name)' in result

    def test_handles_method_call_in_triple_quoted_fstring(self):
        src = 'x = tr(f"""Machines: {", ".join(items)}.""")'
        result = self._apply(src)
        assert 'tr("""Machines: {_arg0}.""")' in result
        assert '.format(_arg0=", ".join(items))' in result

    def test_mixes_name_and_complex_placeholders(self):
        result = self._apply('x = tr(f"{name}={obj.value}")')
        assert 'tr("{name}={_arg0}")' in result
        assert '.format(name=name, _arg0=obj.value)' in result

    def test_skips_fstring_with_dynamic_format_spec(self):
        src = 'x = tr(f"{val:{width}}")\n'
        result = self._apply(src)
        assert result == src   # unchanged: format_spec contains an expression

    def test_complex_expression_with_kwargs(self):
        result = self._apply('x = tr(f"Got {a.b()}", fr=f"Eu {a.b()}")')
        assert 'tr("Got {_arg0}", fr="Eu {_arg0}")' in result
        assert '.format(_arg0=a.b())' in result

    def test_no_fstring_no_change(self):
        src = 'x = tr("static")\n'
        result = self._apply(src)
        assert result == src

    def test_extra_translations_captured(self):
        extra = self._extra('x = tr(f"Hello {name}", fr=f"Bonjour {name}")')
        assert extra == {'Hello {name}': {'fr': 'Bonjour {name}'}}

    def test_extra_translations_move(self):
        extra = self._extra('x = tr(f"Hello {name}", fr=f"Bonjour {name}")', move=True)
        assert extra == {'Hello {name}': {'fr': 'Bonjour {name}'}}

    def test_handled_ids_populated(self):
        src = textwrap.dedent('x = tr(f"Hello {name}")')
        b = src.encode('utf-8')
        tree = ast.parse(src)
        offsets = build_line_offsets(b)
        _, handled, _ = fstring_tr_replacements(b, offsets, tree)
        assert len(handled) == 1

    def test_non_fstring_call_not_in_handled_ids(self):
        src = textwrap.dedent('x = tr("static")\n')
        b = src.encode('utf-8')
        tree = ast.parse(src)
        offsets = build_line_offsets(b)
        _, handled, _ = fstring_tr_replacements(b, offsets, tree)
        assert len(handled) == 0


class TestFstringTrIntegration:
    """End-to-end: run main() and verify the output."""

    def test_fstring_wrapped_in_translations(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            title = tr(f"Hello {name}", fr=f"Bonjour {name}")
        """)
        result = _run(p)
        assert 'tr("Hello {name}", fr="Bonjour {name}").format(name=name)' in result
        assert '"Hello {name}"' in result   # in _TRANSLATIONS
        assert "'fr'" in result

    def test_fstring_move_tr_strings(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            title = tr(f"Hello {name}", fr=f"Bonjour {name}")
        """)
        result = _run(p, '--move-tr-strings')
        # kwargs stripped, format appended
        assert 'tr("Hello {name}").format(name=name)' in result
        # fr translation recovered into _TRANSLATIONS
        assert 'Bonjour {name}' in result

    def test_fstring_and_regular_tr_coexist(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            title = tr(f"Hello {name}")
            lab_name = tr("Static", fr="Statique")
        """)
        result = _run(p)
        assert 'tr("Hello {name}").format(name=name)' in result
        assert 'tr("Static", fr="Statique")' in result

    # --- Bare (un-wrapped) f-strings in translatable positions ---

    def test_bare_fstring_description_kwarg_wrapped_and_lowered(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            ZONE = "lab"
            class G:
                def grade(self):
                    self.question_dummy("T", description=f"Records for {ZONE}")
        """)
        result = _run(p)
        assert 'description=tr("Records for {ZONE}").format(ZONE=ZONE)' in result
        assert '"Records for {ZONE}"' in result   # template (not formatted) in _TRANSLATIONS

    def test_bare_fstring_title_kwarg_wrapped(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            ZONE = "lab"
            class G:
                def grade(self):
                    self.question_dummy(title=f"Zone {ZONE}", description="d")
        """)
        result = _run(p)
        assert 'title=tr("Zone {ZONE}").format(ZONE=ZONE)' in result

    def test_bare_fstring_module_var_wrapped(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            name = "x"
            title = f"Lab {name}"
        """)
        result = _run(p)
        assert 'title = tr("Lab {name}").format(name=name)' in result

    def test_bare_fstring_complex_expr_uses_argN(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.add_grade_element("k", 1, description=f"A {d.nets.net1}")
        """)
        result = _run(p)
        assert 'description=tr("A {_arg0}").format(_arg0=d.nets.net1)' in result


def _lib_sre_imports(result: str) -> set[str]:
    """Names imported from a `from ...lib_sre import ...` line in *result*."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(result)):
        if isinstance(node, ast.ImportFrom) and node.module and 'lib_sre' in node.module:
            names |= {a.asname or a.name for a in node.names}
    return names


class TestNoTranslate:
    """no_tr(...) marks strings that must never be translated."""

    def test_no_tr_arg_not_wrapped(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr, no_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.add_grade_element(title=no_tr("ns2_txt"), description="TXT check")
        """)
        result = _run(p)
        assert 'title=no_tr("ns2_txt")' in result          # left as-is
        assert 'description=tr("TXT check")' in result      # prose still wrapped
        t = get_existing_translations(ast.parse(result))
        assert all('ns2_txt' not in strings for strings in t.values())

    def test_no_tr_removes_existing_translation_entry(self, tmp_path):
        # 'ns2_txt' was translated before; once marked no_tr it must be cleaned up.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr, no_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'ns2_txt': 'ns2_txt'}}
            class G:
                def grade(self):
                    self.add_grade_element(title=no_tr("ns2_txt"), description="d")
        """)
        result = _run(p)
        t = get_existing_translations(ast.parse(result))
        assert all('ns2_txt' not in strings for strings in t.values())

    def test_no_tr_import_added_when_missing(self, tmp_path):
        # no_tr is used but not imported — the tool must add it.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.add_grade_element(title=no_tr("k"), description="d")
        """)
        result = _run(p)
        assert 'no_tr' in _lib_sre_imports(result)

    def test_no_tr_import_not_duplicated(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr, no_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.add_grade_element(title=no_tr("k"), description="d")
        """)
        result = _run(p)
        assert result.count('no_tr') >= 1
        # 'no_tr' appears once in the import line (not added twice)
        import_line = next(l for l in result.splitlines() if 'lib_sre import' in l)
        assert import_line.count('no_tr') == 1

    def test_no_tr_idempotent(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr, no_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {}}
            class G:
                def grade(self):
                    self.add_grade_element(title=no_tr("k"), description="d")
        """)
        first = _run(p)
        p.write_text(first)
        second = _run(p)
        assert first == second

    def test_no_tr_import_added_for_non_multilingual_file(self, tmp_path):
        # Setup block + no_tr import must be folded into one import edit.
        p = _lab(tmp_path, """
            from SRE.lib_sre import Grade0
            class G(Grade0):
                def grade(self):
                    self.add_grade_element(title=no_tr("k"), description="Some prose")
        """)
        result = _run(p)
        imports = _lib_sre_imports(result)
        assert {'make_tr', 'no_tr', 'Grade0'} <= imports
        assert 'description=tr("Some prose")' in result
        assert 'no_tr("k")' in result


# ---------------------------------------------------------------------------
# find_import_time_tr_call_ids — unit tests
# ---------------------------------------------------------------------------

class TestFindImportTimeTrCallIds:

    def test_module_level_call_is_import_time(self):
        tree = _parse('title = tr("My lab")')
        ids = find_import_time_tr_call_ids(tree)
        call = tree.body[0].value
        assert id(call) in ids

    def test_class_body_call_is_import_time(self):
        tree = _parse("""
            class C:
                title = tr("My lab")
        """)
        ids = find_import_time_tr_call_ids(tree)
        class_def = tree.body[0]
        call = class_def.body[0].value
        assert id(call) in ids

    def test_function_body_call_is_not_import_time(self):
        tree = _parse("""
            def f():
                return tr("inside")
        """)
        ids = find_import_time_tr_call_ids(tree)
        assert ids == set()

    def test_method_body_call_is_not_import_time(self):
        tree = _parse("""
            class C:
                def m(self):
                    return tr("inside method")
        """)
        ids = find_import_time_tr_call_ids(tree)
        assert ids == set()

    def test_async_function_body_call_is_not_import_time(self):
        tree = _parse("""
            async def f():
                return tr("inside")
        """)
        ids = find_import_time_tr_call_ids(tree)
        assert ids == set()

    def test_only_tr_name_counts(self):
        # other.tr(...) doesn't qualify (not a bare Name)
        tree = _parse('x = obj.tr("text")')
        ids = find_import_time_tr_call_ids(tree)
        assert ids == set()

    def test_mixed(self):
        tree = _parse("""
            title = tr("module")
            class C:
                tagline = tr("class")
                def m(self):
                    return tr("method")
        """)
        ids = find_import_time_tr_call_ids(tree)
        # Module-level + class-level qualify, method-level does not.
        assert len(ids) == 2


# ---------------------------------------------------------------------------
# add_tr_kwargs_replacements — unit tests
# ---------------------------------------------------------------------------

class TestAddTrKwargsReplacements:

    def _apply(self, src: str, merged: dict, default_lang: str = 'en') -> str:
        src = textwrap.dedent(src)
        sb = src.encode('utf-8')
        tree = ast.parse(src)
        offsets = build_line_offsets(sb)
        targets = {id(n) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        reps = add_tr_kwargs_replacements(sb, offsets, tree, targets, merged, default_lang)
        return apply_replacements(sb, reps).decode('utf-8')

    def test_appends_missing_kwarg(self):
        result = self._apply(
            'title = tr("My lab")',
            {'My lab': {'fr': 'Mon TP'}},
        )
        assert result == "title = tr('My lab', fr='Mon TP')" or \
               result == 'title = tr("My lab", fr=\'Mon TP\')'
        # Both are valid; just check the kwarg got inserted before the ')'.
        assert "fr='Mon TP'" in result
        assert result.endswith(')')

    def test_skips_default_language(self):
        result = self._apply(
            'title = tr("My lab")',
            {'My lab': {'en': 'My lab', 'fr': 'Mon TP'}},
            default_lang='en',
        )
        assert 'en=' not in result
        assert "fr='Mon TP'" in result

    def test_skips_existing_kwarg(self):
        result = self._apply(
            'title = tr("My lab", fr="ExistingFR")',
            {'My lab': {'fr': 'NewFR', 'de': 'NeuDE'}},
        )
        # fr was already present, so it is not added again
        assert result.count('fr=') == 1
        assert 'ExistingFR' in result
        assert "de='NeuDE'" in result

    def test_skips_none_values(self):
        result = self._apply(
            'title = tr("My lab")',
            {'My lab': {'fr': None, 'de': 'Hallo'}},
        )
        assert 'fr=' not in result
        assert "de='Hallo'" in result

    def test_no_change_when_nothing_missing(self):
        src = 'title = tr("X")'
        result = self._apply(src, {'X': {}})
        assert result == src

    def test_only_targets_in_target_ids(self):
        src = textwrap.dedent('a = tr("A")\nb = tr("B")')
        sb = src.encode('utf-8')
        tree = ast.parse(src)
        offsets = build_line_offsets(sb)
        # Target only the first tr() call.
        first_call = tree.body[0].value
        reps = add_tr_kwargs_replacements(
            sb, offsets, tree, {id(first_call)},
            {'A': {'fr': 'Aa'}, 'B': {'fr': 'Bb'}},
            'en',
        )
        result = apply_replacements(sb, reps).decode('utf-8')
        assert "fr='Aa'" in result
        assert 'Bb' not in result

    def test_skips_non_string_first_arg(self):
        # tr() whose first arg isn't a string literal must be left alone.
        src = 'x = tr(variable)'
        result = self._apply(src, {'whatever': {'fr': 'X'}})
        assert result == src


# ---------------------------------------------------------------------------
# Integration: --translations-at-the-end
# ---------------------------------------------------------------------------

def _stmt_lines(result: str) -> dict[str, int]:
    """Return a {kind: line_no} dict for key landmarks in *result*."""
    lines = result.splitlines()
    return {
        'make_tr':       next((i for i, l in enumerate(lines) if 'make_tr' in l), -1),
        '_TRANSLATIONS': next((i for i, l in enumerate(lines) if '_TRANSLATIONS' in l), -1),
        'last_nonblank': max(i for i, l in enumerate(lines) if l.strip()),
    }


class TestTranslationsAtTheEnd:
    """--translations-at-the-end: park _TRANSLATIONS at EOF and keep
    import-time tr() calls self-contained via inline kwargs."""

    # --- Placement ---

    def test_inserts_at_eof_when_absent(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("My lab", fr="Mon TP")
        """)
        result = _run(p, '--translations-at-the-end')
        landmarks = _stmt_lines(result)
        # _TRANSLATIONS exists and is the last non-blank statement.
        assert landmarks['_TRANSLATIONS'] != -1
        # Find the line where the _TRANSLATIONS block ENDS (its closing '}').
        # It must reach the last non-blank line.
        trans_block_end = max(
            i for i, l in enumerate(result.splitlines())
            if l.strip() and i >= landmarks['_TRANSLATIONS']
        )
        assert trans_block_end == landmarks['last_nonblank']
        # And it is below make_tr.
        assert landmarks['_TRANSLATIONS'] > landmarks['make_tr']

    def test_moves_existing_translations_to_eof(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'My lab': 'Mon TP'}}
            title = tr("My lab")
            x = 42
        """)
        result = _run(p, '--translations-at-the-end')
        # Exactly one _TRANSLATIONS, located AFTER `x = 42`.
        assert result.count('_TRANSLATIONS') == 1
        landmarks = _stmt_lines(result)
        x_line = next(i for i, l in enumerate(result.splitlines()) if l.startswith('x = 42'))
        assert landmarks['_TRANSLATIONS'] > x_line

    def test_no_blank_line_left_behind_when_moving(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'My lab': 'Mon TP'}}
            title = tr("My lab")
        """)
        result = _run(p, '--translations-at-the-end')
        # The deleted _TRANSLATIONS must not leave a blank line behind
        # between `tr = make_tr(...)` and `title = ...`.
        lines = result.splitlines()
        make_tr_idx = next(i for i, l in enumerate(lines)
                           if l.startswith('tr = make_tr'))
        title_idx = next(i for i, l in enumerate(lines) if l.startswith('title'))
        between = lines[make_tr_idx + 1:title_idx]
        # No blank lines and no leftover content between the two.
        assert between == []

    def test_updates_in_place_when_already_at_eof(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("My lab")
            _TRANSLATIONS = {'fr': {'My lab': 'Mon TP'}}
        """)
        result = _run(p, '--translations-at-the-end')
        # Single _TRANSLATIONS block, refreshed in place at EOF (no move).
        assert result.count('_TRANSLATIONS') == 1
        landmarks = _stmt_lines(result)
        title_idx = next(i for i, l in enumerate(result.splitlines()) if l.startswith('title'))
        assert landmarks['_TRANSLATIONS'] > title_idx

    # --- Inline kwargs on import-time tr() calls ---

    def test_inlines_kwargs_for_module_level_tr(self, tmp_path):
        # Translation came from _TRANSLATIONS, not inline; with the flag the
        # script must move it inline so the module-level call doesn't depend
        # on the late _TRANSLATIONS definition.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'My lab': 'Mon TP'}}
            title = tr("My lab")
        """)
        result = _run(p, '--translations-at-the-end')
        assert "title = tr(\"My lab\", fr='Mon TP')" in result \
            or 'title = tr("My lab", fr="Mon TP")' in result \
            or "title = tr('My lab', fr='Mon TP')" in result \
            or "fr='Mon TP'" in result.split('_TRANSLATIONS')[0]

    def test_inlines_kwargs_for_class_body_tr(self, tmp_path):
        # Class bodies run at import time too — same treatment.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'Heading': 'Titre'}}
            class C:
                heading = tr("Heading")
        """)
        result = _run(p, '--translations-at-the-end')
        # The class-body call must carry the kwarg inline (above the EOF
        # _TRANSLATIONS block).
        before_trans = result.split('_TRANSLATIONS')[0]
        assert "fr='Titre'" in before_trans

    def test_does_not_inline_kwargs_for_method_body_tr(self, tmp_path):
        # Method bodies are evaluated lazily — _TRANSLATIONS at EOF is fine.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'Inside': 'Dedans'}}
            class C:
                def grade(self):
                    return tr("Inside")
        """)
        result = _run(p, '--translations-at-the-end')
        # The method-level call must NOT receive inline kwargs.
        method_chunk = result.split('def grade')[1].split('_TRANSLATIONS')[0]
        assert 'fr=' not in method_chunk
        # But the translation is still in _TRANSLATIONS for runtime lookup.
        assert "'Inside'" in result
        assert "'Dedans'" in result

    def test_default_language_kwarg_not_inlined(self, tmp_path):
        # The default language is the first positional arg of tr(); never
        # echoed as a kwarg.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'fr'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'en': {'Mon TP': 'My lab'}}
            title = tr("Mon TP")
        """)
        result = _run(p, '--translations-at-the-end')
        before_trans = result.split('_TRANSLATIONS')[0]
        # 'en' translation IS injected, 'fr' (the default) is NOT.
        assert "en='My lab'" in before_trans
        assert 'fr=' not in before_trans

    # --- Interaction with --move-tr-strings ---

    def test_move_tr_strings_spares_import_time_calls(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("My lab", fr="Mon TP")
            class C:
                def grade(self):
                    return tr("Inside", fr="Dedans")
        """)
        result = _run(p, '--move-tr-strings', '--translations-at-the-end')
        before_trans = result.split('_TRANSLATIONS')[0]
        # title is module-level → kwargs preserved
        assert 'fr=' in before_trans.split('class C')[0]
        # method body → kwargs stripped
        method_chunk = before_trans.split('def grade')[1]
        assert 'fr=' not in method_chunk
        # _TRANSLATIONS holds both translations
        assert "'Mon TP'" in result
        assert "'Dedans'" in result

    # --- Translations survive in _TRANSLATIONS too ---

    def test_translations_present_in_eof_block(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'My lab': 'Mon TP'}}
            title = tr("My lab")
        """)
        result = _run(p, '--translations-at-the-end')
        # Translation kept duplicated in _TRANSLATIONS for runtime tr() calls.
        t = get_existing_translations(ast.parse(result))
        assert t.get('fr', {}).get('My lab') == 'Mon TP'

    # --- Regression: no flag → unchanged behavior ---

    def test_no_flag_keeps_translations_after_make_tr(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            title = tr("My lab", fr="Mon TP")
            x = 1
        """)
        result = _run(p)
        landmarks = _stmt_lines(result)
        x_line = next(i for i, l in enumerate(result.splitlines()) if l.startswith('x = 1'))
        # Without the flag, _TRANSLATIONS lands above the body, not at EOF.
        assert landmarks['_TRANSLATIONS'] > landmarks['make_tr']
        assert landmarks['_TRANSLATIONS'] < x_line

    # --- Idempotency ---

    def test_idempotent(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'My lab': 'Mon TP'}}
            title = tr("My lab")
            class C:
                def grade(self):
                    return tr("Inside", fr="Dedans")
        """)
        first = _run(p, '--translations-at-the-end')
        p.write_text(first)
        second = _run(p, '--translations-at-the-end')
        assert first == second

    # --- End-to-end runtime check ---

    def test_runtime_module_level_translation_resolves(self, tmp_path):
        # After --translations-at-the-end, a module-level title=tr(...) must
        # still resolve to the correct translation at import time.
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'My lab': 'Mon TP'}}
            title = tr("My lab")
        """)
        _run(p, '--translations-at-the-end')
        # Import and resolve.
        import importlib.util
        spec = importlib.util.spec_from_file_location('lab_eof', p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.title.resolve('en') == 'My lab'
        assert mod.title.resolve('fr') == 'Mon TP'
