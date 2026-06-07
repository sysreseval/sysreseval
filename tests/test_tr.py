"""Tests for tr(), make_tr(), _lookup_translations(), and TranslatedText.format()."""
import pytest

from SRE.lib_sre import tr, make_tr, _lookup_translations
from SRE.common import TranslatedText


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def set_module_translations():
    """Temporarily inject _TRANSLATIONS into this test module's globals.

    Required for tests that exercise frame inspection: sys._getframe(1).f_globals
    resolves to the test module's __dict__ when tr() / make_tr() is called from
    a test function body.
    """
    import tests.test_tr as _self
    original = getattr(_self, '_TRANSLATIONS', _SENTINEL := object())

    def _set(d):
        _self._TRANSLATIONS = d
        # Also update *this* module's globals so tr() called here sees it.
        globals()['_TRANSLATIONS'] = d

    yield _set

    # Restore previous state.
    if original is _SENTINEL:
        globals().pop('_TRANSLATIONS', None)
        if hasattr(_self, '_TRANSLATIONS'):
            del _self._TRANSLATIONS
    else:
        globals()['_TRANSLATIONS'] = original
        _self._TRANSLATIONS = original


# ---------------------------------------------------------------------------
# _lookup_translations (unit tests for the core helper)
# ---------------------------------------------------------------------------

class TestLookupTranslations:
    def test_returns_translation_from_globals(self):
        g = {'_TRANSLATIONS': {'fr': {'Hello': 'Bonjour'}}}
        assert _lookup_translations(g, 'Hello', {}) == {'fr': 'Bonjour'}

    def test_inline_takes_priority_over_globals(self):
        g = {'_TRANSLATIONS': {'fr': {'Hello': 'Bonjour dict'}}}
        result = _lookup_translations(g, 'Hello', {'fr': 'Bonjour inline'})
        assert result == {'fr': 'Bonjour inline'}

    def test_none_value_is_skipped(self):
        g = {'_TRANSLATIONS': {'fr': {'Hello': None}}}
        assert _lookup_translations(g, 'Hello', {}) == {}

    def test_missing_key_not_included(self):
        g = {'_TRANSLATIONS': {'fr': {'Other': 'Autre'}}}
        assert _lookup_translations(g, 'Hello', {}) == {}

    def test_no_translations_key_in_globals(self):
        assert _lookup_translations({}, 'Hello', {}) == {}

    def test_multiple_languages(self):
        g = {'_TRANSLATIONS': {
            'fr': {'Hello': 'Bonjour'},
            'de': {'Hello': 'Hallo'},
        }}
        result = _lookup_translations(g, 'Hello', {})
        assert result == {'fr': 'Bonjour', 'de': 'Hallo'}

    def test_inline_only_overrides_matching_lang(self):
        g = {'_TRANSLATIONS': {
            'fr': {'Hello': 'Bonjour dict'},
            'de': {'Hello': 'Hallo'},
        }}
        result = _lookup_translations(g, 'Hello', {'fr': 'Bonjour inline'})
        assert result['fr'] == 'Bonjour inline'
        assert result['de'] == 'Hallo'


# ---------------------------------------------------------------------------
# tr() — retro-compatible inline usage (no _TRANSLATIONS)
# ---------------------------------------------------------------------------

class TestTrInline:
    def test_inline_single_lang(self):
        result = tr("My lab", fr="Mon TP")
        assert result.resolve('en') == "My lab"
        assert result.resolve('fr') == "Mon TP"

    def test_inline_multiple_langs(self):
        result = tr("Hello", fr="Bonjour", de="Hallo")
        assert result.resolve('de') == "Hallo"
        assert result.resolve('fr') == "Bonjour"

    def test_no_langs_returns_source(self):
        result = tr("Only English")
        assert result.resolve('en') == "Only English"
        assert result.resolve('fr') == "Only English"  # fallback

    def test_unknown_lang_falls_back_to_first(self):
        result = tr("Source", fr="Traduit")
        assert result.resolve('de') == "Source"  # 'en' is first key


# ---------------------------------------------------------------------------
# tr() — frame inspection (_TRANSLATIONS in caller module globals)
# ---------------------------------------------------------------------------

class TestTrFrameInspection:
    def test_translation_found(self, set_module_translations):
        set_module_translations({'fr': {'Hello': 'Bonjour'}})
        result = tr("Hello")
        assert result.resolve('fr') == 'Bonjour'

    def test_none_value_treated_as_untranslated(self, set_module_translations):
        set_module_translations({'fr': {'Hello': None}})
        result = tr("Hello")
        assert result.resolve('fr') == 'Hello'  # fallback to source

    def test_inline_overrides_dict(self, set_module_translations):
        set_module_translations({'fr': {'Hello': 'Bonjour dict'}})
        result = tr("Hello", fr="Bonjour inline")
        assert result.resolve('fr') == 'Bonjour inline'

    def test_missing_key_not_in_result(self, set_module_translations):
        set_module_translations({'fr': {'Other': 'Autre'}})
        result = tr("Hello")
        assert result.resolve('fr') == 'Hello'  # no French entry → fallback

    def test_multiple_languages(self, set_module_translations):
        set_module_translations({'fr': {'Hi': 'Salut'}, 'de': {'Hi': 'Hallo'}})
        result = tr("Hi")
        assert result.resolve('fr') == 'Salut'
        assert result.resolve('de') == 'Hallo'

    def test_no_translations_in_globals_works_normally(self):
        # No set_module_translations fixture: _TRANSLATIONS absent from globals.
        result = tr("Fine", fr="Bien")
        assert result.resolve('fr') == 'Bien'


# ---------------------------------------------------------------------------
# make_tr() — explicit translations= dict (no frame inspection)
# ---------------------------------------------------------------------------

class TestMakeTrExplicit:
    def test_basic_translation(self):
        # Source text is French; _TRANSLATIONS supplies the English equivalent.
        t = {'en': {'Bonjour': 'Hello'}}
        tr_fr = make_tr('fr', translations=t)
        result = tr_fr("Bonjour")
        assert result.resolve('fr') == 'Bonjour'
        assert result.resolve('en') == 'Hello'

    def test_inline_overrides_dict(self):
        t = {'en': {'Bonjour': 'Hello dict'}}
        tr_fr = make_tr('fr', translations=t)
        result = tr_fr("Bonjour", en="Hello inline")
        assert result.resolve('en') == 'Hello inline'

    def test_none_value_skipped(self):
        t = {'en': {'Bonjour': None}}
        tr_fr = make_tr('fr', translations=t)
        result = tr_fr("Bonjour")
        assert result.resolve('en') == 'Bonjour'  # fallback to source

    def test_missing_key(self):
        t = {'fr': {'Other': 'Autre'}}
        tr_fr = make_tr('fr', translations=t)
        result = tr_fr("Bonjour")
        assert result.resolve('fr') == 'Bonjour'
        assert 'en' not in result

    def test_multiple_languages(self):
        t = {'en': {'Bonjour': 'Hello'}, 'de': {'Bonjour': 'Hallo'}}
        tr_fr = make_tr('fr', translations=t)
        result = tr_fr("Bonjour")
        assert result.resolve('en') == 'Hello'
        assert result.resolve('de') == 'Hallo'

    def test_default_lang_is_first_key(self):
        t = {}
        tr_fr = make_tr('fr', translations=t)
        result = tr_fr("Texte")
        assert list(result.keys())[0] == 'fr'

    def test_dict_mutation_after_make_tr_is_seen(self):
        """Explicit dict is stored by reference — mutations are visible."""
        t = {'en': {}}
        tr_fr = make_tr('fr', translations=t)
        t['en']['Bonjour'] = 'Hello'  # mutate after make_tr
        result = tr_fr("Bonjour")
        assert result.resolve('en') == 'Hello'


# ---------------------------------------------------------------------------
# make_tr() — frame inspection (no translations= argument)
# ---------------------------------------------------------------------------

class TestMakeTrFrameInspection:
    def test_basic_translation(self, set_module_translations):
        set_module_translations({'en': {'Bonjour': 'Hello'}})
        tr_fr = make_tr('fr')
        result = tr_fr("Bonjour")
        assert result.resolve('en') == 'Hello'

    def test_none_value_skipped(self, set_module_translations):
        set_module_translations({'en': {'Bonjour': None}})
        tr_fr = make_tr('fr')
        result = tr_fr("Bonjour")
        assert result.resolve('en') == 'Bonjour'  # fallback

    def test_inline_overrides_dict(self, set_module_translations):
        set_module_translations({'en': {'Bonjour': 'Hello dict'}})
        tr_fr = make_tr('fr')
        result = tr_fr("Bonjour", en="Hello inline")
        assert result.resolve('en') == 'Hello inline'

    def test_translations_added_after_make_tr_are_seen(self, set_module_translations):
        """Captured globals is a live dict: _TRANSLATIONS added after make_tr
        is still visible when _tr() is called, because f_globals is the
        module's __dict__ — not a snapshot.
        """
        tr_fr = make_tr('fr')                                   # no _TRANSLATIONS yet
        set_module_translations({'en': {'Bonjour': 'Hello'}})  # added afterwards
        result = tr_fr("Bonjour")
        assert result.resolve('en') == 'Hello'

    def test_no_translations_in_globals(self):
        tr_fr = make_tr('fr')  # _TRANSLATIONS absent
        result = tr_fr("Bonjour", en="Hello")
        assert result.resolve('en') == 'Hello'
        assert result.resolve('fr') == 'Bonjour'


# ---------------------------------------------------------------------------
# TranslatedText.format()
# ---------------------------------------------------------------------------

class TestTranslatedTextFormat:

    def test_substitutes_all_languages(self):
        tt = TranslatedText({'en': 'Hello {name}', 'fr': 'Bonjour {name}'})
        result = tt.format(name='Alice')
        assert result.resolve('en') == 'Hello Alice'
        assert result.resolve('fr') == 'Bonjour Alice'

    def test_multiple_kwargs(self):
        tt = TranslatedText({'en': '{a} and {b}', 'fr': '{a} et {b}'})
        result = tt.format(a='one', b='two')
        assert result.resolve('en') == 'one and two'
        assert result.resolve('fr') == 'one et two'

    def test_returns_translated_text_instance(self):
        tt = TranslatedText({'en': 'Hi {x}'})
        result = tt.format(x='there')
        assert isinstance(result, TranslatedText)

    def test_missing_language_unaffected(self):
        tt = TranslatedText({'en': 'Hello {name}'})   # no 'fr'
        result = tt.format(name='Bob')
        assert result.resolve('en') == 'Hello Bob'
        assert 'fr' not in result

    def test_chain_with_resolve(self):
        tt = TranslatedText({'en': 'Machine {m} ok', 'fr': 'Machine {m} ok'})
        assert tt.format(m='router').resolve('fr') == 'Machine router ok'

    def test_via_tr_and_translations(self):
        """End-to-end: template key in _TRANSLATIONS, .format() at call site."""
        _TRANSLATIONS = {
            'fr': {
                "The machine {machine} is configured":
                    "La machine {machine} est configurée",
            }
        }
        tr_en = make_tr('en', translations=_TRANSLATIONS)
        result = tr_en("The machine {machine} is configured").format(machine='r1')
        assert result.resolve('en') == 'The machine r1 is configured'
        assert result.resolve('fr') == 'La machine r1 est configurée'


# ---------------------------------------------------------------------------
# TranslatedText + concatenation
# ---------------------------------------------------------------------------

class TestTranslatedTextConcat:

    def test_same_key_set(self):
        a = TranslatedText({'fr': 'Bonjour ', 'en': 'Hello '})
        b = TranslatedText({'fr': 'monde', 'en': 'world'})
        result = a + b
        assert isinstance(result, TranslatedText)
        assert result == {'fr': 'Bonjour monde', 'en': 'Hello world'}

    def test_mismatched_set_right_missing_lang(self):
        """The dns1 bug: bilingual + french-only prose must not raise."""
        a = TranslatedText({'fr': 'Titre ', 'en': 'Title '})
        b = TranslatedText({'fr': 'prose'})            # 'en' untranslated
        result = a + b
        assert result == {'fr': 'Titre prose', 'en': 'Title prose'}

    def test_mismatched_set_left_missing_lang(self):
        a = TranslatedText({'fr': 'prose '})           # 'en' untranslated
        b = TranslatedText({'fr': 'Titre', 'en': 'Title'})
        result = a + b
        assert result == {'fr': 'prose Titre', 'en': 'prose Title'}

    def test_default_language_order_preserved(self):
        a = TranslatedText({'fr': 'a', 'en': 'b'})
        result = a + TranslatedText({'fr': 'c'})
        assert next(iter(result)) == 'fr'

    def test_translated_text_plus_str(self):
        a = TranslatedText({'fr': 'Bonjour', 'en': 'Hello'})
        result = a + '!'
        assert result == {'fr': 'Bonjour!', 'en': 'Hello!'}

    def test_str_plus_translated_text(self):
        a = TranslatedText({'fr': 'Bonjour', 'en': 'Hello'})
        result = '## ' + a
        assert result == {'fr': '## Bonjour', 'en': '## Hello'}

    def test_empty_left(self):
        empty = TranslatedText()
        b = TranslatedText({'fr': 'x', 'en': 'y'})
        assert empty + b == {'fr': 'x', 'en': 'y'}

    def test_empty_right(self):
        a = TranslatedText({'fr': 'x', 'en': 'y'})
        assert a + TranslatedText() == {'fr': 'x', 'en': 'y'}

    def test_dns1_chained_pattern(self):
        """`"##" + bilingual_title + "##\\n" + french_only_prose` end-to-end."""
        title = TranslatedText({'fr': 'DNS 1', 'en': 'DNS 1'})
        prose = TranslatedText({'fr': '\nIntroduction FR'})   # 'en' untranslated
        result = '##' + title + '##\n' + prose
        assert isinstance(result, TranslatedText)
        assert result.resolve('fr') == '##DNS 1##\n\nIntroduction FR'
        assert result.resolve('en') == '##DNS 1##\n\nIntroduction FR'
