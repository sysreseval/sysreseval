"""Tests for src/tools/add_sre_translations.py."""
import ast
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))
import add_sre_translations as mod
from add_sre_translations import (
    DeepLService, GoogleService, LibreTranslateService, AzureService, AmazonService,
    find_missing, prompt_translation, write_back, make_service,
)
from prepare_sre_translations import get_existing_translations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lab(tmp_path: Path, src: str) -> Path:
    p = tmp_path / 'lab.py'
    p.write_text(textwrap.dedent(src), encoding='utf-8')
    return p


def _parse(src: str) -> ast.Module:
    return ast.parse(textwrap.dedent(src))


def _run(path: Path, *cli_args: str) -> str:
    old = sys.argv
    sys.argv = ['add-sre-translations', *cli_args, str(path)]
    try:
        mod.main()
    except SystemExit as e:
        if e.code != 0:
            raise
    finally:
        sys.argv = old
    return path.read_text('utf-8')


def _run_err(path: Path, *cli_args: str) -> int:
    old = sys.argv
    sys.argv = ['add-sre-translations', *cli_args, str(path)]
    try:
        with pytest.raises(SystemExit) as exc:
            mod.main()
        return exc.value.code
    finally:
        sys.argv = old


# ---------------------------------------------------------------------------
# find_missing
# ---------------------------------------------------------------------------

class TestFindMissing:
    def test_none_value_is_missing(self):
        assert find_missing({'Hello'}, {'Hello': None}) == ['Hello']

    def test_absent_key_is_missing(self):
        assert find_missing({'Hello'}, {}) == ['Hello']

    def test_translated_not_missing(self):
        assert find_missing({'Hello'}, {'Hello': 'Bonjour'}) == []

    def test_sorted_output(self):
        result = find_missing({'B', 'A', 'C'}, {})
        assert result == ['A', 'B', 'C']

    def test_mixed(self):
        result = find_missing({'A', 'B', 'C'}, {'A': 'Aa', 'B': None})
        assert result == ['B', 'C']


# ---------------------------------------------------------------------------
# prompt_translation
# ---------------------------------------------------------------------------

class TestPromptTranslation:
    def test_enter_accepts_suggestion(self, capsys):
        with patch('builtins.input', return_value=''):
            result = prompt_translation('Hello', 'Bonjour', 'fr')
        assert result == 'Bonjour'

    def test_typed_text_replaces_suggestion(self, capsys):
        with patch('builtins.input', return_value='Salut'):
            result = prompt_translation('Hello', 'Bonjour', 'fr')
        assert result == 'Salut'

    def test_q_returns_none(self):
        with patch('builtins.input', return_value='q'):
            result = prompt_translation('Hello', 'Bonjour', 'fr')
        assert result is None

    def test_Q_also_returns_none(self):
        with patch('builtins.input', return_value='Q'):
            result = prompt_translation('Hello', 'Bonjour', 'fr')
        assert result is None

    def test_eof_returns_none(self):
        with patch('builtins.input', side_effect=EOFError):
            result = prompt_translation('Hello', 'Bonjour', 'fr')
        assert result is None

    def test_output_shows_lang_and_suggestion(self, capsys):
        with patch('builtins.input', return_value=''):
            prompt_translation('Hello', 'Bonjour', 'fr')
        out = capsys.readouterr().out
        assert '[fr]' in out
        assert "'Hello'" in out
        assert "'Bonjour'" in out


# ---------------------------------------------------------------------------
# DeepLService
# ---------------------------------------------------------------------------

class TestDeepLService:
    def test_free_key_uses_api_free(self):
        svc = DeepLService('mykey:fx')
        assert 'api-free' in svc.base

    def test_paid_key_uses_api(self):
        svc = DeepLService('mykey')
        assert svc.base == 'https://api.deepl.com'

    def test_translate_call(self):
        svc = DeepLService('key:fx')
        with patch('add_sre_translations._http_post',
                   return_value={'translations': [{'text': 'Bonjour'}]}) as mock:
            result = svc.translate('Hello', 'en', 'fr')
        assert result == 'Bonjour'
        url, headers, data = mock.call_args.args
        assert 'api-free.deepl.com' in url
        assert headers == {'Authorization': 'DeepL-Auth-Key key:fx'}
        assert data['text'] == ['Hello']
        assert data['target_lang'] == 'FR'
        assert data['source_lang'] == 'EN'


# ---------------------------------------------------------------------------
# LibreTranslateService
# ---------------------------------------------------------------------------

class TestLibreTranslateService:
    def test_translate_without_key(self):
        svc = LibreTranslateService()
        with patch('add_sre_translations._http_post',
                   return_value={'translatedText': 'Bonjour'}) as mock:
            result = svc.translate('Hello', 'en', 'fr')
        assert result == 'Bonjour'
        _, _, data = mock.call_args.args
        assert 'api_key' not in data

    def test_translate_with_key(self):
        svc = LibreTranslateService(api_key='secret')
        with patch('add_sre_translations._http_post',
                   return_value={'translatedText': 'Bonjour'}) as mock:
            svc.translate('Hello', 'en', 'fr')
        _, _, data = mock.call_args.args
        assert data['api_key'] == 'secret'

    def test_custom_url(self):
        svc = LibreTranslateService(url='http://localhost:5000')
        with patch('add_sre_translations._http_post',
                   return_value={'translatedText': 'Bonjour'}) as mock:
            svc.translate('Hello', 'en', 'fr')
        url, _, _ = mock.call_args.args
        assert url.startswith('http://localhost:5000')

    def test_trailing_slash_stripped(self):
        svc = LibreTranslateService(url='http://localhost:5000/')
        assert svc.url == 'http://localhost:5000'


# ---------------------------------------------------------------------------
# AzureService
# ---------------------------------------------------------------------------

class TestAzureService:
    def test_translate_call(self):
        svc = AzureService('azure-key', region='westeurope')
        with patch('add_sre_translations._http_post',
                   return_value=[{'translations': [{'text': 'Bonjour', 'to': 'fr'}]}]) as mock:
            result = svc.translate('Hello', 'en', 'fr')
        assert result == 'Bonjour'
        url, headers, data = mock.call_args.args
        assert 'cognitive.microsofttranslator.com' in url
        assert 'from=en' in url
        assert 'to=fr' in url
        assert headers['Ocp-Apim-Subscription-Key'] == 'azure-key'
        assert headers['Ocp-Apim-Subscription-Region'] == 'westeurope'
        assert data == [{'Text': 'Hello'}]

    def test_default_region(self):
        svc = AzureService('key')
        assert svc.region == 'global'


# ---------------------------------------------------------------------------
# GoogleService
# ---------------------------------------------------------------------------

class TestGoogleService:
    def test_api_key_path(self):
        svc = GoogleService(api_key='gkey')
        with patch('add_sre_translations._http_post',
                   return_value={'data': {'translations': [{'translatedText': 'Bonjour'}]}}) as mock:
            result = svc.translate('Hello', 'en', 'fr')
        assert result == 'Bonjour'
        url, _, data = mock.call_args.args
        assert 'googleapis.com' in url
        assert 'gkey' in url
        assert data['q'] == 'Hello'
        assert data['target'] == 'fr'

    def test_missing_credentials_raises(self):
        with pytest.raises(SystemExit):
            GoogleService()

    def test_service_account_missing_package(self):
        svc = GoogleService(credentials_file='/fake/key.json')
        with patch.dict(sys.modules, {'google.cloud': None, 'google.cloud.translate_v2': None}):
            with pytest.raises(SystemExit):
                svc.translate('Hello', 'en', 'fr')


# ---------------------------------------------------------------------------
# AmazonService
# ---------------------------------------------------------------------------

class TestAmazonService:
    def _fake_boto3(self):
        """Return a MagicMock that stands in for the boto3 module."""
        fake = MagicMock()
        fake.client.return_value.translate_text.return_value = {'TranslatedText': 'Bonjour'}
        return fake

    def test_translate_call(self):
        svc = AmazonService(region='us-east-1')
        fake = self._fake_boto3()
        with patch.dict(sys.modules, {'boto3': fake}):
            result = svc.translate('Hello', 'en', 'fr')
        assert result == 'Bonjour'
        fake.client.assert_called_once_with('translate', region_name='us-east-1')
        fake.client.return_value.translate_text.assert_called_once_with(
            Text='Hello', SourceLanguageCode='en', TargetLanguageCode='fr')

    def test_no_region(self):
        svc = AmazonService()
        fake = self._fake_boto3()
        with patch.dict(sys.modules, {'boto3': fake}):
            svc.translate('Hello', 'en', 'fr')
        fake.client.assert_called_once_with('translate')   # no region_name kwarg

    def test_missing_boto3(self):
        svc = AmazonService()
        with patch.dict(sys.modules, {'boto3': None}):
            with pytest.raises(SystemExit):
                svc.translate('Hello', 'en', 'fr')


# ---------------------------------------------------------------------------
# make_service — credential loading and unknown service
# ---------------------------------------------------------------------------

class TestMakeService:
    def _args(self, **kw):
        defaults = dict(service=None, api_key=None, credentials=None,
                        region=None, libre_url='https://libretranslate.com')
        defaults.update(kw)
        import argparse
        return argparse.Namespace(**defaults)

    def test_deepl_from_arg(self):
        svc = make_service(self._args(service='deepl', api_key='k:fx'))
        assert isinstance(svc, DeepLService)

    def test_deepl_from_env(self, monkeypatch):
        monkeypatch.setenv('DEEPL_API_KEY', 'envkey:fx')
        svc = make_service(self._args(service='deepl'))
        assert isinstance(svc, DeepLService)
        assert svc.api_key == 'envkey:fx'

    def test_deepl_missing_key_exits(self, monkeypatch):
        monkeypatch.delenv('DEEPL_API_KEY', raising=False)
        with pytest.raises(SystemExit):
            make_service(self._args(service='deepl'))

    def test_libre_no_key_ok(self):
        svc = make_service(self._args(service='libre'))
        assert isinstance(svc, LibreTranslateService)
        assert svc.api_key is None

    def test_azure_from_env(self, monkeypatch):
        monkeypatch.setenv('AZURE_TRANSLATOR_KEY', 'azkey')
        svc = make_service(self._args(service='azure'))
        assert isinstance(svc, AzureService)

    def test_azure_missing_key_exits(self, monkeypatch):
        monkeypatch.delenv('AZURE_TRANSLATOR_KEY', raising=False)
        with pytest.raises(SystemExit):
            make_service(self._args(service='azure'))

    def test_amazon_region_from_env(self, monkeypatch):
        monkeypatch.setenv('AWS_DEFAULT_REGION', 'eu-west-1')
        svc = make_service(self._args(service='amazon'))
        assert isinstance(svc, AmazonService)
        assert svc.region == 'eu-west-1'

    def test_unknown_service_exits(self):
        with pytest.raises(SystemExit):
            make_service(self._args(service='unknown'))

    def test_unknown_service_lists_available(self, capsys):
        with pytest.raises(SystemExit):
            make_service(self._args(service='unknown'))
        err = capsys.readouterr().err
        for name in ('deepl', 'google', 'libre', 'azure', 'amazon'):
            assert name in err


# ---------------------------------------------------------------------------
# write_back
# ---------------------------------------------------------------------------

class TestWriteBack:
    def test_updates_translations_in_file(self, tmp_path):
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'Hello': None}}
            title = tr("Hello")
        """)
        tree = ast.parse(p.read_text())
        write_back(p, tree, {'fr': {'Hello': 'Bonjour'}})
        result = p.read_text()
        assert "'Hello': 'Bonjour'" in result
        assert result.count('_TRANSLATIONS') == 1

    def test_no_translations_node_exits(self, tmp_path):
        p = _lab(tmp_path, "title = tr('x')\n")
        tree = ast.parse(p.read_text())
        with pytest.raises(SystemExit):
            write_back(p, tree, {'fr': {'x': 'y'}})


# ---------------------------------------------------------------------------
# Integration — main()
# ---------------------------------------------------------------------------

class TestIntegration:
    def _lab_with_translations(self, tmp_path, lang_dict=None):
        """A minimal multilingual lab file ready for add-sre-translations."""
        if lang_dict is None:
            lang_dict = {'fr': {'Hello': None}}
        fr_entries = ', '.join(f"{k!r}: {v!r}" for k, v in lang_dict.get('fr', {}).items())
        return _lab(tmp_path, f"""
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {{'fr': {{{fr_entries}}}}}
            title = tr("Hello")
        """)

    def test_auto_mode_writes_translation(self, tmp_path):
        p = self._lab_with_translations(tmp_path)
        mock_svc = MagicMock()
        mock_svc.translate.return_value = 'Bonjour'
        with patch('add_sre_translations.make_service', return_value=mock_svc):
            result = _run(p, '--language', 'fr', '--service', 'deepl',
                          '--api-key', 'k', '--auto')
        assert "'Hello': 'Bonjour'" in result

    def test_interactive_accept(self, tmp_path):
        p = self._lab_with_translations(tmp_path)
        mock_svc = MagicMock()
        mock_svc.translate.return_value = 'Bonjour'
        with patch('add_sre_translations.make_service', return_value=mock_svc), \
             patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value=''):   # Enter = accept
            result = _run(p, '--language', 'fr', '--service', 'deepl', '--api-key', 'k')
        assert "'Hello': 'Bonjour'" in result

    def test_interactive_correction(self, tmp_path):
        p = self._lab_with_translations(tmp_path)
        mock_svc = MagicMock()
        mock_svc.translate.return_value = 'Bonjour'
        with patch('add_sre_translations.make_service', return_value=mock_svc), \
             patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value='Salut'):
            result = _run(p, '--language', 'fr', '--service', 'deepl', '--api-key', 'k')
        assert "'Hello': 'Salut'" in result

    def test_interactive_quit_saves_progress(self, tmp_path):
        """First string accepted, second quit — first must be saved."""
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'A': None, 'B': None}}
            title = tr("A")
            info = tr("B")
        """)
        mock_svc = MagicMock()
        mock_svc.translate.side_effect = ['Aa_fr', 'Bb_fr']
        # First prompt: accept; second prompt: quit
        with patch('add_sre_translations.make_service', return_value=mock_svc), \
             patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', side_effect=['', 'q']):
            result = _run(p, '--language', 'fr', '--service', 'deepl', '--api-key', 'k')
        assert "'A': 'Aa_fr'" in result
        assert "'B': None" in result   # not translated (quit before)

    def test_already_translated_no_op(self, tmp_path, capsys):
        p = self._lab_with_translations(tmp_path, lang_dict={'fr': {'Hello': 'Bonjour'}})
        mock_svc = MagicMock()
        with patch('add_sre_translations.make_service', return_value=mock_svc):
            _run(p, '--language', 'fr', '--service', 'deepl', '--api-key', 'k', '--auto')
        mock_svc.translate.assert_not_called()
        assert 'already translated' in capsys.readouterr().out

    def test_no_translations_dict_exits(self, tmp_path):
        p = _lab(tmp_path, "title = tr('Hello')\n")
        code = _run_err(p, '--language', 'fr', '--api-key', 'k')
        assert code != 0

    def test_same_lang_as_default_exits(self, tmp_path):
        p = self._lab_with_translations(tmp_path)
        code = _run_err(p, '--language', 'en', '--api-key', 'k')
        assert code != 0

    def test_unknown_service_exits_with_list(self, tmp_path, capsys):
        p = self._lab_with_translations(tmp_path)
        code = _run_err(p, '--language', 'fr', '--service', 'babelfish', '--api-key', 'k')
        assert code != 0
        err = capsys.readouterr().err
        assert 'deepl' in err

    def test_translation_error_saves_progress(self, tmp_path, capsys):
        """If the service throws, already-translated strings are saved."""
        p = _lab(tmp_path, """
            from SRE.lib_sre import make_tr
            default_language = 'en'
            tr = make_tr(default_language)
            _TRANSLATIONS = {'fr': {'A': None, 'B': None}}
            x = tr("A")
            y = tr("B")
        """)
        mock_svc = MagicMock()
        mock_svc.translate.side_effect = ['Aa_fr', RuntimeError("API down")]
        with patch('add_sre_translations.make_service', return_value=mock_svc):
            _run(p, '--language', 'fr', '--service', 'deepl', '--api-key', 'k', '--auto')
        result = p.read_text()
        assert "'A': 'Aa_fr'" in result
        assert "'B': None" in result
