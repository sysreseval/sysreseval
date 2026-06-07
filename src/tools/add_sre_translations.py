#!/usr/bin/env python3
"""add-sre-translations — Fill in missing translations in a lab file's _TRANSLATIONS.

Scans the file for tr() strings where the target language is absent or None,
calls the chosen translation service, and writes the results back.

Usage:
    add-sre-translations --language XX [--service YY]
        [--api-key KEY] [--credentials FILE] [--region REGION]
        [--libre-url URL] [--auto] file

Services (--service):
    deepl    DeepL API (default)
             Credentials: --api-key or $DEEPL_API_KEY
    google   Google Cloud Translation
             Credentials: --api-key or $GOOGLE_API_KEY  (REST, simplest)
                      or  --credentials <service-account.json>
                          or $GOOGLE_APPLICATION_CREDENTIALS
                          (requires: pip install google-cloud-translate)
    libre    LibreTranslate (open source, self-hostable)
             Credentials: --api-key or $LIBRE_API_KEY  (optional on some instances)
                          --libre-url for custom instance
    azure    Microsoft Azure Translator
             Credentials: --api-key or $AZURE_TRANSLATOR_KEY
                          --region (default: global)
    amazon   Amazon Translate
             Credentials: standard AWS credential chain (~/.aws/ or env vars)
                          --region or $AWS_DEFAULT_REGION

Interactive mode (default when stdin is a TTY):
    For each string, shows the machine translation and prompts:
      [Enter] to accept, type a correction, or 'q' to stop.
    Translations accepted so far are always saved on stop or Ctrl-C.
    Pass --auto to accept all machine translations without prompting.
"""

import ast
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Shared helpers from the sibling prepare-sre-translations tool.
sys.path.insert(0, str(Path(__file__).parent))
from prepare_sre_translations import (
    build_line_offsets,
    node_span,
    detect_multilingual,
    find_translations_node,
    collect_tr_strings,
    get_existing_translations,
    build_translations_source,
)

# ---------------------------------------------------------------------------
# Services registry
# ---------------------------------------------------------------------------

SERVICES: dict[str, str] = {
    'deepl':  'DeepL API',
    'google': 'Google Cloud Translation',
    'libre':  'LibreTranslate',
    'azure':  'Microsoft Azure Translator',
    'amazon': 'Amazon Translate',
}

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _http_post(url: str, headers: dict, data) -> dict | list:
    body = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(
        url, data=body,
        headers={'Content-Type': 'application/json', **headers},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', errors='replace')
        raise RuntimeError(f"HTTP {e.code} from {url}: {detail}") from e

# ---------------------------------------------------------------------------
# Translation service classes
# ---------------------------------------------------------------------------

class DeepLService:
    """DeepL REST API. Free-tier keys end with ':fx'."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base = (
            'https://api-free.deepl.com' if api_key.endswith(':fx')
            else 'https://api.deepl.com'
        )

    def translate(self, text: str, source_lang: str, target_lang: str) -> str:
        resp = _http_post(
            f'{self.base}/v2/translate',
            {'Authorization': f'DeepL-Auth-Key {self.api_key}'},
            {'text': [text],
             'target_lang': target_lang.upper(),
             'source_lang': source_lang.upper()},
        )
        return resp['translations'][0]['text']


class GoogleService:
    """Google Cloud Translation — REST API key or service-account JSON."""

    def __init__(self, api_key: str | None = None, credentials_file: str | None = None):
        if not api_key and not credentials_file:
            _die("Google requires --api-key / $GOOGLE_API_KEY "
                 "or --credentials / $GOOGLE_APPLICATION_CREDENTIALS.")
        self.api_key = api_key
        self.credentials_file = credentials_file

    def translate(self, text: str, source_lang: str, target_lang: str) -> str:
        if self.api_key:
            return self._via_apikey(text, source_lang, target_lang)
        return self._via_service_account(text, source_lang, target_lang)

    def _via_apikey(self, text: str, source_lang: str, target_lang: str) -> str:
        url = (f'https://translation.googleapis.com/language/translate/v2'
               f'?key={self.api_key}')
        resp = _http_post(url, {}, {
            'q': text, 'target': target_lang,
            'source': source_lang, 'format': 'text',
        })
        return resp['data']['translations'][0]['translatedText']

    def _via_service_account(self, text: str, source_lang: str, target_lang: str) -> str:
        try:
            from google.cloud import translate_v2 as translate      # type: ignore
            import google.oauth2.service_account as sa               # type: ignore
        except ImportError:
            _die("google-cloud-translate is required for service-account credentials.\n"
                 "       Install with: pip install google-cloud-translate")
        creds = sa.Credentials.from_service_account_file(
            self.credentials_file,
            scopes=['https://www.googleapis.com/auth/cloud-translation'],
        )
        client = translate.Client(credentials=creds)
        result = client.translate(text, target_language=target_lang, source_language=source_lang)
        return result['translatedText']


class LibreTranslateService:
    """LibreTranslate — open source, self-hostable."""

    def __init__(self, api_key: str | None = None, url: str = 'https://libretranslate.com'):
        self.api_key = api_key
        self.url = url.rstrip('/')

    def translate(self, text: str, source_lang: str, target_lang: str) -> str:
        data: dict = {'q': text, 'source': source_lang, 'target': target_lang}
        if self.api_key:
            data['api_key'] = self.api_key
        resp = _http_post(f'{self.url}/translate', {}, data)
        return resp['translatedText']


class AzureService:
    """Microsoft Azure Translator."""

    def __init__(self, api_key: str, region: str = 'global'):
        self.api_key = api_key
        self.region = region

    def translate(self, text: str, source_lang: str, target_lang: str) -> str:
        import uuid
        url = (
            'https://api.cognitive.microsofttranslator.com/translate'
            f'?api-version=3.0&from={source_lang}&to={target_lang}'
        )
        resp = _http_post(url, {
            'Ocp-Apim-Subscription-Key': self.api_key,
            'Ocp-Apim-Subscription-Region': self.region,
            'X-ClientTraceId': str(uuid.uuid4()),
        }, [{'Text': text}])
        return resp[0]['translations'][0]['text']


class AmazonService:
    """Amazon Translate — uses the standard AWS credential chain."""

    def __init__(self, region: str | None = None):
        self.region = region

    def translate(self, text: str, source_lang: str, target_lang: str) -> str:
        try:
            import boto3    # type: ignore
        except ImportError:
            _die("boto3 is required for Amazon Translate.\n"
                 "       Install with: pip install boto3")
        kwargs: dict = {}
        if self.region:
            kwargs['region_name'] = self.region
        client = boto3.client('translate', **kwargs)
        result = client.translate_text(
            Text=text,
            SourceLanguageCode=source_lang,
            TargetLanguageCode=target_lang,
        )
        return result['TranslatedText']

# ---------------------------------------------------------------------------
# Service factory
# ---------------------------------------------------------------------------

def make_service(args: argparse.Namespace):
    service = (args.service or 'deepl').lower()
    if service not in SERVICES:
        print(f"Error: unknown service '{service}'. Available services:", file=sys.stderr)
        for k, v in SERVICES.items():
            print(f"  {k:10} {v}", file=sys.stderr)
        sys.exit(1)

    if service == 'deepl':
        key = args.api_key or os.environ.get('DEEPL_API_KEY')
        if not key:
            _die("DeepL requires --api-key or $DEEPL_API_KEY.")
        return DeepLService(key)

    if service == 'google':
        key  = args.api_key     or os.environ.get('GOOGLE_API_KEY')
        cred = args.credentials or os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
        return GoogleService(api_key=key, credentials_file=cred)

    if service == 'libre':
        key = args.api_key or os.environ.get('LIBRE_API_KEY')
        return LibreTranslateService(api_key=key, url=args.libre_url)

    if service == 'azure':
        key = args.api_key or os.environ.get('AZURE_TRANSLATOR_KEY')
        if not key:
            _die("Azure requires --api-key or $AZURE_TRANSLATOR_KEY.")
        return AzureService(key, region=args.region or 'global')

    # amazon
    region = args.region or os.environ.get('AWS_DEFAULT_REGION')
    return AmazonService(region=region)

# ---------------------------------------------------------------------------
# Core logic (testable without CLI)
# ---------------------------------------------------------------------------

def find_missing(tr_strings: set[str], lang_dict: dict) -> list[str]:
    """Return sorted list of strings where translation is absent or None."""
    return sorted(t for t in tr_strings if lang_dict.get(t) is None)


def prompt_translation(text: str, suggestion: str, lang: str) -> str | None:
    """Show suggestion, return accepted/corrected string or None (quit)."""
    print(f"\n[{lang}] {text!r}")
    print(f"     → {suggestion!r}")
    try:
        response = input("  Accept [Enter] or type correction (q to quit): ").strip()
    except EOFError:
        return None
    if response.lower() == 'q':
        return None
    return response if response else suggestion


def write_back(path: Path, tree: ast.Module, updated: dict) -> None:
    """Replace the _TRANSLATIONS assignment in *path* with *updated*."""
    existing_node = find_translations_node(tree)
    if existing_node is None:
        _die("No _TRANSLATIONS dict found. Run prepare-sre-translations first.")
    source_bytes = path.read_text('utf-8').encode('utf-8')
    offsets = build_line_offsets(source_bytes)
    start, end = node_span(offsets, existing_node)
    new_src = build_translations_source(updated).encode('utf-8')
    path.write_text(
        (source_bytes[:start] + new_src + source_bytes[end:]).decode('utf-8'),
        encoding='utf-8',
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _die(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Fill in missing translations in a lab file _TRANSLATIONS dict.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('file',
                        help='Path to the lab .py file')
    parser.add_argument('--language', '-l', required=True, metavar='XX',
                        help='Target language code, e.g. fr, de')
    parser.add_argument('--service', '-s', metavar='YY',
                        help='Translation service: deepl (default), google, libre, azure, amazon')
    parser.add_argument('--api-key', metavar='KEY',
                        help='API key (DeepL, Google API key, LibreTranslate, Azure)')
    parser.add_argument('--credentials', metavar='FILE',
                        help='Service-account JSON file (Google)')
    parser.add_argument('--region', metavar='REGION',
                        help='Region (Azure default: global; optional for Amazon)')
    parser.add_argument('--libre-url', metavar='URL',
                        default='https://libretranslate.com',
                        help='LibreTranslate base URL (default: https://libretranslate.com)')
    parser.add_argument('--auto', action='store_true',
                        help='Accept all machine translations without prompting')
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        _die(f"'{path}' not found.")

    source = path.read_text('utf-8')
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        _die(f"Syntax error in '{path}': {e}")

    _, source_lang = detect_multilingual(tree)
    source_lang = source_lang or 'en'
    target_lang  = args.language

    if source_lang == target_lang:
        _die(f"Target language '{target_lang}' is the same as the file's default language.")

    if find_translations_node(tree) is None:
        _die("No _TRANSLATIONS dict found. Run prepare-sre-translations first.")

    tr_strings = collect_tr_strings(tree)
    if not tr_strings:
        print("No tr() calls found in file.")
        return

    existing  = get_existing_translations(tree)        # {lang: {text: val}}
    lang_dict = dict(existing.get(target_lang, {}))    # mutable copy for target lang
    missing   = find_missing(tr_strings, lang_dict)

    if not missing:
        print(f"All {len(tr_strings)} string(s) already translated to '{target_lang}'.")
        return

    service_name = SERVICES.get((args.service or 'deepl').lower(), args.service or 'deepl')
    print(f"Translating {len(missing)} string(s) to '{target_lang}' "
          f"(source: '{source_lang}') via {service_name}.")

    svc = make_service(args)
    auto = args.auto or not sys.stdin.isatty()
    translated = 0

    try:
        for text in missing:
            try:
                suggestion = svc.translate(text, source_lang, target_lang)
            except RuntimeError as e:
                print(f"  Translation error: {e}", file=sys.stderr)
                break

            if auto:
                lang_dict[text] = suggestion
                print(f"[{target_lang}] {text!r} → {suggestion!r}")
                translated += 1
            else:
                result = prompt_translation(text, suggestion, target_lang)
                if result is None:
                    print("\nStopped. Saving progress so far.")
                    break
                lang_dict[text] = result
                translated += 1

    except KeyboardInterrupt:
        print("\nInterrupted. Saving progress so far.")

    if translated == 0:
        print("No translations written.")
        return

    updated = dict(existing)
    updated[target_lang] = lang_dict
    write_back(path, tree, updated)
    print(f"Wrote {translated} translation(s) to '{path}'.")


if __name__ == '__main__':
    main()
