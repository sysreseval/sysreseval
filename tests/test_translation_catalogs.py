"""The catalogs of the interface languages agree with the French one, the reference.

Every language of ``TRANSLATION_LANGS`` (Makefile) has the three catalogs of the interface:
the Qt GUI (``translations/sysreseval_<l>.ts`` + ``.qm``), the CLI (``locale/<l>/LC_MESSAGES/
sre.po`` + ``.mo``) and the web front-end (``locale/<l>/LC_MESSAGES/sreweb.po`` + ``.mo``).
Each catalog holds the strings of the French one, translated, with the same placeholders, and
its compiled file is up to date; ``debian/rules`` and the install files ship every language.
A string added by hand to a French catalog is therefore added to the others too.
"""
import gettext
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = 'fr'
DOMAINS = ('sre', 'sreweb')

PO_ESCAPE = re.compile(r'\\(.)')
PO_ESCAPES = {'n': '\n', 't': '\t', '"': '"', "'": "'", '\\': '\\'}
# {name} / {} of str.format, %(name)s / %s / %d of the % operator
PLACEHOLDER = re.compile(r'\{\w*\}|%\(\w+\)[sd]|%[sd]')


def translation_langs() -> list:
    """The languages of ``TRANSLATION_LANGS := …`` in the Makefile."""
    match = re.search(r'^TRANSLATION_LANGS\s*:=\s*(.+)$', (ROOT / 'Makefile').read_text(), re.M)
    assert match, 'no TRANSLATION_LANGS in the Makefile'
    return match.group(1).split()


LANGS = translation_langs()
OTHERS = [lang for lang in LANGS if lang != REFERENCE]


def po_path(lang: str, domain: str) -> Path:
    return ROOT / 'locale' / lang / 'LC_MESSAGES' / f'{domain}.po'


def ts_path(lang: str) -> Path:
    return ROOT / 'translations' / f'sysreseval_{lang}.ts'


def parse_po(path: Path) -> dict:
    """``{msgid: msgstr}`` of a .po file without its header (the multi-line strings joined, the
    escapes decoded)."""
    entries = {}
    msgid = msgstr = current = None

    def decode(text: str) -> str:
        return PO_ESCAPE.sub(lambda m: PO_ESCAPES.get(m.group(1), m.group(1)), text)

    def flush():
        if msgid:
            entries[msgid] = msgstr or ''

    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('msgid '):
            flush()
            msgid, msgstr, current = decode(line[6:].strip()[1:-1]), None, 'id'
        elif line.startswith('msgstr '):
            msgstr, current = decode(line[7:].strip()[1:-1]), 'str'
        elif line.startswith('"'):
            piece = decode(line[1:-1])
            if current == 'id':
                msgid += piece
            elif current == 'str':
                msgstr += piece
    flush()
    return entries


def parse_ts(path: Path) -> dict:
    """``{(context, source): (translation, type)}`` of the messages of a Qt .ts file that are
    still in the sources (the vanished and obsolete ones left out)."""
    messages = {}
    for context in ET.parse(path).getroot().iter('context'):
        name = context.findtext('name')
        for message in context.iter('message'):
            translation = message.find('translation')
            kind = translation.get('type', '')
            if kind in ('vanished', 'obsolete'):
                continue
            messages[(name, message.findtext('source'))] = (translation.text or '', kind)
    return messages


def placeholders(text: str) -> list:
    return sorted(PLACEHOLDER.findall(text))


def test_the_reference_is_a_translation_language():
    assert REFERENCE in LANGS and 'de' in LANGS


@pytest.mark.parametrize('lang', LANGS)
def test_every_catalog_and_compiled_file_exists(lang):
    for domain in DOMAINS:
        assert po_path(lang, domain).is_file()
        assert po_path(lang, domain).with_suffix('.mo').is_file(), 'run msgfmt (make translations)'
    assert ts_path(lang).is_file()
    assert ts_path(lang).with_suffix('.qm').is_file(), 'run lrelease (make translations)'


@pytest.mark.parametrize('domain', DOMAINS)
@pytest.mark.parametrize('lang', OTHERS)
def test_po_has_the_strings_of_the_reference(lang, domain):
    reference = parse_po(po_path(REFERENCE, domain))
    entries = parse_po(po_path(lang, domain))
    assert sorted(set(reference) - set(entries)) == [], f'missing in {lang}/{domain}.po'
    assert sorted(set(entries) - set(reference)) == [], f'not in {REFERENCE}/{domain}.po'


@pytest.mark.parametrize('domain', DOMAINS)
@pytest.mark.parametrize('lang', LANGS)
def test_po_is_translated_with_the_placeholders_kept(lang, domain):
    for msgid, msgstr in parse_po(po_path(lang, domain)).items():
        assert msgstr, f'untranslated in {lang}/{domain}.po: {msgid!r}'
        assert placeholders(msgid) == placeholders(msgstr), f'{lang}/{domain}.po: {msgid!r}'


@pytest.mark.parametrize('domain', DOMAINS)
@pytest.mark.parametrize('lang', LANGS)
def test_mo_matches_po(lang, domain):
    translation = gettext.translation(domain, localedir=str(ROOT / 'locale'), languages=[lang])
    for msgid, msgstr in parse_po(po_path(lang, domain)).items():
        assert translation.gettext(msgid) == msgstr, f'{lang}/{domain}.mo out of date: {msgid!r}'


@pytest.mark.parametrize('lang', OTHERS)
def test_ts_has_the_strings_of_the_reference(lang):
    reference = parse_ts(ts_path(REFERENCE))
    messages = parse_ts(ts_path(lang))
    assert sorted(set(reference) - set(messages)) == [], f'missing in sysreseval_{lang}.ts'
    assert sorted(set(messages) - set(reference)) == [], f'not in sysreseval_{REFERENCE}.ts'


@pytest.mark.parametrize('lang', LANGS)
def test_ts_is_translated_with_the_placeholders_kept(lang):
    for (context, source), (translation, kind) in parse_ts(ts_path(lang)).items():
        assert kind != 'unfinished' and translation, f'sysreseval_{lang}.ts: {context} {source!r}'
        assert placeholders(source) == placeholders(translation), f'sysreseval_{lang}.ts: {source!r}'


@pytest.mark.parametrize('lang', LANGS)
def test_qm_matches_ts(lang):
    QtCore = pytest.importorskip('PySide6.QtCore')
    translator = QtCore.QTranslator()
    assert translator.load(str(ts_path(lang).with_suffix('.qm')))
    for (context, source), (translation, _kind) in parse_ts(ts_path(lang)).items():
        assert translator.translate(context, source) == translation, \
            f'sysreseval_{lang}.qm out of date: {context} {source!r}'


@pytest.mark.parametrize('lang', LANGS)
def test_the_debian_packages_ship_every_language(lang):
    rules = (ROOT / 'debian' / 'rules').read_text()
    match = re.search(r'for l in ([\w ]+); do', rules)
    assert match and match.group(1).split() == LANGS, 'debian/rules: the loop of the catalogs'
    install = (ROOT / 'debian' / 'sysreseval.install').read_text().splitlines()
    assert f'debian/build/sysreseval_{lang}.qm usr/share/sysreseval/translations/' in install
    assert f'debian/build/{lang}/sre.mo usr/share/locale/{lang}/LC_MESSAGES/' in install
    web_install = (ROOT / 'debian' / 'sysreseval-web.install').read_text().splitlines()
    assert f'debian/build/{lang}/sreweb.mo usr/share/locale/{lang}/LC_MESSAGES/' in web_install
