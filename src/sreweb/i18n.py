"""Translations of the web front-end: the gettext domain ``sreweb`` (``locale/<lang>/LC_MESSAGES/
sreweb.mo``, hand-maintained like ``sre.po``), used by the Python side and served to the browser
as a JSON catalog."""
import gettext
from typing import Callable

DOMAIN = 'sreweb'


def translation(language: str, localedirs) -> gettext.NullTranslations:
    for localedir in localedirs or ():
        try:
            return gettext.translation(DOMAIN, localedir=str(localedir), languages=[language])
        except (FileNotFoundError, OSError):
            continue
    return gettext.NullTranslations()


def translator(language: str, localedirs) -> Callable[[str], str]:
    return translation(language, localedirs).gettext


def catalog(language: str, localedirs) -> dict:
    """``{msgid: msgstr}`` of the language, for the JavaScript side (empty = English)."""
    t = translation(language, localedirs)
    raw = getattr(t, '_catalog', {}) or {}
    return {k: v for k, v in raw.items() if isinstance(k, str) and k and isinstance(v, str)}
