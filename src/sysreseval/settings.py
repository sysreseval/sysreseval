"""Persistent user settings stored in ~/.config/sysreseval (INI format)."""

import configparser
import locale
import os
from pathlib import Path

from SRE import params

_CONFIG_FILE = Path.home() / ".config" / "sysreseval"
_cfg = configparser.ConfigParser()

_content_font_size_listeners: list = []
_system_font_size_listeners: list = []
_language_listeners: list = []


def load():
    _cfg.read(_CONFIG_FILE)
    if not _cfg.get("interface", "language_priority", fallback="") and \
            not _cfg.get("interface", "language", fallback=""):
        if "interface" not in _cfg:
            _cfg["interface"] = {}
        _cfg["interface"]["language_priority"] = _system_locale_lang()


def get_font_size() -> int:
    return _cfg.getint("terminal", "font_size", fallback=params.terminal_font_size)


def get_color_scheme() -> str:
    return _cfg.get("terminal", "color_scheme", fallback=params.terminal_color_scheme)


def get_content_font_size() -> int:
    return _cfg.getint("content", "font_size", fallback=params.content_font_size)


def add_content_font_size_listener(callback):
    _content_font_size_listeners.append(callback)


def set_content_font_size(size: int):
    size = max(6, min(48, size))
    if "content" not in _cfg:
        _cfg["content"] = {}
    _cfg["content"]["font_size"] = str(size)
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w") as f:
        _cfg.write(f)
    for cb in _content_font_size_listeners:
        cb(size)


def get_system_font_size() -> int:
    return _cfg.getint("interface", "font_size", fallback=params.system_font_size)


def add_system_font_size_listener(callback):
    _system_font_size_listeners.append(callback)


def set_system_font_size(size: int):
    size = max(6, min(48, size))
    if "interface" not in _cfg:
        _cfg["interface"] = {}
    _cfg["interface"]["font_size"] = str(size)
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w") as f:
        _cfg.write(f)
    for cb in _system_font_size_listeners:
        cb(size)


def _system_locale_lang() -> str:
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if val and val != "C" and val != "POSIX":
            return val[:2].lower()
    try:
        code = locale.getdefaultlocale()[0]
        if code:
            return code[:2].lower()
    except Exception:
        pass
    return 'en'


def get_language_priority() -> list:
    """Return the user's language priority list (most preferred first)."""
    raw = _cfg.get("interface", "language_priority", fallback='')
    if raw:
        return [c.strip() for c in raw.split(',') if c.strip()]
    # Fallback: old single-language setting or system locale
    single = _cfg.get("interface", "language", fallback=_system_locale_lang())
    return [single]


def get_language() -> str:
    """Return the highest-priority language (compat helper)."""
    p = get_language_priority()
    return p[0] if p else 'en'


def add_language_listener(callback):
    _language_listeners.append(callback)


def set_language_priority(priority: list):
    if "interface" not in _cfg:
        _cfg["interface"] = {}
    _cfg["interface"]["language_priority"] = ','.join(priority)
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w") as f:
        _cfg.write(f)
    for cb in _language_listeners:
        cb(priority)


def set_language(lang: str):
    """Compat wrapper: set a single preferred language."""
    set_language_priority([lang])


def save(font_size: int, color_scheme: str):
    if "terminal" not in _cfg:
        _cfg["terminal"] = {}
    _cfg["terminal"]["font_size"] = str(font_size)
    _cfg["terminal"]["color_scheme"] = color_scheme
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w") as f:
        _cfg.write(f)


def get_schema_curved() -> bool:
    return _cfg.getboolean("schema", "curved", fallback=False)


def get_schema_sep() -> int:
    return _cfg.getint("schema", "sep", fallback=3)


def get_schema_use_icons() -> bool:
    return _cfg.getboolean("schema", "use_icons", fallback=False)


def save_schema(curved: bool, sep: int, use_icons: bool):
    if "schema" not in _cfg:
        _cfg["schema"] = {}
    _cfg["schema"]["curved"] = str(curved).lower()
    _cfg["schema"]["sep"] = str(sep)
    _cfg["schema"]["use_icons"] = str(use_icons).lower()
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w") as f:
        _cfg.write(f)


load()
