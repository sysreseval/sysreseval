"""The kind of browser behind a ``User-Agent`` header, for the Clients view of the Watch page:
its name, its major version, the system it runs on and whether it is a phone or a tablet.

The header is whatever the client sends: the names given here come from a fixed vocabulary
(an unknown program gives ``''``), the version is a short number, and the text itself is only
handed out cleaned and capped (:func:`clean_user_agent`).  Pure: nothing but the string is read.
"""
import re

from .accesslog import MAX_USER_AGENT

#: The products looked for, in this order: a browser built on another one names both (Edge and
#: Opera say Chrome and Safari, Chrome says Safari, every one says Mozilla).
_BROWSERS = (
    ('Edge', ('Edg', 'EdgA', 'EdgiOS', 'Edge')),
    ('Opera', ('OPR', 'OPT', 'Opera')),
    ('Vivaldi', ('Vivaldi',)),
    ('Samsung Internet', ('SamsungBrowser',)),
    ('Firefox', ('Firefox', 'FxiOS')),
    ('Chromium', ('Chromium',)),
    ('Chrome', ('HeadlessChrome', 'Chrome', 'CriOS')),
)
#: Programs that are no browser, by the product their header starts with.
_TOOLS = (('curl', 'curl'), ('Wget', 'Wget'), ('Python', 'python-requests'), ('Python', 'Python'),
          ('Python', 'aiohttp'))
#: The systems, in this order: Android says Linux, an iPhone says "like Mac OS X".
_SYSTEMS = (('Windows', ('Windows',)), ('Android', ('Android',)), ('iOS', ('iPhone', 'iPad', 'iPod')),
            ('ChromeOS', ('CrOS',)), ('macOS', ('Macintosh', 'Mac OS X')), ('Linux', ('Linux', 'X11')))
_MOBILE = ('Mobi', 'Android', 'iPhone', 'iPad', 'iPod')

_SAFARI = re.compile(r'Version/(\d{1,4})[\d.]*.* Safari/')
_CONTROL = re.compile(r'[^\x20-\x7e]')


def clean_user_agent(ua) -> str:
    """The header as it may be shown: printable ASCII only, capped at ``MAX_USER_AGENT``."""
    return _CONTROL.sub('', ua if isinstance(ua, str) else '')[:MAX_USER_AGENT].strip()


def _version(ua: str, product: str) -> str | None:
    """The major version after ``product/`` at a word start, ``''`` without digits; ``None``
    when the product is not named."""
    match = re.search(r'(?:^|[\s(;])' + re.escape(product) + r'/(\d{1,4})?', ua)
    if match is None:
        return None
    return match.group(1) or ''


def parse_user_agent(ua) -> dict:
    """``{'browser', 'version', 'system', 'mobile'}`` of a ``User-Agent`` header: the name of
    the browser (``''`` unknown), its major version (``''`` unknown), the system (``''``
    unknown) and whether the header says a phone or a tablet."""
    ua = clean_user_agent(ua)
    browser, version = '', ''
    for name, products in _BROWSERS:
        found = next((v for v in (_version(ua, product) for product in products) if v is not None), None)
        if found is not None:
            browser, version = name, found
            break
    else:
        safari = _SAFARI.search(ua)
        if safari is not None:
            browser, version = 'Safari', safari.group(1)
        else:
            for name, product in _TOOLS:
                found = _version(ua, product) if ua.startswith(product) else None
                if found is not None:
                    browser, version = name, found
                    break
    system = next((name for name, marks in _SYSTEMS if any(mark in ua for mark in marks)), '')
    return {'browser': browser, 'version': version, 'system': system,
            'mobile': any(mark in ua for mark in _MOBILE)}
