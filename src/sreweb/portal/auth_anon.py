"""Anonymous mode: a browser gets a pseudonym ``guest-<8 hex>`` on its first visit, kept in the
session cookie, with the display name it chose (used as the full name of the answers)."""
import re
import secrets

from ..identity import Identity

GUEST_PREFIX = 'guest-'
MAX_DISPLAY_NAME = 64
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def clean_display_name(name: str) -> str:
    return _CONTROL.sub('', (name or '')).strip()[:MAX_DISPLAY_NAME]


def new_guest(display_name: str = '', language: str = 'en') -> Identity:
    return Identity(login=GUEST_PREFIX + secrets.token_hex(4), fullname=clean_display_name(display_name),
                    language=language, anonymous=True)


def is_guest(identity: Identity) -> bool:
    return identity.anonymous and identity.login.startswith(GUEST_PREFIX)
