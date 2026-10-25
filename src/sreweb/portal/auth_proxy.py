"""Proxy mode: a reverse proxy of ``trusted_proxies`` (Apache ``mod_authnz_ldap``...) authenticates
the browser itself and passes the identity in request headers, read again on every request (no
session cookie).  Pure functions, no aiohttp: the header values as aiohttp gives them (UTF-8
decoded with ``surrogateescape``) in, an ``Identity`` out.  The role comes from the header tests
(``instructor_groups`` on the groups header, ``instructor_values`` on ``instructor_header``); the
LDAP tests of ``ldap_roles`` are applied afterwards by the portal (``roles.py``)."""
import re

from ..config import ProxyAuthConfig
from ..identity import Identity, IdentityError, ROLE_INSTRUCTOR, ROLE_STUDENT, is_valid_login

MAX_FULLNAME = 64          # like auth_anon.MAX_DISPLAY_NAME
MAX_EMAIL = 254
#: What Apache's mod_headers writes for ``%{VAR}e`` when the variable is not set.
NULL_PLACEHOLDER = '(null)'
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def decode_header_value(value, limit: int | None = None) -> str:
    """The text of a header value.  aiohttp decodes the bytes as UTF-8 with ``surrogateescape``,
    so a Latin-1 value arrives with surrogates: re-encoded, then decoded as UTF-8 or, failing
    that, Latin-1.  Control characters dropped, blanks trimmed, capped at *limit* characters;
    the mod_headers placeholder ``(null)`` (an unset variable) and ``None`` count as empty."""
    if value is None:
        return ''
    raw = str(value).encode('utf-8', 'surrogateescape')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')
    text = _CONTROL.sub('', text).strip()
    if text == NULL_PLACEHOLDER:
        return ''
    return text[:limit].strip() if limit else text


def split_groups(value: str, separator: str) -> list:
    """The values of the groups header (``cn=a,…; cn=b,…``): split on *separator*, trimmed,
    the empty ones dropped."""
    return [g.strip() for g in (value or '').split(separator) if g.strip()]


def is_instructor(groups, instructor_groups) -> bool:
    """Whether one of *groups* is one of *instructor_groups* (whole values, case-insensitive)."""
    wanted = {str(g).strip().lower() for g in instructor_groups if str(g).strip()}
    return bool(wanted) and any(g.lower() in wanted for g in groups)


def identity_from_headers(cfg: ProxyAuthConfig, headers, language: str) -> Identity | None:
    """The identity of a request coming from a trusted proxy (*headers*: any mapping with a
    case-insensitive ``get``, like aiohttp's): ``None`` without a login header, ``IdentityError``
    when its value is not a valid login (it is never truncated)."""
    login = decode_header_value(headers.get(cfg.header_login))
    if not login:
        return None
    if not is_valid_login(login):
        raise IdentityError(f"invalid login {login[:80]!r} in the {cfg.header_login} header")
    groups = split_groups(decode_header_value(headers.get(cfg.header_groups)), cfg.groups_separator)
    extra = (split_groups(decode_header_value(headers.get(cfg.instructor_header)), cfg.groups_separator)
             if cfg.instructor_header else [])
    instructor = is_instructor(groups, cfg.instructor_groups) or is_instructor(extra, cfg.instructor_values)
    return Identity(login=login,
                    fullname=decode_header_value(headers.get(cfg.header_fullname), MAX_FULLNAME),
                    email=decode_header_value(headers.get(cfg.header_email), MAX_EMAIL),
                    role=ROLE_INSTRUCTOR if instructor else ROLE_STUDENT,
                    language=language, anonymous=False)
