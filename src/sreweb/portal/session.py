"""The session cookie of the portal: the identity of the browser, signed with the portal secret
(HMAC-SHA256, stdlib), ``HttpOnly``, ``SameSite=Strict``, ``Secure`` behind HTTPS.  Nothing is
stored server-side.  A cookie lives ``MAX_AGE`` seconds from the sign-in (its ``iat``): a re-issue
(the language change of ``/api/language``) keeps that date, so that a session never slides, and
the role, group and administrator flag it carries are those of the sign-in until then."""
import base64
import hmac
import hashlib
import json
import time

from ..identity import Identity, IdentityError, request_key

COOKIE_NAME = 'sreweb_session'
#: The issue time of the session cookie of the request (``request[SESSION_IAT_KEY]``, set by the
#: identity middleware with the identity): what a re-issue keeps.
SESSION_IAT_KEY = request_key('session_iat')
CSRF_HEADER = 'X-Requested-With'
CSRF_VALUE = 'sre-web'
MAX_AGE = 14 * 24 * 3600
LANG_COOKIE = 'sreweb_lang'          # the language outside the session (proxy mode has no session cookie)
LANG_MAX_AGE = 365 * 24 * 3600


def _sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()


def encode(identity: Identity, secret: str, now: float | None = None) -> str:
    payload = dict(identity.to_dict(), iat=int(now if now is not None else time.time()))
    raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    body = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    return f"{body}.{_sign(secret, raw)}"


def decode_iat(value: str, secret: str, now: float | None = None,
               max_age: float = MAX_AGE) -> tuple[Identity | None, int | None]:
    """The identity of a cookie value and the time it was issued (its ``iat``, what a re-issue
    keeps); ``(None, None)`` when missing, forged or expired."""
    if not value or '.' not in value:
        return None, None
    body, _, signature = value.rpartition('.')
    try:
        raw = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
    except (ValueError, TypeError):
        return None, None
    if not hmac.compare_digest(_sign(secret, raw), signature):
        return None, None
    try:
        payload = json.loads(raw)
    except ValueError:
        return None, None
    if not isinstance(payload, dict):
        return None, None
    iat = payload.pop('iat', 0)
    current = now if now is not None else time.time()
    if not isinstance(iat, (int, float)) or current - iat > max_age or iat > current + 300:
        return None, None
    try:
        identity = Identity(**{k: payload[k] for k in ('login', 'fullname', 'email', 'role', 'language', 'anonymous',
                                                       'group', 'administrator') if k in payload})
    except (IdentityError, TypeError):
        return None, None
    return identity, int(iat)


def decode(value: str, secret: str, now: float | None = None, max_age: float = MAX_AGE) -> Identity | None:
    """The identity of a cookie value, ``None`` when missing, forged or expired."""
    return decode_iat(value, secret, now, max_age)[0]


def set_cookie(response, identity: Identity, secret: str, *, secure: bool, issued_at: float | None = None,
               now: float | None = None):
    """A new session cookie (a sign-in), or, with *issued_at*, the cookie of the session issued
    then signed again with *identity* (a language change): it keeps its issue date and the time
    it has left, so that a session never lives past ``MAX_AGE`` from the sign-in."""
    current = now if now is not None else time.time()
    if issued_at is None:
        issued_at, max_age = current, MAX_AGE
    else:
        max_age = max(1, int(issued_at + MAX_AGE - current))
    response.set_cookie(COOKIE_NAME, encode(identity, secret, now=issued_at), max_age=max_age, httponly=True,
                        secure=secure, samesite='Strict', path='/')


def clear_cookie(response):
    response.del_cookie(COOKIE_NAME, path='/')


def choose_language(candidates, languages) -> str:
    """The first of *candidates* (``?lang=``, the language cookie...) among *languages*, else
    the first language."""
    for candidate in candidates:
        if candidate and candidate in languages:
            return candidate
    return languages[0]


def set_language_cookie(response, language: str, *, secure: bool):
    response.set_cookie(LANG_COOKIE, language, max_age=LANG_MAX_AGE, httponly=True, secure=secure,
                        samesite='Lax', path='/')
