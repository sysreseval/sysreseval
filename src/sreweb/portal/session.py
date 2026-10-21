"""The session cookie of the portal: the identity of the browser, signed with the portal secret
(HMAC-SHA256, stdlib), ``HttpOnly``, ``SameSite=Strict``, ``Secure`` behind HTTPS.  Nothing is
stored server-side."""
import base64
import hmac
import hashlib
import json
import time

from ..identity import Identity, IdentityError

COOKIE_NAME = 'sreweb_session'
CSRF_HEADER = 'X-Requested-With'
CSRF_VALUE = 'sre-web'
MAX_AGE = 14 * 24 * 3600


def _sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()


def encode(identity: Identity, secret: str, now: float | None = None) -> str:
    payload = dict(identity.to_dict(), iat=int(now if now is not None else time.time()))
    raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    body = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    return f"{body}.{_sign(secret, raw)}"


def decode(value: str, secret: str, now: float | None = None, max_age: float = MAX_AGE) -> Identity | None:
    """The identity of a cookie value, ``None`` when missing, forged or expired."""
    if not value or '.' not in value:
        return None
    body, _, signature = value.rpartition('.')
    try:
        raw = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(_sign(secret, raw), signature):
        return None
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    iat = payload.pop('iat', 0)
    current = now if now is not None else time.time()
    if not isinstance(iat, (int, float)) or current - iat > max_age or iat > current + 300:
        return None
    try:
        return Identity(**{k: payload[k] for k in ('login', 'fullname', 'email', 'role', 'language', 'anonymous')
                           if k in payload})
    except (IdentityError, TypeError):
        return None


def set_cookie(response, identity: Identity, secret: str, *, secure: bool):
    response.set_cookie(COOKIE_NAME, encode(identity, secret), max_age=MAX_AGE, httponly=True,
                        secure=secure, samesite='Strict', path='/')


def clear_cookie(response):
    response.del_cookie(COOKIE_NAME, path='/')
