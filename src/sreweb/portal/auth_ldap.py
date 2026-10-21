"""LDAP mode: the user binds with their own password (``ldap3``), the portal reads their full
name and e-mail, and the instructor role comes from a group.

Two ways to find the user's DN: a template (``uid={login},ou=people,...``) or a search with a
service account (``search_base`` + ``search_filter``).  The role: the DNs of
``instructor_groups`` are matched against the ``memberOf`` attribute of the user, or, with
``group_filter``, found by a search of the groups holding the user's DN.  Every ldap3 call runs in
a thread (the library is synchronous).
"""
import asyncio
import logging
import warnings

from ..config import LdapConfig
from ..identity import Identity, ROLE_INSTRUCTOR, ROLE_STUDENT, is_valid_login

log = logging.getLogger('sreweb.portal')


class LdapError(Exception):
    """The directory could not be used (not a wrong password)."""


def _escape_filter(value: str) -> str:
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(value)


def _escape_rdn(value: str) -> str:
    from ldap3.utils.dn import escape_rdn
    return escape_rdn(value)


def _first(entry, attribute: str) -> str:
    try:
        values = entry[attribute].values
    except (KeyError, AttributeError):
        return ''
    for v in values or []:
        if isinstance(v, bytes):
            v = v.decode('utf-8', 'replace')
        if v:
            return str(v)
    return ''


def _all(entry, attribute: str) -> list:
    try:
        values = entry[attribute].values
    except (KeyError, AttributeError):
        return []
    return [v.decode('utf-8', 'replace') if isinstance(v, bytes) else str(v) for v in values or []]


class LdapAuthenticator:
    def __init__(self, cfg: LdapConfig):
        self.cfg = cfg

    async def authenticate(self, login: str, password: str, language: str = 'en') -> Identity | None:
        """The identity of *login* when *password* is right, ``None`` otherwise; ``LdapError``
        when the directory is unreachable."""
        if not is_valid_login(login) or not password:
            return None
        return await asyncio.to_thread(self._authenticate, login, password, language)

    # -- synchronous part (a thread) ----------------------------------------------------------------

    def _server(self):
        import ldap3
        return ldap3.Server(self.cfg.uri, use_ssl=self.cfg.uri.lower().startswith('ldaps://'),
                            get_info=ldap3.NONE, connect_timeout=self.cfg.timeout)

    def _connect(self, user, password):
        import ldap3
        conn = ldap3.Connection(self._server(), user=user or None, password=password or None,
                                receive_timeout=self.cfg.timeout, auto_bind=ldap3.AUTO_BIND_NONE)
        if self.cfg.start_tls:
            conn.start_tls()
        if not conn.bind():
            conn.unbind()
            return None
        return conn

    def _attributes(self) -> list:
        attrs = [self.cfg.attr_fullname, self.cfg.attr_mail]
        if self.cfg.instructor_groups and not self.cfg.group_filter:
            attrs.append('memberOf')
        return attrs

    def _authenticate(self, login: str, password: str, language: str) -> Identity | None:
        try:
            with warnings.catch_warnings():
                # ldap3 2.9 imports names pyasn1 0.6 deprecated (tagMap / typeMap): not ours to fix
                warnings.simplefilter('ignore', DeprecationWarning)
                import ldap3  # noqa: F401
                from ldap3.core.exceptions import LDAPException
        except ImportError:
            raise LdapError("the ldap3 library is not installed")
        try:
            if self.cfg.bind_dn_template:
                dn = self.cfg.bind_dn_template.format(login=_escape_rdn(login))
                conn = self._connect(dn, password)
                if conn is None:
                    return None
                try:
                    conn.search(dn, '(objectClass=*)', search_scope='BASE', attributes=self._attributes())
                    entry = conn.entries[0] if conn.entries else None
                    return self._identity(conn, login, dn, entry, language)
                finally:
                    conn.unbind()
            service = self._connect(self.cfg.bind_dn, self.cfg.bind_password)
            if service is None:
                raise LdapError("the service account cannot bind")
            try:
                service.search(self.cfg.search_base, self.cfg.search_filter.format(login=_escape_filter(login)),
                               attributes=self._attributes())
                if not service.entries:
                    return None
                entry = service.entries[0]
                dn = entry.entry_dn
                user_conn = self._connect(dn, password)
                if user_conn is None:
                    return None
                user_conn.unbind()
                return self._identity(service, login, dn, entry, language)
            finally:
                service.unbind()
        except LDAPException as e:
            log.warning("LDAP failure for %s: %s", login, e)
            raise LdapError(str(e)) from e

    def _identity(self, conn, login: str, dn: str, entry, language: str) -> Identity:
        fullname = _first(entry, self.cfg.attr_fullname) if entry is not None else ''
        email = _first(entry, self.cfg.attr_mail) if entry is not None else ''
        return Identity(login=login, fullname=fullname, email=email, language=language,
                        role=ROLE_INSTRUCTOR if self._is_instructor(conn, dn, entry) else ROLE_STUDENT)

    def _is_instructor(self, conn, dn: str, entry) -> bool:
        groups = {g.lower() for g in self.cfg.instructor_groups}
        if not groups:
            return False
        if self.cfg.group_filter:
            conn.search(self.cfg.search_base, self.cfg.group_filter.format(dn=_escape_filter(dn)), attributes=[])
            return any(e.entry_dn.lower() in groups for e in conn.entries)
        return any(g.lower() in groups for g in (_all(entry, 'memberOf') if entry is not None else []))
