"""LDAP mode: the user binds with their own password (``ldap3``), the portal reads their full
name, e-mail and student group (``attr_group``), and the instructor role comes from the
directory.

Two ways to find the user's DN: a template (``uid={login},ou=people,...``) or a search with a
service account (``search_base`` + ``search_filter``).  The role is the OR of the configured
tests: the DNs of ``instructor_groups`` matched against the ``memberOf`` attribute of the user
(or, with ``group_filter``, found by a search of the groups holding the user's DN),
``instructor_filter`` matched by the user's own entry (``(gidNumber=2000)``, a ``memberOf`` test
when the overlay exists), and ``instructor_group_filter`` finding a group of ``group_search_base``
naming the user (``posixGroup`` + ``memberUid``, the group search that needs no overlay).  The
administrators (the instructors who browse the connection log) come from the same two kinds of
tests, ``administrator_groups`` and ``administrator_group_filter``, run for the instructors only
(``[auth] administrators`` names logins directly, applied by the portal).  Every ldap3 call runs
in a thread (the library is synchronous).

In LDAP mode the role is baked into the session cookie: a rule change applies at the next login.
In proxy mode, :class:`LdapRoleResolver` runs the same tests for the login the proxy gives
(``ldap_roles``) and reads the group, the :class:`DirectoryLookup` being cached per login by
``roles.RoleCache``.
"""
import asyncio
import logging
import math
import warnings
from dataclasses import dataclass

from ..config import LdapConfig
from ..identity import Identity, ROLE_INSTRUCTOR, ROLE_STUDENT, clean_group, is_valid_login

log = logging.getLogger('sreweb.portal')


class LdapError(Exception):
    """The directory could not be used (not a wrong password)."""


@dataclass(frozen=True)
class DirectoryLookup:
    """What the directory says of a login in proxy mode: the role, the student group and
    whether the administrator tests match (the portal grants the flag to the instructors only)."""
    role: str = ROLE_STUDENT
    group: str = ''
    administrator: bool = False


def _escape_filter(value: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)   # pyasn1 names ldap3 2.9 imports
        from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(value)


def _escape_rdn(value: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
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


def entry_matches(conn, dn: str, ldap_filter: str) -> bool:
    """Whether the entry *dn* matches *ldap_filter* (a BASE search on the DN; an empty filter
    never matches)."""
    if not ldap_filter or not dn:
        return False
    conn.search(dn, ldap_filter, search_scope='BASE', attributes=[])
    return bool(conn.entries)


def group_found(conn, base: str, ldap_filter: str, *, login: str, dn: str) -> bool:
    """Whether a group of *base* matches *ldap_filter* with ``{login}`` and ``{dn}`` substituted
    (filter-escaped): the membership test of ``instructor_group_filter``."""
    if not ldap_filter or not base:
        return False
    conn.search(base, ldap_filter.format(login=_escape_filter(login), dn=_escape_filter(dn)), attributes=[])
    return bool(conn.entries)


class _Directory:
    """The synchronous part shared by the authenticator and the role resolver."""

    def __init__(self, cfg: LdapConfig):
        self.cfg = cfg

    def _timeout(self) -> int:
        """``timeout`` of the config as the whole seconds ldap3 wants: on Linux it packs
        ``receive_timeout`` with ``struct.pack('LL', …)``, so a float (the ``10.0`` of
        ``parse_duration``) made every bind fail with *required argument is not an integer*."""
        return max(1, math.ceil(self.cfg.timeout))

    def _server(self):
        import ldap3
        return ldap3.Server(self.cfg.uri, use_ssl=self.cfg.uri.lower().startswith('ldaps://'),
                            get_info=ldap3.NONE, connect_timeout=self._timeout())

    def _connect(self, user, password):
        import ldap3
        conn = ldap3.Connection(self._server(), user=user or None, password=password or None,
                                receive_timeout=self._timeout(), auto_bind=ldap3.AUTO_BIND_NONE)
        if self.cfg.start_tls:
            conn.start_tls()
        if not conn.bind():
            conn.unbind()
            return None
        return conn

    def _attributes(self) -> list:
        attrs = [self.cfg.attr_fullname, self.cfg.attr_mail]
        if self.cfg.attr_group:
            attrs.append(self.cfg.attr_group)
        if (self.cfg.instructor_groups or self.cfg.administrator_groups) and not self.cfg.group_filter:
            attrs.append('memberOf')
        return attrs

    def _group(self, entry) -> str:
        """The student group of *entry* (the first value of ``attr_group``, cleaned), ``''``
        without the attribute."""
        if entry is None or not self.cfg.attr_group:
            return ''
        return clean_group(_first(entry, self.cfg.attr_group))

    def _group_base(self) -> str:
        return self.cfg.group_search_base or self.cfg.search_base

    def _is_instructor(self, conn, login: str, dn: str, entry) -> bool:
        """The OR of the three tests, each skipped when not configured."""
        return (self._in_groups(conn, dn, entry, self.cfg.instructor_groups)
                or entry_matches(conn, dn, self.cfg.instructor_filter)
                or (bool(self.cfg.group_search_base)
                    and group_found(conn, self.cfg.group_search_base, self.cfg.instructor_group_filter,
                                    login=login, dn=dn)))

    def _is_administrator(self, conn, login: str, dn: str, entry) -> bool:
        """The OR of the two administrator tests (``administrator_groups`` like
        ``instructor_groups``, ``administrator_group_filter`` under ``group_search_base``), each
        skipped when not configured; the callers run it for the instructors only."""
        return (self._in_groups(conn, dn, entry, self.cfg.administrator_groups)
                or (bool(self.cfg.group_search_base) and bool(self.cfg.administrator_group_filter.strip())
                    and group_found(conn, self.cfg.group_search_base, self.cfg.administrator_group_filter,
                                    login=login, dn=dn)))

    def _in_groups(self, conn, dn: str, entry, wanted) -> bool:
        """Whether the user is a member of one of the *wanted* groups (DNs): by the ``memberOf``
        attribute of the entry, or by the ``group_filter`` search when configured."""
        groups = {str(g).lower() for g in wanted}
        if not groups:
            return False
        if self.cfg.group_filter:
            conn.search(self._group_base(), self.cfg.group_filter.format(dn=_escape_filter(dn)), attributes=[])
            return any(e.entry_dn.lower() in groups for e in conn.entries)
        return any(g.lower() in groups for g in (_all(entry, 'memberOf') if entry is not None else []))

    @staticmethod
    def _import_ldap3():
        try:
            with warnings.catch_warnings():
                # ldap3 2.9 imports names pyasn1 0.6 deprecated (tagMap / typeMap): not ours to fix
                warnings.simplefilter('ignore', DeprecationWarning)
                import ldap3  # noqa: F401
                from ldap3.core.exceptions import LDAPException
        except ImportError:
            raise LdapError("the ldap3 library is not installed")
        return LDAPException


class LdapRoleResolver(_Directory):
    """Proxy mode: the role, the group and the administrator tests of a login the reverse proxy
    authenticated, computed with the service account (or an anonymous bind) from the same tests
    as the LDAP login."""

    def role_for(self, login: str) -> str:
        """``ROLE_INSTRUCTOR`` or ``ROLE_STUDENT``: the role of :meth:`resolve`."""
        return self.resolve(login).role

    def resolve(self, login: str) -> DirectoryLookup:
        """The role (an unknown login is a student), the student group and the administrator
        tests of *login* (run whatever the role: the portal applies them to the instructors);
        ``LdapError`` when the directory cannot be used.  Synchronous: run it in a thread."""
        if not is_valid_login(login):
            return DirectoryLookup()
        LDAPException = self._import_ldap3()
        try:
            conn = self._connect(self.cfg.bind_dn, self.cfg.bind_password)
            if conn is None:
                raise LdapError("the service account cannot bind")
            try:
                if self.cfg.bind_dn_template:
                    dn = self.cfg.bind_dn_template.format(login=_escape_rdn(login))
                    conn.search(dn, '(objectClass=*)', search_scope='BASE', attributes=self._attributes())
                    entry = conn.entries[0] if conn.entries else None
                else:
                    conn.search(self.cfg.search_base, self.cfg.search_filter.format(login=_escape_filter(login)),
                                attributes=self._attributes())
                    if not conn.entries:
                        return DirectoryLookup()
                    entry = conn.entries[0]
                    dn = entry.entry_dn
                instructor = self._is_instructor(conn, login, dn, entry)
                administrator = self.cfg.administrator_tests and self._is_administrator(conn, login, dn, entry)
                return DirectoryLookup(ROLE_INSTRUCTOR if instructor else ROLE_STUDENT, self._group(entry),
                                       bool(administrator))
            finally:
                conn.unbind()
        except LDAPException as e:
            log.warning("LDAP failure resolving the role of %s: %s", login, e)
            raise LdapError(str(e)) from e


class LdapAuthenticator(_Directory):

    async def authenticate(self, login: str, password: str, language: str = 'en') -> Identity | None:
        """The identity of *login* when *password* is right, ``None`` otherwise; ``LdapError``
        when the directory is unreachable."""
        if not is_valid_login(login) or not password:
            return None
        return await asyncio.to_thread(self._authenticate, login, password, language)

    # -- synchronous part (a thread) ----------------------------------------------------------------

    def _authenticate(self, login: str, password: str, language: str) -> Identity | None:
        LDAPException = self._import_ldap3()
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
        instructor = self._is_instructor(conn, login, dn, entry)
        return Identity(login=login, fullname=fullname, email=email, language=language,
                        role=ROLE_INSTRUCTOR if instructor else ROLE_STUDENT, group=self._group(entry),
                        administrator=instructor and self._is_administrator(conn, login, dn, entry))
