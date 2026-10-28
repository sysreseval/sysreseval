"""The role and the student group of a login looked up in the directory, cached per login.

In proxy mode the reverse proxy authenticates the browser and gives the login on every request;
the portal has no session there, so the LDAP tests of ``[auth.ldap]`` (``LdapRoleResolver``) are
run once per login (``ldap_roles``), with the read of ``attr_group`` (``ldap_roles`` or
``ldap_groups``), and the result kept for ``ldap_roles_ttl`` seconds.  In every mode with a
readable directory (``WebConfig.directory_lookups``), the Watch page completes the groups of the
project owners the agents know none for (:func:`complete_groups`: the projects of the Qt GUI).
A directory failure makes the login a student without group for ``negative_ttl`` seconds (logged
once per message), so the site stays up without its instructors rather than down.
"""
import asyncio
import logging
import time
from typing import Callable

from .auth_ldap import DirectoryLookup
from ..identity import is_valid_login

log = logging.getLogger('sreweb.portal')


class RoleCache:
    def __init__(self, resolver, *, ttl: float, negative_ttl: float = 60.0,
                 clock: Callable[[], float] = time.monotonic):
        """*resolver* has a synchronous ``resolve(login) -> DirectoryLookup`` raising on a
        directory failure (``auth_ldap.LdapRoleResolver``); *clock* is replaceable by the tests."""
        self.resolver = resolver
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.clock = clock
        self._roles: dict[str, tuple[DirectoryLookup, float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._warned: set = set()
        self.lookups = 0

    async def get(self, login: str) -> DirectoryLookup:
        """The role and the group of *login*: the cached lookup while it lasts, else one lookup in
        a thread (the concurrent requests of one browser wait for the same lookup)."""
        cached = self._roles.get(login)
        if cached is not None and cached[1] > self.clock():
            return cached[0]
        lock = self._locks.setdefault(login, asyncio.Lock())
        async with lock:
            cached = self._roles.get(login)
            if cached is not None and cached[1] > self.clock():
                return cached[0]
            self.lookups += 1
            try:
                found = await asyncio.to_thread(self.resolver.resolve, login)
                expires = self.clock() + self.ttl
            except Exception as e:
                key = str(e)
                if key not in self._warned:
                    self._warned.add(key)
                    log.warning("role lookup failed (%s counted as a student for %gs): %s", login, self.negative_ttl, e)
                found, expires = DirectoryLookup(), self.clock() + self.negative_ttl
            self._roles[login] = (found, expires)
            return found

    def forget(self, login: str | None = None):
        """Drop the cached lookup of *login* (every one without it)."""
        if login is None:
            self._roles.clear()
        else:
            self._roles.pop(login, None)


async def complete_groups(rows: list, roles: RoleCache, *, key: str = 'group', login_key: str = 'owner') -> list:
    """The *rows* (dicts naming a login under *login_key*) whose *key* is empty get the group the
    directory gives that login (cached per login, the distinct logins looked up concurrently): the
    Watch rows of the Qt GUI projects, whose answers file never carries a group, and of the
    owners whose header was empty.  A row stays as it is when the directory has no group for its
    owner, or when the login is not a valid one (a malformed running lab name)."""
    logins = {str(row.get(login_key) or '') for row in rows if not row.get(key)}
    logins = sorted(login for login in logins if is_valid_login(login))
    if not logins:
        return rows
    found = dict(zip(logins, await asyncio.gather(*(roles.get(login) for login in logins))))
    for row in rows:
        if not row.get(key):
            lookup = found.get(str(row.get(login_key) or ''))
            if lookup is not None and lookup.group:
                row[key] = lookup.group
    return rows
