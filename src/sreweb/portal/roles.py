"""Proxy mode: the role and the student group of a login looked up in the directory
(``[auth.proxy] ldap_roles``), cached per login.

The reverse proxy authenticates the browser and gives the login on every request; the portal
has no session there, so the LDAP tests of ``[auth.ldap]`` (``LdapRoleResolver``) are run once
per login, with the read of ``attr_group``, and the result kept for ``ldap_roles_ttl`` seconds.
A directory failure makes the login a student without group for ``negative_ttl`` seconds (logged
once per message), so the site stays up without its instructors rather than down.
"""
import asyncio
import logging
import time
from typing import Callable

from .auth_ldap import DirectoryLookup

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
