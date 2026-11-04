"""The user groups of the instructors' pages (``/groups``, the group filter of the Watch page, the
audience of a presentation): who belongs to what, from three sources.

- ``department``: the values of ``attr_group`` of ``[auth.ldap]`` (``departmentNumber``...) over
  every person of ``search_base``, the "student group" the portal has always known per login
  (``Identity.group``, the Group column of the Watch page), listed here as groups.
- ``directory``: the groups of ``group_search_base`` matching ``groups_filter`` (``posixGroup``
  entries: ``cn`` + ``memberUid``), their members mapped onto the people (a member value may be
  the login attribute, the ``uid`` or the DN of a person; a value matching nobody but shaped like
  a login counts as that login).
- ``custom``: the groups the instructors create on the Groups page, in two tables of the
  database of ``[access_log.database]`` (``[groups] table`` and ``<table>_members``): any
  instructor creates, renames, fills, empties and deletes them.

A group is named by a key ``kind:name`` (:func:`group_key`); a bare name is a department (the
``?group=`` of the Watch page and the audiences of the presentations predate the kinds).  The
directory is read whole (two paged searches) and kept ``directory_ttl`` seconds
(:class:`DirectoryCache`); the custom memberships are kept ``MEMBERSHIPS_TTL`` seconds and
reloaded after every write of this process (:class:`GroupStore`); :class:`Memberships` answers
the synchronous questions of the routes, the presence and the presentations from those caches
(``await refresh()`` first: a few comparisons when they are fresh).
"""
import asyncio
import logging
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable, Iterable

from .accessdb import HistoryError, _errno, ensure_table, epoch, transaction, utc_datetime
from .auth_ldap import LdapError, _Directory
from ..config import AccessDatabaseConfig, GroupsConfig
from ..identity import clean_group, is_valid_login

log = logging.getLogger('sreweb.portal')

KIND_DEPARTMENT = 'department'
KIND_DIRECTORY = 'directory'
KIND_CUSTOM = 'custom'
KINDS = (KIND_DEPARTMENT, KIND_DIRECTORY, KIND_CUSTOM)     # the display order
KEY_SEPARATOR = ':'
#: Characters a custom group name may not hold: the key separator, and the path separator of
#: ``/api/groups/custom/{name}``.
FORBIDDEN_IN_NAME = ':/'
NEGATIVE_TTL = 60.0            # seconds before the directory is read again after a failure
MEMBERSHIPS_TTL = 30.0         # seconds the custom memberships are kept (a write of this process reloads them)
PAGE = 500                     # entries per page of the LDAP searches (OpenLDAP's default sizelimit)
MAX_PEOPLE = 50                # people returned by a search of the Add row
MAX_DESCRIPTION = 255          # the column width
MAX_BATCH = 1000               # logins per add call
ER_DUP_ENTRY = 1062            # a UNIQUE key refused the row

# -- the tables of the custom groups ------------------------------------------------------------
# The names: "groups" and "group" are reserved words of MySQL 8.  The name and login columns are
# binary-collated: exact and case-sensitive like the logins and the keys in memory (the default
# utf8mb4_unicode_ci would find INFO1 for info1).  No FOREIGN KEY: creating one needs the
# REFERENCES privilege, and the members of a group are deleted with it in one transaction.
DDL_GROUPS = """\
CREATE TABLE IF NOT EXISTS `{table}` (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name        VARCHAR(64)     CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  description VARCHAR(255)    NOT NULL DEFAULT '',
  created_by  VARCHAR(64)     NOT NULL DEFAULT '',
  created_at  DATETIME(3)     NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
DDL_MEMBERS = """\
CREATE TABLE IF NOT EXISTS `{table}` (
  group_id    BIGINT UNSIGNED NOT NULL,
  login       VARCHAR(64)     CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  added_by    VARCHAR(64)     NOT NULL DEFAULT '',
  added_at    DATETIME(3)     NOT NULL,
  PRIMARY KEY (group_id, login),
  KEY login (login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
SELECT_GROUPS = ("SELECT g.id, g.name, g.description, g.created_by, g.created_at, COUNT(m.login) FROM `{table}` g "
                 "LEFT JOIN `{members}` m ON m.group_id = g.id "
                 "GROUP BY g.id, g.name, g.description, g.created_by, g.created_at ORDER BY g.name")
SELECT_GROUP = "SELECT id, name, description, created_by, created_at FROM `{table}` WHERE name = %s"
SELECT_MEMBERS = "SELECT login, added_by, added_at FROM `{members}` WHERE group_id = %s ORDER BY login"
COUNT_MEMBERS = "SELECT COUNT(*) FROM `{members}` WHERE group_id = %s"
SELECT_MEMBERSHIPS = "SELECT g.name, m.login FROM `{table}` g LEFT JOIN `{members}` m ON m.group_id = g.id"
INSERT_GROUP = "INSERT INTO `{table}` (name, description, created_by, created_at) VALUES (%s, %s, %s, %s)"
UPDATE_GROUP = "UPDATE `{table}` SET name = %s, description = %s WHERE id = %s"
DELETE_MEMBERS_OF = "DELETE FROM `{members}` WHERE group_id = %s"
DELETE_GROUP = "DELETE FROM `{table}` WHERE id = %s"
#: One ``VALUES`` group: ``executemany`` makes one multi-row statement of it; IGNORE skips the
#: logins already members (the primary key).
INSERT_MEMBER = "INSERT IGNORE INTO `{members}` (group_id, login, added_by, added_at) VALUES (%s, %s, %s, %s)"
DELETE_MEMBER = "DELETE FROM `{members}` WHERE group_id = %s AND login = %s"


# -- keys and names -----------------------------------------------------------------------------

def group_key(kind: str, name: str) -> str:
    return f"{kind}{KEY_SEPARATOR}{name}"


def parse_group_key(text) -> tuple[str, str]:
    """``(kind, name)`` of a key; a bare name, or a prefix that is not a kind, is a department
    (``'a:b'`` is the department ``a:b``; a custom name never holds the separator)."""
    text = str(text)
    kind, sep, name = text.partition(KEY_SEPARATOR)
    if sep and kind in KINDS:
        return kind, name
    return KIND_DEPARTMENT, text


def normalize_group_keys(groups: Iterable[str]) -> set:
    """The canonical keys of *groups* (bare names become ``department:<name>``)."""
    return {group_key(*parse_group_key(g)) for g in groups}


def department_member(department: str, keys: Iterable[str]) -> bool:
    """Whether the department *department* (``''`` = none) is one of *keys*."""
    return bool(department) and group_key(KIND_DEPARTMENT, department) in set(keys)


def check_group_name(value) -> str:
    """The name of a custom group as it is kept: the ``clean_group`` rules (no control character,
    trimmed, at most 64 characters) and none of ``FORBIDDEN_IN_NAME``; ``ValueError`` otherwise."""
    if not isinstance(value, str):
        raise ValueError("the group name must be a string")
    name = clean_group(value)
    if not name:
        raise ValueError("the group name cannot be empty")
    if name != value.strip():
        raise ValueError("the group name is too long or holds control characters")
    if any(c in name for c in FORBIDDEN_IN_NAME):
        raise ValueError(f"the group name cannot contain {' or '.join(repr(c) for c in FORBIDDEN_IN_NAME)}")
    return name


def iso_utc(ts: float) -> str:
    """A timestamp as the browsers' ``Date`` parses it everywhere: ``2026-11-04T09:00:00+00:00``."""
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec='seconds')


def group_dict(kind: str, name: str, members: int, *, description: str = '', created_by=None, created_at=None) -> dict:
    """A group as the API gives it."""
    return {'key': group_key(kind, name), 'kind': kind, 'name': name, 'members': members, 'description': description,
            'created_by': created_by, 'created_at': created_at}


def sort_key(group: dict) -> tuple:
    return (KINDS.index(group['kind']) if group['kind'] in KINDS else len(KINDS), group['name'].casefold(), group['name'])


# -- the directory --------------------------------------------------------------------------------

@dataclass(frozen=True)
class Person:
    login: str
    fullname: str = ''
    group: str = ''        # the department (attr_group, first value, cleaned); '' = none


class DirectorySnapshot:
    """What one read of the directory gave: the people by login, the departments (``attr_group``
    value -> logins) and the directory groups (name -> logins)."""

    def __init__(self, people: dict, groups: dict, loaded_at: float):
        self.people: dict[str, Person] = dict(people)
        self.groups: dict[str, frozenset] = {name: frozenset(members) for name, members in groups.items()}
        self.loaded_at = loaded_at
        departments: dict[str, set] = {}
        for person in self.people.values():
            if person.group:
                departments.setdefault(person.group, set()).add(person.login)
        self.departments: dict[str, frozenset] = {name: frozenset(m) for name, m in departments.items()}
        self._groups_of: dict[str, list] = {}
        for name in sorted(self.groups, key=lambda n: (n.casefold(), n)):
            for login in self.groups[name]:
                self._groups_of.setdefault(login, []).append(name)

    def department_of(self, login: str) -> str:
        person = self.people.get(login)
        return person.group if person is not None else ''

    def directory_groups_of(self, login: str) -> list:
        """The names of the directory groups *login* belongs to, sorted."""
        return list(self._groups_of.get(login, ()))

    def members_of(self, kind: str, name: str):
        """The logins of a department or directory group, ``None`` when unknown (a custom kind too)."""
        if kind == KIND_DEPARTMENT:
            return self.departments.get(name)
        if kind == KIND_DIRECTORY:
            return self.groups.get(name)
        return None

    def person_row(self, login: str) -> dict:
        person = self.people.get(login)
        return {'login': login, 'fullname': person.fullname if person is not None else '',
                'group': person.group if person is not None else ''}

    def search(self, text: str, limit: int = MAX_PEOPLE) -> tuple:
        """``(people, more)``: the people whose login or full name contains *text* (case
        folded; every one for ``''``), sorted by login, at most *limit* of them."""
        needle = text.casefold()
        found = [self.people[login] for login in sorted(self.people)
                 if not needle or needle in login.casefold() or needle in self.people[login].fullname.casefold()]
        return found[:limit], len(found) > limit

    def names(self) -> set:
        """The names of the departments and of the directory groups (a custom group may not take one)."""
        return set(self.departments) | set(self.groups)


def _values(attributes: dict, name: str) -> list:
    """The values of attribute *name* of a paged-search entry as strings (a scalar, a list, bytes,
    the name in another case)."""
    value = attributes.get(name)
    if value is None:
        lowered = name.lower()
        value = next((v for k, v in attributes.items() if str(k).lower() == lowered), None)
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple)) else [value]
    return [v.decode('utf-8', 'replace') if isinstance(v, bytes) else str(v) for v in values if v is not None]


def _first_value(attributes: dict, name: str) -> str:
    return next((v for v in _values(attributes, name) if v), '')


def member_logins(values: Iterable[str], index: dict) -> set:
    """The logins named by the member values of a group: each value looked up in *index*
    (case-folded login, ``uid`` and DN of every person -> login); a value matching nobody is
    kept as a login when it is shaped like one (an account outside the people base), dropped
    otherwise (the DN of a nested group...)."""
    logins = set()
    for value in values:
        value = str(value).strip()
        if not value:
            continue
        login = index.get(value.casefold())
        if login is None and is_valid_login(value):
            login = value
        if login is not None:
            logins.add(login)
    return logins


class DirectoryListing(_Directory):
    """One read of the people of ``search_base`` and of the groups of ``group_search_base`` with
    the service account (or an anonymous bind) of ``[auth.ldap]``.  Synchronous: run it in a
    thread (:class:`DirectoryCache` does)."""

    def load(self, now: float) -> DirectorySnapshot:
        """The snapshot dated *now*; ``LdapError`` when the directory cannot be read (the
        message is shown on the Groups page)."""
        login_attr = self.cfg.login_attribute
        if not self.cfg.uri or not self.cfg.search_base:
            raise LdapError("auth.ldap.uri and search_base are required to list the directory")
        if not login_attr:
            raise LdapError("auth.ldap.attr_login is required: search_filter is not of the form (attribute={login})")
        LDAPException = self._import_ldap3()
        try:
            conn = self._connect(self.cfg.bind_dn, self.cfg.bind_password)
            if conn is None:
                raise LdapError("the service account cannot bind")
            try:
                people, index = self._people(conn, login_attr)
                groups = self._groups(conn, index)
            finally:
                conn.unbind()
        except LDAPException as e:
            log.warning("LDAP failure listing the directory: %s", e)
            raise LdapError(str(e)) from e
        return DirectorySnapshot(people, groups, now)

    def _search_all(self, conn, base: str, ldap_filter: str, attributes: list) -> list:
        """``[(dn, attributes)]`` of every entry *ldap_filter* finds under *base*: a paged search
        (the people base exceeds the default size limit of a server), the referrals skipped."""
        found = []
        for item in conn.extend.standard.paged_search(base, ldap_filter, attributes=attributes, paged_size=PAGE,
                                                      generator=True):
            if not isinstance(item, dict) or item.get('type', 'searchResEntry') != 'searchResEntry':
                continue
            found.append((str(item.get('dn') or ''), dict(item.get('attributes') or {})))
        return found

    def _people(self, conn, login_attr: str) -> tuple:
        """``(people, index)``: the people by login, and the case-folded login, ``uid`` values
        and DN of each one -> login (the member values of the groups are looked up there)."""
        attributes = []
        for attr in (login_attr, 'uid', self.cfg.attr_fullname, self.cfg.attr_group):
            if attr and attr not in attributes:
                attributes.append(attr)
        people, index = {}, {}
        for dn, attrs in self._search_all(conn, self.cfg.search_base, f'({login_attr}=*)', attributes):
            login = _first_value(attrs, login_attr)
            if not is_valid_login(login):
                continue
            group = clean_group(_first_value(attrs, self.cfg.attr_group)) if self.cfg.attr_group else ''
            people[login] = Person(login, _first_value(attrs, self.cfg.attr_fullname), group)
            index[login.casefold()] = login
            for uid in _values(attrs, 'uid'):
                if uid:
                    index[uid.casefold()] = login
            if dn:
                index[dn.casefold()] = login
        return people, index

    def _groups(self, conn, index: dict) -> dict:
        """The directory groups (cleaned name -> logins), none without ``group_search_base`` or
        ``groups_filter``; two entries with one name are merged."""
        ldap_filter = str(self.cfg.groups_filter).strip()
        if not self.cfg.group_search_base or not ldap_filter:
            return {}
        groups: dict[str, set] = {}
        attributes = [self.cfg.attr_group_name, self.cfg.attr_group_members]
        for dn, attrs in self._search_all(conn, self.cfg.group_search_base, ldap_filter, attributes):
            name = clean_group(_first_value(attrs, self.cfg.attr_group_name))
            if not name:
                continue
            groups.setdefault(name, set()).update(member_logins(_values(attrs, self.cfg.attr_group_members), index))
        return groups


class DirectoryCache:
    """The snapshot of the directory, read in a thread and kept *ttl* seconds (the concurrent
    requests share one read); after a failure the previous snapshot stays, the error is kept for
    the page and the read is tried again after *negative_ttl* seconds.  *clock* (monotonic) times
    the cache, *wall* (``time.time``) dates the snapshot."""

    def __init__(self, listing: DirectoryListing, *, ttl: float, negative_ttl: float = NEGATIVE_TTL,
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time):
        self.listing = listing
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.clock = clock
        self.wall = wall
        self.snapshot: DirectorySnapshot | None = None
        self.error: str | None = None
        self.loads = 0
        self._expires: float | None = None
        self._lock = asyncio.Lock()
        self._warned: set = set()

    def fresh(self) -> bool:
        return self._expires is not None and self._expires > self.clock()

    async def get(self, *, refresh: bool = False) -> DirectorySnapshot | None:
        """The snapshot (``None`` before the first successful read); *refresh* reads again
        whatever the age."""
        if not refresh and self.fresh():
            return self.snapshot
        async with self._lock:
            if not refresh and self.fresh():
                return self.snapshot
            self.loads += 1
            try:
                self.snapshot = await asyncio.to_thread(self.listing.load, self.wall())
            except Exception as e:
                message = str(e) or type(e).__name__
                self.error = message
                self._expires = self.clock() + self.negative_ttl
                if message not in self._warned:
                    self._warned.add(message)
                    log.warning("directory listing failed (tried again in %gs): %s", self.negative_ttl, message)
            else:
                self.error = None
                self._warned.clear()
                self._expires = self.clock() + self.ttl
            return self.snapshot

    def status(self) -> dict:
        """For the Groups page: when the directory was read, the error of the last read, the
        number of people known."""
        snapshot = self.snapshot
        return {'configured': True, 'loaded_at': iso_utc(snapshot.loaded_at) if snapshot is not None else None,
                'error': self.error, 'people': len(snapshot.people) if snapshot is not None else 0}


# -- the custom groups ----------------------------------------------------------------------------

class GroupError(Exception):
    """An outcome of a group operation the API reports with ``status``."""
    status = 400


class GroupNotFound(GroupError):
    status = 404


class GroupExists(GroupError):
    status = 409


@dataclass(frozen=True)
class CustomGroup:
    id: int
    name: str
    description: str = ''
    created_by: str = ''
    created_at: float = 0.0
    members: int = 0

    def to_dict(self) -> dict:
        return group_dict(KIND_CUSTOM, self.name, self.members, description=self.description,
                          created_by=self.created_by or None, created_at=iso_utc(self.created_at))


class GroupStore:
    """The custom groups in the database: every operation is one transaction on a fresh
    connection of *connect* (``accessdb.connector``, or a fake), run in a thread by the async
    wrappers; the two tables are created at the first operation when they are missing (the
    account needs CREATE then; the documentation gives the DDL to run by hand).  The memberships
    (name -> logins) are kept ``MEMBERSHIPS_TTL`` seconds for the synchronous lookups, reloaded
    after every write of this process."""

    def __init__(self, db: AccessDatabaseConfig, cfg: GroupsConfig, *, connect, clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        self.db = db
        self.cfg = cfg
        self.connect = connect
        self.clock = clock
        self.monotonic = monotonic
        self.table = cfg.table
        self.members_table = cfg.members_table
        self._ready = False
        self.connected = False
        self.last_error: str | None = None
        self._memberships: dict[str, frozenset] = {}
        self._loaded: float | None = None
        self._lock = asyncio.Lock()

    # -- helpers --------------------------------------------------------------------------------

    def _q(self, template: str) -> str:
        return template.format(table=self.table, members=self.members_table)

    def _run(self, work: Callable):
        """*work(cursor)* in one transaction, the tables made sure of first (once per process);
        the outcome recorded in ``connected`` / ``last_error``."""
        ready = self._ready

        def prepared(cur):
            if not ready:
                ensure_table(cur, self.table, DDL_GROUPS, 'groups database')
                ensure_table(cur, self.members_table, DDL_MEMBERS, 'groups database')
            return work(cur)

        try:
            result = transaction(self.connect, prepared, passthrough=(GroupError,))
        except HistoryError as e:
            self.connected = False
            self.last_error = str(e)
            raise
        self._ready = True
        self.connected = True
        self.last_error = None
        return result

    @staticmethod
    def _group_of(row) -> CustomGroup:
        created = row[4]
        return CustomGroup(int(row[0]), str(row[1]), str(row[2] or ''), str(row[3] or ''),
                           epoch(created) if isinstance(created, datetime) else float(created or 0))

    def _lookup(self, cur, name: str) -> CustomGroup | None:
        cur.execute(self._q(SELECT_GROUP), (name,))
        row = cur.fetchone()
        return self._group_of(row) if row else None

    def _find(self, cur, name: str) -> CustomGroup:
        group = self._lookup(cur, name)
        if group is None:
            raise GroupNotFound(f"unknown group {name!r}")
        return group

    def _count(self, cur, group_id: int) -> int:
        cur.execute(self._q(COUNT_MEMBERS), (group_id,))
        row = cur.fetchone()
        return int(row[0]) if row else 0

    # -- synchronous operations (a worker thread) -----------------------------------------------

    def list_sync(self) -> list:
        def work(cur):
            cur.execute(self._q(SELECT_GROUPS))
            return [replace(self._group_of(row), members=int(row[5] or 0)) for row in cur.fetchall()]
        return self._run(work)

    def get_sync(self, name: str) -> tuple:
        """``(group, members)``: the members as ``{'login', 'added_by', 'added_at'}`` by login."""
        def work(cur):
            group = self._find(cur, name)
            cur.execute(self._q(SELECT_MEMBERS), (group.id,))
            members = [{'login': str(r[0]), 'added_by': str(r[1] or '') or None,
                        'added_at': iso_utc(epoch(r[2])) if isinstance(r[2], datetime) else None}
                       for r in cur.fetchall()]
            return replace(group, members=len(members)), members
        return self._run(work)

    def create_sync(self, name: str, description: str, by: str) -> CustomGroup:
        def work(cur):
            if self._lookup(cur, name) is not None:
                raise GroupExists(f"a group named {name!r} exists")
            created = utc_datetime(self.clock())
            try:
                cur.execute(self._q(INSERT_GROUP), (name, description, by, created))
            except Exception as e:
                if _errno(e) == ER_DUP_ENTRY:
                    raise GroupExists(f"a group named {name!r} exists") from e
                raise
            return CustomGroup(int(cur.lastrowid or 0), name, description, by, epoch(created), 0)
        return self._run(work)

    def update_sync(self, name: str, *, new_name: str | None = None, description: str | None = None) -> CustomGroup:
        def work(cur):
            group = self._find(cur, name)
            target = new_name if new_name is not None else group.name
            text = description if description is not None else group.description
            if target != group.name and self._lookup(cur, target) is not None:
                raise GroupExists(f"a group named {target!r} exists")
            try:
                cur.execute(self._q(UPDATE_GROUP), (target, text, group.id))
            except Exception as e:
                if _errno(e) == ER_DUP_ENTRY:
                    raise GroupExists(f"a group named {target!r} exists") from e
                raise
            return replace(group, name=target, description=text, members=self._count(cur, group.id))
        return self._run(work)

    def delete_sync(self, name: str):
        def work(cur):
            group = self._find(cur, name)
            cur.execute(self._q(DELETE_MEMBERS_OF), (group.id,))
            cur.execute(self._q(DELETE_GROUP), (group.id,))
        self._run(work)

    def add_members_sync(self, name: str, logins: Iterable[str], by: str) -> tuple:
        """``(added, members)``: how many logins joined (the members already there do not count)
        and the size of the group afterwards."""
        def work(cur):
            group = self._find(cur, name)
            before = self._count(cur, group.id)
            added_at = utc_datetime(self.clock())
            rows = [(group.id, login, by, added_at) for login in dict.fromkeys(logins)]
            if rows:
                cur.executemany(self._q(INSERT_MEMBER), rows)
            after = self._count(cur, group.id)
            return max(0, after - before), after
        return self._run(work)

    def remove_member_sync(self, name: str, login: str):
        def work(cur):
            group = self._find(cur, name)
            cur.execute(self._q(DELETE_MEMBER), (group.id, login))
            if not cur.rowcount or cur.rowcount < 0:
                raise GroupNotFound(f"{login} is not a member of {name!r}")
        self._run(work)

    def memberships_sync(self) -> dict:
        """Every custom group with its logins (an empty group included)."""
        def work(cur):
            cur.execute(self._q(SELECT_MEMBERSHIPS))
            found: dict[str, set] = {}
            for name, login in cur.fetchall():
                members = found.setdefault(str(name), set())
                if login:
                    members.add(str(login))
            return {name: frozenset(m) for name, m in found.items()}
        return self._run(work)

    # -- the async side ---------------------------------------------------------------------------

    async def list(self) -> list:
        return await asyncio.to_thread(self.list_sync)

    async def get(self, name: str) -> tuple:
        return await asyncio.to_thread(self.get_sync, name)

    async def create(self, name: str, description: str, by: str) -> CustomGroup:
        group = await asyncio.to_thread(self.create_sync, name, description, by)
        self.invalidate()
        return group

    async def update(self, name: str, *, new_name: str | None = None, description: str | None = None) -> CustomGroup:
        group = await asyncio.to_thread(self.update_sync, name, new_name=new_name, description=description)
        self.invalidate()
        return group

    async def delete(self, name: str):
        await asyncio.to_thread(self.delete_sync, name)
        self.invalidate()

    async def add_members(self, name: str, logins: Iterable[str], by: str) -> tuple:
        result = await asyncio.to_thread(self.add_members_sync, name, list(logins), by)
        self.invalidate()
        return result

    async def remove_member(self, name: str, login: str):
        await asyncio.to_thread(self.remove_member_sync, name, login)
        self.invalidate()

    def _fresh(self) -> bool:
        return self._loaded is not None and self.monotonic() - self._loaded < MEMBERSHIPS_TTL

    async def memberships(self, *, refresh: bool = False) -> dict:
        """The memberships (name -> logins), read again after ``MEMBERSHIPS_TTL`` seconds, after a
        write or with *refresh*; ``HistoryError`` when the database does not answer (the previous
        ones stay in ``cached()``)."""
        if not refresh and self._fresh():
            return self._memberships
        async with self._lock:
            if not refresh and self._fresh():
                return self._memberships
            self._memberships = await asyncio.to_thread(self.memberships_sync)
            self._loaded = self.monotonic()
            return self._memberships

    def cached(self) -> dict:
        """The memberships of the last read (``{}`` before any)."""
        return self._memberships

    def invalidate(self):
        self._loaded = None

    def status(self) -> dict:
        return {'connected': self.connected, 'last_error': self.last_error}

    def describe(self) -> str:
        where = self.db.unix_socket or f"{self.db.host}:{self.db.port}"
        return f"database {self.db.name} on {where} (tables {self.table}, {self.members_table})"


# -- the service ------------------------------------------------------------------------------------

class Memberships:
    """Who belongs to what, from the caches of the directory and of the custom groups (either may
    be missing).  The lookups are synchronous and read the caches as they are: the handlers
    ``await refresh()`` first."""

    def __init__(self, *, directory: DirectoryCache | None = None, store: GroupStore | None = None):
        self.directory = directory
        self.store = store
        self._warned: set = set()

    @property
    def available(self) -> bool:
        return self.directory is not None or self.store is not None

    def snapshot(self) -> DirectorySnapshot | None:
        return self.directory.snapshot if self.directory is not None else None

    async def refresh(self, *, force: bool = False):
        """Read the sources again when stale (or whatever their age with *force*); never raises:
        a failure is logged once per message and the previous data stay."""
        if self.directory is not None:
            await self.directory.get(refresh=force)
        if self.store is not None:
            try:
                await self.store.memberships(refresh=force)
            except HistoryError as e:
                message = str(e)
                if message not in self._warned:
                    self._warned.add(message)
                    log.warning("groups database: the memberships could not be read: %s", message)
            else:
                self._warned.clear()

    def knows_people(self) -> bool:
        """Whether a directory snapshot with people is loaded (the logins added to a custom group
        are then checked against it)."""
        snapshot = self.snapshot()
        return snapshot is not None and bool(snapshot.people)

    def names_in_use(self) -> set:
        snapshot = self.snapshot()
        return snapshot.names() if snapshot is not None else set()

    def person_row(self, login: str) -> dict:
        snapshot = self.snapshot()
        return snapshot.person_row(login) if snapshot is not None else {'login': login, 'fullname': '', 'group': ''}

    def directory_groups(self) -> list:
        """The departments and the directory groups as the API lists them (unsorted)."""
        snapshot = self.snapshot()
        if snapshot is None:
            return []
        return ([group_dict(KIND_DEPARTMENT, name, len(members)) for name, members in snapshot.departments.items()]
                + [group_dict(KIND_DIRECTORY, name, len(members)) for name, members in snapshot.groups.items()])

    def groups_of(self, login: str, department: str = '') -> list:
        """The keys of every group of *login*, by kind then name: the department (*department*
        when given, else the snapshot's), the directory groups, the custom groups."""
        snapshot = self.snapshot()
        keys = []
        dept = department or (snapshot.department_of(login) if snapshot is not None else '')
        if dept:
            keys.append(group_key(KIND_DEPARTMENT, dept))
        if snapshot is not None:
            keys.extend(group_key(KIND_DIRECTORY, name) for name in snapshot.directory_groups_of(login))
        if self.store is not None:
            names = sorted((name for name, members in self.store.cached().items() if login in members),
                           key=lambda n: (n.casefold(), n))
            keys.extend(group_key(KIND_CUSTOM, name) for name in names)
        return keys

    def groups_of_identity(self, identity) -> list:
        return self.groups_of(identity.login, identity.group)

    def members_of(self, keys: Iterable[str]) -> set:
        """The logins of the groups *keys* name (unknown keys ignored)."""
        found = set()
        snapshot = self.snapshot()
        for key in keys:
            kind, name = parse_group_key(key)
            if kind == KIND_CUSTOM:
                if self.store is not None:
                    found |= self.store.cached().get(name, frozenset())
            elif snapshot is not None:
                found |= snapshot.members_of(kind, name) or frozenset()
        return found

    def is_member(self, login: str, keys: Iterable[str], department: str = '') -> bool:
        """Whether *login* is in one of the groups *keys* name: its department by the string
        *department* (as the identity carries it), the others by membership."""
        keys = set(keys)
        if department_member(department, keys):
            return True
        return login in self.members_of(keys)

    def annotate(self, rows: list, *, login_key: str = 'owner', group_field: str = 'group') -> list:
        """``row['groups']`` = the keys of the groups of ``row[login_key]`` (the department from
        ``row[group_field]`` when the row carries one) on every row of a Watch listing."""
        for row in rows:
            login = row.get(login_key) if isinstance(row, dict) else None
            row['groups'] = self.groups_of(login, str(row.get(group_field) or '')) \
                if isinstance(login, str) and is_valid_login(login) else []
        return rows
