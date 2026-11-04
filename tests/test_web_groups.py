"""Tests of sreweb.portal.groups (the Groups page of the instructors): the keys, the listing of
the directory on a fake connection and its cache, the store of the custom groups on a fake
database, the memberships, and the page with its API through the portal of test_web_portal.py
(the Watch rows, the presence rows and the audiences of the presentations carry the groups)."""
import asyncio
import json
import re
import types

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import aiohttp  # noqa: E402

from sreweb.config import LdapConfig, GroupsConfig  # noqa: E402
from sreweb.identity import Identity  # noqa: E402
from sreweb.portal import groups as G  # noqa: E402
from sreweb.portal.accessdb import HistoryError  # noqa: E402
from sreweb.portal.accesslog import parse_line  # noqa: E402
from sreweb.portal.auth_ldap import LdapError  # noqa: E402
import test_web_portal as P  # noqa: E402
import test_web_presentation as PR  # noqa: E402
from test_web_accessdb import FakeServer, Down, Broken, config as db_config  # noqa: E402
from test_web_auth_ldap import FakeConn, PEOPLE, GROUPS  # noqa: E402

PEOPLE_FILTER = '(supannAliasLogin=*)'
GROUPS_FILTER = '(objectClass=posixGroup)'
NOW = 1_700_000_000.0            # 2023-11-14T22:13:20+00:00
NOW_ISO = '2023-11-14T22:13:20+00:00'
DB = {'host': 'db.example.org', 'user': 'sre_web', 'name': 'sre'}
LDAP = {'uri': 'ldaps://ldap.example.org', 'search_base': PEOPLE, 'search_filter': '(supannAliasLogin={login})',
        'group_search_base': GROUPS, 'attr_group': 'departmentNumber'}


def run(coro):
    return asyncio.run(coro)


def ldap_cfg(**over) -> LdapConfig:
    base = dict(uri='ldaps://ldap.example.org', search_base=PEOPLE, search_filter='(supannAliasLogin={login})',
                group_search_base=GROUPS, attr_group='departmentNumber', instructor_filter='')
    base.update(over)
    return LdapConfig(**base)


def person(uid, login, cn='', department=''):
    attrs = {'uid': [uid], 'supannAliasLogin': [login], 'cn': [cn] if cn else [],
             'departmentNumber': [department] if department else []}
    return (f'uid={uid},{PEOPLE}', attrs)


def directory_answers() -> dict:
    """The people (login = supannAliasLogin, uid apart) and the posixGroups of a fake directory."""
    return {
        (PEOPLE, PEOPLE_FILTER): [
            person('alice.a', 'alice', 'Alice A', '1A'),
            person('bob.b', 'bob', 'Bob B', '1A'),
            person('carol.c', 'carol', 'Carol C', '2B'),
            person('prof.p', 'prof', 'Pr. Of'),
            (f'uid=bad.login,{PEOPLE}', {'supannAliasLogin': ['bad login'], 'cn': ['Bad']}),     # not a login: skipped
        ],
        (GROUPS, GROUPS_FILTER): [
            # the member values: a uid, a login in another case, a uid, an unknown login (kept as it
            # is), the DN of a nested group (dropped)
            (f'cn=etudiants,{GROUPS}', {'cn': ['etudiants'],
                                        'memberUid': ['alice.a', 'BOB', 'carol.c', 'ghost', f'cn=nested,{GROUPS}']}),
            (f'cn=profs,{GROUPS}', {'cn': ['profs'], 'memberUid': [f'uid=prof.p,{PEOPLE}']}),      # a DN
            (f'cn=profs-bis,{GROUPS}', {'cn': [' profs '], 'memberUid': ['alice']}),                # the same name, cleaned
            (f'cn=unnamed,{GROUPS}', {'cn': [''], 'memberUid': ['alice']}),                         # no name: skipped
        ],
    }


class FakeListing(G.DirectoryListing):
    """The listing on a fake directory: the searches answered from {(base, filter): [(dn, attributes)]}."""

    def __init__(self, cfg=None, answers=None, *, bind_ok=True, fail=None):
        super().__init__(cfg if cfg is not None else ldap_cfg())
        self.answers = directory_answers() if answers is None else answers
        self.bind_ok = bind_ok
        self.fail = fail          # an exception load() raises instead of reading
        self.searches = []
        self.loads = 0

    @staticmethod
    def _import_ldap3():
        return Exception

    def _connect(self, user, password):
        return FakeConn() if self.bind_ok else None

    def _search_all(self, conn, base, ldap_filter, attributes):
        self.searches.append((base, ldap_filter, tuple(attributes)))
        return list(self.answers.get((base, ldap_filter), []))

    def load(self, now):
        self.loads += 1
        if self.fail is not None:
            raise self.fail
        return super().load(now)


class FakeGroupsServer(FakeServer):
    """A model of the two tables of the custom groups behind the FakeServer: the groups by id, the
    members by (group id, login); the statements of groups.py answered from it (the other
    statements keep the generic behaviour of the base)."""

    def __init__(self, *, tables_exist=True, table='user_groups'):
        super().__init__(table_exists=True)
        self.table = table
        self.members_table = table + '_members'
        self.tables = {table, self.members_table} if tables_exist else set()
        self.groups = {}        # id -> [name, description, created_by, created_at]
        self.members = {}       # (group id, login) -> (added_by, added_at)
        self.next_id = 1

    def count(self, gid) -> int:
        return sum(1 for g, _login in self.members if g == gid)

    def dispatch(self, cursor, sql, args) -> bool:
        table = sql.split('`')[1] if '`' in sql else ''
        if table not in (self.table, self.members_table):
            return False
        if sql.startswith('SELECT 1 FROM'):
            if table not in self.tables:
                raise Broken(1146, f"Table 'sre.{table}' doesn't exist")
        elif sql.startswith('CREATE TABLE'):
            self.tables.add(table)
            self.created += 1
        elif sql.startswith('SELECT g.id'):
            cursor._rows = [(gid, *fields, self.count(gid))
                            for gid, fields in sorted(self.groups.items(), key=lambda kv: kv[1][0])]
        elif sql.startswith('SELECT id, name'):
            cursor._rows = [(gid, *fields) for gid, fields in self.groups.items() if fields[0] == args[0]]
        elif sql.startswith('SELECT login'):
            cursor._rows = sorted((login, *v) for (g, login), v in self.members.items() if g == args[0])
        elif sql.startswith('SELECT COUNT'):
            cursor._rows = [(self.count(args[0]),)]
        elif sql.startswith('SELECT g.name'):
            rows = []
            for gid, fields in self.groups.items():
                logins = sorted(login for (g, login) in self.members if g == gid)
                if logins:
                    rows.extend((fields[0], login) for login in logins)
                else:
                    rows.append((fields[0], None))
            cursor._rows = rows
        elif sql.startswith('INSERT IGNORE'):
            added = 0
            for gid, login, by, at in args:
                if (gid, login) not in self.members:
                    self.members[(gid, login)] = (by, at)
                    added += 1
            cursor.rowcount = added
        elif sql.startswith('INSERT'):
            name, description, by, created = args
            if any(f[0] == name for f in self.groups.values()):
                raise Broken(1062, f"Duplicate entry '{name}' for key 'name'")
            gid, self.next_id = self.next_id, self.next_id + 1
            self.groups[gid] = [name, description, by, created]
            cursor.lastrowid, cursor.rowcount = gid, 1
        elif sql.startswith('UPDATE'):
            name, description, gid = args
            if any(f[0] == name and g != gid for g, f in self.groups.items()):
                raise Broken(1062, f"Duplicate entry '{name}' for key 'name'")
            self.groups[gid][0], self.groups[gid][1] = name, description
            cursor.rowcount = 1
        elif sql.startswith('DELETE') and table == self.members_table and 'login' in sql:
            cursor.rowcount = 1 if self.members.pop((args[0], args[1]), None) is not None else 0
        elif sql.startswith('DELETE') and table == self.members_table:
            gone = [k for k in self.members if k[0] == args[0]]
            for k in gone:
                del self.members[k]
            cursor.rowcount = len(gone)
        elif sql.startswith('DELETE'):
            cursor.rowcount = 1 if self.groups.pop(args[0], None) is not None else 0
        else:
            return False
        return True


def make_store(server, *, clock=None, monotonic=None, **over) -> G.GroupStore:
    return G.GroupStore(db_config(), GroupsConfig(**over), connect=server.connect,
                        clock=clock or (lambda: NOW), monotonic=monotonic or (lambda: 0.0))


async def receive(ws, kind: str, timeout=5.0) -> dict:
    """The next text frame of *kind* (``t``) of a presence socket."""
    async with asyncio.timeout(timeout):
        while True:
            msg = await ws.receive()
            assert msg.type == aiohttp.WSMsgType.TEXT, msg
            data = json.loads(msg.data)
            if data.get('t') == kind:
                return data


# ---------------------------------------------------------------------------------------------
# keys and names
# ---------------------------------------------------------------------------------------------

class TestKeys:
    def test_keys(self):
        assert G.group_key('custom', 'TP lundi') == 'custom:TP lundi'
        assert G.parse_group_key('custom:TP lundi') == ('custom', 'TP lundi')
        assert G.parse_group_key('directory:a:b') == ('directory', 'a:b')
        assert G.parse_group_key('1A') == ('department', '1A')            # a bare name
        assert G.parse_group_key('nope:x') == ('department', 'nope:x')   # not a kind: a department named so
        assert G.parse_group_key('') == ('department', '')
        assert G.normalize_group_keys(['1A', 'custom:x', 'department:2B']) == {'department:1A', 'custom:x', 'department:2B'}
        assert G.department_member('1A', {'department:1A', 'custom:x'}) and not G.department_member('', {'department:'})
        assert not G.department_member('1A', {'custom:1A'})
        assert G.KINDS == ('department', 'directory', 'custom')

    def test_check_group_name(self):
        assert G.check_group_name(' TP lundi ') == 'TP lundi'
        for bad in ('', '   ', 'a:b', 'a/b', 'a\x00b', 'x' * 65, 3, None):
            with pytest.raises(ValueError):
                G.check_group_name(bad)
        assert G.check_group_name('x' * 64) == 'x' * 64

    def test_group_dict_and_sort(self):
        d = G.group_dict('directory', 'etudiants', 3)
        assert d == {'key': 'directory:etudiants', 'kind': 'directory', 'name': 'etudiants', 'members': 3,
                     'description': '', 'created_by': None, 'created_at': None}
        groups = [G.group_dict('custom', 'b', 0), G.group_dict('department', '2A', 1), G.group_dict('directory', 'x', 1),
                  G.group_dict('department', '1a', 1), G.group_dict('custom', 'A', 0)]
        assert [g['key'] for g in sorted(groups, key=G.sort_key)] == \
            ['department:1a', 'department:2A', 'directory:x', 'custom:A', 'custom:b']
        assert G.iso_utc(NOW) == NOW_ISO


# ---------------------------------------------------------------------------------------------
# the directory
# ---------------------------------------------------------------------------------------------

class TestDirectoryListing:
    def test_people_departments_and_groups(self):
        listing = FakeListing()
        snapshot = listing.load(NOW)
        assert sorted(snapshot.people) == ['alice', 'bob', 'carol', 'prof'] and snapshot.loaded_at == NOW
        assert snapshot.people['alice'] == G.Person('alice', 'Alice A', '1A')
        assert snapshot.people['prof'] == G.Person('prof', 'Pr. Of', '')
        assert snapshot.departments == {'1A': frozenset({'alice', 'bob'}), '2B': frozenset({'carol'})}
        # the members by uid, by login whatever the case, by DN, an unknown login kept, a nested DN dropped,
        # two entries of one cleaned name merged, an unnamed entry skipped
        assert snapshot.groups == {'etudiants': frozenset({'alice', 'bob', 'carol', 'ghost'}),
                                   'profs': frozenset({'prof', 'alice'})}
        assert listing.searches == [(PEOPLE, PEOPLE_FILTER, ('supannAliasLogin', 'uid', 'cn', 'departmentNumber')),
                                    (GROUPS, GROUPS_FILTER, ('cn', 'memberUid'))]
        # the queries of the snapshot
        assert snapshot.department_of('carol') == '2B' and snapshot.department_of('ghost') == ''
        assert snapshot.directory_groups_of('alice') == ['etudiants', 'profs'] and snapshot.directory_groups_of('x') == []
        assert snapshot.members_of('department', '1A') == {'alice', 'bob'}
        assert snapshot.members_of('directory', 'profs') == {'alice', 'prof'}
        assert snapshot.members_of('department', '9Z') is None and snapshot.members_of('custom', 'x') is None
        assert snapshot.person_row('ghost') == {'login': 'ghost', 'fullname': '', 'group': ''}
        assert snapshot.person_row('bob') == {'login': 'bob', 'fullname': 'Bob B', 'group': '1A'}
        assert snapshot.names() == {'1A', '2B', 'etudiants', 'profs'}
        assert [p.login for p in snapshot.search('a')[0]] == ['alice', 'carol']
        people, more = snapshot.search('', limit=2)
        assert [p.login for p in people] == ['alice', 'bob'] and more
        assert [p.login for p in snapshot.search('of')[0]] == ['prof'] and snapshot.search('zzz') == ([], False)

    def test_login_attribute_and_optional_searches(self):
        listing = FakeListing(ldap_cfg(search_filter='(uid={login})', attr_group=''))
        snapshot = listing.load(NOW)
        assert listing.searches[0] == (PEOPLE, '(uid=*)', ('uid', 'cn')) and snapshot.people == {}
        listing = FakeListing(ldap_cfg(attr_login='mail'))
        listing.load(NOW)
        assert listing.searches[0][1] == '(mail=*)' and listing.searches[0][2][:2] == ('mail', 'uid')
        # no group base, or no groups filter: the people alone
        for cfg in (ldap_cfg(group_search_base=''), ldap_cfg(groups_filter='')):
            listing = FakeListing(cfg)
            snapshot = listing.load(NOW)
            assert len(listing.searches) == 1 and snapshot.groups == {} and sorted(snapshot.people) == ['alice', 'bob', 'carol', 'prof']

    def test_refusals(self):
        with pytest.raises(LdapError, match='cannot bind'):
            FakeListing(bind_ok=False).load(NOW)
        with pytest.raises(LdapError, match='attr_login'):
            FakeListing(ldap_cfg(search_filter='(|(uid={login})(mail={login}))')).load(NOW)
        with pytest.raises(LdapError, match='uri and search_base'):
            FakeListing(ldap_cfg(uri='')).load(NOW)

    def test_search_all_pages(self):
        """The paged search of ldap3: the entries of every page, the referrals skipped."""
        calls = []

        def paged_search(base, ldap_filter, attributes=None, paged_size=None, generator=False):
            calls.append((base, ldap_filter, tuple(attributes), paged_size, generator))
            yield {'type': 'searchResEntry', 'dn': f'uid=a,{PEOPLE}', 'attributes': {'uid': ['a']}}
            yield {'type': 'searchResRef', 'uri': ['ldap://other/']}
            yield {'type': 'searchResEntry', 'dn': f'uid=b,{PEOPLE}', 'attributes': {'uid': 'b'}}

        conn = types.SimpleNamespace(extend=types.SimpleNamespace(standard=types.SimpleNamespace(paged_search=paged_search)))
        found = G.DirectoryListing(ldap_cfg())._search_all(conn, PEOPLE, '(uid=*)', ['uid'])
        assert found == [(f'uid=a,{PEOPLE}', {'uid': ['a']}), (f'uid=b,{PEOPLE}', {'uid': 'b'})]
        assert calls == [(PEOPLE, '(uid=*)', ('uid',), G.PAGE, True)]

    def test_member_logins_and_values(self):
        index = {'alice': 'alice', 'alice.a': 'alice', f'uid=alice.a,{PEOPLE}'.casefold(): 'alice', 'bob.b': 'bob'}
        assert G.member_logins(['ALICE', 'bob.b', f'UID=alice.a,{PEOPLE}', 'ghost', 'cn=x,ou=g', '', ' bob.b '], index) \
            == {'alice', 'bob', 'ghost'}
        attrs = {'cn': 'Alice', 'memberUid': ['a', b'b', None], 'departmentNumber': []}
        assert G._values(attrs, 'cn') == ['Alice'] and G._values(attrs, 'memberUid') == ['a', 'b']
        assert G._values(attrs, 'CN') == ['Alice'] and G._values(attrs, 'mail') == [] and G._first_value(attrs, 'departmentNumber') == ''


class TestDirectoryCache:
    def test_one_load_for_concurrent_gets_then_the_ttl(self):
        async def go():
            clock = types.SimpleNamespace(now=100.0)
            listing = FakeListing()
            cache = G.DirectoryCache(listing, ttl=600, clock=lambda: clock.now, wall=lambda: NOW)
            snapshots = await asyncio.gather(*(cache.get() for _ in range(5)))
            assert listing.loads == 1 and all(s is snapshots[0] for s in snapshots) and cache.fresh()
            assert cache.status() == {'configured': True, 'loaded_at': NOW_ISO, 'error': None, 'people': 4}
            await cache.get()
            assert listing.loads == 1
            clock.now += 601
            assert not cache.fresh()
            await cache.get()
            assert listing.loads == 2
            await cache.get(refresh=True)
            assert listing.loads == 3
        run(go())

    def test_a_failure_keeps_the_snapshot(self):
        async def go():
            clock = types.SimpleNamespace(now=100.0)
            listing = FakeListing()
            cache = G.DirectoryCache(listing, ttl=600, negative_ttl=60, clock=lambda: clock.now, wall=lambda: NOW)
            first = await cache.get()
            listing.fail = LdapError('sizeLimitExceeded')
            clock.now += 601
            assert await cache.get() is first and cache.error == 'sizeLimitExceeded' and listing.loads == 2
            assert cache.status()['error'] == 'sizeLimitExceeded' and cache.status()['people'] == 4
            clock.now += 30
            await cache.get()
            assert listing.loads == 2            # within the negative ttl: not tried again
            clock.now += 31
            listing.fail = None
            assert await cache.get() is not first and listing.loads == 3 and cache.error is None
            # before any success: no snapshot, the error kept
            broken = G.DirectoryCache(FakeListing(fail=LdapError('down')), ttl=600)
            assert await broken.get() is None and broken.error == 'down'
            assert broken.status() == {'configured': True, 'loaded_at': None, 'error': 'down', 'people': 0}
        run(go())


# ---------------------------------------------------------------------------------------------
# the custom groups
# ---------------------------------------------------------------------------------------------

STATEMENTS = (G.SELECT_GROUPS, G.SELECT_GROUP, G.SELECT_MEMBERS, G.COUNT_MEMBERS, G.SELECT_MEMBERSHIPS, G.INSERT_GROUP,
              G.UPDATE_GROUP, G.DELETE_MEMBERS_OF, G.DELETE_GROUP, G.INSERT_MEMBER, G.DELETE_MEMBER)


class TestGroupStore:
    def test_statements(self):
        for sql in STATEMENTS:
            assert sql.count('%') == sql.count('%s'), sql           # placeholders only: PyMySQL formats the statement
            assert set(re.findall(r'\{(\w+)\}', sql)) <= {'table', 'members'}, sql
        for ddl in (G.DDL_GROUPS, G.DDL_MEMBERS):
            assert set(re.findall(r'\{(\w+)\}', ddl)) == {'table'} and 'utf8mb4_bin' in ddl
        assert 'INSERT IGNORE' in G.INSERT_MEMBER and 'PRIMARY KEY (group_id, login)' in G.DDL_MEMBERS

    def test_tables_created_once(self):
        server = FakeGroupsServer(tables_exist=False)
        store = make_store(server)
        assert store.list_sync() == [] and server.created == 2 and server.tables == {'user_groups', 'user_groups_members'}
        assert [s[1] for s in server.statements_of('CREATE')] == [G.DDL_GROUPS.format(table='user_groups'),
                                                                   G.DDL_MEMBERS.format(table='user_groups_members')]
        store.list_sync()
        assert server.created == 2 and len(server.statements_of('SELECT 1 FROM')) == 2
        # another table name: the members table follows
        other = make_store(FakeGroupsServer(tables_exist=False, table='grp'), table='grp')
        assert other.list_sync() == [] and other.members_table == 'grp_members'

    def test_lifecycle(self):
        server = FakeGroupsServer()
        store = make_store(server)
        group = store.create_sync('TP lundi', 'Lundi 8h', 'prof')
        assert group == G.CustomGroup(1, 'TP lundi', 'Lundi 8h', 'prof', NOW, 0)
        assert group.to_dict() == {'key': 'custom:TP lundi', 'kind': 'custom', 'name': 'TP lundi', 'members': 0,
                                   'description': 'Lundi 8h', 'created_by': 'prof', 'created_at': NOW_ISO}
        with pytest.raises(G.GroupExists):
            store.create_sync('TP lundi', '', 'prof')
        assert store.list_sync() == [group]
        assert store.add_members_sync('TP lundi', ['alice', 'bob', 'alice'], 'prof') == (2, 2)
        assert store.add_members_sync('TP lundi', ['bob', 'carol'], 'prof') == (1, 3)
        assert store.add_members_sync('TP lundi', [], 'prof') == (0, 3)
        found, members = store.get_sync('TP lundi')
        assert found.members == 3 and [m['login'] for m in members] == ['alice', 'bob', 'carol']
        assert members[0] == {'login': 'alice', 'added_by': 'prof', 'added_at': NOW_ISO}
        assert store.list_sync()[0].members == 3
        renamed = store.update_sync('TP lundi', new_name='TP mardi', description='Mardi')
        assert (renamed.id, renamed.name, renamed.description, renamed.members) == (1, 'TP mardi', 'Mardi', 3)
        assert store.update_sync('TP mardi', description='Mardi 10h').description == 'Mardi 10h'
        assert store.update_sync('TP mardi').name == 'TP mardi'       # nothing changes
        store.create_sync('autre', '', 'prof')
        with pytest.raises(G.GroupExists):
            store.update_sync('TP mardi', new_name='autre')
        with pytest.raises(G.GroupNotFound):
            store.update_sync('nope', description='x')
        with pytest.raises(G.GroupNotFound):
            store.remove_member_sync('TP mardi', 'ghost')
        store.remove_member_sync('TP mardi', 'alice')
        assert store.memberships_sync() == {'TP mardi': frozenset({'bob', 'carol'}), 'autre': frozenset()}
        store.delete_sync('TP mardi')
        deletes = [s[1] for s in server.statements if s[1].startswith('DELETE')]
        assert deletes[-2:] == [G.DELETE_MEMBERS_OF.format(members='user_groups_members'),
                                G.DELETE_GROUP.format(table='user_groups')]
        with pytest.raises(G.GroupNotFound):
            store.get_sync('TP mardi')
        with pytest.raises(G.GroupNotFound):
            store.delete_sync('TP mardi')
        assert store.memberships_sync() == {'autre': frozenset()} and server.members == {}
        assert store.status() == {'connected': True, 'last_error': None}
        assert 'user_groups, user_groups_members' in store.describe()

    def test_a_duplicate_past_the_check_is_a_group_exists(self):
        server = FakeGroupsServer()
        store = make_store(server)
        server.fail_next.append((lambda sql, args: sql.startswith('INSERT INTO'), Broken(1062, "Duplicate entry 'x'")))
        with pytest.raises(G.GroupExists):
            store.create_sync('x', '', 'prof')
        server.fail_next.append((lambda sql, args: sql.startswith('UPDATE'), Broken(1062, "Duplicate entry 'y'")))
        store.create_sync('x', '', 'prof')
        with pytest.raises(G.GroupExists):
            store.update_sync('x', new_name='y')
        # another refusal is the database's error
        server.fail_next.append((lambda sql, args: sql.startswith('INSERT INTO'), Broken(1366, "Incorrect string value")))
        with pytest.raises(HistoryError, match='Incorrect string value'):
            store.create_sync('z', '', 'prof')

    def test_server_down(self):
        server = FakeGroupsServer()
        store = make_store(server)
        server.down = True
        with pytest.raises(HistoryError):
            store.list_sync()
        assert store.status()['connected'] is False and "Can't connect" in store.status()['last_error']
        server.down = False
        assert store.list_sync() == [] and store.status() == {'connected': True, 'last_error': None}

    def test_memberships_cache(self):
        async def go():
            clock = types.SimpleNamespace(now=1000.0)
            server = FakeGroupsServer()
            store = make_store(server, monotonic=lambda: clock.now)
            assert store.cached() == {}
            await store.create('TP', '', 'prof')
            await store.add_members('TP', ['alice'], 'prof')
            selects = lambda: len([s for s in server.statements if s[1].startswith('SELECT g.name')])   # noqa: E731
            assert await store.memberships() == {'TP': frozenset({'alice'})} and selects() == 1
            assert await store.memberships() == {'TP': frozenset({'alice'})} and selects() == 1   # cached
            assert store.cached() == {'TP': frozenset({'alice'})}
            clock.now += G.MEMBERSHIPS_TTL + 1
            await store.memberships()
            assert selects() == 2
            await store.remove_member('TP', 'alice')        # a write of this process: read again
            assert await store.memberships() == {'TP': frozenset()} and selects() == 3
            await store.memberships(refresh=True)
            assert selects() == 4
            server.down = True
            with pytest.raises(HistoryError):
                await store.memberships(refresh=True)
            assert store.cached() == {'TP': frozenset()}     # the previous ones stay
            server.down = False
            group = await store.update('TP', new_name='TP2')
            assert group.name == 'TP2' and await store.memberships() == {'TP2': frozenset()}
            await store.delete('TP2')
            assert await store.memberships() == {} and (await store.list()) == []
        run(go())


# ---------------------------------------------------------------------------------------------
# the service
# ---------------------------------------------------------------------------------------------

class TestMemberships:
    def make(self, *, directory=True, store=True):
        cache = G.DirectoryCache(FakeListing(), ttl=600) if directory else None
        server = FakeGroupsServer()
        groups = make_store(server) if store else None
        if groups is not None:
            groups.create_sync('TP lundi', '', 'prof')
            groups.add_members_sync('TP lundi', ['alice', 'dave'], 'prof')
            groups.create_sync('vide', '', 'prof')
        memberships = G.Memberships(directory=cache, store=groups)
        run(memberships.refresh())
        return memberships, server

    def test_groups_of_members_of_and_is_member(self):
        m, _server = self.make()
        assert m.available and m.knows_people()
        assert m.groups_of('alice') == ['department:1A', 'directory:etudiants', 'directory:profs', 'custom:TP lundi']
        assert m.groups_of('bob', '9Z') == ['department:9Z', 'directory:etudiants']     # the department given wins
        assert m.groups_of('dave') == ['custom:TP lundi'] and m.groups_of('nobody') == []
        assert m.groups_of_identity(Identity(login='carol', group='2B')) == ['department:2B', 'directory:etudiants']
        assert m.members_of(['department:1A', 'custom:TP lundi', 'nope:x', 'custom:zzz']) == {'alice', 'bob', 'dave'}
        assert m.members_of(['2B']) == {'carol'}            # a bare name: a department
        assert m.is_member('carol', ['department:2B']) and m.is_member('dave', ['department:1A'], department='1A')
        assert m.is_member('ghost', ['directory:etudiants']) and not m.is_member('ghost', ['custom:TP lundi'])
        assert not m.is_member('bob', ['custom:vide']) and m.is_member('dave', {'custom:TP lundi'}, department='')
        assert m.names_in_use() == {'1A', '2B', 'etudiants', 'profs'}
        assert m.person_row('alice') == {'login': 'alice', 'fullname': 'Alice A', 'group': '1A'}
        groups = sorted(m.directory_groups(), key=G.sort_key)
        assert [(g['key'], g['members']) for g in groups] == \
            [('department:1A', 2), ('department:2B', 1), ('directory:etudiants', 4), ('directory:profs', 2)]
        rows = [{'owner': 'alice', 'group': '1A'}, {'owner': 'ghost', 'group': ''}, {'owner': 'bad login', 'group': 'x'},
                {'name': 'no owner'}]
        assert [r['groups'] for r in m.annotate(rows)] == \
            [['department:1A', 'directory:etudiants', 'directory:profs', 'custom:TP lundi'], ['directory:etudiants'], [], []]

    def test_one_source_or_none(self):
        m, _server = self.make(directory=False)
        assert m.available and not m.knows_people() and m.names_in_use() == set() and m.directory_groups() == []
        assert m.groups_of('alice', '1A') == ['department:1A', 'custom:TP lundi'] and m.groups_of('alice') == ['custom:TP lundi']
        assert m.members_of(['department:1A', 'custom:TP lundi']) == {'alice', 'dave'}
        assert m.is_member('bob', ['department:1A'], department='1A') and not m.is_member('bob', ['department:1A'])
        assert m.person_row('alice') == {'login': 'alice', 'fullname': '', 'group': ''}
        m, _server = self.make(store=False)
        assert m.groups_of('alice') == ['department:1A', 'directory:etudiants', 'directory:profs']
        assert m.members_of(['custom:TP lundi']) == set()
        none = G.Memberships()
        assert not none.available and none.groups_of('alice', '1A') == ['department:1A'] and none.members_of(['1A']) == set()
        assert none.is_member('alice', ['department:1A'], department='1A') and not none.is_member('alice', ['custom:x'])
        run(none.refresh())      # nothing to do

    def test_refresh_never_raises(self):
        m, server = self.make()
        server.down = True
        run(m.refresh(force=True))
        assert m.store.cached() == {'TP lundi': frozenset({'alice', 'dave'}), 'vide': frozenset()}
        m.directory.listing.fail = LdapError('down')
        run(m.refresh(force=True))
        assert m.directory.error == 'down' and m.knows_people()


# ---------------------------------------------------------------------------------------------
# through the portal
# ---------------------------------------------------------------------------------------------

def web_over(tmp_path, *, database=True, directory=True) -> dict:
    auth = {**P.PROXY_OVER['auth'], **({'ldap': LDAP} if directory else {})}
    access_log = {'file': str(tmp_path / 'access.log'), 'journal': False, **({'database': DB} if database else {})}
    return {**P.PROXY_OVER, 'auth': auth, 'access_log': access_log, 'archives': {'poll_interval': '1h'}}


def harness(tmp_path, server=None, listing=None, **kw):
    return P.Harness(tmp_path, auth_mode='proxy', web_over=web_over(tmp_path, database=server is not None,
                                                                    directory=listing is not None),
                     db_connect=(server.connect, (Down,)) if server is not None else None,
                     directory_listing=listing, **kw)


class TestGroupsThroughThePortal:
    def test_page_guards_and_sources(self, tmp_path):
        async def go():
            bob, prof = P.who('bob'), P.who('prof', groups=P.TEACHERS)
            async with harness(tmp_path, FakeGroupsServer(), FakeListing()) as h:
                assert (await h.client.get('/groups', allow_redirects=False)).status == 302
                assert (await h.client.get('/groups', headers=bob)).status == 403
                page = await h.client.get('/groups', headers=prof)
                assert page.status == 200 and 'prof True True True True' in await page.text()
                assert (await h.client.get('/api/groups')).status == 401
                assert (await h.client.get('/api/groups', headers=bob)).status == 403
                assert (await h.client.get('/api/groups/people?q=a', headers=bob)).status == 403
                assert (await h.client.post('/api/groups', json={'name': 'x'}, headers=prof)).status == 403   # no CSRF header
            # the directory alone: the custom groups have no database
            async with harness(tmp_path / 'dir', None, FakeListing()) as h:
                page = await h.client.get('/groups', headers=prof)
                assert 'prof True True False True' in await page.text()
                data = await (await h.client.get('/api/groups', headers=prof)).json()
                assert data['database'] is None and data['directory']['configured'] is True
                assert [g['key'] for g in data['groups']] == ['department:1A', 'department:2B', 'directory:etudiants',
                                                              'directory:profs']
                for method, path in (('POST', '/api/groups'), ('PUT', '/api/groups/custom/x'),
                                     ('DELETE', '/api/groups/custom/x'), ('POST', '/api/groups/custom/x/members'),
                                     ('DELETE', '/api/groups/custom/x/members/bob'), ('GET', '/api/groups/custom/x')):
                    resp = await h.client.request(method, path, json={'name': 'x', 'logins': []} if method != 'GET' else None,
                                                  headers={**prof, **P.CSRF})
                    assert resp.status == 409 and 'access_log.database' in (await resp.json())['error'], (method, path)
            # the database alone: no directory, every login accepted
            async with harness(tmp_path / 'db', FakeGroupsServer(), None) as h:
                assert 'prof True False True True' in await (await h.client.get('/groups', headers=prof)).text()
                data = await (await h.client.get('/api/groups', headers=prof)).json()
                assert data['groups'] == [] and data['database'] == {'connected': True, 'last_error': None}
                assert data['directory'] == {'configured': False, 'loaded_at': None, 'people': 0,
                                             'error': 'auth.ldap.uri and search_base are required to list the directory'}
                assert (await h.client.get('/api/groups/people?q=a', headers=prof)).status == 200
                assert await (await h.client.get('/api/groups/people?q=a', headers=prof)).json() == {'people': [], 'more': False}
                assert (await h.client.post('/api/groups', json={'name': 'TP'}, headers={**prof, **P.CSRF})).status == 201
                resp = await h.client.post('/api/groups/custom/TP/members', json={'logins': ['anyone']}, headers={**prof, **P.CSRF})
                assert resp.status == 200 and (await resp.json()) == {'added': 1, 'members': 1, 'unknown': []}
            # neither: the page says so
            async with harness(tmp_path / 'none', None, None) as h:
                assert 'prof True False False False' in await (await h.client.get('/groups', headers=prof)).text()
                data = await (await h.client.get('/api/groups', headers=prof)).json()
                assert data == {'groups': [], 'database': None,
                                'directory': {'configured': False, 'loaded_at': None, 'people': 0,
                                              'error': 'auth.ldap.uri and search_base are required to list the directory'}}
        run(go())

    def test_listing_detail_and_people(self, tmp_path):
        async def go():
            listing = FakeListing()
            prof = P.who('prof', groups=P.TEACHERS)
            async with harness(tmp_path, FakeGroupsServer(), listing) as h:
                data = await (await h.client.get('/api/groups', headers=prof)).json()
                assert [(g['key'], g['members'], g['description'], g['created_by']) for g in data['groups']] == \
                    [('department:1A', 2, '', None), ('department:2B', 1, '', None), ('directory:etudiants', 4, '', None),
                     ('directory:profs', 2, '', None)]
                assert data['directory']['configured'] and data['directory']['error'] is None
                assert data['directory']['people'] == 4 and data['directory']['loaded_at'].endswith('+00:00')
                assert data['database'] == {'connected': True, 'last_error': None}
                loads = listing.loads
                await h.client.get('/api/groups', headers=prof)
                assert listing.loads == loads                       # fresh: not read again
                await h.client.get('/api/groups?refresh=1', headers=prof)
                assert listing.loads == loads + 1
                # the detail of a department, of a directory group
                data = await (await h.client.get('/api/groups/department/1A', headers=prof)).json()
                assert data['group'] == {'key': 'department:1A', 'kind': 'department', 'name': '1A', 'members': 2,
                                         'description': '', 'created_by': None, 'created_at': None}
                assert data['members'] == [{'login': 'alice', 'fullname': 'Alice A', 'group': '1A', 'added_by': None, 'added_at': None},
                                           {'login': 'bob', 'fullname': 'Bob B', 'group': '1A', 'added_by': None, 'added_at': None}]
                data = await (await h.client.get('/api/groups/directory/etudiants', headers=prof)).json()
                assert [(m['login'], m['fullname']) for m in data['members']] == \
                    [('alice', 'Alice A'), ('bob', 'Bob B'), ('carol', 'Carol C'), ('ghost', '')]
                for path in ('/api/groups/nope/x', '/api/groups/department/9Z', '/api/groups/directory/x',
                             '/api/groups/custom/x'):
                    assert (await h.client.get(path, headers=prof)).status == 404, path
                # the people of the directory, for the Add row
                data = await (await h.client.get('/api/groups/people?q=ali', headers=prof)).json()
                assert data == {'people': [{'login': 'alice', 'fullname': 'Alice A', 'group': '1A'}], 'more': False}
                data = await (await h.client.get('/api/groups/people', headers=prof)).json()
                assert [p['login'] for p in data['people']] == ['alice', 'bob', 'carol', 'prof'] and not data['more']
                assert await (await h.client.get('/api/groups/people?q=zzz', headers=prof)).json() == {'people': [], 'more': False}
        run(go())

    def test_custom_groups_lifecycle_and_log(self, tmp_path):
        async def go():
            server = FakeGroupsServer()
            prof = P.who('prof', 'Pr. Of', groups=P.TEACHERS)
            hp = {**prof, **P.CSRF}
            async with harness(tmp_path, server, FakeListing()) as h:
                resp = await h.client.post('/api/groups', json={'name': ' TP lundi ', 'description': ' Lundi 8h '}, headers=hp)
                assert resp.status == 201, await resp.text()
                group = (await resp.json())['group']
                assert {k: v for k, v in group.items() if k != 'created_at'} == \
                    {'key': 'custom:TP lundi', 'kind': 'custom', 'name': 'TP lundi', 'members': 0, 'description': 'Lundi 8h',
                     'created_by': 'prof'}
                assert group['created_at'].endswith('+00:00')
                # the refusals
                assert (await h.client.post('/api/groups', json={'name': 'TP lundi'}, headers=hp)).status == 409
                resp = await h.client.post('/api/groups', json={'name': '1A'}, headers=hp)
                assert resp.status == 409 and 'department' in (await resp.json())['error']
                assert (await h.client.post('/api/groups', json={'name': 'etudiants'}, headers=hp)).status == 409
                for bad in ({'name': 'a:b'}, {'name': 'x/y'}, {'name': ''}, {'name': 3}, {}, {'name': 'ok', 'description': 'x' * 300},
                            {'name': 'ok', 'description': 3}):
                    assert (await h.client.post('/api/groups', json=bad, headers=hp)).status == 400, bad
                assert (await h.client.post('/api/groups', data='nope', headers=hp)).status == 400
                assert (await h.client.post('/api/groups', json=[1], headers=hp)).status == 400
                data = await (await h.client.get('/api/groups', headers=prof)).json()
                assert data['groups'][-1]['key'] == 'custom:TP lundi' and data['groups'][-1]['members'] == 0
                # the members: unknown logins refused as a whole, duplicates ignored, a copy of another group
                resp = await h.client.post('/api/groups/custom/TP%20lundi/members', json={'logins': ['alice', 'zed']}, headers=hp)
                assert resp.status == 400 and (await resp.json())['unknown'] == ['zed']
                assert (await (await h.client.get('/api/groups/custom/TP%20lundi', headers=prof)).json())['members'] == []
                resp = await h.client.post('/api/groups/custom/TP%20lundi/members', json={'logins': ['alice', 'bob', 'alice']}, headers=hp)
                assert resp.status == 200 and await resp.json() == {'added': 2, 'members': 2, 'unknown': []}
                resp = await h.client.post('/api/groups/custom/TP%20lundi/members', json={'from': 'department:2B'}, headers=hp)
                assert resp.status == 200 and await resp.json() == {'added': 1, 'members': 3, 'unknown': []}
                resp = await h.client.post('/api/groups/custom/TP%20lundi/members', json={'from': 'directory:etudiants'}, headers=hp)
                assert await resp.json() == {'added': 1, 'members': 4, 'unknown': []}       # ghost
                for bad, status in (({'from': 'custom:nope'}, 404), ({'from': 'directory:nope'}, 404), ({'from': 3}, 400),
                                    ({'logins': 'alice'}, 400), ({'logins': ['bad login']}, 400), ({'logins': [3]}, 400),
                                    ({'logins': ['a'] * (G.MAX_BATCH + 1)}, 400)):
                    assert (await h.client.post('/api/groups/custom/TP%20lundi/members', json=bad, headers=hp)).status == status, bad
                assert (await h.client.post('/api/groups/custom/nope/members', json={'logins': ['alice']}, headers=hp)).status == 404
                data = await (await h.client.get('/api/groups/custom/TP%20lundi', headers=prof)).json()
                assert data['group']['members'] == 4
                assert [(m['login'], m['fullname'], m['group'], m['added_by']) for m in data['members']] == \
                    [('alice', 'Alice A', '1A', 'prof'), ('bob', 'Bob B', '1A', 'prof'), ('carol', 'Carol C', '2B', 'prof'),
                     ('ghost', '', '', 'prof')]
                assert all(m['added_at'].endswith('+00:00') for m in data['members'])
                # rename and describe
                resp = await h.client.put('/api/groups/custom/TP%20lundi', json={'name': 'TP mardi', 'description': 'Mardi'}, headers=hp)
                assert resp.status == 200
                group = (await resp.json())['group']
                assert (group['key'], group['description'], group['members']) == ('custom:TP mardi', 'Mardi', 4)
                assert (await h.client.get('/api/groups/custom/TP%20lundi', headers=prof)).status == 404
                assert (await h.client.put('/api/groups/custom/TP%20mardi', json={'name': '1A'}, headers=hp)).status == 409
                assert (await h.client.put('/api/groups/custom/TP%20mardi', json={'name': 'a:b'}, headers=hp)).status == 400
                assert (await h.client.put('/api/groups/custom/nope', json={'description': 'x'}, headers=hp)).status == 404
                resp = await h.client.put('/api/groups/custom/TP%20mardi', json={'name': 'TP mardi'}, headers=hp)
                assert resp.status == 200 and (await resp.json())['group']['description'] == 'Mardi'   # the same name: no rename
                # remove members, delete the group
                assert (await h.client.delete('/api/groups/custom/TP%20mardi/members/carol', headers=hp)).status == 204
                assert (await h.client.delete('/api/groups/custom/TP%20mardi/members/carol', headers=hp)).status == 404
                assert (await h.client.delete('/api/groups/custom/TP%20mardi/members/bad%20login', headers=hp)).status == 404
                assert (await (await h.client.get('/api/groups/custom/TP%20mardi', headers=prof)).json())['group']['members'] == 3
                assert (await h.client.delete('/api/groups/custom/TP%20mardi', headers=hp)).status == 204
                assert (await h.client.get('/api/groups/custom/TP%20mardi', headers=prof)).status == 404
                assert (await h.client.delete('/api/groups/custom/TP%20mardi', headers=hp)).status == 404
                assert server.members == {} and server.groups == {}
                # the database down: 503 on the custom routes, the directory groups still listed
                server.down = True
                assert (await h.client.get('/api/groups/custom/x', headers=prof)).status == 503
                assert (await h.client.post('/api/groups', json={'name': 'y'}, headers=hp)).status == 503
                data = await (await h.client.get('/api/groups', headers=prof)).json()
                assert len(data['groups']) == 4 and data['database']['connected'] is False and data['database']['last_error']
            lines = [parse_line(line) for line in (tmp_path / 'access.log').read_text().splitlines()]
            edits = [(l.get('action'), l.get('group'), l.get('status')) for l in lines if l.get('event') == 'group_edit']
            assert ('create', 'TP lundi', '201') in edits and ('create', '1A', '409') in edits
            assert ('add', 'TP lundi', '200') in edits and ('update', 'TP lundi', '200') in edits
            assert ('remove', 'TP mardi', '204') in edits and ('delete', 'TP mardi', '204') in edits
            add = next(l for l in lines if l.get('action') == 'add' and l.get('status') == '200')
            assert add['count'] == '3' and add['login'] == 'prof'
            copy = next(l for l in lines if l.get('source') == 'department:2B')
            assert copy['count'] == '1'
            rename = next(l for l in lines if l.get('new_name'))
            assert (rename['group'], rename['new_name']) == ('TP lundi', 'TP mardi')
            removed = next(l for l in lines if l.get('action') == 'remove' and l.get('status') == '204')
            assert removed['member'] == 'carol'
            reads = [(l.get('kind'), l.get('group')) for l in lines if l.get('event') == 'groups']
            assert (None, None) in reads and ('custom', 'TP lundi') in reads
            assert not any(l.get('event') == 'denied' for l in lines)
        run(go())

    def test_watch_presence_and_presentations_carry_the_groups(self, tmp_path):
        async def go():
            server = FakeGroupsServer()
            alice, bob = P.who('alice', 'Alice A', group='1A'), P.who('bob', 'Bob B', group='1A')
            carol, prof = P.who('carol', group='2B'), P.who('prof', 'Pr. Of', groups=P.TEACHERS)
            hp = {**prof, **P.CSRF}
            async with harness(tmp_path, server, FakeListing()) as h:
                rln = await PR.start_project(h, alice)
                assert (await h.client.post('/api/groups', json={'name': 'TP'}, headers=hp)).status == 201
                assert (await h.client.post('/api/groups/custom/TP/members', json={'logins': ['bob']}, headers=hp)).status == 200
                # the Watch rows
                rows = await (await h.client.get('/api/watch', headers=prof)).json()
                row = next(r for r in rows if r['owner'] == 'alice')
                assert row['group'] == '1A' and row['groups'] == ['department:1A', 'directory:etudiants', 'directory:profs']
                # the presence rows
                bob_ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=bob)
                carol_ws = await h.client.ws_connect('/api/presence/ws', headers=carol)
                rows = await (await h.client.get('/api/presence', headers=prof)).json()
                assert [(r['login'], r['group'], r['groups']) for r in rows] == \
                    [('bob', '1A', ['department:1A', 'directory:etudiants', 'custom:TP']),
                     ('carol', '2B', ['department:2B', 'directory:etudiants'])]
                # a presentation to the custom group: bob is told, carol is not
                resp = await h.client.post('/api/presentations', json={'host': 'a01', 'rln': rln,
                                                                       'audience': {'logins': [], 'groups': ['custom:TP']}},
                                           headers=hp)
                assert resp.status == 201, await resp.text()
                p = await resp.json()
                assert p['audience']['groups'] == ['custom:TP'] and (p['count'], p['connected']) == (1, 0)
                told = await receive(bob_ws, 'presentation')
                assert told['id'] == p['id'] and told['url'] == f"/present/{p['id']}"
                assert (await h.client.get(f"/present/{p['id']}", headers=carol)).status == 403
                # carol joins the group: told at once; bob leaves it: the presentation ends for him
                assert (await h.client.post('/api/groups/custom/TP/members', json={'logins': ['carol']}, headers=hp)).status == 200
                assert (await receive(carol_ws, 'presentation'))['id'] == p['id']
                assert (await h.client.get(f"/present/{p['id']}", headers=carol)).status == 200
                shown = await (await h.client.get(f"/api/presentations/{p['id']}", headers=prof)).json()
                assert shown['count'] == 2                 # bob and carol, both connected members of the group
                assert (await h.client.delete('/api/groups/custom/TP/members/bob', headers=hp)).status == 204
                ended = await receive(bob_ws, 'presentation')
                assert ended['id'] == p['id'] and ended.get('ended') is True
                # a department by the identity's group alone (dave is not in the directory), a bare name accepted
                dave_ws = await h.client.ws_connect('/api/presence/ws', headers=P.who('dave', group='2B'))
                resp = await h.client.put(f"/api/presentations/{p['id']}/audience",
                                          json={'audience': {'logins': [], 'groups': ['2B']}}, headers=hp)
                assert resp.status == 200 and (await resp.json())['audience']['groups'] == ['department:2B']
                assert (await receive(dave_ws, 'presentation'))['id'] == p['id']
                shown = await (await h.client.get(f"/api/presentations/{p['id']}", headers=prof)).json()
                assert shown['count'] == 2                 # carol (by her department, told already) and dave
                for ws in (bob_ws, carol_ws, dave_ws):
                    await ws.close()
        run(go())
