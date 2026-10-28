"""Tests of sreweb.portal.auth_ldap without a directory: the role tests on a duck-typed
connection, the proxy-mode role resolver, and the per-login role cache (sreweb.portal.roles)."""
import asyncio
import sys
import types

import pytest

from sreweb.config import LdapConfig
from sreweb.identity import ROLE_INSTRUCTOR, ROLE_STUDENT
from sreweb.portal import auth_ldap as L
from sreweb.portal.roles import RoleCache

PEOPLE = 'ou=people,dc=example,dc=org'
GROUPS = 'ou=groups,dc=example,dc=org'
TEACHERS = f'cn=teachers,{GROUPS}'
ALICE_DN = f'uid=alice,{PEOPLE}'
POSIX = '(&(objectClass=posixGroup)(gidNumber=2000)(memberUid={login}))'


class FakeAttribute:
    def __init__(self, values):
        self.values = values


class FakeEntry:
    def __init__(self, dn, **attributes):
        self.entry_dn = dn
        self._attributes = attributes

    def __getitem__(self, name):
        return FakeAttribute(self._attributes[name])


class FakeConn:
    """Answers `search()` from a table {(base, filter): [entries]} and records every call."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []
        self.entries = []

    def search(self, base, ldap_filter, search_scope='SUBTREE', attributes=None):
        self.calls.append((base, ldap_filter, search_scope))
        self.entries = list(self.answers.get((base, ldap_filter), []))
        return bool(self.entries)

    def unbind(self):
        pass


def cfg(**over) -> LdapConfig:
    base = dict(uri='ldaps://ldap.example.org', search_base=PEOPLE, instructor_filter='', group_search_base='')
    base.update(over)
    return LdapConfig(**base)


class TestRoleTests:
    def test_nothing_configured_makes_no_search(self):
        conn = FakeConn()
        auth = L.LdapAuthenticator(cfg())
        assert not auth._is_instructor(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN))
        assert conn.calls == []

    def test_instructor_groups_through_member_of(self):
        auth = L.LdapAuthenticator(cfg(instructor_groups=[TEACHERS]))
        teacher = FakeEntry(ALICE_DN, memberOf=['cn=all,dc=x', TEACHERS.upper()])
        student = FakeEntry(ALICE_DN, memberOf=['cn=all,dc=x'])
        assert auth._is_instructor(FakeConn(), 'alice', ALICE_DN, teacher)
        assert not auth._is_instructor(FakeConn(), 'alice', ALICE_DN, student)
        assert 'memberOf' in auth._attributes()

    def test_group_filter_searches_the_group_base(self):
        conn = FakeConn({(GROUPS, f'(member={ALICE_DN})'): [FakeEntry(TEACHERS)]})
        auth = L.LdapAuthenticator(cfg(instructor_groups=[TEACHERS], group_filter='(member={dn})', group_search_base=GROUPS,
                                       instructor_group_filter=''))
        assert auth._is_instructor(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN))
        assert conn.calls == [(GROUPS, f'(member={ALICE_DN})', 'SUBTREE')]
        # without group_search_base the people base is searched, as before
        conn = FakeConn()
        auth = L.LdapAuthenticator(cfg(instructor_groups=[TEACHERS], group_filter='(member={dn})', instructor_group_filter=''))
        assert not auth._is_instructor(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN))
        assert conn.calls == [(PEOPLE, f'(member={ALICE_DN})', 'SUBTREE')]

    def test_instructor_filter_on_the_entry(self):
        conn = FakeConn({(ALICE_DN, '(gidNumber=2000)'): [FakeEntry(ALICE_DN)]})
        auth = L.LdapAuthenticator(cfg(instructor_filter='(gidNumber=2000)'))
        assert auth._is_instructor(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN))
        assert conn.calls == [(ALICE_DN, '(gidNumber=2000)', 'BASE')]
        bob = f'uid=bob,{PEOPLE}'
        assert not auth._is_instructor(conn, 'bob', bob, FakeEntry(bob))

    def test_group_membership_needs_the_group_base(self):
        conn = FakeConn({(GROUPS, POSIX.format(login='alice')): [FakeEntry(f'cn=profs,{GROUPS}')]})
        without = L.LdapAuthenticator(cfg(instructor_group_filter=POSIX))
        assert not without._is_instructor(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN)) and conn.calls == []
        auth = L.LdapAuthenticator(cfg(instructor_group_filter=POSIX, group_search_base=GROUPS))
        assert auth._is_instructor(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN))
        assert conn.calls == [(GROUPS, POSIX.format(login='alice'), 'SUBTREE')]
        assert not auth._is_instructor(conn, 'bob', f'uid=bob,{PEOPLE}', None)

    def test_placeholders_are_escaped(self):
        conn = FakeConn()
        L.group_found(conn, GROUPS, '(&(cn=teachers)(member={dn}))', login='a)b', dn='uid=a)b,' + PEOPLE)
        assert conn.calls == [(GROUPS, f'(&(cn=teachers)(member=uid=a\\29b,{PEOPLE}))', 'SUBTREE')]
        conn = FakeConn()
        L.group_found(conn, GROUPS, POSIX, login='a*b', dn='x')
        assert conn.calls[0][1] == POSIX.format(login='a\\2ab')
        assert not L.entry_matches(conn, ALICE_DN, '') and not L.group_found(conn, '', POSIX, login='a', dn='b')

    def test_defaults_are_the_site_values(self):
        d = LdapConfig()
        assert d.instructor_filter == '(gidNumber=2000)' and d.group_search_base == ''
        assert d.instructor_group_filter == POSIX

    def test_or_of_the_tests(self):
        conn = FakeConn({(GROUPS, POSIX.format(login='alice')): [FakeEntry(f'cn=profs,{GROUPS}')]})
        auth = L.LdapAuthenticator(cfg(instructor_groups=[TEACHERS], instructor_filter='(gidNumber=2000)',
                                       instructor_group_filter=POSIX, group_search_base=GROUPS))
        assert auth._is_instructor(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN, memberOf=[]))
        assert [c[0] for c in conn.calls] == [ALICE_DN, GROUPS]


class TestLdap3Calls:
    """The real ``_connect`` against a fake ldap3 module: what the library is handed."""

    @staticmethod
    def fake_ldap3(calls: list):
        class Server:
            def __init__(self, uri, **kw):
                calls.append(('server', uri, kw))

        class Connection:
            def __init__(self, server, **kw):
                calls.append(('connection', kw))

            def bind(self):
                return True

            def unbind(self):
                pass

        return types.SimpleNamespace(Server=Server, Connection=Connection, NONE='NO_INFO', AUTO_BIND_NONE='NONE')

    def test_timeouts_are_whole_seconds(self, monkeypatch):
        """ldap3 packs receive_timeout with struct.pack('LL', ...) on Linux: the float of
        parse_duration (10.0) made every bind fail with 'required argument is not an integer'
        (seen live on 2026-10-28: no group looked up, logged once per login)."""
        calls = []
        monkeypatch.setitem(sys.modules, 'ldap3', self.fake_ldap3(calls))
        for timeout, expected in ((10.0, 10), (2.5, 3), (0.2, 1), (7, 7)):
            calls.clear()
            conn = L.LdapRoleResolver(cfg(timeout=timeout))._connect('', '')
            assert conn is not None
            (_, uri, server_kw), (_, conn_kw) = calls
            assert uri == 'ldaps://ldap.example.org' and server_kw['use_ssl'] is True
            assert type(server_kw['connect_timeout']) is int and server_kw['connect_timeout'] == expected
            assert type(conn_kw['receive_timeout']) is int and conn_kw['receive_timeout'] == expected
            assert conn_kw['user'] is None and conn_kw['password'] is None       # anonymous bind
        calls.clear()
        L.LdapRoleResolver(cfg(uri='ldap://ldap.example.org'))._connect('cn=svc', 'pw')
        assert calls[0][2]['use_ssl'] is False and calls[1][1]['user'] == 'cn=svc'


class FakeDirectoryResolver(L.LdapRoleResolver):
    """The resolver with a fake directory: one connection per bind, searches from a table."""

    def __init__(self, config, answers, *, bind_ok=True):
        super().__init__(config)
        self.answers = answers
        self.bind_ok = bind_ok
        self.conns = []

    def _import_ldap3(self):
        return Exception

    def _connect(self, user, password):
        if not self.bind_ok:
            return None
        conn = FakeConn(self.answers)
        self.conns.append(conn)
        return conn


class TestGroup:
    def test_attribute_requested_and_read(self):
        auth = L.LdapAuthenticator(cfg(attr_group='departmentNumber'))
        assert auth._attributes() == ['cn', 'mail', 'departmentNumber']
        assert 'departmentNumber' not in L.LdapAuthenticator(cfg())._attributes()
        entry = FakeEntry(ALICE_DN, cn=['Alice'], mail=['a@x'], departmentNumber=[' INFO1 ', 'RT'])
        me = auth._identity(FakeConn(), 'alice', ALICE_DN, entry, 'fr')
        assert (me.login, me.fullname, me.email, me.group, me.role) == ('alice', 'Alice', 'a@x', 'INFO1', ROLE_STUDENT)
        assert auth._identity(FakeConn(), 'alice', ALICE_DN, FakeEntry(ALICE_DN, cn=['Alice'], mail=[]), 'fr').group == ''
        assert auth._identity(FakeConn(), 'alice', ALICE_DN, None, 'fr').group == ''
        # not configured: the attribute of the entry is not read
        assert L.LdapAuthenticator(cfg())._identity(FakeConn(), 'alice', ALICE_DN, entry, 'fr').group == ''


class TestRoleResolver:
    def test_search_mode(self):
        answers = {(PEOPLE, '(uid=alice)'): [FakeEntry(ALICE_DN, cn=['Alice'], mail=[], departmentNumber=['INFO1'])],
                   (ALICE_DN, '(gidNumber=2000)'): [FakeEntry(ALICE_DN)],
                   (PEOPLE, '(uid=bob)'): [FakeEntry(f'uid=bob,{PEOPLE}', cn=['Bob'], mail=[])]}
        r = FakeDirectoryResolver(cfg(instructor_filter='(gidNumber=2000)', attr_group='departmentNumber'), answers)
        assert r.resolve('alice') == L.DirectoryLookup(ROLE_INSTRUCTOR, 'INFO1')
        assert r.role_for('alice') == ROLE_INSTRUCTOR
        assert r.resolve('bob') == L.DirectoryLookup(ROLE_STUDENT, '')
        assert r.role_for('nobody') == ROLE_STUDENT
        assert r.resolve('../x') == L.DirectoryLookup()
        assert r.conns[0].calls[0] == (PEOPLE, '(uid=alice)', 'SUBTREE')

    def test_template_mode(self):
        answers = {(ALICE_DN, '(objectClass=*)'): [FakeEntry(ALICE_DN, cn=['Alice'], mail=[])],
                   (GROUPS, POSIX.format(login='alice')): [FakeEntry(f'cn=profs,{GROUPS}')]}
        r = FakeDirectoryResolver(cfg(search_base='', bind_dn_template='uid={login},' + PEOPLE,
                                      group_search_base=GROUPS, instructor_group_filter=POSIX), answers)
        assert r.role_for('alice') == ROLE_INSTRUCTOR
        assert r.conns[0].calls[0] == (ALICE_DN, '(objectClass=*)', 'BASE')

    def test_bind_failure(self):
        r = FakeDirectoryResolver(cfg(), {}, bind_ok=False)
        with pytest.raises(L.LdapError, match='service account'):
            r.role_for('alice')


class CountingResolver:
    def __init__(self, roles, fail=False, groups=None):
        self.roles, self.fail, self.calls, self.groups = roles, fail, [], groups or {}

    def resolve(self, login):
        self.calls.append(login)
        if self.fail:
            raise L.LdapError("ldap down")
        return L.DirectoryLookup(self.roles.get(login, ROLE_STUDENT), self.groups.get(login, ''))


class TestRoleCache:
    def test_one_lookup_until_the_ttl(self):
        now = [1000.0]
        resolver = CountingResolver({'prof': ROLE_INSTRUCTOR}, groups={'alice': 'INFO1'})
        cache = RoleCache(resolver, ttl=600, clock=lambda: now[0])

        async def go():
            assert (await cache.get('prof')).role == ROLE_INSTRUCTOR
            assert await cache.get('prof') == L.DirectoryLookup(ROLE_INSTRUCTOR, '')
            assert await cache.get('alice') == L.DirectoryLookup(ROLE_STUDENT, 'INFO1')
            roles = await asyncio.gather(*(cache.get('bob') for _ in range(5)))
            assert roles == [L.DirectoryLookup()] * 5
            assert resolver.calls == ['prof', 'alice', 'bob']
            now[0] += 601
            assert (await cache.get('prof')).role == ROLE_INSTRUCTOR
            assert resolver.calls == ['prof', 'alice', 'bob', 'prof']
            cache.forget('prof')
            await cache.get('prof')
            assert resolver.calls[-2:] == ['prof', 'prof']
        asyncio.run(go())

    def test_directory_failure_counts_as_a_student_for_a_while(self):
        now = [0.0]
        resolver = CountingResolver({'prof': ROLE_INSTRUCTOR}, fail=True)
        cache = RoleCache(resolver, ttl=600, negative_ttl=30, clock=lambda: now[0])

        async def go():
            assert await cache.get('prof') == L.DirectoryLookup(ROLE_STUDENT, '')
            assert (await cache.get('prof')).role == ROLE_STUDENT
            assert resolver.calls == ['prof']
            now[0] += 31
            resolver.fail = False
            assert (await cache.get('prof')).role == ROLE_INSTRUCTOR
            assert cache.lookups == 2
        asyncio.run(go())
