"""Tests of sreweb.portal.auth_ldap without a directory: the role tests on a duck-typed
connection, the proxy-mode role resolver, and the per-login role cache (sreweb.portal.roles)."""
import asyncio
import socket
import ssl
import sys
import threading
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
ADMINS = f'cn=sre-admins,{GROUPS}'
ADMIN_POSIX = '(&(objectClass=posixGroup)(cn=sre-admins)(memberUid={login}))'


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


class TestAdministratorTests:
    def test_nothing_configured_makes_no_search(self):
        conn = FakeConn()
        auth = L.LdapAuthenticator(cfg())
        assert not cfg().administrator_tests
        assert not auth._is_administrator(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN, memberOf=[ADMINS]))
        assert conn.calls == [] and 'memberOf' not in auth._attributes()

    def test_groups_through_member_of(self):
        auth = L.LdapAuthenticator(cfg(administrator_groups=[ADMINS]))
        assert auth.cfg.administrator_tests and 'memberOf' in auth._attributes()
        assert auth._is_administrator(FakeConn(), 'alice', ALICE_DN, FakeEntry(ALICE_DN, memberOf=[ADMINS.upper()]))
        assert not auth._is_administrator(FakeConn(), 'alice', ALICE_DN, FakeEntry(ALICE_DN, memberOf=[TEACHERS]))
        assert not auth._is_administrator(FakeConn(), 'alice', ALICE_DN, None)

    def test_groups_through_group_filter(self):
        conn = FakeConn({(GROUPS, f'(member={ALICE_DN})'): [FakeEntry(ADMINS)]})
        auth = L.LdapAuthenticator(cfg(administrator_groups=[ADMINS], group_filter='(member={dn})',
                                       group_search_base=GROUPS, instructor_group_filter=''))
        assert auth._is_administrator(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN))
        assert conn.calls == [(GROUPS, f'(member={ALICE_DN})', 'SUBTREE')]

    def test_group_filter_under_the_group_base(self):
        conn = FakeConn({(GROUPS, ADMIN_POSIX.format(login='alice')): [FakeEntry(ADMINS)]})
        auth = L.LdapAuthenticator(cfg(administrator_group_filter=ADMIN_POSIX, group_search_base=GROUPS))
        assert auth._is_administrator(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN))
        assert conn.calls == [(GROUPS, ADMIN_POSIX.format(login='alice'), 'SUBTREE')]
        assert not auth._is_administrator(conn, 'bob', f'uid=bob,{PEOPLE}', FakeEntry(f'uid=bob,{PEOPLE}'))
        without = L.LdapAuthenticator(cfg(administrator_group_filter=ADMIN_POSIX))     # no base: no test
        conn = FakeConn()
        assert not without._is_administrator(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN)) and conn.calls == []

    def test_identity_flags_the_instructors_only(self):
        answers = {(GROUPS, POSIX.format(login='alice')): [FakeEntry(f'cn=profs,{GROUPS}')],
                   (GROUPS, ADMIN_POSIX.format(login='alice')): [FakeEntry(ADMINS)],
                   (GROUPS, ADMIN_POSIX.format(login='bob')): [FakeEntry(ADMINS)]}
        auth = L.LdapAuthenticator(cfg(instructor_group_filter=POSIX, administrator_group_filter=ADMIN_POSIX,
                                       group_search_base=GROUPS))
        conn = FakeConn(answers)
        alice = auth._identity(conn, 'alice', ALICE_DN, FakeEntry(ALICE_DN, cn=['Alice'], mail=[]), 'fr')
        assert alice.is_instructor and alice.administrator
        conn = FakeConn(answers)
        bob = auth._identity(conn, 'bob', f'uid=bob,{PEOPLE}', FakeEntry(f'uid=bob,{PEOPLE}', cn=['Bob'], mail=[]), 'fr')
        assert bob.role == ROLE_STUDENT and not bob.administrator
        assert conn.calls == [(GROUPS, POSIX.format(login='bob'), 'SUBTREE')]      # the admin test is not run

    def test_resolver_reports_the_tests(self):
        answers = {(PEOPLE, '(uid=alice)'): [FakeEntry(ALICE_DN, cn=['Alice'], mail=[])],
                   (PEOPLE, '(uid=bob)'): [FakeEntry(f'uid=bob,{PEOPLE}', cn=['Bob'], mail=[])],
                   (PEOPLE, '(uid=carol)'): [FakeEntry(f'uid=carol,{PEOPLE}', cn=['Carol'], mail=[])],
                   (GROUPS, POSIX.format(login='alice')): [FakeEntry(f'cn=profs,{GROUPS}')],
                   (GROUPS, ADMIN_POSIX.format(login='alice')): [FakeEntry(ADMINS)],
                   (GROUPS, ADMIN_POSIX.format(login='bob')): [FakeEntry(ADMINS)]}
        r = FakeDirectoryResolver(cfg(instructor_group_filter=POSIX, administrator_group_filter=ADMIN_POSIX,
                                      group_search_base=GROUPS), answers)
        assert r.resolve('alice') == L.DirectoryLookup(ROLE_INSTRUCTOR, '', True, 'Alice')
        assert r.resolve('bob') == L.DirectoryLookup(ROLE_STUDENT, '', True, 'Bob')    # the portal gates it with the role
        assert r.resolve('carol') == L.DirectoryLookup(ROLE_STUDENT, '', False, 'Carol')
        plain = FakeDirectoryResolver(cfg(instructor_group_filter=POSIX, group_search_base=GROUPS), answers)
        assert plain.resolve('alice') == L.DirectoryLookup(ROLE_INSTRUCTOR, '', False, 'Alice')
        assert [c[1] for c in plain.conns[0].calls if 'sre-admins' in c[1]] == []


class TestLdap3Calls:
    """The real ``_connect`` against a fake ldap3 module: what the library is handed."""

    @staticmethod
    def fake_ldap3(calls: list, *, start_tls_result=True):
        class Tls:
            def __init__(self, **kw):
                self.kw = kw
                calls.append(('tls', kw))

        class Server:
            def __init__(self, uri, **kw):
                calls.append(('server', uri, kw))

        class Connection:
            def __init__(self, server, **kw):
                calls.append(('connection', kw))

            def start_tls(self):
                calls.append(('start_tls',))
                return start_tls_result

            def bind(self):
                calls.append(('bind',))
                return True

            def unbind(self):
                calls.append(('unbind',))

        return types.SimpleNamespace(Tls=Tls, Server=Server, Connection=Connection, NONE='NO_INFO', AUTO_BIND_NONE='NONE')

    @staticmethod
    def by_kind(calls: list) -> dict:
        return {c[0]: c for c in calls}

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
            _, uri, server_kw = self.by_kind(calls)['server']
            _, conn_kw = self.by_kind(calls)['connection']
            assert uri == 'ldaps://ldap.example.org' and server_kw['use_ssl'] is True
            assert type(server_kw['connect_timeout']) is int and server_kw['connect_timeout'] == expected
            assert type(conn_kw['receive_timeout']) is int and conn_kw['receive_timeout'] == expected
            assert conn_kw['user'] is None and conn_kw['password'] is None       # anonymous bind
        calls.clear()
        L.LdapRoleResolver(cfg(uri='ldap://ldap.example.org', allow_cleartext=True))._connect('cn=svc', 'pw')
        assert self.by_kind(calls)['server'][2]['use_ssl'] is False and self.by_kind(calls)['connection'][1]['user'] == 'cn=svc'

    def test_server_certificate_is_verified(self, monkeypatch):
        """Every Server gets a Tls requiring and verifying the certificate (ldap3's default
        ``Tls()`` is ``CERT_NONE``): the system store without ``tls_ca``, the configured bundle
        with it, the host of the uri as SNI; the ``ldap://`` uri of a StartTLS connection too."""
        calls = []
        monkeypatch.setitem(sys.modules, 'ldap3', self.fake_ldap3(calls))
        L.LdapRoleResolver(cfg())._connect('', '')
        kinds = self.by_kind(calls)
        tls = kinds['server'][2]['tls']
        assert tls.kw == {'validate': ssl.CERT_REQUIRED, 'ca_certs_file': None, 'sni': 'ldap.example.org'}
        calls.clear()
        L.LdapRoleResolver(cfg(uri='LDAPS://Ldap.Example.org:636/', tls_ca='/etc/sreweb/ldap-ca.pem'))._connect('', '')
        kinds = self.by_kind(calls)
        assert kinds['server'][2]['use_ssl'] is True
        assert kinds['server'][2]['tls'].kw == {'validate': ssl.CERT_REQUIRED, 'ca_certs_file': '/etc/sreweb/ldap-ca.pem',
                                                'sni': 'ldap.example.org'}
        calls.clear()
        L.LdapRoleResolver(cfg(uri='ldap://ldap.example.org', start_tls=True))._connect('', '')
        kinds = self.by_kind(calls)
        assert kinds['server'][2]['use_ssl'] is False
        assert kinds['server'][2]['tls'].kw['validate'] == ssl.CERT_REQUIRED

    def test_start_tls_is_enforced(self, monkeypatch):
        """With ``start_tls`` the bind follows a successful StartTLS; a StartTLS the library
        reports as not started (``False``: a server that is TLS already, operations in progress)
        aborts the login before anything is sent in clear.  A refusal or a certificate failure
        raise inside ldap3 (``LDAPStartTLSError``, an ``LDAPException`` the callers turn into
        ``LdapError``)."""
        calls = []
        monkeypatch.setitem(sys.modules, 'ldap3', self.fake_ldap3(calls))
        assert L.LdapRoleResolver(cfg(uri='ldap://ldap.example.org', start_tls=True))._connect('cn=svc', 'pw') is not None
        assert [c[0] for c in calls if c[0] in ('start_tls', 'bind', 'unbind')] == ['start_tls', 'bind']
        calls.clear()
        L.LdapRoleResolver(cfg())._connect('cn=svc', 'pw')
        assert [c[0] for c in calls if c[0] in ('start_tls', 'bind')] == ['bind']       # ldaps://: no StartTLS
        calls.clear()
        monkeypatch.setitem(sys.modules, 'ldap3', self.fake_ldap3(calls, start_tls_result=False))
        with pytest.raises(L.LdapError, match='did not start TLS'):
            L.LdapRoleResolver(cfg(uri='ldap://ldap.example.org', start_tls=True))._connect('cn=svc', 'pw')
        assert [c[0] for c in calls if c[0] in ('start_tls', 'bind', 'unbind')] == ['start_tls', 'unbind']

    def test_uri_host(self):
        assert L._uri_host('ldaps://LDAP.Example.org:636/') == 'ldap.example.org'
        assert L._uri_host('ldap://ldap.example.org') == 'ldap.example.org'
        assert L._uri_host('ldaps://[::1]:636') == '::1'
        assert L._uri_host('ldap.example.org') is None and L._uri_host('') is None


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
        assert r.resolve('alice') == L.DirectoryLookup(ROLE_INSTRUCTOR, 'INFO1', fullname='Alice')   # the Watch page
        assert r.role_for('alice') == ROLE_INSTRUCTOR
        assert r.resolve('bob') == L.DirectoryLookup(ROLE_STUDENT, '', fullname='Bob')
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


class TlsListener(threading.Thread):
    """A TLS server of this process that speaks no LDAP, for one connection: with *starttls* it
    first answers the StartTLS extended request in clear (success), then wraps the socket.  It
    records what the client did: ``handshake_failed`` (the client refused the certificate),
    ``no_request`` (handshake done, the client sent nothing: the name check failed on its side)
    or ``request`` (an LDAP message arrived over TLS: the bind request)."""

    def __init__(self, cert_file: str, key_file: str, *, starttls: bool = False):
        super().__init__(daemon=True)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_file, key_file)
        self.starttls = starttls
        self.sock = socket.create_server(('127.0.0.1', 0))
        self.sock.settimeout(10)
        self.port = self.sock.getsockname()[1]
        self.events = []

    def run(self):
        try:
            conn, _ = self.sock.accept()
        except TimeoutError:
            self.events.append('no_connection')
            return
        finally:
            self.sock.close()
        conn.settimeout(10)
        try:
            if self.starttls:
                request = conn.recv(4096)                     # the ExtendedRequest 1.3.6.1.4.1.1466.20037
                self.events.append('starttls_request' if b'1.3.6.1.4.1.1466.20037' in request else 'unexpected')
                msg_id = request[4] if request[:1] == b'\x30' and request[2:4] == b'\x02\x01' else 1
                # ExtendedResponse: resultCode success, empty matchedDN and diagnosticMessage
                conn.sendall(bytes([0x30, 0x0c, 0x02, 0x01, msg_id, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]))
            try:
                tls = self.ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                self.events.append('handshake_failed')
                return
            try:
                data = tls.recv(4096)
            except (ssl.SSLError, OSError):
                data = b''
            self.events.append('request' if data[:1] == b'\x30' else 'no_request')
            tls.close()
        finally:
            conn.close()


@pytest.fixture(scope='module')
def pki(tmp_path_factory):
    """A CA, a server certificate for ``localhost`` signed by it, and an unrelated CA, as PEM
    files (``lib/tls.py`` builds them in Python)."""
    from tls import generate_ca_pem, generate_server_cert_pem
    d = tmp_path_factory.mktemp('ldap-pki')
    ca_pem, ca_key = generate_ca_pem('SRE test LDAP CA')
    other_ca, _ = generate_ca_pem('Another CA')
    cert, key = generate_server_cert_pem(ca_pem, ca_key, 'localhost')
    files = {'ca': ca_pem, 'other_ca': other_ca, 'cert': cert, 'key': key}
    return {name: str((d / f'{name}.pem').write_text(text) and d / f'{name}.pem') for name, text in files.items()}


class TestCertificateValidation:
    """The real ldap3 of the venv against :class:`TlsListener`: what the ``Tls`` object buys.
    The listener answers no bind, so the client always ends with ``LdapError``; the proof is on
    the server side: an unknown CA aborts the handshake, a certificate for another name is
    accepted by OpenSSL but refused by ldap3's name check before anything is sent, and only the
    right CA + the right name let the bind request through — over ``ldaps://`` and after a
    StartTLS alike."""

    @staticmethod
    def resolver(port: int, *, host='localhost', tls_ca='', start_tls=False):
        pytest.importorskip('ldap3')
        scheme = 'ldap' if start_tls else 'ldaps'
        return L.LdapRoleResolver(cfg(uri=f'{scheme}://{host}:{port}', tls_ca=tls_ca, start_tls=start_tls, timeout=3))

    def run_case(self, pki, *, starttls=False, **over) -> tuple[list, str]:
        """``(what the server saw, the client's error)``.  The error is kept as a string only:
        its traceback references the wrapped socket, which ldap3 leaves open after a name-check
        failure until the exception is collected (right after the login handler drops it)."""
        server = TlsListener(pki['cert'], pki['key'], starttls=starttls)
        server.start()
        try:
            self.resolver(server.port, start_tls=starttls, **over).resolve('alice')
        except L.LdapError as e:
            error = str(e)
        else:
            pytest.fail("the bind went through without a server")
        server.join(timeout=15)
        assert not server.is_alive()
        return server.events, error

    def test_unknown_ca_is_refused(self, pki):
        events, error = self.run_case(pki, tls_ca=pki['other_ca'])
        assert events == ['handshake_failed'] and 'CERTIFICATE_VERIFY_FAILED' in error
        events, error = self.run_case(pki)                     # the system store: not our CA either
        assert events == ['handshake_failed'] and 'CERTIFICATE_VERIFY_FAILED' in error

    def test_name_mismatch_is_refused(self, pki):
        """The certificate names ``localhost``: the handshake completes (OpenSSL trusts the CA)
        but ldap3 checks the host of the uri against the names of the certificate."""
        events, error = self.run_case(pki, host='127.0.0.1', tls_ca=pki['ca'])
        assert events == ['no_request'] and "doesn't match any name" in error

    def test_right_ca_and_name_let_the_bind_through(self, pki):
        events, error = self.run_case(pki, tls_ca=pki['ca'])
        assert events == ['request'] and 'certificate' not in error.lower()

    def test_start_tls_verifies_the_same_way(self, pki):
        events, error = self.run_case(pki, starttls=True, tls_ca=pki['ca'])
        assert events == ['starttls_request', 'request'] and 'certificate' not in error.lower()
        events, error = self.run_case(pki, starttls=True, tls_ca=pki['other_ca'])
        assert events == ['starttls_request', 'handshake_failed'] and 'CERTIFICATE_VERIFY_FAILED' in error
        events, error = self.run_case(pki, starttls=True, host='127.0.0.1', tls_ca=pki['ca'])
        assert events == ['starttls_request', 'no_request'] and "doesn't match any name" in error
