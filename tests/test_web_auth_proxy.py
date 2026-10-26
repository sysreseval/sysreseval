"""Tests of sreweb.portal.auth_proxy: the identity of a request rebuilt from the headers a
trusted reverse proxy sets (pure functions, no server; the portal side is in test_web_portal.py)."""
import pytest

from sreweb.config import ProxyAuthConfig
from sreweb.identity import IdentityError
from sreweb.portal import auth_proxy as P

TEACHERS = 'cn=teachers,ou=groups,dc=example,dc=org'


class Headers(dict):
    """A case-insensitive mapping, like the headers of an aiohttp request."""

    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


class TestHeaderValues:
    def test_decode(self):
        assert P.decode_header_value('Émile Dupont') == 'Émile Dupont'
        # aiohttp decodes the header bytes as UTF-8 with surrogateescape: a Latin-1 value keeps its bytes
        assert P.decode_header_value(b'\xc9mile'.decode('utf-8', 'surrogateescape')) == 'Émile'
        assert P.decode_header_value(b'\xc3\x89mile'.decode('utf-8', 'surrogateescape')) == 'Émile'
        assert P.decode_header_value('  a\x00b\x7fc\x85  ') == 'abc'
        assert P.decode_header_value('abcdef', 3) == 'abc' and P.decode_header_value('ab  cdef', 4) == 'ab'
        assert P.decode_header_value('(null)') == '' and P.decode_header_value(None) == ''
        assert P.decode_header_value('') == '' and P.decode_header_value(' (null) ') == ''

    def test_split_groups(self):
        assert P.split_groups(f'cn=a,dc=x; {TEACHERS} ;', ';') == ['cn=a,dc=x', TEACHERS]
        assert P.split_groups('', ';') == [] and P.split_groups(None, ';') == []
        assert P.split_groups('a,b', ',') == ['a', 'b']

    def test_is_instructor(self):
        assert P.is_instructor(['cn=a,dc=x', TEACHERS.upper()], [TEACHERS])
        assert not P.is_instructor(['cn=a,dc=x'], [TEACHERS])
        assert not P.is_instructor([TEACHERS], []) and not P.is_instructor([], [TEACHERS])
        assert not P.is_instructor(['cn=teachers'], [TEACHERS])             # whole values only
        assert P.is_instructor(['faculty'], ['staff', ' Faculty '])          # any attribute, not only DNs


class TestIdentityFromHeaders:
    def test_identity(self):
        cfg = ProxyAuthConfig(instructor_groups=[TEACHERS])
        headers = Headers({'x-remote-user': 'alice', 'X-Remote-Name': 'Émile Dupont',
                           'X-Remote-Email': 'alice@example.org', 'X-Remote-Groups': f'cn=students,dc=x; {TEACHERS}'})
        me = P.identity_from_headers(cfg, headers, 'fr')
        assert (me.login, me.fullname, me.email, me.role, me.language, me.anonymous) == \
            ('alice', 'Émile Dupont', 'alice@example.org', 'instructor', 'fr', False)
        student = P.identity_from_headers(cfg, Headers({'X-Remote-User': 'bob', 'X-Remote-Name': ''}), 'en')
        assert student.role == 'student' and student.fullname == '' and student.email == ''
        assert P.identity_from_headers(cfg, Headers({}), 'en') is None
        assert P.identity_from_headers(cfg, Headers({'X-Remote-User': ' '}), 'en') is None
        assert P.identity_from_headers(cfg, Headers({'X-Remote-User': '(null)'}), 'en') is None

    def test_other_header_names_and_caps(self):
        cfg = ProxyAuthConfig(header_login='Remote-User', header_fullname='Remote-Name', header_email='Remote-Email',
                              header_groups='Remote-Groups', groups_separator=',', instructor_groups=['teachers'])
        headers = Headers({'Remote-User': 'alice', 'Remote-Name': 'x' * 100, 'Remote-Email': 'y' * 300,
                           'Remote-Groups': 'students,teachers', 'X-Remote-User': 'ignored'})
        me = P.identity_from_headers(cfg, headers, 'en')
        assert me.login == 'alice' and me.role == 'instructor'
        assert len(me.fullname) == P.MAX_FULLNAME and len(me.email) == P.MAX_EMAIL

    def test_instructor_header(self):
        cfg = ProxyAuthConfig(instructor_header='X-Remote-Gid', instructor_values=['2000'])
        def role(**headers):
            return P.identity_from_headers(cfg, Headers({'X-Remote-User': 'zoe', **headers}), 'en').role
        assert role(**{'X-Remote-Gid': '2000'}) == 'instructor'
        assert role(**{'x-remote-gid': ' 2000 '}) == 'instructor'
        assert role(**{'X-Remote-Gid': '1000; 2000'}) == 'instructor'     # a multi-valued attribute
        assert role(**{'X-Remote-Gid': '1000'}) == 'student'
        assert role(**{'X-Remote-Gid': '(null)'}) == 'student' and role() == 'student'
        assert role(**{'X-Remote-Gid': '20001'}) == 'student'            # whole values only
        # OR with the groups header
        both = ProxyAuthConfig(instructor_groups=[TEACHERS], instructor_header='X-Remote-Gid', instructor_values=['2000'])
        me = P.identity_from_headers(both, Headers({'X-Remote-User': 'zoe', 'X-Remote-Groups': TEACHERS}), 'en')
        assert me.role == 'instructor'
        # the header is ignored when no instructor_header is configured
        assert P.identity_from_headers(ProxyAuthConfig(), Headers({'X-Remote-User': 'zoe', 'X-Remote-Gid': '2000'}), 'en').role == 'student'

    def test_group_header(self):
        cfg = ProxyAuthConfig(header_group='X-Remote-Group')
        def group(**headers):
            return P.identity_from_headers(cfg, Headers({'X-Remote-User': 'zoe', **headers}), 'en').group
        assert group(**{'X-Remote-Group': 'INFO1'}) == 'INFO1'
        assert group(**{'x-remote-group': ' Génie info '}) == 'Génie info'
        assert group(**{'X-Remote-Group': 'INFO1; RT'}) == 'INFO1'            # the first value of the attribute
        assert group(**{'X-Remote-Group': '(null)'}) == '' and group() == ''
        assert group(**{'X-Remote-Group': 'x' * 100}) == 'x' * 64
        # ignored when no header_group is configured
        assert P.identity_from_headers(ProxyAuthConfig(), Headers({'X-Remote-User': 'zoe', 'X-Remote-Group': 'INFO1'}), 'en').group == ''

    @pytest.mark.parametrize('login', ['../x', 'a b', 'alice@example.org', 'x' * 65, 'ali\x00ce!'])
    def test_bad_login_is_refused_not_truncated(self, login):
        with pytest.raises(IdentityError, match='X-Remote-User'):
            P.identity_from_headers(ProxyAuthConfig(), Headers({'X-Remote-User': login}), 'en')
