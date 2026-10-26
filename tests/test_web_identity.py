"""Tests of sreweb.identity: the identity of a web user and its transport in headers."""
import pytest

from SRE import access
from sreweb import identity as ident
from sreweb.identity import Identity, IdentityError, encode_header_text, decode_header_text


def test_login_regex_is_the_one_of_sre_access():
    assert ident.VALID_LOGIN.pattern == access._VALID_USERNAME.pattern


class TestIdentity:
    def test_round_trip_through_headers(self):
        me = Identity(login='dupont', fullname='Émile Dupont', email='e.dupont@example.org', role='instructor',
                      language='fr', anonymous=False, view='instructor', group='Génie info')
        headers = me.headers()
        assert headers[ident.HEADER_LOGIN] == 'dupont' and headers[ident.HEADER_VIEW] == 'instructor'
        assert headers[ident.HEADER_FULLNAME] == encode_header_text('Émile Dupont')
        assert decode_header_text(headers[ident.HEADER_FULLNAME]) == 'Émile Dupont'
        assert decode_header_text(headers[ident.HEADER_GROUP]) == 'Génie info'
        assert Identity.from_headers(headers) == me
        assert all(v.isascii() for v in headers.values())
        # an agent fed by a portal without the group header (an older version) sees no group
        assert Identity.from_headers({k: v for k, v in headers.items() if k != ident.HEADER_GROUP}).group == ''

    def test_defaults_and_dict(self):
        me = Identity.from_headers({ident.HEADER_LOGIN: 'guest-1a2b3c4d', ident.HEADER_ANONYMOUS: '1'})
        assert me.anonymous and me.role == 'student' and me.view == 'student' and me.language == 'en'
        assert me.to_dict() == {'login': 'guest-1a2b3c4d', 'fullname': '', 'email': '', 'role': 'student',
                                'language': 'en', 'anonymous': True, 'group': ''}
        assert not me.is_instructor and not me.instructor_view

    def test_clean_group(self):
        assert ident.clean_group(' INFO1 ') == 'INFO1' and ident.clean_group(None) == ''
        assert ident.clean_group('a\x00b\x7fc\x85 ') == 'abc'
        assert ident.clean_group('x' * 100) == 'x' * ident.MAX_GROUP_LENGTH
        assert ident.clean_group('y' * 63 + '  z') == 'y' * 63      # the cut falls on a blank

    def test_case_insensitive_mapping(self):
        CIMultiDict = pytest.importorskip('multidict').CIMultiDict   # comes with aiohttp
        headers = CIMultiDict({'x-sre-login': 'alice', 'x-sre-role': 'student'})
        assert Identity.from_headers(headers).login == 'alice'

    @pytest.mark.parametrize('kwargs', [
        dict(login=''), dict(login='../x'), dict(login='a b'), dict(login='x' * 65), dict(login='é'),
        dict(login='ok', role='root'), dict(login='ok', view='instructor'),   # student with the instructor view
        dict(login='ok', language='french!'),
    ])
    def test_refused(self, kwargs):
        with pytest.raises(IdentityError):
            Identity(**kwargs)

    def test_missing_or_bad_headers(self):
        with pytest.raises(IdentityError, match='missing'):
            Identity.from_headers({})
        with pytest.raises(IdentityError):
            Identity.from_headers({ident.HEADER_LOGIN: 'ok', ident.HEADER_FULLNAME: '%%%'})

    def test_with_view(self):
        me = Identity(login='prof', role='instructor')
        assert me.with_view('instructor').instructor_view and not me.instructor_view
