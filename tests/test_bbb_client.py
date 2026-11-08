"""Tests of ``sreweb.portal.bbb``: the signed calls of the BigBlueButton API (the pure helpers,
then the client against the fake server of ``fake_bbb.py``)."""
import asyncio
import hashlib
import urllib.parse

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.portal import bbb as B                 # noqa: E402
from fake_bbb import FakeBbbServer                # noqa: E402

API = 'https://bbb.example.org/bigbluebutton/api/'


def run(coro):
    return asyncio.run(coro)


class TestHelpers:
    def test_encode_query(self):
        """Insertion order, the empty and None values dropped, booleans lower-cased, the
        encoding of urlencode (a space as +)."""
        query = B.encode_query([('name', 'Test Meeting'), ('meetingID', 'abc-1'), ('record', False), ('welcome', ''),
                                ('duration', None), ('n', 3), ('muteOnStart', True)])
        assert query == 'name=Test+Meeting&meetingID=abc-1&record=false&n=3&muteOnStart=true'
        assert B.encode_query({'fullName': 'Zoë & "Co"', 'x': 'a=b'}) == 'fullName=Zo%C3%AB+%26+%22Co%22&x=a%3Db'
        assert B.encode_query([]) == ''

    @pytest.mark.parametrize('algorithm', ['sha1', 'sha256', 'sha512'])
    def test_checksum(self, algorithm):
        query = 'name=Test+Meeting&meetingID=abc123'
        expected = hashlib.new(algorithm, ('create' + query + 'sekret').encode()).hexdigest()
        assert B.checksum('create', query, 'sekret', algorithm) == expected

    def test_unknown_algorithm(self):
        with pytest.raises(ValueError, match='md5'):
            B.checksum('create', '', 's', 'md5')
        with pytest.raises(ValueError, match='md5'):
            B.BbbClient(API, 's', 'md5')

    def test_signed_url(self):
        url = B.signed_url(API, 'create', [('name', 'Test Meeting'), ('meetingID', 'abc123')], 'sekret')
        base, query = url.split('?')
        assert base == API + 'create'
        signed, digest = query.rsplit('&checksum=', 1)
        assert signed == 'name=Test+Meeting&meetingID=abc123'
        assert digest == hashlib.sha1(('create' + signed + 'sekret').encode()).hexdigest()
        # no parameter: the checksum alone
        assert B.signed_url(API, 'getMeetings', [], 's') == API + 'getMeetings?checksum=' + hashlib.sha1(b'getMeetingss').hexdigest()
        # another algorithm
        url = B.signed_url(API, 'end', {'meetingID': 'm'}, 's', 'sha256')
        assert url.endswith('checksum=' + hashlib.sha256(b'endmeetingID=ms').hexdigest())

    def test_parse_response(self):
        ok = B.parse_response(b'<response><returncode>SUCCESS</returncode><meetingID>m1</meetingID>'
                              b'<createTime> 1700000000000 </createTime><messageKey>duplicateWarning</messageKey>'
                              b'<attendees><attendee><userID>alice</userID><fullName>Alice A</fullName><role>VIEWER</role>'
                              b'</attendee></attendees></response>')
        assert ok['meetingID'] == 'm1' and ok['createTime'] == '1700000000000' and ok['messageKey'] == 'duplicateWarning'
        assert ok['attendees'] == [{'user_id': 'alice', 'fullname': 'Alice A', 'role': 'VIEWER'}]
        with pytest.raises(B.BbbError) as e:
            B.parse_response(b'<response><returncode>FAILED</returncode><messageKey>checksumError</messageKey>'
                             b'<message>Checksums do not match</message></response>')
        assert e.value.message_key == 'checksumError' and 'Checksums' in e.value.message and 'checksumError' in str(e.value)
        for garbage in (b'<html><body>502 Bad Gateway</body></html>', b'', b'<foo/>', b'<response><x>1</x></response>',
                        b'not xml at all'):
            with pytest.raises(B.BbbUnavailable):
                B.parse_response(garbage)

    def test_meeting_info_of(self):
        info = B.meeting_info_of({'running': 'true', 'hasUserJoined': 'true', 'hasBeenForciblyEnded': 'false',
                                  'participantCount': '3', 'moderatorCount': '1', 'createTime': '1700000000000',
                                  'attendees': [{'user_id': 'a', 'fullname': 'A', 'role': 'MODERATOR'}]})
        assert info.running and info.has_user_joined and not info.has_been_forcibly_ended
        assert (info.participant_count, info.moderator_count, info.create_time) == (3, 1, 1700000000000)
        assert info.attendees == ({'user_id': 'a', 'fullname': 'A', 'role': 'MODERATOR'},)
        empty = B.meeting_info_of({'running': 'false'})
        assert not empty.running and empty.participant_count == 0 and empty.create_time is None and empty.attendees == ()

    def test_join_url(self):
        client = B.BbbClient(API, 'sekret')
        url = client.join_url('sre-1', fullname='Alice A', role=B.ROLE_VIEWER, user_id='alice', password='pw',
                              create_time=1700000000000, userdata={'bbb_skip_check_audio': True, 'bbb_listen_only_mode': False,
                                                                   'bbb_client_title': 'SRE'})
        parsed = urllib.parse.urlsplit(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        assert parsed.scheme == 'https' and parsed.netloc == 'bbb.example.org' and parsed.path == '/bigbluebutton/api/join'
        assert params['fullName'] == 'Alice A' and params['meetingID'] == 'sre-1' and params['role'] == 'VIEWER'
        assert params['password'] == 'pw' and params['createTime'] == '1700000000000' and params['userID'] == 'alice'
        assert params['redirect'] == 'true'
        assert params['userdata-bbb_skip_check_audio'] == 'true' and params['userdata-bbb_listen_only_mode'] == 'false'
        assert params['userdata-bbb_client_title'] == 'SRE'
        signed = parsed.query.rsplit('&checksum=', 1)[0]
        assert params['checksum'] == hashlib.sha1(('join' + signed + 'sekret').encode()).hexdigest()
        assert list(params)[-1] == 'checksum'
        # no create time, no password, no userdata: the parameters are left out
        url = client.join_url('sre-1', fullname='Bob', role=B.ROLE_MODERATOR, user_id='bob')
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        assert 'createTime' not in params and 'password' not in params and params['role'] == 'MODERATOR'
        # the API base is given a trailing slash when it lacks one
        assert B.BbbClient(API.rstrip('/'), 's').api_url == API


class TestClientAgainstTheFakeServer:
    def test_create_info_end(self):
        async def go():
            fake = await FakeBbbServer(secret='sekret').start()
            client = B.BbbClient(fake.url, 'sekret')
            try:
                created = await client.create('sre-abc', 'Room 1', moderator_pw='mod', attendee_pw='att', welcome='Hi',
                                              logout_url='https://sre.example.org/webconf/left?id=x', record=False,
                                              duration=0, mute_on_start=True, max_participants=0, meta={'sre-room': 'x'})
                assert created['create_time'] > 0 and not created['duplicate'] and created['internal_meeting_id']
                again = await client.create('sre-abc', 'Room 1', moderator_pw='mod', attendee_pw='att')
                assert again['duplicate'] and again['create_time'] == created['create_time']
                call, params = fake.calls[0]
                assert call == 'create' and params['name'] == 'Room 1' and params['muteOnStart'] == 'true'
                assert params['meta_sre-room'] == 'x' and params['record'] == 'false' and params['welcome'] == 'Hi'
                assert 'duration' not in params and 'maxParticipants' not in params
                assert params['logoutURL'] == 'https://sre.example.org/webconf/left?id=x'
                info = await client.meeting_info('sre-abc')
                assert info is not None and not info.running and not info.has_user_joined
                assert info.participant_count == 0 and info.create_time == created['create_time']
                assert not await client.is_running('sre-abc')
                fake.join_as('sre-abc', 'alice', 'Alice A', 'VIEWER')
                info = await client.meeting_info('sre-abc')
                assert info.running and info.has_user_joined and info.participant_count == 1 and info.moderator_count == 0
                assert info.attendees == ({'user_id': 'alice', 'fullname': 'Alice A', 'role': 'VIEWER'},)
                assert await client.is_running('sre-abc')
                assert await client.meeting_info('sre-none') is None
                await client.end('sre-abc', 'mod')
                assert fake.calls[-1][0] == 'end' and fake.calls[-1][1]['password'] == 'mod'
                assert await client.meeting_info('sre-abc') is None
                # ending a meeting that is gone is a BbbError (the registry suppresses it)
                with pytest.raises(B.BbbError) as e:
                    await client.end('sre-abc', 'mod')
                assert e.value.message_key == 'notFound'
            finally:
                await client.close()
                await fake.close()
        run(go())

    def test_join_redirects_to_the_client(self):
        async def go():
            fake = await FakeBbbServer().start()
            client = B.BbbClient(fake.url, 'sekret')
            try:
                created = await client.create('sre-j', 'Room J', moderator_pw='mod', attendee_pw='att',
                                              logout_url='https://sre.example.org/webconf/left?id=j')
                url = client.join_url('sre-j', fullname='Zoë ~ 100% "A"', role=B.ROLE_MODERATOR, user_id='zoe',
                                      password='mod', create_time=created['create_time'])
                client.open()
                async with client._session.get(aiohttp.client.URL(url, encoded=True), allow_redirects=False) as resp:
                    assert resp.status == 302, await resp.text()
                    location = resp.headers['Location']
                assert location.startswith(fake.origin + '/html5client/join?')
                assert fake.meetings['sre-j'].attendees == [{'user_id': 'zoe', 'fullname': 'Zoë ~ 100% "A"', 'role': 'MODERATOR'}]
                # the client page: the name of the meeting and the Leave link to the logoutURL
                async with client._session.get(location) as resp:
                    page = await resp.text()
                assert 'Room J' in page and 'href="https://sre.example.org/webconf/left?id=j"' in page
                # a stale createTime is refused
                stale = client.join_url('sre-j', fullname='Bob', role=B.ROLE_VIEWER, user_id='bob', create_time=1)
                async with client._session.get(aiohttp.client.URL(stale, encoded=True), allow_redirects=False) as resp:
                    assert resp.status == 200 and 'mismatchCreateTimeParam' in await resp.text()
            finally:
                await client.close()
                await fake.close()
        run(go())

    def test_errors(self):
        async def go():
            fake = await FakeBbbServer(secret='sekret').start()
            try:
                wrong = B.BbbClient(fake.url, 'wrong')
                with pytest.raises(B.BbbError) as e:
                    await wrong.create('m', 'Name', moderator_pw='a', attendee_pw='b')
                assert e.value.message_key == 'checksumError'
                await wrong.close()
                client = B.BbbClient(fake.url, 'sekret', timeout=0.3)
                fake.fail_next.append(('getMeetingInfo', 502))
                with pytest.raises(B.BbbUnavailable, match='HTTP 502'):
                    await client.meeting_info('m')
                fake.fail_next.append(('*', b'<html><body>nginx</body></html>'))
                with pytest.raises(B.BbbUnavailable, match='not an API answer'):
                    await client.meeting_info('m')
                fake.delay = 1.0
                with pytest.raises(B.BbbUnavailable, match='no answer'):
                    await client.meeting_info('m')
                fake.delay = 0.0
                await client.close()
                refused = B.BbbClient('http://127.0.0.1:9/bigbluebutton/api/', 'sekret', timeout=0.5)
                with pytest.raises(B.BbbUnavailable):
                    await refused.meeting_info('m')
                await refused.close()
            finally:
                await fake.close()
        run(go())

    def test_the_signed_string_is_the_sent_string(self):
        """yarl would re-encode %7E as ~ and the checksum would no longer match: the URL is
        handed to aiohttp as encoded."""
        async def go():
            fake = await FakeBbbServer().start()
            client = B.BbbClient(fake.url, 'sekret')
            try:
                created = await client.create('sre-e', 'Tilde ~ and %7E and 100%', moderator_pw='m', attendee_pw='a',
                                              welcome='<b>Hi</b> & welcome', meta={'sre-owner': 'a~b'})
                assert created['create_time'] > 0
                assert fake.meetings['sre-e'].name == 'Tilde ~ and %7E and 100%'
                assert fake.calls[0][1]['welcome'] == '<b>Hi</b> & welcome' and fake.calls[0][1]['meta_sre-owner'] == 'a~b'
            finally:
                await client.close()
                await fake.close()
        run(go())
