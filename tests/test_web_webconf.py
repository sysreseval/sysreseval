"""Tests of the web conferences of the web front-end: an instructor opens a BigBlueButton room
and puts students in it.  The registry of ``sreweb.portal.webconf`` alone (a fake BBB client,
fake presence sockets, a fixed clock), then a real portal (``test_web_portal.Harness`` in proxy
mode) in front of the fake BBB server of ``fake_bbb.py``."""
import asyncio
import urllib.parse

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")
import yarl                                                   # noqa: E402

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
import test_web_presentation as T                             # noqa: E402  (the fake sockets, the identities)
from fake_bbb import FakeBbbServer                            # noqa: E402
from sreweb.config import BbbConfig                           # noqa: E402
from sreweb.identity import Identity                          # noqa: E402
from sreweb.portal import bbb as B, presentation as PR, webconf as W   # noqa: E402
from sreweb.portal.accesslog import parse_line                # noqa: E402

ALICE, BOB, CAROL, DAVE, PROF, PROF2 = T.ALICE, T.BOB, T.CAROL, T.DAVE, T.PROF, T.PROF2
PROF_FR = Identity(login='prof', fullname='Pr. Of', role='instructor', language='fr')
PROF_INFO1 = Identity(login='prof3', role='instructor', group='INFO1')
run = T.run


def info(*, running=False, joined=False, ended=False, attendees=(), create_time=1001) -> B.MeetingInfo:
    return B.MeetingInfo(running, joined, ended, len(attendees), sum(a['role'] == 'MODERATOR' for a in attendees),
                         create_time, tuple(attendees))


class FakeBbb:
    """An in-process double of ``bbb.BbbClient``: the calls recorded, the answers scripted."""
    api_url = 'https://bbb.example.org/bigbluebutton/api/'
    algorithm = 'sha1'

    def __init__(self):
        self.created = []        # (meeting_id, name, kwargs)
        self.ended = []          # (meeting_id, password)
        self.infos = {}          # meeting_id -> MeetingInfo | None | an exception: what getMeetingInfo answers
        self.info_calls = []
        self.create_time = 1000
        self.fail_create = None  # an exception create raises
        self.fail_end = None     # an exception end raises
        self.hang_end = False    # an end that never answers

    async def create(self, meeting_id, name, **kw):
        if self.fail_create is not None:
            raise self.fail_create
        self.create_time += 1
        self.created.append((meeting_id, name, kw))
        self.infos[meeting_id] = info(create_time=self.create_time)
        return {'create_time': self.create_time, 'internal_meeting_id': 'int-' + meeting_id, 'duplicate': False}

    async def end(self, meeting_id, password=''):
        if self.hang_end:
            await asyncio.sleep(3600)
        if self.fail_end is not None:
            raise self.fail_end
        self.ended.append((meeting_id, password))
        self.infos[meeting_id] = None

    async def meeting_info(self, meeting_id):
        self.info_calls.append(meeting_id)
        answer = self.infos.get(meeting_id)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def join_url(self, meeting_id, *, fullname, role, user_id, password='', create_time=None, userdata=None):
        return (f"bbb://{meeting_id}?role={role}&user={user_id}&name={fullname}&ct={create_time}&pw={password}"
                f"&ud={sorted((userdata or {}).items())}")


def registries(now=1000.0, bbb=None, cfg=None):
    clock = T.Clock(now)
    presence = PR.Presence(clock=clock)
    bbb = bbb if bbb is not None else FakeBbb()
    cfg = cfg if cfg is not None else BbbConfig(url='https://bbb.example.org/', secret='s',
                                                userdata={'bbb_skip_check_audio': True}, poll_interval=10.0)
    return clock, presence, bbb, W.Webconfs(presence, bbb, clock=clock, cfg=cfg, public_url='https://sre.example.org/',
                                            languages=['en', 'fr'])


def started(room: W.Room, role: str) -> dict:
    return {'t': 'webconf', 'id': room.id, 'name': room.name, 'owner': {'login': room.owner.login,
                                                                        'fullname': room.owner.fullname},
            'role': role, 'join_url': f'/api/webconfs/{room.id}/join'}


def ended(room: W.Room) -> dict:
    return {'t': 'webconf', 'id': room.id, 'ended': True}


def connect(presence, *identities) -> list:
    watchers = []
    for identity in identities:
        watcher = T.FakeWatcher()
        presence.add(identity, '/projects', watcher)
        watchers.append(watcher)
    return watchers


# ---------------------------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------------------------

class TestWebconfsRegistry:
    def test_start_creates_the_meeting_and_tells_owner_and_members(self):
        clock, presence, bbb, w = registries()
        wp, wa, wc = connect(presence, PROF_FR, ALICE, CAROL)
        w.cfg.welcome = {'fr': 'Bienvenue', 'en': 'Welcome'}
        w.cfg.record = True
        w.cfg.duration = 7200
        room = run(w.start(PROF_FR, ' Room  1 ', ({'alice', 'prof'}, {'INFO2'}), request_origin='http://ignored'))
        assert room.name == 'Room 1' and room.logins == {'alice'} and room.groups == {'department:INFO2'}
        assert room.meeting_id.startswith('sre-') and room.create_time == 1001 and room.present and not room.served_join
        meeting_id, name, kw = bbb.created[0]
        assert (meeting_id, name) == (room.meeting_id, 'Room 1')
        assert kw['logout_url'] == f'https://sre.example.org/webconf/left?id={room.id}'    # public_url, not the request
        assert kw['welcome'] == 'Bienvenue' and kw['record'] and kw['duration'] == 120 and not kw['mute_on_start']
        assert kw['meta'] == {'sre-room': room.id, 'sre-owner': 'prof'}
        assert (kw['moderator_pw'], kw['attendee_pw']) == (room.moderator_pw, room.attendee_pw) and room.moderator_pw != room.attendee_pw
        assert wp.sent == [started(room, 'moderator')] and wa.sent == [started(room, 'viewer')] and wc.sent == [started(room, 'viewer')]
        assert w.of_participant(ALICE) is room and w.of_participant(CAROL) is room and w.of_participant(BOB) is None
        assert w.preferred['prof'] == room.id and w.shown == {'prof': room.id, 'alice': room.id, 'carol': room.id}
        d = room.to_dict(presence)
        assert d['name'] == 'Room 1' and d['owner'] == {'login': 'prof', 'fullname': 'Pr. Of'} and d['count'] == 3
        assert d['audience'] == {'logins': ['alice'], 'groups': ['department:INFO2']} and d['attending'] == []
        assert [c['login'] for c in d['connected']] == ['alice', 'carol', 'prof'] and d['connected'][0]['fullname'] == 'Alice A'
        assert not d['running'] and d['participants'] == [] and d['meeting_id'] == room.meeting_id
        assert w.listing() == [room] and 'bbb.example.org' in w.describe()
        # without public_url the request origin names the portal; without either no logoutURL
        w.public_url = ''
        other = run(w.start(PROF2, 'Other', (set(), set()), request_origin='http://sre.lan:8450/'))
        assert bbb.created[1][2]['logout_url'] == f'http://sre.lan:8450/webconf/left?id={other.id}'
        third = run(w.start(PROF2, 'Third', (set(), set())))
        assert bbb.created[2][2]['logout_url'] == '' and bbb.created[2][2]['welcome'] == 'Welcome'

    def test_name_and_limits_are_checked(self, monkeypatch):
        assert W.check_name('  Salle   de  TP ') == 'Salle de TP'
        for bad in ('x', 'y' * 65, 3, None, 'a\x00b', ''):
            with pytest.raises(ValueError):
                W.check_name(bad)
        clock, presence, bbb, w = registries()
        with pytest.raises(ValueError, match='name'):
            run(w.start(PROF, 'x', (set(), set())))
        assert bbb.created == [] and w.listing() == []
        monkeypatch.setattr(W, 'MAX_ROOMS', 2)
        run(w.start(PROF, 'One', (set(), set())))
        run(w.start(PROF, 'Two', (set(), set())))
        with pytest.raises(ValueError, match='too many'):
            run(w.start(PROF, 'Three', (set(), set())))
        assert len(w.listing()) == 2
        # the registry of a portal without [bbb]
        off = W.Webconfs(presence, None)
        assert not off.enabled and 'not configured' in off.describe()
        with pytest.raises(W.WebconfDisabled):
            run(off.start(PROF, 'Room', (set(), set())))
        run(off.tick())
        run(off.shutdown())
        off.start_loop()
        assert off._task is None

    def test_bbb_refusal_or_outage_leaves_no_room(self):
        clock, presence, bbb, w = registries()
        (wa,) = connect(presence, ALICE)
        bbb.fail_create = B.BbbError('maxParticipantsReached', 'no')
        with pytest.raises(B.BbbError):
            run(w.start(PROF, 'Room', ({'alice'}, set())))
        bbb.fail_create = B.BbbUnavailable('down')
        with pytest.raises(B.BbbUnavailable):
            run(w.start(PROF, 'Room', ({'alice'}, set())))
        assert w.listing() == [] and wa.sent == [] and w.preferred == {} and w.shown == {}

    def test_newest_room_wins_and_the_student_falls_back(self):
        clock, presence, bbb, w = registries()
        (wa,) = connect(presence, ALICE)
        r1 = run(w.start(PROF, 'R1', ({'alice'}, set())))
        clock.now += 1
        r2 = run(w.start(PROF2, 'R2', ({'alice'}, set())))
        assert wa.sent == [started(r1, 'viewer'), ended(r1), started(r2, 'viewer')]
        assert w.of_participant(ALICE) is r2
        assert run(w.end(r2.id)) is r2 and run(w.end(r2.id)) is None
        assert wa.sent[3:] == [ended(r2), started(r1, 'viewer')] and w.of_participant(ALICE) is r1
        assert bbb.ended == [(r2.meeting_id, r2.moderator_pw)] and w.listing() == [r1]

    def test_attend_sets_the_preferred_room_and_end_cleans_it(self):
        clock, presence, bbb, w = registries()
        wp, wp2 = connect(presence, PROF, PROF2)
        r1 = run(w.start(PROF, 'R1', (set(), set())))
        clock.now += 1
        r2 = run(w.start(PROF2, 'R2', (set(), set())))
        assert w.of_participant(PROF) is r1 and w.of_participant(PROF2) is r2      # their own, not the newest
        assert wp.sent == [started(r1, 'moderator')] and wp2.sent == [started(r2, 'moderator')]
        assert not r2.includes(PROF)
        run(w.attend(r2.id, PROF))
        assert r2.attending == {'prof'} and r2.includes(PROF) and w.preferred['prof'] == r2.id
        assert wp.sent[1:] == [ended(r1), started(r2, 'moderator')] and 'prof' in r2.members(presence)
        assert r2.to_dict(presence)['attending'] == ['prof'] and r2.to_dict(presence)['count'] == 2
        run(w.attend(r1.id, PROF))                      # the owner joining their own room: not in attending
        assert r1.attending == set() and w.preferred['prof'] == r1.id and wp.sent[3:] == [ended(r2), started(r1, 'moderator')]
        run(w.attend(r2.id, PROF))
        run(w.end(r2.id))
        assert 'prof' not in w.preferred and 'prof2' not in w.preferred and w.of_participant(PROF) is r1
        assert wp.sent[-2:] == [ended(r2), started(r1, 'moderator')] and wp2.sent[-1] == ended(r2)
        with pytest.raises(KeyError):
            run(w.attend(r2.id, PROF))

    def test_set_audience_pushes_the_delta_and_keeps_attending(self):
        clock, presence, bbb, w = registries()
        wa, wb, wp2 = connect(presence, ALICE, BOB, PROF2)
        room = run(w.start(PROF, 'Room', ({'alice'}, set())))
        run(w.attend(room.id, PROF2))
        run(w.set_audience(room.id, ({'bob', 'prof'}, set())))
        assert room.logins == {'bob'} and room.attending == {'prof2'} and room.includes(PROF2)
        assert wa.sent == [started(room, 'viewer'), ended(room)] and wb.sent == [started(room, 'viewer')]
        assert wp2.sent == [started(room, 'moderator')]
        run(w.set_audience(room.id, (set(), {'INFO1'})))     # the department of alice and bob
        assert room.groups == {'department:INFO1'} and room.includes(ALICE) and room.includes(BOB) and not room.includes(CAROL)
        assert wa.sent[2:] == [started(room, 'viewer')] and wb.sent == [started(room, 'viewer')]
        d = room.to_dict(presence)
        assert d['audience'] == {'logins': [], 'groups': ['department:INFO1']} and d['count'] == 4
        with pytest.raises(KeyError):
            run(w.set_audience('nope', (set(), set())))

    def test_join_url_roles_fullname_and_userdata(self):
        clock, presence, bbb, w = registries()
        room = run(w.start(PROF, 'Room', ({'alice', 'carol', 'dave'}, set())))
        url = run(w.join_url_for(ALICE, room))
        assert url == (f"bbb://{room.meeting_id}?role=VIEWER&user=alice&name=Alice A&ct=1001&pw={room.attendee_pw}"
                       f"&ud=[('bbb_skip_check_audio', True)]")
        assert room.served_join
        assert run(w.join_url_for(PROF, room)).startswith(f"bbb://{room.meeting_id}?role=MODERATOR&user=prof&name=Pr. Of&ct=1001&pw={room.moderator_pw}")
        assert '&name=carol&' in run(w.join_url_for(CAROL, room))          # no full name: the login
        long = Identity(login='dave', fullname='D' * 300)
        assert '&name=' + 'D' * 255 + '&' in run(w.join_url_for(long, room))
        # the meeting was polled at the creation: no getMeetingInfo within poll_interval
        assert bbb.info_calls == []
        clock.now += 11
        run(w.join_url_for(ALICE, room))
        assert bbb.info_calls == [room.meeting_id] and len(bbb.created) == 1

    def test_join_recreates_an_expired_meeting_before_anyone_joined(self):
        clock, presence, bbb, w = registries()
        (wa,) = connect(presence, ALICE)
        room = run(w.start(PROF, 'Room', ({'alice'}, set())))
        clock.now += 20
        bbb.infos[room.meeting_id] = None                        # expired: nobody joined for a while
        url = run(w.join_url_for(ALICE, room))
        assert len(bbb.created) == 2 and bbb.created[1][0] == room.meeting_id and room.create_time == 1002
        assert '&ct=1002&' in url and room.present and w.listing() == [room] and wa.sent == [started(room, 'viewer')]

    def test_join_after_the_meeting_ended_is_gone(self):
        clock, presence, bbb, w = registries()
        (wa,) = connect(presence, ALICE)
        room = run(w.start(PROF, 'Room', ({'alice'}, set())))
        clock.now += 20
        bbb.infos[room.meeting_id] = info(running=True, joined=True)
        run(w.join_url_for(ALICE, room))
        assert room.seen_joined and room.running
        clock.now += 20
        bbb.infos[room.meeting_id] = None                        # everybody left, the server dropped it
        with pytest.raises(W.RoomGone):
            run(w.join_url_for(ALICE, room))
        assert w.listing() == [] and wa.sent == [started(room, 'viewer'), ended(room)]
        assert bbb.ended == []                                   # gone already: no end call
        with pytest.raises(W.RoomGone):
            run(w.join_url_for(ALICE, room))                     # the room object outlives the registry entry
        # ended by a moderator from the client
        room2 = run(w.start(PROF, 'R2', ({'alice'}, set())))
        clock.now += 20
        bbb.infos[room2.meeting_id] = info(ended=True)
        with pytest.raises(W.RoomGone):
            run(w.join_url_for(ALICE, room2))
        assert w.listing() == [] and wa.sent[-1] == ended(room2) and bbb.ended == []

    def test_concurrent_joins_create_once(self):
        clock, presence, bbb, w = registries()
        room = run(w.start(PROF, 'Room', ({'alice', 'bob'}, set())))
        clock.now += 20
        bbb.infos[room.meeting_id] = None

        async def both():
            return await asyncio.gather(w.join_url_for(ALICE, room), w.join_url_for(BOB, room))
        urls = run(both())
        assert len(bbb.created) == 2 and all('&ct=1002&' in u for u in urls)

    def test_tick_participants_and_ended_rooms(self):
        clock, presence, bbb, w = registries()
        wa, wb = connect(presence, ALICE, BOB)
        r1 = run(w.start(PROF, 'R1', ({'alice'}, set())))
        r2 = run(w.start(PROF2, 'R2', ({'bob'}, set())))
        bbb.infos[r1.meeting_id] = info(running=True, joined=True, attendees=[
            {'user_id': 'alice', 'fullname': 'Alice A', 'role': 'VIEWER'}, {'user_id': 'prof', 'fullname': 'Pr. Of', 'role': 'MODERATOR'},
            {'user_id': 'ghost', 'fullname': 'Ghost', 'role': 'VIEWER'}, {'user_id': '', 'fullname': 'Nobody', 'role': 'VIEWER'}])
        run(w.tick())
        assert r1.running and r1.seen_joined and set(r1.participants) == {'alice', 'prof', 'ghost'} and r1.polled_at == 1000
        d = r1.to_dict(presence)
        assert d['running'] and d['participants'] == [
            {'user_id': 'alice', 'login': 'alice', 'fullname': 'Alice A', 'role': 'VIEWER', 'member': True},
            {'user_id': 'ghost', 'login': None, 'fullname': 'Ghost', 'role': 'VIEWER', 'member': False},
            {'user_id': 'prof', 'login': 'prof', 'fullname': 'Pr. Of', 'role': 'MODERATOR', 'member': True}]
        assert not r2.running and r2.participants == {}
        # r1 gone on the server after it was used: ended; r2 gone before anybody joined: kept, re-created on a join
        bbb.infos[r1.meeting_id] = None
        bbb.infos[r2.meeting_id] = None
        r1.served_join = True
        clock.now += 10
        run(w.tick())
        assert w.listing() == [r2] and wa.sent == [started(r1, 'viewer'), ended(r1)] and wb.sent == [started(r2, 'viewer')]
        assert not r2.present and bbb.ended == []
        run(w.join_url_for(BOB, r2))
        assert len(bbb.created) == 3 and r2.present
        # forcibly ended on the server: the room ends at the next tick
        bbb.infos[r2.meeting_id] = info(running=False, joined=True, ended=True)
        clock.now += 10
        run(w.tick())
        assert w.listing() == [] and wb.sent[-1] == ended(r2) and bbb.ended == []

    def test_tick_tolerates_an_unreachable_server(self):
        clock, presence, bbb, w = registries()
        room = run(w.start(PROF, 'Room', ({'alice'}, set())))
        other = run(w.start(PROF2, 'Salle', (set(), set())))
        bbb.infos[room.meeting_id] = B.BbbUnavailable('down')
        run(w.tick())
        assert set(w.listing()) == {room, other} and len(w._warned) == 1
        run(w.tick())
        assert len(w._warned) == 1                                # one warning per message
        bbb.infos[room.meeting_id] = B.BbbError('x', 'strange')  # one failing answer: the round goes on
        bbb.infos[other.meeting_id] = info(running=True, joined=True, attendees=[{'user_id': 'prof2', 'fullname': '', 'role': 'MODERATOR'}])
        run(w.tick())
        assert w._warned == set() and other.running and set(other.participants) == {'prof2'}

    def test_end_calls_the_server_best_effort(self):
        clock, presence, bbb, w = registries()
        (wa,) = connect(presence, ALICE)
        room = run(w.start(PROF, 'Room', ({'alice'}, set())))
        bbb.fail_end = B.BbbUnavailable('down')
        assert run(w.end(room.id, 'requested')) is room
        assert w.listing() == [] and wa.sent == [started(room, 'viewer'), ended(room)]

    def test_shutdown_is_bounded(self, monkeypatch):
        clock, presence, bbb, w = registries()
        (wa,) = connect(presence, ALICE)
        run(w.start(PROF, 'R1', ({'alice'}, set())))
        run(w.start(PROF2, 'R2', (set(), set())))
        bbb.hang_end = True
        monkeypatch.setattr(W, 'SHUTDOWN_TIMEOUT', 0.2)
        run(w.shutdown())
        assert w.listing() == []
        bbb.hang_end = False
        run(w.start(PROF, 'R3', ({'alice'}, set())))
        run(w.shutdown())
        assert w.listing() == [] and bbb.ended[-1][0].startswith('sre-') and wa.sent[-1]['ended']

    def test_tell_on_a_new_socket(self):
        clock, presence, bbb, w = registries()
        (wa,) = connect(presence, ALICE)
        extra = T.FakeWatcher()
        run(w.tell('alice', extra))                       # no room: nothing
        assert extra.sent == []
        room = run(w.start(PROF, 'Room', ({'alice'}, set())))
        assert wa.sent == [started(room, 'viewer')]
        presence.add(ALICE, '/watch', extra)              # a second tab
        run(w.tell('alice', extra))
        run(w.resync({'alice'}))
        assert extra.sent == [started(room, 'viewer')] and wa.sent == [started(room, 'viewer')]
        # a login whose room changed: resync tells every socket, tell adds nothing
        clock.now += 1
        r2 = run(w.start(PROF2, 'R2', ({'alice'}, set())))
        assert extra.sent[1:] == [ended(room), started(r2, 'viewer')] and wa.sent[1:] == [ended(room), started(r2, 'viewer')]

    def test_an_instructor_in_a_student_group_is_a_moderator(self):
        clock, presence, bbb, w = registries()
        (wp3,) = connect(presence, PROF_INFO1)
        room = run(w.start(PROF, 'Room', (set(), {'INFO1'})))
        assert room.includes(PROF_INFO1) and wp3.sent == [started(room, 'moderator')]
        assert '?role=MODERATOR&user=prof3&name=prof3&' in run(w.join_url_for(PROF_INFO1, room))
        assert w.webconf_id_of(PROF_INFO1) == room.id and w.webconf_id_of(CAROL) is None and w.webconf_id_of(None) is None


# ---------------------------------------------------------------------------------------------
# through the portal
# ---------------------------------------------------------------------------------------------

PROF_H = P.who('prof', 'Pr. Of', groups=P.TEACHERS)
PROF2_H = P.who('prof2', 'Pr. Two', groups=P.TEACHERS)
ALICE_H = P.who('alice', 'Alice A', group='INFO1')
BOB_H = P.who('bob', 'Bob', group='INFO1')


def harness(tmp_path, fake, **over):
    """The proxy-mode portal with the fake BBB server as its [bbb] (a fast poll)."""
    return P.Harness(tmp_path, auth_mode='proxy', web_over={
        **P.PROXY_OVER, 'public_url': 'https://sre.example.org',
        'bbb': {'url': fake.url, 'secret': fake.secret, 'poll_interval': '0.2s', 'userdata': {'bbb_skip_check_audio': True}},
        **over})


async def receive(ws, timeout=5.0) -> dict:
    return await asyncio.wait_for(ws.receive_json(), timeout)


async def until(predicate, timeout=5.0):
    """The first truthy value of *predicate* (sync or async), polled."""
    async with asyncio.timeout(timeout):
        while True:
            result = predicate()
            if asyncio.iscoroutine(result):
                result = await result
            if result:
                return result
            await asyncio.sleep(0.05)


async def create_room(h, headers, name='Salle 1', audience=None) -> dict:
    resp = await h.client.post('/api/webconfs', json={'name': name, 'audience': audience or {}},
                               headers={**headers, **P.CSRF})
    assert resp.status == 201, await resp.text()
    return await resp.json()


async def join(h, headers, room_id):
    return await h.client.get(f'/api/webconfs/{room_id}/join', headers=headers, allow_redirects=False)


def ended_push(room_id: str) -> dict:
    return {'t': 'webconf', 'id': room_id, 'ended': True}


class TestWebconfThroughThePortal:
    def test_lifecycle(self, tmp_path):
        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake) as h:
                    # the flag of the pages and the frame-src of their security policy
                    resp = await h.client.get('/projects', headers=ALICE_H)
                    assert resp.status == 200 and 'webconf=True' in await resp.text()
                    assert f"frame-src 'self' {fake.origin}" in resp.headers['Content-Security-Policy']
                    # students neither list nor create; a bad name or audience is refused
                    assert (await h.client.get('/api/webconfs', headers=ALICE_H)).status == 403
                    resp = await h.client.post('/api/webconfs', json={'name': 'Room', 'audience': {}}, headers={**ALICE_H, **P.CSRF})
                    assert resp.status == 403
                    resp = await h.client.post('/api/webconfs', json={'name': 'x', 'audience': {}}, headers={**PROF_H, **P.CSRF})
                    assert resp.status == 400 and 'name' in (await resp.json())['error']
                    resp = await h.client.post('/api/webconfs', json={'name': 'Room', 'audience': {'logins': ['bad login']}},
                                               headers={**PROF_H, **P.CSRF})
                    assert resp.status == 400
                    assert fake.calls == [] and (await (await h.client.get('/api/webconfs', headers=PROF_H)).json()) == []
                    # alice, bob (INFO1) and prof connected
                    ws_alice = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                    ws_bob = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=BOB_H)
                    ws_prof = await h.client.ws_connect('/api/presence/ws?page=/watch', headers=PROF_H)
                    room = await create_room(h, PROF_H, audience={'logins': ['alice'], 'groups': ['INFO2']})
                    room_id, meeting_id = room['id'], room['meeting_id']
                    assert room['name'] == 'Salle 1' and room['owner'] == {'login': 'prof', 'fullname': 'Pr. Of'}
                    assert room['audience'] == {'logins': ['alice'], 'groups': ['department:INFO2']} and room['attending'] == []
                    assert [c['login'] for c in room['connected']] == ['alice', 'prof'] and room['count'] == 2
                    meeting = fake.meetings[meeting_id]
                    assert meeting.name == 'Salle 1' and meeting.params['logoutURL'] == f"https://sre.example.org/webconf/left?id={room_id}"
                    assert meeting.params['meta_sre-owner'] == 'prof' and meeting.params['meta_sre-room'] == room_id
                    started = {'t': 'webconf', 'id': room_id, 'name': 'Salle 1', 'owner': {'login': 'prof', 'fullname': 'Pr. Of'},
                               'role': 'viewer', 'join_url': f'/api/webconfs/{room_id}/join'}
                    assert await receive(ws_alice) == started
                    assert await receive(ws_prof) == {**started, 'role': 'moderator'}
                    # the presence rows of the instructors carry the room of each user
                    rows = await (await h.client.get('/api/presence', headers=PROF_H)).json()
                    assert {r['login']: r['webconf'] for r in rows} == {'alice': room_id, 'bob': None}
                    rooms = await (await h.client.get('/api/webconfs', headers=PROF2_H)).json()
                    assert [r['id'] for r in rooms] == [room_id]
                    # the join: a 302 to the signed URL of the server, a viewer for alice
                    resp = await join(h, ALICE_H, room_id)
                    assert resp.status == 302 and resp.headers['Cache-Control'] == 'no-store'
                    location = resp.headers['Location']
                    assert location.startswith(fake.url + 'join?')
                    params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
                    assert params['role'] == 'VIEWER' and params['fullName'] == 'Alice A' and params['userID'] == 'alice'
                    assert params['createTime'] == str(meeting.create_time) and params['userdata-bbb_skip_check_audio'] == 'true'
                    assert params['password'] == meeting.attendee_pw
                    # ... which the server accepts (the browser follows it to the client)
                    async with aiohttp.ClientSession() as session:
                        async with session.get(yarl.URL(location, encoded=True), allow_redirects=False) as followed:
                            assert followed.status == 302, await followed.text()
                    assert meeting.attendees == [{'user_id': 'alice', 'fullname': 'Alice A', 'role': 'VIEWER'}]
                    # any instructor joins as a moderator; bob is not in it; no identity, no room
                    resp = await join(h, PROF2_H, room_id)
                    assert resp.status == 302 and 'role=MODERATOR' in resp.headers['Location']
                    assert (await join(h, BOB_H, room_id)).status == 403
                    assert (await h.client.get(f'/api/webconfs/{room_id}/join', allow_redirects=False)).status == 401
                    assert (await join(h, ALICE_H, 'nope')).status == 404
                    assert (await h.client.get(f'/api/webconfs/{room_id}', headers=ALICE_H)).status == 200
                    assert (await h.client.get(f'/api/webconfs/{room_id}', headers=BOB_H)).status == 403
                    # the audience edited by another instructor: bob in, alice out
                    resp = await h.client.put(f'/api/webconfs/{room_id}/audience', json={'audience': {'logins': ['bob']}},
                                              headers={**PROF2_H, **P.CSRF})
                    assert resp.status == 200 and (await resp.json())['audience'] == {'logins': ['bob'], 'groups': []}
                    assert await receive(ws_alice) == ended_push(room_id)
                    assert await receive(ws_bob) == started
                    assert (await h.client.put(f'/api/webconfs/{room_id}/audience', json={'audience': {'logins': ['bob']}},
                                               headers={**BOB_H, **P.CSRF})).status == 403
                    # prof2 joins the room: their browser is told, the room lists them
                    ws_prof2 = await h.client.ws_connect('/api/presence/ws?page=/watch', headers=PROF2_H)
                    resp = await h.client.post(f'/api/webconfs/{room_id}/attend', json={}, headers={**PROF2_H, **P.CSRF})
                    assert resp.status == 200 and (await resp.json())['attending'] == ['prof2']
                    assert (await receive(ws_prof2))['role'] == 'moderator'
                    # a second page of bob is told at once
                    ws_bob2 = await h.client.ws_connect('/api/presence/ws?page=/open', headers=BOB_H)
                    assert (await receive(ws_bob2))['id'] == room_id
                    # the participants, from the polls of the server: bob in now, alice no longer a member
                    fake.join_as(meeting_id, 'bob', 'Bob', 'VIEWER')

                    async def participants():
                        rooms = await (await h.client.get('/api/webconfs', headers=PROF_H)).json()
                        return rooms[0]['participants'] if len(rooms[0]['participants']) == 2 else None
                    assert await until(participants) == [
                        {'user_id': 'alice', 'login': None, 'fullname': 'Alice A', 'role': 'VIEWER', 'member': False},
                        {'user_id': 'bob', 'login': 'bob', 'fullname': 'Bob', 'role': 'VIEWER', 'member': True}]
                    assert (await (await h.client.get('/api/webconfs', headers=PROF_H)).json())[0]['running']
                    # ended: never by a student, by any instructor; the server told, the browsers told
                    assert (await h.client.delete(f'/api/webconfs/{room_id}', headers={**BOB_H, **P.CSRF})).status == 403
                    resp = await h.client.delete(f'/api/webconfs/{room_id}', headers={**PROF2_H, **P.CSRF})
                    assert resp.status == 200 and meeting_id not in fake.meetings
                    assert [p for c, p in fake.calls if c == 'end'][0]['password'] == meeting.moderator_pw
                    for ws in (ws_bob, ws_bob2, ws_prof, ws_prof2):
                        assert await receive(ws) == ended_push(room_id)
                    assert (await h.client.get(f'/api/webconfs/{room_id}', headers=PROF_H)).status == 404
                    assert (await join(h, PROF_H, room_id)).status == 404
                    assert (await h.client.delete(f'/api/webconfs/{room_id}', headers={**PROF_H, **P.CSRF})).status == 404
                    for ws in (ws_alice, ws_bob, ws_bob2, ws_prof, ws_prof2):
                        await ws.close()
            finally:
                await fake.close()
        run(go())

    def test_expired_and_ended_meetings(self, tmp_path):
        """A meeting gone from the server before anybody joined is created again on the next
        join; gone after it was used, or ended by a moderator from the client, it ends the room."""
        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake) as h:
                    w = h.portal.webconfs
                    await w.stop_loop()                   # the polls driven by hand
                    ws_alice = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                    room = await create_room(h, PROF_H, audience={'logins': ['alice']})
                    room_id, meeting_id = room['id'], room['meeting_id']
                    assert (await receive(ws_alice))['id'] == room_id
                    fake.expire(meeting_id)
                    await asyncio.sleep(0.25)             # the last poll is stale
                    resp = await join(h, ALICE_H, room_id)
                    assert resp.status == 302 and meeting_id in fake.meetings and len(fake.calls_of('create')) == 2
                    assert f"createTime={fake.meetings[meeting_id].create_time}" in resp.headers['Location']
                    fake.join_as(meeting_id, 'alice', 'Alice A')
                    await w.tick()
                    assert w.get(room_id).seen_joined and w.get(room_id).running
                    fake.expire(meeting_id)
                    await asyncio.sleep(0.25)
                    resp = await join(h, ALICE_H, room_id)
                    assert resp.status == 410 and 'ended' in (await resp.json())['error']
                    assert w.get(room_id) is None and await receive(ws_alice) == ended_push(room_id)
                    assert len(fake.calls_of('end')) == 0            # gone already: nothing to end
                    # ended by a moderator from the client
                    room2 = await create_room(h, PROF_H, name='Salle 2', audience={'logins': ['alice']})
                    assert (await receive(ws_alice))['id'] == room2['id']
                    fake.force_end(room2['meeting_id'])
                    await w.tick()
                    assert w.get(room2['id']) is None and await receive(ws_alice) == ended_push(room2['id'])
                    assert room2['meeting_id'] in fake.meetings and len(fake.calls_of('end')) == 0
                    await ws_alice.close()
            finally:
                await fake.close()
        run(go())

    def test_server_refusals_and_outage(self, tmp_path):
        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake) as h:
                    fake.fail_next.append(('create', 502))
                    resp = await h.client.post('/api/webconfs', json={'name': 'Salle', 'audience': {}}, headers={**PROF_H, **P.CSRF})
                    assert resp.status == 503 and 'does not answer' in (await resp.json())['error']
                    fake.fail_next.append(('create', b'<response><returncode>FAILED</returncode><messageKey>maxParticipantsReached'
                                                     b'</messageKey><message>Too many meetings</message></response>'))
                    resp = await h.client.post('/api/webconfs', json={'name': 'Salle', 'audience': {}}, headers={**PROF_H, **P.CSRF})
                    assert resp.status == 502 and 'Too many meetings' in (await resp.json())['error']
                    assert await (await h.client.get('/api/webconfs', headers=PROF_H)).json() == []
                    room = await create_room(h, PROF_H, audience={'logins': ['alice']})
                    await h.portal.webconfs.stop_loop()
                    await fake.close()                    # the server gone
                    await asyncio.sleep(0.25)
                    resp = await join(h, ALICE_H, room['id'])
                    assert resp.status == 503
                    resp = await h.client.delete(f"/api/webconfs/{room['id']}", headers={**PROF_H, **P.CSRF})
                    assert resp.status == 200 and h.portal.webconfs.get(room['id']) is None     # best effort
            finally:
                await fake.close()
        run(go())

    def test_left_page_and_a_portal_without_bbb(self, tmp_path):
        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake) as h:
                    resp = await h.client.get('/webconf/left?id=abc_-1')          # no identity needed
                    assert resp.status == 200 and 'abc_-1' in await resp.text()
                    assert "frame-ancestors 'self'" in resp.headers['Content-Security-Policy']
                    assert f"frame-src 'self' {fake.origin}" in resp.headers['Content-Security-Policy']
                    assert resp.headers['X-Frame-Options'] == 'SAMEORIGIN'
                    for bad in ('../x', '', 'a b', 'x' * 40):
                        assert (await h.client.get('/webconf/left', params={'id': bad})).status == 400, bad
            finally:
                await fake.close()
            async with P.Harness(tmp_path / 'off', auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                resp = await h.client.get('/projects', headers=ALICE_H)
                assert resp.status == 200 and 'webconf=False' in await resp.text()
                assert 'frame-src' not in resp.headers['Content-Security-Policy']
                assert (await h.client.get('/api/webconfs', headers=PROF_H)).status == 404
                resp = await h.client.post('/api/webconfs', json={'name': 'Salle', 'audience': {}}, headers={**PROF_H, **P.CSRF})
                assert resp.status == 404 and 'not configured' in (await resp.json())['error']
                assert (await join(h, ALICE_H, 'x')).status == 404
                ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                await ws.close()
        (tmp_path / 'off').mkdir()
        run(go())

    def test_access_log_lines(self, tmp_path):
        over = {'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}

        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake, **over) as h:
                    ws_alice = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                    room = await create_room(h, PROF_H, audience={'logins': ['alice']})
                    await receive(ws_alice)
                    assert (await join(h, ALICE_H, room['id'])).status == 302
                    assert (await h.client.get('/api/webconfs', headers=PROF_H)).status == 200
                    assert (await h.client.get(f"/api/webconfs/{room['id']}", headers=ALICE_H)).status == 200
                    assert (await h.client.get(f"/webconf/left?id={room['id']}")).status == 200
                    await h.client.put(f"/api/webconfs/{room['id']}/audience", json={'audience': {'logins': ['alice', 'bob']}},
                                       headers={**PROF2_H, **P.CSRF})
                    await h.client.post(f"/api/webconfs/{room['id']}/attend", json={}, headers={**PROF2_H, **P.CSRF})
                    await h.client.delete(f"/api/webconfs/{room['id']}", headers={**PROF2_H, **P.CSRF})
                    await ws_alice.close()
                    return room['id']
            finally:
                await fake.close()
        room_id = run(go())
        lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
        by_event = {}
        for line in lines:
            by_event.setdefault(line['event'], []).append(line)
        start = by_event['webconf_start'][0]
        assert (start['login'], start['webconf'], start['name'], start['audience'], start['status']) == ('prof', room_id, 'Salle 1', '1', '201')
        joined = by_event['webconf_join'][0]
        assert (joined['login'], joined['webconf'], joined['id'], joined['role'], joined['status']) == ('alice', room_id, room_id, 'viewer', '302')
        audience = by_event['webconf_audience'][0]
        assert (audience['login'], audience['audience'], audience['owner'], audience['status']) == ('prof2', '2', 'prof', '200')
        attend = by_event['webconf_attend'][0]
        assert (attend['login'], attend['webconf'], attend['owner']) == ('prof2', room_id, 'prof')
        stop = by_event['webconf_stop'][0]
        assert (stop['login'], stop['webconf'], stop['owner'], stop['name']) == ('prof2', room_id, 'prof', 'Salle 1')
        # the listings are keepalives, the page of the iframe is ignored, the presence socket too
        assert set(by_event) <= {'webconf_start', 'webconf_join', 'webconf_audience', 'webconf_attend', 'webconf_stop',
                                 'session_open', 'session_close'}
        text = (tmp_path / 'access.log').read_text()
        assert 'left' not in text and 'presence' not in text
        alice_session = [l for l in by_event['session_close'] if l['login'] == 'alice'][0]
        assert alice_session['requests'] == '1'                      # the join; the GET of the room is a keepalive
