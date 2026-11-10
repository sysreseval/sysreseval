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
# the private conversations
# ---------------------------------------------------------------------------------------------

def invite_push(inv: W.Invitation, reason: str | None = None) -> dict:
    message = {'t': 'webconf-invite', 'id': inv.id,
               'from': {'login': inv.instructor.login, 'fullname': inv.instructor.fullname},
               'to': {'login': inv.student.login, 'fullname': inv.student.fullname}}
    if reason is not None:
        message.update(ended=True, reason=reason)
    return message


def private_started(room: W.Room, identity: Identity, tab: str = '') -> dict:
    other = room.peer if identity.login == room.owner.login else room.owner
    return {**started(room, 'moderator' if identity.is_instructor else 'viewer'), 'kind': 'private',
            'peer': {'login': other.login, 'fullname': other.fullname}, 'tab': tab}


def switched(room: W.Room) -> dict:
    return {**ended(room), 'switch': True}


def conversation(w, instructor=PROF, student=ALICE, tabs=('tp', 'ta')) -> W.Room:
    inv = run(w.invite(instructor, student.login, tab=tabs[0]))
    return run(w.accept(inv.id, student, tab=tabs[1]))


class GatedBbb(FakeBbb):
    """A server whose ``create`` waits for the test (what happens meanwhile)."""

    def __init__(self):
        super().__init__()
        self.gate = None
        self.entered = None

    async def create(self, meeting_id, name, **kw):
        if self.gate is not None:
            self.entered.set()
            await self.gate.wait()
        return await super().create(meeting_id, name, **kw)


class TestPrivateConversations:
    def test_helpers(self):
        assert W.private_name(PROF, ALICE) == 'Pr. Of – Alice A'
        assert W.private_name(PROF2, CAROL) == 'prof2 – carol'                    # no full name: the login
        long = Identity(login='dave', fullname='  D\x00' + 'd' * 80)
        name = W.private_name(long, ALICE)
        assert name == 'D' + 'd' * 29 + ' – Alice A' and W.check_name(name) == name     # a name the API takes
        assert W.check_tab('t-1_A') == 't-1_A'
        for bad in ('', 'a b', 'x' * 65, 3, None, 'é'):
            assert W.check_tab(bad) == ''

    def test_invite_tells_both_and_changes_nothing_else(self):
        clock, presence, bbb, w = registries()
        wp, wa, wc = connect(presence, PROF, ALICE, CAROL)
        r1 = run(w.start(PROF, 'R1', ({'alice'}, set())))
        inv = run(w.invite(PROF, 'alice', tab='tp', request_origin='http://sre.lan', host='h1', rln='x@@@y@@@alice'))
        assert (inv.instructor, inv.student, inv.created_at) == (PROF, ALICE, 1000.0)
        assert (inv.origin, inv.host, inv.rln, inv.tabs) == ('http://sre.lan', 'h1', 'x@@@y@@@alice', {'prof': 'tp'})
        assert wp.sent == [started(r1, 'moderator'), invite_push(inv)] and wa.sent == [started(r1, 'viewer'), invite_push(inv)]
        assert wc.sent == [] and len(bbb.created) == 1 and w.listing() == [r1] and w.of_participant(ALICE) is r1
        assert w.invitation(inv.id) is inv and w.invitations_of('alice') == [inv] == w.invitations_of('prof')
        assert w.invitations_of('carol') == [] and w.private_of('alice') is None
        assert inv.to_dict() == {'id': inv.id, 'from': {'login': 'prof', 'fullname': 'Pr. Of'},
                                 'to': {'login': 'alice', 'fullname': 'Alice A'}, 'created_at': inv.to_dict()['created_at']}
        # another invitation of the same instructor takes the first one back
        inv2 = run(w.invite(PROF, 'carol'))
        assert wa.sent[2:] == [invite_push(inv, 'cancelled')] and wc.sent == [invite_push(inv2)]
        assert wp.sent[2:] == [invite_push(inv, 'cancelled'), invite_push(inv2)] and w.invitation(inv.id) is None
        assert inv2.tabs == {}

    def test_invite_refusals(self):
        clock, presence, bbb, w = registries()
        connect(presence, PROF, PROF2, ALICE)
        for bad in ('prof', '', None, 3):
            with pytest.raises(ValueError):
                run(w.invite(PROF, bad))
        with pytest.raises(W.Refused, match='not connected'):
            run(w.invite(PROF, 'bob'))
        inv = run(w.invite(PROF, 'alice'))
        with pytest.raises(W.Refused, match='somebody else'):
            run(w.invite(PROF2, 'alice'))
        assert run(w.invite(PROF, 'alice')).id != inv.id               # the same instructor again: a new one
        run(w.accept(w.invitations_of('alice')[0].id, ALICE))
        for instructor in (PROF, PROF2):
            with pytest.raises(W.Refused, match='private conversation'):
                run(w.invite(instructor, 'alice'))
        with pytest.raises(W.Refused, match='private conversation'):
            run(w.invite(PROF2, 'prof'))                               # busy in either role
        # switched off, or no server at all
        w.cfg.private_rooms = False
        assert w.enabled and not w.private_enabled
        with pytest.raises(W.WebconfDisabled):
            run(w.invite(PROF2, 'alice'))
        off = W.Webconfs(presence, None)
        assert not off.private_enabled
        with pytest.raises(W.WebconfDisabled):
            run(off.invite(PROF, 'alice'))

    def test_accept_switches_both_and_the_end_brings_them_back(self):
        clock, presence, bbb, w = registries()
        wp, wa = connect(presence, PROF, ALICE)
        r1 = run(w.start(PROF, 'R1', ({'alice'}, set())))
        clock.now += 1
        r2 = run(w.start(PROF2, 'R2', (set(), set())))
        run(w.attend(r2.id, PROF))
        run(w.attend(r1.id, PROF))                    # prof is back in R1, R2 is the newest room including them
        assert w.of_participant(PROF) is r1 and r2.includes(PROF)
        w.cfg.record = True
        w.cfg.mute_on_start = True
        w.cfg.duration = 3600
        w.cfg.max_participants = 30
        w.cfg.welcome = 'Hello'
        del wp.sent[:], wa.sent[:]
        clock.now += 1
        inv = run(w.invite(PROF, 'alice', tab='tp', request_origin='http://ignored'))
        room = run(w.accept(inv.id, ALICE, tab='ta'))
        assert room.private and room.kind == W.ROOM_PRIVATE and room.owner is PROF and room.peer is ALICE
        assert room.name == 'Pr. Of – Alice A' and room.tabs == {'prof': 'tp', 'alice': 'ta'} and room.logins == {'alice'}
        assert room.includes(PROF) and room.includes(ALICE) and not room.includes(PROF2) and not room.includes(None)
        meeting_id, name, kw = bbb.created[-1]
        assert (meeting_id, name) == (room.meeting_id, 'Pr. Of – Alice A')
        assert kw['record'] is False and kw['mute_on_start'] is False and kw['extra'] == W.PRIVATE_CREATE
        assert 'duration' not in kw and 'max_participants' not in kw and 'welcome' not in kw
        assert kw['meta'] == {'sre-room': room.id, 'sre-owner': 'prof', 'sre-kind': 'private'}
        assert kw['logout_url'] == f'https://sre.example.org/webconf/left?id={room.id}'
        assert kw['extra'] is not W.PRIVATE_CREATE and kw['extra']['endWhenNoModerator'] is True
        # both left their class room for it; the ended push says the room goes on
        assert wa.sent == [invite_push(inv), invite_push(inv, 'accepted'), switched(r1), private_started(room, ALICE, 'ta')]
        assert wp.sent == [invite_push(inv), invite_push(inv, 'accepted'), switched(r1), private_started(room, PROF, 'tp')]
        assert w.of_participant(ALICE) is room and w.of_participant(PROF) is room and w.private_of('prof') is room
        assert w.preferred['prof'] == r1.id and w.invitation(inv.id) is None and w.listing() == [r1, r2, room]
        d = room.to_dict(presence)
        assert d['kind'] == 'private' and d['peer'] == {'login': 'alice', 'fullname': 'Alice A'} and d['count'] == 2
        assert r1.to_dict(presence)['kind'] == 'class' and r1.to_dict(presence)['peer'] is None
        # the joins of a private room: straight to the microphone, the site's settings under, its own over
        url = run(w.join_url_for(ALICE, room))
        assert url.startswith(f"bbb://{room.meeting_id}?role=VIEWER&user=alice&")
        assert url.endswith("&ud=[('bbb_auto_join_audio', True), ('bbb_hide_presentation_on_join', True), "
                            "('bbb_listen_only_mode', False), ('bbb_skip_check_audio', True)]")
        w.cfg.private_userdata = {'bbb_auto_join_audio': False, 'bbb_client_title': 'Private'}
        url = run(w.join_url_for(PROF, room))
        assert "role=MODERATOR" in url and "('bbb_auto_join_audio', False), ('bbb_client_title', 'Private')" in url
        assert run(w.join_url_for(ALICE, r1)).endswith("&ud=[('bbb_skip_check_audio', True)]")     # the other rooms: unchanged
        # nobody joins it, it has no audience, a third party cannot end it by leaving
        with pytest.raises(W.Refused):
            run(w.attend(room.id, PROF2))
        with pytest.raises(W.Refused):
            run(w.set_audience(room.id, ({'bob'}, set())))
        with pytest.raises(PermissionError):
            run(w.leave(room.id, PROF2))
        with pytest.raises(W.Refused):
            run(w.leave(r1.id, PROF))                 # a class room is left in the browser only
        with pytest.raises(KeyError):
            run(w.leave('nope', PROF))
        assert room.attending == set() and w.listing() == [r1, r2, room]
        # the student leaves: over for both, each back in the room they were in (prof: R1, not the newest)
        del wp.sent[:], wa.sent[:]
        assert run(w.leave(room.id, ALICE)) is room
        assert wa.sent == [ended(room), started(r1, 'viewer')] and wp.sent == [ended(room), started(r1, 'moderator')]
        assert bbb.ended == [(room.meeting_id, room.moderator_pw)] and w.listing() == [r1, r2] and w.private_of('alice') is None

    def test_decline_cancel_and_expiry(self):
        clock, presence, bbb, w = registries()
        wp, wp2, wa = connect(presence, PROF, PROF2, ALICE)
        inv = run(w.invite(PROF, 'alice'))
        with pytest.raises(PermissionError):
            run(w.decline(inv.id, BOB))
        with pytest.raises(PermissionError):
            run(w.accept(inv.id, BOB))
        run(w.decline(inv.id, ALICE))
        assert wa.sent == [invite_push(inv), invite_push(inv, 'declined')] == wp.sent and w.invitations_of('alice') == []
        for call in (w.decline(inv.id, ALICE), w.accept(inv.id, ALICE), w.cancel(inv.id, PROF), w.cancel('nope', PROF)):
            with pytest.raises(W.InvitationGone):
                run(call)
        # taken back by the instructor, or by another one; never by a student
        inv = run(w.invite(PROF, 'alice'))
        with pytest.raises(PermissionError):
            run(w.cancel(inv.id, ALICE))
        run(w.cancel(inv.id, PROF))
        assert wa.sent[-1] == invite_push(inv, 'cancelled') == wp.sent[-1]
        inv = run(w.invite(PROF, 'alice'))
        run(w.cancel(inv.id, PROF2))
        assert wa.sent[-1] == invite_push(inv, 'cancelled') and wp2.sent == []
        # nobody answers: expired by the tick, even while the server does not answer
        room = run(w.start(PROF2, 'Room', (set(), set())))
        bbb.infos[room.meeting_id] = B.BbbUnavailable('down')
        inv = run(w.invite(PROF, 'alice'))
        clock.now += W.INVITE_TIMEOUT - 1
        run(w.tick())
        assert w.invitation(inv.id) is inv and wa.sent[-1] == invite_push(inv)
        clock.now += 1
        run(w.tick())
        assert w.invitation(inv.id) is None and wa.sent[-1] == invite_push(inv, 'expired') == wp.sent[-1]
        assert len(bbb.created) == 1 and w.listing() == [room]

    def test_accept_failures(self):
        clock, presence, bbb, w = registries()
        wp, wa = connect(presence, PROF, ALICE)
        # the server refuses the meeting, or does not answer: failed, no room
        for error in (B.BbbError('x', 'no'), B.BbbUnavailable('down')):
            inv = run(w.invite(PROF, 'alice'))
            bbb.fail_create = error
            with pytest.raises(type(error)):
                run(w.accept(inv.id, ALICE))
            assert wa.sent[-1] == invite_push(inv, 'failed') == wp.sent[-1]
            assert w.listing() == [] and w.invitations_of('alice') == [] and w.shown == {}
        bbb.fail_create = None
        # the instructor left the site meanwhile
        inv = run(w.invite(PROF, 'alice'))
        presence.remove(presence._sockets['prof'][0])
        with pytest.raises(W.InvitationGone):
            run(w.accept(inv.id, ALICE))
        assert wa.sent[-1] == invite_push(inv, 'cancelled') and w.listing() == [] and bbb.created == []

    def test_cancel_or_a_second_accept_while_the_meeting_is_created(self):
        bbb = GatedBbb()
        clock, presence, bbb, w = registries(bbb=bbb)
        wp, wa = connect(presence, PROF, ALICE)

        async def go(action):
            bbb.gate, bbb.entered = asyncio.Event(), asyncio.Event()
            inv = await w.invite(PROF, 'alice')
            accepting = asyncio.ensure_future(w.accept(inv.id, ALICE))
            await bbb.entered.wait()
            outcome = await action(inv)
            bbb.gate.set()
            return inv, outcome, await asyncio.gather(accepting, return_exceptions=True)

        async def cancel(inv):
            await w.cancel(inv.id, PROF)
            return list(wa.sent)

        inv, before, (result,) = run(go(cancel))
        assert before[-1] == invite_push(inv)                         # nothing said before the meeting exists
        assert isinstance(result, W.InvitationGone) and w.listing() == [] and w.invitations_of('alice') == []
        assert wa.sent[-1] == invite_push(inv, 'cancelled') == wp.sent[-1]
        assert bbb.ended == [(bbb.created[0][0], bbb.ended[0][1])]    # the meeting made for nothing is ended

        async def again(inv):
            results = []
            for call in (w.accept(inv.id, ALICE), w.decline(inv.id, ALICE)):
                try:
                    await call
                except W.InvitationGone:
                    results.append('gone')
            return results

        inv, outcome, (room,) = run(go(again))
        assert outcome == ['gone', 'gone'] and isinstance(room, W.Room) and w.listing() == [room]
        assert wa.sent[-3:-1] == [invite_push(inv), invite_push(inv, 'accepted')] and len(bbb.created) == 2

    def test_a_new_conversation_replaces_the_old_one_without_a_bounce(self):
        clock, presence, bbb, w = registries()
        wp, wa, wb = connect(presence, PROF, ALICE, BOB)
        r1 = run(w.start(PROF, 'R1', ({'alice', 'bob'}, set())))
        clock.now += 1
        first = conversation(w, PROF, ALICE)
        clock.now += 1
        inv = run(w.invite(PROF, 'bob', tab='tp2'))                   # allowed while talking with alice
        assert w.of_participant(PROF) is first and w.of_participant(ALICE) is first
        del wp.sent[:], wa.sent[:], wb.sent[:]
        second = run(w.accept(inv.id, BOB, tab='tb'))
        assert w.listing() == [r1, second] and bbb.ended == [(first.meeting_id, first.moderator_pw)]
        # prof goes from one conversation to the other; alice is back in the class room
        assert wp.sent == [invite_push(inv, 'accepted'), ended(first), private_started(second, PROF, 'tp2')]
        assert wa.sent == [ended(first), started(r1, 'viewer')]
        assert wb.sent == [invite_push(inv, 'accepted'), switched(r1), private_started(second, BOB, 'tb')]

    def test_a_private_room_wins_and_is_never_created_again(self, monkeypatch):
        clock, presence, bbb, w = registries()
        wp, wp2, wa = connect(presence, PROF, PROF2, ALICE)
        r1 = run(w.start(PROF, 'R1', ({'alice'}, set())))
        clock.now += 1
        room = conversation(w)
        del wp.sent[:], wa.sent[:]
        # a newer room including alice does not take her out of the conversation
        clock.now += 1
        monkeypatch.setattr(W, 'MAX_ROOMS', 2)                        # the private rooms are not counted
        r3 = run(w.start(PROF2, 'R3', ({'alice'}, set())))
        with pytest.raises(ValueError, match='too many'):
            run(w.start(PROF2, 'R4', (set(), set())))
        assert wa.sent == [] and w.of_participant(ALICE) is room
        # the meeting gone from the server before the portal saw anybody in it: over, never created again
        clock.now += 20
        bbb.infos[room.meeting_id] = None
        assert not room.seen_joined
        with pytest.raises(W.RoomGone):
            run(w.join_url_for(ALICE, room))
        assert len(bbb.created) == 3 and w.listing() == [r1, r3] and bbb.ended == []
        assert wa.sent == [ended(room), started(r3, 'viewer')] and wp.sent == [ended(room), started(r1, 'moderator')]
        # ... the same from a tick
        room = conversation(w)
        bbb.infos[room.meeting_id] = None
        clock.now += 10
        run(w.tick())
        assert w.private_of('alice') is None and wa.sent[-2:] == [ended(room), started(r3, 'viewer')]
        # an instructor joining another room ends their own conversation
        room = conversation(w)
        del wp.sent[:], wa.sent[:]
        run(w.attend(r3.id, PROF))
        assert w.private_of('prof') is None and wp.sent == [ended(room), started(r3, 'moderator')]
        assert wa.sent == [ended(room), started(r3, 'viewer')] and w.preferred['prof'] == r3.id

    def test_tell_repeats_the_invitation_and_shutdown_drops_it(self):
        clock, presence, bbb, w = registries()
        wp, wa = connect(presence, PROF, ALICE)
        inv = run(w.invite(PROF, 'alice'))
        for identity in (ALICE, PROF):
            extra = T.FakeWatcher()
            presence.add(identity, '/watch', extra)
            run(w.tell(identity.login, extra))
            run(w.resync({identity.login}))
            assert extra.sent == [invite_push(inv)]
        run(w.shutdown())
        assert w.invitations_of('alice') == [] and wa.sent[-1] == invite_push(inv, 'cancelled')
        extra = T.FakeWatcher()
        presence.add(ALICE, '/open', extra)
        run(w.tell('alice', extra))
        assert extra.sent == []
        # a conversation: the new page of each is given its room with the tab that shows it
        room = conversation(w)
        extra = T.FakeWatcher()
        presence.add(ALICE, '/projects', extra)
        run(w.tell('alice', extra))
        assert extra.sent == [private_started(room, ALICE, 'ta')]


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
                    # an audience of nobody is accepted (the instructors alone), then bob is put back
                    resp = await h.client.put(f'/api/webconfs/{room_id}/audience', json={'audience': {'logins': [], 'groups': []}},
                                              headers={**PROF2_H, **P.CSRF})
                    assert resp.status == 200 and (await resp.json())['audience'] == {'logins': [], 'groups': []}
                    assert await receive(ws_bob) == ended_push(room_id)
                    resp = await h.client.put(f'/api/webconfs/{room_id}/audience', json={'audience': {'logins': ['bob']}},
                                              headers={**PROF2_H, **P.CSRF})
                    assert resp.status == 200 and await receive(ws_bob) == started
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


# ---------------------------------------------------------------------------------------------
# the private conversations through the portal
# ---------------------------------------------------------------------------------------------

RLN_ALICE = '20261026100000@@@sre@dhcp.py@@@alice'
PROF_WHO = {'login': 'prof', 'fullname': 'Pr. Of'}
ALICE_WHO = {'login': 'alice', 'fullname': 'Alice A'}


async def invite(h, headers, login, **body):
    return await h.client.post('/api/webconfs/invitations', json={'login': login, **body}, headers={**headers, **P.CSRF})


async def answer(h, headers, invitation_id, what, **body):
    return await h.client.post(f'/api/webconfs/invitations/{invitation_id}/{what}', json=body,
                               headers={**headers, **P.CSRF})


async def take_back(h, headers, invitation_id):
    return await h.client.delete(f'/api/webconfs/invitations/{invitation_id}', headers={**headers, **P.CSRF})


async def leave(h, headers, room_id):
    return await h.client.post(f'/api/webconfs/{room_id}/leave', json={}, headers={**headers, **P.CSRF})


def invitation_push(invitation_id: str, reason: str | None = None) -> dict:
    message = {'t': 'webconf-invite', 'id': invitation_id, 'from': PROF_WHO, 'to': ALICE_WHO}
    if reason is not None:
        message.update(ended=True, reason=reason)
    return message


class TestPrivateThroughThePortal:
    def test_lifecycle(self, tmp_path):
        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake) as h:
                    resp = await h.client.get('/projects', headers=ALICE_H)
                    assert 'webconf=True private=True' in await resp.text()
                    ws_alice = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                    ws_prof = await h.client.ws_connect('/api/presence/ws?page=/projects/h01/x', headers=PROF_H)
                    room = await create_room(h, PROF_H, audience={'logins': ['alice']})
                    class_started = await receive(ws_alice)
                    assert class_started['id'] == room['id'] and (await receive(ws_prof))['role'] == 'moderator'
                    # who may invite whom
                    assert (await invite(h, ALICE_H, 'bob')).status == 403
                    assert (await invite(h, PROF_H, 'prof')).status == 400
                    assert (await invite(h, PROF_H, 3)).status == 400
                    resp = await invite(h, PROF_H, 'bob')
                    assert resp.status == 409 and 'not connected' in (await resp.json())['error']
                    resp = await h.client.post('/api/webconfs/invitations', data='x', headers={**PROF_H, **P.CSRF})
                    assert resp.status == 400
                    # the invitation: both told, nothing created
                    resp = await invite(h, PROF_H, 'alice', tab='tab-prof', host='h01', rln=RLN_ALICE)
                    assert resp.status == 201, await resp.text()
                    inv = await resp.json()
                    assert inv['from'] == PROF_WHO and inv['to'] == ALICE_WHO
                    push = invitation_push(inv['id'])
                    assert await receive(ws_alice) == push
                    assert await receive(ws_prof) == push
                    assert len(fake.calls_of('create')) == 1 and len(await (await h.client.get('/api/webconfs', headers=PROF_H)).json()) == 1
                    # another page of alice shows the class conference and the invitation
                    ws_alice2 = await h.client.ws_connect('/api/presence/ws?page=/open', headers=ALICE_H)
                    assert await receive(ws_alice2) == class_started
                    assert await receive(ws_alice2) == push
                    # answered by the invited one only
                    assert (await answer(h, BOB_H, inv['id'], 'accept')).status == 403
                    assert (await answer(h, BOB_H, inv['id'], 'decline')).status == 403
                    assert (await answer(h, ALICE_H, 'nope', 'accept')).status == 410
                    assert (await take_back(h, ALICE_H, inv['id'])).status == 403
                    resp = await answer(h, ALICE_H, inv['id'], 'accept', tab='tab-alice')
                    assert resp.status == 200, await resp.text()
                    private = await resp.json()
                    assert private['kind'] == 'private' and private['peer'] == ALICE_WHO and private['owner'] == PROF_WHO
                    assert private['name'] == 'Pr. Of – Alice A' and private['id'] != room['id']
                    meeting = fake.meetings[private['meeting_id']]
                    params = meeting.params
                    assert meeting.name == 'Pr. Of – Alice A'
                    assert params['endWhenNoModerator'] == 'true' and params['endWhenNoModeratorDelayInMinutes'] == '1'
                    assert params['disabledFeatures'] == 'breakoutRooms,learningDashboard' and params['meta_sre-kind'] == 'private'
                    assert params['record'] == 'false' and params['muteOnStart'] == 'false' and 'welcome' not in params
                    assert params['logoutURL'] == f"https://sre.example.org/webconf/left?id={private['id']}"
                    assert (await answer(h, ALICE_H, inv['id'], 'accept')).status == 410
                    # both browsers leave the class conference for the private room, in the tab that asked
                    started = {'t': 'webconf', 'id': private['id'], 'name': 'Pr. Of – Alice A', 'owner': PROF_WHO,
                               'join_url': f"/api/webconfs/{private['id']}/join", 'kind': 'private'}
                    for ws in (ws_alice, ws_alice2):
                        assert await receive(ws) == invitation_push(inv['id'], 'accepted')
                        assert await receive(ws) == {**ended_push(room['id']), 'switch': True}
                        assert await receive(ws) == {**started, 'role': 'viewer', 'peer': PROF_WHO, 'tab': 'tab-alice'}
                    assert await receive(ws_prof) == invitation_push(inv['id'], 'accepted')
                    assert await receive(ws_prof) == {**ended_push(room['id']), 'switch': True}
                    assert await receive(ws_prof) == {**started, 'role': 'moderator', 'peer': ALICE_WHO, 'tab': 'tab-prof'}
                    # the joins: straight to the microphone; the two of the conversation alone
                    resp = await join(h, ALICE_H, private['id'])
                    assert resp.status == 302
                    joined = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(resp.headers['Location']).query))
                    assert joined['role'] == 'VIEWER' and joined['meetingID'] == private['meeting_id']
                    assert joined['userdata-bbb_auto_join_audio'] == 'true' and joined['userdata-bbb_listen_only_mode'] == 'false'
                    assert joined['userdata-bbb_skip_check_audio'] == 'true'
                    resp = await join(h, PROF_H, private['id'])
                    assert resp.status == 302 and 'role=MODERATOR' in resp.headers['Location']
                    for other in (PROF2_H, BOB_H):
                        assert (await join(h, other, private['id'])).status == 403
                    resp = await h.client.post(f"/api/webconfs/{private['id']}/attend", json={}, headers={**PROF2_H, **P.CSRF})
                    assert resp.status == 409
                    resp = await h.client.put(f"/api/webconfs/{private['id']}/audience", json={'audience': {'logins': ['bob']}},
                                              headers={**PROF2_H, **P.CSRF})
                    assert resp.status == 409
                    rooms = await (await h.client.get('/api/webconfs', headers=PROF2_H)).json()
                    assert [(r['id'], r['kind']) for r in rooms] == [(room['id'], 'class'), (private['id'], 'private')]
                    rows = await (await h.client.get('/api/presence', headers=PROF2_H)).json()
                    assert {r['login']: r['webconf'] for r in rows} == {'alice': private['id'], 'prof': private['id']}
                    # busy for anybody else
                    resp = await invite(h, PROF2_H, 'alice')
                    assert resp.status == 409 and 'private conversation' in (await resp.json())['error']
                    # left by one of the two: over, both back in the class conference
                    assert (await leave(h, BOB_H, private['id'])).status == 403
                    assert (await leave(h, ALICE_H, room['id'])).status == 409
                    assert (await leave(h, ALICE_H, 'nope')).status == 404
                    assert (await leave(h, ALICE_H, private['id'])).status == 200
                    assert private['meeting_id'] not in fake.meetings and room['meeting_id'] in fake.meetings
                    for ws in (ws_alice, ws_alice2):
                        assert await receive(ws) == ended_push(private['id'])
                        assert await receive(ws) == class_started
                    assert await receive(ws_prof) == ended_push(private['id'])
                    assert (await receive(ws_prof))['id'] == room['id']
                    assert (await leave(h, ALICE_H, private['id'])).status == 404
                    for ws in (ws_alice, ws_alice2, ws_prof):
                        await ws.close()
            finally:
                await fake.close()
        run(go())

    def test_decline_cancel_and_refusals_of_the_server(self, tmp_path):
        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake) as h:
                    ws_alice = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                    ws_prof = await h.client.ws_connect('/api/presence/ws?page=/watch', headers=PROF_H)

                    async def invited() -> str:
                        resp = await invite(h, PROF_H, 'alice')
                        assert resp.status == 201
                        invitation_id = (await resp.json())['id']
                        assert await receive(ws_alice) == invitation_push(invitation_id)
                        assert await receive(ws_prof) == invitation_push(invitation_id)
                        return invitation_id

                    async def over(invitation_id: str, reason: str):
                        assert await receive(ws_alice) == invitation_push(invitation_id, reason)
                        assert await receive(ws_prof) == invitation_push(invitation_id, reason)

                    one = await invited()
                    assert (await answer(h, ALICE_H, one, 'decline')).status == 200
                    await over(one, 'declined')
                    assert (await answer(h, ALICE_H, one, 'decline')).status == 410
                    two = await invited()
                    assert (await take_back(h, PROF2_H, two)).status == 200          # any instructor
                    await over(two, 'cancelled')
                    assert (await take_back(h, PROF_H, two)).status == 410
                    # the server refuses the meeting, or does not answer: the invitation failed
                    three = await invited()
                    fake.fail_next.append(('create', 502))
                    resp = await answer(h, ALICE_H, three, 'accept')
                    assert resp.status == 503 and 'does not answer' in (await resp.json())['error']
                    await over(three, 'failed')
                    four = await invited()
                    fake.fail_next.append(('create', b'<response><returncode>FAILED</returncode><messageKey>x</messageKey>'
                                                     b'<message>Too many meetings</message></response>'))
                    resp = await answer(h, ALICE_H, four, 'accept')
                    assert resp.status == 502 and 'Too many meetings' in (await resp.json())['error']
                    await over(four, 'failed')
                    assert await (await h.client.get('/api/webconfs', headers=PROF_H)).json() == []
                    # nobody answers
                    await h.portal.webconfs.stop_loop()
                    five = await invited()
                    await h.portal.webconfs.tick(h.portal.webconfs.clock() + W.INVITE_TIMEOUT)
                    await over(five, 'expired')
                    await ws_alice.close()
                    await ws_prof.close()
            finally:
                await fake.close()
        run(go())

    def test_switched_off(self, tmp_path):
        async def go():
            fake = await FakeBbbServer().start()
            try:
                bbb = {'url': fake.url, 'secret': fake.secret, 'private_rooms': False}
                async with harness(tmp_path, fake, bbb=bbb) as h:
                    resp = await h.client.get('/projects', headers=ALICE_H)
                    assert 'webconf=True private=False' in await resp.text()
                    ws_alice = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                    resp = await invite(h, PROF_H, 'alice')
                    assert resp.status == 404 and 'not configured' in (await resp.json())['error']
                    assert (await answer(h, ALICE_H, 'x', 'accept')).status == 404
                    assert (await answer(h, ALICE_H, 'x', 'decline')).status == 404
                    assert (await take_back(h, PROF_H, 'x')).status == 404
                    room = await create_room(h, PROF_H, audience={'logins': ['alice']})      # the rooms still work
                    assert (await receive(ws_alice))['id'] == room['id']
                    await ws_alice.close()
            finally:
                await fake.close()
            async with P.Harness(tmp_path / 'off', auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                resp = await h.client.get('/projects', headers=ALICE_H)
                assert 'webconf=False private=False' in await resp.text()
                assert (await invite(h, PROF_H, 'alice')).status == 404
                assert (await leave(h, ALICE_H, 'x')).status == 404
        (tmp_path / 'off').mkdir()
        run(go())

    def test_access_log_lines(self, tmp_path):
        over = {'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}

        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with harness(tmp_path, fake, **over) as h:
                    ws_alice = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=ALICE_H)
                    ws_prof = await h.client.ws_connect('/api/presence/ws?page=/watch', headers=PROF_H)
                    one = (await (await invite(h, PROF_H, 'alice', host='h01', rln=RLN_ALICE)).json())['id']
                    await answer(h, ALICE_H, one, 'decline')
                    two = (await (await invite(h, PROF_H, 'alice', host=3, rln='bad')).json())['id']
                    await take_back(h, PROF_H, two)
                    three = (await (await invite(h, PROF_H, 'alice')).json())['id']
                    room = await (await answer(h, ALICE_H, three, 'accept', tab='t1')).json()
                    await leave(h, PROF_H, room['id'])
                    assert (await invite(h, PROF_H, 'bob')).status == 409
                    await ws_alice.close()
                    await ws_prof.close()
                    return one, two, three, room['id']
            finally:
                await fake.close()
        one, two, three, room_id = run(go())
        by_event = {}
        for line in (parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()):
            by_event.setdefault(line['event'], []).append(line)
        first, second, third, refused = by_event['webconf_invite']
        assert (first['login'], first['student'], first['host'], first['rln'], first['invitation'], first['status']) == \
            ('prof', 'alice', 'h01', RLN_ALICE, one, '201')
        assert (second['invitation'], second['host'], second['rln']) == (two, '', '')      # a bad project: not logged
        assert (refused['student'], refused['status']) == ('bob', '409') and 'invitation' not in refused
        declined = by_event['webconf_decline'][0]
        assert (declined['login'], declined['invitation'], declined['instructor'], declined['status']) == ('alice', one, 'prof', '200')
        cancelled = by_event['webconf_cancel'][0]
        assert (cancelled['login'], cancelled['invitation'], cancelled['student'], cancelled['status']) == ('prof', two, 'alice', '200')
        accepted = by_event['webconf_accept'][0]
        assert (accepted['login'], accepted['invitation'], accepted['instructor'], accepted['webconf'], accepted['status']) == \
            ('alice', three, 'prof', room_id, '200')
        left = by_event['webconf_leave'][0]
        assert (left['login'], left['webconf'], left['owner'], left['status']) == ('prof', room_id, 'prof', '200')
        assert set(by_event) == {'webconf_invite', 'webconf_decline', 'webconf_cancel', 'webconf_accept', 'webconf_leave',
                                 'session_open', 'session_close'}
