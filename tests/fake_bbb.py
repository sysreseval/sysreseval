"""A fake BigBlueButton server for the tests of the web conferences: an aiohttp server on a
loopback port answering the API calls of ``sreweb.portal.bbb`` as the real one does (the
checksum verified over the raw query string, the XML answers, a ``create`` idempotent, a ``join``
answering a 302 to a small fake client page whose *Leave meeting* link goes to the meeting's
``logoutURL``), with knobs for the tests: ``expire()`` (the meeting gone, as after nobody joined
for a while), ``force_end()`` (ended by a moderator from the client), ``join_as()`` (an attendee
seen by ``getMeetingInfo``), ``fail_next`` (an HTTP status or an XML / HTML body to answer the
next call), ``delay`` (seconds before every answer)."""
import asyncio
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

from aiohttp import web
from aiohttp.test_utils import TestServer

API_PATH = '/bigbluebutton/api/'
CLIENT_PATH = '/html5client/join'


@dataclass
class FakeMeeting:
    meeting_id: str
    name: str
    create_time: int
    attendee_pw: str
    moderator_pw: str
    params: dict
    internal_id: str = field(default_factory=lambda: secrets.token_hex(20))
    attendees: list = field(default_factory=list)       # {'user_id', 'fullname', 'role'}
    has_user_joined: bool = False
    forcibly_ended: bool = False


def xml_response(fields: list, attendees: list | None = None) -> web.Response:
    parts = ['<response>']
    for key, value in fields:
        parts.append(f"<{key}>{escape(str(value))}</{key}>")
    if attendees is not None:
        parts.append('<attendees>')
        for a in attendees:
            parts.append(f"<attendee><userID>{escape(a['user_id'])}</userID><fullName>{escape(a['fullname'])}</fullName>"
                         f"<role>{escape(a['role'])}</role></attendee>")
        parts.append('</attendees>')
    parts.append('</response>')
    return web.Response(text=''.join(parts), content_type='text/xml')


def failed(key: str, message: str) -> web.Response:
    return xml_response([('returncode', 'FAILED'), ('messageKey', key), ('message', message)])


class FakeBbbServer:
    def __init__(self, secret='sekret', algorithm='sha1'):
        self.secret = secret
        self.algorithm = algorithm
        self.calls = []            # (call, {param: value}) in order, the checksum left out
        self.meetings: dict[str, FakeMeeting] = {}
        self.fail_next = []        # (call or '*', HTTP status or bytes body) answered to the next matching call
        self.delay = 0.0
        self.server = None

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.port}"

    @property
    def url(self) -> str:
        return self.origin + API_PATH

    async def start(self):
        app = web.Application()
        app.router.add_get(API_PATH + '{call}', self.handle)
        app.router.add_get(CLIENT_PATH, self.client_page)
        self.server = TestServer(app)
        await self.server.start_server()
        return self

    async def close(self):
        if self.server is not None:
            await self.server.close()
            self.server = None

    # -- the knobs --------------------------------------------------------------------------------

    def expire(self, meeting_id: str):
        self.meetings.pop(meeting_id, None)

    def force_end(self, meeting_id: str):
        self.meetings[meeting_id].forcibly_ended = True

    def join_as(self, meeting_id: str, user_id: str, fullname: str, role: str = 'VIEWER'):
        meeting = self.meetings[meeting_id]
        meeting.attendees.append({'user_id': user_id, 'fullname': fullname, 'role': role})
        meeting.has_user_joined = True

    def calls_of(self, call: str) -> list:
        return [params for name, params in self.calls if name == call]

    # -- the API ----------------------------------------------------------------------------------

    async def handle(self, request):
        call = request.match_info['call']
        raw = request.rel_url.raw_query_string      # as received: what the real server signs
        if '&checksum=' in raw:
            query = raw[:raw.rindex('&checksum=')]
        elif raw.startswith('checksum='):
            query = ''
        else:
            query = raw
        params = {k: v for k, v in request.query.items() if k != 'checksum'}
        self.calls.append((call, params))
        if self.delay:
            await asyncio.sleep(self.delay)
        expected = hashlib.new(self.algorithm, (call + query + self.secret).encode('utf-8')).hexdigest()
        if not hmac.compare_digest(request.query.get('checksum', ''), expected):
            return failed('checksumError', 'Checksums do not match')
        if self.fail_next and self.fail_next[0][0] in (call, '*'):
            _, answer = self.fail_next.pop(0)
            if isinstance(answer, int):
                return web.Response(status=answer, text='<html><body>error</body></html>', content_type='text/html')
            return web.Response(body=answer, content_type='text/xml')
        handler = getattr(self, f'call_{call}', None)
        if handler is None:
            return failed('unsupportedRequest', f"This request is not supported: {call}")
        return handler(params)

    def call_create(self, params):
        meeting_id = params.get('meetingID', '')
        name = params.get('name', '')
        if not meeting_id or not name:
            return failed('missingParamMeetingID', 'You must specify a meeting ID and a name')
        meeting = self.meetings.get(meeting_id)
        fields = [('returncode', 'SUCCESS')]
        if meeting is None:
            meeting = FakeMeeting(meeting_id, name, int(time.time() * 1000), params.get('attendeePW') or secrets.token_hex(4),
                                  params.get('moderatorPW') or secrets.token_hex(4), dict(params))
            self.meetings[meeting_id] = meeting
            message = [('messageKey', ''), ('message', '')]
        else:
            message = [('messageKey', 'duplicateWarning'),
                       ('message', 'This conference was already in existence and may currently be in progress.')]
        fields += [('meetingID', meeting.meeting_id), ('internalMeetingID', meeting.internal_id),
                   ('parentMeetingID', 'bbb-none'), ('attendeePW', meeting.attendee_pw), ('moderatorPW', meeting.moderator_pw),
                   ('createTime', meeting.create_time), ('voiceBridge', '70000'), ('dialNumber', '613-555-1234'),
                   ('createDate', 'now'), ('hasUserJoined', str(meeting.has_user_joined).lower()),
                   ('duration', meeting.params.get('duration', '0')),
                   ('hasBeenForciblyEnded', str(meeting.forcibly_ended).lower())] + message
        return xml_response(fields)

    def call_join(self, params):
        meeting = self.meetings.get(params.get('meetingID', ''))
        if meeting is None:
            return failed('notFound', 'A meeting with that ID does not exist')
        if not params.get('fullName'):
            return failed('missingParamFullName', 'You must specify a name for the attendee who will be joining the meeting.')
        create_time = params.get('createTime')
        if create_time and create_time != str(meeting.create_time):
            return failed('mismatchCreateTimeParam', 'The createTime parameter submitted mismatches with the current meeting.')
        role = params.get('role', '').upper()
        if not role:
            password = params.get('password', '')
            if password == meeting.moderator_pw:
                role = 'MODERATOR'
            elif password == meeting.attendee_pw:
                role = 'VIEWER'
            else:
                return failed('invalidPassword', 'You either did not supply a password or the password supplied is neither the attendee or moderator password for this conference.')
        if role not in ('MODERATOR', 'VIEWER'):
            return failed('invalidRole', 'The role parameter must be MODERATOR or VIEWER.')
        meeting.attendees.append({'user_id': params.get('userID', ''), 'fullname': params['fullName'], 'role': role})
        meeting.has_user_joined = True
        token = secrets.token_hex(8)
        raise web.HTTPFound(f"{self.origin}{CLIENT_PATH}?sessionToken={token}&meetingID={meeting.meeting_id}")

    def call_end(self, params):
        meeting = self.meetings.get(params.get('meetingID', ''))
        if meeting is None:
            return failed('notFound', 'We could not find a meeting with that meeting ID - perhaps the meeting is not yet running?')
        password = params.get('password')
        if password and password != meeting.moderator_pw:
            return failed('invalidPassword', 'You must supply the moderator password for this call.')
        del self.meetings[meeting.meeting_id]
        return xml_response([('returncode', 'SUCCESS'), ('messageKey', 'sentEndMeetingRequest'),
                             ('message', 'A request to end the meeting was sent.')])

    def call_getMeetingInfo(self, params):
        meeting = self.meetings.get(params.get('meetingID', ''))
        if meeting is None:
            return failed('notFound', 'We could not find a meeting with that meeting ID')
        moderators = sum(1 for a in meeting.attendees if a['role'] == 'MODERATOR')
        return xml_response([('returncode', 'SUCCESS'), ('meetingName', meeting.name), ('meetingID', meeting.meeting_id),
                             ('internalMeetingID', meeting.internal_id), ('createTime', meeting.create_time),
                             ('createDate', 'now'), ('voiceBridge', '70000'), ('dialNumber', '613-555-1234'),
                             ('attendeePW', meeting.attendee_pw), ('moderatorPW', meeting.moderator_pw),
                             ('running', str(bool(meeting.attendees)).lower()), ('duration', meeting.params.get('duration', '0')),
                             ('hasUserJoined', str(meeting.has_user_joined).lower()), ('recording', 'false'),
                             ('hasBeenForciblyEnded', str(meeting.forcibly_ended).lower()),
                             ('startTime', meeting.create_time), ('endTime', 0),
                             ('participantCount', len(meeting.attendees)), ('listenerCount', 0), ('voiceParticipantCount', 0),
                             ('videoCount', 0), ('maxUsers', meeting.params.get('maxParticipants', '0')),
                             ('moderatorCount', moderators)], attendees=meeting.attendees)

    def call_isMeetingRunning(self, params):
        meeting = self.meetings.get(params.get('meetingID', ''))
        running = meeting is not None and bool(meeting.attendees)
        return xml_response([('returncode', 'SUCCESS'), ('running', str(running).lower())])

    async def client_page(self, request):
        """What the browser lands on after a join: the name of the meeting and the Leave link."""
        meeting = self.meetings.get(request.query.get('meetingID', ''))
        if meeting is None:
            raise web.HTTPNotFound(text="no such meeting")
        logout = meeting.params.get('logoutURL', '')
        return web.Response(content_type='text/html', text=(
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Fake BBB</title></head>'
            f'<body style="margin:0;background:#1a2a3a;color:#fff;font:16px sans-serif">'
            f'<h1 id="meeting-name" style="margin:12px">{escape(meeting.name)}</h1>'
            f'<a id="leave" href="{escape(logout, {chr(34): "&quot;"})}" '
            'style="display:block;position:absolute;inset:0;color:#fff;padding:60px 12px">Leave meeting</a></body></html>'))
