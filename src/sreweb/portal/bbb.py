"""The BigBlueButton API of the web conferences (``webconf.py`` holds the rooms): the signed calls
``create``, ``end``, ``getMeetingInfo``, ``isMeetingRunning``, and the join URLs the browsers are
redirected to.

Every call is ``GET <api>/<call>?<query>&checksum=<hex>`` with ``checksum = sha1(call + query +
secret)`` over the query string *as sent* (sha256 / sha512 accepted since BBB 2.5, see
``supportedChecksumAlgorithms`` of bbb-web.properties); the answer is XML, ``<response>
<returncode>SUCCESS|FAILED</returncode><messageKey>…</messageKey><message>…</message>…``.  The
pure helpers (``encode_query``, ``checksum``, ``signed_url``, ``parse_response``,
``meeting_info_of``) build and read those without a network; ``BbbClient`` makes the calls on its
own plain ``aiohttp.ClientSession``: never the portal's session to the agents, which presents the
client certificate of ``[pool]``.  The URL is handed to aiohttp as already encoded (``yarl.URL(…,
encoded=True)``): yarl would otherwise normalise the percent-encoding and the server would sign a
different string (``checksumError`` on every call carrying a ``~`` or a ``%``).

Facts of the API (docs.bigbluebutton.org/development/api/, 2026-11): a ``create`` is idempotent
(a repeat answers SUCCESS with ``duplicateWarning`` and the same ``createTime``); the
``attendeePW`` / ``moderatorPW`` of ``create`` are deprecated since 2.4 (``role`` on ``join``) but
still passed, for the servers before that and for ``end``, which needs the moderator password
before 3.0; ``join`` with ``redirect=true`` answers a 302 to the HTML5 client (what an iframe
``src`` needs) and refuses a ``createTime`` that is not the meeting's; ``end`` is asynchronous
(``sentEndMeetingRequest``); a meeting nobody joined, or everybody left, expires on the server
after a few minutes and ``getMeetingInfo`` then answers FAILED ``notFound``."""
import asyncio
import hashlib
import logging
import urllib.parse
from dataclasses import dataclass
from xml.etree import ElementTree

import aiohttp
import yarl

log = logging.getLogger('sreweb.portal')

ALGORITHMS = {'sha1': hashlib.sha1, 'sha256': hashlib.sha256, 'sha512': hashlib.sha512}
ROLE_MODERATOR = 'MODERATOR'
ROLE_VIEWER = 'VIEWER'
KEY_NOT_FOUND = 'notFound'
KEY_DUPLICATE = 'duplicateWarning'
KEY_CHECKSUM = 'checksumError'
DEFAULT_TIMEOUT = 10.0        # seconds, per call
MAX_BODY = 1024 * 1024        # bytes of an answer read (a getMeetingInfo lists every attendee)


class BbbError(Exception):
    """A FAILED answer of the server: ``message_key`` (``checksumError``, ``notFound``…) and
    ``message``."""

    def __init__(self, message_key: str, message: str = ''):
        super().__init__(f"{message_key}: {message}" if message else message_key)
        self.message_key = message_key
        self.message = message


class BbbUnavailable(Exception):
    """No usable answer: the server does not answer, answers an HTTP error, or something that is
    not an API answer (the nginx error page)."""


def encode_query(params) -> str:
    """The query string of *params* (a dict or a list of pairs, in order): the ``None`` and empty
    values dropped, the booleans as ``true`` / ``false``, ``urllib.parse.urlencode`` encoding (a
    space as ``+``, like the examples of the API reference)."""
    pairs = []
    for key, value in (params.items() if isinstance(params, dict) else params):
        if value is None or value == '':
            continue
        if isinstance(value, bool):
            value = 'true' if value else 'false'
        pairs.append((key, str(value)))
    return urllib.parse.urlencode(pairs)


def checksum(call: str, query: str, secret: str, algorithm: str = 'sha1') -> str:
    """``hex(algorithm(call + query + secret))``: *query* exactly as it is sent."""
    try:
        digest = ALGORITHMS[algorithm]
    except KeyError:
        raise ValueError(f"unknown checksum algorithm {algorithm!r}") from None
    return digest((call + query + secret).encode('utf-8')).hexdigest()


def signed_url(api_url: str, call: str, params, secret: str, algorithm: str = 'sha1') -> str:
    """``<api_url><call>?<query>&checksum=<hex>``: the query is built once here, and the string
    signed is the string sent."""
    query = encode_query(params)
    digest = checksum(call, query, secret, algorithm)
    return f"{api_url}{call}?{query}{'&' if query else ''}checksum={digest}"


def parse_response(data: bytes) -> dict:
    """The children of ``<response>`` as ``{tag: text}``, the ``attendees`` as a list of
    ``{'user_id', 'fullname', 'role'}``; ``BbbError`` on a FAILED answer, ``BbbUnavailable`` on
    anything that is not an API answer."""
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as e:
        raise BbbUnavailable(f"not an API answer: {e}") from None
    if root.tag != 'response':
        raise BbbUnavailable(f"not an API answer: <{root.tag}>")
    result = {}
    for child in root:
        if child.tag == 'attendees':
            result['attendees'] = [{'user_id': (a.findtext('userID') or '').strip(),
                                    'fullname': (a.findtext('fullName') or '').strip(),
                                    'role': (a.findtext('role') or '').strip()} for a in child.findall('attendee')]
        else:
            result[child.tag] = (child.text or '').strip()
    if 'returncode' not in result:
        raise BbbUnavailable("not an API answer: no returncode")
    if result['returncode'] != 'SUCCESS':
        raise BbbError(result.get('messageKey', ''), result.get('message', ''))
    return result


def _bool(value) -> bool:
    return str(value).strip().lower() == 'true'


def _int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class MeetingInfo:
    """What ``getMeetingInfo`` says of a meeting that exists."""
    running: bool                     # somebody is in (false before the first join)
    has_user_joined: bool             # somebody has ever been in
    has_been_forcibly_ended: bool     # ended by a moderator or by ``end``
    participant_count: int
    moderator_count: int
    create_time: int | None
    attendees: tuple = ()             # of {'user_id', 'fullname', 'role'}


def meeting_info_of(result: dict) -> MeetingInfo:
    return MeetingInfo(running=_bool(result.get('running')), has_user_joined=_bool(result.get('hasUserJoined')),
                       has_been_forcibly_ended=_bool(result.get('hasBeenForciblyEnded')),
                       participant_count=_int(result.get('participantCount')) or 0,
                       moderator_count=_int(result.get('moderatorCount')) or 0,
                       create_time=_int(result.get('createTime')), attendees=tuple(result.get('attendees', ())))


class BbbClient:
    """The calls to one server.  *session*: an ``aiohttp.ClientSession`` to use (the tests);
    without one, ``open()`` creates a plain session (inside the running loop) that ``close()``
    closes."""

    def __init__(self, api_url: str, secret: str, algorithm: str = 'sha1', *, session=None,
                 timeout: float = DEFAULT_TIMEOUT):
        if algorithm not in ALGORITHMS:
            raise ValueError(f"unknown checksum algorithm {algorithm!r}")
        self.api_url = api_url if api_url.endswith('/') else api_url + '/'
        self.secret = secret
        self.algorithm = algorithm
        self.timeout = timeout
        self._session = session
        self._own = False

    def open(self):
        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._own = True

    async def close(self):
        if self._own and self._session is not None:
            await self._session.close()
            self._session = None
            self._own = False

    def url(self, call: str, params) -> str:
        return signed_url(self.api_url, call, params, self.secret, self.algorithm)

    async def _call(self, call: str, params) -> dict:
        self.open()
        url = yarl.URL(self.url(call, params), encoded=True)      # the signed string, untouched
        try:
            async with self._session.get(url, allow_redirects=False,
                                         timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                body = await resp.content.read(MAX_BODY + 1)
                status = resp.status
        except asyncio.TimeoutError:
            raise BbbUnavailable(f"{call}: no answer within {self.timeout:g} s") from None
        except aiohttp.ClientError as e:
            raise BbbUnavailable(f"{call}: {e}") from None
        if status != 200:
            raise BbbUnavailable(f"{call}: HTTP {status}")
        if len(body) > MAX_BODY:
            raise BbbUnavailable(f"{call}: answer too large")
        return parse_response(body)

    async def create(self, meeting_id: str, name: str, *, moderator_pw: str, attendee_pw: str, welcome: str = '',
                     logout_url: str = '', record: bool = False, duration: int = 0, mute_on_start: bool = False,
                     max_participants: int = 0, meta: dict | None = None) -> dict:
        """``{'create_time', 'internal_meeting_id', 'duplicate'}`` (*duplicate*: the meeting
        existed, the answer describes it)."""
        params = [('name', name), ('meetingID', meeting_id), ('attendeePW', attendee_pw), ('moderatorPW', moderator_pw),
                  ('welcome', welcome), ('logoutURL', logout_url), ('record', record),
                  ('duration', duration or None), ('muteOnStart', mute_on_start),
                  ('maxParticipants', max_participants or None)]
        for key, value in sorted((meta or {}).items()):
            params.append((f'meta_{key}', value))
        result = await self._call('create', params)
        return {'create_time': _int(result.get('createTime')), 'internal_meeting_id': result.get('internalMeetingID', ''),
                'duplicate': result.get('messageKey') == KEY_DUPLICATE}

    async def end(self, meeting_id: str, moderator_pw: str = ''):
        """Ask the server to end the meeting (asynchronous on its side)."""
        await self._call('end', [('meetingID', meeting_id), ('password', moderator_pw)])

    async def meeting_info(self, meeting_id: str) -> MeetingInfo | None:
        """``None`` when the server knows no such meeting (never created, or expired)."""
        try:
            result = await self._call('getMeetingInfo', [('meetingID', meeting_id)])
        except BbbError as e:
            if e.message_key == KEY_NOT_FOUND:
                return None
            raise
        return meeting_info_of(result)

    async def is_running(self, meeting_id: str) -> bool:
        return _bool((await self._call('isMeetingRunning', [('meetingID', meeting_id)])).get('running'))

    def join_url(self, meeting_id: str, *, fullname: str, role: str, user_id: str, password: str = '',
                 create_time=None, userdata: dict | None = None) -> str:
        """The URL a browser is sent to (no call here): the client, after a 302 of the server.
        *role* is ``ROLE_MODERATOR`` or ``ROLE_VIEWER`` (BBB >= 2.4), *password* the matching
        password of the meeting for an older server, *userdata* the ``bbb_*`` client settings."""
        params = [('fullName', fullname), ('meetingID', meeting_id), ('role', role), ('password', password),
                  ('createTime', create_time), ('userID', user_id), ('redirect', True)]
        for key, value in sorted((userdata or {}).items()):
            params.append((f'userdata-{key}', value))
        return self.url('join', params)
