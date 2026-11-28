"""Who a web user is, and how the portal tells the agents.

The portal authenticates the browser (LDAP, or an anonymous pseudonym) and adds the identity to
every request it relays to an agent as ``X-SRE-*`` headers, next to the bearer token of the
agent; the browser never sets them.  The agent builds the same ``Identity`` back from the
headers: the login names the owner of the projects (the third ``@@@`` field of a running lab
name, and ``SUDO_USER`` of the ``sre --user`` processes), the full name, e-mail, student group
and language go into ``answers.json`` like the Qt GUI writes them from the session (the group
being the web's own: an attribute of the directory, ``attr_group`` / ``header_group``).

The login must be a valid SRE username (the regex of ``SRE.access.is_valid_username``, repeated
here because the portal does not import ``SRE``).
"""
import base64
import re
from dataclasses import dataclass, replace

ROLE_STUDENT = 'student'
ROLE_INSTRUCTOR = 'instructor'
ROLES = (ROLE_STUDENT, ROLE_INSTRUCTOR)

#: What the user wants to see: the instructor view keeps the instructor() texts and lists every
#: state (instructors only, and only on projects that hold instructor texts).
VIEW_STUDENT = 'student'
VIEW_INSTRUCTOR = 'instructor'
VIEWS = (VIEW_STUDENT, VIEW_INSTRUCTOR)

HEADER_LOGIN = 'X-SRE-Login'
HEADER_ROLE = 'X-SRE-Role'
HEADER_LANGUAGE = 'X-SRE-Language'
HEADER_FULLNAME = 'X-SRE-Fullname'
HEADER_EMAIL = 'X-SRE-Email'
HEADER_VIEW = 'X-SRE-View'
HEADER_ANONYMOUS = 'X-SRE-Anonymous'
HEADER_GROUP = 'X-SRE-Group'
HEADER_ADMINISTRATOR = 'X-SRE-Administrator'
#: Set by the portal alone, on the requests about one project: the caller is a student the
#: owner of that project let in (a shared project, ``sreweb/portal/sharing.py``).
HEADER_PARTICIPANT = 'X-SRE-Participant'
#: The key of the agent's ``/v1/status`` listing its running lab names.  An agent that sends it
#: knows the participants (an older one refuses them: its projects are not offered for sharing),
#: and the portal learns from it that a shared project is gone.
STATUS_PROJECT_NAMES = 'project_names'
#: The keys of the agent's ``/v1/status`` telling the container engines its host allows, the
#: default one first, and that default: what the Pool page shows and what the placement of a
#: project looks at.  An agent that sends none (an older one) is a host whose engines are not
#: known: it is never left out for its engines.
STATUS_ENGINES = 'engines'
STATUS_DEFAULT_ENGINE = 'default_engine'
#: The container engines (``SRE.params.container_engines``, which the portal does not import;
#: kept equal by tests/test_web_identity.py).
CONTAINER_ENGINES = ('kathara', 'podman')
#: The key of a lab entry of ``GET /v1/labs`` listing the engines the lab accepts (a lab that
#: says nothing accepts them all), and the field of a start naming the engine of the project.
LAB_ENGINES_KEY = 'engines'
START_ENGINE_KEY = 'engine'

#: Same as SRE.access._VALID_USERNAME (checked by tests/test_web_identity.py).
VALID_LOGIN = re.compile(r'^[a-zA-Z0-9._-]+$')
MAX_LOGIN_LENGTH = 64
MAX_GROUP_LENGTH = 64
_LANGUAGE = re.compile(r'^[a-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})?$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')


#: Same as params.running_lab_name_match_pattern: <timestamp>@@@<lab>@@@<owner>.
RUNNING_LAB_NAME = re.compile(r'^([0-9]+)@@@(.+)@@@(.+)$')


class IdentityError(ValueError):
    """The headers do not describe a valid identity."""


def request_key(name: str = 'identity'):
    """A key of the per-request storage of aiohttp (``request[IDENTITY_KEY]``, the extra fields
    of the connection log): a typed ``web.RequestKey`` when the installed aiohttp has it, the
    plain name otherwise."""
    try:
        from aiohttp.web import RequestKey
    except ImportError:
        return name
    return RequestKey(name, object)


IDENTITY_KEY = request_key()


def running_lab_name_owner(rln: str) -> str | None:
    """The owner of a running lab name, ``None`` when the name is malformed."""
    if not rln or '/' in rln or '\\' in rln:
        return None
    m = RUNNING_LAB_NAME.match(rln)
    return m.group(3) if m else None


def is_valid_login(login: str) -> bool:
    return bool(login) and len(login) <= MAX_LOGIN_LENGTH and bool(VALID_LOGIN.match(login))


def clean_group(value) -> str:
    """A student group as the directory or the proxy gives it, as it is kept: control
    characters dropped, blanks trimmed, capped at ``MAX_GROUP_LENGTH`` (``''`` for ``None``)."""
    text = _CONTROL.sub('', str(value or '')).strip()
    return text[:MAX_GROUP_LENGTH].strip()


def encode_header_text(text: str) -> str:
    """A UTF-8 text in a header: base64 (headers are Latin-1 at best)."""
    return base64.b64encode((text or '').encode('utf-8')).decode('ascii')


def decode_header_text(value: str) -> str:
    try:
        return base64.b64decode((value or '').encode('ascii'), validate=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise IdentityError("undecodable header text") from None


@dataclass(frozen=True)
class Identity:
    login: str
    fullname: str = ''
    email: str = ''
    role: str = ROLE_STUDENT
    language: str = 'en'
    anonymous: bool = False
    view: str = VIEW_STUDENT
    group: str = ''                 # the student group ('' = unknown)
    # an instructor who may browse the connection log (the History page of the portal): never
    # true for a student, whatever the configuration says (with_administrator applies the rule)
    administrator: bool = False
    # a student taking part in the project of the request, which its owner shares with them:
    # said by the portal request by request (never kept in a session), read by the agent,
    # which then serves them as it serves the owner but for the close and the save
    participant: bool = False

    def __post_init__(self):
        if not is_valid_login(self.login):
            raise IdentityError(f"invalid login {self.login!r}")
        if self.role not in ROLES:
            raise IdentityError(f"invalid role {self.role!r}")
        if self.view not in VIEWS:
            raise IdentityError(f"invalid view {self.view!r}")
        if self.view == VIEW_INSTRUCTOR and self.role != ROLE_INSTRUCTOR:
            raise IdentityError("the instructor view needs the instructor role")
        if self.administrator and self.role != ROLE_INSTRUCTOR:
            raise IdentityError("an administrator must be an instructor")
        if self.participant and self.role == ROLE_INSTRUCTOR:
            raise IdentityError("an instructor is never a participant")
        if not _LANGUAGE.match(self.language or ''):
            raise IdentityError(f"invalid language {self.language!r}")

    @property
    def is_instructor(self) -> bool:
        return self.role == ROLE_INSTRUCTOR

    @property
    def instructor_view(self) -> bool:
        return self.view == VIEW_INSTRUCTOR

    def with_view(self, view: str) -> 'Identity':
        return replace(self, view=view)

    def as_participant(self) -> 'Identity':
        """The identity on a request about a project shared with this user."""
        return replace(self, participant=True)

    def with_administrator(self, granted: bool) -> 'Identity':
        """The identity with the administrator flag when *granted* and the user is an instructor
        (a student never gets it: the one place the rule is applied)."""
        return replace(self, administrator=bool(granted) and self.is_instructor)

    def headers(self) -> dict:
        """The ``X-SRE-*`` headers the portal adds to a request relayed to an agent."""
        return {
            HEADER_LOGIN: self.login,
            HEADER_ROLE: self.role,
            HEADER_LANGUAGE: self.language,
            HEADER_FULLNAME: encode_header_text(self.fullname),
            HEADER_EMAIL: encode_header_text(self.email),
            HEADER_VIEW: self.view,
            HEADER_ANONYMOUS: '1' if self.anonymous else '0',
            HEADER_GROUP: encode_header_text(self.group),
            HEADER_ADMINISTRATOR: '1' if self.administrator else '0',
            HEADER_PARTICIPANT: '1' if self.participant else '0',
        }

    @classmethod
    def from_headers(cls, headers) -> 'Identity':
        """The identity of a relayed request (*headers*: any mapping with case-insensitive
        ``get``, like ``aiohttp``'s); ``IdentityError`` when absent or invalid."""
        login = headers.get(HEADER_LOGIN, '')
        if not login:
            raise IdentityError(f"missing {HEADER_LOGIN} header")
        return cls(
            login=login,
            fullname=decode_header_text(headers.get(HEADER_FULLNAME, '')),
            email=decode_header_text(headers.get(HEADER_EMAIL, '')),
            role=headers.get(HEADER_ROLE, ROLE_STUDENT) or ROLE_STUDENT,
            language=headers.get(HEADER_LANGUAGE, 'en') or 'en',
            anonymous=headers.get(HEADER_ANONYMOUS, '0') == '1',
            view=headers.get(HEADER_VIEW, VIEW_STUDENT) or VIEW_STUDENT,
            group=decode_header_text(headers.get(HEADER_GROUP, '')),
            administrator=headers.get(HEADER_ADMINISTRATOR, '0') == '1',
            participant=headers.get(HEADER_PARTICIPANT, '0') == '1',
        )

    def to_dict(self) -> dict:
        """What the browser is told about itself (``GET /api/me``), and what the session cookie
        keeps: never ``participant``, which belongs to one request."""
        return {'login': self.login, 'fullname': self.fullname, 'email': self.email, 'role': self.role,
                'language': self.language, 'anonymous': self.anonymous, 'group': self.group,
                'administrator': self.administrator}
