"""Exams of the web front-end: an instructor programs an exam, the students of its audience
see only its projects, with countdowns, until it is over.

The portal is the single source of truth: ``Exams`` holds every exam in memory (the database of
``examstore.py`` behind it, written through at every change and read at startup), computes the
phase of each student and tells the browsers (the presence sockets of ``presentation.Presence``
get ``{"t": "exam", "id", "phase"}`` at every change) and, through ``examprojects.py``, the
agents (the exam object of each exam project).  Pure like ``presentation.py``: no aiohttp, a
clock the tests move.

An ``Exam`` is a title, an audience (explicit logins and the keys of groups, as ``groups.py``
keys them), the labs to do (``ExamLab``: the lab in the ``/`` form of the lab list, with an
optional flavor preset), a duration and/or a window (``start_after``, ``end_before``), two
delays before the start (``lead``: the other projects hidden and the countdown shown;
``pre_start``: the exam projects started in the background), the networks the students'
browsers must come from (none = anywhere) and the period of the evaluations the agents run.
Every student has an individual clock (``Member.started_at``): it starts when their exam
projects are all created and the start has passed (``observe``), and their end is
``min(started + duration, end_before)`` plus the minutes an instructor adds to them, capped by
an *End now*.  The phases of a student, in order: ``scheduled`` (before the lead; the exam does
not bind them), ``waiting`` (the lead window: countdown to the start, the exam projects started
from ``prestart_at``), ``starting`` (the start passed, their projects not all created yet),
``active``, ``ended`` (the banner, until they dismiss it), ``done`` (dismissed: unbound again,
their exam projects hidden until closed) and ``past`` (never started, the exam over: unbound).
"""
import asyncio
import contextlib
import logging
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Iterable

from .accessdb import HistoryError
from .groups import department_member
from .presentation import Presence, parse_audience
from ..config import ExamsConfig, ConfigError, client_allowed, parse_networks
from ..identity import Identity, is_valid_login

log = logging.getLogger('sreweb.portal')

PHASE_SCHEDULED = 'scheduled'
PHASE_WAITING = 'waiting'
PHASE_STARTING = 'starting'
PHASE_ACTIVE = 'active'
PHASE_ENDED = 'ended'
PHASE_DONE = 'done'
PHASE_PAST = 'past'
#: The phases in which an exam binds a student (only its projects, the countdowns, the banner).
BINDING_PHASES = frozenset({PHASE_WAITING, PHASE_STARTING, PHASE_ACTIVE, PHASE_ENDED})
#: The phases in which a student may open their exam projects.
OPEN_PHASES = frozenset({PHASE_ACTIVE})
#: The phases in which a student may start (the browser starts) their exam projects.
START_PHASES = frozenset({PHASE_WAITING, PHASE_STARTING, PHASE_ACTIVE})
STATUS_SCHEDULED, STATUS_RUNNING, STATUS_PAST = 'scheduled', 'running', 'past'

TICK = 1.0                      # the phase loop
MEMBERSHIPS_REFRESH = 10.0      # the tick refreshes the group memberships at most this often
DIRTY_RETRY = 10.0              # a write the database refused is tried again this often
MAX_TITLE = 200
MAX_LABS = 20
MAX_NETWORKS = 50
MAX_MINUTES = 7 * 24 * 60       # a duration, a delay, an extra time
MAX_EVAL_INTERVAL = 86400
FLAVOR_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

#: The reasons a project call of a student is refused (the 403 texts).
REASON_NOT_STARTED = "the exam has not started yet"
REASON_OVER = "the exam is over"
REASON_OTHER_LAB = "exam in progress: only the exam labs are available"
REASON_ADDRESS = "exam: your address {address} is not allowed for this exam"


def normal_lab(name) -> str:
    """The ``/`` form of a lab name (the lab list, the exams) from the ``@`` form of ``info.json``
    and of the running lab names (``sre@dhcp.py`` -> ``sre/dhcp.py``)."""
    return str(name or '').replace('@', '/')


def lab_of_rln(rln) -> str | None:
    """The lab of a running lab name, in the ``/`` form; ``None`` when malformed."""
    parts = str(rln or '').split('@@@')
    return normal_lab(parts[1]) if len(parts) == 3 and parts[1] else None


def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec='seconds')


def _minutes(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds / 60, 3)


# -- the model ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class ExamLab:
    """A lab of an exam: its name in the ``/`` form and, optionally, the name of a preset of
    its ``Flavor`` class (``sre set-exam --labs lab:preset``)."""
    lab: str
    flavor: str | None = None

    def to_dict(self) -> dict:
        return {'lab': self.lab, 'flavor': self.flavor}

    @classmethod
    def parse(cls, value) -> 'ExamLab':
        if isinstance(value, str):
            value = {'lab': value}
        if not isinstance(value, dict):
            raise ValueError("a lab must be a name or an object {lab, flavor}")
        lab = value.get('lab')
        if not isinstance(lab, str) or not lab.strip():
            raise ValueError("a lab name is required")
        lab = lab.strip()
        if '@' in lab or lab.startswith('/') or any(part in ('', '.', '..') for part in lab.split('/')) \
                or not lab.isprintable() or len(lab) > MAX_TITLE:
            raise ValueError(f"invalid lab name {lab!r}")
        flavor = value.get('flavor')
        if flavor is not None:
            if not isinstance(flavor, str):
                raise ValueError(f"the flavor of {lab} must be a preset name")
            flavor = flavor.strip() or None
            if flavor is not None and not FLAVOR_RE.match(flavor):
                raise ValueError(f"invalid flavor preset {flavor!r} for {lab}")
        return cls(lab, flavor)


@dataclass
class Member:
    """A student of an exam as the portal knows them: created when they first bind to it, when
    their projects are first observed, or when an instructor adjusts them."""
    login: str
    first_seen: float | None = None
    started_at: float | None = None             # the individual clock
    ended_at: float | None = None               # "End now" for a selection of students
    extra_minutes: int = 0
    labs: list | None = None                    # [ExamLab] replacing the exam's for this student
    dismissed_at: float | None = None
    projects: dict = field(default_factory=dict)    # lab -> {'host', 'rln', 'synced': [started_at, end_at] | None}
    orphans: list = field(default_factory=list)     # [{'host', 'rln'}]: exam projects of labs no longer theirs
    address: str = ''                           # the last address seen (for the instructors)

    def to_dict(self) -> dict:
        return {'login': self.login, 'first_seen': self.first_seen, 'started_at': self.started_at,
                'ended_at': self.ended_at, 'extra_minutes': self.extra_minutes,
                'labs': None if self.labs is None else [l.to_dict() for l in self.labs],
                'dismissed_at': self.dismissed_at, 'address': self.address,
                'projects': {lab: dict(p) for lab, p in self.projects.items()}, 'orphans': list(self.orphans)}


@dataclass(eq=False)
class Exam:
    id: int                                     # 0 until the store gave one
    title: str
    created_by: str
    created_at: float
    updated_at: float
    logins: set
    groups: set
    labs: list                                  # [ExamLab]
    duration: float | None                      # seconds
    start_after: float | None                   # epoch; None = from the creation
    end_before: float | None                    # epoch
    lead: float                                 # seconds before start_after
    pre_start: float                            # seconds before start_after
    networks: list                              # ipaddress networks; [] = anywhere
    eval_interval: float                        # seconds
    ended_at: float | None = None               # "End now" for everybody
    members: dict = field(default_factory=dict)     # login -> Member
    memberships: object = field(default=None, repr=False)

    # -- the audience ---------------------------------------------------------------------------

    def includes(self, login: str, department: str = '') -> bool:
        """Whether *login* is in the audience: by login, or by one of the groups (the department
        by the group string of the identity, the others by the memberships the portal knows)."""
        if login in self.logins:
            return True
        if not self.groups:
            return False
        if self.memberships is not None:
            return self.memberships.is_member(login, self.groups, department=department)
        return department_member(department, self.groups)

    def member(self, login: str, *, create: bool = False) -> Member | None:
        m = self.members.get(login)
        if m is None and create:
            m = self.members[login] = Member(login)
        return m

    def labs_of(self, login: str | None) -> list:
        m = self.members.get(login) if login else None
        return m.labs if m is not None and m.labs is not None else self.labs

    def lab_names(self, login: str | None) -> set:
        return {l.lab for l in self.labs_of(login)}

    def flavor_of(self, login: str | None, lab: str) -> str | None:
        return next((l.flavor for l in self.labs_of(login) if l.lab == lab), None)

    # -- the clock ------------------------------------------------------------------------------

    def hide_at(self) -> float | None:
        """When the other projects of the students are hidden (the lead window opens)."""
        return None if self.start_after is None else self.start_after - self.lead

    def prestart_at(self) -> float | None:
        """When the exam projects may be started in the background."""
        return None if self.start_after is None else self.start_after - self.pre_start

    def end_at(self, member: Member | None) -> float | None:
        """The end of a student's exam: ``min(started + duration, end_before)`` plus their extra
        minutes, capped by an *End now* (of everybody or of them); ``None`` until their clock
        started."""
        if member is None or member.started_at is None:
            return None
        end = math.inf
        if self.duration is not None:
            end = member.started_at + self.duration
        if self.end_before is not None:
            end = min(end, self.end_before)
        if end == math.inf:
            return None
        end += member.extra_minutes * 60
        for cap in (self.ended_at, member.ended_at):
            if cap is not None:
                end = min(end, cap)
        return end

    def phase(self, member: Member | None, now: float) -> str:
        if self.start_after is not None and now < self.start_after - self.lead:
            return PHASE_SCHEDULED
        end = self.end_at(member)
        if end is not None and now >= end:
            if member.dismissed_at is not None and member.dismissed_at >= end:
                return PHASE_DONE
            return PHASE_ENDED
        if member is not None and member.started_at is not None:
            return PHASE_ACTIVE
        if self.ended_at is not None or (self.end_before is not None and now >= self.end_before):
            return PHASE_PAST          # never started, and over (an End now, the window closed)
        if self.start_after is not None and now < self.start_after:
            return PHASE_WAITING
        return PHASE_STARTING

    def may_start(self, member: Member | None, now: float) -> bool:
        """Whether a student's exam clock may start now: the start passed and their exam
        projects all created (``Member.projects``)."""
        if member is None or member.started_at is not None:
            return False
        if self.start_after is not None and now < self.start_after:
            return False
        labs = self.lab_names(member.login)
        return bool(labs) and labs <= set(member.projects)

    def status(self, now: float) -> str:
        """For the listing: ``scheduled`` before the start, ``past`` once ended for everybody
        (an *End now*, or the window closed and nobody still running), ``running`` otherwise."""
        if self.ended_at is not None:
            return STATUS_PAST
        if self.start_after is not None and now < self.start_after:
            return STATUS_SCHEDULED
        if self.end_before is not None and now >= self.end_before:
            if all((end := self.end_at(m)) is None or now >= end for m in self.members.values()):
                return STATUS_PAST
        return STATUS_RUNNING

    def start_at(self) -> float:
        return self.start_after if self.start_after is not None else self.created_at

    def to_dict(self, now: float, members: int = 0) -> dict:
        """The summary of the instructors' listing (minutes in the API, epoch seconds for the
        instants)."""
        return {'id': self.id, 'title': self.title, 'created_by': self.created_by, 'created_at': self.created_at,
                'status': self.status(now),
                'audience': {'logins': sorted(self.logins), 'groups': sorted(self.groups)},
                'labs': [l.to_dict() for l in self.labs], 'duration': _minutes(self.duration),
                'start_after': self.start_after, 'end_before': self.end_before,
                'lead': _minutes(self.lead), 'pre_start': _minutes(self.pre_start),
                'networks': [str(n) for n in self.networks], 'eval_interval': self.eval_interval,
                'ended_at': self.ended_at, 'members': members, 'start_at': self.start_at(),
                'prestart_at': self.prestart_at(), 'hide_at': self.hide_at()}


class ExamRefused(Exception):
    """A project call refused by the exam rules (the routes answer 403 with the reason)."""


# -- the requests ------------------------------------------------------------------------------

def _parse_time(value, key: str) -> float | None:
    """An instant of a request: epoch seconds (a number), or an ISO 8601 string; ``None``
    for null / ''."""
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        raise ValueError(f"{key} must be a time")
    if isinstance(value, (int, float)):
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{key} must be a time")
        return float(value)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.strip())
        except ValueError:
            raise ValueError(f"{key} must be a time (ISO 8601 or epoch seconds)") from None
        return dt.timestamp()
    raise ValueError(f"{key} must be a time")


def _parse_minutes(value, key: str, *, nullable: bool = False, minimum: float = 0.0) -> float | None:
    """Minutes of a request as seconds."""
    if value is None or value == '':
        if nullable:
            return None
        raise ValueError(f"{key} is required")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{key} must be a number of minutes")
    if value < minimum or value > MAX_MINUTES:
        raise ValueError(f"{key} must be between {minimum:g} and {MAX_MINUTES} minutes")
    return float(value) * 60


def parse_labs(value, known_labs: set | None = None) -> list:
    """The labs of an exam: a non-empty list of names or ``{lab, flavor}`` objects, distinct, each
    one of *known_labs* when given (the lab list of the pool)."""
    if not isinstance(value, list) or not value:
        raise ValueError("at least one lab is required")
    if len(value) > MAX_LABS:
        raise ValueError(f"at most {MAX_LABS} labs")
    labs = [ExamLab.parse(v) for v in value]
    names = [l.lab for l in labs]
    if len(set(names)) != len(names):
        raise ValueError("a lab is listed twice")
    if known_labs is not None:
        unknown = [n for n in names if n not in known_labs]
        if unknown:
            raise ValueError(f"unknown lab {unknown[0]!r}")
    return labs


def parse_exam(body, *, cfg: ExamsConfig, now: float, known_labs: set | None = None,
               current: Exam | None = None) -> dict:
    """The definition of an exam from a request body: the fields of ``Exam`` in their internal
    units (seconds, epoch, ``ipaddress`` networks).  With *current* (an edit) the fields the body
    leaves out keep their value; without it the delays and the interval default to *cfg*.
    ``ValueError`` names the first problem."""
    if not isinstance(body, dict):
        raise ValueError("a JSON object is expected")
    fields = {}
    given = body.__contains__
    if given('title') or current is None:
        title = body.get('title')
        if not isinstance(title, str) or not title.strip():
            raise ValueError("a title is required")
        title = ' '.join(title.split())
        if len(title) > MAX_TITLE:
            raise ValueError(f"the title is limited to {MAX_TITLE} characters")
        fields['title'] = title
    if given('audience') or current is None:
        logins, groups = parse_audience(body.get('audience'), '')
        if not logins and not groups:
            raise ValueError("the audience is empty: give logins and/or groups")
        fields['logins'], fields['groups'] = logins, groups
    if given('labs') or current is None:
        fields['labs'] = parse_labs(body.get('labs'), known_labs)
    if given('duration') or current is None:
        fields['duration'] = _parse_minutes(body.get('duration'), 'duration', nullable=True, minimum=1)
    for key in ('start_after', 'end_before'):
        if given(key) or current is None:
            fields[key] = _parse_time(body.get(key), key)
    for key, default in (('lead', cfg.lead), ('pre_start', cfg.pre_start)):
        if given(key):
            fields[key] = _parse_minutes(body.get(key), key, nullable=True)
            if fields[key] is None:
                fields[key] = default
        elif current is None:
            fields[key] = default
    if given('networks') or current is None:
        values = body.get('networks', [])
        if values is None:
            values = []
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError("networks must be a list of addresses or networks")
        values = [v.strip() for v in values if v.strip()]
        if len(values) > MAX_NETWORKS:
            raise ValueError(f"at most {MAX_NETWORKS} networks")
        try:
            fields['networks'] = parse_networks(values, 'networks')
        except ConfigError as e:
            raise ValueError(str(e)) from None
    if given('eval_interval'):
        value = body.get('eval_interval')
        if value is None or value == '':
            value = cfg.eval_interval
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= MAX_EVAL_INTERVAL:
            raise ValueError(f"eval_interval must be between 1 and {MAX_EVAL_INTERVAL} seconds")
        fields['eval_interval'] = float(value)
    elif current is None:
        fields['eval_interval'] = cfg.eval_interval
    merged = dict(fields)
    if current is not None:
        for key in ('title', 'logins', 'groups', 'labs', 'duration', 'start_after', 'end_before', 'lead', 'pre_start',
                    'networks', 'eval_interval'):
            merged.setdefault(key, getattr(current, key))
    if merged['duration'] is None and merged['end_before'] is None:
        raise ValueError("a duration or an end time is required")
    if merged['end_before'] is not None and merged['end_before'] <= now and (current is None or given('end_before')):
        raise ValueError("the end time is in the past")
    if merged['start_after'] is not None and merged['end_before'] is not None \
            and merged['end_before'] <= merged['start_after']:
        raise ValueError("the end must come after the start")
    return merged


def parse_selection(body) -> tuple:
    """``(everybody, logins, groups)`` of an action on some students of an exam: ``{"all": true}``,
    or ``{"logins": [...], "groups": [...]}`` (``parse_audience``); ``ValueError`` when neither."""
    if not isinstance(body, dict):
        raise ValueError("a JSON object is expected")
    if body.get('all') is True:
        return True, set(), set()
    logins, groups = parse_audience({'logins': body.get('logins', []), 'groups': body.get('groups', [])}, '')
    if not logins and not groups:
        raise ValueError("select students (logins and/or groups) or all")
    return False, logins, groups


def parse_extra_minutes(value) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
            or value != int(value) or abs(value) > MAX_MINUTES or value == 0:
        raise ValueError(f"extra_minutes must be a whole number of minutes, at most {MAX_MINUTES}, not 0")
    return int(value)


# -- the registry ------------------------------------------------------------------------------

class Exams:
    """The exams, what the students' browsers were told (``shown``: login -> (exam id, phase))
    and the store behind (``examstore.ExamStore`` or ``None``: in memory only).  *clock*
    (``time.time``) is the time of every phase (the tests move it)."""

    def __init__(self, presence: Presence, store=None, *, memberships=None, clock=time.time,
                 cfg: ExamsConfig | None = None):
        self.presence = presence
        self.store = store
        self.memberships = memberships
        self.clock = clock
        self.cfg = cfg if cfg is not None else ExamsConfig()
        self._exams: dict[int, Exam] = {}
        self.shown: dict[str, tuple] = {}
        self.loaded = store is None
        self._dirty: set = set()            # (exam id, login or None): a write the database refused
        self._warned: set = set()
        self._next_id = 1                   # the ids without a store
        self._last_refresh = 0.0
        self._last_retry = 0.0
        self._last_purge = 0.0
        self.on_tick: list[Callable[[float], Awaitable[None]]] = []
        self._task: asyncio.Task | None = None

    def _at(self, now: float | None) -> float:
        """The time of an operation: *now*, or the clock's, truncated to the millisecond like
        the ``DATETIME(3)`` columns of the store (what is read back is what was kept)."""
        if now is None:
            now = self.clock()
        return math.floor(now * 1000) / 1000

    # -- queries --------------------------------------------------------------------------------

    def get(self, exam_id) -> Exam | None:
        try:
            return self._exams.get(int(exam_id))
        except (TypeError, ValueError):
            return None

    def _require(self, exam_id) -> Exam:
        exam = self.get(exam_id)
        if exam is None:
            raise KeyError(exam_id)
        return exam

    def listing(self) -> list:
        return sorted(self._exams.values(), key=lambda e: (e.start_at(), e.id))

    def exams_of(self, login: str, department: str = '') -> list:
        """Every exam whose audience includes *login*."""
        return [e for e in self.listing() if e.includes(login, department)]

    def for_login(self, login: str, department: str = '', now: float | None = None) -> tuple | None:
        """``(exam, member, phase)`` of the exam binding *login* now (the earliest started one
        when several do), ``None`` when none does.  *member* may be ``None`` (no record yet)."""
        now = self._at(now)
        best = None
        for exam in self.exams_of(login, department):
            member = exam.members.get(login)
            phase = exam.phase(member, now)
            if phase in BINDING_PHASES:
                key = (exam.start_at(), exam.id)
                if best is None or key < best[0]:
                    best = (key, exam, member, phase)
        return None if best is None else best[1:]

    def exam_project(self, login: str, rln: str) -> tuple | None:
        """``(exam, member)`` of the exam that recorded *rln* as an exam project of *login*."""
        for exam in self._exams.values():
            m = exam.members.get(login)
            if m is not None and any(p.get('rln') == rln for p in m.projects.values()):
                return exam, m
        return None

    def project_access(self, login: str, department: str, rln: str, now: float | None = None) -> tuple:
        """``(allowed, reason)`` for a student's call on their project *rln*: during an exam only
        its labs, once it is active for them; an exam project of an exam over for them stays
        refused until it is closed."""
        now = self._at(now)
        binding = self.for_login(login, department, now)
        if binding is not None:
            exam, member, phase = binding
            if lab_of_rln(rln) not in exam.lab_names(login):
                return False, REASON_OTHER_LAB
            if phase == PHASE_ENDED:
                return False, REASON_OVER
            if phase not in OPEN_PHASES:
                return False, REASON_NOT_STARTED
            return True, ''
        if self.exam_project(login, rln) is not None:
            return False, REASON_OVER
        return True, ''

    def start_access(self, login: str, department: str, lab: str, now: float | None = None) -> tuple:
        """``(allowed, reason)`` for a student starting a project of *lab*: during an exam only
        its labs, from ``prestart_at`` on."""
        now = self._at(now)
        binding = self.for_login(login, department, now)
        if binding is None:
            return True, ''
        exam, member, phase = binding
        if lab not in exam.lab_names(login):
            return False, REASON_OTHER_LAB
        if phase == PHASE_ENDED:
            return False, REASON_OVER
        if phase not in START_PHASES:
            return False, REASON_NOT_STARTED
        prestart = exam.prestart_at()
        if phase == PHASE_WAITING and prestart is not None and now < prestart:
            return False, f"the exam projects start at {iso_utc(prestart)}"
        return True, ''

    def visible_rows(self, login: str, department: str, rows: list, now: float | None = None) -> list:
        """The project rows a student sees: during an exam only its labs' projects (each row
        marked ``exam``), the exam projects of an exam over for them hidden otherwise."""
        now = self._at(now)
        binding = self.for_login(login, department, now)
        if binding is not None:
            exam, member, phase = binding
            if phase not in START_PHASES:
                return []
            labs = exam.lab_names(login)
            kept = []
            for row in rows:
                if normal_lab(row.get('lab_name')) in labs:
                    kept.append(dict(row, exam={'id': exam.id, 'title': exam.title}))
            return kept
        hidden = {p.get('rln') for e in self._exams.values() for m in [e.members.get(login)] if m is not None
                  for p in m.projects.values()}
        return [row for row in rows if row.get('running_lab_name') not in hidden]

    @staticmethod
    def address_allowed(exam: Exam, address: str) -> bool:
        return not exam.networks or client_allowed(address, exam.networks)

    def members_of(self, exam: Exam) -> set:
        """The logins of the audience the portal can name: the explicit ones, those of the
        groups (the memberships, the connected members of a department) and the records."""
        logins = set(exam.logins) | set(exam.members)
        if exam.groups:
            if self.memberships is not None:
                logins |= self.memberships.members_of(exam.groups)
            for login in self.presence.logins():
                identity = self.presence.identity_of(login)
                if identity is not None and exam.includes(login, identity.group):
                    logins.add(login)
        return {login for login in logins if is_valid_login(login)}

    def resolve(self, exam: Exam, logins: Iterable[str], groups: Iterable[str]) -> set:
        """The students an action on a selection applies to, now: the explicit logins (members
        of the audience, else ``ValueError``) and the members of the groups the portal can name."""
        members = self.members_of(exam)
        chosen = set(logins)
        unknown = sorted(chosen - members)
        if unknown:
            raise ValueError(f"{unknown[0]} is not in the audience of this exam")
        groups = set(groups)
        if groups:
            if self.memberships is not None:
                chosen |= self.memberships.members_of(groups) & members
            for login in members:
                identity = self.presence.identity_of(login)
                if identity is not None and department_member(identity.group, groups):
                    chosen.add(login)
        return chosen

    def student_view(self, exam: Exam, member: Member | None, phase: str, *, address: str, allowed: bool,
                     titles: dict | None = None, now: float | None = None) -> dict:
        """What a student's browser needs (``GET /api/exam``)."""
        now = self._at(now)
        titles = titles or {}
        labs = [{'lab': l.lab, 'lab_name': l.lab.replace('/', '@'), 'title': titles.get(l.lab), 'flavor': l.flavor}
                for l in exam.labs_of(member.login if member else None)]
        return {'id': exam.id, 'title': exam.title, 'phase': phase, 'start_at': exam.start_after,
                'prestart_at': exam.prestart_at(), 'hide_at': exam.hide_at(),
                'started_at': member.started_at if member else None, 'end_at': exam.end_at(member),
                'lead': exam.lead, 'labs': labs, 'address_allowed': allowed, 'address': address,
                'dismissable': phase == PHASE_ENDED}

    # -- life cycle -----------------------------------------------------------------------------

    def _new_exam(self, creator: Identity, spec: dict, now: float) -> Exam:
        exam = Exam(id=0, title=spec['title'], created_by=creator.login, created_at=now, updated_at=now,
                    logins=set(spec['logins']), groups=set(spec['groups']), labs=list(spec['labs']),
                    duration=spec['duration'], start_after=spec['start_after'], end_before=spec['end_before'],
                    lead=spec['lead'], pre_start=spec['pre_start'], networks=list(spec['networks']),
                    eval_interval=spec['eval_interval'], memberships=self.memberships)
        return exam

    async def create(self, creator: Identity, spec: dict, now: float | None = None) -> Exam:
        """A new exam from a ``parse_exam`` result; ``HistoryError`` when the store refuses it
        (nothing kept then)."""
        now = self._at(now)
        exam = self._new_exam(creator, spec, now)
        if self.store is not None:
            exam.id = await asyncio.to_thread(self.store.save_exam, exam)
        else:
            exam.id, self._next_id = self._next_id, self._next_id + 1
        self._exams[exam.id] = exam
        log.info("exam %d %r created by %s: labs %s, start %s, end %s, duration %s", exam.id, exam.title,
                 creator.login, [l.lab for l in exam.labs], iso_utc(exam.start_after) if exam.start_after else 'now',
                 iso_utc(exam.end_before) if exam.end_before else '-',
                 f"{exam.duration / 60:g} min" if exam.duration else '-')
        await self.resync(self.members_of(exam) | self.presence.logins())
        return exam

    async def update(self, exam_id, spec: dict, *, resume: bool = False, now: float | None = None) -> Exam:
        """The definition edited (a ``parse_exam`` result with ``current=exam``): the members
        keep their clocks and adjustments; with *resume* (the end or the duration edited) an
        *End now* is lifted; the audience before and after is told."""
        now = self._at(now)
        exam = self._require(exam_id)
        before = self.members_of(exam)
        for key in ('title', 'logins', 'groups', 'labs', 'duration', 'start_after', 'end_before', 'lead', 'pre_start',
                    'networks', 'eval_interval'):
            setattr(exam, key, spec[key])
        if resume:
            exam.ended_at = None
        exam.updated_at = now
        await self._persist_exam(exam)
        log.info("exam %d %r edited", exam.id, exam.title)
        await self.resync(before | self.members_of(exam) | self.presence.logins())
        return exam

    async def delete(self, exam_id) -> Exam:
        exam = self._require(exam_id)
        affected = self.members_of(exam) | {login for login, shown in self.shown.items() if shown[0] == exam.id}
        del self._exams[exam.id]
        self._dirty = {d for d in self._dirty if d[0] != exam.id}
        if self.store is not None:
            try:
                await asyncio.to_thread(self.store.delete_exam, exam.id)
            except HistoryError as e:
                self._warn(f"delete {exam.id}", f"exam {exam.id} could not be deleted from the database: {e}")
        log.info("exam %d %r deleted", exam.id, exam.title)
        await self.resync(affected)
        return exam

    async def end_now(self, exam_id, logins: set | None, now: float | None = None) -> Exam:
        """The exam over now, for everybody (*logins* ``None``) or for the students given."""
        now = self._at(now)
        exam = self._require(exam_id)
        if logins is None:
            exam.ended_at = now
            exam.updated_at = now
            await self._persist_exam(exam)
            affected = self.members_of(exam)
        else:
            for login in logins:
                m = exam.member(login, create=True)
                m.ended_at = now
                await self._persist_member(exam, m)
            affected = set(logins)
        log.info("exam %d ended now for %s", exam.id, 'everybody' if logins is None else sorted(logins))
        await self.resync(affected)
        return exam

    async def adjust(self, exam_id, logins: set | None, extra_minutes: int, now: float | None = None) -> Exam:
        """*extra_minutes* (negative to reduce) for everybody — the duration and the end time
        shifted, an End now lifted — or for the students given — their extra minutes, an End
        now of theirs lifted."""
        now = self._at(now)
        exam = self._require(exam_id)
        if logins is None:
            if exam.duration is not None:
                exam.duration = max(60.0, exam.duration + extra_minutes * 60)
            if exam.end_before is not None:
                exam.end_before += extra_minutes * 60
            exam.ended_at = None
            exam.updated_at = now
            await self._persist_exam(exam)
            affected = self.members_of(exam)
        else:
            for login in logins:
                m = exam.member(login, create=True)
                m.extra_minutes += extra_minutes
                m.ended_at = None
                await self._persist_member(exam, m)
            affected = set(logins)
        log.info("exam %d: %+d min for %s", exam.id, extra_minutes, 'everybody' if logins is None else sorted(logins))
        await self.resync(affected)
        return exam

    async def set_labs(self, exam_id, logins: set | None, labs: list, now: float | None = None) -> Exam:
        """The labs of the exam (*logins* ``None``: every student's, the per-student lists
        dropped) or of the students given; the exam projects of labs no longer theirs become
        ``Member.orphans`` (``examprojects`` tells their agents)."""
        now = self._at(now)
        exam = self._require(exam_id)
        if logins is None:
            exam.labs = list(labs)
            exam.updated_at = now
            for m in exam.members.values():
                m.labs = None
                self._orphan(exam, m)
            await self._persist_exam(exam)
            for m in exam.members.values():
                await self._persist_member(exam, m)
            affected = self.members_of(exam)
        else:
            for login in logins:
                m = exam.member(login, create=True)
                m.labs = list(labs)
                self._orphan(exam, m)
                await self._persist_member(exam, m)
            affected = set(logins)
        log.info("exam %d: labs %s for %s", exam.id, [l.lab for l in labs],
                 'everybody' if logins is None else sorted(logins))
        await self.resync(affected)
        return exam

    @staticmethod
    def _orphan(exam: Exam, m: Member):
        for lab in [lab for lab in m.projects if lab not in exam.lab_names(m.login)]:
            p = m.projects.pop(lab)
            m.orphans.append({'host': p.get('host'), 'rln': p.get('rln')})

    async def dismiss(self, exam_id, login: str, now: float | None = None) -> str:
        """The student has seen the end banner: ``done`` (``ValueError`` unless their exam is
        ``ended``)."""
        now = self._at(now)
        exam = self._require(exam_id)
        m = exam.member(login, create=True)
        if exam.phase(m, now) != PHASE_ENDED:
            raise ValueError("nothing to dismiss")
        m.dismissed_at = now
        await self._persist_member(exam, m)
        await self.resync({login})
        return exam.phase(m, now)

    async def note_seen(self, exam: Exam, login: str, address: str, now: float | None = None) -> Member:
        """A request of a student bound by *exam*: their record (created), its first time and
        their address."""
        now = self._at(now)
        m = exam.member(login, create=True)
        changed = False
        if m.first_seen is None:
            m.first_seen = now
            changed = True
        if address and address != m.address:
            m.address = address
            changed = True
        if changed:
            await self._persist_member(exam, m)
        return m

    async def observe(self, exam: Exam, login: str, rows: list, now: float | None = None, address: str = '') -> bool:
        """The running projects of a student (the rows of ``GET /api/projects``) seen: their exam
        projects recorded, their clock started once every lab of theirs has one and the start
        passed.  ``True`` when something changed (the browsers are told)."""
        now = self._at(now)
        m = exam.member(login, create=True)
        changed = m.first_seen is None
        if m.first_seen is None:
            m.first_seen = now
        if address and address != m.address:
            m.address = address
            changed = True
        labs = exam.lab_names(login)
        for row in rows:
            lab = normal_lab(row.get('lab_name'))
            rln, host = row.get('running_lab_name'), row.get('host')
            if lab not in labs or not isinstance(rln, str) or not isinstance(host, str):
                continue
            if row.get('owner', login) != login:
                continue
            current = m.projects.get(lab)
            if current is None or current.get('rln') != rln or current.get('host') != host:
                m.projects[lab] = {'host': host, 'rln': rln, 'synced': None}
                changed = True
        if exam.may_start(m, now):
            m.started_at = now
            changed = True
            log.info("exam %d: the clock of %s starts (ends %s)", exam.id, login,
                     iso_utc(exam.end_at(m)) if exam.end_at(m) else '-')
        if changed:
            await self._persist_member(exam, m)
            await self.resync({login})
        return changed

    # -- persistence ----------------------------------------------------------------------------

    def _warn(self, key: str, message: str):
        if key not in self._warned:
            self._warned.add(key)
            log.warning("exams database: %s", message)

    async def _persist_exam(self, exam: Exam):
        if self.store is None or exam.id <= 0:
            return
        try:
            await asyncio.to_thread(self.store.save_exam, exam)
            self._dirty.discard((exam.id, None))
            self._warned.clear()
        except HistoryError as e:
            self._dirty.add((exam.id, None))
            self._warn('write', f"a write failed (kept in memory, tried again every {DIRTY_RETRY:g} s): {e}")

    async def _persist_member(self, exam: Exam, m: Member):
        if self.store is None or exam.id <= 0:
            return
        try:
            await asyncio.to_thread(self.store.save_member, exam.id, m)
            self._dirty.discard((exam.id, m.login))
            self._warned.clear()
        except HistoryError as e:
            self._dirty.add((exam.id, m.login))
            self._warn('write', f"a write failed (kept in memory, tried again every {DIRTY_RETRY:g} s): {e}")

    async def _retry_dirty(self):
        for exam_id, login in sorted(self._dirty, key=lambda d: (d[0], d[1] or '')):
            exam = self._exams.get(exam_id)
            if exam is None:
                self._dirty.discard((exam_id, login))
                continue
            if login is None:
                await self._persist_exam(exam)
            elif login in exam.members:
                await self._persist_member(exam, exam.members[login])
            else:
                self._dirty.discard((exam_id, login))
            if (exam_id, login) in self._dirty:
                return          # still down: the others would fail too

    async def load(self) -> int:
        """The exams of the store (at startup; tried again by the tick while it fails): the
        ones not in memory yet.  The number read; ``-1`` when the store does not answer."""
        if self.store is None:
            self.loaded = True
            return 0
        try:
            exams = await asyncio.to_thread(self.store.load_all)
        except HistoryError as e:
            self._warn('load', f"the exams could not be read (tried again every {DIRTY_RETRY:g} s): {e}")
            return -1
        for exam in exams:
            exam.memberships = self.memberships
            self._exams.setdefault(exam.id, exam)
        self.loaded = True
        self._warned.discard('load')
        return len(exams)

    def describe(self) -> str:
        cfg = self.cfg
        where = self.store.describe() if self.store is not None else "no database (the exams cannot be stored)"
        return (f"{len(self._exams)} exam(s), {where}; lead {cfg.lead / 60:g} min, pre-start {cfg.pre_start / 60:g} min, "
                f"evaluation every {cfg.eval_interval:g} s, projects closed "
                f"{f'{cfg.close_after / 60:g} min after the end' if cfg.close_after else 'by the instructors'}")

    # -- the browsers ---------------------------------------------------------------------------

    async def resync(self, logins: Iterable[str], now: float | None = None):
        """For each login, the exam binding them now compared with what their pages were told
        (``shown``): one push of the difference, ``{"t": "exam", "id", "phase"}`` (``phase``
        ``null`` when no exam binds them any more)."""
        now = self._at(now)
        for login in set(logins):
            identity = self.presence.identity_of(login)
            if identity is None:
                self.shown.pop(login, None)
                continue
            if identity.is_instructor:
                continue
            binding = self.for_login(login, identity.group, now)
            current = None if binding is None else (binding[0].id, binding[2])
            shown = self.shown.get(login)
            if current == shown:
                continue
            if current is None:
                del self.shown[login]
                await self.presence.push(login, {'t': 'exam', 'id': shown[0], 'phase': None})
            else:
                self.shown[login] = current
                await self.presence.push(login, {'t': 'exam', 'id': current[0], 'phase': current[1]})

    async def tick(self, now: float | None = None):
        """Every second: the clocks of the students whose projects were ready before the start,
        the memberships refreshed, the writes the database refused tried again, the browsers
        told of the phase changes, then the hooks (``examprojects.ExamProjects.reconcile``)."""
        now = self._at(now)
        for exam in list(self._exams.values()):
            if exam.start_after is None or now < exam.start_after:
                continue
            for m in exam.members.values():
                if exam.may_start(m, now):
                    m.started_at = exam.start_after     # their projects were ready before the start
                    log.info("exam %d: the clock of %s starts (ends %s)", exam.id, m.login,
                             iso_utc(exam.end_at(m)) if exam.end_at(m) else '-')
                    await self._persist_member(exam, m)
        if self.memberships is not None and now - self._last_refresh >= MEMBERSHIPS_REFRESH:
            self._last_refresh = now
            await self.memberships.refresh()
        if now - self._last_retry >= DIRTY_RETRY:
            self._last_retry = now
            if not self.loaded:
                await self.load()
            if self._dirty:
                await self._retry_dirty()
            if self.store is not None and self.cfg.keep > 0 and now - self._last_purge >= 86400:
                self._last_purge = now
                with contextlib.suppress(HistoryError):
                    gone = await asyncio.to_thread(self.store.purge, now - self.cfg.keep * 86400)
                    if gone:
                        log.info("exams database: %d past exam(s) older than %d days deleted", gone, self.cfg.keep)
        await self.resync(self.presence.logins(), now)
        for hook in list(self.on_tick):
            try:
                await hook(now)
            except Exception:
                log.exception("exams: a tick hook failed")

    async def _loop(self):
        while True:
            await asyncio.sleep(TICK)
            try:
                await self.tick()
            except Exception:
                log.exception("exams: tick failed")

    def start_loop(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop_loop(self):
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
