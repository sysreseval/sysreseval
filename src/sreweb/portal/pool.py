"""The pool of hosts: the status of their agents, the state of each host, the placement of a
new project, the fan-out of the project lists, and what is changed by hand
(``sre-web-tool add / remove / enable / disable / drain / priority``, the Pool page), kept in a state file
merged with the ``[[hosts]]`` of the configuration so that a restart of the portal changes
nothing."""
import asyncio
import datetime
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict, replace

import aiohttp

from ..agent.occupancy import SESSION_PREFIX
from ..agent.runner import (PRELOAD_STATES, PRELOAD_PENDING, PRELOAD_RUNNING, PRELOAD_DONE, PRELOAD_FAILED,
                            LAB_README_KEY)
from ..config import (HostConfig, host_config_from_dict, check_priority, ConfigError, PLACEMENT_SPREAD,
                      PLACEMENT_PACK)
from ..identity import Identity, is_valid_login

log = logging.getLogger('sreweb.portal')

STATUS_TIMEOUT = 5.0
#: Seconds a host is expected to restart within after ``POST /v1/restart`` (``restart_sent``).
RESTART_HOLD = 120.0

#: The states of a host, as the portal sees it.
STATE_OFF = 'off'              # agent unreachable
STATE_WAKING = 'waking'        # a wake was sent, the agent not up yet
STATE_UP = 'up'                # agent up, free: new projects go there
STATE_OCCUPIED = 'occupied'    # agent up, the machine is used locally: no new project but its local users'
STATE_EXAM = 'exam'            # agent up, exam.json on the host
STATE_DRAINING = 'draining'    # agent up, a power off is wanted: no new project
STATE_DISABLED = 'disabled'    # taken out of the placement by hand
SOURCE_CONFIG = 'config'
SOURCE_ADDED = 'added'
#: The state file (``[admin] state_file``), version 2.  ``enabled`` / ``disabled``: the hosts
#: whose flag was set by hand and differs from their ``enabled`` of the configuration (of their
#: ``added`` entry for an added host); ``drain``: host -> when it was asked; ``priority``: host
#: -> the priority set by hand (``value``) and the one of the configuration it was set over
#: (``configured``), for the hosts where they differ; ``clocks``: per
#: host, the wake in progress, the hold after failed wakes or a power off, the power off and
#: the restart sent.  Every time is a wall-clock one (the runtime keeps monotonic ones).  A
#: version 1 file had ``removed``, ``added`` and every disabled host in ``disabled``; a version
#: 2 file written before the priorities has no ``priority`` key.
STATE_VERSION = 2
KEY_VERSION = 'version'
KEY_SAVED_AT = 'saved_at'
KEY_REMOVED = 'removed'
KEY_ADDED = 'added'
KEY_ENABLED = 'enabled'
KEY_DISABLED = 'disabled'
KEY_DRAIN = 'drain'
KEY_PRIORITY = 'priority'
PRIORITY_VALUE = 'value'
PRIORITY_CONFIGURED = 'configured'
KEY_CLOCKS = 'clocks'
CLOCK_WOKEN_AT = 'woken_at'
CLOCK_NEXT_WAKE_AT = 'next_wake_at'
CLOCK_WAKE_FAILURES = 'wake_failures'
CLOCK_POWER_OFF_SENT = 'power_off_sent'
CLOCK_RESTART_SENT = 'restart_sent'
#: A state file that could not be read is renamed with this suffix instead of being written over.
UNREADABLE_SUFFIX = '.unreadable'
#: The furthest ahead a wake hold read from the state file may lie (the longest backoff is
#: 30 min): a wall clock set back while the portal was stopped cannot hold a host for days.
MAX_HOLD = 3600.0
#: The most failed wakes read from the state file (the backoff doubles with each).
MAX_WAKE_FAILURES = 64
#: Seconds of margin when a drain read from the state file is compared with the boot of its host.
BOOT_MARGIN = 5.0
#: A time of the state file may lie that far ahead of the clock and still be taken (it was
#: rounded, the clock was stepped back a little); further ahead it means nothing.
CLOCK_SLACK = 5.0
#: Why a host was chosen (the ``placement`` field of the ``start`` line of the connection log).
PLACEMENT_LOAD = 'load'          # the least loaded host
PLACEMENT_SESSION = 'session'    # the host of a local login session of the user (follow_local_sessions)
PLACEMENT_NAMED = 'named'        # the host an instructor named
#: The entries of the lab list (``sre list --with-titles`` through the agent) as the Open page
#: reads them: ``kind`` dir / lab, ``sort`` the mode of the titles.json the entry is placed by.
LAB_KIND_DIR = 'dir'
LAB_KIND_LAB = 'lab'
LAB_KINDS = (LAB_KIND_DIR, LAB_KIND_LAB)
LAB_SORT_NAME = 'name'
LAB_SORT_MODES = (LAB_SORT_NAME, 'title', 'manual')


def readme_of(entry: dict) -> dict:
    """The README of a directory entry of ``GET /v1/labs`` (``LAB_README_KEY``:
    ``{language: html}`` rendered by the agent, ``""`` being ``README.md``), its texts that are
    non-empty strings only; ``{}`` when the entry has none (an older agent, no README)."""
    readme = entry.get(LAB_README_KEY)
    if not isinstance(readme, dict):
        return {}
    return {lang: html for lang, html in readme.items() if isinstance(lang, str) and isinstance(html, str) and html}


class PoolError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


@dataclass
class Reservation:
    released_at: float | None = None
    placement: str = PLACEMENT_LOAD


@dataclass
class HostStatus:
    """What the last status poll of the agent said."""
    reachable: bool = False
    projects: int = 0
    managed_projects: int = 0
    local_projects: int = 0
    terminals: int = 0
    load1: float | None = None
    # MemAvailable of the host in MiB (``None``: an agent older than the key, or unreachable): the
    # projects it still takes with ``[pool] project_memory_mb`` (``Pool.memory_room``)
    mem_available_mb: int | None = None
    exam_mode: bool = False
    occupied: bool = False
    occupied_by: list = field(default_factory=list)
    # the users with a running Qt GUI on the host (the ``gui_users`` of the status, coerced by
    # ``gui_user_fields``: ``{login, fullname, since}``): the Clients view of the Watch page;
    # empty for an agent older than the key
    gui_users: list = field(default_factory=list)
    uptime: int | None = None
    power_off_allowed: bool = False
    agent_uptime: int | None = None     # seconds since the agent started: a restart resets it
    restart_allowed: bool = False       # the agent can restart itself (its unit, or restart_command)
    restarting: bool = False            # a restart is pending on the agent (sre commands in flight)
    exam_projects: int = 0              # the running projects of an exam of the web site
    # the exam file of the host (``exam.json``; the ``exam`` object of the status, coerced by
    # ``host_exam_fields``): ``None`` without one; ``exam_known``: the agent tells it at all
    # (an older one does not: it cannot be given the exam of the web site either)
    exam: dict | None = None
    exam_known: bool = False
    # the preload of the Docker images on the host (the ``preload`` object of the status, flat):
    # its state (one of PRELOAD_STATES; '' = an agent that does not know the preload, or
    # unreachable), the seconds in that state, the image being pulled and its rank, the error
    preload: str = ''
    preload_since: int | None = None
    preload_current: int = 0
    preload_total: int = 0
    preload_image: str = ''
    preload_error: str = ''
    # the drain asked on the host itself (`sre set-drain` there; the ``local_drain`` object of the
    # status, flat): whether one is asked and since when (epoch seconds), whether the host may ask
    # for one now and what its agent.toml says (``None``: an agent that does not know the local
    # drains, or unreachable)
    local_drain: bool = False
    local_drain_since: float | None = None
    local_drain_allowed: bool | None = None
    local_drain_default: bool | None = None
    hostname: str = ''
    sre_version: str = ''
    error: str = ''
    updated: float = field(default_factory=time.monotonic)
    polled_at: float = 0.0              # monotonic time the status was asked (``refresh_host``)


#: The longest text (hostname, sre_version, an occupied_by entry) and list kept from a status.
MAX_STATUS_TEXT = 200
MAX_OCCUPIED_BY = 100
MAX_GUI_USERS = 64


def _number(value) -> float | None:
    """A finite number of the status JSON (a bool is not one), else ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in (float('inf'), float('-inf')):
        return None
    return float(value)


def _count(value) -> int:
    number = _number(value)
    return max(0, int(number)) if number is not None else 0


def _seconds(value) -> int | None:
    """A whole number of the status JSON, 0 or more (seconds, MiB), else ``None``."""
    number = _number(value)
    return max(0, int(number)) if number is not None else None


def _text(value) -> str:
    return value[:MAX_STATUS_TEXT] if isinstance(value, str) else ''


def gui_user_fields(value) -> list:
    """The ``gui_users`` of a status as the portal keeps them: ``{login, fullname, since}`` for
    every entry that is an object with a valid login, one per login, at most ``MAX_GUI_USERS``
    (*fullname* a capped text, *since* epoch seconds or ``None``); anything else is dropped."""
    if not isinstance(value, list):
        return []
    users = {}
    for entry in value:
        if not isinstance(entry, dict):
            continue
        login = entry.get('login')
        if not isinstance(login, str) or not is_valid_login(login) or login in users:
            continue
        users[login] = {'login': login, 'fullname': _text(entry.get('fullname')), 'since': _number(entry.get('since'))}
        if len(users) >= MAX_GUI_USERS:
            break
    return list(users.values())


def _names(value) -> list:
    """The host names of a list of the state file (whatever else a hand edit left is ignored)."""
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def preload_fields(value) -> dict:
    """The ``preload*`` fields of a ``HostStatus`` from the ``preload`` object of a status (or of
    the answer to a preload request), coerced like the rest; an agent older than the preload
    sends none: ``''``, a host the portal never gives a turn to."""
    data = value if isinstance(value, dict) else {}
    state = data.get('state')
    return {'preload': state if isinstance(state, str) and state in PRELOAD_STATES else '',
            'preload_since': _seconds(data.get('since')),
            'preload_current': _count(data.get('current')), 'preload_total': _count(data.get('total')),
            'preload_image': _text(data.get('image')), 'preload_error': _text(data.get('error'))}


def local_drain_fields(value) -> dict:
    """The ``local_drain*`` fields of a ``HostStatus`` from the ``local_drain`` object of a status
    (or of the answer to a ``POST /v1/local-drain/...``), coerced like the rest; an agent older
    than the local drains sends none: no drain asked, ``None`` for what is allowed."""
    if not isinstance(value, dict):
        return {'local_drain': False, 'local_drain_since': None,
                'local_drain_allowed': None, 'local_drain_default': None}
    allowed, default = value.get('allowed') is True, value.get('default') is True
    asked = allowed and value.get('asked') is True      # never a drain where the agent forbids them
    return {'local_drain': asked, 'local_drain_since': _number(value.get('since')) if asked else None,
            'local_drain_allowed': allowed, 'local_drain_default': default}


def _instant(value) -> float | None:
    """The epoch of an ISO 8601 instant with an offset of the status JSON, else ``None``."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.timestamp() if parsed.tzinfo is not None else None


def host_exam_fields(value) -> dict | None:
    """The exam file of a host from the ``exam`` object of a status (or of the answer to a
    ``PUT`` / ``DELETE /v1/exam``), coerced like the rest: ``None`` without a file; ``id`` /
    ``rev`` / ``origin`` are ``None`` for a file set by hand (``sre set-exam``), the instants
    are epoch seconds."""
    if not isinstance(value, dict):
        return None

    def token(key):
        return _text(value.get(key)) or None

    duration = _number(value.get('duration'))
    return {'id': token('id'), 'title': _text(value.get('title')), 'rev': token('rev'), 'origin': token('origin'),
            'start_after': _instant(value.get('start_after')), 'end_before': _instant(value.get('end_before')),
            'duration': int(duration) if duration is not None else None,
            'pre_started': value.get('pre_started') is True,
            'started_at': _instant(value.get('started_at')), 'ended_at': _instant(value.get('ended_at'))}


def status_from_json(data, extra_projects: int = 0) -> HostStatus:
    """The ``HostStatus`` of the JSON of ``GET /v1/status``, every field coerced to its type: a
    broken or hostile agent cannot plant a string where ``pick()`` sorts by a number (every
    start of the pool failed on the ``TypeError``), nor stay reachable with a body that is not
    an object (an error, like a bad HTTP status).  *extra_projects*: the reservations counted
    on top of the projects."""
    if not isinstance(data, dict):
        return HostStatus(error="status: not a JSON object")
    occupied_by = data.get('occupied_by')
    return HostStatus(reachable=True,
                      projects=_count(data.get('projects')) + extra_projects,
                      managed_projects=_count(data.get('managed_projects')),
                      local_projects=_count(data.get('local_projects')),
                      terminals=_count(data.get('terminals')),
                      load1=_number(data.get('load1')),
                      mem_available_mb=_seconds(data.get('mem_available_mb')),
                      exam_mode=data.get('exam_mode') is True,
                      occupied=data.get('occupied') is True,
                      occupied_by=([_text(x) for x in occupied_by if isinstance(x, str)][:MAX_OCCUPIED_BY]
                                   if isinstance(occupied_by, list) else []),
                      gui_users=gui_user_fields(data.get('gui_users')),
                      uptime=_seconds(data.get('uptime')),
                      power_off_allowed=data.get('power_off_allowed') is True,
                      agent_uptime=_seconds(data.get('agent_uptime')),
                      restart_allowed=data.get('restart_allowed') is True,
                      restarting=data.get('restarting') is True,
                      exam_projects=_count(data.get('exam_projects')),
                      exam=host_exam_fields(data.get('exam')), exam_known='exam' in data,
                      hostname=_text(data.get('hostname')),
                      sre_version=_text(data.get('sre_version')),
                      **preload_fields(data.get('preload')),
                      **local_drain_fields(data.get('local_drain')))


@dataclass
class HostRuntime:
    """What the portal remembers about a host between polls."""
    source: str = SOURCE_CONFIG
    enabled: bool = True
    priority: int = 0                  # the one of the configuration until it is set by hand (``set_priority``)
    woken_at: float | None = None      # monotonic time of the last wake, None when not waking
    wake_failures: int = 0
    next_wake_at: float = 0.0          # backoff after failed wakes
    idle_since: float | None = None    # monotonic time since the host has no project
    drain: bool = False                # power off wanted as soon as the host is empty
    drain_at: float = 0.0              # wall-clock time the drain was asked (0: unknown), for the state file
    power_off_sent: float | None = None   # monotonic time of the last accepted power off
    restart_sent: float | None = None     # monotonic time of the last accepted restart, until it is seen
    # the preload of the Docker images: monotonic time its turn was given to the host, until a
    # status asked after it tells (the host counts as preloading meanwhile, whatever an older
    # status says), and no new turn before next_preload_at after a refused one; neither is kept
    # in the state file: the agents say where they are
    preload_granted: float | None = None
    next_preload_at: float = 0.0
    last_wake_reason: str = ''
    # the exam file of the host as its agent answered a ``PUT`` / ``DELETE /v1/exam`` of the
    # portal (``Pool.note_exam``), and the monotonic time of that answer: it stands for the
    # ``exam`` of the status until a status asked after it tells (the rule of preload_granted)
    exam_told: float | None = None
    exam_view: dict | None = None
    # the local drain of the host as its agent answered a ``POST /v1/local-drain/...`` of the
    # portal (``Pool.note_local_drain``: the ``local_drain*`` fields) and the monotonic time of
    # that answer: the rule of exam_told, so that a status asked before a cancel never brings the
    # drain back (the policy would power the host off)
    local_drain_told: float | None = None
    local_drain_view: dict | None = None


class Pool:
    def __init__(self, hosts: list, session, *, poll_interval: float = 2.0, wake_timeout: float = 180.0,
                 state_file: str = '', follow_local_sessions: bool = True, labs_cache_ttl: float = 60.0,
                 restart_hold: float = RESTART_HOLD, placement: str = PLACEMENT_SPREAD, project_memory_mb: int = 0):
        self.hosts: dict[str, HostConfig] = {}
        self.status: dict[str, HostStatus] = {}
        self.runtime: dict[str, HostRuntime] = {}
        self.session = session
        self.poll_interval = poll_interval
        self.wake_timeout = wake_timeout
        self.restart_hold = restart_hold
        self.state_file = state_file
        self.follow_local_sessions = follow_local_sessions
        self.labs_cache_ttl = labs_cache_ttl
        self.placement = placement                  # [pool] placement: spread or pack (``pick``)
        self.project_memory_mb = project_memory_mb  # [pool] project_memory_mb: 0 = memory not checked
        #: The lab list of the Open page per role (``labs``), kept labs_cache_ttl seconds, and the
        #: lock making the requests of a role wait for the one fetching it.
        self._labs_cache: dict[tuple, tuple[float, list]] = {}      # (instructor, all labs) -> (when, labs)
        self._labs_locks: dict[tuple, asyncio.Lock] = {}
        self._config_hosts = {h.name: h for h in hosts}
        self._removed: set = set()      # config hosts removed by hand (``enable`` brings them back)
        #: The projects being started on each host: a reservation counts as a project until the
        #: start is over (``release``) and a status polled after that has been received, so that
        #: a stale poll never frees the slot early.
        self._reservations: dict[str, list] = {}
        self._reported: dict[str, bool] = {}
        self._task: asyncio.Task | None = None
        #: Why the state file could not be written ('' when it is saved): what is changed by
        #: hand would be lost at the next restart (``sre-web-tool status``, the Pool page).
        self.state_error = ''
        self._saved_key = None      # ``_state_key()`` at the last save: ``refresh`` saves what changed since
        #: ``exam_hold(name)``: whether an exam of the web site keeps the machine for itself (it
        #: lists it and is about to lock it, or is on it): no new web project goes there, the
        #: policy leaves it on.  Set by the portal (``examhosts.ExamHosts.held``); none = never.
        self.exam_hold = None
        for host in hosts:
            self._register(host, SOURCE_CONFIG)
        self.load_state()
        self._saved_key = self._state_key()

    # -- membership -----------------------------------------------------------------------------

    def _register(self, host: HostConfig, source: str):
        self.hosts[host.name] = host
        self.status[host.name] = HostStatus()
        self.runtime[host.name] = HostRuntime(source=source, enabled=host.enabled, priority=host.priority)
        self._reservations[host.name] = []
        self._reported.pop(host.name, None)

    def host(self, name: str) -> HostConfig:
        host = self.hosts.get(name)
        if host is None:
            raise PoolError(404, "unknown host")
        return host

    def add_host(self, host: HostConfig):
        """``sre-web-tool add``: a host added by hand (an added host of the same name is
        replaced; a config host of that name cannot be redefined)."""
        if host.name in self._config_hosts:
            raise PoolError(409, f"{host.name} is in the configuration file: edit it there"
                            + (", or enable it" if host.name in self._removed else ""))
        self._register(host, SOURCE_ADDED)
        self.save_state()
        log.info("host %s added to the pool (%s)", host.name, host.url)

    def remove_host(self, name: str, force: bool = False):
        """``sre-web-tool remove``: refused while the host has projects, unless forced (they
        stay on the host, out of the portal's reach: the agent's idle reaper closes them)."""
        self.host(name)
        projects = self.status[name].projects if self.status[name].reachable else 0
        if projects and not force:
            raise PoolError(409, f"{name} has {projects} project(s): drain it first, or --force")
        if self.runtime[name].source == SOURCE_CONFIG:
            self._removed.add(name)
        self._forget(name)
        self.save_state()
        log.info("host %s removed from the pool", name)

    def set_enabled(self, name: str, enabled: bool):
        """``enable`` / ``disable``: a disabled host stays polled and listed but gets no project;
        ``enable`` also cancels a drain, and brings back a config host removed by hand."""
        if name in self._removed and enabled:
            self._removed.discard(name)
            self._register(self._config_hosts[name], SOURCE_CONFIG)
            self.runtime[name].enabled = True     # whatever its ``enabled`` of the configuration
            self.save_state()
            log.info("host %s back in the pool from the configuration", name)
            return
        self.host(name)
        runtime = self.runtime[name]
        runtime.enabled = enabled
        if enabled:
            runtime.drain, runtime.drain_at = False, 0.0
        self.save_state()
        log.info("host %s %s", name, 'enabled' if enabled else 'disabled')

    def set_drain(self, name: str, drain: bool = True):
        """``drain``: no new project on the host, powered off once it is empty; cancelled by
        ``enable``, over when the host is gone or back (``refresh_host``).  This is the drain of
        the portal; a host may also ask for its own (``draining``)."""
        self.host(name)
        runtime = self.runtime[name]
        if runtime.drain != drain:
            runtime.drain = drain
            runtime.drain_at = round(time.time(), 3) if drain else 0.0
            self.save_state()

    def set_priority(self, name: str, priority: int):
        """``priority``: the host with the lowest one is woken first and takes a project first
        among the hosts without project; the one with the highest is powered off first when
        idle (``pick``, ``manager.wake_plan`` / ``poweroff_plan``)."""
        self.host(name)
        self.runtime[name].priority = priority
        self.save_state()
        log.info("host %s: priority %d", name, priority)

    # -- the state file -------------------------------------------------------------------------

    def _forget(self, name: str):
        for table in (self.hosts, self.status, self.runtime, self._reservations):
            table.pop(name, None)
        self._reported.pop(name, None)

    def _settings(self) -> dict:
        """What was set by hand, as the state file keeps it: the membership, the ``enabled``
        flags and the priorities differing from the configuration (a priority with the one of
        the configuration it was set over) and the drains."""
        return {
            KEY_REMOVED: sorted(self._removed),
            KEY_ADDED: [asdict(self.hosts[n]) for n, r in self.runtime.items() if r.source == SOURCE_ADDED],
            KEY_ENABLED: sorted(n for n, r in self.runtime.items() if r.enabled and not self.hosts[n].enabled),
            KEY_DISABLED: sorted(n for n, r in self.runtime.items() if not r.enabled and self.hosts[n].enabled),
            KEY_DRAIN: {n: r.drain_at for n, r in sorted(self.runtime.items()) if r.drain},
            KEY_PRIORITY: {n: {PRIORITY_VALUE: r.priority, PRIORITY_CONFIGURED: self.hosts[n].priority}
                           for n, r in sorted(self.runtime.items()) if r.priority != self.hosts[n].priority},
        }

    def _clocks(self) -> dict:
        """The clocks worth keeping across a restart, as wall-clock times: a wake in progress,
        the hold after failed wakes or a power off, the power off and the restart sent.  Not
        the idle clock of ``idle_host_timeout``: a stale one would power a host off too early."""
        now = time.monotonic()
        offset = time.time() - now
        clocks = {}
        for name, rt in self.runtime.items():
            entry = {}
            if rt.woken_at is not None:
                entry[CLOCK_WOKEN_AT] = round(rt.woken_at + offset, 3)
            if rt.next_wake_at > now:
                entry[CLOCK_NEXT_WAKE_AT] = round(rt.next_wake_at + offset, 3)
                if rt.wake_failures:
                    entry[CLOCK_WAKE_FAILURES] = rt.wake_failures
            if rt.power_off_sent is not None:
                entry[CLOCK_POWER_OFF_SENT] = round(rt.power_off_sent + offset, 3)
            if rt.restart_sent is not None:
                entry[CLOCK_RESTART_SENT] = round(rt.restart_sent + offset, 3)
            if entry:
                clocks[name] = entry
        return clocks

    def _state_key(self) -> tuple:
        """What the state file depends on in the runtime of the hosts: ``refresh`` writes the
        file when it changed otherwise than by the calls saving it themselves (a drain over,
        a wake, a power off or a restart sent by the manager)."""
        return tuple((name, rt.enabled, rt.drain, rt.priority, rt.woken_at, rt.next_wake_at, rt.wake_failures,
                      rt.power_off_sent, rt.restart_sent) for name, rt in self.runtime.items())

    def state_info(self) -> dict:
        return {'state_file': self.state_file, 'state_error': self.state_error}

    def _not_saved(self, reason: str):
        self.state_error = reason
        log.error("pool state NOT saved in %s (%s): what is changed by hand is lost at the next restart",
                  self.state_file, reason)

    def _check_writable(self):
        """At startup: a state file that cannot be written is said now, not at the first change."""
        directory = os.path.dirname(self.state_file) or '.'
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            self._not_saved(str(e))
            return
        if not os.access(directory, os.W_OK | os.X_OK):
            self._not_saved(f"{directory} is not writable")

    def _set_aside(self):
        """A state file that could not be read (edited by hand into something else, or as
        another user) is kept under another name: the next save would write over it."""
        kept = self.state_file + UNREADABLE_SUFFIX
        try:
            os.replace(self.state_file, kept)
        except OSError as e:
            log.error("%s could not be kept as %s: %s", self.state_file, kept, e)
        else:
            log.error("%s is kept as %s", self.state_file, kept)

    def load_state(self):
        """What was changed by hand (``state_file``), over the configuration.  A flag of the
        file holds while the ``enabled`` of the host in the configuration is the one it was set
        against: once the configuration says the same, or the host is gone, the entry is
        dropped (the file is written again at once), so that an edit of the configuration
        wins over an older change made by hand.  The same for a priority (``_load_priorities``)."""
        if not self.state_file:
            return
        try:
            with open(self.state_file, encoding='utf-8') as f:
                state = json.load(f)
        except FileNotFoundError:
            log.info("pool state: no file %s yet, the pool is the one of the configuration", self.state_file)
            self._check_writable()
            return
        except (OSError, ValueError) as e:
            log.error("cannot read %s: %s (the pool is the one of the configuration)", self.state_file, e)
            self._set_aside()
            self._check_writable()
            return
        if not isinstance(state, dict):
            log.error("%s is not a JSON object (the pool is the one of the configuration)", self.state_file)
            self._set_aside()
            self._check_writable()
            return
        current = state.get(KEY_VERSION) == STATE_VERSION    # a version 1 file listed every disabled host
        for name in _names(state.get(KEY_REMOVED)):
            if name in self.hosts and self.runtime[name].source == SOURCE_CONFIG:
                self._forget(name)
                self._removed.add(name)
        added = state.get(KEY_ADDED)
        for entry in added if isinstance(added, list) else []:
            try:
                host = host_config_from_dict(entry, f"{self.state_file}: added host")
            except ConfigError as e:
                log.error("%s", e)
                continue
            if host.name in self._config_hosts:
                log.info("pool state: %s, added by hand, is in the configuration now: its entry there is used",
                         host.name)
                continue
            self._register(host, SOURCE_ADDED)
        for key, enabled in ((KEY_ENABLED, True), (KEY_DISABLED, False)):     # disabled wins
            for name in _names(state.get(key)):
                runtime = self.runtime.get(name)
                if runtime is None:
                    if name not in self._removed:
                        log.info("pool state: %s (%s by hand) is not in the pool any more: forgotten", name, key)
                    continue
                if current and self.hosts[name].enabled == enabled:
                    log.info("pool state: %s was %s by hand and the configuration says so now: it follows "
                             "the configuration", name, key)
                runtime.enabled = enabled
        drains = state.get(KEY_DRAIN)
        if isinstance(drains, list):      # written by hand, without the times
            drains = {name: 0 for name in _names(drains)}
        for name, asked_at in (drains if isinstance(drains, dict) else {}).items():
            runtime = self.runtime.get(name)
            if runtime is not None:
                runtime.drain, runtime.drain_at = True, _number(asked_at) or 0.0
        self._load_priorities(state.get(KEY_PRIORITY))
        self._load_clocks(state.get(KEY_CLOCKS))
        settings = self._settings()
        log.info("pool state read from %s: %d removed, %d added, %d enabled and %d disabled by hand, %d draining, "
                 "%d priorities set by hand",
                 self.state_file, len(settings[KEY_REMOVED]), len(settings[KEY_ADDED]), len(settings[KEY_ENABLED]),
                 len(settings[KEY_DISABLED]), len(settings[KEY_DRAIN]), len(settings[KEY_PRIORITY]))
        if not current or any(state.get(key) != value for key, value in settings.items()):
            self.save_state()
        else:
            self._check_writable()

    def _load_priorities(self, priorities):
        """The priorities set by hand, over those of the configuration.  An entry holds while
        the priority of the host in the configuration is the one it was set over
        (``configured``): once the configuration gives another one, or the same as the entry,
        or the host is gone, the entry is dropped — an edit of the configuration wins.  A plain
        number (written by hand, without the configured value) holds."""
        for name, entry in (priorities if isinstance(priorities, dict) else {}).items():
            runtime = self.runtime.get(name)
            if runtime is None:
                if name not in self._removed:
                    log.info("pool state: %s (priority set by hand) is not in the pool any more: forgotten", name)
                continue
            value, configured = entry, None
            if isinstance(entry, dict):
                value, configured = entry.get(PRIORITY_VALUE), entry.get(PRIORITY_CONFIGURED)
            try:
                value = check_priority(value, f"{self.state_file}: the priority of {name}")
            except ConfigError as e:
                log.error("%s", e)
                continue
            in_config = self.hosts[name].priority
            if configured is not None and configured != in_config:
                log.info("pool state: the priority of %s was set by hand to %d over %r and the configuration says "
                         "%d now: it follows the configuration", name, value, configured, in_config)
                continue
            runtime.priority = value

    def _load_clocks(self, clocks):
        """The clocks of the state file back as monotonic times, each one only while it still
        means something: a wake or a power off for ``wake_timeout``, a restart for
        ``restart_hold``, a hold until its time (the portal may have been stopped for long)."""
        if not isinstance(clocks, dict):
            return
        wall = time.time()
        offset = wall - time.monotonic()
        for name, entry in clocks.items():
            runtime = self.runtime.get(name)
            if runtime is None or not isinstance(entry, dict):
                continue
            woken_at = _number(entry.get(CLOCK_WOKEN_AT))
            if woken_at is not None and -CLOCK_SLACK <= wall - woken_at < self.wake_timeout:
                runtime.woken_at = woken_at - offset
            hold = _number(entry.get(CLOCK_NEXT_WAKE_AT))
            if hold is not None and hold > wall:
                runtime.next_wake_at = min(hold, wall + MAX_HOLD) - offset
                runtime.wake_failures = min(_count(entry.get(CLOCK_WAKE_FAILURES)), MAX_WAKE_FAILURES)
            sent = _number(entry.get(CLOCK_POWER_OFF_SENT))
            if sent is not None and -CLOCK_SLACK <= wall - sent < self.wake_timeout:
                runtime.power_off_sent = sent - offset
            sent = _number(entry.get(CLOCK_RESTART_SENT))
            if sent is not None and -CLOCK_SLACK <= wall - sent < self.restart_hold:
                runtime.restart_sent = sent - offset

    def save_state(self):
        """The state file written anew (a temporary file renamed over it): at every change made
        by hand, by ``refresh`` when the runtime it keeps changed, and when the portal stops."""
        self._saved_key = self._state_key()
        if not self.state_file:
            return
        state = {KEY_VERSION: STATE_VERSION, KEY_SAVED_AT: round(time.time(), 3), **self._settings(),
                 KEY_CLOCKS: self._clocks()}
        try:
            os.makedirs(os.path.dirname(self.state_file) or '.', exist_ok=True)
            tmp = self.state_file + '.tmp'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, self.state_file)
        except OSError as e:
            self._not_saved(str(e))
            return
        if self.state_error:
            log.info("pool state saved again in %s", self.state_file)
            self.state_error = ''

    # -- status ---------------------------------------------------------------------------------

    @staticmethod
    def headers(host: HostConfig, identity: Identity | None = None) -> dict:
        headers = {'Authorization': f'Bearer {host.token}'}
        if identity is not None:
            headers.update(identity.headers())
        return headers

    def _consume(self, name: str, polled_at: float) -> int:
        """Forget the reservations released before the status request sent at *polled_at*;
        the number still counted."""
        self._reservations[name] = [r for r in self._reservations[name]
                                    if r.released_at is None or r.released_at > polled_at]
        return len(self._reservations[name])

    async def refresh_host(self, host: HostConfig) -> HostStatus:
        polled_at = time.monotonic()
        try:
            async with self.session.get(f"{host.url}/v1/status", headers=self.headers(host),
                                        timeout=aiohttp.ClientTimeout(total=STATUS_TIMEOUT)) as resp:
                if resp.status != 200:
                    status = HostStatus(error=f"status {resp.status}")
                else:
                    data = await resp.json()
                    status = status_from_json(data, self._consume(host.name, polled_at))
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            status = HostStatus(error=str(e) or type(e).__name__)
        if host.name not in self.status:
            return status   # removed meanwhile
        runtime = self.runtime[host.name]
        restarting = runtime.restart_sent is not None
        previous = self._reported.get(host.name)   # None at the first poll: always reported
        self._reported[host.name] = status.reachable
        if previous is None or previous != status.reachable:
            if status.reachable:
                log.info("host %s reachable: %s, sre %s, %d project(s)%s", host.name, status.hostname,
                         status.sre_version, status.projects, " (occupied)" if status.occupied else "")
            elif restarting:
                log.info("host %s restarting: not answering", host.name)
            else:
                log.warning("host %s unreachable at %s: %s", host.name, host.url, status.error)
        if previous is None and status.reachable and runtime.drain and self._booted_since(status, runtime.drain_at):
            # the first poll of a host whose drain comes from the state file: it went down and
            # came back while the portal was not running, and must not be powered off again
            log.info("host %s booted since its drain was asked: the drain is over", host.name)
            self._drain_over(runtime)
        if restarting:
            self._track_restart(host.name, status, runtime, polled_at)
        elif status.reachable and previous is False:
            # back after a shutdown: a drain, a power off and a backoff of the previous run are over
            self._drain_over(runtime)
            runtime.next_wake_at = 0.0
        elif not status.reachable and runtime.power_off_sent is not None:
            self._drain_over(runtime)       # gone after its power off: the drain is done
        if status.reachable and runtime.woken_at is not None:
            log.info("host %s is up %.0f s after its wake", host.name, time.monotonic() - runtime.woken_at)
            runtime.woken_at = None
            runtime.wake_failures = 0
            runtime.next_wake_at = 0.0
        if runtime.preload_granted is not None and polled_at > runtime.preload_granted:
            runtime.preload_granted = None      # this status was asked after the turn was given: it tells
        status.polled_at = polled_at
        if runtime.exam_told is not None:
            if polled_at > runtime.exam_told:
                runtime.exam_told, runtime.exam_view = None, None    # asked after the agent's answer: it tells
            elif status.reachable:
                # asked before the portal changed the exam file of the host: what the agent
                # answered then is newer than this status
                status.exam, status.exam_mode = runtime.exam_view, runtime.exam_view is not None
        if runtime.local_drain_told is not None:
            if polled_at > runtime.local_drain_told:
                runtime.local_drain_told, runtime.local_drain_view = None, None    # asked after the agent's answer: it tells
            elif status.reachable:
                # asked before the portal cancelled, allowed or forbade the local drain of the
                # host: what the agent answered then is newer than this status
                for key, value in runtime.local_drain_view.items():
                    setattr(status, key, value)
        self._report_preload(host.name, self.status[host.name], status)
        self._report_local_drain(host.name, self.status[host.name], status)
        self.status[host.name] = status
        return status

    def note_exam(self, name: str, view):
        """The agent of *name* answered a ``PUT`` / ``DELETE /v1/exam``: its exam file (``None``:
        removed) shown at once, and kept against a status asked before the answer."""
        if name not in self.status:
            return
        fields = host_exam_fields(view)
        runtime, status = self.runtime[name], self.status[name]
        runtime.exam_told, runtime.exam_view = time.monotonic(), fields
        status.exam, status.exam_mode, status.exam_known = fields, fields is not None, True

    def note_local_drain(self, name: str, view):
        """The agent of *name* answered a ``POST /v1/local-drain/...``: its local drain shown at
        once, and kept against a status asked before the answer."""
        if name not in self.status:
            return
        fields = local_drain_fields(view)
        runtime, status = self.runtime[name], self.status[name]
        runtime.local_drain_told, runtime.local_drain_view = time.monotonic(), fields
        before = replace(status)
        for key, value in fields.items():
            setattr(status, key, value)
        self._report_local_drain(name, before, status)

    def draining(self, name: str) -> bool:
        """Whether a drain is wanted for *name*: the one of the portal (``set_drain``), or the
        one asked on the host itself (``sre set-drain`` there, told by its agent's status)."""
        st = self.status[name]
        return self.runtime[name].drain or (st.reachable and st.local_drain)

    def held_for_exam(self, name: str) -> bool:
        return bool(self.exam_hold is not None and self.exam_hold(name))

    @staticmethod
    def _report_preload(name: str, before: HostStatus, status: HostStatus):
        """The end of a preload of the Docker images the portal saw waiting or running."""
        if status.preload == before.preload or before.preload not in (PRELOAD_PENDING, PRELOAD_RUNNING):
            return
        if status.preload == PRELOAD_DONE:
            log.info("host %s: %d image(s) preloaded", name, status.preload_total)
        elif status.preload == PRELOAD_FAILED:
            log.warning("host %s: preload of the images failed: %s", name, status.preload_error)

    @staticmethod
    def _report_local_drain(name: str, before: HostStatus, status: HostStatus):
        """A drain asked on the host itself, or no longer asked while the host is there (gone
        with its power off, it says nothing)."""
        if status.local_drain and not before.local_drain:
            log.info("host %s asked for its own drain: no new project, power off when empty", name)
        elif before.local_drain and not status.local_drain and status.reachable:
            log.info("host %s: its own drain is no longer asked", name)

    @staticmethod
    def _drain_over(runtime: HostRuntime):
        runtime.drain, runtime.drain_at = False, 0.0
        runtime.power_off_sent = None

    @staticmethod
    def _booted_since(status: HostStatus, asked_at: float) -> bool:
        """Whether the host booted after the wall-clock time *asked_at* (unknown, or no uptime
        in the status: no)."""
        return asked_at > 0 and status.uptime is not None and time.time() - status.uptime > asked_at + BOOT_MARGIN

    def _track_restart(self, name: str, status: HostStatus, runtime: HostRuntime, polled_at: float):
        """A restart was sent to the agent (``restart_sent``): over when its uptime is younger
        than the request (a fast restart may fall between two polls), given up with a warning
        after ``restart_hold`` seconds without it, unless the agent says the restart is still
        pending (a sre command in flight delays it).  Meanwhile the host takes no project, the
        policy leaves it alone and a drain survives the restart (``refresh_host`` skips its
        "back after a shutdown" reset)."""
        elapsed = polled_at - runtime.restart_sent
        # the agent rounds its uptime to the second: half a second of margin, so that an agent
        # younger than that at the request can never look restarted before it is
        if status.reachable and status.agent_uptime is not None and status.agent_uptime + 0.5 < elapsed:
            log.info("host %s back %.0f s after its restart (sre %s)", name, elapsed, status.sre_version)
            runtime.restart_sent = None
        elif elapsed > self.restart_hold and not (status.reachable and status.restarting):
            log.warning("host %s: no restart seen within %.0f s (%s)", name, self.restart_hold,
                        f"agent up for {status.agent_uptime} s" if status.reachable else "unreachable")
            runtime.restart_sent = None

    async def refresh(self):
        await asyncio.gather(*(self.refresh_host(h) for h in list(self.hosts.values())))
        if self.state_file and self._state_key() != self._saved_key:
            self.save_state()       # a drain over, a wake, a power off or a restart sent since the last save

    async def _loop(self):
        while True:
            try:
                await self.refresh()
            except Exception:
                log.exception("pool refresh failed")
            await asyncio.sleep(self.poll_interval)

    def start(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # -- states -----------------------------------------------------------------------------------

    def state_of(self, name: str, now: float | None = None) -> str:
        st, rt = self.status[name], self.runtime[name]
        now = time.monotonic() if now is None else now
        if not rt.enabled:
            return STATE_DISABLED
        if not st.reachable:
            return STATE_WAKING if rt.woken_at is not None and now - rt.woken_at < self.wake_timeout else STATE_OFF
        if st.exam_mode:
            return STATE_EXAM
        if st.occupied:
            return STATE_OCCUPIED
        if self.draining(name):
            return STATE_DRAINING
        return STATE_UP

    def summary(self, now: float | None = None) -> list:
        now = time.monotonic() if now is None else now
        rows = []
        for h in self.hosts.values():
            st, rt = self.status[h.name], self.runtime[h.name]
            rows.append({
                'name': h.name, 'url': h.url, 'max_projects': h.max_projects, 'state': self.state_of(h.name, now),
                'source': rt.source, 'enabled': rt.enabled, 'can_wake': h.can_wake, 'power': h.power,
                'instructors_only': h.instructors_only, 'priority': rt.priority,
                # a drain is wanted: the portal's, or the one asked on the host (``local_drain``, below)
                'drain': self.draining(h.name), 'power_off_sent': rt.power_off_sent is not None,
                'restart_sent': rt.restart_sent is not None,
                'waking_for': round(now - rt.woken_at) if rt.woken_at is not None else None,
                'wake_failures': rt.wake_failures,
                'idle_for': round(now - rt.idle_since) if rt.idle_since is not None else None,
                'exam_hold': self.held_for_exam(h.name),
                'memory_room': self.memory_room(h.name),
                # the users in the Qt GUI are for the Watch page (``gui_users()``), not for the pool
                **{k: v for k, v in vars(st).items() if k not in ('updated', 'polled_at', 'gui_users')},
            })
        return rows

    def gui_users(self) -> dict:
        """The users with a running Qt GUI on each reachable host, as its last status said:
        ``{host name: [{login, fullname, since}]}``, the hosts without one left out."""
        found = {}
        for h in self.hosts.values():
            st = self.status[h.name]
            if st.reachable and st.gui_users:
                found[h.name] = [dict(user) for user in st.gui_users]
        return found

    # -- placement ------------------------------------------------------------------------------

    def memory_room(self, name: str) -> int | None:
        """The new projects the memory of *name* still holds (``project_memory_mb``): its
        available memory at the last poll divided by the memory of a project, less the starts in
        flight (a reservation counts until a status asked after the end of its start: the
        containers of a project starting may not show in the reading yet); ``None`` when the
        memory is not checked, or the agent does not tell it (unreachable, older than the key)."""
        st = self.status[name]
        if not self.project_memory_mb or not st.reachable or st.mem_available_mb is None:
            return None
        return max(0, st.mem_available_mb // self.project_memory_mb - len(self._reservations[name]))

    def _has_room(self, h: HostConfig) -> bool:
        """Below its ``max_projects`` and, with ``project_memory_mb``, memory for one more."""
        return self.status[h.name].projects < h.max_projects and self.memory_room(h.name) != 0

    def pick(self, identity: Identity | None = None, host: str | None = None) -> tuple:
        """The host of a new project and its reservation.  Without *host*: the host of a local
        login session of *identity* (``follow_local_sessions``: the workstation the user sits at,
        occupied by them, whatever its load), else, among the hosts up (enabled, reachable, not
        occupied, not in exam mode, not draining), with ``placement = "spread"`` the least loaded
        (projects / max_projects, then load), the one with the lowest priority among those
        without project (``set_priority``; a start in flight counts as a project), with
        ``placement = "pack"`` the one with the lowest priority, the fullest first among equal
        priorities (then load): the hosts left empty can be powered off;
        always with room (below their maximum, and memory for one more project with
        ``project_memory_mb``: ``memory_room``) and among the hosts *identity* may use: a host with
        ``instructors_only`` takes an instructor's project only, and the caller is a student
        without identity.  With *host* (an instructor naming one on the Open page): that host,
        when the identity may use it (403 otherwise), it is available to them (503) and has room
        (503).  The caller releases the reservation when the start is over."""
        instructor = identity is not None and identity.is_instructor
        now = time.monotonic()
        if host is not None:
            chosen = self.host(host)
            if chosen.instructors_only and not instructor:
                raise PoolError(403, "instructors only")
            if not self._available_to(chosen, identity, self.state_of(host, now))[0]:
                raise PoolError(503, f"the host {host} is not available", retry_after=60)
            if self.status[host].projects >= chosen.max_projects:
                raise PoolError(503, f"the host {host} is full", retry_after=60)
            if self.memory_room(host) == 0:
                raise PoolError(503, f"the host {host} has not enough free memory", retry_after=60)
            return self._reserve(chosen, PLACEMENT_NAMED)
        candidates = []
        waking = False
        for h in self.hosts.values():
            if h.instructors_only and not instructor:
                continue
            state = self.state_of(h.name, now)
            waking = waking or state == STATE_WAKING or self.runtime[h.name].restart_sent is not None
            available, placement = self._available_to(h, identity, state)
            if not available or not self._has_room(h):
                continue
            st, priority = self.status[h.name], self.runtime[h.name].priority
            fill, load = st.projects / h.max_projects, st.load1 if st.load1 is not None else 0.0
            if self.placement == PLACEMENT_PACK:
                # the lowest priority until it is full, the fullest among equal ones: the
                # projects gather on the fewest hosts, the others empty
                candidates.append((placement != PLACEMENT_SESSION, priority, -fill, load, h.name, h, placement))
            else:
                # the priority only tells the hosts without project apart: the least loaded host
                # is one of them whenever there is one, and the loaded hosts are settled as before
                candidates.append((placement != PLACEMENT_SESSION, fill, priority if st.projects == 0 else 0,
                                   load, h.name, h, placement))
        if not candidates:
            if waking:
                raise PoolError(503, "a host is starting, please retry in a moment", retry_after=30)
            raise PoolError(503, "no host available for a new project", retry_after=60)
        candidates.sort(key=lambda c: c[:5])
        return self._reserve(candidates[0][5], candidates[0][6])

    def _available_to(self, h: HostConfig, identity: Identity | None, state: str) -> tuple:
        """Whether a new project of *identity* may go on *h*, in *state*, and what the placement
        would be: a host up (``PLACEMENT_LOAD``), or a host occupied by a local login session of
        the user (``PLACEMENT_SESSION``, with ``follow_local_sessions``; not when a power off is
        wanted: ``state_of`` hides the drain behind the occupation).  Never a host whose agent
        is about to restart (it refuses new projects meanwhile), nor a machine an exam keeps
        for itself (``exam_hold``: about to be locked by its ``exam.json``)."""
        if self.runtime[h.name].restart_sent is not None or self.held_for_exam(h.name):
            return False, ''
        if state == STATE_UP:
            return True, PLACEMENT_LOAD
        if (state == STATE_OCCUPIED and self.follow_local_sessions and identity is not None
                and not self.draining(h.name)
                and SESSION_PREFIX + identity.login in self.status[h.name].occupied_by):
            return True, PLACEMENT_SESSION
        return False, ''

    def _reserve(self, host: HostConfig, placement: str = PLACEMENT_LOAD) -> tuple:
        self.status[host.name].projects += 1
        reservation = Reservation(placement=placement)
        self._reservations[host.name].append(reservation)
        return host, reservation

    @staticmethod
    def release(reservation):
        reservation.released_at = time.monotonic()

    # -- projects -------------------------------------------------------------------------------

    async def _gather(self, identity: Identity, path: str, params=None) -> list:
        """The rows of ``GET {host}/v1{path}`` on every reachable host, each with ``host`` set to
        the host's name; a host that fails or answers something else than a list of dicts
        contributes nothing (logged)."""
        async def one(host: HostConfig):
            try:
                async with self.session.get(f"{host.url}/v1{path}", headers=self.headers(host, identity),
                                            params=params, timeout=aiohttp.ClientTimeout(total=STATUS_TIMEOUT)) as resp:
                    if resp.status != 200:
                        log.warning("host %s: GET /v1%s answered %s: %s", host.name, path, resp.status,
                                    (await resp.text())[:300])
                        return []
                    rows = await resp.json()
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                log.warning("host %s: GET /v1%s failed: %s", host.name, path, e or type(e).__name__)
                return []
            if not isinstance(rows, list):
                return []
            return [dict(p, host=host.name) for p in rows if isinstance(p, dict)]
        results = await asyncio.gather(*(one(h) for h in list(self.hosts.values()) if self.status[h.name].reachable))
        return [p for group in results for p in group]

    async def projects_of(self, identity: Identity, *, all_projects: bool = False) -> list:
        """The projects of a user on every reachable host: ``[{host, ...project}]``; with
        *all_projects* (an instructor's Watch page) every project of every host, with the owner's
        name and the last archived evaluation."""
        projects = await self._gather(identity, '/projects', {'all': '1'} if all_projects else None)
        projects.sort(key=lambda p: (p.get('started_at', ''), p.get('running_lab_name', '')))
        return projects

    async def evaluations_of(self, identity: Identity, lab: str) -> list:
        """The lab summary of the Watch page: every running project of *lab* on every reachable
        host with the elements of its last archived evaluation (``GET /v1/evaluations`` of the
        agents), by owner."""
        rows = await self._gather(identity, '/evaluations', {'lab': lab})
        rows.sort(key=lambda p: (p.get('owner', ''), p.get('started_at', ''), p.get('running_lab_name', '')))
        return rows

    def _labs_hosts(self, identity: Identity) -> list:
        """The hosts whose lab list may be served to *identity*, the most likely placement of a
        new project of theirs first: the enabled reachable hosts they may use (a reserved host
        for an instructor only), the hosts up before the others (occupied, draining, in exam
        mode: no project goes there, but they serve the same lab tree), the least loaded first."""
        now = time.monotonic()
        rows = []
        for h in self.hosts.values():
            if h.instructors_only and not identity.is_instructor:
                continue
            st, rt = self.status[h.name], self.runtime[h.name]
            if not rt.enabled or not st.reachable:
                continue
            rows.append((self.state_of(h.name, now) != STATE_UP, st.projects / h.max_projects,
                         st.load1 if st.load1 is not None else 0.0, h.name, h))
        rows.sort(key=lambda r: r[:4])
        return [r[4] for r in rows]

    def report_hosts(self, identity: Identity) -> list:
        """The hosts able to answer a request any host of the pool can serve for *identity* (the
        reports of the Archives page: one agent runs ``sre report`` on the records the portal
        gives), the most available first, as ``_labs_hosts``."""
        return self._labs_hosts(identity)

    async def labs(self, identity: Identity, *, all_labs: bool = False) -> list:
        """The lab list of the pool for *identity*, ``[{name, title, kind, sort}]`` in the display
        order the host gives (``sre list --with-titles``: the tree flattened, a directory entry
        before its content, the ``title`` mode sorted by the browser): the one of the host a new
        project of theirs would most likely go to (every host of a pool serves the same lab
        tree), the next candidate when it fails, nothing when no host answers.  Kept
        ``labs_cache_ttl`` seconds per role (the reserved hosts are the instructors' only), so
        that the Open page costs one ``sre list`` per minute whatever the size of the pool; the
        requests of one role wait for the one fetching.  *all_labs* (an instructor: the exam-only
        labs too, ``GET /v1/labs?all=1``) is a list of its own."""
        key = (identity.is_instructor, all_labs)
        lock = self._labs_locks.setdefault(key, asyncio.Lock())
        async with lock:
            cached = self._labs_cache.get(key)
            if cached is not None and time.monotonic() - cached[0] < self.labs_cache_ttl:
                return cached[1]
            for host in self._labs_hosts(identity):
                labs = await self._labs_of(host, identity, {'all': '1'} if all_labs else None)
                if labs is not None:
                    self._labs_cache[key] = (time.monotonic(), labs)
                    return labs
            return []

    def lab_titles(self) -> dict:
        """The titles of the labs any cached list knows (``{name: title}``; the names of the
        exam-only labs come from the ``all_labs`` list of the instructors)."""
        titles = {}
        for _, labs in self._labs_cache.values():
            for entry in labs:
                if entry.get('kind') == LAB_KIND_LAB and entry.get('title') is not None:
                    titles.setdefault(entry['name'], entry['title'])
        return titles

    async def _labs_of(self, host: HostConfig, identity: Identity, params=None) -> list | None:
        """``GET /v1/labs`` of one host, normalised (``[{name, title, kind, sort}]``, a bare name
        accepted as a lab, an unknown kind or sort mode replaced by the default, duplicates
        dropped, the order kept); ``None`` when the host does not answer a list.  A directory
        entry keeps its README (``readme_of``: ``LAB_README_KEY``, shown under the tree of the
        Open page when the directory is opened), and the entry without name, the top of the lab
        directory, is kept for its README only: it is no entry of the tree."""
        try:
            async with self.session.get(f"{host.url}/v1/labs", headers=self.headers(host, identity), params=params,
                                        timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    log.warning("host %s: GET /v1/labs answered %s: %s", host.name, resp.status,
                                (await resp.text())[:300])
                    return None
                labs = await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            log.warning("host %s: GET /v1/labs failed: %s", host.name, e or type(e).__name__)
            return None
        if not isinstance(labs, list):
            log.warning("host %s: GET /v1/labs gave no list", host.name)
            return None
        seen: dict[str, dict] = {}
        for entry in labs:
            if isinstance(entry, str):
                entry = {'name': entry}
            if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or entry['name'] in seen:
                continue
            kind, mode = entry.get('kind'), entry.get('sort')
            readme = readme_of(entry) if kind == LAB_KIND_DIR else {}
            if not entry['name'] and not readme:
                continue
            seen[entry['name']] = {'name': entry['name'], 'title': entry.get('title'),
                                   'kind': kind if kind in LAB_KINDS else LAB_KIND_LAB,
                                   'sort': mode if mode in LAB_SORT_MODES else LAB_SORT_NAME}
            if readme:
                seen[entry['name']][LAB_README_KEY] = readme
        return list(seen.values())
