#!/usr/bin/env python3
"""web-stress: a load generator for the SRE web front-end (``sre-web`` + the pool agents).

Simulates N students using the portal through its HTTP / WebSocket API exactly as the browser
does, in proxy authentication mode: the identity of each student travels in the ``X-Remote-*``
headers the reverse proxy would set, so the tool must run on a host the portal trusts
(``trusted_proxies`` of web.toml: the loopback of the portal's host in production).

Each student (login ``<prefix>001``...), after ``i * ramp / users`` seconds:

1. the Projects page: ``GET /projects``, the i18n catalog, the presence WebSocket, ``GET /api/projects``
   then every 5 s (``--browse`` seconds, like a student looking at the page);
2. the Open page: ``GET /open``, the presence WebSocket, ``GET /api/labs``;
3. ``POST /api/projects`` and the NDJSON stream until the ``result`` line (a 503 / 429 is retried
   after its ``retry_after``: the portal's start limit is consumed before the placement);
4. the project page: ``GET /projects/<host>/<rln>``, the presence WebSocket, the project JSON, the
   schema SVG, one ``GET /api/projects`` (the new project must be listed), the events WebSocket
   kept open (reconnected with the browser's backoff when it closes), ``POST .../touch`` every 60 s;
5. one terminal WebSocket on the first device that allows a connection, a few shell commands typed
   as the browser sends them (``--commands``, ``{login}`` substituted; the first one is checked for
   its echo), kept open with the page;
6. during ``--hold`` seconds: ``--answers`` saves of the answers and ``--evals`` self-evaluations,
   spread evenly;
7. ``DELETE /api/projects/<host>/<rln>`` (unless ``--keep``) and the sockets closed.

Side tasks: ``--instructor`` (one instructor watching the class: the Watch page's ``GET /api/watch``
and the Pool page's calls every 5 s), ``--admin-token`` (the pool rows of ``GET /api/pool`` every
5 s, with the ``[admin] token`` of web.toml: ``reachable`` flips show the status polls timing out),
``--probe`` (``GET /api/me`` every 2 s: the responsiveness of the portal's event loop).

Output: a summary on stdout (one line per phase with the latencies and the statuses, the students
completed, the checks failed, the hosts used, the pool flips), ``--report FILE`` (JSON: everything,
one entry per student) and ``--events FILE`` (CSV: one line per request / socket event).  Exit
status 0 when every student completed with every check true, 1 otherwise, 2 on a setup error
(the portal does not trust this peer, the lab is unknown...).  ``--cleanup`` stops every project
of the synthetic logins (through the instructor identity) and exits.

Stage 1 (no Docker): ``scripts/web-fake-pool.py`` launches a portal and fake agents on the mock
``sre`` and runs this tool against them.  Stage 2: on the portal's host, against the portal itself
(``--portal http://127.0.0.1:8450``).  Needs Python >= 3.11 and aiohttp; nothing from the SRE tree.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import math
import random
import re
import signal
import sys
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import aiohttp
except ImportError:                       # pragma: no cover - the usage message is still readable
    aiohttp = None

CSRF_HEADER = 'X-Requested-With'          # portal/session.py CSRF_HEADER / CSRF_VALUE
CSRF_VALUE = 'sre-web'
TERMINAL_SUBPROTOCOL = 'sre-term.v1'
RLN_SEPARATOR = '@@@'                      # <timestamp>@@@<lab>@@@<owner>
LOGIN_RE = re.compile(r'^[a-zA-Z0-9._-]+$')

POLL_INTERVAL = 5.0                       # projects.js REFRESH_INTERVAL
TOUCH_INTERVAL = 60.0                     # project.js TOUCH_INTERVAL
WATCH_INTERVAL = 5.0                      # watch.js / pool.js
PROBE_INTERVAL = 2.0
POOL_SAMPLE_INTERVAL = 5.0
RECONNECT_FIRST = 1.0                     # events.js ReconnectingSocket
RECONNECT_MAX = 30.0
WS_HEARTBEAT = 30.0
STREAM_TIMEOUT = 10.0                     # sock_connect of the streams and sockets
SCHEMA_QUERY = 'curved=0&sep=3&order=forward&icons=0'   # settings.js defaults of the Schema tab
DEFAULT_COMMANDS = ('echo stress-{login}', 'hostname', 'ls /')
CLEANUP_PARALLEL = 8

# phases (the rows of the summary, the `phase` column of the CSV)
PHASE_ME = 'me'
PHASE_PAGE = 'page'
PHASE_I18N = 'i18n'
PHASE_PRESENCE = 'presence_ws'
PHASE_PROJECTS = 'projects_list'
PHASE_PROJECTS_POLL = 'projects_poll'
PHASE_LABS = 'labs'
PHASE_START = 'start'
PHASE_PROJECT_GET = 'project_get'
PHASE_SCHEMA = 'schema'
PHASE_EVENTS = 'events_ws'
PHASE_TOUCH = 'touch'
PHASE_TERMINAL = 'terminal_ws'
PHASE_COMMAND = 'terminal_cmd'
PHASE_ANSWERS = 'answers'
PHASE_EVAL = 'eval'
PHASE_STOP = 'stop'
PHASE_WATCH = 'watch'
PHASE_POOL_PAGE = 'pool_page'
PHASE_POOL = 'pool_sample'
PHASE_ORDER = (PHASE_PAGE, PHASE_I18N, PHASE_PRESENCE, PHASE_PROJECTS, PHASE_PROJECTS_POLL, PHASE_LABS, PHASE_START,
               PHASE_PROJECT_GET, PHASE_SCHEMA, PHASE_EVENTS, PHASE_TOUCH, PHASE_TERMINAL, PHASE_COMMAND, PHASE_ANSWERS,
               PHASE_EVAL, PHASE_STOP, PHASE_WATCH, PHASE_POOL_PAGE, PHASE_POOL, PHASE_ME)

# statuses of a sample: an HTTP status, the status of a `result` line, or one of these
STATUS_OK = 'ok'
STATUS_ERROR = 'error'
STATUS_TIMEOUT = 'timeout'
STATUS_CREATED = 'created'
WS_PREFIX = 'ws:'                         # a socket closed: ws:<close code>
WS_OK_CODES = {1000, 1001}

# the checks of a student (True / False in StudentResult.checks when evaluated)
CHECK_IDENTITY = 'identity_ok'
CHECK_LAB = 'lab_listed'
CHECK_OWN = 'own_projects_only'
CHECK_LISTED = 'project_listed'
CHECK_ECHO = 'terminal_echo'
CHECK_GRADES = 'eval_grades'
CHECK_EVENTS = 'events_stayed_open'
CHECK_REMOVED = 'no_unexpected_removed'
CHECK_STOPPED = 'stopped'

EVENT_REMOVED = 'removed'
RESULT_CREATED = 'created'
RESULT_FLAVOR_FORM = 'flavor_form'
RESULT_FLAVOR_ERROR = 'flavor_error'
RESULT_ERROR = 'error'
ROLE_INSTRUCTOR = 'instructor'
QUESTION_DUMMY, QUESTION_TEXT, QUESTION_FORM = 0, 1, 2     # SRE.common.QuestionType, as the project JSON gives them

ENV_PORTAL = 'SRE_STRESS_PORTAL'          # set by web-fake-pool.py for the command it runs
ENV_ADMIN_TOKEN = 'SRE_STRESS_ADMIN_TOKEN'


class SetupError(Exception):
    """The run cannot even begin (exit status 2)."""


# ---------------------------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------------------------

@dataclass
class HeaderNames:
    """The identity headers of the proxy mode (production values: Apache's RequestHeader lines)."""
    user: str = 'X-Remote-User'
    name: str = 'X-Remote-Name'
    email: str = 'X-Remote-Email'
    group: str = 'X-Remote-Group'
    instructor: str = 'X-Remote-Gid'
    instructor_value: str = '2000'


@dataclass
class Options:
    portal: str
    users: int = 10
    login_prefix: str = 'stress'
    first: int = 1
    lab: str = 'sre/dhcp.py'
    flavor: dict | None = None
    ramp: float = 0.0
    hold: float = 600.0
    browse: float = 10.0
    terminal: bool = True
    commands: tuple = DEFAULT_COMMANDS
    type_pause: float = 2.0
    prompt_timeout: float = 20.0
    answers: int = 2
    evals: int = 1
    keep: bool = False
    instructor: bool = False
    admin_token: str = ''
    probe: bool = False
    report: str = ''
    events: str = ''
    language: str = 'en'
    group: str = 'stress'
    headers: HeaderNames = field(default_factory=HeaderNames)
    timeout: float = 60.0
    start_interval: float = 30.0
    start_retries: int = 10
    verbose: bool = False
    watch_interval: float = WATCH_INTERVAL      # the instructor's polls (the tests shorten it)

    def __post_init__(self):
        self.portal = self.portal.rstrip('/')
        if not LOGIN_RE.match(self.login_prefix):
            raise ValueError(f"bad login prefix {self.login_prefix!r}")

    @property
    def instructor_login(self) -> str:
        return f"{self.login_prefix}-instructor"


def login_of(prefix: str, index: int) -> str:
    return f"{prefix}{index:03d}"


def identity_headers(opts: Options, login: str, *, fullname: str = '', instructor: bool = False) -> dict:
    """The headers of one request of *login* (what Apache sets from the directory)."""
    h = opts.headers
    headers = {h.user: login, h.name: fullname or f"Stress {login.removeprefix(opts.login_prefix).strip('-') or login}",
               h.email: f"{login}@stress.invalid"}
    if opts.group and not instructor:
        headers[h.group] = opts.group
    if instructor and h.instructor:
        headers[h.instructor] = h.instructor_value
    return headers


# ---------------------------------------------------------------------------------------------
# samples, results, statistics
# ---------------------------------------------------------------------------------------------

@dataclass
class Sample:
    t: float            # seconds since the start of the run
    login: str
    phase: str
    status: str         # an HTTP status, a result status, ok / error / timeout, or ws:<code>
    latency: float
    detail: str = ''


def status_ok(status: str) -> bool:
    if status in (STATUS_OK, STATUS_CREATED):
        return True
    if status.startswith(WS_PREFIX):
        code = status[len(WS_PREFIX):]
        return code.isdigit() and int(code) in WS_OK_CODES
    return status.isdigit() and 200 <= int(status) < 300


class Recorder:
    """The sink of the samples: kept in memory, and appended to the CSV file when asked."""

    CSV_FIELDS = ('t', 'login', 'phase', 'status', 'latency', 'detail')

    def __init__(self, events_file: str = '', verbose: bool = False):
        self.samples: list[Sample] = []
        self.started = time.monotonic()
        self.verbose = verbose
        self._file = open(events_file, 'w', newline='') if events_file else None
        self._csv = csv.writer(self._file) if self._file else None
        if self._csv:
            self._csv.writerow(self.CSV_FIELDS)

    def add(self, login: str, phase: str, status: str, latency: float, detail: str = '') -> Sample:
        sample = Sample(round(time.monotonic() - self.started, 3), login, phase, str(status), round(latency, 4), detail)
        self.samples.append(sample)
        if self._csv:
            self._csv.writerow([sample.t, sample.login, sample.phase, sample.status, sample.latency, sample.detail])
        if self.verbose:
            print(f"{sample.t:9.3f} {sample.login:16} {sample.phase:14} {sample.status:8} {sample.latency:7.3f} "
                  f"{sample.detail}", file=sys.stderr)
        return sample

    def timed(self, login: str, phase: str) -> 'Timing':
        return Timing(self, login, phase)

    def close(self):
        if self._file:
            self._file.close()
            self._file = None


class Timing:
    """``async with recorder.timed(login, phase) as t: ...; t.status = '200'``: one sample per block,
    ``error`` / ``timeout`` when the block raises."""

    def __init__(self, recorder: Recorder, login: str, phase: str):
        self.recorder, self.login, self.phase = recorder, login, phase
        self.status = STATUS_OK
        self.detail = ''
        self.sample: Sample | None = None

    async def __aenter__(self):
        self.t0 = time.monotonic()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type is not None and issubclass(exc_type, asyncio.CancelledError):
            return False                      # the page was closed meanwhile: not a measurement
        if exc_type is not None:
            self.status = STATUS_TIMEOUT if issubclass(exc_type, asyncio.TimeoutError) else STATUS_ERROR
            self.detail = self.detail or f"{exc_type.__name__}: {exc}"[:200]
        self.sample = self.recorder.add(self.login, self.phase, self.status, time.monotonic() - self.t0, self.detail)
        return False


@dataclass
class StudentResult:
    login: str
    host: str = ''
    rln: str = ''
    completed: bool = False
    failure: str = ''
    checks: dict = field(default_factory=dict)
    events_received: dict = field(default_factory=dict)
    events_close_codes: list = field(default_factory=list)
    terminal_close_code: int | None = None
    start_attempts: int = 0
    start_seconds: float | None = None

    @property
    def ok(self) -> bool:
        return self.completed and all(self.checks.values())


@dataclass
class PoolSample:
    t: float
    rows: list        # [{name, state, reachable, projects, terminals, load1, error}]


POOL_ROW_KEYS = ('name', 'state', 'reachable', 'projects', 'max_projects', 'terminals', 'load1', 'error')


@dataclass
class PhaseStats:
    count: int = 0
    ok: int = 0
    errors: int = 0
    p50: float = 0.0
    p95: float = 0.0
    max: float = 0.0
    by_status: dict = field(default_factory=dict)


def percentile(values: list, p: float) -> float:
    """Nearest-rank percentile of *values* (0 for none)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), math.ceil(p / 100 * len(ordered))))
    return ordered[rank - 1]


def phase_stats(samples: list) -> dict:
    """``{phase: PhaseStats}`` in the order of PHASE_ORDER (unknown phases last)."""
    by_phase: dict = {}
    for s in samples:
        by_phase.setdefault(s.phase, []).append(s)
    result = {}
    for phase in sorted(by_phase, key=lambda p: (PHASE_ORDER.index(p) if p in PHASE_ORDER else len(PHASE_ORDER), p)):
        group = by_phase[phase]
        latencies = [s.latency for s in group]
        statuses = Counter(s.status for s in group)
        oks = sum(1 for s in group if status_ok(s.status))
        result[phase] = PhaseStats(count=len(group), ok=oks, errors=len(group) - oks, p50=percentile(latencies, 50),
                                   p95=percentile(latencies, 95), max=max(latencies), by_status=dict(statuses))
    return result


def pool_flips(samples: list) -> dict:
    """How many times the ``reachable`` flag of each host changed between two consecutive samples."""
    last: dict = {}
    flips: Counter = Counter()
    for sample in samples:
        for row in sample.rows:
            name, reachable = row.get('name'), bool(row.get('reachable'))
            if name in last and last[name] != reachable:
                flips[name] += 1
            last[name] = reachable
    return dict(flips)


def host_distribution(students: list) -> dict:
    return dict(Counter(s.host for s in students if s.host))


def retry_delay(phase: str, status, retry_after, attempt: int, opts: Options) -> float | None:
    """Seconds to wait before the attempt *attempt* + 1 of *phase* after *status*, None when the
    call is not retried.  A start refused by the pool (503) is retried after the longer of the
    pool's retry_after and the portal's start interval (consumed before the placement)."""
    retry_after = float(retry_after or 0)
    status = str(status)
    if phase == PHASE_START:
        if status == '503' and attempt < opts.start_retries:
            return max(retry_after, opts.start_interval) + 1
        if status == '429' and attempt < opts.start_retries:
            return retry_after + 1
        if status in ('500', '502', '504', RESULT_ERROR, RESULT_FLAVOR_ERROR) and attempt < 3:
            return 5.0 * attempt
        return None
    if phase == PHASE_EVAL:
        if status == '429' and attempt < 3:
            return retry_after + 1
        if status == '409' and attempt < 3:
            return 5.0
        return None
    return None


def pick_terminal_device(project: dict) -> str | None:
    """The device the Terminals tab opens by itself: the first one that allows a connection,
    machines before switches."""
    devices = [d for d in project.get('terminal_devices', []) or [] if d.get('allow_connection')]
    for kind in ('machine', 'switch'):
        for d in devices:
            if d.get('kind', 'machine') == kind and d.get('name'):
                return d['name']
    return None


FORM_CANDIDATES = ('stress', '1', '10.0.0.1', 'a')


def answers_payload(project: dict, login: str, n: int) -> dict:
    """An answer to every question of the project: a text for a text question, a ``{field:
    value}`` dict for a form (a checkbox ticked, the first option of a select, a line that
    matches the regex of the field)."""
    answers = {}
    for q in project.get('questions', []) or []:
        q_hash = q.get('question_hash')
        q_type = q.get('question_type', QUESTION_TEXT)
        if not q_hash or q_type == QUESTION_DUMMY:       # a display-only question takes no answer
            continue
        if q_type == QUESTION_FORM or 'chunks' in q:
            values = {}
            for chunk in q.get('chunks', []) or []:
                if chunk.get('type') != 'field' or not chunk.get('name'):
                    continue
                kind = chunk.get('kind', 'line')
                if kind == 'checkbox':
                    values[chunk['name']] = True
                elif kind == 'select':
                    options = chunk.get('options') or []
                    values[chunk['name']] = options[0] if options else ''
                elif kind == 'submit':
                    continue
                else:
                    default = chunk.get('default')
                    regex = chunk.get('regex') or ''
                    value = default if default not in (None, '') else FORM_CANDIDATES[0]
                    if regex:
                        for candidate in ((default,) if default else ()) + FORM_CANDIDATES:
                            try:
                                if re.fullmatch(regex, str(candidate)):
                                    value = candidate
                                    break
                            except re.error:
                                break
                    values[chunk['name']] = value
            answers[q_hash] = values
        else:
            answers[q_hash] = f"answer {n} by {login}"
    return answers


# ---------------------------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------------------------

@dataclass
class Report:
    options: dict
    started_at: str
    duration: float
    students: list
    phases: dict
    pool: list
    pool_flips: dict
    hosts: dict
    probe: PhaseStats | None
    instructor: dict

    @property
    def exit_code(self) -> int:
        return 0 if self.students and all(s.ok for s in self.students) else 1

    def to_json(self) -> dict:
        return {
            'options': self.options, 'started_at': self.started_at, 'duration': round(self.duration, 3),
            'students': [asdict(s) for s in self.students],
            'phases': {name: asdict(st) for name, st in self.phases.items()},
            'pool': [asdict(p) for p in self.pool], 'pool_flips': self.pool_flips, 'hosts': self.hosts,
            'probe': asdict(self.probe) if self.probe else None, 'instructor': self.instructor,
            'completed': sum(1 for s in self.students if s.completed),
            'ok': sum(1 for s in self.students if s.ok),
        }

    def summary(self) -> str:
        return format_summary(self)


def format_summary(report: Report) -> str:
    o = report.options
    lines = [f"web-stress: {o.get('users')} users, lab {o.get('lab')}, ramp {o.get('ramp')} s, hold {o.get('hold')} s, "
             f"{report.duration:.1f} s"]
    lines.append(f"{'phase':14} {'n':>5} {'ok':>5} {'err':>5} {'p50':>8} {'p95':>8} {'max':>8}   statuses")
    for name, st in report.phases.items():
        statuses = ' '.join(f"{k}={v}" for k, v in sorted(st.by_status.items(), key=lambda kv: -kv[1]))
        lines.append(f"{name:14} {st.count:5d} {st.ok:5d} {st.errors:5d} {st.p50:8.3f} {st.p95:8.3f} {st.max:8.3f}   "
                     f"{statuses}")
    students = report.students
    completed = sum(1 for s in students if s.completed)
    failures = Counter(s.failure.split(':')[0] + ': ' + s.failure.split(':', 1)[1].strip()[:60] if ':' in s.failure
                       else s.failure for s in students if s.failure)
    lines.append(f"students: {completed}/{len(students)} completed, {sum(1 for s in students if s.ok)} fully ok"
                 + (f"; failures: " + ', '.join(f"{k} ({v})" for k, v in failures.most_common()) if failures else ''))
    failed_checks = Counter(name for s in students for name, value in s.checks.items() if value is False)
    lines.append("checks failed: " + (', '.join(f"{k} {v}" for k, v in failed_checks.most_common()) or 'none'))
    starts = [s.start_seconds for s in students if s.start_seconds is not None]
    if starts:
        lines.append(f"start to created: p50 {percentile(starts, 50):.1f} s, p95 {percentile(starts, 95):.1f} s, "
                     f"max {max(starts):.1f} s; attempts: "
                     + ' '.join(f"{k}={v}" for k, v in sorted(Counter(s.start_attempts for s in students).items())))
    if report.hosts:
        lines.append("hosts: " + ' '.join(f"{k}={v}" for k, v in sorted(report.hosts.items())))
    if report.pool:
        loads = [r.get('load1') for p in report.pool for r in p.rows if isinstance(r.get('load1'), (int, float))]
        projects = [r.get('projects') or 0 for p in report.pool for r in p.rows]
        unreachable = sum(1 for p in report.pool for r in p.rows if not r.get('reachable'))
        flips = ' '.join(f"{k}×{v}" for k, v in sorted(report.pool_flips.items())) or 'none'
        lines.append(f"pool: {len(report.pool)} samples; reachable flips {flips}; unreachable rows {unreachable}; "
                     f"max projects {max(projects) if projects else 0}"
                     + (f"; max load1 {max(loads):.1f}" if loads else ''))
    if report.probe:
        st = report.probe
        lines.append(f"probe GET /api/me: n {st.count}, p50 {st.p50:.3f}, p95 {st.p95:.3f}, max {st.max:.3f}, "
                     f"errors {st.errors}")
    if report.instructor:
        i = report.instructor
        lines.append(f"instructor: role {'ok' if i.get('role_ok') else 'NOT instructor'}, watch rows max "
                     f"{i.get('watch_rows_max', 0)} ({i.get('watch_stress_max', 0)} of the run), errors {i.get('errors', 0)}")
    return '\n'.join(lines)


# ---------------------------------------------------------------------------------------------
# one student
# ---------------------------------------------------------------------------------------------

def json_timeout(opts: Options) -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(total=opts.timeout)


def stream_timeout() -> aiohttp.ClientTimeout:
    """An NDJSON stream: a bounded connection, an unbounded wait for the lines."""
    return aiohttp.ClientTimeout(total=None, sock_connect=STREAM_TIMEOUT, sock_read=None)


def ws_timeout() -> 'aiohttp.ClientWSTimeout':
    return aiohttp.ClientWSTimeout(ws_receive=None, ws_close=STREAM_TIMEOUT)


def make_session(headers: dict) -> aiohttp.ClientSession:
    """One session per simulated browser: no connection limit, no cookies (the proxy mode has
    none), the identity headers on every request; the handshakes of its sockets are bounded by
    the default timeout."""
    return aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0), cookie_jar=aiohttp.DummyCookieJar(),
                                 headers=headers, timeout=stream_timeout())


async def body_json(resp) -> dict | list | None:
    try:
        return await resp.json(content_type=None)
    except (ValueError, aiohttp.ClientError):
        return None


def rln_owner(rln: str) -> str:
    parts = rln.split(RLN_SEPARATOR)
    return parts[2] if len(parts) >= 3 else ''


class Student:
    """One simulated student: a session of its own, the scenario of the module docstring."""

    def __init__(self, index: int, opts: Options, recorder: Recorder, stop: asyncio.Event):
        self.index = index
        self.opts = opts
        self.recorder = recorder
        self.stop = stop
        self.login = login_of(opts.login_prefix, opts.first + index)
        self.result = StudentResult(login=self.login)
        self.session: aiohttp.ClientSession | None = None
        self.api_base = ''
        self.project: dict = {}
        self.presence = None
        self.presence_task = None
        self.poll_task = None
        self.events_task = None
        self.touch_task = None
        self.terminal = None
        self.terminal_task = None
        self.terminal_output = bytearray()
        self.terminal_event = asyncio.Event()
        self.closing = False
        self.events_closes = 0

    # -- helpers --------------------------------------------------------------------------------

    def url(self, path: str) -> str:
        return self.opts.portal + path

    async def sleep(self, seconds: float) -> bool:
        """Sleep unless the run is stopped; False when it was."""
        if seconds <= 0:
            return not self.stop.is_set()
        try:
            await asyncio.wait_for(self.stop.wait(), seconds)
            return False
        except asyncio.TimeoutError:
            return True

    async def page(self, path: str) -> int:
        """An HTML page of the site (a 302 to /login = no identity)."""
        async with self.recorder.timed(self.login, PHASE_PAGE) as t:
            async with self.session.get(self.url(path), allow_redirects=False, timeout=json_timeout(self.opts)) as resp:
                await resp.read()
                t.status, t.detail = str(resp.status), path
                return resp.status

    async def i18n(self):
        async with self.recorder.timed(self.login, PHASE_I18N) as t:
            async with self.session.get(self.url(f"/i18n/{self.opts.language}.json"),
                                        timeout=json_timeout(self.opts)) as resp:
                await resp.read()
                t.status = str(resp.status)

    async def api(self, method: str, path: str, phase: str, *, json_body=None, detail: str = ''):
        """A JSON call of the API: ``(status, body)``, one sample; ``(0, None)`` when the call
        failed or timed out (recorded as such: the student goes on, as a browser would)."""
        headers = {} if method == 'GET' else {CSRF_HEADER: CSRF_VALUE}
        try:
            async with self.recorder.timed(self.login, phase) as t:
                t.detail = detail
                async with self.session.request(method, self.url(path), json=json_body, headers=headers,
                                                timeout=json_timeout(self.opts)) as resp:
                    body = await body_json(resp) if resp.status != 204 else None
                    t.status = str(resp.status)
                    if resp.status >= 400 and isinstance(body, dict) and body.get('error'):
                        t.detail = (detail + ' ' if detail else '') + str(body['error'])[:120]
                    return resp.status, body
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return 0, None

    async def open_presence(self, page: str):
        """The presence socket of a page (base.js): opened, frames read and dropped."""
        await self.close_presence()
        async with self.recorder.timed(self.login, PHASE_PRESENCE) as t:
            t.detail = page
            self.presence = await self.session.ws_connect(self.url('/api/presence/ws'), params={'page': page},
                                                          heartbeat=WS_HEARTBEAT, timeout=ws_timeout())
        self.presence_task = asyncio.create_task(self.drain(self.presence))

    @staticmethod
    async def drain(ws):
        try:
            async for _ in ws:
                pass
        except Exception:
            pass

    async def close_presence(self):
        if self.presence_task:
            self.presence_task.cancel()
            self.presence_task = None
        if self.presence:
            await self.presence.close()
            self.presence = None

    async def list_projects(self, phase: str) -> list | None:
        """``GET /api/projects``: the rows, every one of them ours; None when the call failed."""
        status, rows = await self.api('GET', '/api/projects', phase)
        if status == 401:
            raise SetupError("not logged in: the portal does not trust the identity headers of this peer")
        if not isinstance(rows, list):
            return None
        if any(rln_owner(r.get('running_lab_name', '')) != self.login for r in rows if isinstance(r, dict)):
            self.result.checks[CHECK_OWN] = False
        else:
            self.result.checks.setdefault(CHECK_OWN, True)
        return rows

    # -- the scenario ---------------------------------------------------------------------------

    async def run(self) -> StudentResult:
        self.session = make_session(identity_headers(self.opts, self.login))
        try:
            if not await self.sleep(self.index * self.opts.ramp / max(1, self.opts.users)):
                self.result.failure = 'stopped before the start'
                return self.result
            try:
                await self.scenario()
            except SetupError:
                raise
            except asyncio.CancelledError:
                self.result.failure = self.result.failure or 'cancelled'
                raise
            except Exception as e:                   # noqa: BLE001 - every failure is reported
                self.result.failure = self.result.failure or f"{self.phase_name}: {type(e).__name__}: {e}"[:300]
            finally:
                self.closing = True
                try:
                    await self.close()
                except Exception as e:               # noqa: BLE001
                    self.result.failure = self.result.failure or f"close: {type(e).__name__}: {e}"[:300]
        finally:
            await self.session.close()
        self.result.completed = not self.result.failure
        return self.result

    phase_name = 'setup'

    async def scenario(self):
        o = self.opts
        # 1. the Projects page
        self.phase_name = 'projects page'
        status = await self.page('/projects')
        self.result.checks[CHECK_IDENTITY] = status == 200
        if status != 200:
            raise SetupError(f"GET /projects answered {status}: the portal does not trust the identity headers "
                             "of this peer (trusted_proxies)")
        await self.i18n()
        await self.open_presence('/projects')
        await self.list_projects(PHASE_PROJECTS)
        self.poll_task = asyncio.create_task(self.poll_projects())
        if not await self.sleep(o.browse * random.uniform(0.5, 1.5)):
            return
        # 2. the Open page
        self.phase_name = 'open page'
        await self.page('/open')
        await self.i18n()
        await self.open_presence('/open')
        status, labs = await self.api('GET', '/api/labs', PHASE_LABS)
        names = {lab.get('name') for lab in labs if isinstance(lab, dict)} if isinstance(labs, list) else set()
        self.result.checks[CHECK_LAB] = o.lab in names
        if o.lab not in names:
            raise SetupError(f"the lab {o.lab} is not offered (GET /api/labs answered {status}, "
                             f"{len(names)} labs)")
        if not await self.sleep(o.browse * random.uniform(0.5, 1.5)):
            return
        # 3. the start
        self.phase_name = 'start'
        if not await self.start():
            return
        # 4. the project page
        self.phase_name = 'project page'
        if self.poll_task:
            self.poll_task.cancel()
            self.poll_task = None
        await self.page(f"/projects/{quote(self.result.host, safe='')}/{quote(self.result.rln, safe='@')}")
        await self.i18n()
        await self.open_presence(f"/projects/{self.result.host}/{self.result.rln}")
        status, body = await self.api('GET', self.api_base, PHASE_PROJECT_GET)
        if status != 200 or not isinstance(body, dict):
            raise RuntimeError(f"GET {self.api_base} answered {status}")
        self.project = body.get('project', {}) or {}
        async with self.recorder.timed(self.login, PHASE_SCHEMA) as t:
            async with self.session.get(self.url(f"{self.api_base}/schema.svg?{SCHEMA_QUERY}"),
                                        timeout=json_timeout(self.opts)) as resp:
                await resp.read()
                t.status = str(resp.status)
        rows = await self.list_projects(PHASE_PROJECTS)
        self.result.checks[CHECK_LISTED] = rows is not None and any(
            r.get('running_lab_name') == self.result.rln for r in rows if isinstance(r, dict))
        self.events_task = asyncio.create_task(self.events())
        self.touch_task = asyncio.create_task(self.touch())
        # 5. a terminal
        if o.terminal:
            self.phase_name = 'terminal'
            await self.open_terminal()
        # 6. the hold
        self.phase_name = 'hold'
        await self.hold()

    async def poll_projects(self):
        try:
            while True:
                await asyncio.sleep(POLL_INTERVAL)
                await self.list_projects(PHASE_PROJECTS_POLL)
        except asyncio.CancelledError:
            pass
        except Exception:                   # noqa: BLE001 - the sample holds the error
            pass

    async def start(self) -> bool:
        """``POST /api/projects`` until a project is created (the retry policy of retry_delay)."""
        o = self.opts
        attempt = 0
        body = {'lab': o.lab}
        if o.flavor:
            body['flavor'] = o.flavor
        t_first = time.monotonic()
        while True:
            attempt += 1
            self.result.start_attempts = attempt
            status, retry_after, obj = '', None, None
            async with self.recorder.timed(self.login, PHASE_START) as t:
                t.detail = f"attempt {attempt}"
                async with self.session.post(self.url('/api/projects'), json=body, headers={CSRF_HEADER: CSRF_VALUE},
                                             timeout=stream_timeout()) as resp:
                    if resp.status != 200:
                        obj = await body_json(resp)
                        status = str(resp.status)
                        retry_after = obj.get('retry_after') if isinstance(obj, dict) else None
                        t.status = status
                        if isinstance(obj, dict) and obj.get('error'):
                            t.detail += ' ' + str(obj['error'])[:120]
                    else:
                        async for raw in resp.content:
                            line = raw.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                            except ValueError:
                                continue
                            if obj.get('phase') == 'result':
                                break
                        else:
                            obj = {'status': RESULT_ERROR, 'message': 'the stream ended without a result line'}
                        status = str(obj.get('status', RESULT_ERROR))
                        t.status = status
                        t.detail = obj.get('host') or str(obj.get('message', ''))[:120] or t.detail
            if status == RESULT_CREATED:
                self.result.host = obj.get('host', '')
                self.result.rln = obj.get('running_lab_name', '')
                self.result.start_seconds = round(time.monotonic() - t_first, 3)
                self.api_base = f"/api/projects/{quote(self.result.host, safe='')}/{quote(self.result.rln, safe='@')}"
                return True
            if status == RESULT_FLAVOR_FORM:
                if o.flavor and 'flavor' not in body:
                    body['flavor'] = o.flavor
                    continue
                self.result.failure = "start: the lab asks a flavor form (give --flavor)"
                return False
            delay = retry_delay(PHASE_START, status, retry_after, attempt, o)
            if delay is None:
                self.result.failure = f"start: {status} {str((obj or {}).get('error') or (obj or {}).get('message', ''))[:100]}"
                return False
            if not await self.sleep(delay):
                self.result.failure = 'stopped while waiting to start'
                return False

    async def events(self):
        """The events socket of the project page: kept open, reconnected with the backoff of
        events.js; a ``removed`` before our own stop is a failure."""
        delay = RECONNECT_FIRST
        counts = self.result.events_received
        while not self.closing:
            try:
                async with self.recorder.timed(self.login, PHASE_EVENTS) as t:
                    ws = await self.session.ws_connect(self.url(f"{self.api_base}/events"), heartbeat=WS_HEARTBEAT,
                                                       timeout=ws_timeout())
                    t.status = STATUS_OK
                delay = RECONNECT_FIRST
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            kind = json.loads(msg.data).get('t', '?')
                        except (ValueError, AttributeError):
                            kind = '?'
                        counts[kind] = counts.get(kind, 0) + 1
                        if kind == EVENT_REMOVED and not self.closing:
                            self.result.checks[CHECK_REMOVED] = False
                    elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED,
                                      aiohttp.WSMsgType.ERROR):
                        break
                code = ws.close_code
                await ws.close()
                if self.closing:
                    return
                self.events_closes += 1
                self.result.events_close_codes.append(code)
                self.recorder.add(self.login, PHASE_EVENTS, f"{WS_PREFIX}{code}", 0.0, 'closed by the portal')
            except asyncio.CancelledError:
                raise
            except Exception as e:                   # noqa: BLE001 - counted, then the backoff
                if self.closing:
                    return
                self.events_closes += 1
                self.result.events_close_codes.append(None)
                self.recorder.add(self.login, PHASE_EVENTS, STATUS_ERROR, 0.0, f"{type(e).__name__}: {e}"[:120])
            await asyncio.sleep(delay)
            delay = min(RECONNECT_MAX, delay * 2)

    async def touch(self):
        try:
            while True:
                await asyncio.sleep(TOUCH_INTERVAL)
                await self.api('POST', f"{self.api_base}/touch", PHASE_TOUCH)
        except asyncio.CancelledError:
            pass
        except Exception:                   # noqa: BLE001
            pass

    async def open_terminal(self):
        device = pick_terminal_device(self.project)
        if device is None:
            self.result.checks[CHECK_ECHO] = False
            self.recorder.add(self.login, PHASE_TERMINAL, STATUS_ERROR, 0.0, 'no device allows a connection')
            return
        async with self.recorder.timed(self.login, PHASE_TERMINAL) as t:
            t.detail = device
            self.terminal = await self.session.ws_connect(self.url(f"{self.api_base}/terminals/{quote(device, safe='')}"),
                                                          params={'cols': '80', 'rows': '24'},
                                                          protocols=(TERMINAL_SUBPROTOCOL,), heartbeat=WS_HEARTBEAT,
                                                          timeout=ws_timeout())
            first = await asyncio.wait_for(self.terminal.receive(), self.opts.timeout)
            if first.type != aiohttp.WSMsgType.TEXT or json.loads(first.data).get('t') != 'ready':
                code = self.terminal.close_code
                t.status = f"{WS_PREFIX}{code}" if code else STATUS_ERROR
                t.detail = f"{device}: first frame {first.type.name} {str(first.data)[:80]}"
                self.result.terminal_close_code = code
                self.result.checks[CHECK_ECHO] = False
                return
        self.terminal_task = asyncio.create_task(self.read_terminal())
        # the prompt (an init machine gets the agent's probe newline after 5 s of silence)
        await self.wait_output(lambda out: len(out) > 0, self.opts.prompt_timeout)
        for i, command in enumerate(self.opts.commands):
            text = command.replace('{login}', self.login)
            marker = None
            if i == 0 and '{login}' in command:
                marker = f"stress-{self.login}".encode() if 'stress-{login}' in command else self.login.encode()
            async with self.recorder.timed(self.login, PHASE_COMMAND) as t:
                t.detail = text[:40]
                before = len(self.terminal_output)
                await self.terminal.send_bytes(text.encode() + b'\n')
                if marker:
                    echoed = await self.wait_output(
                        lambda out: marker in out[before:].split(text.encode())[-1], self.opts.timeout)
                    self.result.checks[CHECK_ECHO] = echoed
                    if not echoed:
                        t.status = STATUS_ERROR
                        t.detail += ' (no echo)'
            if not await self.sleep(self.opts.type_pause):
                return

    async def read_terminal(self):
        try:
            async for msg in self.terminal:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    self.terminal_output += msg.data
                    self.terminal_event.set()
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        obj = json.loads(msg.data)
                    except ValueError:
                        continue
                    if obj.get('t') == 'exit' and not self.closing:
                        self.recorder.add(self.login, PHASE_TERMINAL, STATUS_ERROR, 0.0, 'exit before the close')
                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED,
                                  aiohttp.WSMsgType.ERROR):
                    break
            self.result.terminal_close_code = self.terminal.close_code
            if not self.closing:
                self.recorder.add(self.login, PHASE_TERMINAL, f"{WS_PREFIX}{self.terminal.close_code}", 0.0,
                                  'closed before the end')
        except asyncio.CancelledError:
            pass
        except Exception as e:              # noqa: BLE001
            if not self.closing:
                self.recorder.add(self.login, PHASE_TERMINAL, STATUS_ERROR, 0.0, f"{type(e).__name__}: {e}"[:120])
        finally:
            self.terminal_event.set()

    async def wait_output(self, predicate, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            if predicate(bytes(self.terminal_output)):
                return True
            if self.terminal_task is None or self.terminal_task.done():
                return predicate(bytes(self.terminal_output))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self.terminal_event.clear()
            try:
                await asyncio.wait_for(self.terminal_event.wait(), remaining)
            except asyncio.TimeoutError:
                return predicate(bytes(self.terminal_output))

    async def hold(self):
        """The project page left open: the answers and the self-evaluations spread over the hold."""
        o = self.opts
        actions = [(PHASE_ANSWERS, i + 1) for i in range(o.answers)] + [(PHASE_EVAL, i + 1) for i in range(o.evals)]
        t0 = time.monotonic()
        for k, (phase, n) in enumerate(actions):
            at = o.hold * (k + 1) / (len(actions) + 1)
            if not await self.sleep(t0 + at - time.monotonic()):
                return
            if phase == PHASE_ANSWERS:
                await self.api('PUT', f"{self.api_base}/answers", PHASE_ANSWERS,
                               json_body={'answers': answers_payload(self.project, self.login, n)}, detail=f"save {n}")
            else:
                await self.evaluate(n)
        await self.sleep(t0 + o.hold - time.monotonic())

    async def evaluate(self, n: int):
        attempt = 0
        while True:
            attempt += 1
            status, body = await self.api('POST', f"{self.api_base}/eval", PHASE_EVAL, detail=f"eval {n}")
            if status == 200 and isinstance(body, dict):
                result = body.get('result') or {}
                graded = bool(body.get('rows')) or isinstance(result.get('grades'), list)
                self.result.checks[CHECK_GRADES] = graded and self.result.checks.get(CHECK_GRADES, True)
                return
            retry_after = body.get('retry_after') if isinstance(body, dict) else None
            delay = retry_delay(PHASE_EVAL, status, retry_after, attempt, self.opts)
            if delay is None:
                self.result.checks[CHECK_GRADES] = False
                return
            if not await self.sleep(delay):
                return

    async def close(self):
        """The page closed: the sockets, then the project stopped (unless --keep)."""
        for task in (self.poll_task, self.touch_task, self.events_task):
            if task:
                task.cancel()
        if self.terminal_task:
            self.terminal_task.cancel()
        if self.terminal:
            await self.terminal.close()
        await self.close_presence()
        if self.events_task:
            try:
                await self.events_task
            except (asyncio.CancelledError, Exception):     # noqa: BLE001
                pass
        if self.result.rln:
            self.result.checks[CHECK_EVENTS] = self.events_closes == 0
            self.result.checks.setdefault(CHECK_REMOVED, True)
            if not self.opts.keep:
                status, body = await self.api('DELETE', self.api_base, PHASE_STOP)
                rows = await self.list_projects(PHASE_PROJECTS)
                gone = rows is not None and not any(r.get('running_lab_name') == self.result.rln for r in rows
                                                    if isinstance(r, dict))
                self.result.checks[CHECK_STOPPED] = status == 200 and gone
                if status != 200:
                    self.result.failure = self.result.failure or f"stop: {status}"


# ---------------------------------------------------------------------------------------------
# side tasks
# ---------------------------------------------------------------------------------------------

async def instructor_task(opts: Options, recorder: Recorder, done: asyncio.Event, info: dict):
    """One instructor on the Watch page (and the Pool page's calls) for the whole run."""
    login = opts.instructor_login
    info.update(role_ok=False, watch_rows_max=0, watch_stress_max=0, errors=0)
    async with make_session(identity_headers(opts, login, fullname='Stress Instructor', instructor=True)) as session:
        async with recorder.timed(login, PHASE_ME) as t:
            async with session.get(opts.portal + '/api/me', timeout=json_timeout(opts)) as resp:
                me = await body_json(resp)
                t.status = str(resp.status)
        identity = (me or {}).get('identity') or {}
        info['role_ok'] = identity.get('role') == ROLE_INSTRUCTOR
        if not info['role_ok']:
            info['errors'] += 1
            recorder.add(login, PHASE_WATCH, STATUS_ERROR, 0.0,
                         f"role {identity.get('role')!r}: the instructor header is not recognised")
            return
        async with recorder.timed(login, PHASE_PAGE) as t:
            async with session.get(opts.portal + '/watch', allow_redirects=False, timeout=json_timeout(opts)) as resp:
                await resp.read()
                t.status, t.detail = str(resp.status), '/watch'
        presence = await session.ws_connect(opts.portal + '/api/presence/ws', params={'page': '/watch'},
                                            heartbeat=WS_HEARTBEAT, timeout=ws_timeout())
        drain = asyncio.create_task(Student.drain(presence))
        try:
            while not done.is_set():
                async with recorder.timed(login, PHASE_WATCH) as t:
                    async with session.get(opts.portal + '/api/watch', timeout=json_timeout(opts)) as resp:
                        rows = await body_json(resp)
                        t.status = str(resp.status)
                        if isinstance(rows, list):
                            ours = sum(1 for r in rows if isinstance(r, dict)
                                       and str(r.get('owner', '')).startswith(opts.login_prefix))
                            info['watch_rows_max'] = max(info['watch_rows_max'], len(rows))
                            info['watch_stress_max'] = max(info['watch_stress_max'], ours)
                            t.detail = f"rows={len(rows)} stress={ours}"
                        else:
                            info['errors'] += 1
                for path in ('/api/pool', '/api/pool/status'):
                    async with recorder.timed(login, PHASE_POOL_PAGE) as t:
                        t.detail = path
                        async with session.get(opts.portal + path, timeout=json_timeout(opts)) as resp:
                            await resp.read()
                            t.status = str(resp.status)
                            if resp.status != 200:
                                info['errors'] += 1
                try:
                    await asyncio.wait_for(done.wait(), opts.watch_interval)
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            pass
        except Exception as e:              # noqa: BLE001
            info['errors'] += 1
            recorder.add(login, PHASE_WATCH, STATUS_ERROR, 0.0, f"{type(e).__name__}: {e}"[:120])
        finally:
            drain.cancel()
            await presence.close()


async def pool_sampler(opts: Options, recorder: Recorder, done: asyncio.Event, samples: list):
    """``GET /api/pool`` with the admin token every 5 s: the state the portal sees of each host."""
    login = 'admin'
    async with make_session({'Authorization': f"Bearer {opts.admin_token}"}) as session:
        while not done.is_set():
            async with recorder.timed(login, PHASE_POOL) as t:
                async with session.get(opts.portal + '/api/pool', timeout=json_timeout(opts)) as resp:
                    rows = await body_json(resp)
                    t.status = str(resp.status)
                    if resp.status == 200 and isinstance(rows, list):
                        kept = [{k: r.get(k) for k in POOL_ROW_KEYS} for r in rows if isinstance(r, dict)]
                        samples.append(PoolSample(round(time.monotonic() - recorder.started, 3), kept))
                        t.detail = ' '.join(f"{r['name']}={'up' if r['reachable'] else 'DOWN'}:{r['projects']}"
                                            for r in kept)[:200]
                    elif resp.status != 200:
                        t.detail = str((rows or {}).get('error', '') if isinstance(rows, dict) else '')[:120]
            try:
                await asyncio.wait_for(done.wait(), POOL_SAMPLE_INTERVAL)
            except asyncio.TimeoutError:
                pass


async def probe_task(opts: Options, recorder: Recorder, done: asyncio.Event):
    """``GET /api/me`` every 2 s: how fast the portal answers a trivial request under load."""
    login = login_of(opts.login_prefix, opts.first)
    async with make_session(identity_headers(opts, login)) as session:
        while not done.is_set():
            async with recorder.timed(login, PHASE_ME) as t:
                async with session.get(opts.portal + '/api/me', timeout=json_timeout(opts)) as resp:
                    await resp.read()
                    t.status = str(resp.status)
            try:
                await asyncio.wait_for(done.wait(), PROBE_INTERVAL)
            except asyncio.TimeoutError:
                pass


async def check_setup(opts: Options):
    """The first login must be recognised, else nothing else can work."""
    login = login_of(opts.login_prefix, opts.first)
    async with make_session(identity_headers(opts, login)) as session:
        try:
            async with session.get(opts.portal + '/api/me', timeout=json_timeout(opts)) as resp:
                me = await body_json(resp)
                status = resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            raise SetupError(f"{opts.portal}: {e}")
        identity = (me or {}).get('identity') if isinstance(me, dict) else None
        if status != 200 or not identity or identity.get('login') != login:
            raise SetupError(f"GET /api/me answered {status} with identity {identity!r}: the portal does not trust "
                             f"this peer (trusted_proxies of web.toml) or is not in proxy mode")


# ---------------------------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------------------------

async def run(opts: Options, *, stop: asyncio.Event | None = None) -> Report:
    if aiohttp is None:
        raise SetupError("aiohttp is not installed")
    stop = stop or asyncio.Event()
    await check_setup(opts)
    recorder = Recorder(opts.events, opts.verbose)
    done = asyncio.Event()
    started_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
    pool_samples: list = []
    instructor_info: dict = {}
    side = []
    if opts.instructor:
        side.append(asyncio.create_task(instructor_task(opts, recorder, done, instructor_info)))
    if opts.admin_token:
        side.append(asyncio.create_task(pool_sampler(opts, recorder, done, pool_samples)))
    if opts.probe:
        side.append(asyncio.create_task(probe_task(opts, recorder, done)))
    students = [Student(i, opts, recorder, stop) for i in range(opts.users)]
    try:
        outcomes = await asyncio.gather(*(s.run() for s in students), return_exceptions=True)
    finally:
        done.set()
        for task in side:
            task.cancel()
        await asyncio.gather(*side, return_exceptions=True)
        recorder.close()
    results = []
    setup_errors = []
    for student, outcome in zip(students, outcomes):
        if isinstance(outcome, SetupError):
            setup_errors.append(str(outcome))
            student.result.failure = f"setup: {outcome}"
            results.append(student.result)
        elif isinstance(outcome, BaseException):
            student.result.failure = f"crash: {type(outcome).__name__}: {outcome}"[:300]
            results.append(student.result)
        else:
            results.append(outcome)
    if setup_errors and len(setup_errors) == len(students):
        raise SetupError(setup_errors[0])
    stats = phase_stats(recorder.samples)
    probe = stats.pop(PHASE_ME, None) if opts.probe else None
    return Report(options=options_dict(opts), started_at=started_at, duration=time.monotonic() - recorder.started,
                  students=results, phases=stats, pool=pool_samples, pool_flips=pool_flips(pool_samples),
                  hosts=host_distribution(results), probe=probe, instructor=instructor_info)


def options_dict(opts: Options) -> dict:
    d = asdict(opts)
    d['commands'] = list(opts.commands)
    return d


async def cleanup(opts: Options) -> int:
    """Stop every project of the synthetic logins (the instructor sees them all on /api/watch)."""
    login = opts.instructor_login
    async with make_session(identity_headers(opts, login, fullname='Stress Instructor', instructor=True)) as session:
        async with session.get(opts.portal + '/api/watch', timeout=json_timeout(opts)) as resp:
            rows = await body_json(resp)
            if resp.status != 200 or not isinstance(rows, list):
                print(f"web-stress: GET /api/watch answered {resp.status}: {rows}", file=sys.stderr)
                return 2
        targets = [r for r in rows if isinstance(r, dict) and str(r.get('owner', '')).startswith(opts.login_prefix)]
        sem = asyncio.Semaphore(CLEANUP_PARALLEL)
        failed = 0

        async def stop_one(row):
            nonlocal failed
            path = f"/api/projects/{quote(str(row.get('host', '')), safe='')}/{quote(row['running_lab_name'], safe='@')}"
            async with sem:
                try:
                    async with session.delete(opts.portal + path, headers={CSRF_HEADER: CSRF_VALUE},
                                              timeout=aiohttp.ClientTimeout(total=900)) as resp:
                        body = await body_json(resp)
                        if resp.status != 200:
                            failed += 1
                            print(f"web-stress: DELETE {path}: {resp.status} {body}", file=sys.stderr)
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    failed += 1
                    print(f"web-stress: DELETE {path}: {e}", file=sys.stderr)
        await asyncio.gather(*(stop_one(r) for r in targets))
        print(f"web-stress: stopped {len(targets) - failed} project(s) of {opts.login_prefix}*"
              + (f", {failed} failed" if failed else ''))
        return 1 if failed else 0


# ---------------------------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------------------------

def parse_args(argv=None) -> Options:
    import os
    p = argparse.ArgumentParser(prog='web-stress', description=__doc__.split('\n\n')[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--portal', default=os.environ.get(ENV_PORTAL, ''),
                   help=f"the portal, e.g. http://127.0.0.1:8450 (default: ${ENV_PORTAL})")
    p.add_argument('--users', type=int, default=10, help="number of simulated students (10)")
    p.add_argument('--login-prefix', default='stress', help="logins are <prefix>001, <prefix>002... (stress)")
    p.add_argument('--first', type=int, default=1, help="index of the first login (1)")
    p.add_argument('--lab', default='sre/dhcp.py', help="the lab every student starts (sre/dhcp.py)")
    p.add_argument('--flavor', default='', help="JSON object sent as the flavor when the lab asks a form")
    p.add_argument('--ramp', type=float, default=0.0, help="seconds over which the students begin (0: all at once)")
    p.add_argument('--hold', type=float, default=600.0, help="seconds the project page stays open (600)")
    p.add_argument('--browse', type=float, default=10.0, help="seconds on the Projects page, then on the Open page (10)")
    p.add_argument('--no-terminal', dest='terminal', action='store_false', help="no terminal")
    p.add_argument('--commands', default=';'.join(DEFAULT_COMMANDS),
                   help="shell commands typed in the terminal, separated by ';' ({login} substituted)")
    p.add_argument('--type-pause', type=float, default=2.0, help="seconds between two commands (2)")
    p.add_argument('--prompt-timeout', type=float, default=20.0, help="seconds to wait for the first output (20)")
    p.add_argument('--answers', type=int, default=2, help="saves of the answers during the hold (2)")
    p.add_argument('--evals', type=int, default=1, help="self-evaluations during the hold (1)")
    p.add_argument('--keep', action='store_true', help="leave the projects running at the end")
    p.add_argument('--cleanup', action='store_true', help="stop every project of the synthetic logins and exit")
    p.add_argument('--instructor', action='store_true', help="one instructor watching the class meanwhile")
    p.add_argument('--admin-token', default=os.environ.get(ENV_ADMIN_TOKEN, ''),
                   help=f"[admin] token of web.toml: sample GET /api/pool every 5 s (default: ${ENV_ADMIN_TOKEN})")
    p.add_argument('--probe', action='store_true', help="GET /api/me every 2 s as a responsiveness probe")
    p.add_argument('--report', default='', help="write the JSON report there")
    p.add_argument('--events', default='', help="write the CSV timeline there")
    p.add_argument('--language', default='en', help="language of the students (en)")
    p.add_argument('--group', default='stress', help="student group sent in the group header ('' = none)")
    p.add_argument('--header-user', default='X-Remote-User')
    p.add_argument('--header-name', default='X-Remote-Name')
    p.add_argument('--header-email', default='X-Remote-Email')
    p.add_argument('--header-group', default='X-Remote-Group')
    p.add_argument('--instructor-header', default='X-Remote-Gid', help="header making the instructor (X-Remote-Gid)")
    p.add_argument('--instructor-value', default='2000', help="its value (2000)")
    p.add_argument('--timeout', type=float, default=60.0, help="seconds per JSON call (60)")
    p.add_argument('--start-interval', type=float, default=30.0,
                   help="[limits] start_interval of the portal: the wait after a refused start (30)")
    p.add_argument('--start-retries', type=int, default=10, help="attempts of a refused start (10)")
    p.add_argument('--verbose', action='store_true', help="one line per request on stderr")
    a = p.parse_args(argv)
    if not a.portal:
        p.error("--portal is required")
    flavor = None
    if a.flavor:
        try:
            flavor = json.loads(a.flavor)
        except ValueError as e:
            p.error(f"--flavor: {e}")
        if not isinstance(flavor, dict):
            p.error("--flavor must be a JSON object")
    headers = HeaderNames(user=a.header_user, name=a.header_name, email=a.header_email, group=a.header_group,
                          instructor=a.instructor_header, instructor_value=a.instructor_value)
    try:
        opts = Options(portal=a.portal, users=a.users, login_prefix=a.login_prefix, first=a.first, lab=a.lab,
                       flavor=flavor, ramp=a.ramp, hold=a.hold, browse=a.browse, terminal=a.terminal,
                       commands=tuple(c.strip() for c in a.commands.split(';') if c.strip()), type_pause=a.type_pause,
                       prompt_timeout=a.prompt_timeout, answers=a.answers, evals=a.evals, keep=a.keep,
                       instructor=a.instructor, admin_token=a.admin_token, probe=a.probe, report=a.report,
                       events=a.events, language=a.language, group=a.group, headers=headers, timeout=a.timeout,
                       start_interval=a.start_interval, start_retries=a.start_retries, verbose=a.verbose)
    except ValueError as e:
        p.error(str(e))
    opts.cleanup = a.cleanup          # not a scenario option: the mode of main()
    return opts


def main(argv=None) -> int:
    opts = parse_args(argv)
    if aiohttp is None:
        print("web-stress: aiohttp is required (pip install aiohttp)", file=sys.stderr)
        return 2
    if getattr(opts, 'cleanup', False):
        try:
            return asyncio.run(cleanup(opts))
        except (aiohttp.ClientError, OSError) as e:
            print(f"web-stress: {e}", file=sys.stderr)
            return 2

    async def go():
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        return await run(opts, stop=stop)

    try:
        report = asyncio.run(go())
    except SetupError as e:
        print(f"web-stress: {e}", file=sys.stderr)
        return 2
    print(report.summary())
    if opts.report:
        with open(opts.report, 'w') as f:
            json.dump(report.to_json(), f, indent=1)
        print(f"report: {opts.report}")
    return report.exit_code


if __name__ == '__main__':
    sys.exit(main())
