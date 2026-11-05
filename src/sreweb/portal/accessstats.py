"""The Statistics view of the History page (``GET /api/history/statistics``): who connected over
a period and for how long, computed by the portal from the rows of the connection log
(``accessdb.py``, read through ``accesshistory.AccessDatabase``): one row per user (the sum of
their connected time), per student group, per lab, the totals and the distribution of the
students' time.  Pure functions: the route reads the rows and the open sessions, the
aggregation runs in a worker thread.

**What is counted.**  A session (one login from one address, its ``session_close`` row, or a
session still open in the portal's memory) counts when it was active during the period
``[since, until)``; only its part inside the period is counted, and the time of a user is the
union of their clipped sessions (two devices at once are not counted twice).  The role, name
and group of a user are those of their sessions (the last non-empty value); a user whose role
is not ``instructor`` is a student (the rows closed before the role was logged count as
students).  The ``project_close`` rows (the project page of a user, open as long as its events
WebSocket was) give the time spent on a lab, clipped the same way, the union per user and lab;
the spectators of a presentation are left out.  The ``start`` rows with ``result=created``
count the projects started, the ``eval`` rows answered 200 the evaluations asked.  The
requests, projects and evaluations of a counted session are not clipped (the line has no
per-time detail).

**What is read.**  The rows of those four events from ``since`` to ``until + SLACK``: a session
or a page active in the period but closed up to two days after it is still found (the
``(event, ts)`` index serves the range); the newest ``MAX_ROWS`` rows at most, ``truncated``
beyond (the oldest of the period missing: the page says to narrow it)."""
from dataclasses import dataclass, field

from .accesshistory import session_of_row, SESSION_CLOSE_EVENT
from ..agent.runner import RESULT_CREATED
from ..identity import ROLE_INSTRUCTOR, ROLE_STUDENT

PROJECT_CLOSE_EVENT = 'project_close'
START_EVENT = 'start'
EVAL_EVENT = 'eval'
STATISTICS_EVENTS = (SESSION_CLOSE_EVENT, PROJECT_CLOSE_EVENT, START_EVENT, EVAL_EVENT)
#: The period without ``since`` / ``until``: the last 24 hours.
DEFAULT_PERIOD = 86400.0
#: Rows up to two days after the end of the period are read: the closing lines of the sessions
#: and pages active in the period.
SLACK = 2 * 86400.0
#: The newest rows read at most (``truncated`` beyond).
MAX_ROWS = 200000
#: The buckets of the students' connection time, in seconds (``None`` = no upper bound).
BUCKETS = ((0, 900), (900, 1800), (1800, 3600), (3600, 7200), (7200, 14400), (14400, None))
#: The HTTP status of an evaluation that gave grades.
OK_STATUS = '200'


def statistics_window(filters: dict, now: float) -> dict:
    """The window of the statistics from a ``parse_filters()`` result: the login / address
    prefixes, the group and its ``logins`` (the members, when the route resolved them: an empty
    list is kept, nobody matches), ``until`` (``now`` by default) and ``since``
    (``DEFAULT_PERIOD`` before ``until`` by default), as floats; the event, host, project, lab
    and cursor filters of the events view are dropped.  ``ValueError`` when the period is empty
    (a 400)."""
    window = {key: filters[key] for key in ('login', 'addr') if filters.get(key)}
    window.update({key: filters[key] for key in ('group', 'logins') if key in filters})
    until = float(filters['until']) if filters.get('until') is not None else float(now)
    since = float(filters['since']) if filters.get('since') is not None else until - DEFAULT_PERIOD
    if since >= until:
        raise ValueError("since: must be before until")
    window['since'] = since
    window['until'] = until
    return window


def statistics_query(window: dict) -> dict:
    """The filters of ``AccessDatabase.query()`` for *window*: the four events, the rows from
    ``since`` to ``until + SLACK``, ``MAX_ROWS`` of them (``more`` = truncated)."""
    return {**window, 'until': float(window['until']) + SLACK, 'event': list(STATISTICS_EVENTS), 'limit': MAX_ROWS}


def lab_of_rln(rln) -> str:
    """The lab of a running lab name (``<timestamp>@@@<lab>@@@<login>``): the lab as given to
    ``sre start`` (``sre/dhcp.py``: its ``/`` are ``@`` in the name); ``''`` when malformed."""
    parts = str(rln or '').split('@@@')
    if len(parts) != 3 or not all(parts):
        return ''
    return parts[1].replace('@', '/')


def intersects(start, end, since: float, until: float) -> bool:
    """Whether ``[start, end]`` meets the period ``[since, until)``: some of it after ``since``
    and before ``until`` (a zero-length session inside the period counts)."""
    if start is None or end is None or start >= until:
        return False
    return end > since or start >= since


def clip(start: float, end: float, since: float, until: float) -> tuple | None:
    """``(start, end)`` reduced to the period, ``None`` when outside it."""
    lo, hi = max(start, since), min(end, until)
    return (lo, hi) if hi >= lo else None


def merge_intervals(intervals) -> list:
    """The union of ``(start, end)`` pairs: sorted, the overlapping and touching ones merged."""
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def total_of(intervals) -> float:
    return float(sum(end - start for start, end in intervals))


def peak_of(intervals) -> tuple:
    """``(count, at)``: the most intervals open at once and the first time it happened
    (``(0, None)`` without any; the zero-length ones are ignored)."""
    events = []
    for start, end in intervals:
        if end > start:
            events.append((start, 1))
            events.append((end, -1))
    events.sort()                       # at one time, the ends (-1) before the starts (+1)
    best, at, count = 0, None, 0
    for when, delta in events:
        count += delta
        if count > best:
            best, at = count, when
    return best, at


def distribution_of(times) -> list:
    """``[{'min', 'max', 'users'}]``: how many of *times* (seconds) fall in each of ``BUCKETS``."""
    rows = [{'min': lo, 'max': hi, 'users': 0} for lo, hi in BUCKETS]
    for t in times:
        for row in rows:
            if t >= row['min'] and (row['max'] is None or t < row['max']):
                row['users'] += 1
                break
    return rows


def _median(values: list) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    return float(ordered[n // 2]) if n % 2 else (ordered[n // 2 - 1] + ordered[n // 2]) / 2.0


@dataclass
class _User:
    login: str
    name: str = ''
    role: str = ''
    group: str = ''
    sessions: int = 0
    open: int = 0
    requests: int = 0
    evaluations: int = 0
    intervals: list = field(default_factory=list)       # the clipped sessions
    pages: list = field(default_factory=list)           # the clipped project pages
    addresses: set = field(default_factory=set)
    projects: set = field(default_factory=set)

    def seen(self, session: dict):
        """The identity of a session: the last non-empty value wins."""
        for key in ('name', 'role', 'group'):
            value = str(session.get(key) or '')
            if value:
                setattr(self, key, value)

    @property
    def is_student(self) -> bool:
        return self.role != ROLE_INSTRUCTOR


@dataclass
class _Lab:
    lab: str
    starts: int = 0
    evaluations: int = 0
    pages: dict = field(default_factory=dict)           # login -> the clipped project pages
    users: set = field(default_factory=set)
    projects: set = field(default_factory=set)


def _get(table: dict, cls, key: str):
    entry = table.get(key)
    if entry is None:
        entry = table[key] = cls(key)
    return entry


def _in_period(ts, since: float, until: float) -> bool:
    return ts is not None and since <= float(ts) < until


def compute_statistics(rows: list, open_sessions: list, since: float, until: float) -> dict:
    """The statistics of the period ``[since, until)`` from *rows* (``row_to_dict`` results of
    ``STATISTICS_EVENTS``, newest first) and *open_sessions* (``session_of_visit`` results):
    ``{since, until, totals, users, groups, labs, distribution}``, times in seconds, the
    instants in seconds since the epoch."""
    since, until = float(since), float(until)
    users, labs = {}, {}
    projects_used, projects_started = set(), 0
    # the sessions: the closed ones oldest first, then the open ones (the last identity wins)
    sessions = [session_of_row(row) for row in reversed(rows) if row.get('event') == SESSION_CLOSE_EVENT]
    sessions.extend(open_sessions)
    for s in sessions:
        start, end = s.get('start'), s.get('end')
        if start is None or end is None:
            continue
        end = max(float(end), float(start))
        if not intersects(start, end, since, until):
            continue
        user = _get(users, _User, s.get('login') or '')
        user.seen(s)
        user.sessions += 1
        if s.get('closed') is None:
            user.open += 1
        user.intervals.append(clip(float(start), end, since, until))
        user.addresses.add(s.get('addr') or '')
        user.requests += int(s.get('requests') or 0)
        user.projects.update(s.get('projects') or ())
        projects_used.update(s.get('projects') or ())
    # the project pages, the starts and the evaluations
    for row in rows:
        event = row.get('event')
        details = row.get('details') or {}
        login = row.get('login') or ''
        rln = row.get('rln') or ''
        if event == PROJECT_CLOSE_EVENT:
            if details.get('spectator') or row.get('duration') is None or row.get('ts') is None:
                continue
            end = float(row['ts'])
            start = end - max(0.0, float(row['duration']))
            if not intersects(start, end, since, until):
                continue
            interval = clip(start, end, since, until)
            user = _get(users, _User, login)
            user.pages.append(interval)
            if rln:
                user.projects.add(rln)
                projects_used.add(rln)
            lab = lab_of_rln(rln)
            if lab:
                entry = _get(labs, _Lab, lab)
                entry.pages.setdefault(login, []).append(interval)
                entry.users.add(login)
                entry.projects.add(rln)
        elif event == START_EVENT:
            if details.get('result') != RESULT_CREATED or not _in_period(row.get('ts'), since, until):
                continue
            projects_started += 1
            user = _get(users, _User, login)
            if rln:
                user.projects.add(rln)
                projects_used.add(rln)
            lab = lab_of_rln(rln) or str(row.get('lab') or '')
            if lab:
                entry = _get(labs, _Lab, lab)
                entry.starts += 1
                entry.users.add(login)
                if rln:
                    entry.projects.add(rln)
        elif event == EVAL_EVENT:
            if str(row.get('status') or '') != OK_STATUS or not _in_period(row.get('ts'), since, until):
                continue
            user = _get(users, _User, login)
            user.evaluations += 1
            if rln:
                user.projects.add(rln)
                projects_used.add(rln)
            lab = lab_of_rln(rln)
            if lab:
                entry = _get(labs, _Lab, lab)
                entry.evaluations += 1
                entry.users.add(login)
                entry.projects.add(rln)
    # the users
    user_rows, merged_all, groups = [], [], {}
    for user in users.values():
        merged = merge_intervals(user.intervals)
        merged_all.extend(merged)
        connected = total_of(merged)
        row = {'login': user.login, 'name': user.name, 'role': ROLE_INSTRUCTOR if not user.is_student else ROLE_STUDENT,
               'group': user.group, 'sessions': user.sessions, 'open': user.open, 'time': connected,
               'page_time': total_of(merge_intervals(user.pages)),
               'first': merged[0][0] if merged else None, 'last': merged[-1][1] if merged else None,
               'addresses': len(user.addresses), 'projects': len(user.projects), 'evaluations': user.evaluations,
               'requests': user.requests}
        user_rows.append(row)
        if user.is_student:
            group = groups.setdefault(user.group, {'group': user.group, 'students': 0, 'sessions': 0, 'time': 0.0,
                                                   'projects': set(), 'evaluations': 0})
            group['students'] += 1
            group['sessions'] += user.sessions
            group['time'] += connected
            group['projects'].update(user.projects)
            group['evaluations'] += user.evaluations
    user_rows.sort(key=lambda r: (-r['time'], r['login']))
    group_rows = []
    for group in sorted(groups.values(), key=lambda g: g['group']):
        group_rows.append({**group, 'projects': len(group['projects']),
                           'average': group['time'] / group['students'] if group['students'] else 0.0})
    # the labs
    lab_rows = []
    for entry in labs.values():
        times = {login: total_of(merge_intervals(pages)) for login, pages in entry.pages.items()}
        connected = float(sum(times.values()))
        students = sum(1 for login in entry.users if users[login].is_student)
        lab_rows.append({'lab': entry.lab, 'projects': len(entry.projects), 'users': len(entry.users),
                         'students': students, 'time': connected, 'average': connected / len(times) if times else 0.0,
                         'starts': entry.starts, 'evaluations': entry.evaluations})
    lab_rows.sort(key=lambda r: (-r['time'], r['lab']))
    # the totals
    student_times = [r['time'] for r in user_rows if r['role'] == ROLE_STUDENT]
    peak_count, peak_at = peak_of(merged_all)
    totals = {'users': len(user_rows), 'students': len(student_times),
              'instructors': len(user_rows) - len(student_times),
              'groups': sum(1 for g in group_rows if g['group']),
              'sessions': sum(r['sessions'] for r in user_rows), 'open': sum(r['open'] for r in user_rows),
              'addresses': len(set().union(*(u.addresses for u in users.values()))) if users else 0,
              'time': float(sum(r['time'] for r in user_rows)), 'students_time': float(sum(student_times)),
              'average': sum(student_times) / len(student_times) if student_times else 0.0,
              'median': _median(student_times), 'longest': float(max(student_times)) if student_times else 0.0,
              'peak': {'users': peak_count, 'at': peak_at},
              'projects_started': projects_started, 'projects_used': len(projects_used),
              'evaluations': sum(r['evaluations'] for r in user_rows),
              'page_time': float(sum(r['page_time'] for r in user_rows))}
    return {'since': since, 'until': until, 'totals': totals, 'users': user_rows, 'groups': group_rows,
            'labs': lab_rows, 'distribution': distribution_of(student_times)}
