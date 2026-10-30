"""The read side of the database of the connection log (``accessdb.py``): the queries of the
History page of the administrators (``GET /api/history``), newest first, with the filters of
the page and a cursor (``before`` = the id of the oldest row shown) for the older pages.  Pure
functions build the SQL; a query runs on a fresh connection in a worker thread (an occasional
request of an administrator: no pool, no state, no stale connection to handle).

The filters: ``login`` and ``addr`` are prefixes (``10.0.1.`` = a subnet; a prefix uses the
``(login, ts)`` / ``(addr, ts)`` indexes), ``event`` a list of names, ``host`` exact, ``rln``
and ``lab`` substrings (``lab`` is only on the ``start`` lines), ``since`` / ``until`` seconds
since the epoch.  No count of the matching rows: ``limit + 1`` rows are asked and ``more`` says
whether older ones exist (a ``COUNT(*)`` would scan the table of a year at every page).

The Sessions view of the page (``GET /api/history/sessions``) is built on the same query: one
row per session from its ``session_close`` line (``session_filters`` keeps the login / address
prefixes, the time window and the cursor, and selects that event), turned into a session by
``session_of_row``; the sessions still open come from the portal's memory (``session_of_visit``,
``visit_matches``)."""
import asyncio
import json
from datetime import datetime

from .accessdb import SELECT, epoch, utc_datetime
from ..config import AccessDatabaseConfig

FILTER_KEYS = ('login', 'addr', 'event', 'host', 'rln', 'lab', 'since', 'until', 'before', 'limit')
TEXT_FILTERS = ('login', 'addr', 'host', 'rln', 'lab')
#: The filters of the Sessions view (``since`` / ``until`` bound the time the session was closed).
SESSION_FILTER_KEYS = ('login', 'addr', 'since', 'until', 'before', 'limit')
SESSION_CLOSE_EVENT = 'session_close'
#: The format of the ``since`` of a ``session_close`` line (``accesslog.iso_time``: the local
#: time of the portal with its UTC offset, ``2026-10-26T09:11:50+0100``).
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
MAX_TEXT = 255
LIKE_ESCAPE = '!'      # the ESCAPE of the LIKE patterns: independent of the backslash handling of sql_mode


class HistoryError(Exception):
    """The database could not answer (the message is the driver's)."""


def escape_like(text: str, esc: str = LIKE_ESCAPE) -> str:
    """*text* as a literal inside a ``LIKE`` pattern (``%``, ``_`` and the escape itself)."""
    return text.replace(esc, esc + esc).replace('%', esc + '%').replace('_', esc + '_')


def _values(query, key: str) -> list:
    getall = getattr(query, 'getall', None)
    if getall is not None:
        return list(getall(key, []))
    value = query.get(key)
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def parse_filters(query) -> dict:
    """The filters of a request from its query string (aiohttp's ``MultiDictProxy``, or a plain
    dict), typed: the text filters stripped (an empty one dropped), ``event`` as a list (the
    parameter repeated or comma-separated), ``since`` / ``until`` as floats, ``before`` as an
    int, ``limit`` 1..``MAX_LIMIT`` (``DEFAULT_LIMIT`` without).  ``ValueError`` names the bad
    parameter (a 400)."""
    filters = {}
    for key in TEXT_FILTERS:
        value = str(query.get(key, '') or '').strip()
        if value:
            filters[key] = value[:MAX_TEXT]
    events = []
    for value in _values(query, 'event'):
        for name in str(value).split(','):
            name = name.strip()
            if name and name not in events:
                events.append(name)
    if events:
        filters['event'] = events
    for key in ('since', 'until'):
        value = str(query.get(key, '') or '').strip()
        if value:
            try:
                filters[key] = float(value)
            except ValueError:
                raise ValueError(f"{key}: seconds since the epoch are expected") from None
    before = str(query.get('before', '') or '').strip()
    if before:
        if not before.isdigit():
            raise ValueError("before: the id of a row is expected")
        filters['before'] = int(before)
    limit = str(query.get('limit', '') or '').strip()
    if limit:
        if not limit.isdigit() or int(limit) < 1:
            raise ValueError("limit: a positive number of rows is expected")
        filters['limit'] = min(int(limit), MAX_LIMIT)
    else:
        filters['limit'] = DEFAULT_LIMIT
    return filters


def build_where(filters: dict) -> tuple:
    """``(fragments, params)`` of the ``WHERE`` clause of *filters* (joined with ``AND``)."""
    parts, params = [], []
    like = f"LIKE %s ESCAPE '{LIKE_ESCAPE}'"
    if filters.get('login'):
        parts.append(f"login {like}")
        params.append(escape_like(filters['login']) + '%')
    if filters.get('addr'):
        parts.append(f"addr {like}")
        params.append(escape_like(filters['addr']) + '%')
    if filters.get('event'):
        events = list(filters['event'])
        parts.append("event IN (" + ', '.join(['%s'] * len(events)) + ")")
        params.extend(events)
    if filters.get('host'):
        parts.append("host = %s")
        params.append(filters['host'])
    for key in ('rln', 'lab'):
        if filters.get(key):
            parts.append(f"{key} {like}")
            params.append('%' + escape_like(filters[key]) + '%')
    if filters.get('since') is not None:
        parts.append("ts >= %s")
        params.append(utc_datetime(float(filters['since'])))
    if filters.get('until') is not None:
        parts.append("ts < %s")
        params.append(utc_datetime(float(filters['until'])))
    if filters.get('before') is not None:
        parts.append("id < %s")
        params.append(int(filters['before']))
    return parts, params


def build_select(table: str, filters: dict) -> tuple:
    """``(sql, params)`` of a page: the rows of *filters*, newest first, ``limit + 1`` of them
    (the extra one tells there are older rows)."""
    parts, params = build_where(filters)
    sql = SELECT.format(table=table)
    if parts:
        sql += " WHERE " + " AND ".join(parts)
    sql += " ORDER BY id DESC LIMIT %s"
    params.append(int(filters.get('limit', DEFAULT_LIMIT)) + 1)
    return sql, params


def session_filters(filters: dict) -> dict:
    """The filters of the Sessions view from a ``parse_filters()`` result: the login / address
    prefixes, the time window (on the time the sessions were closed), the cursor and the limit;
    the rows asked are the ``session_close`` lines.  The event, host, project and lab filters of
    the events view are left out."""
    kept = {key: filters[key] for key in SESSION_FILTER_KEYS if key in filters}
    kept['event'] = [SESSION_CLOSE_EVENT]
    return kept


def parse_time(text) -> float | None:
    """Seconds since the epoch of the ``since`` of a line (``TIME_FORMAT``); ``None`` when
    missing or malformed (the browser's ``Date.parse`` does not take the ``+0100`` offset, so the
    server does it)."""
    if not text:
        return None
    try:
        return datetime.strptime(str(text), TIME_FORMAT).timestamp()
    except ValueError:
        return None


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def session_of_row(row: dict) -> dict:
    """The session of a ``session_close`` row (a ``row_to_dict`` result): ``start`` / ``end`` in
    seconds since the epoch (the start from the ``since`` of the line, else the row's time minus
    the duration; the end is the last request of the session, ``duration`` after the start),
    ``closed`` the time of the line itself (``session_timeout`` after the end for an idle
    session), the request count, the projects (running lab names), ``reason`` (``logout``,
    ``idle``, ``shutdown``), and the name and role of the user (``''`` on the lines written before
    they were logged there)."""
    details = row.get('details') or {}
    duration = row.get('duration')
    duration = float(duration) if duration is not None else 0.0
    ts = row.get('ts')
    start = parse_time(details.get('since'))
    if start is None and ts is not None:
        start = float(ts) - duration
    projects = details.get('projects')
    if isinstance(projects, str):
        projects = [projects] if projects else []
    elif not isinstance(projects, list):
        projects = []
    reason = details.get('reason')
    return {'id': row.get('id'), 'login': row.get('login') or '', 'name': str(details.get('name') or ''),
            'role': str(details.get('role') or ''), 'addr': row.get('addr') or '',
            'start': start, 'end': start + duration if start is not None else None, 'closed': ts,
            'duration': duration, 'requests': _int(details.get('requests')), 'projects': [str(p) for p in projects],
            'reason': str(reason) if reason else None}


def session_of_visit(visit) -> dict:
    """The same keys for a session still open (an ``accesslog.Visit``): no id, no closing time
    nor reason, the end is the last request, plus ``sockets``, the WebSockets open (a project
    page, a terminal, a desktop)."""
    return {'id': None, 'login': visit.login, 'name': visit.name, 'role': visit.role, 'addr': visit.addr,
            'start': visit.first_seen, 'end': visit.last_seen, 'closed': None, 'duration': visit.duration,
            'requests': visit.requests, 'projects': list(visit.projects), 'reason': None, 'sockets': visit.sockets}


def visit_matches(visit, filters: dict) -> bool:
    """Whether an open session passes the login / address prefixes of *filters* and overlaps
    its time window (active after ``since``, started before ``until``)."""
    if filters.get('login') and not visit.login.startswith(filters['login']):
        return False
    if filters.get('addr') and not visit.addr.startswith(filters['addr']):
        return False
    if filters.get('since') is not None and visit.last_seen < float(filters['since']):
        return False
    if filters.get('until') is not None and visit.first_seen >= float(filters['until']):
        return False
    return True


def row_to_dict(names: list, row: tuple) -> dict:
    """A JSON-able row: ``ts`` as seconds since the epoch, ``details`` as a dict (``{}`` when
    unreadable), ``duration`` a float or ``None``."""
    data = dict(zip(names, row))
    ts = data.get('ts')
    if isinstance(ts, datetime):
        data['ts'] = epoch(ts)
    details = data.get('details')
    if isinstance(details, (bytes, bytearray)):
        details = details.decode('utf-8', 'replace')
    try:
        parsed = json.loads(details) if details else {}
    except ValueError:
        parsed = {}
    data['details'] = parsed if isinstance(parsed, dict) else {}
    if data.get('duration') is not None:
        data['duration'] = float(data['duration'])
    return data


class AccessDatabase:
    """The queries of the History page, each on a fresh connection of *connect* (the
    ``connector()`` of ``accessdb.py``, or a fake) in a worker thread."""

    def __init__(self, cfg: AccessDatabaseConfig, *, connect):
        self.cfg = cfg
        self.connect = connect
        self.table = cfg.table

    def query_sync(self, filters: dict) -> dict:
        """``{'rows': [...], 'more': bool}`` of *filters* (``parse_filters``); ``HistoryError``
        when the server cannot be used."""
        sql, params = build_select(self.table, filters)
        limit = int(filters.get('limit', DEFAULT_LIMIT))
        try:
            conn = self.connect()
        except Exception as e:
            raise HistoryError(str(e) or type(e).__name__) from e
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                names = [d[0] for d in cur.description]
                rows = cur.fetchall()
        except Exception as e:
            raise HistoryError(str(e) or type(e).__name__) from e
        finally:
            try:
                conn.close()
            except Exception:
                pass
        rows = [row_to_dict(names, row) for row in rows]
        return {'rows': rows[:limit], 'more': len(rows) > limit}

    async def query(self, filters: dict) -> dict:
        return await asyncio.to_thread(self.query_sync, filters)
