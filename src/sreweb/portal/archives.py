"""The archives of the evaluations in the database of the connection log (``[archives]`` of
web.toml, the connection of ``[access_log.database]``): every archive ``sre eval`` writes on a
pool host (``params.archive_dirs``: the students' self-evaluations, the periodic ones of the
agent, an instructor's, the final one of a closing project, those of the Qt GUI) becomes one
row of the ``archives`` table, the results without the answers; the Archives page of the
instructors reads it (``routes.py``: ``/api/archives...``).

**Collection.** The portal pulls: every ``poll_interval`` seconds the collector asks each
reachable host ``GET /v1/archives?after=<name>&limit=<page>`` (``sreweb.agent``: the archives
whose file name is greater than *after*, in the order of the names, as the records of
``SRE.archive_summary.archive_record``), repeated while the agent says ``more`` up to
``CALLS_PER_TICK`` times per host and tick.  One cursor per host is kept in memory: the greatest
name taken from that host, initialised from the table itself (``SELECT host, MAX(archive) ...
GROUP BY host``) at the first tick after a start — nothing is collected while the database does
not answer, so a restart never re-imports a host — and advanced to the last name the agent
listed whatever the insert outcome: the name of an archive is unique in the table (``UNIQUE
(archive)``, ``INSERT IGNORE``), so two hosts sharing an archive directory, or a restart with
rows still queued, only cost a harmless re-insert.  An archive
rewritten in place (``sre re-eval -p ''``) or named below the cursor (a host clock set back) is
not taken again, as ``sre watch`` would not see it either.  The ``group`` and ``fullname`` an
archive lacks (the projects of the Qt GUI) are completed from the directory when the portal
has one (``roles.complete_owners``, as on the Watch page).

**Storage.** The writer is a second ``accessdb.DatabaseSink`` (a queue, one thread, batches,
backoff, the daily purge of ``keep`` days when set) with the ``TableSpec`` of the table: the
filters of the page in columns (``ts`` = the evaluation time in UTC, ``host`` = the pool host,
``archive``, ``rln``, ``lab`` in the form of the lab list, ``login``, ``fullname``, ``grp`` (the
student group: ``group`` is a reserved word), ``hostname`` (the one the archive names), the
exo-eval ``grade`` / ``max_grade`` / ``mark`` / ``maximum_mark``, the ``errors`` / ``warnings``
counts, ``exam``, ``auto_eval_count``) and the rest as JSON in ``details`` (the elements with
their raw titles, the parts, the error list, the self-eval totals, the metadata).  The reader
runs each query on a fresh connection in a thread like ``accesshistory.AccessDatabase``; the
"show" filter picks every row, the newest of each project or the newest of each student and
lab among the rows matching the other filters (a ``NOT EXISTS`` on the same table).
"""
import asyncio
import json
import logging
import time
from datetime import datetime

import aiohttp

from .accessdb import DatabaseSink, TableSpec, utc_datetime, epoch, clean_text
from .accesshistory import (HistoryError, escape_like, fetch, parse_epoch, DEFAULT_LIMIT, MAX_LIMIT, MAX_TEXT,
                            LIKE_ESCAPE)
from .roles import complete_owners
from ..config import AccessDatabaseConfig, ArchivesConfig

log = logging.getLogger('sreweb.portal')

#: The columns of a row, in the order of ``row_of_record()`` and of ``INSERT``.
COLUMNS = ('ts', 'host', 'archive', 'rln', 'lab', 'login', 'fullname', 'grp', 'hostname', 'grade', 'max_grade',
           'mark', 'maximum_mark', 'errors', 'warnings', 'exam', 'auto_eval_count', 'details')
#: The widths of the text columns: a longer value is truncated (a strict ``sql_mode`` would
#: refuse the row).  An archive name is 19 characters plus the running lab name.
WIDTHS = {'host': 64, 'archive': 300, 'rln': 255, 'lab': 255, 'login': 64, 'fullname': 255, 'grp': 64,
          'hostname': 64}
MAX_DETAILS = 1 << 20          # bytes of JSON (MEDIUMTEXT holds 16 MB; a lab has tens of elements)
#: The keys of a record kept in ``details`` (the others have a column).
DETAIL_KEYS = ('elements', 'parts', 'errors', 'self_grade', 'self_max_grade', 'self_mark', 'email', 'language',
               'answers_updated_at', 're_eval_date', 'exam_started_at', 'exam_duration', 'exam_time_remaining',
               'managed')
#: The lab summary (the matrix of the students): the rows with their details, at most.
MAX_SUMMARY_ROWS = 500
#: ``GET /v1/archives``: archives asked per call, and calls per host and tick.
PAGE = 50
CALLS_PER_TICK = 10
AGENT_TIMEOUT = 30.0           # seconds: the agent reads the archives of a page in a thread
#: The ``show`` filter: every row, the newest of each project, the newest of each student and lab.
SHOW_ALL, SHOW_PROJECT, SHOW_STUDENT = 'all', 'project', 'student'
SHOW_MODES = (SHOW_PROJECT, SHOW_STUDENT, SHOW_ALL)
FILTER_KEYS = ('student', 'group', 'lab', 'host', 'since', 'until', 'exam', 'show', 'before', 'limit')

DDL = """\
CREATE TABLE IF NOT EXISTS `{table}` (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ts              DATETIME(3)     NOT NULL,
  host            VARCHAR(64)     NOT NULL DEFAULT '',
  archive         VARCHAR(300)    NOT NULL,
  rln             VARCHAR(255)    NOT NULL DEFAULT '',
  lab             VARCHAR(255)    NOT NULL DEFAULT '',
  login           VARCHAR(64)     NOT NULL DEFAULT '',
  fullname        VARCHAR(255)    NOT NULL DEFAULT '',
  grp             VARCHAR(64)     NOT NULL DEFAULT '',
  hostname        VARCHAR(64)     NOT NULL DEFAULT '',
  grade           DOUBLE          NOT NULL DEFAULT 0,
  max_grade       DOUBLE          NOT NULL DEFAULT 0,
  mark            DOUBLE          NULL,
  maximum_mark    DOUBLE          NULL,
  errors          INT             NOT NULL DEFAULT 0,
  warnings        INT             NOT NULL DEFAULT 0,
  exam            TINYINT         NOT NULL DEFAULT 0,
  auto_eval_count INT             NULL,
  details         MEDIUMTEXT      NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY archive (archive),
  KEY ts (ts),
  KEY login_lab_id (login, lab, id),
  KEY rln_id (rln, id),
  KEY lab_ts (lab, ts),
  KEY grp_ts (grp, ts),
  KEY host_archive (host, archive)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
#: One ``VALUES (...)`` group (PyMySQL's ``executemany`` makes one multi-row statement of it);
#: an archive already there (the unique name) is skipped by ``IGNORE``: an ``ON DUPLICATE KEY
#: UPDATE`` no-op would need the UPDATE privilege the account of the portal does not have.  The
#: rows are typed and cut to the columns here, so the data errors ``IGNORE`` would also demote to
#: warnings (a NULL in a NOT NULL column, a value too long) cannot come from them.
INSERT = ("INSERT IGNORE INTO `{table}` (" + ', '.join(COLUMNS) + ") VALUES (" + ', '.join(['%s'] * len(COLUMNS))
          + ")")
_SUMMARY_COLUMNS = ('id',) + COLUMNS[:-1]
SELECT_ROWS = "SELECT " + ', '.join(f"t.{c}" for c in _SUMMARY_COLUMNS) + " FROM `{table}` t"
SELECT_FULL = "SELECT " + ', '.join(f"t.{c}" for c in _SUMMARY_COLUMNS + ('details',)) + " FROM `{table}` t"
CURSORS = "SELECT host, MAX(archive) AS archive FROM `{table}` GROUP BY host"
LABS = "SELECT DISTINCT lab FROM `{table}` ORDER BY lab"
GROUPS = "SELECT DISTINCT grp FROM `{table}` WHERE grp <> '' ORDER BY grp"


def _describe_row(row: tuple) -> str:
    return f"archive={row[2]} login={row[5]}"


def table_spec(cfg: ArchivesConfig) -> TableSpec:
    return TableSpec(name=cfg.table, ddl=DDL, insert=INSERT, keep=cfg.keep, label='archives database',
                     thread_name='sreweb-archives-db', describe_row=_describe_row)


# -- the rows ---------------------------------------------------------------------------------

def record_time(record: dict) -> float:
    """The evaluation time of a record as seconds since the epoch: its ISO ``eval_date`` (aware
    as the agent sends it; a naive one is read as the portal's local time), else the 14-digit
    prefix of the archive name (the clock of the host, read as local time), else now."""
    value = record.get('eval_date')
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            pass
    name = str(record.get('archive') or '')
    try:
        return datetime.strptime(name[:14], '%Y%m%d%H%M%S').timestamp()
    except ValueError:
        return time.time()


def _text(value, width: int) -> str:
    return '' if value is None else clean_text(str(value)[:width])


def _float(value, default=None):
    """A number of a record, *default* for ``None``, a non-number, ``NaN`` or an infinity (an
    agent may send them as JSON: MySQL refuses the row)."""
    try:
        number = default if value is None else float(value)
    except (TypeError, ValueError):
        return default
    if number is not None and (number != number or number in (float('inf'), float('-inf'))):
        return default
    return number


def _int(value, default=None):
    if isinstance(value, bool):
        return default
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError):
        return default


def row_of_record(host: str, record: dict) -> tuple:
    """The row of an archive record of the agent (``archive_record`` + ``managed``) reported by
    the pool host *host*, in ``COLUMNS`` order; the keys of ``DETAIL_KEYS`` as JSON in
    ``details`` (the elements, parts and errors dropped with ``truncated`` when it exceeds
    ``MAX_DETAILS``)."""
    details = {key: record.get(key) for key in DETAIL_KEYS if key in record}
    text = clean_text(json.dumps(details, ensure_ascii=False, separators=(',', ':'), default=str))
    if len(text.encode('utf-8')) > MAX_DETAILS:
        for key in ('elements', 'parts', 'errors'):
            details.pop(key, None)
        details['truncated'] = True
        text = clean_text(json.dumps(details, ensure_ascii=False, separators=(',', ':'), default=str))
    return (utc_datetime(record_time(record)), _text(host, WIDTHS['host']), _text(record.get('archive'), WIDTHS['archive']),
            _text(record.get('running_lab_name'), WIDTHS['rln']), _text(record.get('lab'), WIDTHS['lab']),
            _text(record.get('login'), WIDTHS['login']), _text(record.get('fullname'), WIDTHS['fullname']),
            _text(record.get('group'), WIDTHS['grp']), _text(record.get('hostname'), WIDTHS['hostname']),
            _float(record.get('grade'), 0.0), _float(record.get('max_grade'), 0.0),
            _float(record.get('mark')), _float(record.get('maximum_mark')),
            _int(record.get('error_count'), 0), _int(record.get('warning_count'), 0),
            1 if record.get('exam') else 0, _int(record.get('auto_eval_count')), text)


def row_to_dict(names: list, row: tuple) -> dict:
    """A JSON-able row: ``ts`` as seconds since the epoch, ``group`` for the ``grp`` column,
    ``exam`` a bool, ``details`` a dict when selected (``{}`` when unreadable)."""
    data = dict(zip(names, row))
    ts = data.get('ts')
    if isinstance(ts, datetime):
        data['ts'] = epoch(ts)
    if 'grp' in data:
        data['group'] = data.pop('grp')
    data['exam'] = bool(data.get('exam'))
    for key in ('grade', 'max_grade', 'mark', 'maximum_mark'):
        if data.get(key) is not None:
            data[key] = float(data[key])
    if 'details' in data:
        details = data['details']
        if isinstance(details, (bytes, bytearray)):
            details = details.decode('utf-8', 'replace')
        try:
            parsed = json.loads(details) if details else {}
        except ValueError:
            parsed = {}
        data['details'] = parsed if isinstance(parsed, dict) else {}
    return data


# -- the queries ------------------------------------------------------------------------------

def parse_archive_filters(query, *, default_show: str = SHOW_PROJECT) -> dict:
    """The filters of the Archives page from the query parameters (an aiohttp MultiDict or a
    dict): ``student`` (a login prefix or a part of a name), ``group`` (exact), ``lab`` (a part
    of the name), ``host`` (exact), ``since`` / ``until`` (seconds since the epoch, on the
    evaluation time), ``exam`` (``1`` / ``0``), ``show`` (``SHOW_MODES``), ``before`` (the id
    cursor) and ``limit``; ``ValueError`` on a bad value."""
    filters: dict = {}
    for key in ('student', 'group', 'lab', 'host'):
        value = str(query.get(key, '') or '').strip()
        if value:
            filters[key] = value[:MAX_TEXT]
    for key in ('since', 'until'):
        value = str(query.get(key, '') or '').strip()
        if value:
            filters[key] = parse_epoch(key, value)
    exam = str(query.get('exam', '') or '').strip().lower()
    if exam:
        if exam not in ('1', '0', 'true', 'false'):
            raise ValueError("exam: 1 or 0 is expected")
        filters['exam'] = exam in ('1', 'true')
    show = str(query.get('show', '') or '').strip() or default_show
    if show not in SHOW_MODES:
        raise ValueError("show: " + ', '.join(SHOW_MODES[:-1]) + f" or {SHOW_MODES[-1]} is expected")
    filters['show'] = show
    before = str(query.get('before', '') or '').strip()
    if before:
        if not before.isdigit():
            raise ValueError("before: the id of a row is expected")
        filters['before'] = int(before)
    limit = str(query.get('limit', '') or '').strip()
    if limit:
        if not limit.isdigit() or not 1 <= int(limit) <= MAX_LIMIT:
            raise ValueError(f"limit: a number from 1 to {MAX_LIMIT} is expected")
        filters['limit'] = int(limit)
    else:
        filters['limit'] = DEFAULT_LIMIT
    return filters


def _scope_predicates(filters: dict, prefix: str) -> tuple:
    """The predicates every row and its challengers share (the time window, the host, the exam
    flag), on the table aliased *prefix* (``t.`` or ``t2.``)."""
    parts, params = [], []
    if filters.get('since') is not None:
        parts.append(f"{prefix}ts >= %s")
        params.append(utc_datetime(float(filters['since'])))
    if filters.get('until') is not None:
        parts.append(f"{prefix}ts < %s")
        params.append(utc_datetime(float(filters['until'])))
    if filters.get('host'):
        parts.append(f"{prefix}host = %s")
        params.append(filters['host'])
    if filters.get('exam') is not None:
        parts.append(f"{prefix}exam = %s")
        params.append(1 if filters['exam'] else 0)
    return parts, params


def build_archives_where(table: str, filters: dict) -> tuple:
    """``(fragments, params)`` of the ``WHERE`` clause of *filters* on the table aliased ``t``
    (joined with ``AND``).  ``show`` = ``project`` keeps the newest row of each project among
    those matching the time window, host and exam filters, ``student`` the newest of each login
    and lab (a ``NOT EXISTS`` of a newer row with the same filters), ``all`` every row."""
    like = f"LIKE %s ESCAPE '{LIKE_ESCAPE}'"
    parts, params = [], []
    if filters.get('student'):
        parts.append(f"(t.login {like} OR t.fullname {like})")
        params.extend([escape_like(filters['student']) + '%', '%' + escape_like(filters['student']) + '%'])
    if filters.get('group'):
        parts.append("t.grp = %s")
        params.append(filters['group'])
    if filters.get('lab'):
        parts.append(f"t.lab {like}")
        params.append('%' + escape_like(filters['lab']) + '%')
    scope, scope_params = _scope_predicates(filters, 't.')
    parts.extend(scope)
    params.extend(scope_params)
    show = filters.get('show', SHOW_PROJECT)
    if show != SHOW_ALL:
        same = ["t2.rln = t.rln"] if show == SHOW_PROJECT else ["t2.login = t.login", "t2.lab = t.lab"]
        inner, inner_params = _scope_predicates(filters, 't2.')
        parts.append(f"NOT EXISTS (SELECT 1 FROM `{table}` t2 WHERE " + " AND ".join([*same, "t2.id > t.id", *inner])
                     + ")")
        params.extend(inner_params)
    if filters.get('before') is not None:
        parts.append("t.id < %s")
        params.append(int(filters['before']))
    return parts, params


def build_archives_select(table: str, filters: dict) -> tuple:
    """``(sql, params)`` of a page of the table: the rows of *filters* without their details,
    newest first, ``limit + 1`` of them (the extra one tells there are older rows)."""
    parts, params = build_archives_where(table, filters)
    sql = SELECT_ROWS.format(table=table)
    if parts:
        sql += " WHERE " + " AND ".join(parts)
    sql += " ORDER BY t.id DESC LIMIT %s"
    params.append(int(filters.get('limit', DEFAULT_LIMIT)) + 1)
    return sql, params


def build_summary_select(table: str, filters: dict, limit: int = MAX_SUMMARY_ROWS) -> tuple:
    """``(sql, params)`` of the lab summary: the rows of *filters* with their details, by
    student then newest first, ``limit + 1`` of them."""
    parts, params = build_archives_where(table, filters)
    sql = SELECT_FULL.format(table=table)
    if parts:
        sql += " WHERE " + " AND ".join(parts)
    sql += " ORDER BY t.login, t.lab, t.id DESC LIMIT %s"
    params.append(int(limit) + 1)
    return sql, params


class ArchiveDatabase:
    """The queries of the Archives page, each on a fresh connection of *connect* in a worker
    thread (``HistoryError`` when the server cannot be used)."""

    def __init__(self, table: str, *, connect):
        self.table = table
        self.connect = connect

    def query_sync(self, filters: dict) -> dict:
        """``{'rows': [...], 'more': bool}`` of *filters* (``parse_archive_filters``)."""
        sql, params = build_archives_select(self.table, filters)
        limit = int(filters.get('limit', DEFAULT_LIMIT))
        names, rows = fetch(self.connect, sql, params)
        rows = [row_to_dict(names, row) for row in rows]
        return {'rows': rows[:limit], 'more': len(rows) > limit}

    def summary_sync(self, filters: dict, limit: int = MAX_SUMMARY_ROWS) -> dict:
        """``{'rows': [...with details], 'truncated': bool}`` of *filters* for the lab summary."""
        sql, params = build_summary_select(self.table, filters, limit)
        names, rows = fetch(self.connect, sql, params)
        rows = [row_to_dict(names, row) for row in rows]
        return {'rows': rows[:limit], 'truncated': len(rows) > limit}

    def get_sync(self, row_id: int) -> dict | None:
        """One row with its details, or ``None``."""
        names, rows = fetch(self.connect, SELECT_FULL.format(table=self.table) + " WHERE t.id = %s", [int(row_id)])
        return row_to_dict(names, rows[0]) if rows else None

    def options_sync(self) -> dict:
        """``{'labs': [...], 'groups': [...]}``: the distinct labs and student groups of the table."""
        _, labs = fetch(self.connect, LABS.format(table=self.table))
        _, groups = fetch(self.connect, GROUPS.format(table=self.table))
        return {'labs': [str(r[0]) for r in labs if r and r[0]], 'groups': [str(r[0]) for r in groups if r and r[0]]}

    def cursors_sync(self) -> dict:
        """``{host: greatest archive name}`` of the rows of the table (the cursors of the
        collector after a start); rows without the two values are skipped."""
        _, rows = fetch(self.connect, CURSORS.format(table=self.table))
        cursors = {}
        for row in rows:
            if row and len(row) >= 2 and row[0] and row[1]:
                cursors[str(row[0])] = str(row[1])
        return cursors

    async def query(self, filters: dict) -> dict:
        return await asyncio.to_thread(self.query_sync, filters)

    async def summary(self, filters: dict, limit: int = MAX_SUMMARY_ROWS) -> dict:
        return await asyncio.to_thread(self.summary_sync, filters, limit)

    async def get(self, row_id: int) -> dict | None:
        return await asyncio.to_thread(self.get_sync, row_id)

    async def options(self) -> dict:
        return await asyncio.to_thread(self.options_sync)

    async def cursors(self) -> dict:
        return await asyncio.to_thread(self.cursors_sync)


# -- the collector ----------------------------------------------------------------------------

class ArchiveCollector:
    """The task pulling the archives of the pool hosts into the sink (see the module
    docstring).  *pool* gives the hosts, their reachability, the headers and the client
    session; *roles* (``roles.RoleCache`` or ``None``) completes the student groups and names."""

    def __init__(self, pool, sink: DatabaseSink, reader: ArchiveDatabase, *, interval: float = 30.0, roles=None,
                 page: int = PAGE, calls_per_tick: int = CALLS_PER_TICK, timeout: float = AGENT_TIMEOUT):
        self.pool = pool
        self.sink = sink
        self.reader = reader
        self.interval = interval
        self.roles = roles
        self.page = page
        self.calls_per_tick = calls_per_tick
        self.timeout = timeout
        self.cursors: dict | None = None       # host -> the greatest archive name taken; None until read
        self.collected = 0                     # records queued since the start
        self.ticks = 0
        self._task: asyncio.Task | None = None
        self._warned: dict = {}                # host (or 'database') -> the message warned about

    def start(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self):
        while True:
            await asyncio.sleep(self.interval)
            try:
                await self.tick()
            except Exception:
                log.exception("archives: collection failed")

    async def tick(self):
        """One collection: the cursors read first when unknown (nothing collected until the
        database answers), then every reachable host, concurrently."""
        if self.cursors is None:
            try:
                self.cursors = await self.reader.cursors()
            except HistoryError as e:
                self._warn('database', f"cannot read the cursors of the hosts: {e}")
                return
            self._warned.pop('database', None)
            log.info("archives: collecting from the pool (%d host(s) already in the table)", len(self.cursors))
        hosts = [h for h in list(self.pool.hosts.values())
                 if h.name in self.pool.status and self.pool.status[h.name].reachable]
        await asyncio.gather(*(self._collect(h) for h in hosts))
        self.ticks += 1

    async def _collect(self, host):
        after = self.cursors.get(host.name, '')
        for _ in range(self.calls_per_tick):
            data = await self._fetch(host, after)
            if data is None:
                return
            records = [r for r in (data.get('archives') or []) if isinstance(r, dict)
                       and r.get('archive') and r.get('running_lab_name')]
            if records and self.roles is not None:
                await complete_owners(records, self.roles, login_key='login')
            for record in records:
                self.sink.put_row(row_of_record(host.name, record))
            self.collected += len(records)
            last = data.get('last') if isinstance(data.get('last'), str) else ''
            after = max([after, last, *(str(r['archive']) for r in records)])
            self.cursors[host.name] = after
            if not data.get('more'):
                return

    async def _fetch(self, host, after: str) -> dict | None:
        try:
            async with self.pool.session.get(f"{host.url}/v1/archives", headers=self.pool.headers(host),
                                             params={'after': after, 'limit': str(self.page)},
                                             timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                if resp.status == 404:
                    self._warn(host.name, "no /v1/archives: the agent is to be updated")
                    return None
                if resp.status != 200:
                    self._warn(host.name, f"GET /v1/archives answered {resp.status}: {(await resp.text())[:200]}")
                    return None
                data = await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            self._warn(host.name, f"GET /v1/archives failed: {e or type(e).__name__}")
            return None
        if not isinstance(data, dict):
            self._warn(host.name, "GET /v1/archives: not a JSON object")
            return None
        self._warned.pop(host.name, None)
        return data

    def _warn(self, key: str, message: str):
        """Once per distinct message of a host (or of the database) until it recovers."""
        if self._warned.get(key) != message:
            self._warned[key] = message
            log.warning("archives: %s: %s", key, message)

    def status(self) -> dict:
        return {'hosts': len(self.cursors or {}), 'collected': self.collected, 'ticks': self.ticks,
                'cursors_known': self.cursors is not None}


class ArchiveStore:
    """The sink, the reader and the collector of the archives table, owned by the portal
    (``Portal.archives``, ``None`` without a database)."""

    def __init__(self, db: AccessDatabaseConfig, cfg: ArchivesConfig, *, connect, transient=(), clock=time.time):
        self.db = db
        self.cfg = cfg
        self.sink = DatabaseSink(db, connect=connect, transient=transient, clock=clock, spec=table_spec(cfg))
        self.reader = ArchiveDatabase(cfg.table, connect=connect)
        self.collector: ArchiveCollector | None = None

    def open(self):
        self.sink.start()

    def start(self, pool, roles=None):
        """Start the collector on *pool* (after its first refresh: its client session exists)."""
        self.collector = ArchiveCollector(pool, self.sink, self.reader, interval=self.cfg.poll_interval, roles=roles)
        self.collector.start()

    async def tick(self):
        """One collection now (the tests)."""
        if self.collector is not None:
            await self.collector.tick()

    async def stop(self):
        if self.collector is not None:
            await self.collector.stop()

    def close(self):
        self.sink.close()

    def describe(self) -> str:
        return f"{self.sink.describe()}, collected from the agents every {self.cfg.poll_interval:g} s"

    def status(self) -> dict:
        """For the Archives page: the writer's state and the collector's."""
        status = self.sink.status()
        if self.collector is not None:
            status['collector'] = self.collector.status()
        return status
