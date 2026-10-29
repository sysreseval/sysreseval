"""The database of the connection log (``[access_log.database]`` of web.toml): the lines of
``accesslog.py`` also go to a MariaDB / MySQL table through PyMySQL, one row per event, the
fields a filter of the History page needs in columns (``ts`` in UTC, millisecond precision) and
the other fields of the line as JSON in ``details``.  The read side is ``accesshistory.py``.

The writer is one daemon thread fed by a bounded queue: ``record()`` never waits for the
server.  The thread connects when the first row comes (a server down at startup never stops
the portal), inserts in batches of one multi-row statement, keeps the rows and retries with a
backoff while the server is unreachable (one warning per distinct error, the oldest rows
dropped beyond ``queue``), writes a batch the server refuses one row at a time (a bad row is
dropped, not the batch), purges the rows older than ``keep`` days once a day, and makes a last
attempt at what is queued when the portal stops (the ``shutdown`` lines of the sessions).

The table is probed with a ``SELECT`` and created only when missing: ``CREATE TABLE IF NOT
EXISTS`` wants the ``CREATE`` privilege even when the table exists, and the account of the
portal needs ``SELECT, INSERT, DELETE`` only once the table is there.  The driver is imported
when a database is configured, never before (``import_pymysql``).
"""
import functools
import json
import logging
import math
import queue
import threading
import time
from datetime import datetime, timezone

from ..config import AccessDatabaseConfig, ConfigError

log = logging.getLogger('sreweb.portal')

#: The columns of a row, in the order of ``row_of()`` and of ``INSERT``.
COLUMNS = ('ts', 'event', 'login', 'addr', 'host', 'rln', 'lab', 'status', 'duration', 'details')
#: The widths of the text columns: a longer value is truncated (a strict ``sql_mode``, the
#: MariaDB default, would refuse the whole batch otherwise).
WIDTHS = {'event': 32, 'login': 64, 'addr': 64, 'host': 64, 'rln': 255, 'lab': 255, 'status': 16}
MAX_DETAILS = 65000            # bytes of JSON (TEXT holds 65535)
BATCH = 500                    # rows per INSERT
PURGE_BATCH = 10000            # rows per DELETE of the purge
PURGE_PERIOD = 86400.0         # seconds between two purges
BACKOFF = (1.0, 2.0, 5.0, 10.0, 30.0, 60.0)   # seconds before the next attempt after a failure, then 60
POLL = 1.0                     # how long the writer waits for a row before looking at the stop flag
NO_SUCH_TABLE = 1146           # ER_NO_SUCH_TABLE: the probe says the table is to be created

DDL = """\
CREATE TABLE IF NOT EXISTS `{table}` (
  id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ts       DATETIME(3)     NOT NULL,
  event    VARCHAR(32)     NOT NULL,
  login    VARCHAR(64)     NOT NULL DEFAULT '',
  addr     VARCHAR(64)     NOT NULL DEFAULT '',
  host     VARCHAR(64)     NOT NULL DEFAULT '',
  rln      VARCHAR(255)    NOT NULL DEFAULT '',
  lab      VARCHAR(255)    NOT NULL DEFAULT '',
  status   VARCHAR(16)     NOT NULL DEFAULT '',
  duration DOUBLE          NULL,
  details  TEXT            NOT NULL,
  PRIMARY KEY (id),
  KEY ts (ts),
  KEY login_ts (login, ts),
  KEY addr_ts (addr, ts),
  KEY event_ts (event, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
PROBE = "SELECT 1 FROM `{table}` LIMIT 0"
#: One ``VALUES (...)`` group of placeholders: PyMySQL's ``executemany`` turns it into one
#: multi-row statement (anything else degrades to one round trip per row).
INSERT = ("INSERT INTO `{table}` (ts, event, login, addr, host, rln, lab, status, duration, details) "
          "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
PURGE = "DELETE FROM `{table}` WHERE ts < %s LIMIT " + str(PURGE_BATCH)
SELECT = "SELECT id, ts, event, login, addr, host, rln, lab, status, duration, details FROM `{table}`"


def import_pymysql():
    """The driver, or ``ConfigError`` naming the package (checked when a database is configured)."""
    try:
        import pymysql
        import pymysql.err  # noqa: F401
    except ImportError:
        raise ConfigError("access_log.database: the PyMySQL library is not installed "
                          "(python3-pymysql, or `pip install pymysql` in the venv)") from None
    return pymysql


def connector(cfg: AccessDatabaseConfig) -> tuple:
    """``(connect, transient)``: a callable opening a connection with the settings of *cfg*, and
    the exception classes meaning "the server is unreachable" (the rows are kept and the
    connection retried: a lost connection, a refused login, a stopped server)."""
    pymysql = import_pymysql()
    timeout = max(1, math.ceil(cfg.connect_timeout))
    connect = functools.partial(pymysql.connect, host=cfg.host or None, port=cfg.port,
                                unix_socket=cfg.unix_socket or None, user=cfg.user, password=cfg.password,
                                database=cfg.name, charset='utf8mb4', autocommit=False, connect_timeout=timeout,
                                read_timeout=max(30, timeout), write_timeout=max(30, timeout))
    return connect, (pymysql.err.OperationalError, pymysql.err.InterfaceError)


def utc_datetime(ts: float) -> datetime:
    """A timestamp as the naive UTC datetime stored in ``ts``, truncated to the millisecond
    (MariaDB truncates the fractional seconds of a ``DATETIME(3)``, MySQL rounds them: truncated
    here, the row reads back the same on both)."""
    dt = datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=dt.microsecond // 1000 * 1000)


def epoch(dt: datetime) -> float:
    """The seconds since the epoch of a naive UTC datetime read back from ``ts``."""
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _json_default(value):
    if isinstance(value, (set, frozenset)):
        return sorted(str(v) for v in value)
    return str(value)


def _column(value, width: int) -> str:
    """A text column: nothing (``None``, ``''`` and the ``-`` of the lines) is ``''``, a bool
    ``1`` / ``0`` like the lines, the rest its text cut at *width*."""
    if value is None or value == '' or value == '-':
        return ''
    if isinstance(value, bool):
        return '1' if value else '0'
    return str(value)[:width]


def row_of(ts: float, event: str, fields: dict) -> tuple:
    """The row of a line, in ``COLUMNS`` order: the fields that have a column, ``duration`` as a
    float or NULL, the other fields as typed JSON (bools, numbers, lists; sets sorted, anything
    else as text); an over-long JSON is replaced by the list of its keys."""
    rest = dict(fields)
    rest.pop('event', None)
    columns = {name: _column(rest.pop(name, None), WIDTHS[name])
               for name in ('login', 'addr', 'host', 'rln', 'lab', 'status')}
    duration = rest.pop('duration', None)
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        duration = None
    else:
        duration = float(duration)
    details = json.dumps(rest, ensure_ascii=False, separators=(',', ':'), default=_json_default)
    if len(details.encode('utf-8')) > MAX_DETAILS:
        details = json.dumps({'truncated': True, 'keys': sorted(rest)})
    return (utc_datetime(ts), str(event)[:WIDTHS['event']], columns['login'], columns['addr'], columns['host'],
            columns['rln'], columns['lab'], columns['status'], duration, details)


def _errno(exc) -> int | None:
    args = getattr(exc, 'args', ())
    return args[0] if args and isinstance(args[0], int) else None


def _close_quietly(conn):
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    return None


def _rollback_quietly(conn):
    try:
        conn.rollback()
    except Exception:
        pass


class DatabaseSink:
    """The writer: a queue and one daemon thread (see the module docstring).  *connect* and
    *transient* come from :func:`connector` (the tests give a fake connection and their own
    exception class); *clock* (``time.time``) dates the purges, *sleep* waits out the backoff."""

    def __init__(self, cfg: AccessDatabaseConfig, *, connect, transient=(), clock=time.time, sleep=time.sleep):
        self.cfg = cfg
        self.connect = connect
        self.transient = tuple(transient)
        self.clock = clock
        self.sleep = sleep
        self.table = cfg.table
        self._insert = INSERT.format(table=self.table)
        self._purge_sql = PURGE.format(table=self.table)
        self._queue = queue.Queue(maxsize=cfg.queue)
        self._lock = threading.Lock()          # the idle flag against the queue
        self._idle = threading.Event()         # set while nothing waits to be written
        self._idle.set()
        self._stop = threading.Event()
        self._thread = None
        self._closed = False
        self.connected = False
        self.last_error = None
        self.dropped = 0                       # rows dropped since the start (queue full)
        self._drop_warned = False
        self._failures = 0                     # consecutive failed attempts
        self._failed_since = None
        self._warned = set()                   # the messages warned about during the current failure
        self._last_purge = None

    # -- the callers' side ----------------------------------------------------------------------

    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name='sreweb-access-db', daemon=True)
            self._thread.start()

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def put(self, ts: float, event: str, fields: dict) -> bool:
        """Queue one line (the row is built here, in the caller's thread).  Never raises: a bad
        value is logged.  ``False`` when a row was lost: the sink is closed, or the queue is full
        and its oldest row went (warned once per episode)."""
        if self._closed:
            return False
        try:
            row = row_of(ts, event, fields)
        except Exception:
            log.exception("access database: cannot build the row of %s", event)
            return False
        lost = False
        with self._lock:
            self._idle.clear()
            try:
                self._queue.put_nowait(row)
            except queue.Full:
                lost = True
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait(row)
                except queue.Full:
                    pass
        if lost:
            self.dropped += 1
            if not self._drop_warned:
                self._drop_warned = True
                log.warning("access database: %d rows wait for the server, the oldest are dropped", self.cfg.queue)
        return not lost

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued row is written (``False`` after *timeout*: the server does not
        answer)."""
        return self._idle.wait(timeout)

    def close(self, timeout: float = 5.0):
        """Stop the writer after one last attempt at the queued rows; the rows still unwritten
        after *timeout* are counted in a warning.  Idempotent; a call from the writer thread
        itself only sets the flag."""
        if self._closed:
            return
        self._closed = True
        thread = self._thread
        if thread is None:
            return
        self._stop.set()
        try:
            self._queue.put_nowait(None)       # wakes the writer up without waiting out POLL
        except queue.Full:
            pass
        if threading.current_thread() is thread:
            return
        thread.join(timeout)
        if thread.is_alive():
            log.warning("access database: the writer did not stop within %.0f s (%d row(s) queued)",
                        timeout, self._queue.qsize())

    def describe(self) -> str:
        where = self.cfg.unix_socket or f"{self.cfg.host}:{self.cfg.port}"
        kept = f"{self.cfg.keep} days kept" if self.cfg.keep else "rows kept forever"
        return f"database {self.cfg.name} on {where} (table {self.table}, {kept})"

    def status(self) -> dict:
        """For the History page: whether the rows reach the server."""
        return {'connected': self.connected, 'last_error': self.last_error, 'queued': self._queue.qsize(),
                'dropped': self.dropped}

    # -- the writer thread ----------------------------------------------------------------------

    def _run(self):
        conn = None
        rows = []
        while True:
            if not rows:
                rows = self._take()
            if not rows:
                if self._stop.is_set():
                    break
                if conn is not None and self._purge_due():
                    conn = self._purge(conn)
                continue
            try:
                if conn is None:
                    conn = self._connect()
                self._write(conn, rows)
            except Exception as e:
                conn = _close_quietly(conn)
                if self._stop.is_set():
                    break                       # one attempt at shutdown
                self._fail(e)
                self.sleep(BACKOFF[min(self._failures, len(BACKOFF)) - 1])
                continue
            rows = []
            self._recovered()
            with self._lock:
                if self._queue.empty():
                    self._idle.set()
            if self._purge_due():
                conn = self._purge(conn)
        _close_quietly(conn)
        self.connected = False
        lost = len(rows)
        while True:                                     # what is still queued (the wake-up markers apart)
            try:
                lost += self._queue.get_nowait() is not None
            except queue.Empty:
                break
        if lost:
            log.warning("access database: %d row(s) not written at shutdown", lost)

    def _take(self) -> list:
        """Up to ``BATCH`` rows, waiting ``POLL`` for the first one; ``[]`` when none came (the
        stop flag is looked at by the caller); the wake-up markers are skipped."""
        try:
            first = self._queue.get(timeout=POLL)
        except queue.Empty:
            return []
        rows = [] if first is None else [first]
        while len(rows) < BATCH:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not None:
                rows.append(item)
        return rows

    def _connect(self):
        """A connection with the table probed, created when it does not exist."""
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                try:
                    cur.execute(PROBE.format(table=self.table))
                    cur.fetchall()
                except Exception as e:
                    if _errno(e) != NO_SUCH_TABLE:
                        raise
                    cur.execute(DDL.format(table=self.table))
                    log.info("access database: table %s created", self.table)
            conn.commit()
        except Exception:
            _close_quietly(conn)
            raise
        return conn

    def _write(self, conn, rows: list):
        """One multi-row INSERT and a commit; a refused batch (not the server gone: a transient
        error propagates with the rows kept) is written row by row."""
        try:
            with conn.cursor() as cur:
                cur.executemany(self._insert, rows)
            conn.commit()
        except self.transient:
            raise
        except Exception as e:
            _rollback_quietly(conn)
            log.warning("access database: a batch of %d row(s) was refused (%s): written one by one", len(rows), e)
            self._write_each(conn, rows)

    def _write_each(self, conn, rows: list):
        """*rows* one by one, the written ones removed from the list (a transient error leaves the
        rest for the retry), a refused row dropped with a warning."""
        while rows:
            row = rows[0]
            try:
                with conn.cursor() as cur:
                    cur.execute(self._insert, row)
                conn.commit()
            except self.transient:
                raise
            except Exception as e:
                _rollback_quietly(conn)
                log.warning("access database: row dropped (%s): event=%s login=%s", e, row[1], row[2])
            rows.pop(0)

    def _fail(self, exc):
        self._failures += 1
        self.connected = False
        if self._failed_since is None:
            self._failed_since = self.clock()
        message = str(exc) or type(exc).__name__
        self.last_error = message
        if message not in self._warned:
            self._warned.add(message)
            log.warning("access database: %s (the rows wait in memory: %d queued)", message, self._queue.qsize())

    def _recovered(self):
        if self._failures:
            waited = self.clock() - (self._failed_since if self._failed_since is not None else self.clock())
            log.info("access database: writing again after %d attempt(s) and %.0f s%s", self._failures, waited,
                     f", {self.dropped} row(s) dropped" if self.dropped else "")
        self._failures = 0
        self._failed_since = None
        self._warned.clear()
        self._drop_warned = False
        self.last_error = None
        self.connected = True

    def _purge_due(self) -> bool:
        return bool(self.cfg.keep) and (self._last_purge is None or self.clock() - self._last_purge >= PURGE_PERIOD)

    def _purge(self, conn):
        """Delete the rows older than ``keep`` days, ``PURGE_BATCH`` at a time; the connection
        back (``None`` when the server went: the next batch reconnects)."""
        cutoff = utc_datetime(self.clock() - self.cfg.keep * 86400)
        try:
            while True:
                with conn.cursor() as cur:
                    cur.execute(self._purge_sql, (cutoff,))
                    count = cur.rowcount
                conn.commit()
                if count is None or count < PURGE_BATCH:
                    break
            self._last_purge = self.clock()
            return conn
        except self.transient as e:
            self._fail(e)
            return _close_quietly(conn)
        except Exception as e:
            _rollback_quietly(conn)
            self._last_purge = self.clock()                 # again tomorrow
            message = f"purge: {e}"
            if message not in self._warned:
                self._warned.add(message)
                log.warning("access database: %s (the rows older than %d days stay until tomorrow)", message,
                            self.cfg.keep)
            return conn
