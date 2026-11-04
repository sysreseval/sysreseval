"""The exams in the database of the connection log (``[exams] table`` and its ``_members``
table): the store behind ``exams.Exams``, which keeps every exam in memory and writes through
here.  Every operation is one transaction on a fresh connection of *connect*
(``accessdb.connector``, or a fake), run in a thread by the registry; the two tables are
created at the first operation when they are missing (the account needs CREATE then; the
documentation gives the DDL to run by hand).  Like ``groups.GroupStore``."""
import json
import logging
import time
from datetime import datetime
from typing import Callable

from .accessdb import HistoryError, ensure_table, transaction, utc_datetime, epoch
from .exams import Exam, ExamLab, Member
from ..config import AccessDatabaseConfig, ExamsConfig, parse_networks, ConfigError

log = logging.getLogger('sreweb.portal')

# The definition columns the listing needs are typed; the rest (the audience, the labs, the
# delays, the networks, the interval) is one JSON document.  No FOREIGN KEY (the REFERENCES
# privilege): the members of an exam are deleted with it in one transaction.
DDL_EXAMS = """\
CREATE TABLE IF NOT EXISTS `{table}` (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  title       VARCHAR(200)    NOT NULL,
  created_by  VARCHAR(64)     NOT NULL DEFAULT '',
  created_at  DATETIME(3)     NOT NULL,
  updated_at  DATETIME(3)     NOT NULL,
  start_after DATETIME(3)     NULL,
  end_before  DATETIME(3)     NULL,
  duration    INT             NULL,
  ended_at    DATETIME(3)     NULL,
  details     MEDIUMTEXT      NOT NULL,
  PRIMARY KEY (id),
  KEY start_after (start_after),
  KEY created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
DDL_MEMBERS = """\
CREATE TABLE IF NOT EXISTS `{table}` (
  exam_id       BIGINT UNSIGNED NOT NULL,
  login         VARCHAR(64)     CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  first_seen    DATETIME(3)     NULL,
  started_at    DATETIME(3)     NULL,
  ended_at      DATETIME(3)     NULL,
  dismissed_at  DATETIME(3)     NULL,
  extra_minutes INT             NOT NULL DEFAULT 0,
  address       VARCHAR(64)     NOT NULL DEFAULT '',
  details       TEXT            NOT NULL,
  updated_at    DATETIME(3)     NOT NULL,
  PRIMARY KEY (exam_id, login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
EXAM_COLUMNS = "id, title, created_by, created_at, updated_at, start_after, end_before, duration, ended_at, details"
SELECT_EXAMS = f"SELECT {EXAM_COLUMNS} FROM `{{table}}` ORDER BY id"
INSERT_EXAM = ("INSERT INTO `{table}` (title, created_by, created_at, updated_at, start_after, end_before, duration, "
               "ended_at, details) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)")
UPDATE_EXAM = ("UPDATE `{table}` SET title = %s, updated_at = %s, start_after = %s, end_before = %s, duration = %s, "
               "ended_at = %s, details = %s WHERE id = %s")
DELETE_EXAM = "DELETE FROM `{table}` WHERE id = %s"
MEMBER_COLUMNS = "exam_id, login, first_seen, started_at, ended_at, dismissed_at, extra_minutes, address, details"
SELECT_MEMBERS = f"SELECT {MEMBER_COLUMNS} FROM `{{members}}` ORDER BY exam_id, login"
# the account has INSERT and DELETE on the tables: REPLACE needs no UPDATE privilege
REPLACE_MEMBER = (f"REPLACE INTO `{{members}}` ({MEMBER_COLUMNS}, updated_at) "
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
DELETE_MEMBERS_OF = "DELETE FROM `{members}` WHERE exam_id = %s"
# the past exams older than the retention: ended, or whose window closed, before *before*
PURGE_EXAMS = ("DELETE FROM `{table}` WHERE updated_at < %s AND (ended_at IS NOT NULL OR "
               "(end_before IS NOT NULL AND end_before < %s))")
PURGE_MEMBERS = "DELETE m FROM `{members}` m LEFT JOIN `{table}` e ON e.id = m.exam_id WHERE e.id IS NULL"


def _dt(ts: float | None):
    return None if ts is None else utc_datetime(ts)


def _ts(value) -> float | None:
    if isinstance(value, datetime):
        return epoch(value)
    return None if value is None else float(value)


def exam_details(exam: Exam) -> str:
    return json.dumps({'audience': {'logins': sorted(exam.logins), 'groups': sorted(exam.groups)},
                       'labs': [l.to_dict() for l in exam.labs], 'lead': exam.lead, 'pre_start': exam.pre_start,
                       'networks': [str(n) for n in exam.networks], 'eval_interval': exam.eval_interval},
                      separators=(',', ':'))


def member_details(m: Member) -> str:
    return json.dumps({'labs': None if m.labs is None else [l.to_dict() for l in m.labs],
                       'projects': m.projects, 'orphans': m.orphans}, separators=(',', ':'))


def _labs(value) -> list | None:
    if value is None:
        return None
    labs = []
    for item in value if isinstance(value, list) else []:
        try:
            labs.append(ExamLab.parse(item))
        except ValueError:
            continue
    return labs


def exam_of_row(row, cfg: ExamsConfig) -> Exam:
    """An ``Exam`` from a row of ``SELECT_EXAMS`` (a broken ``details`` gives the defaults)."""
    try:
        details = json.loads(row[9] or '{}')
    except ValueError:
        details = {}
    if not isinstance(details, dict):
        details = {}
    audience = details.get('audience') if isinstance(details.get('audience'), dict) else {}
    try:
        networks = parse_networks([str(n) for n in details.get('networks', []) or []], 'networks')
    except (ConfigError, TypeError):
        networks = []
    duration = row[7]
    return Exam(id=int(row[0]), title=str(row[1] or ''), created_by=str(row[2] or ''),
                created_at=_ts(row[3]) or 0.0, updated_at=_ts(row[4]) or 0.0,
                logins={str(l) for l in audience.get('logins', []) or []},
                groups={str(g) for g in audience.get('groups', []) or []},
                labs=_labs(details.get('labs')) or [],
                duration=None if duration is None else float(duration),
                start_after=_ts(row[5]), end_before=_ts(row[6]),
                lead=float(details.get('lead', cfg.lead)), pre_start=float(details.get('pre_start', cfg.pre_start)),
                networks=networks, eval_interval=float(details.get('eval_interval', cfg.eval_interval)),
                ended_at=_ts(row[8]))


def member_of_row(row) -> tuple:
    """``(exam id, Member)`` from a row of ``SELECT_MEMBERS``."""
    try:
        details = json.loads(row[8] or '{}')
    except ValueError:
        details = {}
    if not isinstance(details, dict):
        details = {}
    projects = details.get('projects') if isinstance(details.get('projects'), dict) else {}
    orphans = details.get('orphans') if isinstance(details.get('orphans'), list) else []
    m = Member(login=str(row[1]), first_seen=_ts(row[2]), started_at=_ts(row[3]), ended_at=_ts(row[4]),
               dismissed_at=_ts(row[5]), extra_minutes=int(row[6] or 0), address=str(row[7] or ''),
               labs=_labs(details.get('labs')),
               projects={str(lab): dict(p) for lab, p in projects.items() if isinstance(p, dict)},
               orphans=[dict(o) for o in orphans if isinstance(o, dict)])
    return int(row[0]), m


class ExamStore:
    """The two tables; ``connected`` / ``last_error`` tell the Exams page how the database
    does."""

    def __init__(self, db: AccessDatabaseConfig, cfg: ExamsConfig, *, connect, clock: Callable[[], float] = time.time):
        self.db = db
        self.cfg = cfg
        self.connect = connect
        self.clock = clock
        self.table = cfg.table
        self.members_table = cfg.members_table
        self._ready = False
        self.connected = False
        self.last_error: str | None = None

    def _q(self, template: str) -> str:
        return template.format(table=self.table, members=self.members_table)

    def _run(self, work: Callable):
        """*work(cursor)* in one transaction, the tables made sure of first (once per process);
        the outcome recorded in ``connected`` / ``last_error``."""
        ready = self._ready

        def prepared(cur):
            if not ready:
                ensure_table(cur, self.table, DDL_EXAMS, 'exams database')
                ensure_table(cur, self.members_table, DDL_MEMBERS, 'exams database')
            return work(cur)

        try:
            result = transaction(self.connect, prepared)
        except HistoryError as e:
            self.connected = False
            self.last_error = str(e)
            raise
        self._ready = True
        self.connected = True
        self.last_error = None
        return result

    # -- synchronous operations (a worker thread) -----------------------------------------------

    def load_all(self) -> list:
        """Every exam with its members."""
        def work(cur):
            cur.execute(self._q(SELECT_EXAMS))
            exams = {}
            for row in cur.fetchall():
                exam = exam_of_row(row, self.cfg)
                exams[exam.id] = exam
            cur.execute(self._q(SELECT_MEMBERS))
            for row in cur.fetchall():
                exam_id, m = member_of_row(row)
                exam = exams.get(exam_id)
                if exam is not None:
                    exam.members[m.login] = m
            return list(exams.values())
        return self._run(work)

    def save_exam(self, exam: Exam) -> int:
        """The exam written (inserted when it has no id yet); its id."""
        def work(cur):
            values = (exam.title, _dt(exam.updated_at), _dt(exam.start_after), _dt(exam.end_before),
                      None if exam.duration is None else int(round(exam.duration)), _dt(exam.ended_at),
                      exam_details(exam))
            if exam.id > 0:
                cur.execute(self._q(UPDATE_EXAM), (*values, exam.id))
                return exam.id
            cur.execute(self._q(INSERT_EXAM), (exam.title, exam.created_by, _dt(exam.created_at), *values[1:]))
            return int(cur.lastrowid or 0)
        return self._run(work)

    def save_member(self, exam_id: int, m: Member):
        def work(cur):
            cur.execute(self._q(REPLACE_MEMBER),
                        (exam_id, m.login, _dt(m.first_seen), _dt(m.started_at), _dt(m.ended_at), _dt(m.dismissed_at),
                         int(m.extra_minutes), m.address[:64], member_details(m), utc_datetime(self.clock())))
        self._run(work)

    def delete_exam(self, exam_id: int):
        def work(cur):
            cur.execute(self._q(DELETE_MEMBERS_OF), (exam_id,))
            cur.execute(self._q(DELETE_EXAM), (exam_id,))
        self._run(work)

    def purge(self, before: float) -> int:
        """The past exams last changed before *before* deleted (their members too); how many."""
        def work(cur):
            cur.execute(self._q(PURGE_EXAMS), (utc_datetime(before), utc_datetime(before)))
            gone = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            cur.execute(self._q(PURGE_MEMBERS))
            return gone
        return self._run(work)

    def status(self) -> dict:
        return {'connected': self.connected, 'last_error': self.last_error}

    def describe(self) -> str:
        where = self.db.unix_socket or f"{self.db.host}:{self.db.port}"
        return f"database {self.db.name} on {where} (tables {self.table}, {self.members_table})"
