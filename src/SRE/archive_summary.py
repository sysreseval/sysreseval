"""Summaries of the evaluation archives (the ``.zst`` files of ``params.archive_dirs``), without
Qt and without the terminal: what the web agent shows on the instructors' Watch page, and what
``sre watch`` computes for its rows.

An archive is a zstandard-compressed msgpack dict written by ``Grade0.save_tests_on_file()``:
``running_lab_name``, ``eval_date`` (an ISO string: ``datetime.now().isoformat()``), ``errors``
(``(category, text)`` pairs, or plain strings in old archives), ``answers`` (the student's answers
plus the metadata ``login``, ``hostname``, ``fullname``, ``auto_eval_count``,
``answers_updated_at``), ``grade_list`` / ``grade_parts``, the self-eval and exo-eval totals and
marks, ``maximum_mark``.  Its name is ``<YYYYmmddHHMMSS>_<running_lab_name>.zst``
(``params.get_archive_name``), the prefix being the evaluation time on the clock of the host that
wrote it, so the newest archive of a project is the greatest prefix.

Note on ``eval_date``: ``sre watch`` feeds the ISO string to ``params.string_to_datetime`` (the
14-digit form), which always fails, and silently falls back on the file's mtime;
:func:`archive_eval_date` parses the ISO form first.
"""
import os
import re
from dataclasses import dataclass
from datetime import datetime

import msgpack
import zstandard as zstd

from SRE import params

ARCHIVE_NAME_RE = re.compile(params.archive_name_match_pattern)
WARNING_CATEGORY = "WARNING"


@dataclass
class ArchiveSummary:
    """What one archive says of a project, as the Watch page shows it (exo-eval scope)."""
    path: str
    running_lab_name: str
    eval_date: datetime
    grade: float
    max_grade: float
    mark: float | None
    maximum_mark: float | None
    errors: int
    warnings: int
    auto_eval_count: int | None
    answers_updated_at: str
    login: str
    hostname: str
    fullname: str

    def to_json(self, now: datetime | None = None) -> dict:
        """A JSON-friendly dict, ``age_s`` being the age of the evaluation at *now*."""
        now = now or datetime.now()
        return {
            'eval_date': self.eval_date.isoformat(timespec='seconds'),
            'age_s': max(0, int((now - self.eval_date).total_seconds())),
            'grade': self.grade,
            'max_grade': self.max_grade,
            'mark': self.mark,
            'maximum_mark': self.maximum_mark,
            'errors': self.errors,
            'warnings': self.warnings,
            'auto_eval_count': self.auto_eval_count,
            'answers_updated_at': self.answers_updated_at,
            'archive': os.path.basename(self.path),
        }


def read_archive(path: str) -> dict:
    """The dict of an archive: strings decoded, arrays as tuples (``use_list=False``, as ``sre
    cat`` reads them: the keys of ``tests`` are ``(machine, step)`` and ``(command, timeout)``
    tuples, written as msgpack arrays, and a list is no dict key)."""
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def error_category(entry) -> str:
    """The category of an error entry (a ``(category, text)`` pair, or a legacy string)."""
    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
        return str(entry[0])
    return "ERROR"


def error_text(entry) -> str:
    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
        return str(entry[1])
    return str(entry)


def error_counts(errors) -> tuple[int, int]:
    """``(errors, warnings)`` of the ``errors`` list of an archive."""
    entries = list(errors or [])
    warnings = sum(1 for e in entries if error_category(e) == WARNING_CATEGORY)
    return len(entries) - warnings, warnings


def error_entries(errors) -> list:
    """The ``errors`` list as ``[{'category', 'text'}]``."""
    return [{'category': error_category(e), 'text': error_text(e)} for e in (errors or [])]


def archive_eval_date(raw: dict, path: str) -> datetime:
    """When the evaluation ran: the ISO ``eval_date`` of the archive, else the 14-digit form,
    else the prefix of the file name, else the file's mtime."""
    value = raw.get(params.eval_date_keyword, '')
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
        try:
            return params.string_to_datetime(value)
        except Exception:
            pass
    from_name = params.get_date_from_archive_name(path)
    if from_name is not None:
        return from_name
    try:
        return datetime.fromtimestamp(os.path.getmtime(path))
    except OSError:
        return datetime.now()


def _float_or_none(value):
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def summarize(raw: dict, path: str) -> ArchiveSummary:
    """The summary of an archive dict (exo-eval totals, like ``sre watch``)."""
    answers = raw.get('answers') or {}
    if not isinstance(answers, dict):
        answers = {}
    errors, warnings = error_counts(raw.get('errors'))
    auto_eval_count = answers.get(params.auto_eval_count_keyword)
    try:
        auto_eval_count = None if auto_eval_count is None else int(auto_eval_count)
    except (TypeError, ValueError):
        auto_eval_count = None
    return ArchiveSummary(
        path=path,
        running_lab_name=str(raw.get(params.running_lab_name_keyword, '') or ''),
        eval_date=archive_eval_date(raw, path),
        grade=_float_or_none(raw.get('total_grade_exo_eval', raw.get('total_grade'))) or 0.0,
        max_grade=_float_or_none(raw.get('total_max_exo_eval', raw.get('total_max'))) or 0.0,
        mark=_float_or_none(raw.get('mark_exo_eval')),
        maximum_mark=_float_or_none(raw.get('maximum_mark')),
        errors=errors,
        warnings=warnings,
        auto_eval_count=auto_eval_count,
        answers_updated_at=str(answers.get(params.sysreseval_answers_updated_at, '') or ''),
        login=str(answers.get(params.login_keyword, '') or ''),
        hostname=str(answers.get(params.hostname_keyword, '') or ''),
        fullname=str(answers.get(params.fullname_keyword, '') or ''),
    )


def scan_archive_dirs(dirs) -> list:
    """The paths of the archives found directly in *dirs* (a missing or unreadable directory is
    skipped; no recursion: ``sre eval`` writes flat directories)."""
    paths = []
    for d in dirs or []:
        try:
            with os.scandir(d) as it:
                for entry in it:
                    if ARCHIVE_NAME_RE.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                        paths.append(entry.path)
        except OSError:
            continue
    return paths


def newest_by_running_lab_name(paths, only=None) -> dict:
    """``{running_lab_name: path}`` of the newest archive of each project among *paths* (the
    14-digit prefix of the name decides, then the name), restricted to the names of *only* when
    given."""
    newest: dict = {}
    for path in paths:
        m = ARCHIVE_NAME_RE.fullmatch(os.path.basename(path))
        if not m:
            continue
        rln = m.group(2)
        if only is not None and rln not in only:
            continue
        key = (m.group(1), os.path.basename(path))
        if rln not in newest or key > newest[rln][0]:
            newest[rln] = (key, path)
    return {rln: path for rln, (_, path) in newest.items()}


def exo_grade_list(raw: dict, *, debug: bool = False) -> list:
    """The ``grade_list`` of an archive restricted to the exo-eval scope (every element for a
    debug project), as ``sre eval`` prints it without ``--auto-eval``."""
    grades = [dict(e) for e in (raw.get('grade_list') or []) if isinstance(e, dict)]
    if debug:
        return grades
    return [e for e in grades if int(e.get('scope', 3) or 0) & params.EXO_EVAL_SCOPE]
