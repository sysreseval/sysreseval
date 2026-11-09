"""Summaries of the evaluation archives (the ``.zst`` files of ``params.archive_dirs``), without
Qt and without the terminal: what the web agent shows on the instructors' Watch page, what
``sre watch`` computes for its rows, and the record of an archive the web portal keeps in its
database (:func:`archive_record`, served by the agent's ``GET /v1/archives``).

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
from SRE.common import TranslatedText, _tt_hash_str

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


def read_archive(path: str, max_size: int | None = None) -> dict:
    """The dict of an archive: strings decoded, arrays as tuples (``use_list=False``, as ``sre
    cat`` reads them: the keys of ``tests`` are ``(machine, step)`` and ``(command, timeout)``
    tuples, written as msgpack arrays, and a list is no dict key).  At most *max_size*
    (``params.archive_max_size``) decompressed bytes are read: a bigger archive (a zstd bomb in
    an archive directory, which may be a site or NFS directory) is a ``ValueError``, never the
    agent's memory."""
    limit = int(params.archive_max_size if max_size is None else max_size)
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path}: archive bigger than {limit} bytes once decompressed")
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


def _label(description, title, lang_priority) -> str:
    """The text a report shows for an element or a part: its description, else its title, in the
    first language of *lang_priority* it has."""
    for value in (description, title):
        text = TranslatedText.from_value(value).resolve_priority(list(lang_priority))
        if text:
            return text
    return ''


def lab_name_of_rln(running_lab_name: str) -> str:
    """The lab of a running lab name as the lab list names it (``sre/dhcp.py``: the ``@`` of
    the name turned back into ``/``), ``''`` when the name is malformed."""
    m = re.match(params.running_lab_name_match_pattern, running_lab_name or '')
    return m.group(2).replace('@', '/') if m else ''


def archives_after(paths, after: str = '', limit: int | None = None) -> tuple[list, bool]:
    """The paths of the archives of *paths* whose file name is greater than *after*, in the
    order of the names (their 14-digit prefix: chronological, then by running lab name), one
    per name (the same archive found in two directories counts once, the first path kept), at
    most *limit* of them; the flag tells whether others follow.  ``''`` lists everything.
    The collector of the portal walks the archives of a host with the last name it took as
    *after*: a 14-digit prefix alone compares as expected against full names."""
    by_name: dict = {}
    for path in paths:
        name = os.path.basename(path)
        if not ARCHIVE_NAME_RE.fullmatch(name) or name <= after:
            continue
        by_name.setdefault(name, path)
    names = sorted(by_name)
    more = limit is not None and len(names) > limit
    if limit is not None:
        names = names[:limit]
    return [by_name[n] for n in names], more


def _raw_text(value) -> dict | str:
    """A title or description as the archive holds it: a dict of languages (``{"en": ...}``),
    else its text (``''`` for nothing).  The browser resolves the dict in its own language."""
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return '' if value is None else str(value)


def _plain(value):
    """A metadata value as JSON carries it (the exam fields of the answers)."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def archive_record(raw: dict, path: str) -> dict:
    """Everything the portal keeps of an archive (``GET /v1/archives`` of the agent, the
    archives table of the database): the file name (``archive``), the project, the lab in the
    form of the lab list, the evaluation date as an aware ISO string (the clock of the host that
    wrote it), the student's identity from the answers metadata (``login``, ``fullname``,
    ``group``, ``email``, ``hostname``, ``language``), the exam flag and fields, the exo-eval
    totals (``grade`` / ``max_grade`` / ``mark``, as :func:`summarize`) and the self-eval ones,
    ``maximum_mark``, the errors (``[{'category', 'text'}]`` with their counts) and every
    element of the grade list (``key`` as :func:`lab_elements`, the ``title`` / ``description``
    **raw**, dict or string, the grade, maximum, letter, part, bonus flag and scope) with the
    parts.  No answer of the student."""
    summary = summarize(raw, path)
    answers = raw.get('answers') or {}
    if not isinstance(answers, dict):
        answers = {}
    eval_date = summary.eval_date
    if eval_date.tzinfo is None:
        eval_date = eval_date.astimezone()
    elements = []
    for e in raw.get('grade_list') or []:
        if not isinstance(e, dict):
            continue
        title = e.get('title', '')
        part = e.get('grade_part')
        elements.append({
            'key': _tt_hash_str(title),
            'title': _raw_text(title),
            'description': _raw_text(e.get('description', '')),
            'grade': _float_or_none(e.get('grade')),
            'max_grade': _float_or_none(e.get('max_grade')),
            'grade_letter': str(e['grade_letter']) if e.get('grade_letter') else None,
            'part': str(part) if part is not None else None,
            'bonus': bool(e.get('bonus', False)),
            'scope': int(e.get('scope', params.BOTH_EVAL_SCOPE) or params.BOTH_EVAL_SCOPE),
        })
    parts = [{'title': str(p.get('title', '')), 'description': _raw_text(p.get('description', ''))}
             for p in (raw.get('grade_parts') or []) if isinstance(p, dict)]
    re_eval = raw.get(params.re_eval_date_keyword)
    return {
        'archive': os.path.basename(path),
        'running_lab_name': summary.running_lab_name,
        'lab': lab_name_of_rln(summary.running_lab_name),
        'eval_date': eval_date.isoformat(timespec='seconds'),
        're_eval_date': str(re_eval) if re_eval else None,
        'login': summary.login,
        'fullname': summary.fullname,
        'group': str(answers.get(params.group_keyword, '') or ''),
        'email': str(answers.get(params.email_keyword, '') or ''),
        'hostname': summary.hostname,
        'language': str(answers.get(params.language_keyword, '') or ''),
        'exam': bool(answers.get(params.sysreseval_exam_mode)) or params.exam_json_keyword in raw,
        'exam_started_at': _plain(answers.get(params.sysreseval_exam_started_at)),
        'exam_duration': _plain(answers.get(params.sysreseval_exam_duration)),
        'exam_time_remaining': _plain(answers.get(params.sysreseval_exam_time_remaining)),
        'auto_eval_count': summary.auto_eval_count,
        'answers_updated_at': summary.answers_updated_at,
        'grade': summary.grade,
        'max_grade': summary.max_grade,
        'mark': summary.mark,
        'maximum_mark': summary.maximum_mark,
        'self_grade': _float_or_none(raw.get('total_grade_self_eval')),
        'self_max_grade': _float_or_none(raw.get('total_max_self_eval')),
        'self_mark': _float_or_none(raw.get('mark_self_eval')),
        'errors': error_entries(raw.get('errors')),
        'error_count': summary.errors,
        'warning_count': summary.warnings,
        'elements': elements,
        'parts': parts,
    }


def _whole(value):
    """A number as an archive holds it: :func:`archive_record` gives floats, a whole one goes
    back to an ``int`` (``3`` in a spreadsheet cell, not ``3.0``); anything else as is."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


#: The metadata keys of a record and the answers keywords they come from.
_RECORD_ANSWERS = (('login', params.login_keyword), ('fullname', params.fullname_keyword),
                   ('email', params.email_keyword), ('hostname', params.hostname_keyword),
                   ('language', params.language_keyword), ('group', params.group_keyword))


def raw_from_record(record: dict) -> dict:
    """A pseudo archive dict rebuilt from a record of :func:`archive_record` (what the portal
    keeps of an archive in its database), the inverse for the keys the collectors of ``sre
    sheet`` / ``sre outline`` read: ``running_lab_name``, ``eval_date`` (the aware ISO string of
    the record back to the local naive form of the real archives, ``''`` when missing or
    malformed), the ``answers`` metadata (an empty ``language`` left out so that the collectors
    take their default), ``errors`` (the entries, else one placeholder per counted error and
    warning), ``grade_list`` (``part`` back to ``grade_part``) and ``grade_parts``, the exo-eval
    totals and mark, ``maximum_mark``, the self-eval totals; the numbers whole again
    (:func:`_whole`).  What ``sre report`` feeds the builders of the two commands with.  Neither
    the tests nor the answers of the student: the record never had them."""
    eval_date = ''
    value = record.get('eval_date')
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            dt = None
        if dt is not None:
            if dt.tzinfo is not None:
                dt = dt.astimezone().replace(tzinfo=None)
            eval_date = dt.isoformat()
    answers = {}
    for key, keyword in _RECORD_ANSWERS:
        text = record.get(key)
        if text:
            answers[keyword] = str(text)
    if record.get('exam_time_remaining') is not None:
        answers[params.sysreseval_exam_time_remaining] = record['exam_time_remaining']
    if record.get('exam'):
        answers[params.sysreseval_exam_mode] = True
    entries = record.get('errors')
    if isinstance(entries, (list, tuple)):
        errors = [(str(e.get('category', 'ERROR')), str(e.get('text', ''))) if isinstance(e, dict) else ('ERROR', str(e))
                  for e in entries]
    else:
        errors = ([('ERROR', '')] * int(record.get('error_count') or 0)
                  + [(WARNING_CATEGORY, '')] * int(record.get('warning_count') or 0))
    grade_list = []
    for e in record.get('elements') or []:
        if not isinstance(e, dict):
            continue
        grade_list.append({
            'title': e.get('title', ''),
            'description': e.get('description', ''),
            'grade': _whole(e.get('grade')),
            'max_grade': _whole(e.get('max_grade')),
            'grade_letter': e.get('grade_letter'),
            'grade_part': e.get('part'),
            'bonus': bool(e.get('bonus', False)),
            'scope': int(e.get('scope', params.BOTH_EVAL_SCOPE) or params.BOTH_EVAL_SCOPE),
        })
    grade_parts = [{'title': str(p.get('title', '')), 'description': p.get('description', '')}
                   for p in (record.get('parts') or []) if isinstance(p, dict)]
    return {
        params.running_lab_name_keyword: str(record.get('running_lab_name') or ''),
        params.eval_date_keyword: eval_date,
        params.re_eval_date_keyword: record.get('re_eval_date'),
        'answers': answers,
        'errors': errors,
        'grade_list': grade_list,
        'grade_parts': grade_parts,
        'total_grade_exo_eval': _whole(record.get('grade')),
        'total_max_exo_eval': _whole(record.get('max_grade')),
        'mark_exo_eval': _whole(record.get('mark')),
        'maximum_mark': _whole(record.get('maximum_mark')),
        'total_grade_self_eval': _whole(record.get('self_grade')),
        'total_max_self_eval': _whole(record.get('self_max_grade')),
        'mark_self_eval': _whole(record.get('self_mark')),
    }


def lab_elements(raw: dict, *, lang_priority, debug: bool = False) -> tuple[list, list]:
    """``(elements, parts)`` of an archive for the lab summary of the Watch page, where the
    elements of several projects of one lab are matched across students: one dict per element
    of :func:`exo_grade_list` with ``key`` (``_tt_hash_str`` of the title: the key of
    ``Grade0._grades``, the same in every language), ``label`` (the description, else the title,
    resolved by *lang_priority*), ``grade``, ``max_grade``, ``grade_letter``, ``part`` (the title
    of its grade part, or ``None``) and ``bonus``; the parts as ``[{'title', 'label'}]``."""
    elements = []
    for e in exo_grade_list(raw, debug=debug):
        title = e.get('title', '')
        part = e.get('grade_part') or None
        elements.append({
            'key': _tt_hash_str(title),
            'label': _label(e.get('description', ''), title, lang_priority),
            'grade': _float_or_none(e.get('grade')),
            'max_grade': _float_or_none(e.get('max_grade')),
            'grade_letter': str(e['grade_letter']) if e.get('grade_letter') else None,
            'part': str(part) if part is not None else None,
            'bonus': bool(e.get('bonus', False)),
        })
    parts = [{'title': str(p.get('title', '')), 'label': _label(p.get('description', ''), p.get('title', ''), lang_priority)}
             for p in (raw.get('grade_parts') or []) if isinstance(p, dict)]
    return elements, parts
