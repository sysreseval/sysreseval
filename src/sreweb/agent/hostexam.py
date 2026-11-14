"""The exam of the host, as the portal tells it: ``exam.json`` written by the agent.

The exam mode of the Qt GUI is host-wide: the file ``exam.json`` of ``params.sre_pub_dir``, which
``sre set-exam`` writes by hand on every workstation and the GUI of the student logged in reads
every second (it launches ``sre pre-start-exam`` / ``start-exam`` / ``eval-exam`` / ``end-exam``
itself).  When an exam of the web site lists the machine, the portal sends its definition
(``PUT /v1/exam``) and the agent writes that file in place of ``sre set-exam``, removes it in
place of ``sre del-exam`` (``DELETE /v1/exam``).  The request::

    {"id": "12", "title": "Partiel", "rev": "5f0c…", "origin": "9a41…",
     "labs": [{"lab": "sre/_EXAM_/x.py", "flavor": null}],
     "start_after": "2026-11-16T08:00:00+00:00", "end_before": "2026-11-16T10:00:00+00:00",
     "duration": 90, "eval_interval": 60, "now": "2026-11-16T07:50:01+00:00"}

The file holds the keys ``sre set-exam`` writes, in the same forms (the times naive and local,
``labs`` as ``[[lab, flavor]]``, the duration in minutes), and one more, the marker
``params.exam_web``: the id and title of the exam of the web site, ``rev`` (the revision of the
definition the portal sent: how it sees that the machine is up to date) and ``origin`` (the
portal the exam comes from).  A file without the marker was set by hand: never touched.

The commands the GUI launches rewrite the file in place (``pre_start_date``, ``started_at``,
``ended_at``): an update merges into the current content, and the content read is checked again
after the replace (:func:`write`).  The pure functions here parse, merge and describe;
``app.py`` holds the two handlers.
"""
import json
import os
import re
import time
from datetime import datetime, timezone

from SRE import params
from SRE import answers as A

from .access import AccessError
from .exam import ID_RE, MAX_TITLE, MAX_EVAL_INTERVAL, check_flavor_preset, iso_utc, parse_utc

#: What :func:`read` found: no file, the file of an exam of the web site, a file set by hand
#: (no marker), a file that does not parse (a command of the CLI is rewriting it).
ABSENT = 'absent'
WEB = 'web'
FOREIGN = 'foreign'
UNREADABLE = 'unreadable'

KEY_ID = 'id'
KEY_TITLE = 'title'
KEY_REV = 'rev'
KEY_ORIGIN = 'origin'
KEY_LABS = 'labs'
KEY_START_AFTER = params.exam_start_after
KEY_END_BEFORE = params.exam_end_before
KEY_DURATION = params.exam_duration
KEY_EVAL_INTERVAL = params.exam_eval_interval
KEY_RECORD_SESSIONS = params.exam_record_sessions
KEY_NOW = 'now'

TOKEN_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')     # a revision, an origin
MAX_LABS = 20
MAX_LAB_NAME = 200
MAX_DURATION = 7 * 24 * 60          # minutes
#: How many times :func:`write` merges again when a command of the CLI rewrote the file while
#: it was being replaced, and the pause before a content that does not parse is read again.
WRITE_ATTEMPTS = 5
REREAD_DELAY = 0.02


def exam_path(pub_dir: str | None = None) -> str:
    return os.path.join(pub_dir or params.sre_pub_dir, params.exam_json_name)


def _lab(value) -> list:
    """``[lab, flavor]`` of a lab of the request: the name as ``sre list`` gives it (relative,
    no ``..``), an optional ``Flavor`` preset."""
    if isinstance(value, str):
        value = {'lab': value}
    if not isinstance(value, dict):
        raise AccessError(400, "exam: a lab must be a name or an object {lab, flavor}")
    lab = value.get('lab')
    if not isinstance(lab, str) or not lab or len(lab) > MAX_LAB_NAME or not lab.isprintable() \
            or lab.startswith('/') or '@' in lab or any(part in ('', '.', '..') for part in lab.split('/')):
        raise AccessError(400, "exam: bad lab name")
    flavor = value.get('flavor')
    return [lab, check_flavor_preset(flavor) if flavor is not None else None]


def _token(body: dict, key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise AccessError(400, f"exam: bad {key}")
    return value


def _whole(body: dict, key: str, low: int, high: int, unit: str) -> int:
    value = body.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise AccessError(400, f"exam: {key} must be a number of {unit} ({low} to {high})")
    return value


def parse_host_exam(body) -> tuple[dict, float | None]:
    """The definition of the exam of the host from a request, validated (the times as epoch
    seconds), and the skew of the portal's clock (``now`` minus the host's time; ``None``
    without ``now``).  ``AccessError`` 400 on anything wrong."""
    if not isinstance(body, dict):
        raise AccessError(400, "exam must be an object")
    exam_id = body.get(KEY_ID)
    if not isinstance(exam_id, str) or not ID_RE.fullmatch(exam_id):
        raise AccessError(400, "exam: bad id")
    title = body.get(KEY_TITLE, '')
    if title is None:
        title = ''
    if not isinstance(title, str) or len(title) > MAX_TITLE or not title.isprintable():
        raise AccessError(400, "exam: bad title")
    labs = body.get(KEY_LABS)
    if not isinstance(labs, list) or not labs or len(labs) > MAX_LABS:
        raise AccessError(400, f"exam: 1 to {MAX_LABS} labs are required")
    labs = [_lab(value) for value in labs]
    if len({lab for lab, _ in labs}) != len(labs):
        raise AccessError(400, "exam: a lab is listed twice")
    times = {}
    for key in (KEY_START_AFTER, KEY_END_BEFORE):
        value = body.get(key)
        times[key] = parse_utc(value, key).timestamp() if value is not None else None
    record = body.get(KEY_RECORD_SESSIONS, True)
    if not isinstance(record, bool):
        raise AccessError(400, f"exam: {KEY_RECORD_SESSIONS} must be a boolean")
    skew = None
    if body.get(KEY_NOW) is not None:
        skew = parse_utc(body[KEY_NOW], KEY_NOW).timestamp() - time.time()
    spec = {KEY_ID: exam_id, KEY_TITLE: title, KEY_REV: _token(body, KEY_REV), KEY_ORIGIN: _token(body, KEY_ORIGIN),
            KEY_LABS: labs, KEY_START_AFTER: times[KEY_START_AFTER], KEY_END_BEFORE: times[KEY_END_BEFORE],
            KEY_DURATION: _whole(body, KEY_DURATION, 1, MAX_DURATION, 'minutes'),
            KEY_EVAL_INTERVAL: _whole(body, KEY_EVAL_INTERVAL, 1, MAX_EVAL_INTERVAL, 'seconds'),
            KEY_RECORD_SESSIONS: record}
    return spec, skew


# -- the times of the file ---------------------------------------------------------------------

def local_iso(epoch: float) -> str:
    """An instant as ``sre set-exam`` writes it: naive, in the time of the host, to the second."""
    return datetime.fromtimestamp(int(epoch)).isoformat(timespec='seconds')


def epoch_of(value) -> float | None:
    """The instant of a time of the file (naive: the time of the host; an offset is obeyed);
    ``None`` for anything else."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _utc(value) -> str | None:
    epoch = epoch_of(value)
    return None if epoch is None else iso_utc(datetime.fromtimestamp(epoch, timezone.utc))


def _minutes(data: dict) -> int | None:
    value = data.get(params.exam_duration)
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def end_of(data: dict) -> float | None:
    """When the exam of the file ends on this host, as the GUI computes it: ``end_before``, and
    ``started_at`` plus the duration once the exam started, whichever comes first; ``None``
    when neither is known."""
    ends = []
    end_before = epoch_of(data.get(params.exam_end_before))
    if end_before is not None:
        ends.append(end_before)
    started, minutes = epoch_of(data.get(params.exam_started_at)), _minutes(data)
    if started is not None and minutes is not None:
        ends.append(started + minutes * 60)
    return min(ends) if ends else None


def over(data: dict, now: float | None = None) -> bool:
    end = end_of(data)
    return end is not None and (time.time() if now is None else now) >= end


def running(data: dict, now: float | None = None) -> bool:
    """The exam started on this host (``sre start-exam`` stamped it) and its end has not come."""
    return epoch_of(data.get(params.exam_started_at)) is not None and not over(data, now)


def needs_final_evaluation(data: dict) -> bool:
    """The exam started here and no ``sre end-exam`` recorded its end since (a machine closed
    while it runs, or an exam resumed with extra minutes: the GUI ends an exam once only)."""
    return epoch_of(data.get(params.exam_started_at)) is not None and params.exam_ended_at not in data


# -- the file ----------------------------------------------------------------------------------

def marker_of(data) -> dict | None:
    """The marker of a file of the web site (an object with an id), else ``None``."""
    marker = data.get(params.exam_web) if isinstance(data, dict) else None
    if isinstance(marker, dict) and isinstance(marker.get(params.exam_web_id), str):
        return marker
    return None


def classify(raw: bytes) -> tuple:
    """``(state, data)`` of the bytes of the file."""
    try:
        data = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return UNREADABLE, None
    if not isinstance(data, dict):
        return UNREADABLE, None
    return (WEB if marker_of(data) is not None else FOREIGN), data


def read(pub_dir: str | None = None) -> tuple:
    """``(state, data)`` of the exam file of the host: :data:`ABSENT`, :data:`WEB` (an exam of
    the web site), :data:`FOREIGN` (set with ``sre set-exam``) with its content, or
    :data:`UNREADABLE` (not a JSON object: a command is rewriting it, or it is damaged)."""
    try:
        with open(exam_path(pub_dir), 'rb') as f:
            raw = f.read()
    except FileNotFoundError:
        return ABSENT, None
    except OSError:
        return UNREADABLE, None
    return classify(raw)


def check_ours(state: str, data: dict | None, exam_id: str, origin: str | None = None):
    """The file may be written or removed for the exam *exam_id* of the portal *origin*: absent,
    or the one of that exam.  503 when it cannot be read now, 409 when it belongs to somebody
    else (set by hand, another exam, another portal)."""
    if state == ABSENT:
        return
    if state == UNREADABLE:
        raise AccessError(503, "exam.json cannot be read now, try again")
    marker = marker_of(data)
    if marker is None:
        raise AccessError(409, "an exam set with sre set-exam is on this host")
    if origin is not None and marker.get(params.exam_web_origin) != origin:
        raise AccessError(409, "an exam of another web site is on this host")
    if marker.get(params.exam_web_id) != exam_id:
        title = marker.get(params.exam_web_title) or ''
        raise AccessError(409, f"the exam {marker.get(params.exam_web_id)}"
                               f"{f' «{title}»' if title else ''} is on this host")


def document(spec: dict, current: dict | None = None, now: float | None = None) -> dict:
    """The content of the file for the definition *spec*, merged into *current*: what the
    commands of the GUI recorded (``pre_start_date``, ``started_at``) and any key this module
    does not know are kept — the machine keeps its clock through an edit, as a student does —,
    ``ended_at`` too unless the exam goes on (an end moved into the future: a resume)."""
    doc = dict(current) if current else {}
    doc[params.exam_labs] = [[lab, flavor] for lab, flavor in spec[KEY_LABS]]
    for key in (KEY_START_AFTER, KEY_END_BEFORE):
        if spec[key] is None:
            doc.pop(key, None)
        else:
            doc[key] = local_iso(spec[key])
    doc[params.exam_duration] = spec[KEY_DURATION]
    doc[params.exam_eval_interval] = spec[KEY_EVAL_INTERVAL]
    doc[params.exam_record_sessions] = spec[KEY_RECORD_SESSIONS]
    doc[params.exam_web] = {params.exam_web_id: spec[KEY_ID], params.exam_web_title: spec[KEY_TITLE],
                            params.exam_web_rev: spec[KEY_REV], params.exam_web_origin: spec[KEY_ORIGIN]}
    if params.exam_ended_at in doc and not over(doc, now):
        del doc[params.exam_ended_at]
    return doc


def _content(f) -> bytes:
    f.seek(0)
    return f.read()


def write(pub_dir: str | None, spec: dict, *, now: float | None = None, owner: tuple | None = None,
          mode: int = 0o644, before_replace=None) -> dict:
    """The file written for *spec* (atomically: the GUI never reads half a file) and the
    document it now holds.  ``AccessError`` as :func:`check_ours`.

    The commands the GUI launches rewrite the file in place while this runs: the file read is
    kept open across the replace and read again afterwards; when it changed meanwhile (a
    ``started_at`` stamped into the file just replaced), the new content is merged and written
    again, ``WRITE_ATTEMPTS`` times at most (503 then: the portal tries again).  *owner*:
    ``(uid, gid)`` of the file, the user those commands run as; *before_replace*: called before
    each replace (the tests)."""
    path = exam_path(pub_dir)
    try:
        old = open(path, 'rb')
    except FileNotFoundError:
        old = None
    except OSError:
        raise AccessError(503, "exam.json cannot be read now, try again")
    try:
        raw = _content(old) if old is not None else None
        for _ in range(WRITE_ATTEMPTS):
            state, current = (ABSENT, None) if raw is None else classify(raw)
            if state == UNREADABLE and old is not None:
                time.sleep(REREAD_DELAY)        # a command is in the middle of its write
                raw = _content(old)
                continue
            check_ours(state, current, spec[KEY_ID], spec[KEY_ORIGIN])
            doc = document(spec, current, now)
            if before_replace is not None:
                before_replace()
            A.save_answers(path, doc, atomic=True, owner=owner, mode=mode)
            if old is None:
                return doc
            again = _content(old)
            if again == raw:
                return doc
            raw = again
    finally:
        if old is not None:
            old.close()
    raise AccessError(503, "exam.json keeps changing, try again")


def remove(pub_dir: str | None = None) -> bool:
    """The file removed; false when it was not there."""
    try:
        os.unlink(exam_path(pub_dir))
    except FileNotFoundError:
        return False
    return True


def lab_names(data: dict) -> set:
    """The labs of the file, in the ``@`` form of the running lab names."""
    names = set()
    for entry in data.get(params.exam_labs, []) if isinstance(data.get(params.exam_labs), list) else []:
        lab = entry[0] if isinstance(entry, list) and entry else entry
        if isinstance(lab, str) and lab:
            names.add(params.get_lab_name_from_cli_arg(lab, is_path=lab.startswith('/')))
    return names


def view(data: dict | None) -> dict | None:
    """What the portal is told about the exam file of the host (``/v1/status``): ``null``
    without one; ``id`` is ``null`` for a file set by hand.  The times in UTC."""
    if data is None:
        return None
    marker = marker_of(data) or {}
    labs = []
    for entry in data.get(params.exam_labs, []) if isinstance(data.get(params.exam_labs), list) else []:
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            labs.append([entry[0], entry[1] if len(entry) > 1 and isinstance(entry[1], str) else None])
        elif isinstance(entry, str):
            labs.append([entry, None])
    interval = data.get(params.exam_eval_interval)
    return {KEY_ID: marker.get(params.exam_web_id), KEY_TITLE: str(marker.get(params.exam_web_title) or ''),
            KEY_REV: marker.get(params.exam_web_rev), KEY_ORIGIN: marker.get(params.exam_web_origin),
            KEY_LABS: labs,
            KEY_START_AFTER: _utc(data.get(params.exam_start_after)),
            KEY_END_BEFORE: _utc(data.get(params.exam_end_before)),
            KEY_DURATION: _minutes(data),
            KEY_EVAL_INTERVAL: interval if isinstance(interval, int) and not isinstance(interval, bool) else None,
            'pre_started': bool(data.get(params.exam_pre_start_date)),
            params.exam_started_at: _utc(data.get(params.exam_started_at)),
            params.exam_ended_at: _utc(data.get(params.exam_ended_at))}
