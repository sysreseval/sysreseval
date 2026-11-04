"""The exam of a project, as the portal tells it: the exam mode of the web front-end.

The Qt GUI's exam mode is host-wide (``exam.json`` in ``params.sre_pub_dir``); a pool host of
the web is shared by many students, so the portal programs the exams itself and tells the agent,
per project, that it is an exam project (``POST /v1/projects`` with an ``exam`` object, then
``PUT /v1/projects/{rln}/exam`` when the student's clock starts or the instructor moves the end).
The agent then does for that project what the GUI does in exam mode: a periodic evaluation at
the exam's interval, the final evaluation at the end, the exam fields of the answers metadata,
no self-evaluation nor state for the owner, the Evaluation / Apply Config tabs hidden, the owner
cut off at the end.  The object::

    {"id": "12", "title": "Partiel", "started_at": "2026-11-04T09:00:00+00:00",
     "end_at": "2026-11-04T10:30:00+00:00", "eval_interval": 60, "now": "2026-11-04T09:00:02+00:00"}

``started_at`` / ``end_at`` are ``null`` while the student's clock has not started (the project
pre-started before the exam): no periodic nor final evaluation then, every other rule applies.
The times are ISO 8601 with an offset (``Z`` accepted), stored in UTC; ``now`` (optional) is the
portal's clock, only compared with the host's.  Once the end ran, the stored object also holds
``ended_at`` and, after the final evaluation, ``final_eval_at`` (``params.exam_ended_at`` and
``KEY_FINAL_EVAL_AT``).  The pure functions here parse, store and describe it; ``registry.py``
keeps it on the project and in its state file, ``schedulers.py`` acts on it.
"""
import math
import re
import time
from datetime import datetime, timezone

from SRE import params

from .access import AccessError

#: The keys of the object: the shared ones are those of ``exam.json``.
KEY_ID = 'id'
KEY_TITLE = 'title'
KEY_STARTED_AT = params.exam_started_at
KEY_END_AT = 'end_at'
KEY_EVAL_INTERVAL = params.exam_eval_interval
KEY_NOW = 'now'
KEY_ENDED_AT = params.exam_ended_at
KEY_FINAL_EVAL_AT = 'final_eval_at'
KEYS = (KEY_ID, KEY_TITLE, KEY_STARTED_AT, KEY_END_AT, KEY_EVAL_INTERVAL)

ID_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
FLAVOR_PRESET_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
MAX_TITLE = 200
MAX_EVAL_INTERVAL = 86400
#: Seconds of difference between the portal's clock and the host's worth a warning.
SKEW_WARNING = 5.0


def parse_utc(value, field: str) -> datetime:
    """An ISO 8601 instant with an offset (``Z`` accepted), as an aware UTC datetime; 400 for
    anything else (a naive time would mean a different instant on every host)."""
    if not isinstance(value, str):
        raise AccessError(400, f"exam: {field} must be an ISO 8601 time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise AccessError(400, f"exam: {field} must be an ISO 8601 time")
    if parsed.tzinfo is None:
        raise AccessError(400, f"exam: {field} must carry a timezone")
    return parsed.astimezone(timezone.utc)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')


def now_iso() -> str:
    return iso_utc(datetime.now(timezone.utc))


def _epoch(value) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return parse_utc(value, '').timestamp()
    except AccessError:
        return None


def check_flavor_preset(value) -> str:
    """The name of a ``Flavor`` preset (a class attribute: an identifier)."""
    if not isinstance(value, str) or not FLAVOR_PRESET_RE.fullmatch(value):
        raise AccessError(400, "bad flavor preset")
    return value


def parse_exam(body) -> tuple[dict, float | None]:
    """The exam object of a request, validated and normalised (times in UTC), and the skew of
    the portal's clock (``now`` minus the host's time, in seconds; ``None`` without ``now``).
    ``AccessError`` 400 on anything wrong."""
    if not isinstance(body, dict):
        raise AccessError(400, "exam must be an object")
    exam_id = body.get(KEY_ID)
    if not isinstance(exam_id, str) or not ID_RE.fullmatch(exam_id):
        raise AccessError(400, "exam: bad id")
    title = body.get(KEY_TITLE, '')
    if title is None:
        title = ''
    if not isinstance(title, str) or len(title) > MAX_TITLE:
        raise AccessError(400, "exam: bad title")
    started_at = body.get(KEY_STARTED_AT)
    end_at = body.get(KEY_END_AT)
    start = parse_utc(started_at, KEY_STARTED_AT) if started_at is not None else None
    end = parse_utc(end_at, KEY_END_AT) if end_at is not None else None
    if end is not None and start is None:
        raise AccessError(400, f"exam: {KEY_END_AT} needs {KEY_STARTED_AT}")
    if end is not None and end < start:
        raise AccessError(400, f"exam: {KEY_END_AT} is before {KEY_STARTED_AT}")
    interval = body.get(KEY_EVAL_INTERVAL, 0)
    if interval is None:
        interval = 0
    if isinstance(interval, bool) or not isinstance(interval, int) or not 0 <= interval <= MAX_EVAL_INTERVAL:
        raise AccessError(400, f"exam: {KEY_EVAL_INTERVAL} must be a number of seconds (0 to {MAX_EVAL_INTERVAL})")
    skew = None
    if body.get(KEY_NOW) is not None:
        skew = parse_utc(body[KEY_NOW], KEY_NOW).timestamp() - time.time()
    exam = {KEY_ID: exam_id, KEY_TITLE: title,
            KEY_STARTED_AT: iso_utc(start) if start is not None else None,
            KEY_END_AT: iso_utc(end) if end is not None else None,
            KEY_EVAL_INTERVAL: interval}
    return exam, skew


def load_exam(value) -> dict | None:
    """The exam object of a state file, or ``None`` when it is unusable: the keys of
    :func:`parse_exam` validated again, ``ended_at`` / ``final_eval_at`` kept when they are
    instants."""
    if not isinstance(value, dict):
        return None
    try:
        exam, _ = parse_exam({key: value.get(key) for key in KEYS})
    except AccessError:
        return None
    for key in (KEY_ENDED_AT, KEY_FINAL_EVAL_AT):
        if _epoch(value.get(key)) is not None:
            exam[key] = value[key]
    return exam


def start_epoch(exam: dict) -> float | None:
    return _epoch(exam.get(KEY_STARTED_AT))


def end_epoch(exam: dict) -> float | None:
    return _epoch(exam.get(KEY_END_AT))


def is_over(exam: dict | None) -> bool:
    return bool(exam and exam.get(KEY_ENDED_AT))


def is_running(exam: dict | None) -> bool:
    """An exam project whose exam has not ended (its clock started or not)."""
    return exam is not None and not is_over(exam)


def remaining(exam: dict, now: float | None = None) -> int | None:
    """Seconds to the end on this host's clock (0 once ended), ``None`` while the clock of the
    student has not started."""
    if is_over(exam):
        return 0
    end = end_epoch(exam)
    if end is None:
        return None
    return max(0, int(math.ceil(end - (time.time() if now is None else now))))


def exam_json_data(exam: dict) -> dict:
    """The ``exam.json``-shaped dict of the exam fields of the answers metadata
    (``SRE.answers.exam_fields``): ``started_at``, ``duration`` in whole minutes rounded up and
    ``end_before`` = the end, so that the clamp by ``end_before`` makes ``exam_time_remaining``
    exact; ``{}`` while the clock has not started (``exam_mode`` alone)."""
    start, end = start_epoch(exam), end_epoch(exam)
    if start is None or end is None:
        return {}
    return {params.exam_started_at: exam[KEY_STARTED_AT],
            params.exam_duration: max(1, int(math.ceil((end - start) / 60))),
            params.exam_end_before: exam[KEY_END_AT]}


def view(exam: dict | None, now: float | None = None) -> dict | None:
    """What the portal and the browsers are told about the exam of a project (``null`` for a
    plain project)."""
    if exam is None:
        return None
    return {KEY_ID: exam[KEY_ID], KEY_TITLE: exam.get(KEY_TITLE, ''),
            KEY_STARTED_AT: exam.get(KEY_STARTED_AT), KEY_END_AT: exam.get(KEY_END_AT),
            KEY_EVAL_INTERVAL: exam.get(KEY_EVAL_INTERVAL, 0),
            'ended': is_over(exam), KEY_ENDED_AT: exam.get(KEY_ENDED_AT),
            KEY_FINAL_EVAL_AT: exam.get(KEY_FINAL_EVAL_AT), 'remaining': remaining(exam, now)}
