"""The answers file of a running project: ``answers/answers.json``.

The file holds the student's answers (``{question_hash: answer}``) and the metadata archived with
the grades (identity of the student, language, time of the last change, exam fields). It is
written by the Qt GUI (``sysreseval.view.questions_view.QuestionsView``) on the student's
workstation, and by the web agent on behalf of a browser user; it is read by
``Grade0.load_answers()`` at evaluation time. This module is the Qt-free logic both writers
share: reading and writing the file, the metadata, the exam fields of ``exam.json``, and the
cheat file ``answers/cheat.json`` that ``sre state`` writes for the GUI to merge.

The identity is the caller's: the GUI takes it from its desktop session
(:func:`session_identity`), the web agent passes the LDAP account or the pseudonym of the
browser user to :func:`with_metadata`.
"""
import contextlib
import getpass
import json
import os
import pwd
import re
import socket
import tempfile
from datetime import datetime
from pathlib import Path

from . import params
from .utils import exam_remaining_seconds

_CONTROL_CHARS = r'[\x00-\x1f\x7f]'        # removed from the GECOS fields
_FULLNAME_UNWANTED = r'[\x00-\x1f\x7f,]'   # and commas from the full name


def read_exam_json(pub_dir: str | os.PathLike) -> dict | None:
    """The content of ``exam.json`` in *pub_dir* (``params.sre_pub_dir``): its dict, or ``None``
    when the file is missing, unreadable or not a JSON object."""
    try:
        with open(Path(pub_dir) / params.exam_json_name, encoding='utf-8') as f:
            exam_data = json.load(f)
    except (OSError, ValueError):
        return None
    return exam_data if isinstance(exam_data, dict) else None


def exam_fields(exam_data: dict | None, now: datetime | None = None) -> dict:
    """The exam keys of the answers file for the ``exam.json`` dict *exam_data* (``None``
    outside exam mode): always ``params.sysreseval_exam_mode``; in exam mode, also
    ``exam_started_at`` and ``exam_duration`` when ``exam.json`` holds them, and
    ``exam_time_remaining`` (``utils.exam_remaining_seconds(exam_data, now)``) when it can be
    computed."""
    if exam_data is None:
        return {params.sysreseval_exam_mode: False}
    result = {params.sysreseval_exam_mode: True}
    if params.exam_started_at in exam_data:
        result[params.sysreseval_exam_started_at] = exam_data[params.exam_started_at]
    if params.exam_duration in exam_data:
        result[params.sysreseval_exam_duration] = exam_data[params.exam_duration]
    remaining = exam_remaining_seconds(exam_data, now)
    if remaining is not None:
        result[params.sysreseval_exam_time_remaining] = remaining
    return result


def load_answers(path: str | os.PathLike) -> dict:
    """The answers file *path* as a dict: ``{}`` when it is missing, unreadable, a symbolic link
    (opened with ``O_NOFOLLOW``, like ``Grade0.load_answers``), not JSON or not a JSON object."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding='utf-8') as f:
            answers = json.load(f)
    except (OSError, ValueError):
        return {}
    return answers if isinstance(answers, dict) else {}


def with_metadata(answers: dict, *, hostname: str, login: str, fullname: str, email: str | None,
                  language: str, exam_data: dict | None, now: datetime | None = None) -> dict:
    """A copy of *answers* with the metadata of the answers file: the identity keys
    (``hostname``, ``login``, ``fullname``, and ``email`` only when not ``None``: the GUI gives
    it only with ``params.email_in_gecos_last_field``), ``answers_updated_at``
    (``params.datetime_to_string`` of *now*, the current time by default), ``language`` and the
    :func:`exam_fields` of *exam_data*. Keys already present keep their place."""
    if now is None:
        now = datetime.now()
    data = dict(answers)
    data[params.hostname_keyword] = hostname
    data[params.login_keyword] = login
    data[params.fullname_keyword] = fullname
    if email is not None:
        data[params.email_keyword] = email
    data[params.sysreseval_answers_updated_at] = params.datetime_to_string(now)
    data[params.language_keyword] = language
    data.update(exam_fields(exam_data, now))
    return data


def merge_cheat(answers: dict, cheat: dict) -> dict:
    """A copy of *answers* with the entries of *cheat* (``{question_hash: answer}``, the cheat
    answers of a state): the cheat values win."""
    return {**answers, **cheat}


def consume_cheat_file(path: str | os.PathLike) -> dict | None:
    """Read and remove the cheat file *path* (``params.cheat_filename(...)``, written by
    ``sre state``): its dict, or ``None`` when the file does not exist.

    The file is removed once its content is read and parsed; an unreadable file or one that is
    not a JSON object raises (``OSError`` / ``ValueError``) and stays in place, so that a caller
    polling the project directory tries again later."""
    path = Path(path)
    try:
        text = path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return None
    cheat = json.loads(text)
    if not isinstance(cheat, dict):
        raise ValueError(f"{path}: not a JSON object")
    path.unlink()
    return cheat


def save_answers(path: str | os.PathLike, data: dict, *, atomic: bool = False,
                 owner: tuple[int, int] | None = None, mode: int | None = None) -> None:
    """Write *data* to the answers file *path* as JSON (``indent=2``, ``ensure_ascii=False``),
    creating the parent directory when missing; errors raise (``OSError``).

    Plain (the GUI): the file is opened and written in place. With ``atomic=True`` (the web
    agent, whose project is evaluated while it writes): a temporary file in the directory of
    *path* (mode 0600 until *mode* is applied), flushed to disk, then ``os.replace`` over
    *path*, the pattern of ``Grade0.save_lab_info()``, so a reader never sees a partial file.
    In both modes *mode* is applied with ``fchmod`` when given, and *owner* (``(uid, gid)``,
    ``-1`` to leave one unchanged) with ``fchown`` when given and the process runs as root
    (skipped silently otherwise)."""
    path = Path(path)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not atomic:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
            _apply_file_attributes(f.fileno(), mode, owner)
        return
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f'.{path.name}.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            _apply_file_attributes(f.fileno(), mode, owner)
        os.replace(temp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def _apply_file_attributes(fd: int, mode: int | None, owner: tuple[int, int] | None) -> None:
    if mode is not None:
        os.fchmod(fd, mode)
    if owner is not None and os.geteuid() == 0:
        os.fchown(fd, *owner)


def session_identity() -> dict:
    """The identity keys of the answers file for the desktop session running the GUI:
    ``params.hostname_keyword`` (``socket.gethostname()``), ``params.login_keyword``
    (``getpass.getuser()``), ``params.fullname_keyword`` (the first GECOS field of the account,
    control characters and commas removed, ``''`` for an unknown account) and, with
    ``params.email_in_gecos_last_field``, ``params.email_keyword`` (the last GECOS field).

    The web agent has no session: it passes the LDAP identity or the pseudonym of the browser
    user to :func:`with_metadata` instead."""
    login = getpass.getuser()
    try:
        gecos = pwd.getpwnam(login).pw_gecos
    except Exception:
        gecos = ''
    fields = gecos.split(',') if gecos else ['']
    identity = {
        params.hostname_keyword: socket.gethostname(),
        params.login_keyword: login,
        params.fullname_keyword: re.sub(_FULLNAME_UNWANTED, '', fields[0]).strip(),
    }
    if params.email_in_gecos_last_field:
        identity[params.email_keyword] = re.sub(_CONTROL_CHARS, '', fields[-1]).strip()
    return identity
