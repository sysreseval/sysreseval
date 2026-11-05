"""The answers file of a running project: ``answers/answers.json``.

The file holds the student's answers (``{question_hash: answer}``) and the metadata archived with
the grades (identity of the student, language, time of the last change, exam fields). It is
written by the Qt GUI (``sysreseval.view.questions_view.QuestionsView``) on the student's
workstation, and by the web agent on behalf of a browser user; it is read by
``Grade0.load_answers()`` at evaluation time. This module is the Qt-free logic both writers
share: reading and writing the file, the metadata, the exam fields of ``exam.json``, and the
cheat file ``answers/cheat.json`` that ``sre state`` writes for the GUI to merge.

Both writers may be at work on the same project (the student logged in on a pool host opens
their project in a browser too, an instructor helps from the web): each one reads the file
before writing it, puts only the answers it changed on top, and replaces the file atomically
(:func:`save_answers` with ``atomic=True``, which works whatever the owner of the previous
file since the ``answers/`` directory is 0777), then watches the file's :func:`file_signature`
to show what the other wrote.  The read and the write are done under :class:`AnswersLock`, an
advisory lock on the ``answers/`` directory itself, so that two writes at the same moment do
not lose one of them.

The identity is the caller's: the GUI takes it from its desktop session
(:func:`session_identity`), the web agent passes the LDAP account or the pseudonym of the
browser user to :func:`with_metadata`.
"""
import contextlib
import fcntl
import getpass
import json
import os
import pwd
import re
import socket
import stat
import tempfile
import time
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
                  language: str, exam_data: dict | None, now: datetime | None = None,
                  group: str | None = None) -> dict:
    """A copy of *answers* with the metadata of the answers file: the identity keys
    (``hostname``, ``login``, ``fullname``, and ``email`` only when not ``None``: the GUI gives
    it only with ``params.email_in_gecos_last_field``; ``group``, the student group of the
    user, only when not ``None``: the web agent gives it, the GUI never does),
    ``answers_updated_at`` (``params.datetime_to_string`` of *now*, the current time by
    default), ``language`` and the :func:`exam_fields` of *exam_data*. Keys already present
    keep their place."""
    if now is None:
        now = datetime.now()
    data = dict(answers)
    data[params.hostname_keyword] = hostname
    data[params.login_keyword] = login
    data[params.fullname_keyword] = fullname
    if email is not None:
        data[params.email_keyword] = email
    if group is not None:
        data[params.group_keyword] = group
    data[params.sysreseval_answers_updated_at] = params.datetime_to_string(now)
    data[params.language_keyword] = language
    data.update(exam_fields(exam_data, now))
    return data


def merge_cheat(answers: dict, cheat: dict) -> dict:
    """A copy of *answers* with the entries of *cheat* (``{question_hash: answer}``, the cheat
    answers of a state): the cheat values win."""
    return {**answers, **cheat}


class CheatFileRefused(ValueError):
    """What :func:`consume_cheat_file` found at the path is not a cheat file written by
    ``sre state`` (*reason*: a symbolic link, a directory, a FIFO, a file of another user, a
    hard link, a file above ``params.cheat_file_max_size``); *removed* tells whether the entry
    could be removed."""

    def __init__(self, path, reason: str, removed: bool):
        super().__init__(f"{path}: {reason}" + ('' if removed else ' (not removed)'))
        self.path = path
        self.reason = reason
        self.removed = removed


def trusted_cheat_uids() -> set[int]:
    """The owners a cheat file may have: root, ``params.sre_uid`` (``sre state`` writes the
    file as the sre user) and the reader itself (the student's GUI reads its own project;
    the tests write the file as the user running them)."""
    return {0, params.sre_uid, os.geteuid()}


def _cheat_entry_problem(st: os.stat_result) -> str | None:
    """Why the entry *st* (``fstat`` of the opened file, or ``lstat`` of a path that could not
    be opened) is not a cheat file to read: ``None`` when it may be read."""
    if not stat.S_ISREG(st.st_mode):
        if stat.S_ISLNK(st.st_mode):
            kind = 'a symbolic link'
        elif stat.S_ISDIR(st.st_mode):
            kind = 'a directory'
        elif stat.S_ISFIFO(st.st_mode):
            kind = 'a FIFO'
        elif stat.S_ISSOCK(st.st_mode):
            kind = 'a socket'
        else:
            kind = 'not a regular file'
        return kind
    if st.st_nlink > 1:
        return f"a file with {st.st_nlink} links"
    if st.st_uid not in trusted_cheat_uids():
        return f"a file owned by uid {st.st_uid}"
    if st.st_size > params.cheat_file_max_size:
        return f"{st.st_size} bytes, above {params.cheat_file_max_size}"
    return None


def _remove_entry(path: Path) -> bool:
    """Remove the directory entry *path* (a file, a symbolic link, a FIFO: the link itself,
    never a target; an empty directory): whether it is gone."""
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        pass
    try:
        os.rmdir(path)
        return True
    except OSError:
        return not os.path.lexists(path)


def consume_cheat_file(path: str | os.PathLike) -> dict | None:
    """Read and remove the cheat file *path* (``params.cheat_filename(...)``, written by
    ``sre state``): its dict, or ``None`` when the file does not exist.

    The ``answers/`` directory is world-writable (the student's GUI writes there) and the web
    agent reads the file as root: only a regular file with one link, owned by one of
    :func:`trusted_cheat_uids` and at most ``params.cheat_file_max_size`` bytes is read, opened
    with ``O_NOFOLLOW`` (a symbolic link is never followed) and ``O_NONBLOCK`` (a FIFO does not
    block). Anything else found at the path is removed (the entry only, never what a link
    points to) and :class:`CheatFileRefused` raised, with ``removed`` false when the entry
    could not be removed (a non-empty directory).

    The file is removed once its content is read and parsed; a file that cannot be opened or
    one that is not a JSON object raises (``OSError`` / ``ValueError``) and stays in place, so
    that a caller polling the project directory tries again later (``sre state`` truncates the
    file before writing it)."""
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:
        # ELOOP: a symbolic link under O_NOFOLLOW; ENXIO: a socket; EACCES...: judged on lstat
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        reason = _cheat_entry_problem(st)
        if reason is None:
            raise
        raise CheatFileRefused(path, reason, _remove_entry(path)) from None
    try:
        reason = _cheat_entry_problem(os.fstat(fd))
        if reason is None:
            with os.fdopen(fd, 'rb') as f:
                fd = None
                data = f.read(params.cheat_file_max_size + 1)
            if len(data) > params.cheat_file_max_size:
                reason = f"above {params.cheat_file_max_size} bytes"
    finally:
        if fd is not None:
            os.close(fd)
    if reason is not None:
        raise CheatFileRefused(path, reason, _remove_entry(path))
    cheat = json.loads(data.decode('utf-8'))
    if not isinstance(cheat, dict):
        raise ValueError(f"{path}: not a JSON object")
    path.unlink()
    return cheat


def file_signature(path: str | os.PathLike) -> tuple | None:
    """``(inode, mtime in ns, size)`` of the file *path*, ``None`` when it cannot be stat'ed:
    what tells the two writers of the answers file (the GUI and the web agent, see
    :func:`save_answers`) a write of the other from their own, which they know by the signature
    :func:`save_answers` returns."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_mtime_ns, st.st_size)


#: how long a writer waits for the :class:`AnswersLock` before writing without it
ANSWERS_LOCK_TIMEOUT = 1.0


class AnswersLock:
    """The lock the writers of the answers file take around their read-merge-write (the Qt
    GUI as the student, the web agent as root): an advisory ``flock`` on the ``answers/``
    directory itself, which any of them opens read-only whatever its owner, so nothing is
    created and the save files carry no lock file.  Without it two writes within the same
    millisecond (the student typing in the GUI while the instructor types in a browser) would
    each replace the file with the copy they had read, and one answer would be lost.

    Best effort: :meth:`acquire` gives up after its timeout (a writer stopped while holding
    the lock must not freeze the other) and the caller writes anyway; a missing directory
    gives no lock either.  :meth:`try_acquire` is the non-blocking step of a caller waiting
    its own way (the agent's event loop)."""

    POLL = 0.005   # s between two attempts of acquire()

    def __init__(self, path: str | os.PathLike):
        self.directory = Path(path).parent
        self._fd: int | None = None

    def try_acquire(self) -> bool:
        """Take the lock without waiting: ``False`` when another process holds it.  Raises
        ``OSError`` when the directory cannot be opened."""
        if self._fd is None:
            self._fd = os.open(self.directory, os.O_RDONLY)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def acquire(self, timeout: float = ANSWERS_LOCK_TIMEOUT) -> bool:
        """Take the lock, waiting up to *timeout* seconds: ``False`` when it could not be
        (held for longer by another process, or no directory)."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                if self.try_acquire():
                    return True
            except OSError:
                return False
            if time.monotonic() >= deadline:
                return False
            time.sleep(self.POLL)

    def release(self) -> None:
        """Release the lock when held; harmless otherwise."""
        if self._fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None


@contextlib.contextmanager
def answers_lock(path: str | os.PathLike, timeout: float = ANSWERS_LOCK_TIMEOUT):
    """``with answers_lock(path) as locked:`` around a read-merge-write of the answers file
    *path* (:class:`AnswersLock`); *locked* says whether the lock was obtained within
    *timeout* seconds, and the block runs in both cases."""
    lock = AnswersLock(path)
    try:
        yield lock.acquire(timeout)
    finally:
        lock.release()


def save_answers(path: str | os.PathLike, data: dict, *, atomic: bool = False,
                 owner: tuple[int, int] | None = None, mode: int | None = None) -> tuple:
    """Write *data* to the answers file *path* as JSON (``indent=2``, ``ensure_ascii=False``),
    creating the parent directory when missing; errors raise (``OSError``). Returns the
    :func:`file_signature` of the file written.

    Plain: the file is opened and written in place. With ``atomic=True`` (both writers: the web
    agent, whose project is evaluated while it writes, and the GUI, whose file the agent may
    have replaced as root, since ``os.replace`` needs the write permission on the ``answers/``
    directory (0777) only): a temporary file in the directory of *path* (mode 0600 until *mode*
    is applied: pass 0644 so that ``sre eval`` reads it), flushed to disk, then ``os.replace``
    over *path*, the pattern of ``Grade0.save_lab_info()``, so a reader never sees a partial
    file. In both modes *mode* is applied with ``fchmod`` when given, and *owner* (``(uid,
    gid)``, ``-1`` to leave one unchanged) with ``fchown`` when given and the process runs as
    root (skipped silently otherwise)."""
    path = Path(path)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not atomic:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            _apply_file_attributes(f.fileno(), mode, owner)
            return _fd_signature(f.fileno())
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f'.{path.name}.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            _apply_file_attributes(f.fileno(), mode, owner)
            signature = _fd_signature(f.fileno())
        os.replace(temp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    return signature


def _fd_signature(fd: int) -> tuple:
    st = os.fstat(fd)
    return (st.st_ino, st.st_mtime_ns, st.st_size)


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
