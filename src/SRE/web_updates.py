"""The re-evaluations queued for the web portal (``sre re-eval --update-web``).

The portal keeps one row per evaluation archive, taken once from the agent of the pool host
and known by the file name of the archive; a re-graded archive never reaches it by itself.
``sre re-eval --update-web`` therefore leaves, for each archive it re-grades, the record of the
new results (``archive_summary.archive_record``, under the *original* archive name) in a spool
directory of the host, ``params.web_updates_dir``: one ``<archive name>.json`` per pending
update, a later re-evaluation of the same archive replacing the earlier one.  The web agent of
the host serves the spool to the portal (:func:`pending`), which replaces the rows it holds and
tells which entries it settled (:func:`remove`).

The spool decides grades in the database, and its records name students: the directory is
0700, the entries 0600, both owned by the sre user (``sre`` run by root ends as that user).
The reader — the agent, root — trusts nothing else: a directory that is a link, owned by
somebody else or writable by others is not read at all, and an entry that is not a regular file
of a trusted owner holding the record of its own name is removed.  An entry the portal never
took (the evaluation is not in its table, or nothing collects from this host) is dropped after
``params.web_updates_max_age``: by the agent when the portal asks for the queue, and by the
next ``sre re-eval --update-web`` (:func:`expire`).

Pure: the standard library and ``params`` only; nothing is logged here, :func:`pending` gives
back what it removed.
"""
import json
import os
import re
import stat
import tempfile
import time

from . import params


class _Refused(Exception):
    """An entry of the spool that is not to be served: the reason."""


def trusted_uids() -> set[int]:
    """The owners the spool and its entries may have: root, ``params.sre_uid`` (``sre`` writes
    them as the sre user) and the reader itself (the tests write them as the user running
    them), as ``answers.trusted_cheat_uids()``."""
    return {0, params.sre_uid, os.geteuid()}


def is_archive_name(name) -> bool:
    """Whether *name* is the file name of an archive (``params.get_archive_name``), without any
    directory part (the ``.+`` of the pattern would take one)."""
    return (isinstance(name, str) and os.path.basename(name) == name
            and re.fullmatch(params.archive_name_match_pattern, name) is not None)


def entry_name(archive: str) -> str:
    """The file of the spool holding the update of the archive named *archive*."""
    return archive + params.web_updates_suffix


def _archive_of(name: str) -> str | None:
    """The archive an entry file is named after, ``None`` for any other file of the spool."""
    if not name.endswith(params.web_updates_suffix):
        return None
    archive = name[:-len(params.web_updates_suffix)]
    return archive if is_archive_name(archive) else None


def _token(st: os.stat_result) -> str:
    """What tells one version of an entry from the next (every write replaces the file)."""
    return f"{st.st_ino}-{st.st_mtime_ns}-{st.st_size}"


def directory_problem(directory: str | os.PathLike) -> str | None:
    """Why the spool *directory* is not to be used (``None`` when it is): missing, not a real
    directory (a symbolic link is not followed), owned by somebody else, or writable by other
    users than its owner."""
    try:
        st = os.lstat(directory)
    except FileNotFoundError:
        return "no such directory"
    except OSError as e:
        return e.strerror or type(e).__name__
    if not stat.S_ISDIR(st.st_mode):
        return "not a directory"
    if st.st_uid not in trusted_uids():
        return f"owned by uid {st.st_uid}"
    if st.st_mode & 0o022:
        return "writable by other users"
    return None


def prepare(directory: str | os.PathLike) -> str | None:
    """Make the spool *directory* ready for :func:`queue_update`: created 0700 when missing
    (its parent must exist), then checked (:func:`directory_problem`) and writable.  The
    reason it cannot be used, ``None`` when it can."""
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    except OSError as e:
        return f"cannot create {directory}: {e.strerror or type(e).__name__}"
    problem = directory_problem(directory)
    if problem is not None:
        return f"{directory}: {problem}"
    if not os.access(directory, os.W_OK | os.X_OK):
        return f"{directory}: not writable by this user"
    return None


def queue_update(record: dict, directory: str | os.PathLike) -> str:
    """Leave *record* (``archive_summary.archive_record``, its ``archive`` being the original
    file name) in the spool *directory*, in place of an update of the same archive still
    waiting there; the path written.  Atomic (a temporary file of the directory, mode 0600,
    then ``os.replace``): the agent never reads half an entry.  ``ValueError`` when the record
    names no archive; ``OSError`` when the file cannot be written."""
    archive = record.get(params.archive_keyword)
    if not is_archive_name(archive):
        raise ValueError(f"not the name of an archive: {archive!r}")
    path = os.path.join(directory, entry_name(archive))
    text = json.dumps(record, ensure_ascii=False, separators=(',', ':'), default=str)
    fd, temp_name = tempfile.mkstemp(dir=directory, prefix='.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return path


def _names(directory) -> list:
    try:
        return os.listdir(directory)
    except OSError:
        return []


def pending_count(directory: str | os.PathLike) -> int:
    """How many updates wait in the spool *directory* (0 for one that is not to be used): the
    entry files by their name, none of them opened."""
    if directory_problem(directory) is not None:
        return 0
    return sum(1 for name in _names(directory) if _archive_of(name) is not None)


def _read_entry(path: str, archive: str, now: float) -> tuple:
    """``(token, record)`` of the entry *path* of the archive *archive*, or :class:`_Refused`."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise _Refused(e.strerror or type(e).__name__)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise _Refused("not a regular file")
        if st.st_uid not in trusted_uids():
            raise _Refused(f"owned by uid {st.st_uid}")
        if now - st.st_mtime > params.web_updates_max_age:
            raise _Refused(f"waiting for more than {params.web_updates_max_age} s: the portal does not have "
                           f"this evaluation")
        if st.st_size > params.web_updates_max_size:
            raise _Refused(f"{st.st_size} bytes, above {params.web_updates_max_size}")
        data = f.read(params.web_updates_max_size + 1)
    if len(data) > params.web_updates_max_size:
        raise _Refused(f"above {params.web_updates_max_size} bytes")
    try:
        record = json.loads(data.decode('utf-8'))
    except ValueError:
        raise _Refused("not JSON")
    if not isinstance(record, dict):
        raise _Refused("not a JSON object")
    if record.get(params.archive_keyword) != archive:
        raise _Refused("the record of another archive")
    running_lab_name = record.get(params.running_lab_name_keyword)
    if not isinstance(running_lab_name, str) or not running_lab_name:
        raise _Refused("no running lab name")
    return _token(st), record


def _unlink(path: str) -> bool:
    try:
        os.unlink(path)
    except OSError:
        return False
    return True


def pending(directory: str | os.PathLike, after: str = '', limit: int | None = None,
            now: float | None = None) -> tuple[list, bool, str, list]:
    """``(entries, more, last, dropped)`` of the spool *directory*: the updates of the archives
    named after *after*, in the order of the archive names, at most *limit* of them, each as
    ``{'token': ..., 'record': ...}`` (the token tells that version of the entry:
    :func:`remove` wants it back); *more* tells whether others follow and *last* is the
    greatest archive name looked at (the next *after*).  An entry that is not to be served
    (not a regular file of a trusted owner, too big, not the record of its own name, waiting
    for more than ``params.web_updates_max_age``) is removed, and so is any other file left
    there for that long (a temporary file of an interrupted write): *dropped* lists them as
    ``(file name, reason)``.  Nothing is read from a directory that is not to be used."""
    if directory_problem(directory) is not None:
        return [], False, '', []
    now = time.time() if now is None else now
    entries, dropped, last, more = [], [], '', False
    waiting = []
    for name in _names(directory):
        archive = _archive_of(name)
        path = os.path.join(directory, name)
        if archive is not None:
            waiting.append((archive, path))
            continue
        try:
            stale = now - os.lstat(path).st_mtime > params.web_updates_max_age
        except OSError:
            continue
        if stale and _unlink(path):
            dropped.append((name, "not an update, left there"))
    for archive, path in sorted(waiting):
        if archive <= after:
            continue
        if limit is not None and len(entries) >= limit:
            more = True
            break
        last = archive
        try:
            token, record = _read_entry(path, archive, now)
        except _Refused as e:
            if _unlink(path):
                dropped.append((os.path.basename(path), str(e)))
            continue
        entries.append({'token': token, 'record': record})
    return entries, more, last, dropped


def expire(directory: str | os.PathLike, now: float | None = None) -> list:
    """Remove from the spool *directory* what waits there for more than
    ``params.web_updates_max_age``; the file names removed.  :func:`pending` does it for what
    it looks at; this is for the writer, on a host whose queue nothing reads (no portal
    collecting, an agent that does not know the queue): the next ``sre re-eval --update-web``
    clears what the previous ones left, and can say so."""
    if directory_problem(directory) is not None:
        return []
    now = time.time() if now is None else now
    removed = []
    for name in sorted(_names(directory)):
        path = os.path.join(directory, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode) and now - st.st_mtime > params.web_updates_max_age and _unlink(path):
            removed.append(name)
    return removed


def remove(directory: str | os.PathLike, done) -> int:
    """Remove the entries of the spool *directory* the portal settled: *done* is an iterable
    of ``(archive name, token)`` pairs, and an entry goes only when it still is the version of
    that token (one written again since stays for the next round).  The entries are found by
    listing the directory, never by a path built from a name given by the caller.  How many
    were removed."""
    if directory_problem(directory) is not None:
        return 0
    wanted = {(str(archive), str(token)) for archive, token in done}
    archives = {archive for archive, _ in wanted}
    removed = 0
    for name in _names(directory):
        archive = _archive_of(name)
        if archive is None or archive not in archives:
            continue
        path = os.path.join(directory, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if (archive, _token(st)) in wanted and _unlink(path):
            removed += 1
    return removed
