"""The archive files of the evaluations on the portal host (``[archives] directory`` of
``web.toml``): the *Archive file* view of the Archives page, what ``sre cat`` shows of an archive
(the commands run and their outputs, the answers, the data of the lab, the saved files).

The archives table names an archive by its file name only, and the files may be moved inside the
directory at any time (a nightly rotation renames ``current/<machine>/`` to ``YYYY-MM-DD/``): a
file is **looked up by name, at any depth, at each request**, and no path is ever stored.

``ArchiveFiles`` is the lookup, synchronous and thread-safe.  It keeps one summary per directory
(not per file: a site writes 10 000 to 20 000 archives a day): the smallest and the greatest
archive name directly inside, and the sub-directories.  A name is probed (one ``lstat``) in the
directories whose range holds it and in the most recently modified ones, so a file written
seconds ago is found without reading any directory.  On a miss the tree is read again, each
known directory checked with one ``fstat`` and listed only when it changed, and the probe runs
again: that is what finds a renamed directory or a file moved alone.

Nothing here comes from ``SRE`` (the portal installs alone): the reader and the fields of ``sre
cat`` are written again, ``tests/test_web_archive_files.py`` compares them with the command's.
``zstandard`` and ``msgpack`` are imported when first needed (``import_codecs``)."""
import asyncio
import collections
import errno
import heapq
import json
import logging
import math
import os
import re
import stat
import threading
import time
import urllib.parse
from dataclasses import dataclass

from ..config import ConfigError

log = logging.getLogger('sreweb.portal')

# the name of an archive (``params.get_archive_name``: the 14 digits of the time, the running lab
# name): one path component, never ``..``.  The name comes from the archives table, filled with
# what the agents sent: checked before any system call
NAME_RE = re.compile(r'[0-9]{14}_[^/\x00-\x1f\x7f]+\.zst', re.ASCII)
MAX_NAME_BYTES = 255

MAX_DEPTH = 6                   # sub-directory levels read under the root
MAX_DIRS = 200_000              # directories kept (about 400 bytes each)
HOT_DIRS = 256                  # the most recently modified directories, probed for every name
MTIME_SETTLE = 3.0              # s a directory time must have been seen unchanged before a listing is trusted
OLD_MTIME = 3600.0              # ... or the time is this old on the wall clock when it is listed
REFRESH_COST_FACTOR = 5         # the next reading of the tree waits this many times the last one's duration
REFRESH_MAX_INTERVAL = 120.0    # ... at most
REFRESH_WAIT = 2.0              # s a lookup waits for the next reading to be allowed, rather than answer "later"
REFRESH_LOCK_WAIT = 15.0        # s a lookup waits for a reading of the tree in progress

MAX_FILE_SIZE = 64 << 20        # bytes of an archive file
MAX_ARCHIVE_SIZE = 64 << 20     # bytes once decompressed (params.archive_max_size of the agents)
ZSTD_WINDOW_MAX = 1 << 25
MAX_OUTPUT_CHARS = 256 << 10    # characters of one command output in the view
MAX_OUTPUTS_CHARS = 8 << 20     # ... and of all of them
MAX_SAVED_NAME = 255            # characters of the name of a saved file asked for

SLOTS = 2                       # archive files read at a time
SLOT_WAIT = 10.0                # s a request waits for a slot
TIMEOUT = 30.0                  # s a request waits for its file (an NFS mount that hangs)
RETRY_AFTER = 5

FOUND = 'found'
MISSING = 'missing'             # not in the directory, read since the lookup began
PENDING = 'pending'             # not found in what is known; the directory may not be read again yet
DENIED = 'denied'               # found, not readable by the portal
UNSURE = 'unsure'               # not found, but a part of the directory could not be read
UNAVAILABLE = 'unavailable'     # the directory itself cannot be read
BUSY = 'busy'                   # the directory is being read

_NOT_THERE = (errno.ENOENT, errno.ENOTDIR, errno.ELOOP)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

# the keys of an archive (params.*_keyword of SRE, which the portal does not import)
RUNNING_LAB_NAME = 'running_lab_name'
EVAL_DATE = 'eval_date'
CONTAINER_ENGINE = 'container_engine'      # the engine of the evaluated project; missing in an older archive
LOGIN = 'login'
HOSTNAME = 'hostname'
EXAM_JSON = 'exam_json'


class ArchiveFileError(Exception):
    """What a request about an archive file answers when it cannot be served."""

    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


class ArchiveTooBig(ValueError):
    pass


def import_codecs() -> tuple:
    """``(zstandard, msgpack)``, or ``ConfigError`` naming the packages (checked when a directory
    is configured, like the database driver)."""
    try:
        import msgpack
        import zstandard
    except ImportError:
        raise ConfigError("archives.directory: the zstandard and msgpack libraries are not installed "
                          "(python3-zstandard and python3-msgpack, or `pip install zstandard msgpack` "
                          "in the venv)") from None
    return zstandard, msgpack


def valid_name(name) -> bool:
    """Whether *name* is the file name of an archive: a single path component."""
    return (isinstance(name, str) and NAME_RE.fullmatch(name) is not None
            and len(name.encode('utf-8', 'surrogatepass')) <= MAX_NAME_BYTES)


def _reason(error: OSError) -> str:
    return error.strerror or errno.errorcode.get(error.errno, str(error))


@dataclass(frozen=True, slots=True)
class DirInfo:
    """What is kept of one directory.  ``stamp`` is ``(st_dev, st_ino, st_mtime_ns)`` read on the
    descriptor before its listing: an entry added, removed or renamed changes the time."""
    path: str                   # relative to the root, '' = the root
    stamp: tuple
    lo: str = ''                # smallest / greatest archive name directly inside ('' = none)
    hi: str = ''
    files: int = 0              # archive names directly inside
    subdirs: tuple = ()
    seen: float = 0.0           # monotonic clock: this stamp first seen
    settled: bool = False       # the listing was taken while the stamp was known to be stable
    error: str = ''             # why it could not be opened or listed ('' = read)


@dataclass(frozen=True, slots=True)
class Location:
    """The outcome of a lookup."""
    status: str
    name: str
    directory: str = ''         # FOUND / DENIED: relative to the root, '' = the root itself
    size: int = 0
    mtime: float = 0.0
    detail: str = ''            # what could not be read
    checked_age: float = 0.0    # MISSING / PENDING: seconds since the directory was last read
    retry_after: float = 0.0    # PENDING: seconds until it may be read again


class ArchiveFiles:
    """The archive files under *root*, found by name.  Synchronous and thread-safe; the system
    calls may block (NFS): never called from the event loop."""

    def __init__(self, root: str, *, clock=time.monotonic, wall=time.time, max_depth: int = MAX_DEPTH,
                 max_dirs: int = MAX_DIRS, hot_dirs: int = HOT_DIRS, settle: float = MTIME_SETTLE,
                 lock_wait: float = REFRESH_LOCK_WAIT, refresh_wait: float = REFRESH_WAIT, sleep=None):
        self.root = root
        self.max_depth = max_depth
        self.max_dirs = max_dirs
        self.hot_dirs = hot_dirs
        self.settle = settle
        self.lock_wait = lock_wait
        self.refresh_wait = refresh_wait
        self._clock = clock
        self._wall = wall
        self._lock = threading.Lock()               # the fields below, replaced together by a reading
        self._refresh_lock = threading.Lock()       # one reading of the tree at a time
        self._cancel = threading.Event()
        self._sleep = sleep if sleep is not None else self._cancel.wait
        self._dirs: dict = {}                       # relative path → DirInfo
        self._root_error = ''
        self._unread: tuple = ()                    # ((path, reason), ...): directories not read
        self._capped = ''                           # why a part of the tree was left unread ('' = all read)
        # the readings are numbered as they start (a clock may give two of them the same time):
        # a lookup that noted `_seq` when it began was served by any reading of a higher number
        self._seq = 0                               # the number of the last reading started
        self._done = 0                              # the number of the last reading completed
        self._ended: float | None = None            # the last reading completed: its end, its duration
        self._duration = 0.0
        self.stats = collections.Counter()          # probes, checks, listings, refreshes (the tests)

    # -- reading the tree --------------------------------------------------------------------

    def cancel(self):
        """Stops a reading in progress (the portal stops)."""
        self._cancel.set()

    def refresh(self) -> dict:
        """Reads the tree now (the start of the portal, the tests); ``status()``."""
        with self._refresh_lock:
            self._refresh_locked()
        return self.status()

    def _refresh_for(self, seq: int) -> float | None:
        """Reads the tree again for a lookup that noted ``_seq`` = *seq* when it began, unless
        it was read since.  ``0``: what is known was read after the lookup began (a file not
        found then is not there); a number of seconds: the tree was read too recently for what
        a reading costs (files asked again and again after a purge must not hammer NFS) and may
        be read again after that long, a wait of at most ``refresh_wait`` being made here;
        ``None``: another thread has been reading the tree for more than ``lock_wait`` seconds."""
        if not self._refresh_lock.acquire(timeout=self.lock_wait):
            return None
        try:
            if self._done > seq:
                return 0.0          # read since this lookup began, by a lookup it waited for
            if self._ended is not None:
                allowed = self._ended + min(REFRESH_COST_FACTOR * self._duration, REFRESH_MAX_INTERVAL)
                left = allowed - self._clock()
                if left > self.refresh_wait:
                    return left
                if left > 0:
                    self._sleep(left)
            self._refresh_locked()
            return 0.0
        finally:
            self._refresh_lock.release()

    def _refresh_locked(self):
        self._seq += 1
        number = self._seq
        started = self._clock()
        old = self._dirs
        new: dict = {}
        unread: list = []
        capped = ['']
        root_error = ''
        try:
            fd = os.open(self.root, _DIR_FLAGS)         # the root may be a symbolic link, nothing under it
        except OSError as e:
            root_error = f"{self.root}: {_reason(e)}"
        else:
            try:
                self._scan(fd, '', 0, old, new, unread, capped)
            except OSError as e:
                root_error = f"{self.root}: {_reason(e)}"
            finally:
                os.close(fd)
        if self._cancel.is_set():
            return
        ended = self._clock()
        with self._lock:
            self._dirs = new
            self._root_error = root_error
            self._unread = tuple(unread)
            self._capped = capped[0]
            self._ended, self._duration = ended, ended - started
            self._done = number
        self.stats['refreshes'] += 1

    def _scan(self, fd: int, rel: str, depth: int, old: dict, new: dict, unread: list, capped: list):
        """Summarises the directory open on *fd* and those under it."""
        st = os.fstat(fd)
        self.stats['checks'] += 1
        stamp = (st.st_dev, st.st_ino, st.st_mtime_ns)
        prev = old.get(rel)
        same = prev is not None and prev.stamp == stamp and not prev.error
        if same and prev.settled:
            info = prev             # nothing was added, removed or renamed in it since its listing
        else:
            now = self._clock()
            seen = prev.seen if same else now
            # a listing taken in the second the directory changed may miss an entry added in
            # that same second with the same time (coarse times): trusted only when the time was
            # already old, on this clock or on the wall
            settled = now - seen >= self.settle or self._wall() - st.st_mtime >= OLD_MTIME
            try:
                lo, hi, files, subdirs = self._list(fd)
            except OSError as e:
                info = DirInfo(rel, stamp, seen=seen, error=_reason(e))
            else:
                info = DirInfo(rel, stamp, lo, hi, files, subdirs, seen, settled)
        new[rel] = info
        if info.error:
            unread.append((rel, info.error))
        if depth >= self.max_depth:
            if info.subdirs:
                capped[0] = f"the directories more than {self.max_depth} levels deep are not read"
            return
        for sub in info.subdirs:
            if self._cancel.is_set():
                return
            if len(new) >= self.max_dirs:
                capped[0] = f"more than {self.max_dirs} directories: not all were read"
                return
            child = f"{rel}/{sub}" if rel else sub
            try:
                child_fd = os.open(sub, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as e:
                if e.errno not in _NOT_THERE:           # else gone, or a symbolic link now
                    new[child] = DirInfo(child, (0, 0, 0), error=_reason(e))
                    unread.append((child, _reason(e)))
                continue
            try:
                self._scan(child_fd, child, depth + 1, old, new, unread, capped)
            except OSError as e:                        # its fstat (a stale NFS handle)
                new[child] = DirInfo(child, (0, 0, 0), error=_reason(e))
                unread.append((child, _reason(e)))
            finally:
                os.close(child_fd)

    def _list(self, fd: int) -> tuple:
        self.stats['listings'] += 1
        lo = hi = ''
        files = 0
        subdirs = []
        with os.scandir(fd) as entries:
            for entry in entries:
                name = entry.name
                if name.startswith('.'):
                    continue
                if NAME_RE.fullmatch(name):
                    files += 1
                    if not lo or name < lo:
                        lo = name
                    if name > hi:
                        hi = name
                elif name != 'lost+found' and entry.is_dir(follow_symlinks=False):
                    subdirs.append(name)
        return lo, hi, files, tuple(sorted(subdirs))

    # -- looking a name up -------------------------------------------------------------------

    def _candidates(self, dirs: dict, name: str) -> list:
        """Where *name* may be: the directories whose range holds it, then the most recently
        modified ones (a file written after their listing is above their range)."""
        infos = [d for d in dirs.values() if not d.error]
        in_range = sorted((d for d in infos if d.lo and d.lo <= name <= d.hi), key=lambda d: -d.stamp[2])
        hot = heapq.nlargest(self.hot_dirs, infos, key=lambda d: d.stamp[2])
        seen = set()
        return [d for d in in_range + hot if not (d.path in seen or seen.add(d.path))]

    def _open_checked(self, rel: str, name: str) -> tuple:
        """``(fd, stat)`` of the regular file *name* of the directory *rel*, every component
        opened from the root without following a symbolic link: a directory replaced by a link
        after its listing leads nowhere."""
        fd = os.open(self.root, _DIR_FLAGS)
        try:
            for part in rel.split('/') if rel else ():
                child = os.open(part, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            file_fd = os.open(name, _FILE_FLAGS, dir_fd=fd)
        finally:
            os.close(fd)
        try:
            st = os.fstat(file_fd)
            if not stat.S_ISREG(st.st_mode):
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), name)
        except BaseException:
            os.close(file_fd)
            raise
        return file_fd, st

    def _probe(self, name: str) -> tuple:
        """``(Location, fd or None)`` from what is known of the tree."""
        with self._lock:
            dirs, root_error, unread, capped, ended = \
                self._dirs, self._root_error, self._unread, self._capped, self._ended
        troubles = []               # (path, reason): where the name could not be looked for
        denied = None
        for info in self._candidates(dirs, name):
            path = os.path.join(self.root, info.path, name)
            self.stats['probes'] += 1
            try:
                found = os.lstat(path)
            except OSError as e:
                if e.errno not in _NOT_THERE:
                    troubles.append((info.path, _reason(e)))
                continue
            if not stat.S_ISREG(found.st_mode):
                continue            # a symbolic link, a directory, a FIFO named like an archive
            try:
                fd, st = self._open_checked(info.path, name)
            except OSError as e:
                if e.errno in (errno.EACCES, errno.EPERM):
                    denied = denied or Location(DENIED, name, info.path, found.st_size, found.st_mtime,
                                                detail=_reason(e))
                elif e.errno not in _NOT_THERE:     # else moved meanwhile
                    troubles.append((info.path, _reason(e)))
                continue
            return Location(FOUND, name, info.path, st.st_size, st.st_mtime), fd
        if denied is not None:
            return denied, None
        if root_error:
            return Location(UNAVAILABLE, name, detail=root_error), None
        if ended is None:
            return Location(UNAVAILABLE, name, detail=f"{self.root}: not read yet"), None
        troubles = troubles + list(unread)
        if troubles:
            path, reason = troubles[0]
            count = f"{len(troubles)} director{'y' if len(troubles) == 1 else 'ies'}"
            return Location(UNSURE, name, detail=f"{count} cannot be read (e.g. {path or '.'}: {reason})"), None
        if capped:
            return Location(UNSURE, name, detail=capped), None
        if not any(d.files for d in dirs.values()):
            return Location(UNAVAILABLE, name, detail=f"{self.root}: no archive file in it (not mounted?)"), None
        return Location(MISSING, name, checked_age=max(0.0, self._clock() - ended)), None

    def open(self, name: str) -> tuple:
        """``(Location, fd)``: the archive file *name* open for reading when its status is
        ``FOUND`` (the caller closes it), else ``None`` and why."""
        if not valid_name(name):
            return Location(MISSING, str(name)[:MAX_NAME_BYTES], detail="not the name of an archive"), None
        seq, done = self._seq, self._done
        location, fd = self._probe(name)
        if fd is not None:
            return location, fd
        left = self._refresh_for(seq)
        if left is None:
            return Location(BUSY, name), None
        if self._done != done:          # the tree was read meanwhile, here or by another lookup
            location, fd = self._probe(name)
        if fd is None and left > 0 and location.status == MISSING:
            # the file may have been moved since the last reading: never "not there" on old news
            location = Location(PENDING, name, checked_age=location.checked_age, retry_after=left)
        return location, fd

    def locate(self, name: str) -> Location:
        location, fd = self.open(name)
        if fd is not None:
            os.close(fd)
        return location

    def status(self) -> dict:
        with self._lock:
            dirs = self._dirs
            return {'root': self.root, 'directories': len(dirs), 'files': sum(d.files for d in dirs.values()),
                    'unread': len(self._unread), 'capped': bool(self._capped), 'error': self._root_error,
                    'read': self._ended is not None, 'duration': self._duration}


# -- reading an archive ------------------------------------------------------------------------

def read_bytes_fd(fd: int, max_size: int = MAX_FILE_SIZE) -> bytes:
    """The bytes of the file open on *fd*, ``ArchiveTooBig`` above *max_size*."""
    with os.fdopen(fd, 'rb', closefd=False) as f:
        data = f.read(max_size + 1)
    if len(data) > max_size:
        raise ArchiveTooBig(f"archive file bigger than {max_size} bytes")
    return data


def read_archive_fd(fd: int, max_size: int = MAX_ARCHIVE_SIZE) -> dict:
    """The dict of the archive open on *fd*, read as ``sre cat`` reads it (arrays as tuples: the
    keys of ``tests`` are ``(machine, step)`` and ``(command, timeout)``).  At most *max_size*
    decompressed bytes: a zstd bomb is an ``ArchiveTooBig``, never the portal's memory."""
    zstandard, msgpack = import_codecs()
    with os.fdopen(fd, 'rb', closefd=False) as f:
        if os.fstat(fd).st_size > MAX_FILE_SIZE:
            raise ArchiveTooBig(f"archive file bigger than {MAX_FILE_SIZE} bytes")
        with zstandard.ZstdDecompressor(max_window_size=ZSTD_WINDOW_MAX).stream_reader(f) as reader:
            data = reader.read(max_size + 1)
    if len(data) > max_size:
        raise ArchiveTooBig(f"archive bigger than {max_size} bytes once decompressed")
    raw = msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)
    if not isinstance(raw, dict):
        raise ValueError("not an archive")
    return raw


def _plain(value):
    """*value* as JSON can carry it (tuples as lists, bytes decoded, any key a string)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {key if isinstance(key, str) else str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode('utf-8', errors='replace')
    return str(value)


def _pair(value, default) -> tuple:
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        return value[0], value[1]
    return str(value), default


def _tests(tests, budget: list, max_output: int) -> list:
    """The ``tests`` of an archive (``{(machine, step): {(command, timeout): (output, code)}}``)
    as ``sre cat`` lists them: one entry per machine and step, in that order, the commands in
    the order they ran.  The outputs are cut at *max_output* characters, and at what is left of
    *budget* for the whole archive (``truncated`` + ``length``)."""
    if not isinstance(tests, dict):
        return []
    items = list(tests.items())
    try:
        items.sort(key=lambda item: (item[0][0], item[0][1]))
    except Exception:
        pass
    result = []
    for outer, commands in items:
        machine, step = _pair(outer, 0)
        entries = []
        for inner, value in (commands.items() if isinstance(commands, dict) else ()):
            command, timeout = _pair(inner, 0)
            output, code = _pair(value, 0)
            entry = {'command': _plain(command), 'timeout': _plain(timeout), 'code': _plain(code)}
            output = _plain(output)
            if isinstance(output, str):
                kept = max(0, min(max_output, budget[0]))
                if len(output) > kept:
                    entry['truncated'] = True
                    entry['length'] = len(output)
                    output = output[:kept]
                budget[0] -= len(output)
            entry['output'] = output
            entries.append(entry)
        result.append({'machine': _plain(machine), 'step': _plain(step), 'commands': entries})
    return result


def _errors(entries) -> list:
    result = []
    for entry in entries if isinstance(entries, (list, tuple)) else ():
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            result.append({'category': str(entry[0]), 'text': _plain(entry[1])})
        else:
            result.append({'category': 'ERROR', 'text': _plain(entry)})
    return result


def _file_size(content) -> int:
    if isinstance(content, (bytes, bytearray)):
        return len(content)
    return len(str(content).encode('utf-8', errors='replace'))


def archive_view(raw: dict, *, max_output: int = MAX_OUTPUT_CHARS, max_outputs: int = MAX_OUTPUTS_CHARS) -> dict:
    """What ``sre cat --json`` prints of an archive (its ``data``, ``tests``, ``errors``,
    ``answers`` and ``grades`` sections, key for key), with ``files`` as ``[{name, size}]``
    (the contents are downloaded one by one), the long outputs cut, and the text of an error
    that has translations left as its dict (the page resolves it in its language; ``sre cat``
    prints the dict as a string)."""
    answers = raw.get('answers')
    answers = answers if isinstance(answers, dict) else {}
    try:
        data = json.loads(raw['data_json'])
        data = data.get('data', data)
    except Exception:
        data = str(raw.get('data_json', '(missing)'))
    files = raw.get('files')
    files = files if isinstance(files, dict) else {}
    total = raw.get('total_grade', 0)
    return {
        'data': _plain(data),
        'tests': _tests(raw.get('tests', {}), [max_outputs], max_output),
        'errors': _errors(raw.get('errors', ())),
        'answers': _plain(answers),
        'grades': {
            RUNNING_LAB_NAME: _plain(raw.get(RUNNING_LAB_NAME, '')),
            EVAL_DATE: _plain(raw.get(EVAL_DATE)),
            CONTAINER_ENGINE: _plain(raw.get(CONTAINER_ENGINE)),
            LOGIN: _plain(answers.get(LOGIN, '')),
            HOSTNAME: _plain(answers.get(HOSTNAME, '')),
            'grade_list': _plain([dict(e) for e in raw.get('grade_list', ()) if isinstance(e, dict)]),
            'grade_parts': _plain([dict(p) for p in raw.get('grade_parts', ()) if isinstance(p, dict)]),
            'total_grade_self_eval': _plain(raw.get('total_grade_self_eval', total)),
            'total_max_self_eval': _plain(raw.get('total_max_self_eval', raw.get('total_max', 0))),
            'mark_self_eval': _plain(raw.get('mark_self_eval', raw.get('mark'))),
            'total_grade_exo_eval': _plain(raw.get('total_grade_exo_eval', total)),
            'total_max_exo_eval': _plain(raw.get('total_max_exo_eval', raw.get('total_max', 0))),
            'mark_exo_eval': _plain(raw.get('mark_exo_eval', raw.get('mark'))),
            'maximum_mark': _plain(raw.get('maximum_mark')),
            EXAM_JSON: _plain(raw.get(EXAM_JSON)),
        },
        'files': [{'name': str(name), 'size': _file_size(content)} for name, content in files.items()],
    }


def attachment(name: str) -> str:
    """The ``Content-Disposition`` of a download named *name* (an archive, a saved file): a
    plain ASCII name, and the real one in the RFC 5987 form."""
    plain = re.sub(r'[^A-Za-z0-9._@+-]', '_', name)[:MAX_NAME_BYTES] or 'file'
    return f"attachment; filename=\"{plain}\"; filename*=UTF-8''{urllib.parse.quote(name, safe='')}"


def saved_file(raw: dict, name: str) -> bytes | None:
    """The content of the file *name* saved in the archive (``files``), None when it has none."""
    files = raw.get('files')
    if not isinstance(files, dict) or name not in files:
        return None
    content = files[name]
    return bytes(content) if isinstance(content, (bytes, bytearray)) else str(content).encode('utf-8', errors='replace')


# -- the asyncio side --------------------------------------------------------------------------

class ArchiveFileStore:
    """The archive files for the routes.  Every lookup and read runs in a thread of its own,
    ``SLOTS`` at a time, and a slot is given back when its thread ends, not when the request
    gives up: a mount that hangs holds these slots and nothing else of the portal (neither the
    queries of the database nor the reports)."""

    def __init__(self, root: str, *, files: ArchiveFiles | None = None, slots: int = SLOTS,
                 wait: float = SLOT_WAIT, timeout: float = TIMEOUT):
        import_codecs()
        self.root = root
        self.files = files if files is not None else ArchiveFiles(root)
        self.wait = wait
        self.timeout = timeout
        self._slots = asyncio.Semaphore(slots)

    def describe(self) -> str:
        return f"{self.root} (looked up by name at any depth)"

    def start(self):
        """Reads the tree once in the background, so that the first request finds it read."""
        threading.Thread(target=self._first_reading, daemon=True, name='archive-files').start()

    def _first_reading(self):
        try:
            status = self.files.refresh()
        except Exception:
            log.exception("archive files: the reading of %s failed", self.root)
            return
        if status['error']:
            log.warning("archive files: %s (looked for again at each request)", status['error'])
        else:
            log.info("archive files: %d archive(s) in %d directories of %s, read in %.1f s%s",
                     status['files'], status['directories'], self.root, status['duration'],
                     f"; {status['unread']} directories cannot be read" if status['unread'] else '')

    async def stop(self):
        self.files.cancel()

    async def _call(self, fn, *args):
        try:
            await asyncio.wait_for(self._slots.acquire(), self.wait)
        except asyncio.TimeoutError:
            raise ArchiveFileError(503, "other archive files are being read, try again in a moment",
                                   RETRY_AFTER) from None
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        future.add_done_callback(lambda f: f.cancelled() or f.exception())     # an outcome nobody waits for

        def done(outcome, error):
            self._slots.release()
            if future.done():
                return
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(outcome)

        def run():
            try:
                outcome, error = fn(*args), None
            except Exception as e:
                outcome, error = None, e
            try:
                loop.call_soon_threadsafe(done, outcome, error)
            except RuntimeError:
                pass        # the loop is closed: the portal stopped

        threading.Thread(target=run, daemon=True, name='archive-file').start()
        try:
            return await asyncio.wait_for(asyncio.shield(future), self.timeout)
        except asyncio.TimeoutError:
            raise ArchiveFileError(503, "the archives directory does not answer", RETRY_AFTER) from None

    @staticmethod
    def _refusal(location: Location) -> ArchiveFileError:
        if location.status == MISSING:
            if location.detail:
                return ArchiveFileError(404, f"{location.name}: {location.detail}")
            return ArchiveFileError(404, "the archive file is not in the archives directory")
        if location.status == PENDING:
            wait = max(1, math.ceil(location.retry_after))
            return ArchiveFileError(503, f"the archive file was not found so far: the archives directory, read "
                                         f"{round(location.checked_age)} s ago, is read again in {wait} s", wait)
        if location.status == DENIED:
            where = f"{location.directory}/{location.name}" if location.directory else location.name
            return ArchiveFileError(409, f"the portal cannot read {where}: {location.detail} "
                                         f"(the archives are written for their owner only)")
        if location.status == UNSURE:
            return ArchiveFileError(409, f"the archive file was not found, and {location.detail}")
        if location.status == BUSY:
            return ArchiveFileError(503, "the archives directory is being read, try again in a moment", RETRY_AFTER)
        return ArchiveFileError(503, f"the archives directory cannot be read: {location.detail}", RETRY_AFTER)

    def _opened(self, name: str) -> tuple:
        location, fd = self.files.open(name)
        if fd is None:
            raise self._refusal(location)
        return location, fd

    def _load(self, name: str) -> tuple:
        location, fd = self._opened(name)
        try:
            return location, read_archive_fd(fd)
        except ArchiveTooBig as e:
            raise ArchiveFileError(413, str(e)) from None
        except Exception as e:
            log.warning("archive files: %r of %s cannot be decoded: %s", name, location.directory or '.', e)
            raise ArchiveFileError(422, "the archive file cannot be decoded") from None
        finally:
            os.close(fd)

    def _view(self, name: str, rln: str) -> dict:
        location, raw = self._load(name)
        view = archive_view(raw)
        view.update(archive=name, directory=location.directory, size=location.size, mtime=location.mtime,
                    mismatch=bool(rln) and raw.get(RUNNING_LAB_NAME) != rln)
        return view

    def _raw(self, name: str) -> bytes:
        _location, fd = self._opened(name)
        try:
            return read_bytes_fd(fd)
        except ArchiveTooBig as e:
            raise ArchiveFileError(413, str(e)) from None
        except OSError as e:
            raise ArchiveFileError(503, f"the archive file cannot be read: {_reason(e)}", RETRY_AFTER) from None
        finally:
            os.close(fd)

    def _saved(self, name: str, file: str) -> bytes:
        _location, raw = self._load(name)
        content = saved_file(raw, file)
        if content is None:
            raise ArchiveFileError(404, "no such file in the archive")
        return content

    async def view(self, name: str, rln: str = '') -> dict:
        """The content of the archive file *name* (``archive_view``) with where it was found
        (``directory``, relative), its ``size`` and ``mtime``, and ``mismatch`` when its running
        lab name is not *rln* (a file of that name written by something else)."""
        return await self._call(self._view, name, rln)

    async def raw(self, name: str) -> bytes:
        """The archive file itself."""
        return await self._call(self._raw, name)

    async def saved(self, name: str, file: str) -> bytes:
        """One of the files saved in the archive."""
        return await self._call(self._saved, name, file)
