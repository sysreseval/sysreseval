"""The store of the saved projects of the web front-end: files on a volume shared by the pool hosts.

``<root>/.sre-saves``            the marker the administrator creates: no marker, no store (a
                                 mount that is missing must not turn into saves on the local disk)
``<root>/<owner>/<id>.sre``      the stream of ``sre save``, mode 0600
``<root>/<owner>/<id>.json``     the sidecar: who saved what, when, shared with whom; written
                                 last, so a save exists when its sidecar does

This module is two things.  Imported (``sreweb.savestore``), it gives the portal and the agent
the names of the sidecar keys and the validators of an owner and of an id.  Run as a program by
the agent, it is the only code that touches the volume: ``python -I -B savestore.py <operation>
'<JSON request>'``, a process per operation under the account that owns the store (``[saves]
user`` of agent.toml, ``sre``), so that the export may squash root and the directories stay
closed to the local users of a pool host.  The result is one JSON object on stdout (the bytes of
the save for ``cat``); a refusal is one JSON object on stderr and the exit status
``EXIT_REFUSED``.  ``put`` reads the save on stdin and never makes it visible: ``commit`` does,
once ``sre save`` is known to have ended well.

Only the standard library, and no import of the package: the program runs isolated (``-I``),
whatever the layout of the install.  Nothing here is trusted from a caller but the root: an owner
and an id are checked against their patterns before any path is built, every file is opened
without following a link, and what a sidecar holds is coerced field by field when it is listed.
"""
import contextlib
import errno
import hashlib
import json
import os
import re
import stat
import sys
import time

VERSION = 1
MARKER = '.sre-saves'
SAVE_SUFFIX = '.sre'
SIDECAR_SUFFIX = '.json'
PART_SUFFIX = '.part'
#: Same as ``SRE.params.save_file_magic`` (checked by tests/test_savestore.py): the first bytes
#: of a save file, followed by one line of JSON, its header.
MAGIC = b'SRESAVE1\n'
MAX_HEADER = 64 << 10

#: A login that may own saves: ``identity.VALID_LOGIN`` and a first character that is a letter
#: or a digit (``.`` and ``..`` are valid logins, and directory names).
OWNER = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$')
#: ``<YYYYmmddHHMMSS>-<8 hexadecimal digits>``: when the save was asked, and a random part.
SAVE_ID = re.compile(r'^[0-9]{14}-[0-9a-f]{8}$')

# The keys of a sidecar, and of a save in every API of the web front-end.
KEY_VERSION = 'version'
KEY_ID = 'id'
KEY_OWNER = 'owner'
KEY_FULLNAME = 'fullname'
KEY_GROUP = 'group'
KEY_LAB = 'lab'
KEY_PROJECT = 'project'
KEY_PROJECT_OWNER = 'project_owner'
KEY_SAVED_AT = 'saved_at'
KEY_SIZE = 'size'
KEY_SHA256 = 'sha256'
KEY_HOST = 'host'
KEY_ARCH = 'arch'
KEY_COMMENT = 'comment'
KEY_SHARED_WITH = 'shared_with'
KEY_EXAM = 'exam'
KEY_INSTRUCTOR_MODE = 'instructor_mode'
KEY_DEBUG_PROJECT = 'debug_project'
KEY_SRE_VERSION = 'sre_version'

MAX_COMMENT = 100
MAX_SHARED_WITH = 64
MAX_GROUP_KEY = 200
#: The longest text kept for each text field of a sidecar.
_TEXT_FIELDS = {KEY_FULLNAME: 200, KEY_GROUP: 64, KEY_LAB: 300, KEY_PROJECT: 400, KEY_PROJECT_OWNER: 64,
                KEY_SAVED_AT: 40, KEY_HOST: 200, KEY_ARCH: 32, KEY_COMMENT: MAX_COMMENT, KEY_SRE_VERSION: 32}
_FLAG_FIELDS = (KEY_EXAM, KEY_INSTRUCTOR_MODE, KEY_DEBUG_PROJECT)
#: What ``update`` may change.
UPDATABLE = (KEY_SHARED_WITH, KEY_COMMENT)

#: Seconds after which what a save that never ended left behind is removed by a listing: a
#: ``.part`` file (a save lasts minutes), a save file without sidecar.
STALE_PART = 24 * 3600
STALE_ORPHAN = 3600
CHUNK = 1 << 20

#: The keys of ``GET /v1/status`` of an agent: whether the host saves and restores projects (its
#: directory is configured and usable), why not, and whether a directory is configured at all
#: (configured and not usable is what an administrator has to hear about: a volume that is not
#: mounted, a marker nobody created).
STATUS_SAVES = 'saves'
STATUS_SAVES_ERROR = 'saves_error'
STATUS_SAVES_CONFIGURED = 'saves_configured'

CODE_QUOTA = 'quota'
CODE_TOO_LARGE = 'too_large'
CODE_NOT_A_SAVE = 'not_a_save'
CODE_UNAVAILABLE = 'unavailable'
CODE_CORRUPTED = 'corrupted'
EXIT_REFUSED = 3

_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')
_SHA256 = re.compile(r'^[0-9a-f]{64}$')
_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


class StoreError(Exception):
    """A refusal: the HTTP status the agent answers, a message, and a code for the cases a
    program tells apart (``CODE_*``)."""

    def __init__(self, status: int, message: str, code: str = ''):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code

    def to_dict(self) -> dict:
        return {'status': self.status, 'error': self.message, 'code': self.code}


# -- names --------------------------------------------------------------------------------------

def valid_owner(owner) -> bool:
    return isinstance(owner, str) and bool(OWNER.match(owner))


def valid_id(save_id) -> bool:
    return isinstance(save_id, str) and bool(SAVE_ID.match(save_id))


def new_id(now: float | None = None) -> str:
    stamp = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time() if now is None else now))
    return f"{stamp}-{os.urandom(4).hex()}"


def clean_text(value, limit: int) -> str:
    """A text as a sidecar keeps it: control characters dropped, trimmed, capped."""
    return _CONTROL.sub('', value if isinstance(value, str) else '').strip()[:limit].strip()


def clean_shared_with(value) -> list:
    """The group keys a save is shared with: texts, each once, in their order, capped."""
    keys = []
    for item in value if isinstance(value, list) else []:
        key = clean_text(item, MAX_GROUP_KEY)
        if key and key not in keys:
            keys.append(key)
    return keys[:MAX_SHARED_WITH]


def clean_entry(raw, owner: str, save_id: str) -> dict:
    """The sidecar *raw* as it is given out: every field of its type, the owner and the id those
    of its path (never what the file says)."""
    raw = raw if isinstance(raw, dict) else {}
    entry = {KEY_VERSION: VERSION, KEY_ID: save_id, KEY_OWNER: owner}
    for key, limit in _TEXT_FIELDS.items():
        entry[key] = clean_text(raw.get(key), limit)
    size = raw.get(KEY_SIZE)
    entry[KEY_SIZE] = size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else 0
    digest = raw.get(KEY_SHA256)
    entry[KEY_SHA256] = digest if isinstance(digest, str) and _SHA256.match(digest) else ''
    entry[KEY_SHARED_WITH] = clean_shared_with(raw.get(KEY_SHARED_WITH))
    for key in _FLAG_FIELDS:
        entry[key] = raw.get(key) is True
    return entry


# -- paths --------------------------------------------------------------------------------------

def _check_names(owner, save_id=None):
    if not valid_owner(owner) or (save_id is not None and not valid_id(save_id)):
        raise StoreError(404, "unknown saved project")


def _real_directory(path: str) -> os.stat_result:
    """*path* is a directory of the account running this, not a link to one."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise StoreError(503, f"{path} is not a directory", CODE_UNAVAILABLE)
    if st.st_uid != os.geteuid():
        raise StoreError(503, f"{path} does not belong to the account of the saved projects", CODE_UNAVAILABLE)
    return st


def _mount(root: str):
    """Open *root* once, so that the volume of an automount point (``x-systemd.automount`` in
    /etc/fstab) is mounted before it is checked.  A ``stat`` or ``lstat`` never triggers an
    automount (Linux adds ``AT_NO_AUTOMOUNT`` to both): on a point not mounted yet it sees the
    placeholder of autofs, owned by root, and the check refused the store, without ever touching
    a path under it (which would have mounted it), on every host where nothing else had touched
    the volume since the boot.  The open of a directory mounts it and waits for the mount.  A
    path that is not a directory, or that this account may not open, is told better by the
    checks that follow; a mount that fails is told here, by its error."""
    try:
        fd = os.open(root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0))
    except (NotADirectoryError, PermissionError):
        return
    os.close(fd)


def check(root: str) -> dict:
    """The store is usable: its marker is there (the volume is mounted), its root belongs to
    this account.  Its free and total space in MiB."""
    try:
        _mount(root)
        _real_directory(root)
        try:
            marker = os.lstat(os.path.join(root, MARKER))
        except FileNotFoundError as e:
            # the directory is there and the marker is not: nothing ever creates it but the
            # administrator, once, so a volume that is mounted lacks it until then
            raise StoreError(503, f"{e.filename}: not found (the volume of the saved projects is not mounted, "
                                  f"or its marker was never created)", CODE_UNAVAILABLE) from None
        if not stat.S_ISREG(marker.st_mode):
            raise StoreError(503, f"{MARKER} is not a file", CODE_UNAVAILABLE)
        if not os.access(root, os.W_OK | os.X_OK):
            raise StoreError(503, "the directory of the saved projects is not writable", CODE_UNAVAILABLE)
        space = os.statvfs(root)
    except FileNotFoundError as e:
        raise StoreError(503, f"{e.filename}: not found (is the volume of the saved projects mounted?)",
                         CODE_UNAVAILABLE) from None
    except OSError as e:
        raise StoreError(503, f"{e.filename or root}: {e.strerror}", CODE_UNAVAILABLE) from None
    return {'free_mb': space.f_bavail * space.f_frsize >> 20, 'total_mb': space.f_blocks * space.f_frsize >> 20}


def _owner_dir(root: str, owner: str, *, create: bool = False) -> str | None:
    """The directory of the saves of *owner*; ``None`` when there is none and *create* is off."""
    path = os.path.join(root, owner)
    if create:
        with contextlib.suppress(FileExistsError):
            os.mkdir(path, 0o700)
    try:
        _real_directory(path)
    except FileNotFoundError:
        return None
    return path


def _paths(root: str, owner: str, save_id: str, *, create: bool = False) -> tuple:
    """``(directory, save file, sidecar)`` of a save; 404 when the owner has no directory."""
    _check_names(owner, save_id)
    directory = _owner_dir(root, owner, create=create)
    if directory is None:
        raise StoreError(404, "unknown saved project")
    return directory, os.path.join(directory, save_id + SAVE_SUFFIX), os.path.join(directory, save_id + SIDECAR_SUFFIX)


def _open(path: str, flags: int, mode: int = 0o600) -> int:
    return os.open(path, flags | _NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), mode)


def _read_json(path: str):
    """The JSON of a small regular file, ``None`` when it is missing or is not one."""
    try:
        fd = _open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    except OSError:
        return None
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        try:
            return json.loads(f.read(1 << 20).decode('utf-8'))
        except ValueError:
            return None


def _write_json(path: str, data: dict):
    """*data* written beside *path* then moved onto it: a reader sees the old file or the new."""
    temporary = path + PART_SUFFIX
    with contextlib.suppress(FileNotFoundError):
        os.unlink(temporary)
    fd = _open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(fd, 'wb') as f:
        f.write(json.dumps(data, ensure_ascii=False, sort_keys=True).encode('utf-8') + b'\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def _sync_directory(path: str):
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


# -- reading ------------------------------------------------------------------------------------

def _sweep(directory: str, names: set, now: float):
    """Remove what a save that never ended left in *directory*: the old ``.part`` files, an old
    save file without sidecar."""
    for name in names:
        path = os.path.join(directory, name)
        if name.endswith(PART_SUFFIX):
            limit = STALE_PART
        elif name.endswith(SAVE_SUFFIX) and name[:-len(SAVE_SUFFIX)] + SIDECAR_SUFFIX not in names:
            limit = STALE_ORPHAN
        else:
            continue
        with contextlib.suppress(OSError):
            if now - os.lstat(path).st_mtime > limit:
                os.unlink(path)


def _list_owner(root: str, owner: str, now: float) -> list:
    directory = _owner_dir(root, owner)
    if directory is None:
        return []
    names = set(os.listdir(directory))
    _sweep(directory, names, now)
    saves = []
    for name in sorted(names):
        save_id = name[:-len(SIDECAR_SUFFIX)]
        if not name.endswith(SIDECAR_SUFFIX) or not valid_id(save_id) or save_id + SAVE_SUFFIX not in names:
            continue
        raw = _read_json(os.path.join(directory, name))
        if raw is not None:
            saves.append(clean_entry(raw, owner, save_id))
    return saves


def list_saves(root: str, owner: str | None = None, now: float | None = None) -> list:
    """The saves of *owner*, or of everybody, the oldest first for each owner."""
    now = time.time() if now is None else now
    if owner is not None:
        _check_names(owner)
        return _list_owner(root, owner, now)
    saves = []
    for name in sorted(os.listdir(root)):
        if valid_owner(name):
            with contextlib.suppress(StoreError, OSError):
                saves.extend(_list_owner(root, name, now))
    return saves


def get(root: str, owner: str, save_id: str) -> dict:
    _, data, sidecar = _paths(root, owner, save_id)
    raw = _read_json(sidecar)
    if raw is None or not os.path.lexists(data):
        raise StoreError(404, "unknown saved project")
    return clean_entry(raw, owner, save_id)


def cat(root: str, owner: str, save_id: str, out) -> int:
    """Write the save to *out*.  The last piece is held back until the whole file matches the
    size and the checksum of its sidecar: a damaged file reaches ``sre restore`` cut short, which
    it refuses, never whole."""
    entry = get(root, owner, save_id)
    _, data, _ = _paths(root, owner, save_id)
    digest = hashlib.sha256()
    size = 0
    held = b''
    with os.fdopen(_open(data, os.O_RDONLY), 'rb') as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if held:
                out.write(held)
            held = chunk
            digest.update(chunk)
            size += len(chunk)
    if size != entry[KEY_SIZE] or (entry[KEY_SHA256] and digest.hexdigest() != entry[KEY_SHA256]):
        raise StoreError(500, "the saved project is damaged", CODE_CORRUPTED)
    out.write(held)
    out.flush()
    return size


# -- writing ------------------------------------------------------------------------------------

def put(root: str, owner: str, save_id: str, stream, max_bytes: int = 0) -> dict:
    """Write the save read from *stream* to its ``.part`` file: nothing lists it until
    :func:`commit`.  The stream must start like a save file; more than *max_bytes* (0 = no
    limit) is refused and what was written removed.  Returns the size, the checksum and the
    header of the save."""
    directory, data, _ = _paths(root, owner, save_id, create=True)
    part = data + PART_SUFFIX
    digest = hashlib.sha256()
    size = 0
    head = b''
    header = None
    fd = _open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(fd, 'wb') as f:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if max_bytes and size > max_bytes:
                    raise StoreError(413, "the project is too large to be saved", CODE_TOO_LARGE)
                if header is None:
                    head += chunk
                    header = _header_of(head)
                digest.update(chunk)
                f.write(chunk)
            if header is None:
                raise StoreError(502, "not a save file", CODE_NOT_A_SAVE)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(part)
        with contextlib.suppress(OSError):
            os.rmdir(directory)                 # empty: the first save of the owner
        raise
    return {KEY_SIZE: size, KEY_SHA256: digest.hexdigest(), 'header': header}


def _header_of(head: bytes) -> dict | None:
    """The header of a save file whose first bytes are *head*; ``None`` while its line is not
    complete.  Refuses what does not start like a save file."""
    if not MAGIC.startswith(head[:len(MAGIC)]):
        raise StoreError(502, "not a save file", CODE_NOT_A_SAVE)
    end = head.find(b'\n', len(MAGIC))
    if end < 0:
        if len(head) > len(MAGIC) + MAX_HEADER:
            raise StoreError(502, "not a save file", CODE_NOT_A_SAVE)
        return None
    try:
        header = json.loads(head[len(MAGIC):end].decode('utf-8'))
    except ValueError:
        header = None
    if not isinstance(header, dict):
        raise StoreError(502, "not a save file", CODE_NOT_A_SAVE)
    return header


def commit(root: str, owner: str, save_id: str, sidecar: dict) -> dict:
    """Make the save written by :func:`put` visible: its file takes its name, then its sidecar
    is written.  The size is the one of the file, whatever *sidecar* says."""
    directory, data, path = _paths(root, owner, save_id)
    part = data + PART_SUFFIX
    try:
        size = os.lstat(part).st_size
    except FileNotFoundError:
        raise StoreError(404, "nothing to commit for this saved project") from None
    entry = clean_entry({**sidecar, KEY_SIZE: size}, owner, save_id)
    os.replace(part, data)
    _write_json(path, entry)
    _sync_directory(directory)
    return entry


def discard(root: str, owner: str, save_id: str) -> dict:
    """Remove what a save that failed wrote; a save that was committed is left alone."""
    _check_names(owner, save_id)
    directory = _owner_dir(root, owner)
    if directory is not None:
        base = os.path.join(directory, save_id)
        with contextlib.suppress(OSError):
            os.unlink(base + SAVE_SUFFIX + PART_SUFFIX)
        with contextlib.suppress(OSError):
            os.unlink(base + SIDECAR_SUFFIX + PART_SUFFIX)
        if not os.path.lexists(base + SIDECAR_SUFFIX):
            with contextlib.suppress(OSError):
                os.unlink(base + SAVE_SUFFIX)
        with contextlib.suppress(OSError):
            os.rmdir(directory)                 # empty: the first save of the owner failed
    return {}


def update(root: str, owner: str, save_id: str, changes: dict) -> dict:
    """Change who a save is shared with, or its comment: nothing else of a sidecar changes."""
    entry = get(root, owner, save_id)
    _, _, path = _paths(root, owner, save_id)
    if KEY_SHARED_WITH in changes:
        entry[KEY_SHARED_WITH] = clean_shared_with(changes[KEY_SHARED_WITH])
    if KEY_COMMENT in changes:
        entry[KEY_COMMENT] = clean_text(changes[KEY_COMMENT], MAX_COMMENT)
    _write_json(path, entry)
    return entry


def delete(root: str, owner: str, save_id: str) -> dict:
    """Remove a save: its sidecar first (it is gone from every listing at once), then its file."""
    entry = get(root, owner, save_id)
    directory, data, sidecar = _paths(root, owner, save_id)
    os.unlink(sidecar)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(data)
    with contextlib.suppress(OSError):
        os.rmdir(directory)                     # the last save of the owner
    return entry


# -- the program --------------------------------------------------------------------------------

def run(operation: str, request: dict, stdin, stdout) -> dict | None:
    """One operation of the helper; the JSON result, ``None`` when the output is the save."""
    root = request.get('root')
    if not isinstance(root, str) or not os.path.isabs(root):
        raise StoreError(500, "no directory of the saved projects")
    owner, save_id = request.get(KEY_OWNER), request.get(KEY_ID)
    # every operation starts here: a volume that is not mounted is never read as an empty store,
    # and never written to
    space = check(root)
    if operation == 'check':
        return space
    if operation == 'list':
        return {'saves': list_saves(root, owner), **space}
    if operation == 'get':
        return get(root, owner, save_id)
    if operation == 'put':
        limit = request.get('max_bytes')
        return put(root, owner, save_id, stdin, limit if isinstance(limit, int) and limit > 0 else 0)
    if operation == 'commit':
        sidecar = request.get('sidecar')
        return commit(root, owner, save_id, sidecar if isinstance(sidecar, dict) else {})
    if operation == 'discard':
        return discard(root, owner, save_id)
    if operation == 'cat':
        cat(root, owner, save_id, stdout)
        return None
    if operation == 'update':
        changes = request.get('changes')
        return update(root, owner, save_id, changes if isinstance(changes, dict) else {})
    if operation == 'delete':
        return delete(root, owner, save_id)
    raise StoreError(500, f"unknown operation {operation!r}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    os.umask(0o077)
    try:
        if len(argv) != 2:
            raise StoreError(500, "usage: savestore.py <operation> <JSON request>")
        try:
            request = json.loads(argv[1])
        except ValueError:
            request = None
        if not isinstance(request, dict):
            raise StoreError(500, "the request is not a JSON object")
        result = run(argv[0], request, sys.stdin.buffer, sys.stdout.buffer)
    except StoreError as e:
        sys.stderr.write(json.dumps(e.to_dict()) + '\n')
        return EXIT_REFUSED
    except BrokenPipeError:
        return 1                                # the reader of a `cat` went away
    except OSError as e:
        full = e.errno in (errno.ENOSPC, errno.EDQUOT)
        refusal = StoreError(507 if full else 503, f"{e.filename or 'saved projects'}: {e.strerror}",
                             CODE_UNAVAILABLE)
        sys.stderr.write(json.dumps(refusal.to_dict()) + '\n')
        return EXIT_REFUSED
    if result is not None:
        sys.stdout.write(json.dumps(result) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
