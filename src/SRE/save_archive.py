"""Save-file format shared by ``sre save`` and ``sre restore``.

Pure file helpers (no Kathara import) so that they can be unit-tested without Docker.

Layout of a save file (stream-friendly: ``sre restore -`` reads it from stdin)::

    SRESAVE1\\n                  magic                       (params.save_file_magic)
    {"format_version": 1, …}\\n   one-line cleartext JSON header (SaveMeta, keys = params.save_meta_*)
    <payload>                    tar stream containing data.json, kathara.tar, answers/, files/,
                                 user_public/ and mnt/ — encrypted when the lab defines ``save_key``

In ``user_public/`` and ``mnt/`` a file or a directory that a machine of the project owns carries
two extended header records, ``params.save_machine_uid_record`` and ``save_machine_gid_record``:
its owner as the machines see it.  A restore gives it to the same user of the new machines where
the engine has ids of its own for them; the other members go back to the student.

Encryption: the payload tar stream is cut into chunks of ``params.save_cipher_chunk_size``
bytes, each one sealed with AES-256-GCM (key derived from ``save_key`` with PBKDF2-HMAC-SHA256
and the salt stored in the header).  Frame: ``[4-byte length][1-byte last flag][12-byte nonce]
[ciphertext + tag]``; the associated data binds every chunk to the header, its index and the
last flag, so reordering, truncation or header tampering are detected.
"""
import dataclasses
import grp
import hashlib
import json
import os
import pwd
import secrets
import stat
import struct
import tarfile
import typing

from . import params
from .utils import error_quit, log_error

_FRAME_LEN = struct.Struct('>I')
_CHUNK_INDEX = struct.Struct('>Q')
_NONCE_SIZE = 12


@dataclasses.dataclass
class SaveMeta:
    """Cleartext header of a save file."""
    lab_name: str                   # `lab@path` form (params.get_lab_name_from_running_lab_name)
    running_lab_name: str           # instance the file was saved from
    srelab_file: str
    username: str                   # owner of the saved instance
    saved_at: str                   # ISO 8601
    debug_project: bool = False
    full_images: bool = False
    shared_path: bool = False
    encrypted: bool = False
    kdf_salt: str = ''              # hex, empty when not encrypted
    kdf_iterations: int = params.save_kdf_iterations
    format_version: int = params.save_format_version
    sre_version: str = params.sre_version

    _keys = {
        'format_version': params.save_meta_format_version,
        'sre_version': params.save_meta_sre_version,
        'running_lab_name': params.save_meta_running_lab_name,
        'lab_name': params.save_meta_lab_name,
        'srelab_file': params.save_meta_srelab_file,
        'username': params.save_meta_username,
        'saved_at': params.save_meta_saved_at,
        'debug_project': params.save_meta_debug_project,
        'full_images': params.save_meta_full_images,
        'shared_path': params.save_meta_shared_path,
        'encrypted': params.save_meta_encrypted,
        'kdf_salt': params.save_meta_kdf_salt,
        'kdf_iterations': params.save_meta_kdf_iterations,
    }

    def to_json(self) -> str:
        d = {self._keys[f.name]: getattr(self, f.name) for f in dataclasses.fields(self)}
        return json.dumps(d, ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "SaveMeta":
        try:
            d = json.loads(s)
        except ValueError as e:
            error_quit(f"invalid save file header: {e}")
        if not isinstance(d, dict):
            error_quit("invalid save file header")
        kwargs = {}
        for f in dataclasses.fields(cls):
            key = cls._keys[f.name]
            if key in d:
                kwargs[f.name] = d[key]
            elif f.default is dataclasses.MISSING:
                error_quit(f"invalid save file header: missing '{key}'")
        return cls(**kwargs)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def write_header(fileobj, meta: SaveMeta) -> str:
    """Write the magic and the header line; return the header JSON (used as cipher AAD)."""
    header_json = meta.to_json()
    fileobj.write(params.save_file_magic)
    fileobj.write(header_json.encode('utf-8') + b"\n")
    return header_json


def read_header(fileobj) -> tuple[SaveMeta, str]:
    """Read the magic and the header line from a binary stream; return ``(meta, header_json)``."""
    magic = _read_exact(fileobj, len(params.save_file_magic))
    if magic != params.save_file_magic:
        error_quit("not an SRE save file")
    line = fileobj.readline()
    if not line.endswith(b"\n"):
        error_quit("truncated save file header")
    header_json = line[:-1].decode('utf-8', errors='replace')
    meta = SaveMeta.from_json(header_json)
    if not isinstance(meta.format_version, int) or meta.format_version > params.save_format_version:
        error_quit(f"unsupported save file format version {meta.format_version!r} "
                   f"(this version of sre supports up to {params.save_format_version})")
    return meta, header_json


def _read_exact(fileobj, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = fileobj.read(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


# ---------------------------------------------------------------------------
# Payload (tar stream)
# ---------------------------------------------------------------------------

_PAYLOAD_TOP_LEVEL = frozenset({
    params.data_json_name, params.save_kathara_name, params.answer_dir_name,
    params.files_dir_name, params.save_user_public_member, params.private_mount_dir_name,
})


# The members whose owner and mode a restore puts back: what the machines and the student wrote
_OWNED_TOP_LEVEL = frozenset({params.save_user_public_member, params.private_mount_dir_name})
_MAX_ID = 2 ** 32 - 1


class SavedEntry(typing.NamedTuple):
    """What a save file says of a file or a directory of ``user_public/`` or ``mnt/``."""
    mode: int                               # its permission bits (0o777 at most)
    machine_ids: tuple[int, int] | None     # its owner in the machines; None: not a machine's


def _member_filter(tarinfo: tarfile.TarInfo):
    """Skip device nodes and fifos when saving."""
    if tarinfo.ischr() or tarinfo.isblk() or tarinfo.isfifo():
        return None
    return tarinfo


def _described(tar: tarfile.TarFile, arcname: str, st: os.stat_result, linkname: str = '') -> tarfile.TarInfo:
    """The member of a directory or of a symbolic link whose status is *st*, as ``TarFile.gettarinfo``
    describes one (which reads the status by path: not usable on a tree somebody else may change)."""
    info = tar.tarinfo(arcname)
    info.type = tarfile.DIRTYPE if stat.S_ISDIR(st.st_mode) else tarfile.SYMTYPE
    info.mode, info.uid, info.gid, info.size, info.mtime = st.st_mode, st.st_uid, st.st_gid, 0, st.st_mtime
    info.linkname = linkname
    try:
        info.uname = pwd.getpwuid(st.st_uid)[0]
    except KeyError:
        pass
    try:
        info.gname = grp.getgrgid(st.st_gid)[0]
    except KeyError:
        pass
    return info


def _add_tree(tar: tarfile.TarFile, src: str, member: str, machine_owner=None):
    """Add the directory *src* as *member*.

    The tree may belong to the student and be changed while it is read, by a process that is
    root: it is walked by directory descriptors (``os.fwalk``) and every file is opened without
    following a link, relative to the directory it was listed in.  An entry replaced by a link
    meanwhile is stored as that link, never followed: nothing outside *src* is read.  Symbolic
    links are stored as links; devices, fifos and sockets are left out; an unreadable file is
    skipped with a warning instead of aborting the whole save.

    *machine_owner*: ``(uid, gid) -> (uid, gid) in the machines``, or ``None`` for a file that
    is not a machine's; the answer is recorded with the member."""
    def record_owner(info: tarfile.TarInfo):
        ids = machine_owner(info.uid, info.gid) if machine_owner is not None else None
        if ids is not None:
            info.pax_headers = {params.save_machine_uid_record: str(ids[0]),
                                params.save_machine_gid_record: str(ids[1])}
        return info

    def on_error(error: OSError):
        log_error(f"save: skipping '{error.filename}': {error.strerror or error}")

    for root, dirs, files, root_fd in os.fwalk(src, onerror=on_error, follow_symlinks=False):
        rel = os.path.relpath(root, src)
        base = member if rel == '.' else os.path.join(member, rel)
        if rel == '.':
            tar.addfile(_described(tar, member, os.fstat(root_fd)))
        dirs.sort()         # the order they are walked in
        for name in dirs + sorted(files):
            arcname = os.path.join(base, name)
            try:
                st = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    tar.addfile(record_owner(_described(tar, arcname, st)))
                elif stat.S_ISLNK(st.st_mode):
                    tar.addfile(record_owner(_described(tar, arcname, st, os.readlink(name, dir_fd=root_fd))))
                elif stat.S_ISREG(st.st_mode):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
                    with os.fdopen(fd, 'rb') as f:
                        info = tar.gettarinfo(arcname=arcname, fileobj=f)   # the status of the open file
                        if info is None or not (info.isreg() or info.islnk()):
                            continue        # it was replaced by something else meanwhile
                        record_owner(info)
                        if info.isreg():
                            tar.addfile(info, f)
                        else:
                            tar.addfile(info)       # another name of a file already stored
            except OSError as e:
                log_error(f"save: skipping '{os.path.join(root, name)}': {e.strerror or e}")


def write_payload(fileobj, data_json_path: str, kathara_tar_path: str,
                  answers_dir: str | None, files_dir: str | None,
                  user_public_dir: str | None, mnt_dir: str | None, machine_owner=None):
    """Write the payload tar stream to *fileobj* (a plain stream or an :class:`EncryptingWriter`).
    *machine_owner*: see :func:`_add_tree`; asked for the members of ``user_public/`` and ``mnt/``."""
    with tarfile.open(fileobj=fileobj, mode='w|', format=tarfile.PAX_FORMAT) as tar:
        tar.add(data_json_path, arcname=params.data_json_name, filter=_member_filter)
        tar.add(kathara_tar_path, arcname=params.save_kathara_name, filter=_member_filter)
        for src, member in ((answers_dir, params.answer_dir_name),
                            (files_dir, params.files_dir_name),
                            (user_public_dir, params.save_user_public_member),
                            (mnt_dir, params.private_mount_dir_name)):
            if src and os.path.isdir(src):
                _add_tree(tar, src, member, machine_owner if member in _OWNED_TOP_LEVEL else None)


# The members whose content SRE itself made, never a student nor a machine: no link belongs there
_NO_LINK_TOP_LEVEL = frozenset({params.answer_dir_name, params.files_dir_name})


def _restore_filter(member: tarfile.TarInfo, dest_path: str):
    parts = os.path.normpath(member.name).split('/')
    top = parts[0]
    if top not in _PAYLOAD_TOP_LEVEL:
        log_error(f"restore: skipping unexpected member '{member.name}'")
        return None
    # A save file is the student's to write.  What SRE works in afterwards with more rights than
    # the student must be what SRE would have made:
    # - the first level of user_public/ and mnt/ holds shared/ and the directories of the
    #   volumes, which the start of the project opens to its machines and mounts in them, and
    #   what the lab itself put there: a link there would be followed, to a directory the
    #   student chose (deeper, the links are the machines' own business);
    # - answers/ and .private/files hold files only: a link there would be read or written
    #   through by the commands of the lab that run on the host.
    if top in _OWNED_TOP_LEVEL and len(parts) == 2 and (member.issym() or member.islnk()):
        log_error(f"restore: skipping '{member.name}': no link at the first level of {top}/")
        return None
    if top in _NO_LINK_TOP_LEVEL and (member.issym() or member.islnk()):
        log_error(f"restore: skipping '{member.name}': no link in {top}/")
        return None
    try:
        return tarfile.data_filter(member, dest_path)
    except tarfile.FilterError as e:
        log_error(f"restore: skipping '{member.name}': {e}")
        return None


def _recorded_machine_ids(member: tarfile.TarInfo) -> tuple[int, int] | None:
    """The owner in the machines a save recorded for *member*; ``None`` without both records,
    or when one is not an id (the file is a student's: it is theirs to write)."""
    ids = []
    for key in (params.save_machine_uid_record, params.save_machine_gid_record):
        value = (member.pax_headers or {}).get(key)
        if not isinstance(value, str) or not value.isascii() or not value.isdigit() or int(value) > _MAX_ID:
            return None
        ids.append(int(value))
    return ids[0], ids[1]


def extract_payload(fileobj, dest_dir: str) -> dict[str, SavedEntry]:
    """Extract the payload tar stream into *dest_dir* (safe extraction: ``tarfile.data_filter``,
    top-level whitelist); ``data.json`` and ``kathara.tar`` must be present.

    That filter drops the owners and part of the modes.  What the save file says of the files and
    directories of ``user_public/`` and ``mnt/`` is returned, by member name: the caller, who
    knows where the files go and for whom, puts back what it sees fit."""
    saved = {}

    def extraction_filter(member: tarfile.TarInfo, dest_path: str):
        filtered = _restore_filter(member, dest_path)
        if (filtered is not None and member.name.split('/', 1)[0] in _OWNED_TOP_LEVEL
                and (member.isreg() or member.isdir() or member.islnk()) and isinstance(member.mode, int)):
            saved[os.path.normpath(member.name)] = SavedEntry(member.mode & 0o777, _recorded_machine_ids(member))
        return filtered

    try:
        with tarfile.open(fileobj=fileobj, mode='r|') as tar:
            tar.extractall(dest_dir, filter=extraction_filter)
    except tarfile.TarError as e:
        error_quit(f"invalid or truncated save file: {e}")
    for required in (params.data_json_name, params.save_kathara_name):
        if not os.path.isfile(os.path.join(dest_dir, required)):
            error_quit(f"invalid save file: '{required}' is missing")
    return saved


# ---------------------------------------------------------------------------
# Encryption (lab-level `save_key`)
# ---------------------------------------------------------------------------

def derive_key(save_key: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', save_key.encode('utf-8'), salt, iterations, dklen=32)


def header_aad(header_json: str) -> bytes:
    """Associated data binding the encrypted payload to its cleartext header."""
    return hashlib.sha256(header_json.encode('utf-8')).digest()


def _aesgcm(key: bytes):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        error_quit("the python 'cryptography' package is required for encrypted save files "
                   "(pip install cryptography)")
    return AESGCM(key)


def _chunk_aad(aad: bytes, index: int, last: bool) -> bytes:
    return aad + _CHUNK_INDEX.pack(index) + (b"\x01" if last else b"\x00")


class EncryptingWriter:
    """Binary file-like object that encrypts what is written to it, chunk by chunk.
    ``close()`` seals the last chunk and appends the end-of-stream marker."""

    def __init__(self, fileobj, key: bytes, aad: bytes):
        self._f = fileobj
        self._aead = _aesgcm(key)
        self._aad = aad
        self._buf = bytearray()
        self._index = 0
        self._closed = False

    def write(self, data) -> int:
        self._buf += data
        size = params.save_cipher_chunk_size
        while len(self._buf) >= size:
            self._emit(bytes(self._buf[:size]), last=False)
            del self._buf[:size]
        return len(data)

    def _emit(self, plaintext: bytes, last: bool):
        nonce = secrets.token_bytes(_NONCE_SIZE)
        ciphertext = self._aead.encrypt(nonce, plaintext, _chunk_aad(self._aad, self._index, last))
        self._f.write(_FRAME_LEN.pack(len(ciphertext)) + (b"\x01" if last else b"\x00") + nonce + ciphertext)
        self._index += 1

    def flush(self):
        self._f.flush()

    def close(self):
        if self._closed:
            return
        if self._buf:
            self._emit(bytes(self._buf), last=False)
            self._buf.clear()
        self._emit(b"", last=True)
        self._closed = True
        self._f.flush()


class DecryptingReader:
    """Binary file-like object that decrypts a stream produced by :class:`EncryptingWriter`.
    Only sequential ``read(n)`` is supported (enough for ``tarfile`` in ``r|`` mode)."""

    def __init__(self, fileobj, key: bytes, aad: bytes):
        self._f = fileobj
        self._aead = _aesgcm(key)
        self._aad = aad
        self._plain = b""
        self._index = 0
        self._eof = False

    def _next_chunk(self) -> bytes:
        frame = _read_exact(self._f, _FRAME_LEN.size + 1 + _NONCE_SIZE)
        if len(frame) < _FRAME_LEN.size + 1 + _NONCE_SIZE:
            error_quit("truncated encrypted save file")
        (length,) = _FRAME_LEN.unpack(frame[:_FRAME_LEN.size])
        last = frame[_FRAME_LEN.size] == 1
        nonce = frame[_FRAME_LEN.size + 1:]
        ciphertext = _read_exact(self._f, length)
        if len(ciphertext) < length:
            error_quit("truncated encrypted save file")
        try:
            from cryptography.exceptions import InvalidTag
            plaintext = self._aead.decrypt(nonce, ciphertext, _chunk_aad(self._aad, self._index, last))
        except InvalidTag:
            error_quit("cannot decrypt the save file: wrong save_key or corrupted file")
        self._index += 1
        if last:
            self._eof = True
        return plaintext

    def read(self, n: int = -1) -> bytes:
        out = bytearray()
        while n < 0 or len(out) < n:
            if not self._plain:
                if self._eof:
                    break
                self._plain = self._next_chunk()
                continue
            take = len(self._plain) if n < 0 else min(n - len(out), len(self._plain))
            out += self._plain[:take]
            self._plain = self._plain[take:]
        return bytes(out)

    def finish(self):
        """Consume the stream up to the end-of-stream marker (detects a truncated file
        whose tar part happened to end cleanly)."""
        while not self._eof:
            self._next_chunk()


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def lab_cli_arg_from_lab_name(lab_name: str) -> tuple[str, bool]:
    """Invert ``params.get_lab_name_from_cli_arg``: ``'s4@tp_ssh'`` → ``('s4/tp_ssh', False)``,
    ``'@opt@x@lab.py'`` → ``('/opt/x/lab.py', True)`` (absolute-path lab, ``sre start -p``).

    An absolute path *inside* ``params.lab_dir`` (a lab of the lab directory started with
    ``-p``) is turned back into its lab name, so that such a save file is restored like any
    other lab, including in user mode: ``'@opt@sre@lab@s4@tp_ssh'`` → ``('s4/tp_ssh', False)``."""
    path = lab_name.replace('@', '/')
    if not path.startswith('/'):
        return path, False
    # the path as given first (a lab reached through a symbolic link of the lab directory keeps
    # its name), then with its links resolved; the lab directory itself may be a link
    rel = '..'
    for candidate in (os.path.normpath(path), os.path.realpath(path)):
        for lab_dir in (os.path.abspath(params.lab_dir), os.path.realpath(params.lab_dir)):
            try:
                rel = os.path.relpath(candidate, lab_dir)
            except ValueError:      # different drives (Windows only)
                rel = '..'
            if not (rel == '..' or rel.startswith('../') or rel == '.'):
                break
        else:
            continue
        break
    if rel == '..' or rel.startswith('../') or rel == '.':
        return path, True
    if os.path.basename(rel) == params.srelab_py_name:
        rel = os.path.dirname(rel)          # directory lab given as .../srelab.py
    return rel, False
