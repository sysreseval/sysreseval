"""Save-file format shared by ``sre save`` and ``sre restore``.

Pure file helpers (no Kathara import) so that they can be unit-tested without Docker.

Layout of a save file (stream-friendly: ``sre restore -`` reads it from stdin)::

    SRESAVE1\\n                  magic                       (params.save_file_magic)
    {"format_version": 1, …}\\n   one-line cleartext JSON header (SaveMeta, keys = params.save_meta_*)
    <payload>                    tar stream containing data.json, kathara.tar, answers/, files/,
                                 user_public/ and mnt/ — encrypted when the lab defines ``save_key``

Encryption: the payload tar stream is cut into chunks of ``params.save_cipher_chunk_size``
bytes, each one sealed with AES-256-GCM (key derived from ``save_key`` with PBKDF2-HMAC-SHA256
and the salt stored in the header).  Frame: ``[4-byte length][1-byte last flag][12-byte nonce]
[ciphertext + tag]``; the associated data binds every chunk to the header, its index and the
last flag, so reordering, truncation or header tampering are detected.
"""
import dataclasses
import hashlib
import json
import os
import secrets
import struct
import tarfile

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


def _member_filter(tarinfo: tarfile.TarInfo):
    """Skip device nodes and fifos when saving."""
    if tarinfo.ischr() or tarinfo.isblk() or tarinfo.isfifo():
        return None
    return tarinfo


def _add_tree(tar: tarfile.TarFile, src: str, member: str):
    """Add the directory *src* as *member*, one entry at a time so that an unreadable file
    is skipped with a warning instead of aborting the whole save.  Symlinks are stored as
    symlinks (never followed)."""
    tar.add(src, arcname=member, recursive=False, filter=_member_filter)
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        for name in sorted(dirs) + sorted(files):
            path = os.path.join(root, name)
            arcname = os.path.join(member, name) if rel == '.' else os.path.join(member, rel, name)
            try:
                tar.add(path, arcname=arcname, recursive=False, filter=_member_filter)
            except OSError as e:
                log_error(f"save: skipping '{path}': {e}")


def write_payload(fileobj, data_json_path: str, kathara_tar_path: str,
                  answers_dir: str | None, files_dir: str | None,
                  user_public_dir: str | None, mnt_dir: str | None):
    """Write the payload tar stream to *fileobj* (a plain stream or an :class:`EncryptingWriter`)."""
    with tarfile.open(fileobj=fileobj, mode='w|') as tar:
        tar.add(data_json_path, arcname=params.data_json_name, filter=_member_filter)
        tar.add(kathara_tar_path, arcname=params.save_kathara_name, filter=_member_filter)
        for src, member in ((answers_dir, params.answer_dir_name),
                            (files_dir, params.files_dir_name),
                            (user_public_dir, params.save_user_public_member),
                            (mnt_dir, params.private_mount_dir_name)):
            if src and os.path.isdir(src):
                _add_tree(tar, src, member)


def _restore_filter(member: tarfile.TarInfo, dest_path: str):
    top = member.name.split('/', 1)[0]
    if top not in _PAYLOAD_TOP_LEVEL:
        log_error(f"restore: skipping unexpected member '{member.name}'")
        return None
    try:
        return tarfile.data_filter(member, dest_path)
    except tarfile.FilterError as e:
        log_error(f"restore: skipping '{member.name}': {e}")
        return None


def extract_payload(fileobj, dest_dir: str):
    """Extract the payload tar stream into *dest_dir* (safe extraction: ``tarfile.data_filter``,
    top-level whitelist); ``data.json`` and ``kathara.tar`` must be present."""
    try:
        with tarfile.open(fileobj=fileobj, mode='r|') as tar:
            tar.extractall(dest_dir, filter=_restore_filter)
    except tarfile.TarError as e:
        error_quit(f"invalid or truncated save file: {e}")
    for required in (params.data_json_name, params.save_kathara_name):
        if not os.path.isfile(os.path.join(dest_dir, required)):
            error_quit(f"invalid save file: '{required}' is missing")


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
    ``'@opt@x@lab.py'`` → ``('/opt/x/lab.py', True)`` (absolute-path lab)."""
    path = lab_name.replace('@', '/')
    return path, path.startswith('/')
