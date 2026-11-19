"""The drain of a pool host asked on the host itself (``sre set-drain`` / ``sre remove-drain``).

A drain (no new web project on the host, powered off once it is empty) belongs to the portal,
and the web agent of a host never calls the portal: the host *asks through its status*.  Two
small files of the public directory (``params.sre_pub_dir``) carry it between ``sre`` and the
agent, which share no socket:

- the **request** (``params.local_drain_json_name``), written by ``sre set-drain`` and removed
  by ``sre remove-drain``: ``{asked_at, boot_id}``.  The agent reads it at every status the
  portal asks for, and removes it when the portal cancels the drain or forbids local drains;
- the **agent's state** (``params.agent_state_json_name``), written by the agent at its start
  and whenever the portal changes it: ``{boot_id, local_drain: {allowed, default}}``.  ``sre
  set-drain`` reads it first: no file of this boot means no agent that would honour the request.

Both name the boot they were written in (:func:`boot_id`): a drain ends with the power off it
asked for, and what the portal chose holds until the host boots again, across the restarts of
the agent.

The reader trusts nothing else: a file that is a link, not a regular file, owned by somebody
else, too big or not the expected JSON is not read (the agent then removes the request).

Pure: the standard library and ``params`` only; nothing is logged here.
"""
import json
import os
import stat
import tempfile
import time

from . import params

BOOT_ID_FILE = '/proc/sys/kernel/random/boot_id'

#: Why a request is not honoured although its file is sound: it was asked before the last boot.
STALE = "asked before the last boot"


def boot_id(path: str = BOOT_ID_FILE) -> str:
    """What names the current boot of the machine (a new random id at every boot), ``''`` where
    the kernel does not tell (not a Linux system: every file then counts as of this boot)."""
    try:
        with open(path, encoding='ascii') as f:
            return f.read().strip()
    except (OSError, ValueError):
        return ''


def request_path(pub_dir: str | None = None) -> str:
    return os.path.join(pub_dir or params.sre_pub_dir, params.local_drain_json_name)


def agent_state_path(pub_dir: str | None = None) -> str:
    return os.path.join(pub_dir or params.sre_pub_dir, params.agent_state_json_name)


def request_uids() -> set[int]:
    """The owners a request may have: root, ``params.sre_uid`` (``sre`` run by root ends as that
    user) and the reader itself (the tests), as ``web_updates.trusted_uids()``."""
    return {0, params.sre_uid, os.geteuid()}


def agent_uids() -> set[int]:
    """The owners the agent's state may have: root (the agent) and the reader itself.  For the
    agent that is root alone; ``sre`` reads the file as the sre user, who may run any command
    anyway, and the agent checks a request again when it honours it."""
    return {0, os.geteuid()}


def _write(path: str, document: dict):
    """Atomic (a temporary file of the directory, then ``os.replace``), mode 0644: the reader
    never sees half a file.  ``OSError`` when it cannot be written."""
    fd, temp_name = tempfile.mkstemp(dir=os.path.dirname(path) or '.', prefix='.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(json.dumps(document, ensure_ascii=False, separators=(',', ':')))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _read(path: str, uids: set) -> tuple:
    """``(document, problem)`` of the JSON object in *path*: ``(None, '')`` without a file,
    ``(None, reason)`` for a file that is not to be read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, ''
    except OSError as e:
        return None, e.strerror or type(e).__name__
    try:
        # checked on the descriptor, before any Python file object: opening one on a directory raises
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file"
        if st.st_uid not in uids:
            return None, f"owned by uid {st.st_uid}"
        data = os.read(fd, params.local_drain_max_size + 1)
    except OSError as e:
        return None, e.strerror or type(e).__name__
    finally:
        os.close(fd)
    if len(data) > params.local_drain_max_size:
        return None, f"above {params.local_drain_max_size} bytes"
    try:
        document = json.loads(data.decode('utf-8'))
    except ValueError:
        return None, "not JSON"
    if not isinstance(document, dict):
        return None, "not a JSON object"
    return document, ''


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value \
        and value not in (float('inf'), float('-inf'))


# -- the request -----------------------------------------------------------------------------------

def write_request(path: str, boot: str, now: float | None = None) -> dict:
    """Ask for the drain of this host: the request written (a request already there is replaced,
    with its new time).  ``OSError`` when the file cannot be written."""
    request = {params.local_drain_asked_at_keyword: round(time.time() if now is None else now, 3),
               params.boot_id_keyword: boot}
    _write(path, request)
    return request


def read_request(path: str, boot: str) -> tuple:
    """``(request, problem)``: the request of *path* when it is one of the boot *boot*
    (``{asked_at}``), else ``None`` with the reason the file is not honoured, ``''`` when there
    is no file."""
    document, problem = _read(path, request_uids())
    if document is None:
        return None, problem
    asked_at = document.get(params.local_drain_asked_at_keyword)
    if not _is_number(asked_at) or asked_at < 0:
        return None, "no time of the request"
    if document.get(params.boot_id_keyword) != boot:
        return None, STALE
    return {params.local_drain_asked_at_keyword: float(asked_at)}, ''


def remove_request(path: str) -> bool:
    """Remove the request: whether there was a file (of whatever content).  ``OSError`` when it
    cannot be removed."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    return True


# -- the state of the agent -----------------------------------------------------------------------

def write_agent_state(path: str, boot: str, *, allowed: bool, default: bool):
    """What the agent of the host says about local drains now.  ``OSError`` when the file cannot
    be written."""
    _write(path, {params.boot_id_keyword: boot,
                  params.local_drain_keyword: {params.local_drain_allowed_keyword: bool(allowed),
                                               params.local_drain_default_keyword: bool(default)}})


def read_agent_state(path: str, boot: str) -> dict | None:
    """``{allowed, default}`` as the agent of the host wrote them during the boot *boot*;
    ``None`` without such a file (no agent since the boot, an agent older than the local drains,
    a file that is not to be read)."""
    document, _problem = _read(path, agent_uids())
    if document is None or document.get(params.boot_id_keyword) != boot:
        return None
    state = document.get(params.local_drain_keyword)
    if not isinstance(state, dict):
        return None
    allowed = state.get(params.local_drain_allowed_keyword)
    default = state.get(params.local_drain_default_keyword)
    if not isinstance(allowed, bool) or not isinstance(default, bool):
        return None
    return {params.local_drain_allowed_keyword: allowed, params.local_drain_default_keyword: default}


# -- both, as `sre status` shows them -----------------------------------------------------------

def summary(pub_dir: str | None = None, boot: str | None = None) -> dict | None:
    """``{allowed, asked, asked_at}`` from the two files of the public directory: whether this
    host may ask for its own drain, and whether it did (never while forbidden: the agent drops
    such a request); ``None`` when the agent of the host published nothing since the boot (no
    agent, or one older than the local drains)."""
    boot = boot_id() if boot is None else boot
    state = read_agent_state(agent_state_path(pub_dir), boot)
    if state is None:
        return None
    allowed = state[params.local_drain_allowed_keyword]
    request, _problem = read_request(request_path(pub_dir), boot)
    asked = allowed and request is not None
    return {params.local_drain_allowed_keyword: allowed,
            params.local_drain_asked_keyword: asked,
            params.local_drain_asked_at_keyword: request[params.local_drain_asked_at_keyword] if asked else None}
