"""The saved projects on a pool host: every access of the agent to their shared directory.

The directory (``[saves] dir`` of agent.toml) is a volume every pool host mounts, so that a
project saved on one host is restored on another.  The agent itself never touches it: each access
is one run of ``sreweb/savestore.py`` as a program, under the account that owns the directory
(``[saves] user``, ``sre``).  That keeps the store closed to the local users of the host and lets
the export squash root, and a volume that hangs blocks a child the agent kills, never the agent
(its status is polled every five seconds: :attr:`SaveStore.available` is what a background
check last found, nothing is asked when the status is).

A save is ``sre save <project>`` writing into the stdin of the helper's ``put`` through a pipe:
the bytes never cross the agent.  ``put`` only writes a hidden file; the save becomes visible
with ``commit``, once ``sre`` and the helper both ended well.  A restore is the helper's ``cat``
writing into the stdin of ``sre restore -`` the same way.
"""
import asyncio
import contextlib
import json
import logging
import os
import platform
import pwd
import shutil
import signal
import sys
import time
from datetime import datetime, timezone

from SRE import params
from SRE.save_archive import lab_cli_arg_from_lab_name
from .access import AccessError
from .runner import CommandError, SreRunner, sre_args
from .. import savestore
from ..config import SavesConfig

log = logging.getLogger(__name__)

HEALTH_INTERVAL = 60.0          # seconds between two checks of the directory
#: What ``sre save`` may write in one temporary file beyond the size a save may have: the
#: archive of the machines is written whole before it is streamed.
FILE_SIZE_SLACK = 64 << 20


class SaveRefused(AccessError):
    """A refusal about a saved project; ``code`` (``savestore.CODE_*``) and ``extra`` go into
    the JSON answer next to the message."""

    def __init__(self, status: int, message: str, code: str = '', **extra):
        super().__init__(status, message)
        self.code = code
        self.extra = extra


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def sweep_tmp_dir(directory: str, older_than: float, now: float | None = None) -> list:
    """Remove the ``save-*`` and ``restore-*`` directories of *directory* (``params.save_tmp_dir``:
    where ``sre save`` and ``sre restore`` build and unpack their archives) untouched for
    *older_than* seconds: a command killed with the agent never removes its own.  The names
    removed; a missing directory or an entry that resists is skipped."""
    now = time.time() if now is None else now
    removed = []
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return removed
    for entry in entries:
        if not entry.name.startswith(('save-', 'restore-')):
            continue
        try:
            if not entry.is_dir(follow_symlinks=False) or now - entry.stat(follow_symlinks=False).st_mtime < older_than:
                continue
        except OSError:
            continue
        shutil.rmtree(entry.path, ignore_errors=True)
        if not os.path.lexists(entry.path):
            removed.append(entry.name)
    if removed:
        log.info("saved projects: %d stale temporary director%s removed from %s", len(removed),
                 'y' if len(removed) == 1 else 'ies', directory)
    return removed


class SaveReader:
    """One saved project being read for a restore: the helper's ``cat``, started by
    :meth:`open` once ``sre restore`` is about to run, ended by :meth:`close`."""

    def __init__(self, store: 'SaveStore', owner: str, save_id: str):
        self._store = store
        self._request = store.request(owner, save_id)
        self._proc = None

    async def open(self) -> int:
        """Start the helper; the descriptor ``sre restore -`` reads (the caller closes it)."""
        read_end, write_end = os.pipe()
        try:
            self._proc = await self._store.spawn('cat', self._request, stdin=asyncio.subprocess.DEVNULL,
                                                 stdout=write_end)
        except BaseException:
            os.close(read_end)
            raise
        finally:
            os.close(write_end)
        return read_end

    async def close(self) -> str:
        """End the helper (killed when it still runs: ``sre`` stopped reading); the reason it
        refused, ``''`` when it gave the whole save or never ran."""
        proc = self._proc
        if proc is None:
            return ''
        if proc.returncode is None:
            with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), 5)
        if proc.returncode is None:
            await self._store.kill(proc)
            return ''
        stderr = await proc.stderr.read()
        if proc.returncode == 0:
            return ''
        return self._store.refusal(proc.returncode, stderr).message


class SaveStore:
    def __init__(self, cfg: SavesConfig, *, hostname: str = '', tmp_dir: str | None = None,
                 spawn=asyncio.create_subprocess_exec):
        self.cfg = cfg
        self.hostname = hostname
        self.enabled = bool(cfg.dir)
        #: Where ``sre save`` writes its temporary files (the archive of the machines).
        self.tmp_dir = tmp_dir or params.save_tmp_dir
        self.max_bytes = cfg.max_size_mb << 20
        self._spawn = spawn
        self._uid: int | None = None
        self._gid: int | None = None
        #: What the last check found: nothing is asked of the directory when the status is.
        self.available = False
        self.error = '' if self.enabled else 'not configured'
        self.free_mb: int | None = None
        self.total_mb: int | None = None
        self._slots = asyncio.Semaphore(cfg.max_concurrent)
        self._owner_locks: dict[str, asyncio.Lock] = {}
        self._list_lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._running: set = set()

    # -- life -----------------------------------------------------------------------------------

    async def start(self):
        if not self.enabled:
            return
        try:
            self._resolve_user()
        except SaveRefused as e:
            self.error = e.message
            log.error("saved projects: %s", e.message)
            return
        await self.refresh()
        self._task = asyncio.ensure_future(self._watch())

    def _resolve_user(self):
        if self.cfg.user:
            try:
                entry = pwd.getpwnam(self.cfg.user)
            except KeyError:
                raise SaveRefused(503, f"saves.user {self.cfg.user} does not exist") from None
            if os.geteuid() == 0:
                self._uid, self._gid = entry.pw_uid, entry.pw_gid
            elif entry.pw_uid != os.geteuid():
                raise SaveRefused(503, f"the agent does not run as root: it cannot act as saves.user {self.cfg.user}")
        elif os.geteuid() == 0:
            raise SaveRefused(503, "saves.user is required when the agent runs as root")

    async def stop(self):
        """Stop the check, and every save or restore helper still running."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        for proc in list(self._running):
            await self.kill(proc)

    async def _watch(self):
        while True:
            await asyncio.sleep(HEALTH_INTERVAL)
            try:
                await self.refresh()
            except Exception:
                log.exception("saved projects: the check of %s failed", self.cfg.dir)

    async def refresh(self) -> bool:
        """Check the directory now; :attr:`available` and :attr:`error` say what was found."""
        try:
            self._note_space(await self._call('check', {'root': self.cfg.dir}, checked=False))
        except SaveRefused as e:
            self._unavailable(e.message)
            return False
        if not self.available:
            log.info("saved projects: %s is usable", self.cfg.dir)
        self.available, self.error = True, ''
        return True

    def _unavailable(self, message: str):
        if self.available or message != self.error:
            log.warning("saved projects: %s unusable: %s", self.cfg.dir, message)
        self.available, self.error = False, message

    def _note_space(self, answer: dict):
        self.free_mb = answer.get('free_mb') if isinstance(answer.get('free_mb'), int) else None
        self.total_mb = answer.get('total_mb') if isinstance(answer.get('total_mb'), int) else None

    def status(self) -> dict:
        """The keys of ``GET /v1/status``: whether this host saves and restores projects, why not,
        and whether it is meant to (a directory is configured: the Pool page of the portal and
        `sre-web-tool list` name the hosts that are meant to and cannot)."""
        return {savestore.STATUS_SAVES: self.enabled and self.available, savestore.STATUS_SAVES_ERROR: self.error,
                savestore.STATUS_SAVES_CONFIGURED: self.enabled}

    def require(self):
        if not self.enabled:
            raise SaveRefused(404, "saved projects are not enabled on this host", savestore.CODE_UNAVAILABLE)
        if not self.available:
            raise SaveRefused(503, f"the saved projects are not available on this host: {self.error}",
                              savestore.CODE_UNAVAILABLE)

    # -- the helper -----------------------------------------------------------------------------

    def request(self, owner: str | None = None, save_id: str | None = None, **more) -> dict:
        request = {'root': self.cfg.dir, **more}
        if owner is not None:
            request[savestore.KEY_OWNER] = owner
        if save_id is not None:
            request[savestore.KEY_ID] = save_id
        return request

    async def spawn(self, operation: str, request: dict, *, stdin, stdout=asyncio.subprocess.PIPE):
        """Run the helper for one operation, under the account of the store."""
        kwargs = dict(stdin=stdin, stdout=stdout, stderr=asyncio.subprocess.PIPE, start_new_session=True,
                      close_fds=True, umask=0o077, cwd='/',
                      env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        if self._uid is not None:
            kwargs.update(user=self._uid, group=self._gid, extra_groups=[])
        proc = await self._spawn(sys.executable, '-I', '-B', savestore.__file__, operation, json.dumps(request),
                                 **kwargs)
        self._running.add(proc)
        return proc

    async def kill(self, proc):
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                await proc.wait()
        self._running.discard(proc)

    @staticmethod
    def refusal(returncode: int, stderr: bytes) -> SaveRefused:
        """What the helper said when it did not exit 0."""
        text = stderr.decode('utf-8', 'replace').strip()
        if returncode == savestore.EXIT_REFUSED:
            try:
                said = json.loads(text.splitlines()[-1])
                return SaveRefused(int(said['status']), str(said['error']), str(said.get('code') or ''))
            except (ValueError, KeyError, IndexError, TypeError):
                pass
        log.error("saved projects: the helper failed (%s): %s", returncode, text[-500:])
        return SaveRefused(502, "the saved projects could not be accessed", savestore.CODE_UNAVAILABLE)

    async def _result(self, proc, timeout: float) -> dict:
        """The JSON answer of a helper once it ends; killed, and the store marked unusable, when
        it does not within *timeout*."""
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
        except (TimeoutError, asyncio.TimeoutError):
            await self.kill(proc)
            self._unavailable("the directory does not answer")
            raise SaveRefused(504, "the saved projects do not answer", savestore.CODE_UNAVAILABLE) from None
        except BaseException:
            await self.kill(proc)
            raise
        finally:
            self._running.discard(proc)
        if proc.returncode != 0:
            raise self.refusal(proc.returncode, stderr)
        try:
            answer = json.loads(stdout.decode('utf-8'))
        except ValueError:
            answer = None
        if not isinstance(answer, dict):
            raise SaveRefused(502, "the saved projects could not be accessed", savestore.CODE_UNAVAILABLE)
        return answer

    async def _call(self, operation: str, request: dict, *, checked: bool = True) -> dict:
        if checked:
            self.require()
        proc = await self.spawn(operation, request, stdin=asyncio.subprocess.DEVNULL)
        return await self._result(proc, self.cfg.timeout)

    # -- the saves ------------------------------------------------------------------------------

    async def list(self, owner: str | None = None) -> dict:
        """``{saves, free_mb, total_mb}``: the saves of *owner*, or of everybody (one listing of
        the whole store at a time: the callers of a second one wait for it)."""
        if owner is not None:
            answer = await self._call('list', self.request(owner))
        else:
            async with self._list_lock:
                answer = await self._call('list', self.request())
        self._note_space(answer)
        saves = answer.get('saves')
        return {'saves': saves if isinstance(saves, list) else [], 'free_mb': self.free_mb, 'total_mb': self.total_mb}

    async def get(self, owner: str, save_id: str) -> dict:
        return await self._call('get', self.request(owner, save_id))

    async def update(self, owner: str, save_id: str, changes: dict) -> dict:
        return await self._call('update', self.request(owner, save_id, changes=changes))

    async def delete(self, owner: str, save_id: str) -> dict:
        return await self._call('delete', self.request(owner, save_id))

    def reader(self, owner: str, save_id: str) -> SaveReader:
        return SaveReader(self, owner, save_id)

    # -- saving ---------------------------------------------------------------------------------

    def slot(self) -> asyncio.Semaphore:
        """The saves running at once on the host (``max_concurrent``): taken before the lock of
        the project, so that a save waiting for its turn does not freeze its project."""
        return self._slots

    def owner_lock(self, owner: str) -> asyncio.Lock:
        """One save at a time for an owner on this host: their count, then their new save."""
        return self._owner_locks.setdefault(owner, asyncio.Lock())

    def check_space(self):
        """Room for a save: in the store (what the last check or listing found), and where
        ``sre save`` writes the archive of the machines before streaming it."""
        least = self.cfg.min_free_mb
        if self.free_mb is not None and self.free_mb < least:
            raise SaveRefused(507, "not enough free space for the saved projects", savestore.CODE_UNAVAILABLE)
        directory = self.tmp_dir
        while directory and not os.path.isdir(directory):
            directory = os.path.dirname(directory.rstrip('/'))
        with contextlib.suppress(OSError):
            if shutil.disk_usage(directory or '/').free >> 20 < least:
                raise SaveRefused(507, "not enough free space on this host to save a project",
                                  savestore.CODE_UNAVAILABLE)

    async def count(self, owner: str) -> int:
        return len((await self.list(owner))['saves'])

    async def save(self, runner: SreRunner, *, user: str, rln: str, privileged: bool, owner: str, sidecar: dict,
                   lang: str | None = None) -> dict:
        """Save the project *rln* as a new save of *owner* and give its entry: ``sre save``
        (run for *user*, privileged for an instructor on somebody else's project) piped into
        the helper, then the commit.  Whatever fails, nothing of the save is left."""
        self.require()
        save_id = savestore.new_id()
        request = self.request(owner, save_id, max_bytes=self.max_bytes)
        read_end, write_end = os.pipe()
        put = None
        try:
            try:
                put = await self.spawn('put', request, stdin=read_end)
            finally:
                os.close(read_end)
            failure = None
            try:
                await runner.pipe_stdout(user, sre_args('save', rln), write_end, privileged=privileged, lang=lang,
                                         file_size_limit=self.max_bytes + FILE_SIZE_SLACK)
            except (CommandError, FileNotFoundError) as e:
                failure = e
            finally:
                os.close(write_end)
                write_end = None
            # the helper ends with the stream; a volume that hangs is given the time of one access
            helper, put = put, None
            try:
                written = await self._result(helper, self.cfg.timeout)
            except SaveRefused as refusal:
                # which of the two failed first: the helper refusing (too large, no space left)
                # makes sre fail on a closed pipe, and its reason is the one to tell; sre failing
                # makes the helper see a stream that is not a save, and the reason is sre's
                if failure is not None and refusal.code == savestore.CODE_NOT_A_SAVE:
                    raise failure from None
                raise
            if failure is not None:
                raise failure
            entry = await self._call('commit', self.request(owner, save_id, sidecar=self._sidecar(sidecar, written)))
        except BaseException:
            if write_end is not None:
                os.close(write_end)
            if put is not None:
                await self.kill(put)
            await self._discard(owner, save_id)
            raise
        log.info("saved projects: %s saved by %s as %s/%s (%d bytes)", rln, owner, owner, save_id,
                 entry.get(savestore.KEY_SIZE, 0))
        return entry

    def _sidecar(self, sidecar: dict, written: dict) -> dict:
        """The sidecar of a save that was written: what the caller knows of the project, the lab
        the header of the save names (what ``sre restore`` will start), its checksum."""
        header = written.get('header') if isinstance(written.get('header'), dict) else {}
        lab, is_path = lab_cli_arg_from_lab_name(str(header.get(params.save_meta_lab_name) or ''))
        return {**sidecar,
                savestore.KEY_LAB: '' if is_path else lab,
                savestore.KEY_DEBUG_PROJECT: header.get(params.save_meta_debug_project) is True,
                savestore.KEY_SHA256: written.get(savestore.KEY_SHA256, ''),
                savestore.KEY_SAVED_AT: now_iso(), savestore.KEY_HOST: self.hostname,
                savestore.KEY_ARCH: platform.machine(), savestore.KEY_SRE_VERSION: params.sre_version}

    async def _discard(self, owner: str, save_id: str):
        """Remove what a save that failed wrote; best effort, also when the caller was cancelled."""
        async def discard():
            with contextlib.suppress(Exception):
                await self._call('discard', self.request(owner, save_id), checked=False)

        with contextlib.suppress(BaseException):
            await asyncio.shield(asyncio.ensure_future(discard()))
