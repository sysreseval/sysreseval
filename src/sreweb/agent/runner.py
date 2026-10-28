"""The one place of the agent that spawns ``sre``.

A web user is served exactly like a student of the Qt GUI, whose ``sre-wrapper`` runs
``sudo sre --user ...``: the agent is root and runs ``<sre_exe> --user <cmd...>`` with the
environment sudo would have left (``LOGNAME=root``, ``SUDO_USER=<login>``,
``USER_USERNAME=<login>``) and **without** ``SUDO_COMMAND``, so that ``sre`` neither looks for
the wrapper among its ancestors nor trusts anything else (this is what the Docker lifecycle tests
do with ``_sre_user()``).  ``sre`` then applies the user-mode restrictions itself and takes the
owner of a new project from ``SUDO_USER``.  A privileged call (``privileged=True``: no ``--user``,
``LOGNAME=<login>``) is reserved to the instructor role.

The stderr of ``sre start`` / ``sre restore`` carries one JSON object per line
(``SRE/progress.py``: ``pull`` / ``deploy`` progress, ``flavor_form`` / ``flavor_error``, and the
final ``project created`` event with the running lab name) between plain error lines:
:meth:`SreRunner.stream` yields them as dicts, a plain line becoming
``{"phase": "message", "line": ...}``.
"""
import asyncio
import json
import os
import signal
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable

from .. import config as _config

#: Exit codes of ``sre start`` (params.exit_code_flavor_form_needed / _not_allowed).
EXIT_FLAVOR_FORM_NEEDED = 3
EXIT_FLAVOR_NOT_ALLOWED = 4

PHASE_MESSAGE = 'message'       # a plain stderr line
PHASE_PROJECT = 'project'       # {"phase": "project", "status": "created", "running_lab_name": ...}
PHASE_FLAVOR_FORM = 'flavor_form'
PHASE_FLAVOR_ERROR = 'flavor_error'

#: The ``status`` of the final ``{"phase": "result"}`` line of the creation stream of the agent
#: (``POST /v1/projects``), read by the portal too: after a form or a refused flavor no project
#: exists, and the start slot of the user is given back.
RESULT_CREATED = 'created'
RESULT_FLAVOR_FORM = 'flavor_form'
RESULT_FLAVOR_ERROR = 'flavor_error'
RESULT_ERROR = 'error'

#: Commands sharing the "start" and the "eval" concurrency limits.
START_LIKE = frozenset({'start'})
EVAL_LIKE = frozenset({'eval', 'state'})

STREAM_LINE_LIMIT = 1 << 22     # a flavor form (JSON on one stderr line) can be long


class CommandError(Exception):
    """``sre`` exited with an error (or could not be run)."""

    def __init__(self, rc: int, message: str, stderr: str = ''):
        super().__init__(message or f"sre exited with status {rc}")
        self.rc = rc
        self.message = message
        self.stderr = stderr


class CommandTimeout(CommandError):
    def __init__(self, timeout: float):
        super().__init__(-1, f"sre did not finish within {timeout:g} s")
        self.timeout = timeout


class FlavorFormNeeded(Exception):
    """``sre start`` wants the Flavor form filled (exit 3): re-run with ``--flavor-json``."""

    def __init__(self, form, form_size=None):
        super().__init__("flavor form needed")
        self.form = form
        self.form_size = form_size


class FlavorError(Exception):
    """``sre start`` refused the flavor (exit 4): the message of ``Flavor.allowed_by_user()``."""

    def __init__(self, message):
        super().__init__(str(message))
        self.message = message


@dataclass
class RunResult:
    rc: int
    stdout: bytes
    stderr: str
    events: list = field(default_factory=list)   # the JSON lines of stderr

    @property
    def message(self) -> str:
        """The last plain (non-JSON) line of stderr: what ``sre`` said when it failed."""
        return last_message(self.stderr)


def build_env(user: str, *, privileged: bool = False, lang: str | None = None, term: str | None = None,
              path: str = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin') -> dict:
    """The environment of a ``sre`` process run for *user*: built from scratch, never from the
    agent's own environment (no ``SUDO_COMMAND``, no ``SUDO_UID``)."""
    env = {'PATH': path, 'HOME': '/root', 'USER': 'root', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    if privileged:
        env['LOGNAME'] = user
    else:
        env.update(LOGNAME='root', SUDO_USER=user, USER_USERNAME=user)
    if lang:
        env['LANGUAGE'] = lang
    if term:
        env['TERM'] = term
    return env


def build_argv(sre_exe: str, args, *, privileged: bool = False) -> list:
    return [sre_exe] + ([] if privileged else ['--user']) + [str(a) for a in args]


def parse_stderr_line(line: str) -> dict:
    """A stderr line of ``sre``: the JSON event it holds, else a ``message`` event."""
    text = line.rstrip('\r\n')
    if text.startswith('{'):
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and 'phase' in obj:
            return obj
    return {'phase': PHASE_MESSAGE, 'line': text}


def last_message(stderr: str) -> str:
    """The last plain line of a stderr text (the JSON events skipped)."""
    message = ''
    for line in stderr.splitlines():
        event = parse_stderr_line(line)
        if event['phase'] == PHASE_MESSAGE and event['line'].strip():
            message = event['line'].strip()
    return message


class StreamingRun:
    """A running ``sre`` whose stderr events are consumed one by one (``start``, ``restore``).

    ``async for event in run.events(): ...`` ends when the process has exited; ``rc``,
    ``stdout`` and ``received`` (every event) are then set.  :meth:`result` turns the flavor exit codes into
    :class:`FlavorFormNeeded` / :class:`FlavorError` and any other failure into
    :class:`CommandError`."""

    def __init__(self, proc: asyncio.subprocess.Process, timeout: float | None, on_done: Callable):
        self._proc = proc
        self._timeout = timeout
        self._on_done = on_done
        self.rc: int | None = None
        self.stdout: bytes = b''
        self.received: list = []
        self._stderr_lines: list = []

    @property
    def pid(self) -> int:
        return self._proc.pid

    async def events(self) -> AsyncIterator[dict]:
        stdout_task = asyncio.ensure_future(self._proc.stdout.read())
        try:
            async with asyncio.timeout(self._timeout):
                while True:
                    line = await self._proc.stderr.readline()
                    if not line:
                        break
                    text = line.decode('utf-8', 'replace')
                    self._stderr_lines.append(text)
                    event = parse_stderr_line(text)
                    self.received.append(event)
                    yield event
                self.stdout = await stdout_task
                self.rc = await self._proc.wait()
        except TimeoutError:
            await cancel_process(self._proc)
            stdout_task.cancel()
            raise CommandTimeout(self._timeout or 0)
        finally:
            if not stdout_task.done():
                stdout_task.cancel()
            self._on_done()

    @property
    def stderr(self) -> str:
        return ''.join(self._stderr_lines)

    def result(self) -> RunResult:
        if self.rc is None:
            raise RuntimeError("the events have not been consumed")
        if self.rc == EXIT_FLAVOR_FORM_NEEDED:
            form_event = next((e for e in self.received if e.get('phase') == PHASE_FLAVOR_FORM), {})
            raise FlavorFormNeeded(form_event.get('form', ''), form_event.get('form_size'))
        if self.rc == EXIT_FLAVOR_NOT_ALLOWED:
            error_event = next((e for e in self.received if e.get('phase') == PHASE_FLAVOR_ERROR), {})
            raise FlavorError(error_event.get('message', last_message(self.stderr)))
        if self.rc != 0:
            raise CommandError(self.rc, last_message(self.stderr), self.stderr)
        return RunResult(self.rc, self.stdout, self.stderr, self.received)

    def created_running_lab_name(self) -> str | None:
        for event in self.received:
            if event.get('phase') == PHASE_PROJECT and event.get('status') == 'created':
                return event.get('running_lab_name')
        return None


async def cancel_process(proc: asyncio.subprocess.Process, *, grace: float = 30.0):
    """Stop a ``sre`` process: SIGINT first (``sre start`` then rolls the project back), SIGTERM,
    and SIGKILL on the whole process group as a last resort."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), grace)
            return
        except TimeoutError:
            pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    await proc.wait()


class SreRunner:
    def __init__(self, sre_exe: str, *, timeouts: dict | None = None, max_concurrent_starts: int = 2,
                 max_concurrent_evals: int = 2, extra_env: dict | None = None):
        self.sre_exe = sre_exe
        #: Variables added to the environment of every sre process (tests point a fake sre at a
        #: temporary SRE_PUB_DIR this way); never used in production.
        self.extra_env = dict(extra_env or {})
        self.timeouts = dict(_config.DEFAULT_TIMEOUTS)
        self.timeouts.update(timeouts or {})
        self._start_sem = asyncio.Semaphore(max_concurrent_starts)
        self._eval_sem = asyncio.Semaphore(max_concurrent_evals)
        self._user_start_locks: dict[str, asyncio.Lock] = {}
        #: The sre commands running (counted from their limits acquired to their release): what
        #: a stop or a restart of the agent waits for (:meth:`wait_idle`).
        self.in_flight = 0

    # -- limits ---------------------------------------------------------------------------------

    def _timeout(self, args, timeout) -> float | None:
        if timeout is not None:
            return timeout or None
        return self.timeouts.get(str(args[0]) if args else '', None)

    async def _acquire(self, user: str, args) -> list:
        """The semaphores / locks a command holds; released in order by :meth:`_release`."""
        held = []
        command = str(args[0]) if args else ''
        if command in START_LIKE:
            lock = self._user_start_locks.setdefault(user, asyncio.Lock())
            await lock.acquire()
            held.append(lock)
            await self._start_sem.acquire()
            held.append(self._start_sem)
        elif command in EVAL_LIKE:
            await self._eval_sem.acquire()
            held.append(self._eval_sem)
        self.in_flight += 1
        return held

    def _release(self, held: list):
        self.in_flight -= 1
        for item in reversed(held):
            item.release()

    async def wait_idle(self, timeout: float) -> int:
        """Wait until no sre command runs, at most *timeout* seconds; the number still running."""
        deadline = time.monotonic() + timeout
        while self.in_flight > 0:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            await asyncio.sleep(min(0.5, left))
        return self.in_flight

    # -- spawning -------------------------------------------------------------------------------

    async def _spawn(self, user: str, args, *, privileged: bool, stdin, lang=None, env=None):
        """*env*: variables added for this call (``start``: the X cookie and display number of
        the virtual desktop of the project); the agent's ``extra_env`` comes last."""
        argv = build_argv(self.sre_exe, args, privileged=privileged)
        environment = build_env(user, privileged=privileged, lang=lang)
        environment.update(env or {})
        environment.update(self.extra_env)
        env = environment
        return await asyncio.create_subprocess_exec(
            *argv, env=env,
            stdin=stdin, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True, close_fds=True, limit=STREAM_LINE_LIMIT)

    async def run(self, user: str, args, *, privileged: bool = False, stdin: bytes | None = None,
                  timeout: float | None = None, lang: str | None = None, env: dict | None = None) -> RunResult:
        """Run ``sre`` to completion: ``list``, ``eval``, ``state``, ``stop``.  Raises
        :class:`CommandError` on a non-zero exit, :class:`CommandTimeout` after *timeout*
        (default: the timeout of the command)."""
        held = await self._acquire(user, args)
        try:
            proc = await self._spawn(user, args, privileged=privileged,
                                     stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
                                     lang=lang, env=env)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(stdin), self._timeout(args, timeout))
            except TimeoutError:
                await cancel_process(proc)
                raise CommandTimeout(self._timeout(args, timeout) or 0)
        finally:
            self._release(held)
        text = stderr.decode('utf-8', 'replace')
        events = [parse_stderr_line(line) for line in text.splitlines()]
        if proc.returncode != 0:
            raise CommandError(proc.returncode, last_message(text), text)
        return RunResult(proc.returncode, stdout, text, events)

    async def stream(self, user: str, args, *, privileged: bool = False, stdin: bytes | None = None,
                     timeout: float | None = None, lang: str | None = None, env: dict | None = None) -> StreamingRun:
        """Start ``sre`` and give its stderr events as they come (``start``, ``restore``: the
        progress of the pulls and deploys, the flavor form, the ``project created`` event).
        *stdin* (``restore -``) is written then closed."""
        held = await self._acquire(user, args)
        try:
            proc = await self._spawn(user, args, privileged=privileged,
                                     stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
                                     lang=lang, env=env)
        except BaseException:
            self._release(held)
            raise
        if stdin is not None:
            asyncio.ensure_future(_feed_stdin(proc, stdin))
        return StreamingRun(proc, self._timeout(args, timeout), lambda: self._release(held))

    async def stream_stdout(self, user: str, args, *, privileged: bool = False, timeout: float | None = None,
                            chunk_size: int = 1 << 16) -> AsyncIterator[bytes]:
        """The stdout of ``sre`` chunk by chunk (``export``); :class:`CommandError`
        at the end when it failed."""
        held = await self._acquire(user, args)
        try:
            proc = await self._spawn(user, args, privileged=privileged, stdin=asyncio.subprocess.DEVNULL)
            stderr_task = asyncio.ensure_future(proc.stderr.read())
            try:
                async with asyncio.timeout(self._timeout(args, timeout)):
                    while True:
                        chunk = await proc.stdout.read(chunk_size)
                        if not chunk:
                            break
                        yield chunk
                    rc = await proc.wait()
                    stderr = (await stderr_task).decode('utf-8', 'replace')
            except TimeoutError:
                await cancel_process(proc)
                stderr_task.cancel()
                raise CommandTimeout(self._timeout(args, timeout) or 0)
            if rc != 0:
                raise CommandError(rc, last_message(stderr), stderr)
        finally:
            self._release(held)


async def _feed_stdin(proc: asyncio.subprocess.Process, data: bytes):
    try:
        proc.stdin.write(data)
        await proc.stdin.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
