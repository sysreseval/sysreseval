"""The running projects of the host, as the agent sees them.

Like the Qt GUI (``MainWindow._scan_projects``, ``ProjectWidget.refresh``), the agent polls the
projects directory every second: a new directory holding ``info.json`` is a project, a vanished
one is gone, a newer ``info.json`` is reloaded, ``answers/cheat.json`` is consumed and
``operations.log`` is tailed.  The subscribers of a project (the event WebSockets of the open
browser pages) are told through :meth:`Registry.broadcast`; the other per-tick jobs (the answers
store, the schedulers) register themselves as tick hooks.

Polling first: one ``scandir`` and three ``stat`` per project per second cost nothing, and the
one-second latency is the one the Qt GUI has today.  The mechanism is hidden behind this class so
that inotify can replace it later.
"""
import asyncio
import codecs
import contextlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from SRE import params
from sysreseval.util import load_projects, load_info

from .access import AccessError
from ..identity import Identity

log = logging.getLogger('sreweb.agent')

#: Events pushed to the subscribers of a project.
EVENT_INFO = 'info'
EVENT_ANSWERS = 'answers'
EVENT_LOG = 'log'
EVENT_REMOVED = 'removed'
EVENT_TERMINALS = 'terminals'
EVENT_EVALUATED = 'evaluated'   # a new archived evaluation (periodic, the student's, an instructor's)

LOG_CHUNK = 1 << 18          # bytes of operations.log read per tick at most
STATE_WRITE_INTERVAL = 60.0  # seconds between two writes of the state file of a project
_HEX = re.compile(r'[0-9A-Fa-f]+')


@dataclass
class Subscriber:
    send: Callable[[dict], Awaitable[None]]
    identity: Identity


@dataclass
class Project:
    rln: str
    path: Path
    owner: str
    lab_name: str
    started: str
    info: dict
    info_mtime: float
    debug: bool = False
    instructor: bool = False
    log_offset: int = 0
    log_decoder: codecs.IncrementalDecoder = field(default_factory=lambda: codecs.getincrementaldecoder('utf-8')('replace'))
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    answers_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_activity: float = field(default_factory=time.monotonic)
    idle_timeout: float | None = None       # seconds, None: the default of the agent, 0: never
    next_eval_at: float | None = None
    closing: bool = False
    #: Created by this agent (a state file exists): the schedulers act on managed projects only;
    #: a project started by the Qt GUI on the same host is listed to its owner, nothing more.
    managed: bool = False
    created_at: float = field(default_factory=time.time)
    subscribers: list = field(default_factory=list)
    #: The live terminal sessions (``terminals.TerminalSession``) by session id; a session is
    #: shared by every browser attached to it (the owner's, the instructors who joined).
    terminals: dict = field(default_factory=dict)
    _terminals_push_pending: bool = False
    #: The virtual X desktop of the project ({'number', 'cookie'}, kept in the state file: the
    #: containers were started with them), and the open display WebSockets (``display.py``).
    display: dict | None = None
    display_clients: list = field(default_factory=list)
    _state_written: float = 0.0

    @property
    def holds_instructor_texts(self) -> bool:
        return self.debug or self.instructor

    # the files of the project, from its own path (not from params.sre_projects_dir: the agent may
    # watch another directory, as the tests do)
    @property
    def private_dir(self) -> Path:
        return self.path / params.private_dir_name

    @property
    def answers_path(self) -> Path:
        return self.path / params.answer_dir_name / params.answer_file_name

    @property
    def cheat_path(self) -> Path:
        return self.path / params.answer_dir_name / params.cheat_file_name

    @property
    def log_path(self) -> Path:
        return self.path / params.operations_log_name

    def read_markers(self):
        self.debug = (self.private_dir / params.debug_project_marker_name).exists()
        self.instructor = (self.private_dir / params.instructor_mode_marker_name).exists()

    def terminal_count(self) -> int:
        """The live sessions (a browser joining a session opens no new one)."""
        return len(self.terminals)

    def terminals_on(self, device: str) -> int:
        return sum(1 for t in self.terminals.values() if getattr(t, 'device', None) == device)

    def terminal_list(self, identity: Identity) -> list:
        """The live sessions as the browser of *identity* may list them: the private ones (an
        instructor's, hidden from the student) only to instructors; oldest first."""
        sessions = [t for t in self.terminals.values() if not getattr(t, 'closing', False)
                    and (not getattr(t, 'private', False) or identity.is_instructor)]
        return [t.to_dict() for t in sorted(sessions, key=lambda t: getattr(t, 'created_at', 0.0))]

    def touch(self):
        self.last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        return time.monotonic() - self.last_activity

    def to_dict(self) -> dict:
        return {
            'running_lab_name': self.rln,
            'lab_name': self.lab_name,
            'owner': self.owner,
            'started_at': self.started,
            'title': self.info.get('title', ''),
            'debug_project': bool(self.info.get('debug_project', False)),
            'instructor_mode': bool(self.info.get('instructor_mode', False)),
            'info_mtime': self.info_mtime,
            'terminals': self.terminal_count(),
            'managed': self.managed,
            'eval_interval': int(self.info.get('eval_interval_without_exam_mode', 0) or 0),
        }


TickHook = Callable[[Project], Awaitable[None]]


class Registry:
    def __init__(self, projects_dir: str, *, poll_interval: float = 1.0, state_dir: str = ''):
        self.projects_dir = Path(projects_dir)
        self.poll_interval = poll_interval
        self.state_dir = Path(state_dir) if state_dir else None
        self.projects: dict[str, Project] = {}
        self.tick_hooks: list[TickHook] = []
        self.on_added: list[Callable[[Project], None]] = []
        self.on_info_changed: list[Callable[[Project], None]] = []
        #: Called when a project created by this agent is adopted (:meth:`adopt`): the tick has
        #: usually found its directory before ``sre start`` ended, as a project of somebody else.
        self.on_managed: list[Callable[[Project], None]] = []
        #: Awaited for every project whose directory vanished, and for every project at stop().
        self.on_removed: list[Callable[[Project], Awaitable[None]]] = []
        #: Builds the ``info`` event of a subscriber (set by the app: the sanitised view).
        self.info_event: Callable[[Project, Identity], dict] | None = None
        #: Whether a subscriber may read the operations log of a project (set by the app: debug
        #: projects, and the instructor view of an instructor-mode project); everybody without it.
        self.log_allowed: Callable[[Project, Identity], bool] | None = None
        self._task: asyncio.Task | None = None

    # -- lookup ---------------------------------------------------------------------------------

    def get(self, rln: str) -> Project | None:
        return self.projects.get(rln)

    def require(self, rln: str) -> Project:
        project = self.projects.get(rln)
        if project is None or project.closing:
            raise AccessError(404, "unknown project")
        return project

    def visible_to(self, identity: Identity, *, all_projects: bool = False) -> list:
        """The projects a user lists: their own; every one of the host with *all_projects* (the
        Watch page of the instructors: the caller checks the role)."""
        projects = [p for p in self.projects.values() if not p.closing]
        if all_projects:
            return projects
        return [p for p in projects if p.owner == identity.login]

    def count(self) -> int:
        return len(self.projects)

    # -- scanning -------------------------------------------------------------------------------

    def _load_state(self, project: Project):
        if self.state_dir is None:
            return
        try:
            with open(self.state_dir / f"{project.rln}.json", encoding='utf-8') as f:
                state = json.load(f)
        except (OSError, ValueError):
            return
        if isinstance(state, dict):
            project.managed = True
            idle = state.get('idle_timeout')
            project.idle_timeout = float(idle) if isinstance(idle, (int, float)) else None
            # the idle clock of the previous agent, kept across restarts
            last = state.get('last_activity_at')
            if isinstance(last, (int, float)):
                project.last_activity = time.monotonic() - max(0.0, time.time() - last)
            created = state.get('created_at')
            if isinstance(created, (int, float)):
                project.created_at = created
            display = state.get('display')
            if (isinstance(display, dict) and isinstance(display.get('number'), int)
                    and not isinstance(display.get('number'), bool) and isinstance(display.get('cookie'), str)
                    and _HEX.fullmatch(display['cookie'])):
                project.display = {'number': display['number'], 'cookie': display['cookie']}

    def write_state(self, project: Project, force: bool = False):
        """The state file of a managed project (idle clock, idle timeout), at most once a minute."""
        if self.state_dir is None or not project.managed:
            return
        now = time.monotonic()
        if not force and now - project._state_written < STATE_WRITE_INTERVAL:
            return
        project._state_written = now
        state = {'idle_timeout': project.idle_timeout, 'created_at': project.created_at,
                 'last_activity_at': time.time() - project.idle_seconds(), 'owner': project.owner}
        if project.display:
            state['display'] = dict(project.display)
        try:
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            tmp = self.state_dir / f".{project.rln}.json.tmp"
            tmp.write_text(json.dumps(state), encoding='utf-8')
            os.replace(tmp, self.state_dir / f"{project.rln}.json")
        except OSError as e:
            log.warning("cannot write the state of %s: %s", project.rln, e)

    def _remove_state(self, rln: str):
        if self.state_dir is not None:
            with contextlib.suppress(OSError):
                os.unlink(self.state_dir / f"{rln}.json")

    def _new_project(self, path: Path) -> Project | None:
        rln = path.name
        try:
            info = load_info(path)
            mtime = os.path.getmtime(path / params.info_json_name)
            owner = params.get_username_from_running_lab_name(rln)
            started = rln.split('@@@', 1)[0]
        except (OSError, ValueError, AttributeError) as e:
            log.warning("ignoring %s: %s", path, e)
            return None
        if not isinstance(info, dict):
            return None
        # the canonical lab name (with slashes) is in info.json; the directory name carries it with @
        lab_name = info.get('lab_name') or params.get_lab_name_from_running_lab_name(rln)
        project = Project(rln=rln, path=path, owner=owner, lab_name=lab_name, started=started, info=info,
                          info_mtime=mtime)
        project.read_markers()
        self._load_state(project)
        return project

    def scan_once(self) -> tuple[list, list]:
        """Discover new project directories and forget the vanished ones: ``(added, removed)``."""
        try:
            paths = {p.name: p for p in load_projects()} if str(self.projects_dir) == params.sre_projects_dir \
                else {p.name: p for p in self._iter_dirs()}
        except OSError:
            paths = {}
        added, removed = [], []
        for rln in list(self.projects):
            if rln not in paths:
                removed.append(self.projects.pop(rln))
        for rln, path in paths.items():
            if rln not in self.projects:
                project = self._new_project(path)
                if project is not None:
                    self.projects[rln] = project
                    added.append(project)
        return added, removed

    def _iter_dirs(self):
        if not self.projects_dir.is_dir():
            return []
        return [d for d in sorted(self.projects_dir.iterdir())
                if d.is_dir() and '@@@' in d.name and (d / params.info_json_name).exists()]

    def refresh_info(self, project: Project) -> bool:
        """Reload ``info.json`` when its mtime changed (``sre eval`` rewrites it when the lab
        file is newer); a transient unreadable file is retried at the next tick."""
        try:
            mtime = os.path.getmtime(project.path / params.info_json_name)
        except OSError:
            return False
        if mtime == project.info_mtime:
            return False
        try:
            info = load_info(project.path)
        except (OSError, ValueError):
            return False
        if not isinstance(info, dict):
            return False
        project.info = info
        project.info_mtime = mtime
        project.read_markers()
        return True

    def read_log(self, project: Project) -> tuple[str, bool]:
        """What ``operations.log`` gained since the last tick: ``(text, reset)``, *reset* when
        the file shrank (the tail starts again from the beginning)."""
        path = project.log_path
        try:
            size = os.path.getsize(path)
        except OSError:
            return '', False
        reset = False
        if size < project.log_offset:
            project.log_offset = 0
            project.log_decoder.reset()
            reset = True
        if size == project.log_offset:
            return '', reset
        try:
            with open(path, 'rb') as f:
                f.seek(project.log_offset)
                data = f.read(LOG_CHUNK)
        except OSError:
            return '', reset
        project.log_offset += len(data)
        return project.log_decoder.decode(data), reset

    # -- subscribers ----------------------------------------------------------------------------

    def subscribe(self, project: Project, send, identity: Identity) -> Subscriber:
        sub = Subscriber(send, identity)
        project.subscribers.append(sub)
        return sub

    def unsubscribe(self, project: Project, sub: Subscriber):
        with contextlib.suppress(ValueError):
            project.subscribers.remove(sub)

    async def broadcast(self, project: Project, event, *, only: Callable[[Identity], bool] | None = None):
        """Send an event to every subscriber (those *only* accepts, when given): a dict, or a
        callable of the subscriber's identity giving the dict (the ``info`` event differs by role)."""
        for sub in list(project.subscribers):
            if only is not None and not only(sub.identity):
                continue
            try:
                payload = event(sub.identity) if callable(event) else event
                await sub.send(payload)
            except Exception as e:   # a dead socket must not stop the others
                log.debug("subscriber of %s dropped: %s", project.rln, e)
                self.unsubscribe(project, sub)

    # -- the loop -------------------------------------------------------------------------------

    async def adopt(self, rln: str) -> Project | None:
        """Take a project just created by this agent (``sre start`` / ``sre restore``) into
        account at once, without waiting for the next tick: it becomes managed.  The tick has
        usually found its directory already (``info.json`` is written long before ``sre start``
        ends), as a project of somebody else: the ``on_managed`` hooks then plan what the
        ``on_added`` ones could not (the periodic evaluation)."""
        added, removed = self.scan_once()
        await self._apply_scan(added, removed)
        project = self.projects.get(rln)
        if project is not None:
            project.managed = True
            self.write_state(project, force=True)
            log.info("project adopted: %s", rln)
            for cb in self.on_managed:
                cb(project)
        return project

    async def _apply_scan(self, added, removed):
        for project in removed:
            log.info("project gone: %s", project.rln)
            self._remove_state(project.rln)
            await self._close_terminals(project)
            await self._run_removed_hooks(project)
            await self.broadcast(project, {'t': EVENT_REMOVED})
            project.subscribers.clear()
        for project in added:
            log.info("project found: %s%s", project.rln, "" if project.managed else " (not managed by this agent)")
            for cb in self.on_added:
                cb(project)

    async def tick(self):
        added, removed = self.scan_once()
        await self._apply_scan(added, removed)
        for project in list(self.projects.values()):
            if self.refresh_info(project):
                for cb in self.on_info_changed:
                    cb(project)
                if self.info_event is not None:
                    await self.broadcast(project, lambda identity, p=project: self.info_event(p, identity))
            if project.holds_instructor_texts and project.subscribers:
                allowed = (lambda identity: True) if self.log_allowed is None \
                    else (lambda identity, p=project: self.log_allowed(p, identity))
                if any(allowed(sub.identity) for sub in project.subscribers):
                    text, reset = self.read_log(project)
                    if text or reset:
                        await self.broadcast(project, {'t': EVENT_LOG, 'data': text, 'reset': reset}, only=allowed)
            for hook in self.tick_hooks:
                try:
                    await hook(project)
                except Exception:
                    log.exception("tick hook failed on %s", project.rln)
            self.write_state(project)

    async def run(self):
        while True:
            try:
                await self.tick()
            except Exception:
                log.exception("registry tick failed")
            await asyncio.sleep(self.poll_interval)

    def start(self):
        self._task = asyncio.ensure_future(self.run())

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        for project in list(self.projects.values()):
            await self._close_terminals(project)
            await self._run_removed_hooks(project)

    async def _run_removed_hooks(self, project: Project):
        for hook in self.on_removed:
            try:
                await hook(project)
            except Exception:
                log.exception("removal hook failed on %s", project.rln)

    @staticmethod
    async def _close_terminals(project: Project):
        sessions = list(project.terminals.values())
        project.terminals.clear()
        for session in sessions:
            with contextlib.suppress(Exception):
                await session.close()
