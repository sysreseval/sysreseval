"""The virtual X desktop of a project: the Display tab of the web site.

A lab machine declared ``x11_host`` draws its graphical applications on the X server of the host
(``DISPLAY`` is ``SRE_HOST_IP:0`` on a workstation, see ``get_new_lab_from_scheme``).  A pool host
has no X server, so the agent runs one TigerVNC ``Xvnc`` per project whose lab has such a machine,
with a window manager on it, as an unprivileged user (``[display] user``): the containers reach
display ``:N`` on TCP port 6000+N of the host with the cookie of the project, the browser sees it
through noVNC on the RFB Unix socket of the server, relayed by the agent (``app.display_ws``).

The number and the cookie are chosen before ``sre start`` (``reserve()``: they go to the CLI as
``SRE_X11_DISPLAY`` and ``SRE_XAUTH_COOKIE``, and into the containers), kept in the state file of
the project (``Project.display``) and reused for the whole life of the project: the X server is
created lazily and again after it died or after a restart of the agent (the processes are plain
children of the agent).  The files of a display live in ``<runtime_dir>/display/``: ``<N>.sock``
(RFB, created by Xvnc, mode 0600), ``<N>.xauth`` (the cookie, 0600), ``<N>.log`` (what Xvnc and
the window manager print) and ``<N>.wm/`` (the home of the window manager).
"""
import asyncio
import contextlib
import logging
import os
import pwd
import secrets
import shlex
import shutil
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from SRE import params

from ..config import DisplayConfig
from .registry import Registry, Project

log = logging.getLogger('sreweb.agent')

X11_BASE_PORT = 6000
#: Close codes of the display WebSocket (with the 4403 / 4404 of the terminals).
WS_DISPLAY_GONE = 4404
WS_DISPLAY_FAILED = 4500
RC_FILE = Path(__file__).with_name('display-rc.xml')
STOP_GRACE = 5.0            # seconds between SIGTERM and SIGKILL of the X processes
POLL = 0.05                 # seconds between two looks for the RFB socket
LOG_TAIL = 1500             # bytes of the log quoted in an error

_FAMILY_WILD = 0xFFFF       # an Xauthority record valid for every address of the display
_AUTH_NAME = b'MIT-MAGIC-COOKIE-1'


class DisplayError(Exception):
    pass


def new_cookie() -> str:
    return secrets.token_hex(16)


def _field(data: bytes) -> bytes:
    return struct.pack('>H', len(data)) + data


def xauthority_record(number: int, cookie: str, *, family: int = _FAMILY_WILD, address: bytes = b'') -> bytes:
    """One record of an Xauthority file: family, address, display number, name and data of the
    cookie, each prefixed by its 16-bit length (``start._read_xauth_cookie_from_file`` reads it)."""
    return (struct.pack('>H', family) + _field(address) + _field(str(number).encode())
            + _field(_AUTH_NAME) + _field(bytes.fromhex(cookie)))


def parse_xauthority(blob: bytes) -> list:
    """The records of an Xauthority file: ``(family, address, number, name, data)`` tuples."""
    records, i = [], 0
    while i < len(blob):
        (family,) = struct.unpack_from('>H', blob, i)
        i += 2
        fields = []
        for _ in range(4):
            (n,) = struct.unpack_from('>H', blob, i)
            fields.append(bytes(blob[i + 2:i + 2 + n]))
            i += 2 + n
        records.append((family, *fields))
    return records


def write_xauthority(path, number: int, cookie: str, *, uid: int | None = None, gid: int | None = None):
    """The X authority file of a display, readable by its owner only."""
    path = Path(path)
    with open(path, 'wb', opener=lambda p, flags: os.open(p, flags, 0o600)) as f:
        f.write(xauthority_record(number, cookie))
    os.chmod(path, 0o600)
    if uid is not None:
        os.chown(path, uid, gid if gid is not None else -1)


def port_free(port: int) -> bool:
    """Whether nothing listens on the TCP port (every address)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('', port))
        except OSError:
            return False
    return True


@dataclass
class Reservation:
    number: int
    cookie: str


@dataclass
class DisplaySession:
    number: int
    cookie: str
    socket_path: Path
    xauth_path: Path
    log_path: Path
    home: Path
    proc: asyncio.subprocess.Process | None = None
    wm: asyncio.subprocess.Process | None = None
    error: str = ''
    reported: bool = False      # the death of the X server was logged and the clients told

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.returncode is None


class DisplayManager:
    """The virtual desktops of the projects of this host (one instance per agent)."""

    def __init__(self, cfg: DisplayConfig, *, registry: Registry):
        self.cfg = cfg
        self.registry = registry
        self.ready = False
        self.reason = "the displays are disabled on this host"
        self.uid: int | None = None
        self.gid: int | None = None
        self.sessions: dict[str, DisplaySession] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._in_flight: set = set()
        self.display_dir = Path(cfg.runtime_dir) / 'display'
        self.xvnc_argv = shlex.split(cfg.xvnc_command) if cfg.xvnc_command else []
        self.wm_argv = shlex.split(cfg.window_manager_command) if cfg.window_manager_command else []
        registry.on_removed.append(self.stop)
        registry.tick_hooks.append(self.on_tick)

    # -- availability ---------------------------------------------------------------------------

    def prepare(self):
        """At the start of the agent: whether displays can be run here (``ready``, else ``reason``):
        the configuration, the user, the X server command, the runtime directory."""
        self.ready = False
        if not self.cfg.enabled:
            self.reason = "the displays are disabled on this host"
            return
        try:
            if self.cfg.user:
                entry = pwd.getpwnam(self.cfg.user)
                self.uid, self.gid = entry.pw_uid, entry.pw_gid
            elif os.geteuid() == 0:
                raise DisplayError("display.user is required when the agent runs as root")
            for argv, what in ((self.xvnc_argv, 'xvnc_command'), (self.wm_argv, 'window_manager_command')):
                if argv and shutil.which(argv[0]) is None:
                    raise DisplayError(f"{what}: {argv[0]} not found")
            if not self.xvnc_argv:
                raise DisplayError("xvnc_command is empty")
            self.display_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.display_dir, 0o700)
            if self.uid is not None:
                os.chown(self.display_dir, self.uid, self.gid)
        except KeyError:
            self.reason = f"display.user {self.cfg.user} does not exist"
        except (OSError, DisplayError) as e:
            self.reason = str(e)
        else:
            self.ready = True
            self.reason = ''
            log.info("displays :%d-:%d in %s, user %s", self.cfg.first_display, self.cfg.last_display,
                     self.display_dir, self.cfg.user or 'the agent')
            return
        log.warning("displays unavailable: %s", self.reason)

    def offered(self, project: Project) -> bool:
        """Whether the project has a desktop to show (the host runs them and the project was
        started with one)."""
        return self.ready and project.display is not None

    # -- the number and the cookie of a new project ---------------------------------------------

    def reserve(self) -> Reservation:
        """A display number nobody uses (no known project, no lock file of an X server, nobody on
        its TCP port) and a fresh cookie, for a ``sre start`` to come; released or committed."""
        used = {p.display['number'] for p in self.registry.projects.values() if p.display} | self._in_flight
        for number in range(self.cfg.first_display, self.cfg.last_display + 1):
            if number in used or Path(f'/tmp/.X{number}-lock').exists() or not port_free(X11_BASE_PORT + number):
                continue
            self._in_flight.add(number)
            return Reservation(number, new_cookie())
        raise DisplayError("no free display number on this host")

    @staticmethod
    def env_for(reservation: Reservation) -> dict:
        """What ``sre start`` needs: the cookie and the display number of the containers."""
        return {params.sre_xauth_cookie_env_variable: reservation.cookie,
                params.sre_x11_display_env_variable: str(reservation.number)}

    def release(self, reservation: Reservation):
        self._in_flight.discard(reservation.number)

    def commit(self, project: Project, reservation: Reservation):
        """The project started with the reservation: remembered in its state, the desktop
        created in the background."""
        self._in_flight.discard(reservation.number)
        project.display = {'number': reservation.number, 'cookie': reservation.cookie}
        self.registry.write_state(project, force=True)
        asyncio.ensure_future(self._ensure_logged(project))

    async def _ensure_logged(self, project: Project):
        try:
            await self.ensure(project)
        except DisplayError as e:
            log.warning("display of %s: %s", project.rln, e)

    # -- the processes --------------------------------------------------------------------------

    def _paths(self, number: int) -> dict:
        d = self.display_dir
        return {'socket_path': d / f'{number}.sock', 'xauth_path': d / f'{number}.xauth',
                'log_path': d / f'{number}.log', 'home': d / f'{number}.wm'}

    async def ensure(self, project: Project) -> DisplaySession:
        """The running X server of the project, started if needed (``DisplayError`` when it cannot
        be)."""
        if not self.ready:
            raise DisplayError(self.reason)
        if not project.display:
            raise DisplayError("no display for this project")
        lock = self._locks.setdefault(project.rln, asyncio.Lock())
        async with lock:
            session = self.sessions.get(project.rln)
            if session is not None and session.running:
                return session
            if session is not None:
                await self._end(session)
            session = await self._start(project)
            self.sessions[project.rln] = session
            return session

    def _child_kwargs(self) -> dict:
        kwargs = dict(stdin=asyncio.subprocess.DEVNULL, start_new_session=True, close_fds=True, umask=0o077)
        if self.uid is not None:
            kwargs.update(user=self.uid, group=self.gid, extra_groups=[])
        return kwargs

    async def _start(self, project: Project) -> DisplaySession:
        number, cookie = project.display['number'], project.display['cookie']
        session = DisplaySession(number, cookie, **self._paths(number))
        try:
            session.home.mkdir(mode=0o700, exist_ok=True)
            if self.uid is not None:
                os.chown(session.home, self.uid, self.gid)
            write_xauthority(session.xauth_path, number, cookie, uid=self.uid, gid=self.gid)
            with contextlib.suppress(FileNotFoundError):
                session.socket_path.unlink()
            argv = self.xvnc_argv + [
                f':{number}', '-rfbunixpath', str(session.socket_path), '-rfbunixmode', '0600', '-rfbport', '-1',
                '-SecurityTypes', 'None', '-AlwaysShared', '-AcceptSetDesktopSize', '-geometry', self.cfg.geometry,
                '-depth', str(self.cfg.depth), '-FrameRate', str(self.cfg.frame_rate),
                '-desktop', f"{project.lab_name} ({project.owner})", '-auth', str(session.xauth_path), '-listen', 'tcp']
            env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'), 'HOME': str(session.home),
                   'LANG': 'C.UTF-8', 'XAUTHORITY': str(session.xauth_path)}
            with open(session.log_path, 'ab') as logfile:
                session.proc = await asyncio.create_subprocess_exec(
                    *argv, cwd=session.home, env=env, stdout=logfile, stderr=asyncio.subprocess.STDOUT,
                    **self._child_kwargs())
                deadline = time.monotonic() + self.cfg.start_timeout
                while not session.socket_path.exists():
                    if session.proc.returncode is not None:
                        raise DisplayError(f"the X server exited ({session.proc.returncode}): {self._log_tail(session)}")
                    if time.monotonic() > deadline:
                        raise DisplayError("the X server did not come up in time")
                    await asyncio.sleep(POLL)
                if self.wm_argv:
                    wm_argv = list(self.wm_argv)
                    if os.path.basename(wm_argv[0]) == 'openbox':
                        wm_argv += ['--config-file', str(RC_FILE)]
                    session.wm = await asyncio.create_subprocess_exec(
                        *wm_argv, cwd=session.home, stdout=logfile, stderr=asyncio.subprocess.STDOUT,
                        env=dict(env, DISPLAY=f':{number}', XDG_CONFIG_HOME=str(session.home),
                                 XDG_CONFIG_DIRS=str(session.home), XDG_DATA_HOME=str(session.home)),
                        **self._child_kwargs())
        except OSError as e:
            await self._end(session)
            raise DisplayError(f"cannot start the X server: {e}")
        except DisplayError as e:
            session.error = str(e)
            await self._end(session)
            raise
        log.info("display :%d of %s started (pid %d)", number, project.rln, session.proc.pid)
        return session

    def _log_tail(self, session: DisplaySession) -> str:
        try:
            with open(session.log_path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - LOG_TAIL))
                return f.read().decode('utf-8', 'replace').strip()
        except OSError:
            return ''

    async def _end(self, session: DisplaySession):
        """Stop the processes of a session (the window manager first) and remove its files."""
        for proc in (session.wm, session.proc):
            if proc is None or proc.returncode is not None:
                continue
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), STOP_GRACE)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
        for path in (session.socket_path, session.xauth_path, session.log_path):
            with contextlib.suppress(OSError):
                path.unlink()
        with contextlib.suppress(OSError):
            shutil.rmtree(session.home)

    async def _close_clients(self, project: Project, code: int, message: str):
        clients, project.display_clients = list(project.display_clients), []
        for ws in clients:
            with contextlib.suppress(Exception):
                await ws.close(code=code, message=message.encode())

    async def stop(self, project: Project):
        """The project is gone (or the agent stops): its desktop too."""
        session = self.sessions.pop(project.rln, None)
        self._locks.pop(project.rln, None)
        await self._close_clients(project, WS_DISPLAY_GONE, "the project is gone")
        if session is not None:
            await self._end(session)
            log.info("display :%d of %s stopped", session.number, project.rln)

    async def stop_all(self):
        for project in list(self.registry.projects.values()):
            await self.stop(project)
        for rln in list(self.sessions):
            await self._end(self.sessions.pop(rln))

    async def on_tick(self, project: Project):
        """A dead X server: logged once, its viewers told; the next request starts another."""
        session = self.sessions.get(project.rln)
        if session is None or session.running or session.reported:
            return
        session.reported = True
        session.error = f"the X server exited ({session.proc.returncode})"
        log.warning("display :%d of %s: %s", session.number, project.rln, session.error)
        await self._close_clients(project, WS_DISPLAY_FAILED, session.error)

    # -- what the API reports -------------------------------------------------------------------

    def status(self, project: Project, available: bool) -> dict:
        session = self.sessions.get(project.rln)
        return {'available': bool(available and self.offered(project)),
                'running': bool(session is not None and session.running),
                'display': project.display['number'] if project.display else None,
                'geometry': self.cfg.geometry,
                'error': (session.error if session is not None else '') or ('' if self.ready else self.reason)}

    def running_count(self) -> int:
        return sum(1 for s in self.sessions.values() if s.running)
