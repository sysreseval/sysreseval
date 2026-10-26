"""The pool of hosts: the status of their agents, the state of each host, the placement of a
new project, the fan-out of the project lists, and the membership changed by hand
(``sre-web-tool add / remove / enable / disable``, kept in a state file merged with the
``[[hosts]]`` of the configuration)."""
import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict

import aiohttp

from ..agent.occupancy import SESSION_PREFIX
from ..config import HostConfig, host_config_from_dict, ConfigError
from ..identity import Identity

log = logging.getLogger('sreweb.portal')

STATUS_TIMEOUT = 5.0

#: The states of a host, as the portal sees it.
STATE_OFF = 'off'              # agent unreachable
STATE_WAKING = 'waking'        # a wake was sent, the agent not up yet
STATE_UP = 'up'                # agent up, free: new projects go there
STATE_OCCUPIED = 'occupied'    # agent up, the machine is used locally: no new project but its local users'
STATE_EXAM = 'exam'            # agent up, exam.json on the host
STATE_DRAINING = 'draining'    # agent up, a power off is wanted: no new project
STATE_DISABLED = 'disabled'    # taken out of the placement by hand
SOURCE_CONFIG = 'config'
SOURCE_ADDED = 'added'
#: Why a host was chosen (the ``placement`` field of the ``start`` line of the connection log).
PLACEMENT_LOAD = 'load'          # the least loaded host
PLACEMENT_SESSION = 'session'    # the host of a local login session of the user (follow_local_sessions)
PLACEMENT_NAMED = 'named'        # the host an instructor named


class PoolError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


@dataclass
class Reservation:
    released_at: float | None = None
    placement: str = PLACEMENT_LOAD


@dataclass
class HostStatus:
    """What the last status poll of the agent said."""
    reachable: bool = False
    projects: int = 0
    managed_projects: int = 0
    local_projects: int = 0
    terminals: int = 0
    load1: float | None = None
    exam_mode: bool = False
    occupied: bool = False
    occupied_by: list = field(default_factory=list)
    uptime: int | None = None
    power_off_allowed: bool = False
    hostname: str = ''
    sre_version: str = ''
    error: str = ''
    updated: float = field(default_factory=time.monotonic)


@dataclass
class HostRuntime:
    """What the portal remembers about a host between polls."""
    source: str = SOURCE_CONFIG
    enabled: bool = True
    woken_at: float | None = None      # monotonic time of the last wake, None when not waking
    wake_failures: int = 0
    next_wake_at: float = 0.0          # backoff after failed wakes
    idle_since: float | None = None    # monotonic time since the host has no project
    drain: bool = False                # power off wanted as soon as the host is empty
    power_off_sent: float | None = None   # monotonic time of the last accepted power off
    last_wake_reason: str = ''


class Pool:
    def __init__(self, hosts: list, session, *, poll_interval: float = 2.0, wake_timeout: float = 180.0,
                 state_file: str = '', follow_local_sessions: bool = True):
        self.hosts: dict[str, HostConfig] = {}
        self.status: dict[str, HostStatus] = {}
        self.runtime: dict[str, HostRuntime] = {}
        self.session = session
        self.poll_interval = poll_interval
        self.wake_timeout = wake_timeout
        self.state_file = state_file
        self.follow_local_sessions = follow_local_sessions
        self._config_hosts = {h.name: h for h in hosts}
        self._removed: set = set()      # config hosts removed by hand (``enable`` brings them back)
        #: The projects being started on each host: a reservation counts as a project until the
        #: start is over (``release``) and a status polled after that has been received, so that
        #: a stale poll never frees the slot early.
        self._reservations: dict[str, list] = {}
        self._reported: dict[str, bool] = {}
        self._task: asyncio.Task | None = None
        for host in hosts:
            self._register(host, SOURCE_CONFIG)
        self.load_state()

    # -- membership -----------------------------------------------------------------------------

    def _register(self, host: HostConfig, source: str):
        self.hosts[host.name] = host
        self.status[host.name] = HostStatus()
        self.runtime[host.name] = HostRuntime(source=source, enabled=host.enabled)
        self._reservations[host.name] = []
        self._reported.pop(host.name, None)

    def host(self, name: str) -> HostConfig:
        host = self.hosts.get(name)
        if host is None:
            raise PoolError(404, "unknown host")
        return host

    def add_host(self, host: HostConfig):
        """``sre-web-tool add``: a host added by hand (an added host of the same name is
        replaced; a config host of that name cannot be redefined)."""
        if host.name in self._config_hosts:
            raise PoolError(409, f"{host.name} is in the configuration file: edit it there"
                            + (", or enable it" if host.name in self._removed else ""))
        self._register(host, SOURCE_ADDED)
        self.save_state()
        log.info("host %s added to the pool (%s)", host.name, host.url)

    def remove_host(self, name: str, force: bool = False):
        """``sre-web-tool remove``: refused while the host has projects, unless forced (they
        stay on the host, out of the portal's reach: the agent's idle reaper closes them)."""
        self.host(name)
        projects = self.status[name].projects if self.status[name].reachable else 0
        if projects and not force:
            raise PoolError(409, f"{name} has {projects} project(s): drain it first, or --force")
        if self.runtime[name].source == SOURCE_CONFIG:
            self._removed.add(name)
        for table in (self.hosts, self.status, self.runtime, self._reservations):
            table.pop(name, None)
        self._reported.pop(name, None)
        self.save_state()
        log.info("host %s removed from the pool", name)

    def set_enabled(self, name: str, enabled: bool):
        """``enable`` / ``disable``: a disabled host stays polled and listed but gets no project;
        ``enable`` also cancels a drain, and brings back a config host removed by hand."""
        if name in self._removed and enabled:
            self._removed.discard(name)
            self._register(self._config_hosts[name], SOURCE_CONFIG)
            self.save_state()
            log.info("host %s back in the pool from the configuration", name)
            return
        self.host(name)
        self.runtime[name].enabled = enabled
        if enabled:
            self.runtime[name].drain = False
        self.save_state()
        log.info("host %s %s", name, 'enabled' if enabled else 'disabled')

    def load_state(self):
        """The hosts added, removed and disabled by hand (``state_file``), over the configuration."""
        if not self.state_file:
            return
        try:
            with open(self.state_file, encoding='utf-8') as f:
                state = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            log.error("cannot read %s: %s", self.state_file, e)
            return
        if not isinstance(state, dict):
            return
        for name in state.get('removed', []) or []:
            if name in self.hosts and self.runtime[name].source == SOURCE_CONFIG:
                for table in (self.hosts, self.status, self.runtime, self._reservations):
                    table.pop(name, None)
                self._removed.add(name)
        for entry in state.get('added', []) or []:
            try:
                host = host_config_from_dict(entry, f"{self.state_file}: added host")
            except ConfigError as e:
                log.error("%s", e)
                continue
            if host.name in self.hosts and self.runtime[host.name].source == SOURCE_CONFIG:
                continue
            self._register(host, SOURCE_ADDED)
        for name in state.get('disabled', []) or []:
            if name in self.runtime:
                self.runtime[name].enabled = False
        log.info("pool state read from %s: %d removed, %d added, %d disabled", self.state_file,
                 len(self._removed), sum(1 for r in self.runtime.values() if r.source == SOURCE_ADDED),
                 sum(1 for r in self.runtime.values() if not r.enabled))

    def save_state(self):
        if not self.state_file:
            return
        state = {
            'removed': sorted(self._removed),
            'added': [asdict(self.hosts[n]) for n, r in self.runtime.items() if r.source == SOURCE_ADDED],
            'disabled': sorted(n for n, r in self.runtime.items() if not r.enabled),
        }
        try:
            os.makedirs(os.path.dirname(self.state_file) or '.', exist_ok=True)
            tmp = self.state_file + '.tmp'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, self.state_file)
        except OSError as e:
            log.error("cannot write %s: %s", self.state_file, e)

    # -- status ---------------------------------------------------------------------------------

    @staticmethod
    def headers(host: HostConfig, identity: Identity | None = None) -> dict:
        headers = {'Authorization': f'Bearer {host.token}'}
        if identity is not None:
            headers.update(identity.headers())
        return headers

    def _consume(self, name: str, polled_at: float) -> int:
        """Forget the reservations released before the status request sent at *polled_at*;
        the number still counted."""
        self._reservations[name] = [r for r in self._reservations[name]
                                    if r.released_at is None or r.released_at > polled_at]
        return len(self._reservations[name])

    async def refresh_host(self, host: HostConfig) -> HostStatus:
        polled_at = time.monotonic()
        try:
            async with self.session.get(f"{host.url}/v1/status", headers=self.headers(host),
                                        timeout=aiohttp.ClientTimeout(total=STATUS_TIMEOUT)) as resp:
                if resp.status != 200:
                    status = HostStatus(error=f"status {resp.status}")
                else:
                    data = await resp.json()
                    status = HostStatus(reachable=True,
                                        projects=int(data.get('projects', 0)) + self._consume(host.name, polled_at),
                                        managed_projects=int(data.get('managed_projects', 0)),
                                        local_projects=int(data.get('local_projects', 0)),
                                        terminals=int(data.get('terminals', 0)), load1=data.get('load1'),
                                        exam_mode=bool(data.get('exam_mode', False)),
                                        occupied=bool(data.get('occupied', False)),
                                        occupied_by=list(data.get('occupied_by', []) or []),
                                        uptime=data.get('uptime'),
                                        power_off_allowed=bool(data.get('power_off_allowed', False)),
                                        hostname=str(data.get('hostname', '')),
                                        sre_version=str(data.get('sre_version', '')))
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            status = HostStatus(error=str(e) or type(e).__name__)
        if host.name not in self.status:
            return status   # removed meanwhile
        previous = self._reported.get(host.name)   # None at the first poll: always reported
        self._reported[host.name] = status.reachable
        if previous is None or previous != status.reachable:
            if status.reachable:
                log.info("host %s reachable: %s, sre %s, %d project(s)%s", host.name, status.hostname,
                         status.sre_version, status.projects, " (occupied)" if status.occupied else "")
            else:
                log.warning("host %s unreachable at %s: %s", host.name, host.url, status.error)
        runtime = self.runtime[host.name]
        if status.reachable and previous is False:
            # back after a shutdown: a drain, a power off and a backoff of the previous run are over
            runtime.drain = False
            runtime.power_off_sent = None
            runtime.next_wake_at = 0.0
        elif not status.reachable and runtime.power_off_sent is not None:
            runtime.drain = False           # gone after its power off: the drain is done
            runtime.power_off_sent = None
        if status.reachable and runtime.woken_at is not None:
            log.info("host %s is up %.0f s after its wake", host.name, time.monotonic() - runtime.woken_at)
            runtime.woken_at = None
            runtime.wake_failures = 0
            runtime.next_wake_at = 0.0
        self.status[host.name] = status
        return status

    async def refresh(self):
        await asyncio.gather(*(self.refresh_host(h) for h in list(self.hosts.values())))

    async def _loop(self):
        while True:
            try:
                await self.refresh()
            except Exception:
                log.exception("pool refresh failed")
            await asyncio.sleep(self.poll_interval)

    def start(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # -- states -----------------------------------------------------------------------------------

    def state_of(self, name: str, now: float | None = None) -> str:
        st, rt = self.status[name], self.runtime[name]
        now = time.monotonic() if now is None else now
        if not rt.enabled:
            return STATE_DISABLED
        if not st.reachable:
            return STATE_WAKING if rt.woken_at is not None and now - rt.woken_at < self.wake_timeout else STATE_OFF
        if st.exam_mode:
            return STATE_EXAM
        if st.occupied:
            return STATE_OCCUPIED
        if rt.drain:
            return STATE_DRAINING
        return STATE_UP

    def summary(self, now: float | None = None) -> list:
        now = time.monotonic() if now is None else now
        rows = []
        for h in self.hosts.values():
            st, rt = self.status[h.name], self.runtime[h.name]
            rows.append({
                'name': h.name, 'url': h.url, 'max_projects': h.max_projects, 'state': self.state_of(h.name, now),
                'source': rt.source, 'enabled': rt.enabled, 'can_wake': h.can_wake, 'power': h.power,
                'instructors_only': h.instructors_only,
                'drain': rt.drain, 'power_off_sent': rt.power_off_sent is not None,
                'waking_for': round(now - rt.woken_at) if rt.woken_at is not None else None,
                'wake_failures': rt.wake_failures,
                'idle_for': round(now - rt.idle_since) if rt.idle_since is not None else None,
                **{k: v for k, v in vars(st).items() if k != 'updated'},
            })
        return rows

    # -- placement ------------------------------------------------------------------------------

    def pick(self, identity: Identity | None = None, host: str | None = None) -> tuple:
        """The host of a new project and its reservation.  Without *host*: the host of a local
        login session of *identity* (``follow_local_sessions``: the workstation the user sits at,
        occupied by them, whatever its load), else the least loaded (projects / max_projects, then
        load) of the hosts up (enabled, reachable, not occupied, not in exam mode, not draining);
        always below their maximum and among the hosts *identity* may use: a host with
        ``instructors_only`` takes an instructor's project only, and the caller is a student
        without identity.  With *host* (an instructor naming one on the Open page): that host,
        when the identity may use it (403 otherwise), it is available to them (503) and has room
        (503).  The caller releases the reservation when the start is over."""
        instructor = identity is not None and identity.is_instructor
        now = time.monotonic()
        if host is not None:
            chosen = self.host(host)
            if chosen.instructors_only and not instructor:
                raise PoolError(403, "instructors only")
            if not self._available_to(chosen, identity, self.state_of(host, now))[0]:
                raise PoolError(503, f"the host {host} is not available", retry_after=60)
            if self.status[host].projects >= chosen.max_projects:
                raise PoolError(503, f"the host {host} is full", retry_after=60)
            return self._reserve(chosen, PLACEMENT_NAMED)
        candidates = []
        waking = False
        for h in self.hosts.values():
            if h.instructors_only and not instructor:
                continue
            state = self.state_of(h.name, now)
            waking = waking or state == STATE_WAKING
            available, placement = self._available_to(h, identity, state)
            st = self.status[h.name]
            if not available or st.projects >= h.max_projects:
                continue
            candidates.append((placement != PLACEMENT_SESSION, st.projects / h.max_projects,
                               st.load1 if st.load1 is not None else 0.0, h.name, h, placement))
        if not candidates:
            if waking:
                raise PoolError(503, "a host is starting, please retry in a moment", retry_after=30)
            raise PoolError(503, "no host available for a new project", retry_after=60)
        candidates.sort(key=lambda c: c[:4])
        return self._reserve(candidates[0][4], candidates[0][5])

    def _available_to(self, h: HostConfig, identity: Identity | None, state: str) -> tuple:
        """Whether a new project of *identity* may go on *h*, in *state*, and what the placement
        would be: a host up (``PLACEMENT_LOAD``), or a host occupied by a local login session of
        the user (``PLACEMENT_SESSION``, with ``follow_local_sessions``; not when a power off is
        wanted: ``state_of`` hides the drain behind the occupation)."""
        if state == STATE_UP:
            return True, PLACEMENT_LOAD
        if (state == STATE_OCCUPIED and self.follow_local_sessions and identity is not None
                and not self.runtime[h.name].drain
                and SESSION_PREFIX + identity.login in self.status[h.name].occupied_by):
            return True, PLACEMENT_SESSION
        return False, ''

    def _reserve(self, host: HostConfig, placement: str = PLACEMENT_LOAD) -> tuple:
        self.status[host.name].projects += 1
        reservation = Reservation(placement=placement)
        self._reservations[host.name].append(reservation)
        return host, reservation

    @staticmethod
    def release(reservation):
        reservation.released_at = time.monotonic()

    # -- projects -------------------------------------------------------------------------------

    async def projects_of(self, identity: Identity, *, all_projects: bool = False) -> list:
        """The projects of a user on every reachable host: ``[{host, ...project}]``; with
        *all_projects* (an instructor's Watch page) every project of every host, with the owner's
        name and the last archived evaluation."""
        params = {'all': '1'} if all_projects else None

        async def one(host: HostConfig):
            try:
                async with self.session.get(f"{host.url}/v1/projects", headers=self.headers(host, identity),
                                            params=params, timeout=aiohttp.ClientTimeout(total=STATUS_TIMEOUT)) as resp:
                    if resp.status != 200:
                        log.warning("host %s: GET /v1/projects answered %s: %s", host.name, resp.status,
                                    (await resp.text())[:300])
                        return []
                    projects = await resp.json()
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                log.warning("host %s: GET /v1/projects failed: %s", host.name, e or type(e).__name__)
                return []
            return [dict(p, host=host.name) for p in projects if isinstance(p, dict)]
        results = await asyncio.gather(*(one(h) for h in list(self.hosts.values()) if self.status[h.name].reachable))
        projects = [p for group in results for p in group]
        projects.sort(key=lambda p: (p.get('started_at', ''), p.get('running_lab_name', '')))
        return projects

    async def labs(self, identity: Identity) -> list:
        """The union of the lab lists of the reachable hosts *identity* may use (one list wins
        when they differ): a student is never placed on a host reserved for instructors, so its
        labs are not offered."""
        seen: dict[str, dict] = {}
        for host in list(self.hosts.values()):
            if not self.status[host.name].reachable or (host.instructors_only and not identity.is_instructor):
                continue
            try:
                async with self.session.get(f"{host.url}/v1/labs", headers=self.headers(host, identity),
                                            timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        log.warning("host %s: GET /v1/labs answered %s: %s", host.name, resp.status,
                                    (await resp.text())[:300])
                        continue
                    labs = await resp.json()
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                log.warning("host %s: GET /v1/labs failed: %s", host.name, e or type(e).__name__)
                continue
            for entry in labs if isinstance(labs, list) else []:
                if isinstance(entry, str):
                    entry = {'name': entry, 'title': None}
                if isinstance(entry, dict) and entry.get('name') and entry['name'] not in seen:
                    seen[entry['name']] = {'name': entry['name'], 'title': entry.get('title')}
        return sorted(seen.values(), key=lambda e: e['name'])
