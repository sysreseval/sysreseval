"""The pool of hosts: the status of their agents, the placement of a new project, the fan-out
of the project lists."""
import asyncio
import logging
import time
from dataclasses import dataclass, field

import aiohttp

from ..config import HostConfig
from ..identity import Identity

log = logging.getLogger('sreweb.portal')

STATUS_TIMEOUT = 5.0


class PoolError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Reservation:
    released_at: float | None = None


@dataclass
class HostStatus:
    reachable: bool = False
    projects: int = 0
    terminals: int = 0
    load1: float | None = None
    exam_mode: bool = False
    hostname: str = ''
    sre_version: str = ''
    error: str = ''
    updated: float = field(default_factory=time.monotonic)


class Pool:
    def __init__(self, hosts: list, session: aiohttp.ClientSession, *, poll_interval: float = 2.0):
        self.hosts: dict[str, HostConfig] = {h.name: h for h in hosts}
        self.session = session
        self.poll_interval = poll_interval
        self.status: dict[str, HostStatus] = {name: HostStatus() for name in self.hosts}
        #: The projects being started on each host: a reservation counts as a project until the
        #: start is over (``release``) and a status polled after that has been received, so that
        #: a stale poll never frees the slot early.
        self._reservations: dict[str, list] = {name: [] for name in self.hosts}
        self._reported: dict[str, bool] = {}
        self._task: asyncio.Task | None = None

    def _consume(self, name: str, polled_at: float) -> int:
        """Forget the reservations released before the status request sent at *polled_at*;
        the number still counted."""
        self._reservations[name] = [r for r in self._reservations[name]
                                    if r.released_at is None or r.released_at > polled_at]
        return len(self._reservations[name])

    def host(self, name: str) -> HostConfig:
        host = self.hosts.get(name)
        if host is None:
            raise PoolError(404, "unknown host")
        return host

    @staticmethod
    def headers(host: HostConfig, identity: Identity | None = None) -> dict:
        headers = {'Authorization': f'Bearer {host.token}'}
        if identity is not None:
            headers.update(identity.headers())
        return headers

    # -- status ---------------------------------------------------------------------------------

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
                                        terminals=int(data.get('terminals', 0)), load1=data.get('load1'),
                                        exam_mode=bool(data.get('exam_mode', False)),
                                        hostname=str(data.get('hostname', '')),
                                        sre_version=str(data.get('sre_version', '')))
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            status = HostStatus(error=str(e) or type(e).__name__)
        previous = self._reported.get(host.name)   # None at the first poll: always reported
        self._reported[host.name] = status.reachable
        if previous is None or previous != status.reachable:
            if status.reachable:
                log.info("host %s reachable: %s, sre %s, %d project(s)", host.name, status.hostname, status.sre_version,
                         status.projects)
            else:
                log.warning("host %s unreachable at %s: %s", host.name, host.url, status.error)
        self.status[host.name] = status
        return status

    async def refresh(self):
        await asyncio.gather(*(self.refresh_host(h) for h in self.hosts.values()))

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

    def summary(self) -> list:
        return [{'name': h.name, 'url': h.url, 'max_projects': h.max_projects, **vars(self.status[h.name])}
                for h in self.hosts.values()]

    # -- placement ------------------------------------------------------------------------------

    def pick(self) -> tuple:
        """The host of a new project and its reservation: reachable, not in exam mode, below its
        maximum, the least loaded (projects / max_projects, then load).  The caller releases the
        reservation when the start is over."""
        candidates = []
        for host in self.hosts.values():
            st = self.status[host.name]
            if not st.reachable or st.exam_mode or st.projects >= host.max_projects:
                continue
            candidates.append((st.projects / host.max_projects, st.load1 if st.load1 is not None else 0.0, host.name, host))
        if not candidates:
            raise PoolError(503, "no host available for a new project")
        candidates.sort(key=lambda c: c[:3])
        host = candidates[0][3]
        self.status[host.name].projects += 1
        reservation = Reservation()
        self._reservations[host.name].append(reservation)
        return host, reservation

    @staticmethod
    def release(reservation):
        reservation.released_at = time.monotonic()

    # -- projects -------------------------------------------------------------------------------

    async def projects_of(self, identity: Identity) -> list:
        """The projects of a user on every reachable host: ``[{host, ...project}]``."""
        async def one(host: HostConfig):
            try:
                async with self.session.get(f"{host.url}/v1/projects", headers=self.headers(host, identity),
                                            timeout=aiohttp.ClientTimeout(total=STATUS_TIMEOUT)) as resp:
                    if resp.status != 200:
                        log.warning("host %s: GET /v1/projects answered %s: %s", host.name, resp.status,
                                    (await resp.text())[:300])
                        return []
                    projects = await resp.json()
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                log.warning("host %s: GET /v1/projects failed: %s", host.name, e or type(e).__name__)
                return []
            return [dict(p, host=host.name) for p in projects if isinstance(p, dict)]
        results = await asyncio.gather(*(one(h) for h in self.hosts.values() if self.status[h.name].reachable))
        projects = [p for group in results for p in group]
        projects.sort(key=lambda p: (p.get('started_at', ''), p.get('running_lab_name', '')))
        return projects

    async def labs(self, identity: Identity) -> list:
        """The union of the lab lists of the reachable hosts (one list wins when they differ)."""
        seen: dict[str, dict] = {}
        for host in self.hosts.values():
            if not self.status[host.name].reachable:
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
