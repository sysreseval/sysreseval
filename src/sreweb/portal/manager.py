"""The elastic pool: hosts woken when the spare capacity drops, kept awake up to a floor during
the active hours, powered off when idle (optional), and the preloads of the Docker images given
their turn a few hosts at a time; the policy is a pure function of the hosts' states
(``wake_plan`` / ``poweroff_plan`` / ``preload_plan``), the manager applies it every poll."""
import asyncio
import datetime
import logging
import shlex
import socket
import time
from dataclasses import dataclass

import aiohttp

from .pool import (Pool, PoolError, preload_fields, STATE_UP, STATE_WAKING, STATE_OCCUPIED, STATE_EXAM,
                   STATE_DRAINING, STATE_OFF)
from ..agent.runner import PRELOAD_PENDING, PRELOAD_RUNNING, PRELOAD_FAILED
from ..config import PoolConfig, HostConfig, parse_active_hours, in_active_hours

log = logging.getLogger('sreweb.portal')

WOL_PORT = 9
WAKE_COMMAND_TIMEOUT = 30.0
BACKOFF_MIN, BACKOFF_MAX = 60.0, 1800.0
POWER_OFF_HOLD = 600.0      # no automatic wake of a host for this long after its power off
AWAKE_STATES = (STATE_UP, STATE_OCCUPIED, STATE_EXAM, STATE_DRAINING)
AGENT_POST_TIMEOUT = 15.0   # a request to an agent asked by hand
PRELOAD_GRANT_TIMEOUT = 5.0     # the turn given to a host by the policy: an agent that hangs must not stall the tick
PRELOAD_REFUSED_HOLD = 60.0     # a host that refused its turn is not offered another one for this long


@dataclass
class HostView:
    """What the policy knows of a host."""
    name: str
    state: str
    projects: int
    max_projects: int
    can_wake: bool
    enabled: bool
    power: bool
    power_off_allowed: bool
    next_wake_at: float
    idle_for: float | None      # seconds without a project (None when it has some, or is not up)
    drain: bool
    power_off_pending: bool     # a power off was accepted lately: the host is going down
    instructors_only: bool = False   # reserved for the instructors' projects: outside the policy
    restart_pending: bool = False    # a restart of the agent was sent: the policy leaves the host alone
    # the preload of the Docker images on the host: the state its agent tells ('' unknown), the
    # seconds in it (the host that waited longest is served first), a turn given that no status
    # has told yet (the host counts as preloading), a turn refused lately (not offered again yet)
    preload: str = ''
    preload_since: float = 0.0
    preload_granted: bool = False
    preload_hold: bool = False
    exam_projects: int = 0           # running projects of an exam of the web site: no preload meanwhile


def awake_count(hosts) -> int:
    """The shared hosts awake (``AWAKE_STATES``) or waking: what the floor ``min_hosts_up``
    counts (a host reserved for instructors serves no student)."""
    return sum(1 for h in hosts if not h.instructors_only and (h.state in AWAKE_STATES or h.state == STATE_WAKING))


def spare_capacity(hosts) -> int:
    """The free project slots of the shared hosts up, plus the whole capacity of those waking
    (a host reserved for instructors is no capacity for the students)."""
    return sum(h.max_projects - h.projects for h in hosts if h.state == STATE_UP and not h.instructors_only) + \
        sum(h.max_projects for h in hosts if h.state == STATE_WAKING and not h.instructors_only)


def wake_plan(hosts, cfg: PoolConfig, now: float, active: bool, last_wake_at: float) -> list:
    """The names of the hosts to wake now, in configuration order: enough sleeping hosts to bring
    the spare capacity back to ``spare_projects`` and, during the active hours, the awake hosts
    up to ``min_hosts_up``; at most one wake per ``wake_interval``.  A host reserved for
    instructors is never woken by the policy (``sre-web-tool wake``, or its own boot)."""
    if now - last_wake_at < cfg.wake_interval:
        return []
    awake = awake_count(hosts)
    spare = spare_capacity(hosts)
    wanted = []
    for h in hosts:
        if h.state != STATE_OFF or not h.can_wake or not h.enabled or h.instructors_only or now < h.next_wake_at \
                or h.restart_pending:
            continue
        if spare < cfg.spare_projects or (active and awake < cfg.min_hosts_up):
            wanted.append(h.name)
            spare += h.max_projects
            awake += 1
    return wanted[:1]


def poweroff_plan(hosts, cfg: PoolConfig, active: bool) -> list:
    """The names of the hosts to power off now: a draining host as soon as it is empty; with
    ``idle_host_timeout``, one idle host that the floor and the spare capacity can spare (a
    host reserved for instructors counts for neither: idle long enough is enough)."""
    empties = [h for h in hosts if h.state in (STATE_UP, STATE_DRAINING) and h.projects == 0 and h.power
               and h.power_off_allowed and not h.power_off_pending and not h.restart_pending]
    drained = [h.name for h in empties if h.drain]
    if drained:
        return drained[:1]
    if cfg.idle_host_timeout <= 0:
        return []
    awake = awake_count(hosts)
    floor = cfg.min_hosts_up if active else 0
    for h in sorted(empties, key=lambda h: -(h.idle_for or 0)):
        if h.idle_for is None or h.idle_for < cfg.idle_host_timeout:
            continue
        if cfg.max_preloads > 0 and (is_preloading(h) or h.preload == PRELOAD_PENDING):
            continue    # pulling the images, or waiting for its turn to: off, it would never have them
        if h.instructors_only:
            return [h.name]
        if awake > floor and spare_capacity([x for x in hosts if x.name != h.name]) >= cfg.spare_projects:
            return [h.name]
    return []


def is_preloading(host) -> bool:
    """Whether the host holds one of the ``max_preloads`` turns: its agent says it pulls the
    images, or the turn was just given and no status has told yet."""
    return host.preload_granted or host.preload == PRELOAD_RUNNING


def preload_plan(hosts, cfg: PoolConfig) -> list:
    """The names of the hosts whose preload of the Docker images starts now: those asking for
    one (``pending``), the one that waited longest first, as many as ``max_preloads`` leaves
    free — the downloads of a few hosts at a time, not of the whole site at once.  A disabled
    or occupied host is served like any other (its local users start labs too); not one whose
    agent runs an exam of the web site, nor one going down (drain, power off) or restarting."""
    if cfg.max_preloads <= 0:
        return []
    free = cfg.max_preloads - sum(1 for h in hosts if is_preloading(h))
    if free <= 0:
        return []
    waiting = [h for h in hosts if h.preload == PRELOAD_PENDING and not h.preload_granted and not h.preload_hold
               and not h.exam_projects and not h.drain and not h.restart_pending and not h.power_off_pending]
    waiting.sort(key=lambda h: (-h.preload_since, h.name))
    return [h.name for h in waiting[:free]]


def magic_packet(mac: str) -> bytes:
    return b'\xff' * 6 + bytes.fromhex(mac.replace(':', '')) * 16


def send_magic_packet(mac: str, broadcast: str, port: int = WOL_PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic_packet(mac), (broadcast, port))


class PoolManager:
    def __init__(self, pool: Pool, cfg: PoolConfig, *, wol=send_magic_packet, clock=datetime.datetime.now):
        self.pool = pool
        self.cfg = cfg
        self.wol = wol
        self.clock = clock
        self.hours = parse_active_hours(cfg.active_hours)
        self.last_wake_at = -1e9
        self._task: asyncio.Task | None = None

    # -- views ----------------------------------------------------------------------------------

    def active(self) -> bool:
        now = self.clock()
        return in_active_hours(self.hours, now.hour * 60 + now.minute)

    def views(self, now: float | None = None) -> list:
        now = time.monotonic() if now is None else now
        views = []
        for host in self.pool.hosts.values():
            st, rt = self.pool.status[host.name], self.pool.runtime[host.name]
            state = self.pool.state_of(host.name, now)
            views.append(HostView(name=host.name, state=state, projects=st.projects, max_projects=host.max_projects,
                                  can_wake=host.can_wake, enabled=rt.enabled, power=host.power,
                                  power_off_allowed=st.power_off_allowed, next_wake_at=rt.next_wake_at,
                                  idle_for=(now - rt.idle_since) if rt.idle_since is not None and st.projects == 0
                                  and state in (STATE_UP, STATE_DRAINING) else None, drain=rt.drain,
                                  power_off_pending=rt.power_off_sent is not None
                                  and now - rt.power_off_sent < self.pool.wake_timeout,
                                  instructors_only=host.instructors_only,
                                  restart_pending=rt.restart_sent is not None,
                                  preload=st.preload, preload_since=float(st.preload_since or 0),
                                  preload_granted=rt.preload_granted is not None,
                                  preload_hold=now < rt.next_preload_at, exam_projects=st.exam_projects))
        return views

    def status(self) -> dict:
        views = self.views()
        return {'spare_projects': spare_capacity(views), 'wanted_spare': self.cfg.spare_projects,
                'awake': sum(1 for h in views if h.state in AWAKE_STATES and not h.instructors_only),
                'min_hosts_up': self.cfg.min_hosts_up,
                'active_hours': self.cfg.active_hours or 'always', 'active_now': self.active(),
                'waking': [h.name for h in views if h.state == STATE_WAKING],
                'idle_host_timeout': self.cfg.idle_host_timeout,
                'max_preloads': self.cfg.max_preloads,
                'preloading': [h.name for h in views if is_preloading(h)],
                'preload_queued': sum(1 for h in views if h.preload == PRELOAD_PENDING and not h.preload_granted),
                'preload_failed': sum(1 for h in views if h.preload == PRELOAD_FAILED),
                **self.pool.state_info()}

    # -- the loop -------------------------------------------------------------------------------

    async def tick(self):
        now = time.monotonic()
        self._track_idle(now)
        self._expire_wakes(now)
        views = self.views(now)
        active = self.active()
        for name in wake_plan(views, self.cfg, now, active, self.last_wake_at):
            try:
                await self.wake(name, "spare capacity" if spare_capacity(views) < self.cfg.spare_projects else "floor")
            except PoolError as e:
                log.warning("wake of %s: %s", name, e.message)
        for name in preload_plan(views, self.cfg):
            try:
                await self.start_preload(name)
            except PoolError as e:
                log.warning("preload of %s: %s", name, e.message)
        for name in poweroff_plan(views, self.cfg, active):
            try:
                await self.power_off(name, "draining" if self.pool.runtime[name].drain else "idle")
            except PoolError as e:
                log.warning("power off of %s: %s", name, e.message)

    def _track_idle(self, now: float):
        for name, st in self.pool.status.items():
            rt = self.pool.runtime[name]
            if st.reachable and st.projects == 0:
                if rt.idle_since is None:
                    rt.idle_since = now
            else:
                rt.idle_since = None

    @staticmethod
    def _wake_failed(name: str, rt, now: float, what: str):
        """One more failure: the next automatic wake of the host waits 1, 2, 4... up to 30 min."""
        rt.woken_at = None
        rt.wake_failures += 1
        backoff = min(BACKOFF_MIN * 2 ** (rt.wake_failures - 1), BACKOFF_MAX)
        rt.next_wake_at = now + backoff
        log.warning("host %s %s (failure %d): next automatic attempt in %.0f s", name, what, rt.wake_failures, backoff)

    def _expire_wakes(self, now: float):
        for name, rt in self.pool.runtime.items():
            if rt.woken_at is not None and not self.pool.status[name].reachable \
                    and now - rt.woken_at >= self.pool.wake_timeout:
                self._wake_failed(name, rt, now, f"did not come up within {self.pool.wake_timeout:.0f} s")

    async def _loop(self):
        while True:
            try:
                await self.tick()
            except Exception:
                log.exception("pool manager tick failed")
            await asyncio.sleep(self.pool.poll_interval)

    def start(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # -- actions ----------------------------------------------------------------------------------

    async def wake(self, name: str, reason: str = "requested"):
        host = self.pool.host(name)
        if not host.can_wake:
            raise PoolError(409, f"{name} has no mac nor wake_command")
        rt = self.pool.runtime[name]
        log.info("waking host %s (%s)", name, reason)
        self.last_wake_at = time.monotonic()
        try:
            if host.wake_command:
                argv = [a.format(name=host.name, mac=host.mac) for a in shlex.split(host.wake_command)]
                try:
                    proc = await asyncio.create_subprocess_exec(*argv)
                    await asyncio.wait_for(proc.wait(), WAKE_COMMAND_TIMEOUT)
                except (OSError, TimeoutError) as e:
                    raise PoolError(502, f"wake command failed: {e}")
                if proc.returncode != 0:
                    raise PoolError(502, f"wake command failed (exit {proc.returncode})")
            else:
                try:
                    await asyncio.get_running_loop().run_in_executor(None, self.wol, host.mac, self.cfg.wol_broadcast)
                except OSError as e:
                    raise PoolError(502, f"Wake-on-LAN failed: {e}")
        except PoolError as e:
            self._wake_failed(name, rt, self.last_wake_at, e.message)
            raise
        rt.woken_at = self.last_wake_at
        rt.last_wake_reason = reason

    async def power_off(self, name: str, reason: str = "requested"):
        """``POST /v1/power/off`` on the agent; the host is marked draining until it is gone."""
        host = self.pool.host(name)
        st, rt = self.pool.status[name], self.pool.runtime[name]
        if not st.reachable:
            raise PoolError(409, f"{name} is not reachable")
        log.info("powering off host %s (%s)", name, reason)
        try:
            async with self.pool.session.post(f"{host.url}/v1/power/off", headers=self.pool.headers(host),
                                              timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.json(content_type=None) if resp.content_type.endswith('json') else {}
                if resp.status != 200:
                    raise PoolError(resp.status, f"{name} refused: {body.get('error', resp.status)}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise PoolError(502, f"{name} does not answer: {e or type(e).__name__}")
        if not rt.drain:
            rt.drain, rt.drain_at = True, round(time.time(), 3)
        rt.power_off_sent = time.monotonic()
        rt.next_wake_at = max(rt.next_wake_at, rt.power_off_sent + POWER_OFF_HOLD)
        self.pool.save_state()      # a portal restarted now still knows the host is going down

    async def restart(self, name: str, reason: str = "requested"):
        """``POST /v1/restart`` on the agent (``sre-web-tool restart``: the agent restarts its
        own unit once its sre commands are over; the projects stay); the host is marked
        ``restart_sent`` until the portal sees the agent's uptime reset, or ``restart_hold``:
        no placement there, no wake nor power off by the policy, its drain kept."""
        host = self.pool.host(name)
        st, rt = self.pool.status[name], self.pool.runtime[name]
        if not st.reachable:
            raise PoolError(409, f"{name} is not reachable")
        if rt.restart_sent is not None:
            raise PoolError(409, f"{name}: a restart was sent {time.monotonic() - rt.restart_sent:.0f} s ago")
        log.info("restarting the agent of host %s (%s)", name, reason)
        try:
            async with self.pool.session.post(f"{host.url}/v1/restart", headers=self.pool.headers(host),
                                              timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.json(content_type=None) if resp.content_type.endswith('json') else {}
                if resp.status != 200:
                    raise PoolError(resp.status, f"{name} refused: {body.get('error', resp.status)}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise PoolError(502, f"{name} does not answer: {e or type(e).__name__}")
        rt.restart_sent = time.monotonic()

    # -- the preloads of the Docker images --------------------------------------------------------

    async def _post(self, host: HostConfig, path: str, timeout: float = AGENT_POST_TIMEOUT) -> dict:
        """``POST`` *path* on the agent of *host*: its JSON answer.  ``PoolError`` with the
        status of a refusal, 502 when the agent does not answer."""
        try:
            async with self.pool.session.post(f"{host.url}{path}", headers=self.pool.headers(host),
                                              timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                body = await resp.json(content_type=None) if resp.content_type.endswith('json') else {}
                if not isinstance(body, dict):
                    body = {}
                if resp.status != 200:
                    raise PoolError(resp.status, f"{host.name} refused: {body.get('error', resp.status)}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise PoolError(502, f"{host.name} does not answer: {e or type(e).__name__}")
        return body

    def _note_preload(self, name: str, body: dict):
        """What the agent answered about its preload, shown at once (the next status says it again)."""
        fields = preload_fields(body.get('preload'))
        if fields['preload']:
            status = self.pool.status[name]
            for key, value in fields.items():
                setattr(status, key, value)

    async def start_preload(self, name: str):
        """The turn of *name* (``POST /v1/preload/start`` on its agent, by the policy alone):
        the host counts as preloading (``preload_granted``) until a status asked after this
        request tells where it is, an agent that did not answer included, since it may have
        started; after a refusal (an exam, an agent restarting, nothing asked any more) it is
        not offered a turn for ``PRELOAD_REFUSED_HOLD`` seconds."""
        host = self.pool.host(name)
        rt = self.pool.runtime[name]
        try:
            body = await self._post(host, '/v1/preload/start', PRELOAD_GRANT_TIMEOUT)
        except PoolError as e:
            if e.status == 502:
                rt.preload_granted = time.monotonic()
            else:
                rt.next_preload_at = time.monotonic() + PRELOAD_REFUSED_HOLD
            raise
        rt.preload_granted = time.monotonic()
        self._note_preload(name, body)
        log.info("host %s preloads the Docker images", name)

    async def request_preload(self, name: str, reason: str = "requested"):
        """A preload of the images is asked for *name* by hand (``sre-web-tool preload``, the
        Pool page): ``POST /v1/preload/request`` on its agent, which then waits for its turn
        like a host that asked at its start; the policy gives it (``preload_plan``), so the
        hosts preloading at the same time never exceed ``max_preloads``."""
        host = self.pool.host(name)
        st = self.pool.status[name]
        if not st.reachable:
            raise PoolError(409, f"{name} is not reachable")
        if not st.preload:
            raise PoolError(409, f"{name}: its agent does not know the preload of the images (an older version)")
        if self.cfg.max_preloads <= 0:
            raise PoolError(409, "the preloads are turned off (max_preloads = 0)")
        log.info("preload of the Docker images asked for host %s (%s)", name, reason)
        self._note_preload(name, await self._post(host, '/v1/preload/request'))
