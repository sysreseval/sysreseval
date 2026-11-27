"""What the running projects use: the containers of each project, their memory and their
processor time, with the processors the whole host uses.  Every ``[usage] interval`` seconds the
sampler finds the containers of the projects and reads what each uses in its cgroup (version 2:
``memory.current``, ``memory.stat``, ``cpu.stat``).  The status of the agent carries the figures
to the portal, which learns from them what a project of each lab costs (``portal/costs.py``).

Where the containers are found depends on the container engine of the host:

* Kathara: the Docker daemon is asked which containers Kathara runs (one request on its socket:
  the ``lab_hash`` label of a container names its project);
* Podman: nothing is asked.  The engine gives the machines of a project a slice of their own of
  the user manager of its account, ``<podman_slices>/srelab-<lab_hash>.slice``, where each
  machine is a ``libpod-<container id>.scope``: the directory is listed.

The figures mean the same with both (the machines of the project, nothing of what links them):
the portal learns one cost per lab from all its hosts.

A project is **settled** once the set of its containers has stayed the same for
``SETTLE_AFTER`` seconds: the boot of the containers is left out of its figures, and a container
created again starts the count again.  Its processor figure is the mean number of cores it used
since then (not what it burns this second: an evaluation or a compilation is a burst).

Nothing here is a limit: a host without Docker socket, without the user manager of the Podman
account or without cgroup v2 gives no figure, and the portal goes on with what the labs declare.

No ``SRE`` import: the portal reads the wire constants of this module."""
import asyncio
import contextlib
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass

import aiohttp

from ..config import UsageConfig

log = logging.getLogger('sreweb.agent')

#: The keys of ``GET /v1/status`` this module fills.
STATUS_CPUS = 'cpus'                # the processors of the host
STATUS_MEM_TOTAL = 'mem_total_mb'   # its memory (MemTotal), in MiB
STATUS_CPU_BUSY = 'cpu_busy'        # the cores the whole host uses, smoothed (None: not measured)
STATUS_USAGE = 'usage'              # one entry per project of the host, the keys below
USAGE_NAME = 'name'                 # its running lab name
USAGE_LAB = 'lab'                   # its lab, as the project names it (the `@` form of info.json)
USAGE_CONTAINERS = 'containers'     # its running containers (None: not measured)
USAGE_MEM = 'mem_mb'                # the memory they use, in MiB (None: not measured)
USAGE_CPU = 'cpu'                   # the cores they used on average since the project settled (None: not yet)
USAGE_SETTLED = 'settled'           # the set of its containers has been the same for SETTLE_AFTER seconds

SETTLE_AFTER = 120.0        # seconds without a change of the containers of a project before it is settled
MEAN_AFTER = 60.0           # seconds measured after that before a mean is told (a shorter one says little)
BUSY_TAU = 60.0             # time constant, in seconds, of the smoothed processor use of the host
DOCKER_TIMEOUT = 5.0        # the request to the Docker daemon
#: Where the cgroup of a container is, under the cgroup root: with the systemd driver of Docker
#: (the default on a cgroup v2 host), then with its cgroupfs driver.
CGROUP_DIRS = ('system.slice/docker-{id}.scope', 'docker/{id}')
KATHARA_FILTER = json.dumps({'label': ['app=kathara']}, separators=(',', ':'))
LAB_HASH_LABEL = 'lab_hash'
LAB_HASH_KEY = 'lab_hash'   # of info.json
CONTAINER_ID_RE = re.compile(r'[0-9a-f]{64}')
#: Podman: the cgroup of a container in the slice of its project (the scope of its monitor
#: process, ``libpod-conmon-<id>.scope``, is beside it and is not the container), and what a lab
#: hash is made of (never a path built from anything else).
PODMAN_SCOPE_RE = re.compile(r'libpod-([0-9a-f]{64})\.scope')
PODMAN_LAB_HASH_RE = re.compile(r'[A-Za-z0-9]+')
SLICE_SUFFIX = '.slice'
MIB = 1024 * 1024


def parse_stat(text: str) -> dict:
    """The ``name value`` lines of a cgroup file (``cpu.stat``, ``memory.stat``) as
    ``{name: int}``; a line that is not one is left out."""
    values = {}
    for line in text.splitlines():
        name, _, value = line.partition(' ')
        try:
            values[name] = int(value)
        except ValueError:
            continue
    return values


def _read(path: str) -> str | None:
    try:
        with open(path, encoding='ascii', errors='replace') as f:
            return f.read()
    except OSError:
        return None


def cpu_usec(directory: str) -> int | None:
    """The processor time a cgroup has used so far, in microseconds (``usage_usec`` of its
    ``cpu.stat``); ``None`` when it cannot be read."""
    text = _read(os.path.join(directory, 'cpu.stat'))
    return parse_stat(text).get('usage_usec') if text is not None else None


def read_cgroup(directory: str) -> tuple:
    """``(memory in bytes, processor time in microseconds)`` of the cgroup *directory*: its
    working set (``memory.current`` less the ``inactive_file`` of ``memory.stat``: the pages of
    files the kernel gives back at once, what ``docker stats`` leaves out too) and the
    ``usage_usec`` of its ``cpu.stat``, each ``None`` when it cannot be read."""
    memory = None
    current = _read(os.path.join(directory, 'memory.current'))
    if current is not None:
        with contextlib.suppress(ValueError):
            stat = _read(os.path.join(directory, 'memory.stat'))
            inactive = parse_stat(stat).get('inactive_file', 0) if stat is not None else 0
            memory = max(0, int(current.strip()) - inactive)
    return memory, cpu_usec(directory)


def read_container(root: str, cid: str) -> tuple:
    """``read_cgroup()`` of the Docker container *cid* from its cgroup under *root*;
    ``(None, None)`` for a container without cgroup directory in either layout of
    ``CGROUP_DIRS`` (cgroup v1, another cgroup parent, a container that just ended) and for an
    id that is not one (never a path built from anything else)."""
    if not isinstance(cid, str) or not CONTAINER_ID_RE.fullmatch(cid):
        return None, None
    for layout in CGROUP_DIRS:
        directory = os.path.join(root, layout.format(id=cid))
        if os.path.isdir(directory):
            return read_cgroup(directory)
    return None, None


def podman_containers(slices: str, lab_hashes) -> tuple:
    """The containers of the projects *lab_hashes* on a host whose engine is Podman:
    ``({lab_hash: [container id]}, {container id: its cgroup directory})``, from the slices of
    the projects in the directory *slices* (the cgroup of a slice ``srelab.slice``: a project is
    the slice ``srelab-<lab_hash>.slice`` inside it, as systemd names the slices of a slice).
    A project without slice has no container.  Raises ``OSError`` when the directory above
    *slices* is not there: the user manager of the account of the engine does not run, nothing
    can be measured.  Run in a thread."""
    slices = slices.rstrip('/')
    os.stat(os.path.dirname(slices))
    name = os.path.basename(slices)
    prefix = name[:-len(SLICE_SUFFIX)] if name.endswith(SLICE_SUFFIX) else name
    by_lab: dict = {}
    where: dict = {}
    for lab_hash in lab_hashes:
        if not isinstance(lab_hash, str) or not PODMAN_LAB_HASH_RE.fullmatch(lab_hash):
            continue
        directory = os.path.join(slices, f'{prefix}-{lab_hash}{SLICE_SUFFIX}')
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for entry in entries:
            match = PODMAN_SCOPE_RE.fullmatch(entry)
            if match:
                by_lab.setdefault(lab_hash, []).append(match.group(1))
                where[match.group(1)] = os.path.join(directory, entry)
    return by_lab, where


def containers_by_lab(body) -> dict:
    """``{lab_hash: [container id]}`` of the answer of ``GET /containers/json`` (the running
    containers Kathara labelled): the entries with an id and a ``lab_hash`` label that are
    strings, anything else left out."""
    found: dict = {}
    if not isinstance(body, list):
        return found
    for entry in body:
        if not isinstance(entry, dict):
            continue
        cid, labels = entry.get('Id'), entry.get('Labels')
        lab_hash = labels.get(LAB_HASH_LABEL) if isinstance(labels, dict) else None
        if isinstance(cid, str) and CONTAINER_ID_RE.fullmatch(cid) and isinstance(lab_hash, str) and lab_hash:
            found.setdefault(lab_hash, []).append(cid)
    return found


def _read_all(root: str, ids, where: dict | None = None) -> dict:
    """``{id: its figures}`` of every container of *ids* (``read_cgroup()`` of its directory in
    *where* when it is there, else ``read_container()``), and the processor time of the whole
    host under the key ``None`` (the root cgroup); run in a thread."""
    where = where or {}
    figures = {cid: read_cgroup(where[cid]) if cid in where else read_container(root, cid) for cid in ids}
    figures[None] = cpu_usec(root)
    return figures


@dataclass
class _Track:
    """What the sampler remembers of one project between two measures."""
    ids: frozenset                      # its containers at the last measure
    since: float                        # when that set was first seen
    base_at: float | None = None        # the measure its mean starts from (the first one once settled)
    base_usec: int | None = None        # the processor time its containers had used then
    containers: int | None = None       # the figures of the last measure (None: not measured)
    mem_mb: float | None = None
    cpu: float | None = None
    settled: bool = False


class UsageSampler:
    """The periodic measure of the projects of *registry* (``sample()``, run every
    ``cfg.interval`` seconds by its own task: never from the status handler, which a slow Docker
    daemon would hold longer than the portal waits for it) and what the status tells of it
    (``rows()``, ``cpu_busy``).  *docker_socket*: the socket of the daemon; *podman_slices*: the
    directory of the slices of the projects of the Podman engine, which is read when it is given
    (the daemon is then not asked); both ``''`` for an agent that measures nothing (its status
    still lists its projects, without figures); *clock*: injectable for the tests."""

    def __init__(self, registry, cfg: UsageConfig, *, docker_socket: str, podman_slices: str = '',
                 clock=time.monotonic):
        self.registry = registry
        self.cfg = cfg
        self.docker_socket = docker_socket
        self.podman_slices = podman_slices
        self.clock = clock
        self.cpu_busy: float | None = None      # the cores the host uses, smoothed over BUSY_TAU
        self._tracks: dict[str, _Track] = {}
        self._host: tuple | None = None         # (clock, usage_usec) of the root cgroup at the last measure
        self._warned = ''                       # the last reason no measure could be made, logged once
        self._task: asyncio.Task | None = None

    @property
    def enabled(self) -> bool:
        return self.cfg.interval > 0 and bool(self.docker_socket or self.podman_slices)

    # -- the measure ----------------------------------------------------------------------------

    async def _list_containers(self) -> dict:
        """``containers_by_lab()`` of the running Kathara containers; raises on any failure of
        the daemon."""
        timeout = aiohttp.ClientTimeout(total=DOCKER_TIMEOUT)
        # a session per measure: a connection kept would be dead after a restart of the daemon
        async with aiohttp.ClientSession(connector=aiohttp.UnixConnector(path=self.docker_socket),
                                         timeout=timeout) as session:
            async with session.get('http://docker/containers/json', params={'filters': KATHARA_FILTER}) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"the Docker daemon answered {resp.status}")
                return containers_by_lab(await resp.json(content_type=None))

    def _warn(self, reason: str):
        """*reason* logged the first time it is met (and when it changes); ``''``: all is well."""
        if reason and reason != self._warned:
            log.warning("usage of the projects not measured: %s", reason)
        self._warned = reason

    async def sample(self):
        """One measure: the containers of every project of the registry, their figures, and the
        processors of the host.  Without project the Docker daemon is not asked."""
        now = self.clock()
        projects = {p.rln: p for p in self.registry.projects.values()}
        hash_of = {rln: project.info.get(LAB_HASH_KEY) if isinstance(project.info, dict) else None
                   for rln, project in projects.items()}
        by_lab: dict | None = {}
        where: dict = {}
        if projects:
            try:
                if self.podman_slices:
                    by_lab, where = await asyncio.to_thread(podman_containers, self.podman_slices,
                                                            list(hash_of.values()))
                else:
                    by_lab = await self._list_containers()
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError, RuntimeError, ValueError) as e:
                by_lab = None
                self._warn(f"{self.podman_slices or self.docker_socket}: {e or type(e).__name__}")
        ids_of = {}
        if by_lab is not None:
            for rln, lab_hash in hash_of.items():
                ids_of[rln] = frozenset(by_lab.get(lab_hash, ())) if isinstance(lab_hash, str) else frozenset()
        wanted = set().union(*ids_of.values()) if ids_of else set()
        figures = await asyncio.to_thread(_read_all, self.cfg.cgroup_root, wanted, where)
        self._host_measure(now, figures.pop(None))
        for rln in list(self._tracks):
            if rln not in projects:
                del self._tracks[rln]
        if by_lab is None:
            # the daemon did not answer: the projects keep their place (the settling goes on),
            # but nothing is told of them until the next measure
            for track in self._tracks.values():
                track.containers = track.mem_mb = track.cpu = None
            return
        unread = 0
        for rln, ids in ids_of.items():
            track = self._tracks.get(rln)
            if track is None or track.ids != ids:
                track = self._tracks[rln] = _Track(ids=ids, since=now)
            unread += self._project_measure(track, now, [figures[cid] for cid in ids])
        if projects and wanted and unread == len(wanted):
            self._warn(f"no cgroup of a container found under {self.cfg.cgroup_root} (cgroup v2 expected)")
        elif projects:
            self._warn('')

    @staticmethod
    def _project_measure(track: _Track, now: float, figures: list) -> int:
        """The figures of one project from those of its containers; the number of containers
        whose cgroup was not found."""
        track.containers = len(figures)
        track.settled = bool(figures) and now - track.since >= SETTLE_AFTER
        memory = [m for m, _ in figures]
        used = [u for _, u in figures]
        # a figure missing for one container (it just ended, its cgroup is elsewhere) would make
        # the sum too low: nothing is told then
        track.mem_mb = sum(memory) / MIB if figures and None not in memory else None
        total = sum(used) if figures and None not in used else None
        track.cpu = None
        if total is None:
            track.base_at = track.base_usec = None
        elif track.settled:
            if track.base_at is None or total < track.base_usec:
                track.base_at, track.base_usec = now, total     # the mean starts here
            elif now - track.base_at >= MEAN_AFTER:
                track.cpu = (total - track.base_usec) / 1e6 / (now - track.base_at)
        return sum(1 for m, u in figures if m is None and u is None)

    def _host_measure(self, now: float, usec: int | None):
        """The cores the host used since the last measure (the root cgroup), smoothed."""
        previous = self._host
        if usec is None:
            self._host = self.cpu_busy = None
            return
        self._host = (now, usec)
        if previous is None or now <= previous[0] or usec < previous[1]:
            return
        elapsed = now - previous[0]
        cores = (usec - previous[1]) / 1e6 / elapsed
        if self.cpu_busy is None:
            self.cpu_busy = cores
        else:
            self.cpu_busy += (1 - math.exp(-elapsed / BUSY_TAU)) * (cores - self.cpu_busy)

    # -- what the status tells ------------------------------------------------------------------

    def rows(self) -> list:
        """The ``usage`` of the status: every project of the registry now, with the figures of
        the last measure (``None`` before its first one: a project just created is listed at
        once, the portal counts it by the cost of its lab meanwhile)."""
        rows = []
        for project in self.registry.projects.values():
            track = self._tracks.get(project.rln)
            rows.append({
                USAGE_NAME: project.rln, USAGE_LAB: project.lab_name,
                USAGE_CONTAINERS: track.containers if track else None,
                USAGE_MEM: round(track.mem_mb, 1) if track and track.mem_mb is not None else None,
                USAGE_CPU: round(track.cpu, 4) if track and track.cpu is not None else None,
                USAGE_SETTLED: bool(track and track.settled),
            })
        return rows

    # -- the loop -------------------------------------------------------------------------------

    async def run(self):
        while True:
            try:
                await self.sample()
            except Exception:
                log.exception("usage sample failed")
            await asyncio.sleep(self.cfg.interval)

    def start(self):
        if self.enabled and self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self):
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
