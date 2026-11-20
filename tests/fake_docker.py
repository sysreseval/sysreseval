"""A fake Docker daemon for the usage sampler of the agent (sreweb.agent.usage): an aiohttp
server on a unix socket answering ``GET /containers/json`` with its containers, and the cgroup
(version 2) of each of them in a directory, in either layout the sampler knows.

    docker = FakeDocker(short_dir)          # a short path: a unix socket path is limited
    await docker.start()
    cid = docker.add(lab_hash, mem=64 * MIB, cpu_usec=0)
    Harness(tmp_path, usage=docker.config())
    ...
    await docker.stop()

Run as a program it is a fake host for the fake pool (``scripts/web-fake-pool.py --usage``): it
follows the projects directory of an agent on the fake ``sre`` and gives each project containers
that use memory and processor time (``Simulation``).
"""
import json
from pathlib import Path

from aiohttp import web

MIB = 1024 * 1024
SYSTEMD, CGROUPFS = 'systemd', 'cgroupfs'
LAYOUTS = {SYSTEMD: 'system.slice/docker-{id}.scope', CGROUPFS: 'docker/{id}'}


class FakeDocker:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.socket = str(self.directory / 'docker.sock')
        self.cgroup_root = self.directory / 'cgroup'
        self.cgroup_root.mkdir(parents=True, exist_ok=True)
        self.containers: dict = {}      # id -> {'lab_hash', 'layout'}
        self.status = 200               # what the daemon answers
        self.body = None                # when set: answered in place of the list of containers
        self.requests: list = []        # the query of every request received
        self._runner = None
        self._serial = 0

    def config(self, **more) -> dict:
        """The ``[usage]`` table of the agent.toml of an agent measuring this daemon."""
        return {'docker_socket': self.socket, 'cgroup_root': str(self.cgroup_root), **more}

    # -- containers -----------------------------------------------------------------------------

    def _directory(self, cid: str):
        layout = self.containers[cid]['layout']
        return self.cgroup_root / LAYOUTS[layout].format(id=cid) if layout else None

    def add(self, lab_hash: str, *, mem: int = 0, inactive_file: int = 0, cpu_usec: int = 0,
            layout: str | None = SYSTEMD) -> str:
        """A new running container of the project *lab_hash*; *layout*: where its cgroup is
        (``None``: nowhere the sampler looks).  Returns its id."""
        self._serial += 1
        cid = f"{self._serial:064x}"
        self.containers[cid] = {'lab_hash': lab_hash, 'layout': layout}
        if layout:
            self._directory(cid).mkdir(parents=True)
            self.set(cid, mem=mem, inactive_file=inactive_file, cpu_usec=cpu_usec)
        return cid

    def set(self, cid: str, *, mem: int | None = None, inactive_file: int | None = None,
            cpu_usec: int | None = None):
        """The figures of a container: its ``memory.current``, the ``inactive_file`` of its
        ``memory.stat`` and the ``usage_usec`` of its ``cpu.stat`` (those given)."""
        directory = self._directory(cid)
        if mem is not None:
            (directory / 'memory.current').write_text(f"{mem}\n")
        if inactive_file is not None:
            (directory / 'memory.stat').write_text(f"anon 4096\nfile 8192\ninactive_file {inactive_file}\nactive_file 0\n")
        if cpu_usec is not None:
            (directory / 'cpu.stat').write_text(f"usage_usec {cpu_usec}\nuser_usec {cpu_usec}\nsystem_usec 0\n")

    def remove(self, cid: str):
        directory = self._directory(cid)
        if directory is not None:
            for path in directory.iterdir():
                path.unlink()
            directory.rmdir()
        del self.containers[cid]

    def host_cpu(self, usec: int):
        """The processor time the whole host has used: the ``cpu.stat`` of the root cgroup."""
        (self.cgroup_root / 'cpu.stat').write_text(f"usage_usec {usec}\nuser_usec {usec}\nsystem_usec 0\n")

    # -- the daemon -----------------------------------------------------------------------------

    async def _containers(self, request):
        self.requests.append(dict(request.query))
        if self.body is not None:
            return web.json_response(self.body, status=self.status)
        return web.json_response(
            [{'Id': cid, 'State': 'running', 'Labels': {'app': 'kathara', 'lab_hash': c['lab_hash'], 'name': 'm'}}
             for cid, c in self.containers.items()], status=self.status)

    async def start(self):
        app = web.Application()
        app.router.add_get('/containers/json', self._containers)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.UnixSite(self._runner, self.socket).start()

    async def stop(self):
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.stop()


# ---------------------------------------------------------------------------------------------
# a fake host of the fake pool (scripts/web-fake-pool.py --usage)
# ---------------------------------------------------------------------------------------------

DEFAULT_USAGE = (4, 60.0, 0.02)     # of a lab the table does not name: containers, MiB, cores
HOST_BASE_MB = 1500                 # the memory the fake host uses without any project


class Simulation:
    """A fake host for the fake pool: it follows the projects directory of an agent on the fake
    ``sre`` (which deploys no container), gives each project the containers of its lab, makes
    them use memory and processor time, and writes the memory of the host (``meminfo``: what
    ``[usage] meminfo`` of the agent reads) — so that the load of a fake host follows its
    projects.  *table*: ``{lab name: [containers, MiB, cores]}`` of a project of each lab (the
    names of the lab list, ``sre/dhcp.py``), ``DEFAULT_USAGE`` for the others."""

    def __init__(self, docker: FakeDocker, projects_dir, table: dict | None = None, *, mem_total_mb: int = 16384):
        self.docker = docker
        self.projects_dir = Path(projects_dir)
        self.table = table or {}
        self.mem_total_mb = mem_total_mb
        self.meminfo = docker.directory / 'meminfo'
        self.projects: dict = {}    # running lab name -> {'ids', 'mem_mb', 'cpu', 'usec'}
        self.host_usec = 0
        self.step(0.0)

    def _usage_of(self, lab: str) -> tuple:
        entry = self.table.get(lab.replace('@', '/'), DEFAULT_USAGE)
        return int(entry[0]), float(entry[1]), float(entry[2])

    def _running(self) -> dict:
        """``{running lab name: (lab_hash, lab_name)}`` of the projects whose info.json is there."""
        found = {}
        try:
            entries = sorted(self.projects_dir.iterdir())
        except OSError:
            return found
        for entry in entries:
            try:
                info = json.loads((entry / 'info.json').read_text())
            except (OSError, ValueError):
                continue
            if isinstance(info, dict) and isinstance(info.get('lab_hash'), str):
                found[entry.name] = (info['lab_hash'], str(info.get('lab_name') or ''))
        return found

    def step(self, elapsed: float):
        """*elapsed* seconds later: the containers of the new projects, those of the projects
        gone removed, the processor time used meanwhile, the memory of the host."""
        running = self._running()
        for name in [name for name in self.projects if name not in running]:
            for cid in self.projects.pop(name)['ids']:
                self.docker.remove(cid)
        for name, (lab_hash, lab) in running.items():
            if name not in self.projects:
                containers, mem_mb, cpu = self._usage_of(lab)
                ids = [self.docker.add(lab_hash, mem=int(mem_mb * MIB / max(1, containers)), cpu_usec=0)
                       for _ in range(containers)]
                self.projects[name] = {'ids': ids, 'mem_mb': mem_mb, 'cpu': cpu, 'usec': 0.0}
        for project in self.projects.values():
            used = project['cpu'] * elapsed * 1e6
            project['usec'] += used
            self.host_usec += used
            for cid in project['ids']:
                self.docker.set(cid, cpu_usec=int(project['usec'] / len(project['ids'])))
        self.docker.host_cpu(int(self.host_usec))
        available = max(0.0, self.mem_total_mb - HOST_BASE_MB - sum(p['mem_mb'] for p in self.projects.values()))
        tmp = self.meminfo.with_suffix('.tmp')
        tmp.write_text(f"MemTotal:       {self.mem_total_mb * 1024} kB\nMemAvailable:   {int(available * 1024)} kB\n")
        tmp.replace(self.meminfo)


async def serve(directory, projects_dir, table: dict, *, mem_total_mb: int, interval: float):
    """Run a fake host until the task is cancelled (SIGTERM / SIGINT of ``main``)."""
    import asyncio
    import time
    async with FakeDocker(directory) as docker:
        simulation = Simulation(docker, projects_dir, table, mem_total_mb=mem_total_mb)
        last = time.monotonic()
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            simulation.step(now - last)
            last = now


def main(argv=None) -> int:
    import argparse
    import asyncio
    import contextlib
    import signal
    parser = argparse.ArgumentParser(prog='fake_docker', description="a fake Docker daemon and host for the fake pool")
    parser.add_argument('--dir', required=True, help="a short directory: docker.sock, cgroup/ and meminfo are made there")
    parser.add_argument('--follow', required=True, metavar='PROJECTS_DIR', help="the projects directory of the agent")
    parser.add_argument('--usage', default='{}', metavar='JSON',
                        help='{lab name: [containers, MiB, cores]} of a project of each lab '
                             f'(the others: {list(DEFAULT_USAGE)})')
    parser.add_argument('--mem-total-mb', type=int, default=16384, help="the memory of the fake host (16384)")
    parser.add_argument('--interval', type=float, default=1.0, help="seconds between two steps (1)")
    args = parser.parse_args(argv)
    table = json.loads(args.usage)

    async def run():
        task = asyncio.ensure_future(serve(args.dir, args.follow, table, mem_total_mb=args.mem_total_mb,
                                           interval=args.interval))
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, task.cancel)
        with contextlib.suppress(asyncio.CancelledError):
            await task
    asyncio.run(run())
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
