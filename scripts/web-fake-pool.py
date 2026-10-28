#!/usr/bin/env python3
"""web-fake-pool: a portal and N fake pool agents on the mock ``sre``, for the stress test.

Launches, from this checkout, N real agents (``python3 -m sreweb.agent``) whose ``sre`` is a wrapper
of ``tests/mock_sre.py`` (no Docker, no root: the projects are directories, the terminals are
``/bin/sh``), and one real portal (``python3 -m sreweb.portal``) in proxy authentication mode
trusting the loopback, with the production role header (``X-Remote-Gid`` = ``2000``), every host
with the same ``max_projects``, the admin token of ``[admin]`` and a connection log file.  Then it
prints ``portal=URL admin_token=TOKEN workdir=DIR`` and either waits for Ctrl-C or runs the command
given after ``--`` with ``SRE_STRESS_PORTAL``, ``SRE_STRESS_ADMIN_TOKEN`` and ``SRE_STRESS_WORKDIR``
in its environment (``scripts/web-stress.py`` reads the first two), and exits with its status.
Everything is stopped at the end; the work directory (configs, ``portal.log``, ``access.log``,
``<host>/agent.log`` and ``<host>/sre.log``) is removed unless ``--keep-workdir`` or a daemon died.

    venv/bin/python3 scripts/web-fake-pool.py --hosts 4 -- \\
        venv/bin/python3 scripts/web-stress.py --users 100 --ramp 60 --hold 120 --instructor --probe
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MOCK_SRE = ROOT / 'tests' / 'mock_sre.py'
ENV_PORTAL = 'SRE_STRESS_PORTAL'
ENV_ADMIN_TOKEN = 'SRE_STRESS_ADMIN_TOKEN'
ENV_WORKDIR = 'SRE_STRESS_WORKDIR'
READY_TIMEOUT = 30.0
STOP_TIMEOUT = 15.0
HOST_NAME = 'fake{:02d}'


@dataclass
class PoolOptions:
    hosts: int = 2
    max_projects: int = 25
    listen: str = '127.0.0.1:18450'
    start_delay: float = 0.5
    eval_delay: float = 1.0
    max_concurrent_starts: int = 2
    max_concurrent_evals: int = 2
    start_interval: float | None = None
    eval_interval: float | None = None
    poll_interval: float = 2.0
    workdir: str = ''
    keep_workdir: bool = False
    debug: bool = False
    command: list = field(default_factory=list)

    @property
    def host(self) -> str:
        return self.listen.rpartition(':')[0] or '127.0.0.1'

    @property
    def port(self) -> int:
        return int(self.listen.rpartition(':')[2])


@dataclass
class FakeHost:
    name: str
    dir: Path
    port: int
    token: str

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@dataclass
class PoolFiles:
    workdir: Path
    web_toml: Path
    admin_token: str
    hosts: list
    portal_url: str


def toml_str(value: str) -> str:
    return json.dumps(value)


def write_configs(opts: PoolOptions) -> PoolFiles:
    workdir = Path(opts.workdir).resolve() if opts.workdir else Path(tempfile.mkdtemp(prefix='web-fake-pool-'))
    workdir.mkdir(parents=True, exist_ok=True)
    hosts = []
    for i in range(opts.hosts):
        name = HOST_NAME.format(i + 1)
        host_dir = workdir / name
        (host_dir / 'pub').mkdir(parents=True, exist_ok=True)
        host = FakeHost(name=name, dir=host_dir, port=opts.port + 1 + i, token=secrets.token_hex(16))
        sre = host_dir / 'sre'
        sre.write_text(
            '#!/bin/sh\n'
            f'export MOCK_START_DELAY={opts.start_delay} MOCK_EVAL_DELAY={opts.eval_delay} '
            f'MOCK_SRE_LOG={toml_str(str(host_dir / "sre.log"))}\n'
            f'exec {toml_str(sys.executable)} -W ignore {toml_str(str(MOCK_SRE))} "$@"\n')
        sre.chmod(0o755)
        (host_dir / 'agent.toml').write_text(
            f'listen = {toml_str(f"127.0.0.1:{host.port}")}\n'
            f'token = {toml_str(host.token)}\n'
            f'sre_exe = {toml_str(str(sre))}\n'
            'poll_interval = 1\n'
            'occupied_check = "never"\n'
            f'max_concurrent_starts = {opts.max_concurrent_starts}\n'
            f'max_concurrent_evals = {opts.max_concurrent_evals}\n'
            'close_projects_on_stop = "never"\n'
            'shutdown_timeout = 5\n')
        hosts.append(host)
    admin_token = secrets.token_hex(16)
    limits = ''
    if opts.start_interval is not None or opts.eval_interval is not None:
        limits = '[limits]\n'
        if opts.start_interval is not None:
            limits += f'start_interval = {opts.start_interval}\n'
        if opts.eval_interval is not None:
            limits += f'eval_interval = {opts.eval_interval}\n'
    web = (
        f'listen = {toml_str(opts.listen)}\n'
        f'secret = {toml_str(secrets.token_hex(32))}\n'
        'trusted_proxies = ["127.0.0.1", "::1"]\n'
        '[auth]\nmode = "proxy"\n'
        '[auth.proxy]\n'
        'header_group = "X-Remote-Group"\n'
        'instructor_header = "X-Remote-Gid"\n'
        'instructor_values = ["2000"]\n'
        f'[pool]\npoll_interval = {opts.poll_interval}\nactive_hours = ""\n'
        f'[admin]\ntoken = {toml_str(admin_token)}\nstate_file = {toml_str(str(workdir / "pool.json"))}\n'
        f'[access_log]\nfile = {toml_str(str(workdir / "access.log"))}\njournal = false\n'
        + limits
        + ''.join(f'[[hosts]]\nname = {toml_str(h.name)}\nurl = {toml_str(h.url)}\ntoken = {toml_str(h.token)}\n'
                  f'max_projects = {opts.max_projects}\n' for h in hosts))
    web_toml = workdir / 'web.toml'
    web_toml.write_text(web)
    return PoolFiles(workdir=workdir, web_toml=web_toml, admin_token=admin_token, hosts=hosts,
                     portal_url=f"http://{opts.host}:{opts.port}")


def daemon_env() -> dict:
    return {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}


def start_agents(files: PoolFiles, opts: PoolOptions) -> dict:
    procs = {}
    for host in files.hosts:
        log = open(host.dir / 'agent.log', 'ab')
        argv = [sys.executable, '-m', 'sreweb.agent', '--config', str(host.dir / 'agent.toml'),
                '--listen', f"127.0.0.1:{host.port}", '--pub-dir', str(host.dir / 'pub')] + (['--debug'] if opts.debug else [])
        procs[host.name] = subprocess.Popen(argv, env=daemon_env(), stdout=log, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, cwd=str(ROOT))
        log.close()
    return procs


def start_portal(files: PoolFiles, opts: PoolOptions) -> subprocess.Popen:
    log = open(files.workdir / 'portal.log', 'ab')
    argv = [sys.executable, '-m', 'sreweb.portal', '--config', str(files.web_toml), '--web-dir', str(ROOT / 'web')] \
        + (['--debug'] if opts.debug else [])
    proc = subprocess.Popen(argv, env=daemon_env(), stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            cwd=str(ROOT))
    log.close()
    return proc


def http_get(url: str, headers: dict, timeout: float = 5.0):
    """``(status, body)`` or ``(None, error)`` of a GET."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return None, str(e)


def wait_http(url: str, headers: dict, ok, timeout: float, procs: list) -> str:
    """Poll *url* until *ok(status, body)*; '' or the reason it did not happen (a daemon that
    died, the timeout)."""
    deadline = time.monotonic() + timeout
    while True:
        status, body = http_get(url, headers)
        if status is not None and ok(status, body):
            return ''
        for name, proc in procs:
            if proc.poll() is not None:
                return f"{name} exited with status {proc.returncode}"
        if time.monotonic() > deadline:
            return f"{url}: not ready after {timeout:.0f} s (last answer: {status} {str(body)[:120]})"
        time.sleep(0.2)


def all_reachable(status, body) -> bool:
    if status != 200:
        return False
    try:
        rows = json.loads(body)
    except ValueError:
        return False
    return isinstance(rows, list) and bool(rows) and all(r.get('reachable') for r in rows)


def stop_all(procs: list, timeout: float = STOP_TIMEOUT):
    """SIGTERM then SIGKILL, the portal first (its sockets to the agents close), then the agents."""
    for _, proc in procs:
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + timeout
    for _, proc in procs:
        remaining = max(0.1, deadline - time.monotonic())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def run_command(command: list, files: PoolFiles) -> int:
    env = {**os.environ, ENV_PORTAL: files.portal_url, ENV_ADMIN_TOKEN: files.admin_token,
           ENV_WORKDIR: str(files.workdir)}
    return subprocess.call(command, env=env)


def wait_for_signal(procs: list) -> str:
    """Until SIGINT / SIGTERM, or a daemon dies ('' or the reason)."""
    stopped = []

    def handler(signum, frame):
        stopped.append(signum)
    previous = {s: signal.signal(s, handler) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        while not stopped:
            for name, proc in procs:
                if proc.poll() is not None:
                    return f"{name} exited with status {proc.returncode}"
            time.sleep(0.5)
        return ''
    finally:
        for s, h in previous.items():
            signal.signal(s, h)


def parse_args(argv=None) -> PoolOptions:
    argv = sys.argv[1:] if argv is None else list(argv)
    command = []
    if '--' in argv:
        i = argv.index('--')
        argv, command = argv[:i], argv[i + 1:]
    p = argparse.ArgumentParser(prog='web-fake-pool', description=__doc__.split('\n\n')[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="A command after `--` runs against the pool, then everything is stopped.")
    p.add_argument('--hosts', type=int, default=2, help="number of fake agents (2)")
    p.add_argument('--max-projects', type=int, default=25, help="max_projects of each host (25)")
    p.add_argument('--listen', default='127.0.0.1:18450', help="portal address (127.0.0.1:18450); the agents take the next ports")
    p.add_argument('--start-delay', type=float, default=0.5, help="MOCK_START_DELAY: seconds per step of a start, 7 steps (0.5)")
    p.add_argument('--eval-delay', type=float, default=1.0, help="MOCK_EVAL_DELAY: seconds per evaluation (1)")
    p.add_argument('--max-concurrent-starts', type=int, default=2, help="per agent (2, the production default)")
    p.add_argument('--max-concurrent-evals', type=int, default=2, help="per agent (2)")
    p.add_argument('--start-interval', type=float, default=None, help="[limits] start_interval of the portal (default 30)")
    p.add_argument('--eval-interval', type=float, default=None, help="[limits] eval_interval of the portal (default 10)")
    p.add_argument('--poll-interval', type=float, default=2.0, help="[pool] poll_interval of the portal (2)")
    p.add_argument('--workdir', default='', help="work directory (default: a temporary one)")
    p.add_argument('--keep-workdir', action='store_true', help="keep the work directory and its logs")
    p.add_argument('--debug', action='store_true', help="debug logging of the daemons")
    a = p.parse_args(argv)
    if a.hosts < 1:
        p.error("--hosts must be at least 1")
    if a.start_delay < 0 or a.eval_delay < 0 or a.poll_interval <= 0:
        p.error("the delays must be positive")
    if not a.listen.rpartition(':')[2].isdigit():
        p.error("--listen must be host:port")
    return PoolOptions(hosts=a.hosts, max_projects=a.max_projects, listen=a.listen, start_delay=a.start_delay,
                       eval_delay=a.eval_delay, max_concurrent_starts=a.max_concurrent_starts,
                       max_concurrent_evals=a.max_concurrent_evals, start_interval=a.start_interval,
                       eval_interval=a.eval_interval, poll_interval=a.poll_interval, workdir=a.workdir,
                       keep_workdir=a.keep_workdir, debug=a.debug, command=command)


def main(argv=None) -> int:
    opts = parse_args(argv)
    if not MOCK_SRE.is_file():
        print(f"web-fake-pool: {MOCK_SRE}: no such file", file=sys.stderr)
        return 2
    files = write_configs(opts)
    procs: list = []
    status = 0
    failure = ''
    try:
        agents = start_agents(files, opts)
        procs.extend(agents.items())
        for host in files.hosts:
            failure = wait_http(f"{host.url}/v1/status", {'Authorization': f"Bearer {host.token}"},
                                lambda s, b: s == 200, READY_TIMEOUT, procs)
            if failure:
                break
        if not failure:
            portal = start_portal(files, opts)
            procs.append(('portal', portal))
            failure = wait_http(f"{files.portal_url}/api/pool", {'Authorization': f"Bearer {files.admin_token}"},
                                all_reachable, READY_TIMEOUT, procs)
        if failure:
            status = 1
        else:
            print(f"portal={files.portal_url} admin_token={files.admin_token} workdir={files.workdir}", flush=True)
            if opts.command:
                status = run_command(opts.command, files)
            else:
                print("web-fake-pool: running, Ctrl-C stops everything", file=sys.stderr, flush=True)
                failure = wait_for_signal(procs)
                if failure:
                    status = 1
    finally:
        stop_all(procs)
        if failure:
            print(f"web-fake-pool: {failure}; logs kept in {files.workdir}", file=sys.stderr)
        elif not opts.keep_workdir:
            shutil.rmtree(files.workdir, ignore_errors=True)
        else:
            print(f"web-fake-pool: work directory kept: {files.workdir}", file=sys.stderr)
    return status


if __name__ == '__main__':
    sys.exit(main())
