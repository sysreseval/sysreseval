"""``sre-web-tool ...``: manage the pool of the running portal from the command line,
through its administration API (``[admin] token`` of web.toml; stdlib ``urllib`` only).

  sre-web-tool list                 the hosts, their state, projects, load, terminals...
  sre-web-tool status               the spare capacity, the floor, the active hours, who is waking, the state file
  sre-web-tool add NAME --url URL --token TOKEN [--mac MAC | --wake-command CMD] [--max-projects N] [--power] [--instructors-only] [--priority GROUP:ORDER] [--total-usable-capacity PERCENT]
  sre-web-tool remove NAME [--force]
  sre-web-tool enable | disable | wake | poweroff | drain NAME
  sre-web-tool allow-local-drain | forbid-local-drain NAME   whether the host may ask for its own drain (sre set-drain)
  sre-web-tool priority NAME GROUP:ORDER   a new project goes to the lowest group that has an available host, and
                                    in it to the lowest order among the hosts without project (0:0 by default)
  sre-web-tool usable-capacity NAME PERCENT   the share of the memory and processors of the host its projects
                                    may fill (100 by default; with [pool] capacity = "resources")
  sre-web-tool reset-settings       the priority and the usable capacity of every host back to the values of
                                    the configuration
  sre-web-tool restart NAME | --all [--wait] [--timeout S]   the agents restart themselves (new code after an update)
  sre-web-tool preload NAME | --all | --failed   the hosts pull the Docker images of the labs, a few at a time
"""
import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

from ..agent.runner import PRELOAD_PENDING, PRELOAD_RUNNING, PRELOAD_FAILED
from ..config import (load_web_config, check_priority, check_usable_capacity, Priority, ConfigError,
                      DEFAULT_USABLE_CAPACITY, USABLE_CAPACITY_KEY)

PROG = 'sre-web-tool'
ERROR_WIDTH = 60
RESTART_WAIT_TIMEOUT = 180.0    # --wait: seconds for the agents to be back (the portal's hold is 120 s)
RESTART_POLL = 2.0              # --wait: seconds between two readings of the pool
_INTEGER_RE = re.compile(r'^-?\d+$')
# what argparse takes for a value and not for an option: a negative number and, added here for
# the sub-commands taking a priority, a "group:order" whose group is negative ("-1:5")
_NEGATIVE_VALUE_RE = re.compile(r'^-\d+(:-?\d+)?$|^-\d*\.\d+$')
COLUMNS = [('name', 'NAME'), ('state', 'STATE'), ('projects', 'PROJECTS'), ('load1', 'LOAD'),
           ('mem_available_mb', 'FREE MEM'), ('cpu_used', 'CPU'), ('terminals', 'TERMINALS'), ('occupied_by', 'OCCUPIED'),
           ('uptime', 'UPTIME'), ('source', 'SOURCE'), ('error', 'LAST ERROR')]
# `costs`: what a project of each lab costs a host (the rows are formatted by cost_rows())
COSTS_COLUMNS = [('lab', 'LAB'), ('weight', 'WEIGHT'), ('containers', 'CONTAINERS'), ('memory', 'MEMORY'),
                 ('cpu', 'CPU'), ('samples', 'PROJECTS'), ('source', 'SOURCE')]


class CallError(Exception):
    """A failed call of the portal: *code* is the HTTP status, None when it could not be reached."""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self):
        return f"{self.message} ({self.code})" if self.code is not None else self.message


class PoolClient:
    def __init__(self, url: str, token: str, cafile: str = ''):
        self.url = url.rstrip('/')
        self.token = token
        self.context = None
        if cafile:   # the portal's own certificate, reached on the loopback: pinned, whatever its names
            self.context = ssl.create_default_context(cafile=cafile)
            self.context.check_hostname = False

    def call(self, method: str, path: str, body=None):
        data = json.dumps(body).encode('utf-8') if body is not None else None
        request = urllib.request.Request(self.url + path, data=data, method=method,
                                         headers={'Authorization': f'Bearer {self.token}',
                                                  'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=60, context=self.context) as resp:
                text = resp.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            text = e.read().decode('utf-8', 'replace')
            try:
                message = json.loads(text).get('error', text)
            except ValueError:
                message = text
            raise CallError(message, e.code)
        except (urllib.error.URLError, OSError) as e:
            raise CallError(f"cannot reach the portal at {self.url}: {e.reason if hasattr(e, 'reason') else e}")
        return json.loads(text) if text else None


def _cell(row: dict, key: str) -> str:
    value = row.get(key)
    if key == 'projects':
        return f"{row.get('projects', 0)}/{row.get('max_projects', '?')}" if row.get('reachable') else '-'
    if key == 'load1':
        return f"{value:.2f}" if isinstance(value, (int, float)) else '-'
    if key == 'mem_available_mb':       # MemAvailable of the host (an older agent or portal says nothing)
        if isinstance(value, (int, float)) and row.get('reachable'):
            return f"{value / 1024:.1f}G"
        return '-' if row.get('reachable') else ''
    if key == 'cpu_used':       # the cores the projects of the host are counted for / those they may use
        capacity = row.get('cpu_capacity')
        if isinstance(value, (int, float)) and isinstance(capacity, (int, float)) and row.get('reachable'):
            return f"{value:.1f}/{capacity:.1f}"
        return '-' if row.get('reachable') else ''
    if key == 'terminals':
        return str(value) if row.get('reachable') else '-'
    if key == 'occupied_by':
        return ','.join(value) if value else ('-' if row.get('reachable') else '')
    if key == 'uptime':
        if not isinstance(value, (int, float)):
            return '-' if row.get('reachable') else ''
        hours, minutes = divmod(int(value) // 60, 60)
        return f"{hours}h{minutes:02d}"
    if key == 'state':
        extra = []
        if row.get('waking_for') is not None:
            extra.append(f"{row['waking_for']}s")
        if row.get('wake_failures'):
            extra.append(f"{row['wake_failures']} failed")
        if row.get('local_drain'):      # asked on the host itself (sre set-drain)
            extra.append('local drain')
        elif row.get('drain') and value != 'draining':
            extra.append('drain')
        if row.get('restart_sent'):
            extra.append('restart')
        if row.get('exam_hold') and value != 'exam':    # about to be locked by an exam of the Exams page
            extra.append('kept for an exam')
        if row.get('memory_room') == 0 and row.get('reachable'):    # [pool] project_memory_mb: no new project
            extra.append('memory full')
        if row.get('cpu_room') == 0 and row.get('reachable'):       # [pool] capacity = "resources": no new project
            extra.append('cpu full')
        if row.get('preload') == PRELOAD_RUNNING:       # the Docker images: pulling (image 2 of 5), waiting, failed
            total = row.get('preload_total')
            extra.append(f"preload {row.get('preload_current', 0)}/{total}" if total else 'preload')
        elif row.get('preload') == PRELOAD_PENDING:
            extra.append('preload queued')
        elif row.get('preload') == PRELOAD_FAILED:
            extra.append('preload failed')
        if row.get('instructors_only'):
            extra.append('instructors')
        if row.get('priority') not in (None, 0, str(Priority())):    # group:order, not the default: the lowest is used first
            extra.append(f"priority {row['priority']}")
        if row.get(USABLE_CAPACITY_KEY) not in (None, DEFAULT_USABLE_CAPACITY):     # not the whole host
            extra.append(f"capacity {row[USABLE_CAPACITY_KEY]}%")
        return value + (f" ({', '.join(extra)})" if extra else '')
    if key == 'error':
        text = '' if row.get('reachable') else (value or '')
        return text if len(text) <= ERROR_WIDTH else text[:ERROR_WIDTH - 1] + '…'
    return '' if value is None else str(value)


def _figure(value, form: str) -> str:
    return form.format(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else '-'


def cost_rows(labs: list) -> list:
    """The rows of ``GET /api/pool/costs`` as `costs` prints them (``COSTS_COLUMNS``): the weight
    the lab declares, the containers its projects had, the memory and the cores one more project
    is counted for, the projects that were measured, and where the cost comes from."""
    return [{'lab': str(row.get('lab', '')), 'weight': _figure(row.get('weight'), '{:g}'),
             'containers': _figure(row.get('containers'), '{:.0f}'), 'memory': _figure(row.get('mem_mb'), '{:.0f}M'),
             'cpu': _figure(row.get('cpu'), '{:.3f}'), 'samples': _figure(row.get('samples'), '{:.0f}'),
             'source': str(row.get('source', ''))} for row in labs if isinstance(row, dict)]


def cost_lines(costs: dict) -> list:
    """What `costs` prints above its table: the cost of a lab the pool knows nothing of, what a
    unit of weight stands for and what the measures of the pool say it is, the file."""
    def pair(value) -> str:
        if not isinstance(value, dict):
            return '?'
        return f"{_figure(value.get('mem_mb'), '{:g}')} MiB, {_figure(value.get('cpu'), '{:g}')} core"
    lines = [f"a lab never seen, without weight: {pair(costs.get('default'))}"]
    measured = costs.get('measured_unit')
    lines.append(f"one unit of weight: {pair(costs.get('weight_unit'))}"
                 + (f" (measured on this pool: {pair(measured)})" if measured else " (nothing measured yet)"))
    if costs.get('error'):
        lines.append(f"costs: NOT SAVED in {costs.get('file') or '?'}: {costs['error']}")
    else:
        lines.append(f"costs: {costs.get('file') or 'not kept (no state file)'}")
    return lines


def table(rows: list, columns=COLUMNS) -> str:
    cells = [[_cell(row, key) for key, _ in columns] for row in rows]
    widths = [max(len(title), *(len(c[i]) for c in cells)) if cells else len(title) for i, (_, title) in enumerate(columns)]
    lines = ['  '.join(title.ljust(widths[i]) for i, (_, title) in enumerate(columns)).rstrip()]
    for c in cells:
        lines.append('  '.join(c[i].ljust(widths[i]) for i in range(len(columns))).rstrip())
    return '\n'.join(lines)


def _portal_url(cfg) -> str:
    """The URL of the running portal for this command: its listening port (never the reverse
    proxy), under its ``base_path`` when the site lives in a sub-path."""
    host, port = cfg.listen
    if host in ('0.0.0.0', '', '::'):
        host = '127.0.0.1'
    scheme = 'https' if cfg.tls_cert else 'http'
    return f"{scheme}://{host}:{port}{cfg.base_path}"


def restart_hosts(client: PoolClient, names: list | None, *, wait: bool, timeout: float, as_json: bool) -> int:
    """``restart NAME`` / ``restart --all`` (*names* None: every reachable host of the pool,
    whatever its state: the point is the code of the agent): one POST per host, answered at
    once (the agents restart concurrently, once their sre commands are over).  With *wait*, the
    pool is read every RESTART_POLL seconds until each agent is back with an uptime younger
    than its request, at most *timeout* seconds.  The rows of the hosts restarted are printed,
    the failures on stderr; 1 when any failed."""
    if names is None:
        names = [row['name'] for row in client.call('GET', '/api/pool') if row.get('reachable')]
        if not names:
            print(f"{PROG}: no reachable host in the pool", file=sys.stderr)
            return 1
    rows, sent, failures = _post_each(client, names, 'restart')
    if wait and sent:
        failures.extend(_wait_restarted(client, sent, timeout, rows))
    return _report(rows, failures, as_json)


def _post_each(client: PoolClient, names: list, action: str) -> tuple:
    """One ``POST /api/pool/hosts/<name>/<action>`` per host: the rows answered, when each
    request was accepted (``{name: monotonic time}``) and the texts of the failures."""
    rows, sent, failures = [], {}, []
    for name in names:
        try:
            rows.append(client.call('POST', f"/api/pool/hosts/{name}/{action}"))
            sent[name] = time.monotonic()
        except CallError as e:
            failures.append(f"{name}: {e}")
    return rows, sent, failures


def _report(rows: list, failures: list, as_json: bool) -> int:
    """The rows on stdout, the failures on stderr; 1 when any failed."""
    if rows:
        print(json.dumps(rows, indent=2) if as_json else table(rows))
    for failure in failures:
        print(f"{PROG}: {failure}", file=sys.stderr)
    return 1 if failures else 0


def preload_hosts(client: PoolClient, names: list | None, *, failed_only: bool, as_json: bool) -> int:
    """``preload NAME`` / ``preload --all`` (*names* None: every reachable host whose agent
    knows the preload) / ``preload --failed`` (those whose last preload failed): the hosts are
    asked to pull the Docker images of the labs, each waits for its turn (``preload queued`` in
    ``list``) and the portal lets ``[pool] max_preloads`` of them download at the same time.  The
    rows of the hosts asked are printed, the failures on stderr; 1 when any failed."""
    if names is None:
        rows = [row for row in client.call('GET', '/api/pool') if row.get('reachable') and row.get('preload')]
        names = [row['name'] for row in rows if not failed_only or row['preload'] == PRELOAD_FAILED]
        if not names:
            if failed_only:
                print("no host whose preload failed")
                return 0
            print(f"{PROG}: no reachable host whose agent knows the preload", file=sys.stderr)
            return 1
    rows, _, failures = _post_each(client, names, 'preload')
    return _report(rows, failures, as_json)


def _wait_restarted(client: PoolClient, sent: dict, timeout: float, rows: list) -> list:
    """Read the pool until every host of *sent* (``{name: monotonic time of its request}``) is
    reachable with an agent uptime younger than the request (the value of the portal's last
    poll, a few seconds old at most); *rows* are replaced by the last ones read.  The texts of
    the hosts not back after *timeout* seconds."""
    deadline = time.monotonic() + timeout
    pending = dict(sent)
    latest = {}
    while pending:
        time.sleep(min(RESTART_POLL, max(0.0, deadline - time.monotonic())))
        now = time.monotonic()
        for row in client.call('GET', '/api/pool'):
            latest[row['name']] = row
            when = pending.get(row['name'])
            if when is not None and row.get('reachable') and isinstance(row.get('agent_uptime'), (int, float)) \
                    and row['agent_uptime'] + 0.5 < now - when:      # rounded to the second by the agent
                del pending[row['name']]
        if now >= deadline:
            break
    rows[:] = [latest.get(row.get('name'), row) for row in rows]
    failures = []
    for name in pending:
        row = latest.get(name, {})
        if row.get('reachable'):
            failures.append(f"{name}: did not restart within {timeout:.0f} s (agent up for {row.get('agent_uptime')} s)")
        else:
            failures.append(f"{name}: did not come back within {timeout:.0f} s")
    return failures


def _priority(text: str) -> str:
    """A priority given on the command line, as the portal reads it: "group:order", or one
    integer, that order in group 0 (the argparse type of ``priority`` and ``add --priority``)."""
    try:
        return str(check_priority(int(text) if _INTEGER_RE.match(text) else text, "the priority"))
    except ConfigError as e:
        raise argparse.ArgumentTypeError(str(e))


def _usable_capacity(text: str) -> int:
    """A share of a host given on the command line, as the portal reads it: a percentage, an
    integer from 1 to 100 (the argparse type of ``usable-capacity`` and ``add
    --total-usable-capacity``)."""
    try:
        return check_usable_capacity(int(text) if _INTEGER_RE.match(text) else text, "the usable capacity")
    except ConfigError as e:
        raise argparse.ArgumentTypeError(str(e))


def main(argv, default_config: str) -> int:
    parser = argparse.ArgumentParser(prog=PROG, description="manage the pool of the running portal")
    parser.add_argument('--config', default=default_config, help="web.toml (the portal address and the admin token)")
    parser.add_argument('--url', default=None, help="the portal (default: from the configuration)")
    parser.add_argument('--token', default=None, help="the admin token (default: [admin] token of the configuration)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--json', action='store_true', help="JSON output")
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help="the hosts of the pool", parents=[common])
    sub.add_parser('status', help="spare capacity, floor, active hours, hosts waking, the state file",
                   parents=[common])
    sub.add_parser('costs', help="what a project of each lab costs a host (memory, processors): measured on "
                                 "the running projects, else from the weight the lab declares", parents=[common])
    add = sub.add_parser('add', help="add a host", parents=[common])
    add.add_argument('name')
    add.add_argument('--url', required=True, dest='host_url', help="the agent, e.g. https://10.0.0.11:8451")
    add.add_argument('--token', required=True, dest='host_token', help="the token of agent.toml")
    add.add_argument('--mac', default='', help="Wake-on-LAN address")
    add.add_argument('--wake-command', default='', help="command waking the host ({name}, {mac})")
    add.add_argument('--max-projects', type=int, default=25)
    add.add_argument('--power', action='store_true', help="the portal may power it off")
    add.add_argument('--instructors-only', action='store_true', help="only the instructors' projects are placed there")
    add.add_argument('--priority', type=_priority, default=None, metavar='GROUP:ORDER',
                     help="the lowest group is used first, then the lowest order in it (default: 0:0)")
    add.add_argument('--total-usable-capacity', type=_usable_capacity, default=None, metavar='PERCENT',
                     help="the share of the memory and processors of the host its projects may fill, 1 to 100 "
                          "(100)")
    remove = sub.add_parser('remove', help="remove a host", parents=[common])
    remove.add_argument('name')
    remove.add_argument('--force', action='store_true', help="even with projects (they stay on the host)")
    for action, text in (('enable', "place projects on the host again"), ('disable', "no new project (the running ones go on, the host is never powered off)"),
                         ('wake', "wake the host now"), ('poweroff', "power the host off now (refused with projects)"),
                         ('drain', "no new project, power off when empty"),
                         ('allow-local-drain', "the host may ask for its own drain (sre set-drain there), until its next boot"),
                         ('forbid-local-drain', "the host may not ask for its own drain, until its next boot; "
                                                "cancels the one it asked for")):
        sub.add_parser(action, help=text, parents=[common]).add_argument('name')
    priority = sub.add_parser('priority', help="set the priority of the host, group:order: a new project goes to the "
                                               "lowest group that has an available host and, in it, to the lowest "
                                               "order among the hosts without project; the hosts are woken in that "
                                               "order and powered off in the reverse one", parents=[common])
    priority.add_argument('name')
    priority.add_argument('value', type=_priority, metavar='GROUP:ORDER',
                          help="two integers, 0:0 by default (negative ones: before the others; one integer: "
                               "that order in group 0)")
    usable = sub.add_parser('usable-capacity', help="set the share of the memory and of the processors of the host "
                                                    "its projects may fill, in percent (100: the whole host); "
                                                    "it counts with [pool] capacity = \"resources\"",
                            parents=[common])
    usable.add_argument('name')
    usable.add_argument('value', type=_usable_capacity, metavar='PERCENT', help="an integer from 1 to 100")
    sub.add_parser('reset-settings', help="the priority and the usable capacity of every host back to the values "
                                          "of the configuration (web.toml; the entry it was added with for a "
                                          "host added by hand)", parents=[common])
    for parser_with_priority in (add, priority):      # "-1:5" is a value there, as "-2" is everywhere
        parser_with_priority._negative_number_matcher = _NEGATIVE_VALUE_RE
    restart = sub.add_parser('restart', help="the agent of a host restarts itself (new code after an update; "
                                             "the projects stay, the open terminals are lost)", parents=[common])
    restart.add_argument('name', nargs='?', help="the host (or --all)")
    restart.add_argument('--all', action='store_true', help="every reachable host of the pool")
    restart.add_argument('--wait', action='store_true', help="wait until the agents are back")
    restart.add_argument('--timeout', type=float, default=RESTART_WAIT_TIMEOUT,
                         help="seconds to wait with --wait (default: %(default)s)")
    preload = sub.add_parser('preload', help="the host pulls the Docker images of the labs when its turn comes "
                                             "(the portal lets a few hosts download at a time)", parents=[common])
    preload.add_argument('name', nargs='?', help="the host (or --all, --failed)")
    preload.add_argument('--all', action='store_true', help="every reachable host of the pool")
    preload.add_argument('--failed', action='store_true', help="the hosts whose last preload failed")
    args = parser.parse_args(argv)
    if args.command == 'restart' and bool(args.name) == args.all:
        restart.error("give a host name or --all")
    if args.command == 'preload' and (bool(args.name), args.all, args.failed).count(True) != 1:
        preload.error("give a host name, --all or --failed")

    url, token, cafile = args.url, args.token, ''
    if url is None or token is None:
        try:
            cfg = load_web_config(args.config)
        except ConfigError as e:
            print(f"{PROG}: {e}", file=sys.stderr)
            return 1
        if url is None:
            url, cafile = _portal_url(cfg), cfg.tls_cert
        token = token or cfg.admin.token
    if not token:
        print(f"{PROG}: no administration token ([admin] token in web.toml, or --token)", file=sys.stderr)
        return 1
    client = PoolClient(url, token, cafile)
    try:
        return _dispatch(client, args)
    except CallError as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 1


def _dispatch(client: PoolClient, args) -> int:
    if args.command == 'list':
        rows = client.call('GET', '/api/pool')
        print(json.dumps(rows, indent=2) if args.json else table(rows))
    elif args.command == 'status':
        status = client.call('GET', '/api/pool/status')
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print(f"spare capacity: {status['spare_projects']} project slot(s) (wanted: {status['wanted_spare']})")
            print(f"hosts awake: {status['awake']} (floor: {status['min_hosts_up']} during {status['active_hours']}, "
                  f"{'active' if status['active_now'] else 'inactive'} now)")
            print(f"waking: {', '.join(status['waking']) or 'none'}")
            print(f"idle host timeout: {status['idle_host_timeout'] or 'never (the nightly cron)'}")
            if 'project_memory_mb' in status:   # an older portal says nothing
                memory = status.get('project_memory_mb') or 0
                if memory:
                    full = ', '.join(status.get('memory_full') or []) or 'none'
                    print(f"memory per project: {memory} MiB (memory full: {full})")
                else:
                    print("memory per project: not checked")
            if status.get('capacity') == 'resources':   # the hosts hold what their memory and processors hold
                reference = status.get('reference') or {}
                full = ', '.join(status.get('cpu_full') or []) or 'none'
                memory_full = ', '.join(status.get('memory_full') or []) or 'none'
                print(f"capacity: resources (a slot: {_figure(reference.get('mem_mb'), '{:g}')} MiB, "
                      f"{_figure(reference.get('cpu'), '{:g}')} core; memory full: {memory_full}; cpu full: {full})")
            elif 'capacity' in status:
                print("capacity: projects (the number of projects of a host)")
            if 'cpu_target' in status:          # the load of a host in memory and processors (an older portal says nothing)
                unit = status.get('weight_unit') or {}
                share = status['cpu_target'] * 100 if isinstance(status['cpu_target'], (int, float)) else None
                print(f"load of a host: {_figure(status.get('memory_reserve_mb'), '{:g}')} MiB of memory kept free, "
                      f"{_figure(share, '{:.0f}')} % of its processors for the projects; "
                      f"one unit of weight: {_figure(unit.get('mem_mb'), '{:g}')} MiB, "
                      f"{_figure(unit.get('cpu'), '{:g}')} core")
            if 'max_preloads' in status:        # the preloads of the Docker images (an older portal says nothing)
                running = status.get('preloading') or []
                names = f" ({', '.join(running)})" if running else ''
                print(f"image preloads: {len(running)} running{names}, {status.get('preload_queued', 0)} queued, "
                      f"{status.get('preload_failed', 0)} failed (at most {status['max_preloads']} at a time)")
            # what is changed by hand, kept across the restarts of the portal (an older portal says nothing)
            if status.get('state_error'):
                print(f"pool state: NOT SAVED in {status.get('state_file') or '?'}: {status['state_error']}")
            elif 'state_file' in status:
                print(f"pool state: {status['state_file'] or 'not kept (no state file)'}")
    elif args.command == 'costs':
        costs = client.call('GET', '/api/pool/costs')
        if args.json:
            print(json.dumps(costs, indent=2))
        else:
            print('\n'.join(cost_lines(costs)))
            print(table(cost_rows(costs.get('labs') or []), COSTS_COLUMNS))
    elif args.command == 'add':
        body = {'name': args.name, 'url': args.host_url, 'token': args.host_token, 'max_projects': args.max_projects,
                'mac': args.mac, 'wake_command': args.wake_command, 'power': args.power,
                'instructors_only': args.instructors_only}
        if args.priority is not None:   # left out unless given: a portal not restarted yet refuses what it does not know
            body['priority'] = args.priority
        if args.total_usable_capacity is not None:      # the same
            body[USABLE_CAPACITY_KEY] = args.total_usable_capacity
        row = client.call('POST', '/api/pool/hosts', body)
        print(json.dumps(row, indent=2) if args.json else table([row]))
    elif args.command == 'priority':
        row = client.call('POST', f"/api/pool/hosts/{args.name}/priority", {'priority': args.value})
        print(json.dumps(row, indent=2) if args.json else table([row]))
    elif args.command == 'usable-capacity':
        row = client.call('POST', f"/api/pool/hosts/{args.name}/usable-capacity",
                          {USABLE_CAPACITY_KEY: args.value})
        print(json.dumps(row, indent=2) if args.json else table([row]))
    elif args.command == 'reset-settings':
        answer = client.call('POST', '/api/pool/reset-settings')
        names = (answer or {}).get('reset') or []
        if args.json:
            print(json.dumps(answer, indent=2))
        else:
            print(f"settings reset on {len(names)} host(s): {', '.join(names)}" if names else "nothing to reset")
    elif args.command == 'remove':
        client.call('DELETE', f"/api/pool/hosts/{args.name}" + ('?force=1' if args.force else ''))
        print(f"{args.name} removed")
    elif args.command == 'restart':
        return restart_hosts(client, None if args.all else [args.name], wait=args.wait, timeout=args.timeout,
                             as_json=args.json)
    elif args.command == 'preload':
        return preload_hosts(client, [args.name] if args.name else None, failed_only=args.failed, as_json=args.json)
    else:
        row = client.call('POST', f"/api/pool/hosts/{args.name}/{args.command}")
        print(json.dumps(row, indent=2) if args.json else table([row]))
    return 0
