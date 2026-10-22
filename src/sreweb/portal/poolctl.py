"""``sre-web pool ...``: manage the pool of the running portal from the command line, through
its administration API (``[admin] token`` of web.toml; stdlib ``urllib`` only).

  sre-web pool list                 the hosts, their state, projects, load, terminals...
  sre-web pool status               the spare capacity, the floor, the active hours, who is waking
  sre-web pool add NAME --url URL --token TOKEN [--mac MAC | --wake-command CMD] [--max-projects N] [--power]
  sre-web pool remove NAME [--force]
  sre-web pool enable | disable | wake | poweroff | drain NAME
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

from ..config import load_web_config, ConfigError

ERROR_WIDTH = 60
COLUMNS = [('name', 'NAME'), ('state', 'STATE'), ('projects', 'PROJECTS'), ('load1', 'LOAD'),
           ('terminals', 'TERMINALS'), ('occupied_by', 'OCCUPIED'), ('uptime', 'UPTIME'), ('source', 'SOURCE'),
           ('error', 'LAST ERROR')]


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
            raise SystemExit(f"sre-web pool: {message} ({e.code})")
        except (urllib.error.URLError, OSError) as e:
            raise SystemExit(f"sre-web pool: cannot reach the portal at {self.url}: {e.reason if hasattr(e, 'reason') else e}")
        return json.loads(text) if text else None


def _cell(row: dict, key: str) -> str:
    value = row.get(key)
    if key == 'projects':
        return f"{row.get('projects', 0)}/{row.get('max_projects', '?')}" if row.get('reachable') else '-'
    if key == 'load1':
        return f"{value:.2f}" if isinstance(value, (int, float)) else '-'
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
        if row.get('drain') and value != 'draining':
            extra.append('drain')
        return value + (f" ({', '.join(extra)})" if extra else '')
    if key == 'error':
        text = '' if row.get('reachable') else (value or '')
        return text if len(text) <= ERROR_WIDTH else text[:ERROR_WIDTH - 1] + '…'
    return '' if value is None else str(value)


def table(rows: list, columns=COLUMNS) -> str:
    cells = [[_cell(row, key) for key, _ in columns] for row in rows]
    widths = [max(len(title), *(len(c[i]) for c in cells)) if cells else len(title) for i, (_, title) in enumerate(columns)]
    lines = ['  '.join(title.ljust(widths[i]) for i, (_, title) in enumerate(columns)).rstrip()]
    for c in cells:
        lines.append('  '.join(c[i].ljust(widths[i]) for i in range(len(columns))).rstrip())
    return '\n'.join(lines)


def _portal_url(cfg) -> str:
    host, port = cfg.listen
    if host in ('0.0.0.0', '', '::'):
        host = '127.0.0.1'
    scheme = 'https' if cfg.tls_cert else 'http'
    return f"{scheme}://{host}:{port}"


def main(argv, default_config: str) -> int:
    parser = argparse.ArgumentParser(prog='sre-web pool', description="manage the pool of the running portal")
    parser.add_argument('--config', default=default_config, help="web.toml (the portal address and the admin token)")
    parser.add_argument('--url', default=None, help="the portal (default: from the configuration)")
    parser.add_argument('--token', default=None, help="the admin token (default: [admin] token of the configuration)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--json', action='store_true', help="JSON output")
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help="the hosts of the pool", parents=[common])
    sub.add_parser('status', help="spare capacity, floor, active hours, hosts waking", parents=[common])
    add = sub.add_parser('add', help="add a host", parents=[common])
    add.add_argument('name')
    add.add_argument('--url', required=True, dest='host_url', help="the agent, e.g. https://10.0.0.11:8451")
    add.add_argument('--token', required=True, dest='host_token', help="the token of agent.toml")
    add.add_argument('--mac', default='', help="Wake-on-LAN address")
    add.add_argument('--wake-command', default='', help="command waking the host ({name}, {mac})")
    add.add_argument('--max-projects', type=int, default=25)
    add.add_argument('--power', action='store_true', help="the portal may power it off")
    remove = sub.add_parser('remove', help="remove a host", parents=[common])
    remove.add_argument('name')
    remove.add_argument('--force', action='store_true', help="even with projects (they stay on the host)")
    for action, text in (('enable', "place projects on the host again"), ('disable', "keep the host polled, place nothing"),
                         ('wake', "wake the host now"), ('poweroff', "power the host off now (refused with projects)"),
                         ('drain', "no new project, power off when empty")):
        sub.add_parser(action, help=text, parents=[common]).add_argument('name')
    args = parser.parse_args(argv)

    url, token, cafile = args.url, args.token, ''
    if url is None or token is None:
        try:
            cfg = load_web_config(args.config)
        except ConfigError as e:
            print(f"sre-web pool: {e}", file=sys.stderr)
            return 1
        if url is None:
            url, cafile = _portal_url(cfg), cfg.tls_cert
        token = token or cfg.admin.token
    if not token:
        print("sre-web pool: no administration token ([admin] token in web.toml, or --token)", file=sys.stderr)
        return 1
    client = PoolClient(url, token, cafile)

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
    elif args.command == 'add':
        body = {'name': args.name, 'url': args.host_url, 'token': args.host_token, 'max_projects': args.max_projects,
                'mac': args.mac, 'wake_command': args.wake_command, 'power': args.power}
        row = client.call('POST', '/api/pool/hosts', body)
        print(json.dumps(row, indent=2) if args.json else table([row]))
    elif args.command == 'remove':
        client.call('DELETE', f"/api/pool/hosts/{args.name}" + ('?force=1' if args.force else ''))
        print(f"{args.name} removed")
    else:
        row = client.call('POST', f"/api/pool/hosts/{args.name}/{args.command}")
        print(json.dumps(row, indent=2) if args.json else table([row]))
    return 0
