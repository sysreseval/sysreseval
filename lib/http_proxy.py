"""State and grade helpers of the HTTP reverse proxy / load balancer lab
(``lab/sre/_DRAFT_misc2/reverse-proxy.py``: nginx 1.22, Varnish 7.1, HAProxy 2.6, keepalived 2.2
on the ``proxy`` image, Debian 12).

State side: :func:`install_backend` copies ``lib/http_backend.py`` (the application the proxies
are put in front of) into a machine and starts it.  Its pages are ``KEY=value`` lines read with
:func:`field` / :func:`fields`: who answered (``SERVER=``), what the proxy sent (``HOST=``,
``PATH=``, ``HEADER_X_FORWARDED_FOR=``...), whether the answer is fresh (``REQUEST_ID=``).

Grade side, behaviour first: :func:`http_request` is one ``curl`` from a (hidden) client, the
connection forced to an address so that no name resolution is needed (:class:`HttpReply`: status,
headers, every ``Set-Cookie``, body, HTTP version, duration); :func:`http_burst` is one shell
loop of N requests (the list of bodies: which backends answered, in order).  Pure parsers for
what behaviour cannot show: HAProxy's ``show stat`` (:func:`parse_haproxy_stat`), Varnish's
``backend.list`` (:func:`parse_varnish_backends`), a keepalived configuration
(:func:`parse_keepalived_conf`), VRRP adverts seen by ``tcpdump`` (:func:`parse_tcpdump_vrrp`),
the ``upstream`` blocks of ``nginx -T`` (:func:`parse_nginx_upstreams`) and the access log of
the backends (:func:`parse_backend_log`: the health checks they receive).

Every command is a single line (the exetests runner keys a result by the first line of its
command) and only depends on its arguments.  Fixtures: ``tests/mock_data/http_proxy/``, tests:
``tests/test_http_proxy.py``.
"""
import csv
import io
import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0, NetScheme0
from firewall import http_field
from tls import parse_curl_output

#: where install_backend() copies lib/http_backend.py, its configuration and what it writes
BACKEND_PATH = '/usr/local/sbin/sre_http_backend.py'
BACKEND_CONFIG = '/etc/sre_http_backend.json'
BACKEND_PID_FILE = '/run/sre_http_backend.pid'
BACKEND_STATE_DIR = '/var/lib/sre_http_backend'
BACKEND_LOG = '/var/log/sre_http_backend/access.log'
BACKEND_SICK_FILE = f"{BACKEND_STATE_DIR}/sick"

HAPROXY_SOCKET = '/run/haproxy/admin.sock'
META_MARK = '===SRE_META '
BURST_MARK = '===SRE_REQ'
REDIRECT_CODES = (301, 302, 303, 307, 308)


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def backend_config(name: str, apps: Dict[int, str], version: str = '1.0', vhosts: Optional[Dict[str, str]] = None,
                   old_slug: str = 'welcome', form_code: str = '', form_token: str = '',
                   catalog_delay_ms: int = 200) -> Dict[str, Any]:
    """The configuration of ``lib/http_backend.py`` for the backend *name*: *apps* maps a port
    to the name of the application served there (``{8080: 'shop', 8081: 'api'}``)."""
    return {
        'name': name,
        'apps': {str(int(port)): app for port, app in apps.items()},
        'version': version,
        'vhosts': dict(vhosts or {}),
        'old_slug': old_slug,
        'form_code': form_code,
        'form_token': form_token,
        'catalog_delay_ms': int(catalog_delay_ms),
        'state_dir': BACKEND_STATE_DIR,
        'log_file': BACKEND_LOG,
    }


def backend_start_cmd() -> str:
    """Shell command (re)starting the backend application (the previous instance, known by its
    pid file, is killed first)."""
    return (f"sh -c '[ -f {BACKEND_PID_FILE} ] && kill $(cat {BACKEND_PID_FILE}) 2>/dev/null; sleep 0.3; "
            f"python3 {BACKEND_PATH} {BACKEND_CONFIG}'")


def install_backend(net_scheme: NetScheme0, machine: str, config: Dict[str, Any], sick: bool = False,
                    step: int = 1) -> None:
    """Copy ``lib/http_backend.py`` and its *config* (:func:`backend_config`) to *machine* and
    start it; *sick* makes its ``/health`` page answer 503 from the start."""
    script = Path(__file__).with_name('http_backend.py').read_text()
    net_scheme.file(machine, BACKEND_PATH, script, permissions=0o755, step=step)
    net_scheme.file(machine, BACKEND_CONFIG, json.dumps(config, indent=1) + "\n", step=step)
    marker = f"touch {BACKEND_SICK_FILE}" if sick else f"rm -f {BACKEND_SICK_FILE}"
    net_scheme.cmd(machine, f"mkdir -p {BACKEND_STATE_DIR} && {marker}", step=step)
    net_scheme.cmd(machine, backend_start_cmd(), step=step)


# ---------------------------------------------------------------------------
# the pages of the backend
# ---------------------------------------------------------------------------


def field(body: str, key: str) -> str:
    """First ``KEY=value`` of a backend page (``''`` when missing)."""
    return http_field(body or '', key)


def fields(body: str, key: str) -> List[str]:
    """Every value of ``KEY=`` in a backend page (a header received twice gives two lines)."""
    prefix = key + '='
    return [line[len(prefix):].strip() for line in (body or '').splitlines() if line.startswith(prefix)]


def header_field(name: str) -> str:
    """The key of a request header in a backend page: ``X-Forwarded-For`` → ``HEADER_X_FORWARDED_FOR``."""
    return 'HEADER_' + ''.join(c if c.isalnum() else '_' for c in name.upper())


def request_header(body: str, name: str) -> str:
    """The request header *name* as the backend received it (first value, ``''`` when absent)."""
    return field(body, header_field(name))


def forwarded_for(body: str) -> List[str]:
    """The addresses of the ``X-Forwarded-For`` header(s) the backend received, in order."""
    addresses = []
    for value in fields(body, header_field('X-Forwarded-For')):
        addresses.extend(part.strip() for part in value.split(',') if part.strip())
    return addresses


def servers(bodies: Sequence[str]) -> List[str]:
    """The ``SERVER=`` name of each page (``''`` for a failed request)."""
    return [field(body, 'SERVER') for body in bodies]


def distribution(bodies: Sequence[str]) -> Counter:
    """How many pages each backend served (failed requests left out)."""
    return Counter(name for name in servers(bodies) if name)


# ---------------------------------------------------------------------------
# one request
# ---------------------------------------------------------------------------


@dataclass
class HttpReply:
    """One answer read by :func:`http_request`: *code* is ``None`` when no HTTP answer came
    (refused or reset connection, TLS failure, timeout, or the tests have not run yet);
    *headers* are lower-cased (last value), *all_headers* keeps every ``(name, value)``."""
    code: Optional[int] = None
    headers: Dict[str, str] = dataclass_field(default_factory=dict)
    all_headers: List[Tuple[str, str]] = dataclass_field(default_factory=list)
    body: str = ''
    http_version: str = ''
    time_total: Optional[float] = None
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        return self.code is not None and 200 <= self.code < 300

    @property
    def redirect(self) -> bool:
        return self.code in REDIRECT_CODES

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), '')

    def header_values(self, name: str) -> List[str]:
        wanted = name.lower()
        return [value for key, value in self.all_headers if key.lower() == wanted]

    def set_cookies(self) -> Dict[str, str]:
        """``{name: value}`` of the ``Set-Cookie`` headers."""
        jar = {}
        for value in self.header_values('Set-Cookie'):
            name, sep, rest = value.partition('=')
            if sep and name.strip():
                jar[name.strip()] = rest.split(';', 1)[0].strip()
        return jar

    def field(self, key: str) -> str:
        return field(self.body, key)

    @property
    def server(self) -> str:
        """The backend that answered (``SERVER=`` of the page)."""
        return field(self.body, 'SERVER')


def _address(value) -> str:
    return str(value).split('/')[0]


def _curl_options(connect_ip=None, connect_port=None, method=None, headers=None, data=None, cookies=None,
                  user=None, cacert=None, insecure=False, http2=False, source=None, compressed=False,
                  jar=None) -> List[str]:
    opts = []
    if jar:
        opts.append(f"-b {shlex.quote(jar)} -c {shlex.quote(jar)}")
    if connect_ip is not None:
        port = '' if connect_port is None else str(int(connect_port))
        opts.append(f"--connect-to {shlex.quote(f'::{_address(connect_ip)}:{port}')}")
    if source is not None:
        opts.append(f"--interface {shlex.quote(_address(source))}")
    if insecure:
        opts.append("-k")
    if cacert:
        opts.append(f"--cacert {shlex.quote(cacert)}")
    if http2:
        opts.append("--http2")
    if compressed:
        opts.append("-H 'Accept-Encoding: gzip'")
    if method:
        opts.append(f"-X {shlex.quote(method)}")
    for name, value in (headers or {}).items():
        opts.append(f"-H {shlex.quote(f'{name}: {value}')}")
    if cookies:
        opts.append("-H " + shlex.quote("Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items())))
    if user:
        opts.append(f"-u {shlex.quote(f'{user[0]}:{user[1]}')}")
    if data is not None:
        opts.append(f"--data {shlex.quote(data)}")
    return opts


def _shell_url(url: str) -> str:
    """*url* between double quotes, so that a shell variable set before the command (``$u``) is
    expanded in it; anything else the shell would interpret is refused."""
    if any(c in url for c in '"`\\') or '$(' in url:
        raise ValueError(f"unsupported character in a shell URL: {url!r}")
    return f'"{url}"'


def request_cmd(url: str, connect_ip=None, connect_port: Optional[int] = None, max_time: int = 6,
                no_body: bool = False, shell_url: bool = False, **options) -> str:
    """One ``curl`` of *url*, the connection sent to *connect_ip* (and *connect_port*) whatever
    the name and the port of the URL (``--connect-to``: the ``Host`` header and the SNI stay
    those of the URL).  Options: ``method``, ``headers`` (dict), ``data`` (a POST body),
    ``cookies`` (dict), ``user`` ((login, password): basic authentication), ``cacert`` (a path on
    the machine), ``insecure``, ``http2``, ``source`` (a local address to send from),
    ``compressed`` (asks for gzip without decoding it), ``jar`` (a cookie file read and written).
    *no_body* drops the body (a compressed one is not text); *shell_url* leaves ``$variables`` of
    the URL to the shell (:func:`sequence_cmd`).  The output holds the response headers, the
    body, then the HTTP version, the duration and the status (:func:`parse_reply`)."""
    opts = _curl_options(connect_ip, connect_port, **options)
    target = _shell_url(url) if shell_url else shlex.quote(url)
    return (f"curl -s -S --max-time {int(max_time)} {' '.join(opts)} -D - -o {'/dev/null' if no_body else '-'} "
            f"-w '\\n{META_MARK}%{{http_version}} %{{time_total}}\\n===SRE_CODE %{{http_code}}' "
            f"{target} 2>&1")


def parse_reply(out: str, exit_code: int = 0) -> HttpReply:
    """The :class:`HttpReply` of the output of a :func:`request_cmd` command."""
    text = out or ''
    http_version, time_total = '', None
    head, mark, tail = text.rpartition('\n' + META_MARK)
    if mark:
        meta_line, _, rest = tail.partition('\n')
        parts = meta_line.split()
        if parts:
            http_version = parts[0] if parts[0] != '0' else ''
        if len(parts) > 1:
            try:
                time_total = float(parts[1].replace(',', '.'))
            except ValueError:
                time_total = None
        text = head + '\n' + rest
    result = parse_curl_output(text, exit_code)
    body = result.body[:-1] if result.body.endswith('\n') and mark else result.body
    return HttpReply(code=result.code, headers=result.headers, all_headers=list(result.all_headers), body=body,
                     http_version=http_version, time_total=time_total, exit_code=exit_code)


def http_request(grade: Grade0, src: str, url: str, connect_ip=None, connect_port: Optional[int] = None,
                 step: int = 1, max_time: int = 6, **options) -> HttpReply:
    """Run :func:`request_cmd` on *src* and parse the answer (an empty :class:`HttpReply`, code
    ``None``, until the tests have run or when no HTTP answer came)."""
    cmd = request_cmd(url, connect_ip, connect_port, max_time=max_time, **options)
    out, code = grade.test(src, cmd, step=step, timeout=max_time + 6, allow_error=True)
    return parse_reply(out, code)


# ---------------------------------------------------------------------------
# a burst of requests
# ---------------------------------------------------------------------------


def burst_cmd(url: str, count: int, connect_ip=None, connect_port: Optional[int] = None, max_time: int = 4,
              **options) -> str:
    """*count* successive ``curl`` of *url* in one shell loop, each on its own connection and
    with its own query parameter (``burst=<i>``), the bodies separated by ``===SRE_REQ`` lines
    (:func:`parse_burst`).  Same options as :func:`request_cmd`."""
    if any(c in url for c in '"$`\\'):
        raise ValueError(f"unsupported character in the URL of a burst: {url!r}")
    opts = _curl_options(connect_ip, connect_port, **options)
    separator = '&' if '?' in url else '?'
    return (f"for i in $(seq 1 {int(count)}); do curl -s --max-time {int(max_time)} {' '.join(opts)} "
            f"\"{url}{separator}burst=$i\"; echo; echo '{BURST_MARK}'; done 2>&1")


def parse_burst(out: str) -> List[str]:
    """The bodies of a :func:`burst_cmd` output, in order (``''`` for a failed request)."""
    chunks = (out or '').split(BURST_MARK)
    return [chunk.strip('\n') for chunk in chunks[:-1]]


def http_burst(grade: Grade0, src: str, url: str, count: int, connect_ip=None, connect_port: Optional[int] = None,
               step: int = 1, max_time: int = 4, **options) -> List[str]:
    """Run :func:`burst_cmd` on *src*: the list of the bodies received (empty until the tests
    have run)."""
    cmd = burst_cmd(url, count, connect_ip, connect_port, max_time=max_time, **options)
    out, _ = grade.test(src, cmd, step=step, timeout=count * max_time + 10, allow_error=True)
    return parse_burst(out)


def sequence_cmd(commands: Sequence[str], prelude: str = '') -> str:
    """Several :func:`request_cmd` commands run in a row by one shell, after *prelude* (e.g.
    ``u=/page-$(date +%s%N)``: a URL that is new at each run, used by commands built with
    ``shell_url=True``); the outputs are separated by ``===SRE_REQ`` lines (:func:`parse_sequence`)."""
    body = '; '.join(f"{command}; echo; echo '{BURST_MARK}'" for command in commands)
    return f"{prelude}; {body}" if prelude else body


def parse_sequence(out: str) -> List[HttpReply]:
    """The :class:`HttpReply` of each command of a :func:`sequence_cmd` output, in order."""
    return [parse_reply(chunk) for chunk in parse_burst(out)]


def status_burst_cmd(url: str, count: int, connect_ip=None, connect_port: Optional[int] = None,
                     pause_before: float = 0, pause_after: Optional[float] = None, **options) -> str:
    """*count* requests of *url* sent as fast as one ``curl`` can (one connection, query
    parameter ``burst=1..count``), only their status codes printed; with *pause_after*, one more
    request after that pause, printed ``after=<code>`` (:func:`parse_status_burst`)."""
    if any(c in url for c in '\'"$`\\[]{}'):
        raise ValueError(f"unsupported character in the URL of a status burst: {url!r}")
    opts = ' '.join(_curl_options(connect_ip, connect_port, **options))
    separator = '&' if '?' in url else '?'
    command = (f"curl -s -o /dev/null -w '%{{http_code}} ' --max-time 5 {opts} "
               f"'{url}{separator}burst=[1-{int(count)}]'; echo")
    if pause_before:
        command = f"sleep {pause_before}; {command}"
    if pause_after is not None:
        command += (f"; sleep {pause_after}; curl -s -o /dev/null -w 'after=%{{http_code}}' --max-time 5 {opts} "
                    f"'{url}'; echo")
    return command + " 2>&1"


def parse_status_burst(out: str) -> Tuple[List[int], Optional[int]]:
    """``(codes, after)`` of a :func:`status_burst_cmd` output: the status of each request of
    the burst (``0`` for one that got no answer) and of the request sent after the pause."""
    codes: List[int] = []
    after = None
    for line in (out or '').splitlines():
        line = line.strip()
        if line.startswith('after='):
            after = int(line[6:]) if line[6:].isdigit() else None
        elif line and all(word.isdigit() for word in line.split()):
            codes.extend(int(word) for word in line.split())
    return codes, after


def banner_cmd(host, port: int, source=None, timeout: int = 3) -> str:
    """What a TCP service sends at connection (``nc``, nothing sent), optionally from the local
    address *source*."""
    bind = f"-s {shlex.quote(_address(source))} " if source is not None else ''
    return f"nc -w {int(timeout)} {bind}{shlex.quote(_address(host))} {int(port)} </dev/null 2>&1"


# ---------------------------------------------------------------------------
# HAProxy
# ---------------------------------------------------------------------------


def haproxy_show_cmd(command: str = 'show stat', socket: str = HAPROXY_SOCKET) -> str:
    """One command of HAProxy's runtime API through its admin socket."""
    return f"echo {shlex.quote(command)} | socat stdio UNIX-CONNECT:{socket} 2>&1"


def parse_haproxy_stat(text: str) -> List[Dict[str, str]]:
    """The rows of ``show stat`` (or of the ``;csv`` statistics page): one dict per line, keyed
    by the column names of the ``# pxname,svname,...`` header (``[]`` when it is missing)."""
    lines = [line for line in (text or '').splitlines() if line.strip()]
    start = next((i for i, line in enumerate(lines) if line.startswith('# pxname') or line.startswith('#pxname')), None)
    if start is None:
        return []
    names = [name.strip() for name in lines[start].lstrip('# ').split(',')]
    rows = []
    for values in csv.reader(io.StringIO('\n'.join(lines[start + 1:]))):
        if len(values) < 2:
            continue
        rows.append({name: value for name, value in zip(names, values) if name})
    return rows


def haproxy_servers(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """``{proxy: {server: {'status', 'up', 'check_status', 'weight', 'backup', 'cookie', 'address', 'mode'}}}``
    of the server rows of :func:`parse_haproxy_stat` (``status`` is ``UP``, ``DOWN``, ``MAINT``,
    ``DRAIN``, ``no check``...; ``check_status`` is ``L7OK``, ``L7STS``, ``L4OK``, ``L4CON``...)."""
    result: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for row in rows:
        name = row.get('svname', '')
        if name in ('FRONTEND', 'BACKEND') or not name:
            continue
        if row.get('type') not in (None, '', '2'):
            continue
        status = row.get('status', '')
        weight = row.get('weight', '')
        result.setdefault(row.get('pxname', ''), {})[name] = {
            'status': status,
            'up': status.split(' ')[0] == 'UP' or status == 'no check',
            'check_status': row.get('check_status', ''),
            'weight': int(weight) if weight.isdigit() else None,
            'backup': row.get('bck', '') == '1',
            'cookie': row.get('cookie', ''),
            'address': row.get('addr', ''),
            'mode': row.get('mode', ''),
        }
    return result


def haproxy_pool(servers_by_proxy: Dict[str, Dict[str, Dict[str, Any]]], members: Sequence[str],
                 port: Optional[int] = None) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    """The proxy (backend or listen section) holding the most servers among *members*, matched
    by their address (``ip`` or ``ip:port``; with *port*, only servers on that port):
    ``(proxy name, {member address: server row})``, ``('', {})`` when none matches."""
    wanted = [_address(m) for m in members]
    best: Tuple[str, Dict[str, Dict[str, Any]]] = ('', {})
    for proxy, rows in servers_by_proxy.items():
        found = {}
        for row in rows.values():
            host, _, server_port = row['address'].partition(':')
            if host in wanted and (port is None or server_port == str(port)):
                found[host] = row
        if len(found) > len(best[1]):
            best = (proxy, found)
    return best


# ---------------------------------------------------------------------------
# Varnish
# ---------------------------------------------------------------------------


def parse_varnish_backends(text: str) -> Dict[str, Dict[str, str]]:
    """``{backend: {'admin', 'probe', 'health'}}`` of ``varnishadm backend.list``: the name
    without its VCL prefix (``boot.web1`` → ``web1``), ``admin`` (``probe``, ``healthy``,
    ``sick``), ``probe`` (``3/3``, ``0/0`` without probe) and ``health`` (``healthy`` / ``sick``)."""
    backends = {}
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] == 'Backend':
            continue
        if parts[3].lower() not in ('healthy', 'sick'):
            continue
        backends[parts[0].split('.', 1)[-1]] = {'admin': parts[1], 'probe': parts[2], 'health': parts[3].lower()}
    return backends


# ---------------------------------------------------------------------------
# keepalived
# ---------------------------------------------------------------------------


def _keepalived_tokens(text: str) -> List[str]:
    tokens = []
    for line in (text or '').splitlines():
        line = re.split(r'(?<!\S)[#!]', line, maxsplit=1)[0]
        tokens.extend(re.findall(r'"[^"]*"|[{}]|[^\s{}]+', line))
        tokens.append('\n')
    return tokens


def _keepalived_block(tokens: List[str], pos: int) -> Tuple[List[List[Any]], int]:
    """The statements of a block starting after its ``{``: each one is a list of words, the last
    item being the nested block (a list of statements) when it has one."""
    statements: List[List[Any]] = []
    current: List[Any] = []
    while pos < len(tokens):
        token = tokens[pos]
        pos += 1
        if token == '\n':
            if current:
                statements.append(current)
                current = []
        elif token == '{':
            nested, pos = _keepalived_block(tokens, pos)
            current.append(nested)
            statements.append(current)
            current = []
        elif token == '}':
            if current:
                statements.append(current)
            return statements, pos
        else:
            current.append(token.strip('"'))
    if current:
        statements.append(current)
    return statements, pos


def _first_words(block: List[List[Any]]) -> List[str]:
    return [statement[0] for statement in block if statement and isinstance(statement[0], str)]


def parse_keepalived_conf(text: str) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """``{'instances': {name: {...}}, 'scripts': {name: {...}}, 'processes': {name: {...}}}`` of a
    ``keepalived.conf``.  An instance holds ``state``, ``interface``, ``virtual_router_id`` and
    ``priority`` (ints), ``advert_int``, ``auth_type``, ``auth_pass``, ``virtual_ipaddress`` (the
    addresses, prefix included as written), ``track_script``, ``track_process``, ``track_interface``
    and ``unicast_peer`` (lists of names); a ``vrrp_script`` holds ``script``, ``interval``,
    ``weight``, ``fall``, ``rise``; a ``vrrp_track_process`` holds ``process``."""
    statements, _ = _keepalived_block(_keepalived_tokens(text), 0)
    result: Dict[str, Dict[str, Dict[str, Any]]] = {'instances': {}, 'scripts': {}, 'processes': {}}
    for statement in statements:
        if len(statement) < 3 or not isinstance(statement[-1], list):
            continue
        kind, name, block = statement[0], statement[1], statement[-1]
        if kind == 'vrrp_instance':
            entry: Dict[str, Any] = {'virtual_ipaddress': [], 'track_script': [], 'track_process': [],
                                     'track_interface': [], 'unicast_peer': []}
            for item in block:
                key = item[0]
                if key in ('virtual_ipaddress', 'track_script', 'track_process', 'track_interface', 'unicast_peer') \
                        and isinstance(item[-1], list):
                    entry[key] = _first_words(item[-1])
                elif key == 'authentication' and isinstance(item[-1], list):
                    for auth in item[-1]:
                        if len(auth) >= 2 and auth[0] in ('auth_type', 'auth_pass'):
                            entry[auth[0]] = auth[1]
                elif key in ('virtual_router_id', 'priority', 'advert_int') and len(item) >= 2:
                    entry[key] = int(item[1]) if str(item[1]).isdigit() else item[1]
                elif len(item) >= 2 and isinstance(item[1], str):
                    entry[key] = item[1]
            result['instances'][name] = entry
        elif kind in ('vrrp_script', 'vrrp_track_process'):
            entry = {}
            for item in block:
                if len(item) >= 2 and isinstance(item[1], str):
                    entry[item[0]] = ' '.join(word for word in item[1:] if isinstance(word, str))
            result['scripts' if kind == 'vrrp_script' else 'processes'][name] = entry
    return result


def keepalived_tracks(conf: Dict[str, Dict[str, Dict[str, Any]]], process: str) -> bool:
    """True when an instance of a parsed ``keepalived.conf`` follows the daemon *process*: a
    ``track_script`` whose script names it, or a ``track_process`` watching it."""
    for instance in conf.get('instances', {}).values():
        for name in instance.get('track_script', []):
            if process in conf.get('scripts', {}).get(name, {}).get('script', ''):
                return True
        for name in instance.get('track_process', []):
            if process in conf.get('processes', {}).get(name, {}).get('process', ''):
                return True
    return False


def vrrp_capture_cmd(interface: str = 'eth0', count: int = 2, seconds: int = 5) -> str:
    """The first *count* VRRP adverts seen on *interface* within *seconds* (one line each)."""
    return f"timeout {int(seconds)} tcpdump -l -n -c {int(count)} -i {shlex.quote(interface)} vrrp 2>/dev/null; true"


_VRRP_LINE = re.compile(r"IP (?P<src>[0-9.]+) > (?P<dst>[0-9.]+): VRRPv(?P<version>\d).*?"
                        r"vrid (?P<vrid>\d+), prio (?P<prio>\d+)")


def parse_tcpdump_vrrp(out: str) -> List[Dict[str, Any]]:
    """``[{'src', 'dst', 'version', 'vrid', 'prio'}]`` of the VRRP adverts of a ``tcpdump -n`` output."""
    adverts = []
    for match in _VRRP_LINE.finditer(out or ''):
        adverts.append({'src': match['src'], 'dst': match['dst'], 'version': int(match['version']),
                        'vrid': int(match['vrid']), 'prio': int(match['prio'])})
    return adverts


# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------


def strip_nginx_comments(text: str) -> str:
    """An nginx configuration without its ``#`` comments (quoted strings are kept)."""
    lines = []
    for line in (text or '').splitlines():
        out, quote = [], ''
        for char in line:
            if quote:
                if char == quote:
                    quote = ''
            elif char in '"\'':
                quote = char
            elif char == '#':
                break
            out.append(char)
        lines.append(''.join(out))
    return '\n'.join(lines)


def parse_nginx_upstreams(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """``{upstream: [{'address', 'weight', 'backup', 'down', 'params'}]}`` of the ``upstream``
    blocks of an nginx configuration (``nginx -T``)."""
    upstreams: Dict[str, List[Dict[str, Any]]] = {}
    clean = strip_nginx_comments(text)
    for match in re.finditer(r"\bupstream\s+(\S+)\s*\{([^}]*)\}", clean):
        members = []
        for server in re.finditer(r"\bserver\s+([^;]+);", match.group(2)):
            words = server.group(1).split()
            if not words:
                continue
            params = words[1:]
            weight = next((int(p.split('=', 1)[1]) for p in params
                           if p.startswith('weight=') and p.split('=', 1)[1].isdigit()), 1)
            members.append({'address': words[0], 'weight': weight, 'backup': 'backup' in params,
                            'down': 'down' in params, 'params': params})
        upstreams[match.group(1)] = members
    return upstreams


# ---------------------------------------------------------------------------
# access log of the backends
# ---------------------------------------------------------------------------


def backend_log_cmd(lines: int = 400) -> str:
    """The clock of the backend then the last lines of its access log."""
    return f"echo NOW=$(date +%s); tail -n {int(lines)} {BACKEND_LOG} 2>/dev/null; true"


def parse_backend_log(text: str) -> Tuple[Optional[float], List[Dict[str, Any]]]:
    """``(now, entries)`` of a :func:`backend_log_cmd` output: *now* is the clock of the backend
    (``None`` when missing), each entry ``{'ts', 'client', 'method', 'target', 'status', 'port',
    'host', 'xff', 'ua'}`` (``ua`` is the rest of the line)."""
    now = None
    entries = []
    for line in (text or '').splitlines():
        if line.startswith('NOW='):
            try:
                now = float(line[4:])
            except ValueError:
                now = None
            continue
        parts = line.split(' ', 5)
        if len(parts) < 5:
            continue
        try:
            ts, status = float(parts[0]), int(parts[4])
        except ValueError:
            continue
        entry = {'ts': ts, 'client': parts[1], 'method': parts[2], 'target': parts[3], 'status': status,
                 'port': '', 'host': '', 'xff': '', 'ua': ''}
        rest = parts[5] if len(parts) > 5 else ''
        match = re.match(r"port=(\S*) host=(\S*) xff=(.*?) ua=(.*)$", rest)
        if match:
            entry.update(port=match.group(1), host=match.group(2), xff=match.group(3), ua=match.group(4))
        entries.append(entry)
    return now, entries


def health_checks(entries: List[Dict[str, Any]], now: Optional[float], client, window: float = 20,
                  path: str = '/health') -> List[Dict[str, Any]]:
    """The requests of *path* received from the address *client* during the last *window*
    seconds: the health checks a proxy sends.  (*now* is a whole number of seconds read just
    before the log: an entry may be up to a second "younger" than it.)"""
    if now is None:
        return []
    wanted = _address(client)
    return [e for e in entries
            if e['client'] == wanted and e['target'].split('?', 1)[0] == path and -2 <= now - e['ts'] <= window]
