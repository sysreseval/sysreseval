"""Helpers of the forward proxy lab (``lab/sre/_DRAFT_misc/forward-proxy.py``: Squid 6 with
authentication, filtering, SslBump, interception, PAC / WPAD, cache, delay pools and squidGuard,
image ``sysreseval/proxy13``).

The requests themselves go through ``http_proxy.request_cmd(..., proxy=, proxy_user=)``; this
module holds what is specific to a forward proxy:

State side (pure functions, the lab writes their results with ``NetScheme0.file``)::

    ut1_blacklist_files({'games': {'domains': ['games.tp']}}, root)   # {path: content}
    text, answers = sample_access_log(seed, users, clients, sites, start)

Grade side (one command per test, a parser for its output)::

    cmd = pac_eval_cmd('http://wpad.corp.tp/wpad.dat', cases, hosts, my_ip)   # run with duk
    result = parse_pac_output(out)            # PacResult: fetch code, content type, answers
    pac_directives(result.answers[url])       # [('PROXY', 'proxy.corp.tp:3128'), ('DIRECT', '')]
    names = parse_cert_names(out_of(proxied_cert_cmd(proxy_ip, 3128, 'secure.news.tp', user=...)))
    entries = parse_access_log(out_of(access_log_cmd()))
    code, size, seconds = parse_timed_download(out_of(timed_download_cmd(...)))

Facts measured on Squid 6.13 (Debian 13, s16, 2026-11-25) are in ``.claude/rules/lib-squid.md``.
"""
import base64
import json
import random
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

#: Squid's access log (native format) in the Debian package
ACCESS_LOG = '/var/log/squid/access.log'
#: where the categories of a UT1-style blacklist live (one directory per category)
BLACKLIST_ROOT = '/etc/squid/blacklists'

PAC_FETCH_MARK = '===SRE_PAC_FETCH'
PAC_RESULT_MARK = '===SRE_PAC_RESULT'
DOWNLOAD_MARK = '===SRE_DL'
CERT_MARK = '===SRE_CERT'

# ---------------------------------------------------------------------------
# state side: blacklists in the UT1 format
# ---------------------------------------------------------------------------


def ut1_blacklist_files(categories: Mapping[str, Mapping[str, Sequence[str]]],
                        root: str = BLACKLIST_ROOT) -> Dict[str, str]:
    """The files of a blacklist in the format of the Université Toulouse 1 Capitole lists
    (squidGuard, e2guardian, and Squid ACL files): ``<root>/<category>/domains`` (one domain per
    line, **without** a leading dot: squidGuard matches the subdomains, Squid's ``dstdomain``
    does not) and ``<root>/<category>/urls`` (``host/path`` prefixes).  *categories* maps a
    category to ``{'domains': [...], 'urls': [...]}``; an empty list gives no file."""
    files = {}
    for category, lists in categories.items():
        for kind in ('domains', 'urls'):
            entries = list(lists.get(kind) or ())
            if entries:
                files[f"{root.rstrip('/')}/{category}/{kind}"] = ''.join(f"{entry}\n" for entry in entries)
    return files


# ---------------------------------------------------------------------------
# state side: a sample of access log for the students to analyse
# ---------------------------------------------------------------------------


@dataclass
class LogAnswers:
    """What :func:`sample_access_log` asks about its text."""
    denied: int            # requests refused by a rule (TCP_DENIED/403)
    top_user: str          # the user with the most requests (authenticated lines only)
    top_domain: str        # the host with the most requests (CONNECT targets included)
    bytes_user: str        # the user of the next answer
    user_bytes: int        # bytes sent by the proxy to *bytes_user*, every line of that user


def _log_line(ts: float, elapsed: int, client: str, code: str, status: int, size: int, method: str,
              url: str, user: str, hierarchy: str, ctype: str) -> str:
    return f"{ts:.3f} {elapsed:6d} {client} {code}/{status:03d} {size} {method} {url} {user} {hierarchy} {ctype}\n"


def sample_access_log(seed: int, users: Sequence[str], clients: Mapping[str, str], sites,
                      start: float, count: int = 240) -> Tuple[str, LogAnswers]:
    """A plausible Squid access log (native format) of about *count* lines, drawn from *seed*,
    and its answers.  *clients* maps each user to the address of their workstation; *sites*
    are host names (the first ones visited more often), or a mapping of them to their address
    (shown in the hierarchy field, as Squid does).  The busiest user and host are made unique by
    a margin of lines, and the user of the byte count is not the busiest one."""
    rng = random.Random(seed)
    users = list(users)
    addresses = dict(sites) if isinstance(sites, Mapping) else {}
    sites = list(sites)
    weights = [len(sites) - i for i in range(len(sites))]
    top_user = rng.choice(users)
    top_domain = rng.choice(sites[:3])
    entries = []
    t = float(start)

    def add(user, host, kind):
        nonlocal t
        t += rng.uniform(0.2, 9.0)
        client = clients.get(user, clients[users[0]])
        path = rng.choice(['/', '/index.html', '/news/today', '/img/logo.png', '/api/feed',
                           '/static/app.js', '/search?q=proxy', '/video/clip.mp4'])
        if kind == 'tunnel':
            entries.append((t, rng.randint(80, 30000), client, 'TCP_TUNNEL', 200, rng.randint(2000, 400000),
                            'CONNECT', f"{host}:443", user, f"HIER_DIRECT/{addresses.get(host, host)}", '-'))
        elif kind == 'denied':
            entries.append((t, rng.randint(0, 3), client, 'TCP_DENIED', 403, rng.randint(3300, 3600),
                            'GET', f"http://{host}{path}", user, 'HIER_NONE/-', 'text/html'))
        elif kind == 'auth':
            entries.append((t, rng.randint(0, 3), client, 'TCP_DENIED', 407, rng.randint(3700, 3900),
                            'GET', f"http://{host}{path}", '-', 'HIER_NONE/-', 'text/html'))
        else:
            hit = kind == 'hit'
            code = rng.choice(['TCP_HIT', 'TCP_MEM_HIT', 'TCP_REFRESH_UNMODIFIED']) if hit else 'TCP_MISS'
            size = rng.randint(400, 2_000_000) if path.endswith('.mp4') else rng.randint(300, 90000)
            hierarchy = 'HIER_NONE/-' if hit else f"HIER_DIRECT/{addresses.get(host, host)}"
            ctype = 'video/mp4' if path.endswith('.mp4') else rng.choice(['text/html', 'image/png', 'application/json'])
            entries.append((t, rng.randint(0, 900), client, code, 200, size, 'GET', f"http://{host}{path}",
                            user, hierarchy, ctype))

    kinds = ['miss'] * 9 + ['hit'] * 4 + ['tunnel'] * 3 + ['denied'] * 2 + ['auth']
    for _ in range(count):
        add(rng.choice(users), rng.choices(sites, weights)[0], rng.choice(kinds))

    def counts(index):
        tally = {}
        for entry in entries:
            if index == 8 and entry[3] == 'TCP_DENIED' and entry[4] == 407:
                continue
            key = entry[index] if index == 8 else _entry_host(entry[7])
            tally[key] = tally.get(key, 0) + 1
        return tally

    # margins: the chosen user and host lead by at least five lines; the lines added for the host
    # are the chosen user's, so that they only widen the lead of the user
    for index, wanted in ((8, top_user), (7, top_domain)):
        tally = counts(index)
        best_other = max((n for key, n in tally.items() if key != wanted and key != '-'), default=0)
        for _ in range(max(0, best_other - tally.get(wanted, 0) + 5)):
            host = rng.choices(sites, weights)[0] if index == 8 else top_domain
            add(top_user, host, rng.choice(['miss', 'hit', 'tunnel']))
    entries.sort(key=lambda entry: entry[0])
    text = ''.join(_log_line(*entry) for entry in entries)
    others = [user for user in users if user != top_user]
    bytes_user = rng.choice(others or users)
    answers = LogAnswers(
        denied=sum(1 for e in entries if e[3] == 'TCP_DENIED' and e[4] == 403),
        top_user=top_user, top_domain=top_domain, bytes_user=bytes_user,
        user_bytes=sum(e[5] for e in entries if e[8] == bytes_user))
    return text, answers


def _entry_host(url: str) -> str:
    """The host of a URL of the access log (``http://h/p`` or the ``h:443`` of a CONNECT)."""
    rest = url.split('://', 1)[1] if '://' in url else url
    host = rest.split('/', 1)[0]
    return host.rsplit(':', 1)[0] if ':' in host else host


# ---------------------------------------------------------------------------
# grade side: the access log
# ---------------------------------------------------------------------------


@dataclass
class AccessEntry:
    """One line of Squid's access log in the native format."""
    ts: float
    elapsed: int
    client: str
    code: str              # TCP_MISS, TCP_HIT, TCP_DENIED, TCP_TUNNEL, NONE_NONE...
    status: int
    size: int
    method: str
    url: str
    user: str              # '-' when the request carried no authenticated user
    hierarchy: str         # HIER_DIRECT/1.2.3.4, ORIGINAL_DST/..., HIER_NONE/-
    content_type: str
    raw: str = ''

    @property
    def host(self) -> str:
        return _entry_host(self.url)


# time, elapsed, client, code/status, bytes, then method, URL, user, hierarchy, type
_ACCESS_RE = re.compile(r'^(\d+\.\d+)\s+(\d+)\s+(\S+)\s+([A-Z_]+)/(\d{3})\s+(\d+)'
                        r'\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)')


def access_log_cmd(lines: int = 400, path: str = ACCESS_LOG) -> str:
    """The last *lines* of the access log."""
    return f"tail -n {int(lines)} {shlex.quote(path)} 2>/dev/null"


def parse_access_log(text: str) -> List[AccessEntry]:
    """The lines of *text* in Squid's native format (the others are skipped: a student may
    change the format, the raw lines then stay readable with :func:`log_lines_with`)."""
    entries = []
    for line in (text or '').splitlines():
        m = _ACCESS_RE.match(line.strip())
        if m:
            entries.append(AccessEntry(float(m[1]), int(m[2]), m[3], m[4], int(m[5]), int(m[6]), m[7], m[8], m[9],
                                       m[10], m[11], raw=line))
    return entries


def log_lines_with(text: str, *needles: str) -> List[str]:
    """The lines of *text* holding every one of *needles* (whatever the log format)."""
    return [line for line in (text or '').splitlines() if all(needle in line for needle in needles)]


# ---------------------------------------------------------------------------
# grade side: certificates seen through the proxy
# ---------------------------------------------------------------------------


@dataclass
class CertNames:
    """Issuer and subject of a certificate (*ok* is False when none was read)."""
    issuer: str = ''
    subject: str = ''
    is_ca: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.subject)

    @property
    def issuer_cn(self) -> str:
        return _common_name(self.issuer)

    @property
    def subject_cn(self) -> str:
        return _common_name(self.subject)


def _common_name(dn: str) -> str:
    m = re.search(r'(?:^|[,/]\s*)CN\s*=\s*([^,/]+)', dn or '')
    return m[1].strip() if m else ''


def proxied_cert_cmd(proxy_ip, proxy_port: int, host: str, port: int = 443, connect_ip=None,
                     user: Optional[Tuple[str, str]] = None, timeout: int = 8) -> str:
    """The certificate a client receives for *host* through the forward proxy (``openssl
    s_client -proxy``, ``CONNECT`` to *connect_ip* or *host*, SNI *host*): the real one when the
    proxy splices, one signed by the proxy's CA when it bumps (:func:`parse_cert_names`)."""
    auth = ''
    if user:
        auth = f" -proxy_user {shlex.quote(user[0])} -proxy_pass {shlex.quote('pass:' + user[1])}"
    target = f"{connect_ip or host}:{int(port)}"
    proxy = shlex.quote(f"{proxy_ip}:{int(proxy_port)}")
    return (f"echo {CERT_MARK}; timeout {int(timeout)} openssl s_client -proxy {proxy}"
            f"{auth} -connect {shlex.quote(target)} -servername {shlex.quote(host)} </dev/null 2>/dev/null"
            f" | openssl x509 -noout -issuer -subject 2>&1")


def cert_file_cmd(path: str) -> str:
    """Issuer, subject and basic constraints of a certificate file (:func:`parse_cert_names`)."""
    return (f"echo {CERT_MARK}; openssl x509 -noout -issuer -subject -ext basicConstraints "
            f"-in {shlex.quote(path)} 2>&1")


def parse_cert_names(out: str) -> CertNames:
    """The :class:`CertNames` of the output of :func:`proxied_cert_cmd` / :func:`cert_file_cmd`."""
    names = CertNames()
    text = out or ''
    if CERT_MARK in text:
        text = text.split(CERT_MARK, 1)[1]
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('issuer='):
            names.issuer = line[len('issuer='):].strip()
        elif line.startswith('subject='):
            names.subject = line[len('subject='):].strip()
        elif re.match(r'^CA:\s*TRUE', line, re.I):
            names.is_ca = True
    return names


# ---------------------------------------------------------------------------
# grade side: PAC files run with duk (duktape, in the proxy13 image)
# ---------------------------------------------------------------------------

#: the functions a PAC file may call (the classic Netscape set), written for this lab: the names
#: resolve through a table given by the grader (``SRE_HOSTS``), the time functions are true
PAC_RUNTIME_JS = r"""
function dnsDomainIs(host, domain) {
    host = String(host); domain = String(domain);
    return host.length >= domain.length && host.substring(host.length - domain.length) == domain;
}
function dnsDomainLevels(host) { return String(host).split('.').length - 1; }
function isPlainHostName(host) { return String(host).indexOf('.') < 0; }
function localHostOrDomainIs(host, hostdom) {
    host = String(host); hostdom = String(hostdom);
    return host == hostdom || hostdom.lastIndexOf(host + '.', 0) == 0;
}
function shExpMatch(str, pattern) {
    var re = String(pattern).replace(/[.+^${}()|[\]\\\/]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp('^' + re + '$').test(String(str));
}
function dnsResolve(host) {
    host = String(host);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host;
    return Object.prototype.hasOwnProperty.call(SRE_HOSTS, host) ? SRE_HOSTS[host] : null;
}
function isResolvable(host) { return dnsResolve(host) !== null; }
function myIpAddress() { return SRE_MY_IP; }
function convert_addr(ip) {
    var b = String(ip).split('.');
    return ((+b[0]) * 16777216 + (+b[1]) * 65536 + (+b[2]) * 256 + (+b[3])) | 0;
}
function isInNet(host, pattern, mask) {
    var ip = dnsResolve(host);
    if (ip === null) return false;
    var m = convert_addr(mask);
    return (convert_addr(ip) & m) == (convert_addr(pattern) & m);
}
function weekdayRange() { return true; }
function dateRange() { return true; }
function timeRange() { return true; }
function alert(message) {}
"""

_PAC_CASES_JS = r"""
for (var sre_i = 0; sre_i < SRE_CASES.length; sre_i++) {
    var sre_r;
    try { sre_r = String(FindProxyForURL(SRE_CASES[sre_i][0], SRE_CASES[sre_i][1])); }
    catch (sre_e) { sre_r = 'ERROR ' + sre_e; }
    print('%s ' + SRE_CASES[sre_i][0] + '\t' + sre_r.replace(/\s+/g, ' '));
}
""" % PAC_RESULT_MARK


@dataclass
class PacResult:
    """What :func:`pac_eval_cmd` read: the HTTP status and type of the PAC file and, for each
    URL of the cases, the string ``FindProxyForURL`` returned (``ERROR ...`` when it threw)."""
    fetch_code: Optional[int] = None
    content_type: str = ''
    answers: Dict[str, str] = field(default_factory=dict)
    output: str = ''

    @property
    def fetched(self) -> bool:
        return self.fetch_code == 200


def pac_eval_cmd(pac_url: str, cases: Sequence[Tuple[str, str]], hosts: Mapping[str, str], my_ip: str,
                 timeout: int = 6) -> str:
    """Download the PAC file at *pac_url* (directly, never through a proxy) and run its
    ``FindProxyForURL(url, host)`` on each ``(url, host)`` of *cases* with ``duk``, after
    :data:`PAC_RUNTIME_JS` (names resolved by *hosts*, ``myIpAddress()`` = *my_ip*).  The output
    is read by :func:`parse_pac_output`.  The JavaScript travels in base64: a grader command must
    stay on one line (``exetests.py`` echoes each command line before its output)."""
    head = (f"var SRE_HOSTS = {json.dumps(dict(hosts), sort_keys=True)};\n"
            f"var SRE_MY_IP = {json.dumps(str(my_ip))};\n"
            f"var SRE_CASES = {json.dumps([list(case) for case in cases])};\n" + PAC_RUNTIME_JS)
    return ("d=$(mktemp -d); "
            f"printf '%s ' {shlex.quote(PAC_FETCH_MARK)}; "
            f"curl -s --noproxy '*' --max-time {int(timeout)} -o $d/pac.js -w '%{{http_code}} %{{content_type}}\\n' "
            f"{shlex.quote(pac_url)}; "
            f"echo {_b64(head)} | base64 -d > $d/head.js; "
            f"echo {_b64(_PAC_CASES_JS)} | base64 -d > $d/tail.js; "
            "cat $d/head.js $d/pac.js > $d/all.js; printf '\\n;\\n' >> $d/all.js; cat $d/tail.js >> $d/all.js; "
            f"timeout {int(timeout)} duk $d/all.js 2>&1 | head -c 20000; rm -rf $d")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def parse_pac_output(out: str) -> PacResult:
    """The :class:`PacResult` of the output of :func:`pac_eval_cmd`."""
    result = PacResult(output=out or '')
    for line in (out or '').splitlines():
        if line.startswith(PAC_FETCH_MARK):
            parts = line[len(PAC_FETCH_MARK):].split(None, 1)
            if parts and parts[0].isdigit() and int(parts[0]):
                result.fetch_code = int(parts[0])
            if len(parts) > 1:
                result.content_type = parts[1].strip()
        elif line.startswith(PAC_RESULT_MARK):
            url, _, answer = line[len(PAC_RESULT_MARK):].strip().partition('\t')
            result.answers[url.strip()] = answer.strip()
    return result


def pac_directives(answer: str) -> List[Tuple[str, str]]:
    """``"PROXY p:3128; DIRECT"`` -> ``[('PROXY', 'p:3128'), ('DIRECT', '')]`` (types upper-cased,
    an ``ERROR`` answer gives no directive)."""
    if not answer or answer.startswith('ERROR'):
        return []
    directives = []
    for item in answer.split(';'):
        words = item.split()
        if words:
            directives.append((words[0].upper(), words[1] if len(words) > 1 else ''))
    return directives


# ---------------------------------------------------------------------------
# grade side: a timed download (delay pools)
# ---------------------------------------------------------------------------


def timed_download_cmd(proxy: str, host: str, size: int, user: Optional[Tuple[str, str]] = None,
                       prefix: str = 'dl', max_time: int = 20) -> str:
    """Download ``http://<host>/files/<fresh name>?size=<size>`` through *proxy*: a name new at
    each run, so that the object is never in the cache (Squid's delay pools do not slow cache
    hits).  Read by :func:`parse_timed_download`."""
    auth = f" -U {shlex.quote(f'{user[0]}:{user[1]}')}" if user else ''
    return (f"u=/files/{shlex.quote(prefix)}-$(date +%s%N); "
            f"curl -s --max-time {int(max_time)} -o /dev/null -x {shlex.quote(proxy)}{auth} "
            f"-w '{DOWNLOAD_MARK} %{{http_code}} %{{size_download}} %{{time_total}}\\n' "
            f"\"http://{host}$u?size={int(size)}\" 2>&1")


def parse_timed_download(out: str) -> Tuple[Optional[int], int, Optional[float]]:
    """``(status, bytes, seconds)`` of :func:`timed_download_cmd` (``(None, 0, None)`` without an answer)."""
    for line in (out or '').splitlines():
        if line.startswith(DOWNLOAD_MARK):
            parts = line.split()
            try:
                code = int(parts[1])
                return (code or None), int(float(parts[2])), float(parts[3].replace(',', '.'))
            except (IndexError, ValueError):
                break
    return None, 0, None
