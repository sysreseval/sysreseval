"""Central logs lab helpers (lab/sre/_DRAFT_misc/rsyslog.py): rsyslog 8.2302 and logrotate 3.21
of Debian 12 in the ``sysreseval/monitoring`` image; fixtures captured live in
tests/mock_data/rsyslog/.  (Never ``syslog.py``: the standard library has a module of that name.)

Grading is behavioural: every message the evaluation sends carries a **marker**
``sreprobe.<token>.<id>.<epoch>`` (the epoch of the sending machine; all the containers share the
host's clock), so the files of the collector tell where each message of this evaluation went
(:func:`parse_marked_lines`, :func:`fresh`, :func:`where`).  Senders: ``logger`` on the clients
(:func:`logger_cmd`), a line appended to an application file (:func:`append_marker_cmd`), an HTTP
request into an access log (:func:`http_marker_cmd`) and raw RFC 3164 messages from a hidden
machine over UDP, TCP or TLS (``lib/syslog_probe.py``: :func:`syslog_message`,
:func:`syslog_probe_cmd`).  logrotate is checked by a dry run of the students' file and by a forced
rotation of a sandbox copy limited to one directory of the probe (:func:`logrotate_sandbox_cmd`).

Facts (verified live on 2026-11-12, images 1.32):

- on an init machine rsyslog is active at boot; ``logger`` → journald → rsyslog's ``imuxsock`` on
  ``/run/systemd/journal/syslog`` (socket activation: ``systemctl stop rsyslog`` is undone by the
  next message, ``syslog.socket``); a line is in ``/var/log/syslog`` within 0.1 s; timestamps are
  RFC 3339 (``2026-11-12T02:03:23.694139+00:00``); ``/etc/rsyslog.d/`` is empty; Debian's
  ``rsyslog.conf`` loads ``imklog``, which in a privileged container reads the *host's* kernel
  ring buffer (the lab comments it out);
- one ``imtcp`` module serves a plain input (514) and a TLS input (6514) with per-input
  ``streamDriver.*`` parameters, ``permittedPeer`` and certificate files; ``x509/name`` accepts a
  client certificate whose extended key usage is serverAuth only, refuses a certificate of
  another name (``peer name not authorized``) and a client without certificate (``peer did not
  provide a certificate``), the message being dropped; a client closing without close_notify is
  logged as ``The TLS connection was non-properly terminated``;
- ``%HOSTNAME%`` and ``%PROGRAMNAME%`` of a raw ``<134>Nov 12 02:03:28 sw-3fa1 sre-probe: text`` are
  ``sw-3fa1`` and ``sre-probe``; a dynaFile with ``createDirs="on"`` creates the directory;
- ``omfwd`` over TCP and over gtls with a disk-assisted queue forwards within a second; ``ss -Htn
  state established '( sport = :514 or sport = :6514 )'`` prints ``Recv-Q Send-Q local peer``;
- ``imfile`` reads the file from its beginning on its first start, then follows appends (inotify
  works on overlayfs); its state is in ``/var/spool/rsyslog``;
- ``rsyslogd -N1`` prints ``error during parsing file F, on or before line N: ...``;
- ``logrotate -d`` prints ``rotating pattern: P  after 1 days (14 rotations)`` and, for a bad file,
  ``error: F:3 argument expected after rotate count`` then ``error: found error in P , skipping``;
  a log it has never seen is given ``Last rotated at <this hour>`` (no daily rotation before
  tomorrow); a forced rotation renames ``x.log`` → ``x.log.1`` (``delaycompress``); with
  ``/usr/lib/rsyslog/rsyslog-rotate`` in ``postrotate`` (HUP) the next message creates a new
  ``x.log``, without it rsyslog goes on writing into ``x.log.1``.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import random
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from SRE.lib_sre import Grade0, NetScheme0

FACILITIES = {"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
              "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, **{f"local{i}": 16 + i for i in range(8)}}
SEVERITIES = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
MARK_PREFIX = "sreprobe"
REMOTE_ROOT = "/var/log/remote"
T0_FILE = "/run/sre_syslog_t0"
SYSLOG_PROBE_PATH = "/usr/local/sbin/sre_syslog_probe.py"
TLS_DIR = "/etc/ssl/rsyslog"
PROBE_TLS_DIR = "/etc/sre-probe"
LOGROTATE_FILE = "/etc/logrotate.d/remote"
RSYSLOG_ROTATE = "/usr/lib/rsyslog/rsyslog-rotate"
SANDBOX_CONF = "/run/sre_logrotate.conf"
SANDBOX_STATE = "/run/sre_logrotate.state"
RC_SUFFIX = ' 2>&1; echo "===RC $?"'


def syslog_pri(facility: str, severity: str) -> int:
    """PRI = facility × 8 + severity (``local3.warning`` → 156)."""
    return FACILITIES[facility] * 8 + SEVERITIES[severity]


# ---------------------------------------------------------------------------
# markers
# ---------------------------------------------------------------------------


def marker_text(token: str, msg_id: str, epoch: str = "{epoch}") -> str:
    """The marker of one message; ``{epoch}`` is filled by the probe, ``$(date +%s)`` by a shell."""
    return f"{MARK_PREFIX}.{token}.{msg_id}.{epoch}"


def shell_marker(token: str, msg_id: str) -> str:
    return marker_text(token, msg_id, "$(date +%s)")


@dataclass(frozen=True)
class MarkedLine:
    path: str
    msg_id: str
    epoch: int
    line: str


def parse_marked_lines(text: Optional[str], token: str) -> List[MarkedLine]:
    """The markers of *token* in a ``grep -H`` / ``zgrep -H`` output (``path:line``); a line
    without a path is kept with an empty one."""
    pattern = re.compile(re.escape(f"{MARK_PREFIX}.{token}.") + r"([a-z0-9_]+)\.(\d+)")
    found = []
    for raw in (text or "").splitlines():
        match = pattern.search(raw)
        if not match:
            continue
        head = raw[: match.start()]
        path = head.split(":", 1)[0] if head.startswith("/") and ":" in head else ""
        found.append(MarkedLine(path, match.group(1), int(match.group(2)), raw))
    return found


def fresh(lines: Iterable[MarkedLine], t0: Optional[int], slack: int = 2) -> List[MarkedLine]:
    """The lines sent by this evaluation: epoch ≥ t0 − slack (nothing when t0 is unknown)."""
    return [] if t0 is None else [l for l in lines if l.epoch >= t0 - slack]


def where(lines: Iterable[MarkedLine], msg_id: str) -> Set[str]:
    """The files holding message *msg_id*."""
    return {l.path for l in lines if l.msg_id == msg_id}


def parse_t0(text: Optional[str]) -> Optional[int]:
    m = re.search(r"^T0=(\d+)$", text or "", re.M)
    return int(m.group(1)) if m else None


def split_rc(output: Optional[str]) -> Tuple[str, Optional[int]]:
    lines = (output or "").splitlines()
    for i in range(len(lines) - 1, -1, -1):
        m = re.fullmatch(r"===RC (-?\d+)", lines[i].strip())
        if m:
            return "\n".join(lines[:i]), int(m.group(1))
    return output or "", None


# ---------------------------------------------------------------------------
# sockets, configuration, logrotate
# ---------------------------------------------------------------------------


def parse_established(text: Optional[str]) -> List[Tuple[int, str]]:
    """``(local port, peer address)`` of ``ss -Htn state established ...`` lines."""
    found = []
    for line in (text or "").splitlines():
        words = line.split()
        if len(words) >= 4 and ":" in words[2] and ":" in words[3]:
            local_port = words[2].rsplit(":", 1)[1]
            peer = words[3].rsplit(":", 1)[0].strip("[]")
            if local_port.isdigit():
                found.append((int(local_port), peer))
    return found


def active_config_lines(text: Optional[str]) -> List[str]:
    """The lines of a configuration dump, comments and blank lines left out."""
    body, _ = split_rc(text)
    return [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]


def has_disk_queue(lines: Sequence[str]) -> bool:
    """A forwarding action with a disk-assisted queue retried for ever (both syntaxes)."""
    text = "\n".join(lines)
    queue = re.search(r'queue\.filename\s*=|\$ActionQueueFileName\s+\S', text, re.I)
    retry = re.search(r'resumeRetryCount\s*=\s*"?-1|\$ActionResumeRetryCount\s+-1', text, re.I)
    return bool(queue and retry)


def has_name_auth(lines: Sequence[str], peer: str) -> bool:
    """A TLS action authenticating its peer by name (``x509/name``) and naming *peer*."""
    text = "\n".join(lines)
    return bool(re.search(r'x509/name', text, re.I)) and peer in text


@dataclass
class LogrotateBlock:
    patterns: List[str]
    directives: Dict[str, List[str]] = field(default_factory=dict)   # name → arguments (words)
    scripts: Dict[str, str] = field(default_factory=dict)

    def has(self, name: str) -> bool:
        return name in self.directives

    def value(self, name: str) -> Optional[str]:
        args = self.directives.get(name)
        return args[0] if args else None


def parse_logrotate_conf(text: Optional[str]) -> List[LogrotateBlock]:
    """The blocks of a logrotate file: patterns (one or more lines before ``{``), directives,
    ``postrotate`` / ``prerotate`` scripts."""
    blocks: List[LogrotateBlock] = []
    pending: List[str] = []
    current: Optional[LogrotateBlock] = None
    script: Optional[str] = None
    body, _ = split_rc(text)
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if current is not None and script is not None:
            if line == "endscript":
                script = None
            else:
                current.scripts[script] = (current.scripts.get(script, "") + line + "\n")
            continue
        if current is None:
            head, brace, rest = line.partition("{")
            pending += shlex.split(head) if head.strip() else []
            if brace:
                current = LogrotateBlock(pending)
                pending = []
                inner = rest.strip()
                if inner.endswith("}"):              # a block on one line: "/x/*.log { daily }"
                    words = inner[:-1].split()
                    if words:
                        current.directives[words[0]] = words[1:]
                    blocks.append(current)
                    current = None
            continue
        if line == "}":
            blocks.append(current)
            current = None
            continue
        words = line.split()
        if words[0] in ("postrotate", "prerotate", "firstaction", "lastaction", "preremove"):
            script = words[0]
            current.directives.setdefault(words[0], [])
            continue
        current.directives[words[0]] = words[1:]
    return blocks


def glob_covers(pattern: str, path: str) -> bool:
    """*pattern* (a logrotate glob) matches *path*, ``*`` never crossing a ``/``."""
    if pattern.count("/") != path.count("/"):
        return False
    return all(fnmatch.fnmatchcase(p, q) for p, q in zip(path.split("/"), pattern.split("/")))


def block_for(blocks: Sequence[LogrotateBlock], path: str) -> Optional[LogrotateBlock]:
    return next((b for b in blocks if any(glob_covers(p, path) for p in b.patterns)), None)


def parse_logrotate_debug(output: Optional[str]) -> dict:
    """``logrotate -d``: ``{"ran", "rc", "errors": [...], "patterns": [...]}``."""
    body, rc = split_rc(output)
    return {"ran": rc is not None, "rc": rc, "errors": re.findall(r"^error: (.*)$", body, re.M),
            "patterns": re.findall(r"^rotating pattern: (\S+)", body, re.M)}


def parse_syslog_probe(output: Optional[str]) -> Dict[str, dict]:
    """``lib/syslog_probe.py``: ``{id: {"sent", "error", "handshake", "verified", ...}}``."""
    body, rc = split_rc(output)
    if rc is None or not body.strip():
        return {}
    try:
        doc = json.loads(body.strip().splitlines()[-1])
    except ValueError:
        return {}
    results = doc.get("results") if isinstance(doc, dict) else None
    return {str(k): v for k, v in results.items() if isinstance(v, dict)} if isinstance(results, dict) else {}


# ---------------------------------------------------------------------------
# histories (auth.log and the access log of the lab)
# ---------------------------------------------------------------------------

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _syslog_ts(dt: datetime) -> str:
    return f"{_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"


def _clf_ts(dt: datetime) -> str:
    return f"{dt.day:02d}/{_MONTHS[dt.month - 1]}/{dt.year}:{dt:%H:%M:%S} +0000"


def _spread(rnd: random.Random, count: int, start: datetime, end: datetime) -> List[datetime]:
    span = (end - start).total_seconds()
    return [start + timedelta(seconds=s) for s in sorted(rnd.uniform(0, span) for _ in range(count))]


def ssh_bruteforce_lines(ip: str, count: int, start: datetime, end: datetime, hostname: str, seed: int) -> List[str]:
    """A password-guessing attack in ``auth.log`` form: *count* failed logins from *ip*."""
    rnd = random.Random(seed)
    users = ("root", "admin", "oracle", "test", "postgres", "ubuntu", "git", "pi")
    lines = []
    for dt in _spread(rnd, count, start, end):
        user = rnd.choice(users)
        invalid = "invalid user " if user not in ("root",) and rnd.random() < 0.6 else ""
        lines.append(f"{_syslog_ts(dt)} {hostname} sshd[{rnd.randint(600, 30000)}]: Failed password for "
                     f"{invalid}{user} from {ip} port {rnd.randint(1024, 65535)} ssh2")
    return lines


def http_scan_lines(ip: str, count: int, start: datetime, end: datetime, seed: int) -> List[str]:
    """A scan in combined log format: *count* requests from *ip* on paths that mostly do not exist."""
    rnd = random.Random(seed)
    paths = ("/wp-login.php", "/.env", "/admin/", "/phpmyadmin/", "/.git/config", "/backup.zip", "/cgi-bin/test",
             "/server-status", "/config.php", "/xmlrpc.php", "/vendor/phpunit/", "/login")
    lines = []
    for dt in _spread(rnd, count, start, end):
        path = rnd.choice(paths)
        status = 200 if path == "/login" else 404
        lines.append(f'{ip} - - [{_clf_ts(dt)}] "GET {path} HTTP/1.1" {status} {rnd.randint(150, 600)} "-" '
                     f'"Mozilla/5.0 (compatible; scanner/2.1)"')
    return lines


def merge_by_time(background: str, extra: Sequence[str], clf: bool = False) -> str:
    """The lines of *background* and *extra* in time order (syslog or combined log timestamps of
    one year)."""
    def key(line: str):
        if clf:
            m = re.search(r"\[(\d\d)/(\w{3})/(\d{4}):(\d\d:\d\d:\d\d)", line)
            return (m.group(3), _MONTHS.index(m.group(2)), m.group(1), m.group(4)) if m else ("", 0, "", "")
        m = re.match(r"(\w{3}) +(\d+) (\d\d:\d\d:\d\d)", line)
        return (_MONTHS.index(m.group(1)), int(m.group(2)), m.group(3)) if m else (0, 0, "")
    lines = [l for l in background.splitlines() if l.strip()] + list(extra)
    return "\n".join(sorted(lines, key=key)) + "\n"


def failed_by_ip(text: str) -> Dict[str, int]:
    """Failed ssh logins per source address of an ``auth.log``."""
    counts: Dict[str, int] = {}
    for m in re.finditer(r"Failed password for .*? from (\S+) port", text):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def requests_by_ip(text: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for line in text.splitlines():
        ip = line.split(" ", 1)[0]
        if ip:
            counts[ip] = counts.get(ip, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def t0_cmd() -> str:
    """The start of this evaluation on a machine (first command of each)."""
    return f'date +%s > {T0_FILE}; echo "T0=$(cat {T0_FILE})"'


def logger_cmd(token: str, msg_id: str, priority: str = "user.notice", tag: str = "sre-probe") -> str:
    return f'logger -t {shlex.quote(tag)} -p {shlex.quote(priority)} "{shell_marker(token, msg_id)}"{RC_SUFFIX}'


def append_marker_cmd(path: str, token: str, msg_id: str, prefix: str = "") -> str:
    text = f"$(date '+%F %T') {prefix}{shell_marker(token, msg_id)}"
    return f'echo "{text}" >> {shlex.quote(path)}{RC_SUFFIX}'


def http_marker_cmd(token: str, msg_id: str, host: str = "127.0.0.1") -> str:
    return f'curl -s -m 3 -o /dev/null "http://{host}/{shell_marker(token, msg_id)}"{RC_SUFFIX}'


def collect_cmd(token: str, paths: Sequence[str], wait_root: Optional[str] = None, expected: int = 0,
                max_wait: int = 0) -> str:
    """The lines holding a marker of *token* in *paths* (recursively); first waits up to
    *max_wait* seconds for *expected* fresh markers under *wait_root*."""
    grep = f"grep -rHF {shlex.quote(f'{MARK_PREFIX}.{token}.')} {' '.join(shlex.quote(p) for p in paths)} 2>/dev/null"
    wait = ""
    if wait_root and expected and max_wait:
        regex = shlex.quote(re.escape(f"{MARK_PREFIX}.{token}.") + r"[a-z0-9_]+\.[0-9]+")
        wait = (f"t0=$(cat {T0_FILE} 2>/dev/null || echo 0); i=0; while [ $i -lt {int(max_wait)} ]; do"
                f" n=$(grep -rhoE {regex} {shlex.quote(wait_root)} 2>/dev/null"
                f" | awk -F. -v t0=\"$t0\" '$4+0 >= t0-2 {{c++}} END {{print c+0}}');"
                f' [ "$n" -ge {int(expected)} ] && break; sleep 1; i=$((i+1)); done; ')
    return f"{wait}{grep} | tail -n 300; echo \"===RC $?\""


def established_cmd(ports: Sequence[int] = (514, 6514)) -> str:
    sports = " or ".join(f"sport = :{p}" for p in ports)
    return f"ss -Htn state established '( {sports} )'{RC_SUFFIX}"


def config_dump_cmd() -> str:
    return ("grep -hvE '^[[:space:]]*(#|$)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
            "; echo \"===RC $?\"")


def config_check_cmd() -> str:
    return 'rsyslogd -N1 2>&1 | tail -n 15; echo "===RC $?"'


def cat_cmd(path: str) -> str:
    return f"cat {shlex.quote(path)}{RC_SUFFIX}"


def logrotate_debug_cmd(path: str = LOGROTATE_FILE) -> str:
    return f'out=$(logrotate -d {shlex.quote(path)} 2>&1); rc=$?; echo "$out" | head -n 60; echo "===RC $rc"'


def logrotate_sandbox_cmd(source: str, directory: str) -> str:
    """Force the rotation of the first block of *source* on *directory* only: the block's pattern
    lines are replaced by ``directory/*.log`` (``awk``: the lines up to the first ``{`` dropped, the
    block kept until its closing ``}``), the rotated files of earlier runs removed."""
    d = shlex.quote(directory.rstrip("/"))
    awk = ("awk -v g=\"$d/*.log\" 'p==0 && /\\{/ {p=1; print g \" {\"; next}"
           " p==1 {print; if ($0 ~ /^[ \\t]*\\}[ \\t]*$/) exit}'")
    return (f"d={d}; rm -f $d/*.log.* $d/*.log-* 2>/dev/null; {awk} {shlex.quote(source)} > {SANDBOX_CONF};"
            f" logrotate -f -s {SANDBOX_STATE} {SANDBOX_CONF} 2>&1; echo \"===RC $?\"")


def rotated_cmd(directory: str, token: str) -> str:
    d = shlex.quote(directory.rstrip("/"))
    return (f"ls -1 {d}/ 2>&1; zgrep -HF {shlex.quote(f'{MARK_PREFIX}.{token}.')} {d}/* 2>/dev/null"
            " | tail -n 40; echo \"===RC $?\"")


def syslog_message(msg_id: str, host: str, token: str, proto: str = "udp", port: int = 514,
                   hostname: str = "probe", tag: str = "sre-probe", pri: int = 134,
                   tls: Optional[dict] = None) -> dict:
    message = {"id": msg_id, "host": host, "port": port, "proto": proto, "hostname": hostname, "tag": tag,
               "pri": pri, "text": marker_text(token, msg_id)}
    if tls is not None:
        message["tls"] = tls
    return message


def syslog_probe_cmd(messages: Sequence[dict], timeout: float = 3) -> str:
    text = json.dumps({"timeout": timeout, "messages": list(messages)}, sort_keys=True, separators=(",", ":"))
    spec = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    return f"python3 {SYSLOG_PROBE_PATH} {spec}{RC_SUFFIX}"


# ---------------------------------------------------------------------------
# renderers (state side, instructor texts)
# ---------------------------------------------------------------------------


def render_collector_conf(root: str = REMOTE_ROOT, tls: Optional[dict] = None) -> str:
    """The collector: UDP and TCP 514 (and TLS 6514 with *tls* = ``{"ca", "cert", "key",
    "peers"}``) into ``root/<HOSTNAME>/<PROGRAMNAME>.log``."""
    text = f'''module(load="imudp")
module(load="imtcp")
template(name="PerHostFile" type="string"
         string="{root}/%HOSTNAME:::secpath-replace%/%PROGRAMNAME:::secpath-replace%.log")
ruleset(name="remote") {{
    action(type="omfile" dynaFile="PerHostFile" createDirs="on" dirCreateMode="0755" fileCreateMode="0640")
}}
input(type="imudp" port="514" ruleset="remote")
input(type="imtcp" port="514" ruleset="remote")
'''
    if tls:
        peers = ",".join(f'"{p}"' for p in tls["peers"])
        text += f'''input(type="imtcp" port="6514" ruleset="remote"
      streamDriver.name="gtls" streamDriver.mode="1" streamDriver.authMode="x509/name"
      permittedPeer=[{peers}]
      streamDriver.CAFile="{tls["ca"]}"
      streamDriver.CertFile="{tls["cert"]}"
      streamDriver.KeyFile="{tls["key"]}")
'''
    return text


def render_forward_conf(target: str, port: int = 514, tls: Optional[dict] = None,
                        queue_name: str = "fwd_logsrv") -> str:
    """Forward everything over TCP with a disk-assisted queue (and gtls ``x509/name`` with *tls* =
    ``{"ca", "cert", "key"}``)."""
    text = ""
    tls_lines = ""
    if tls:
        text += (f'global(DefaultNetstreamDriverCAFile="{tls["ca"]}"\n'
                 f'       DefaultNetstreamDriverCertFile="{tls["cert"]}"\n'
                 f'       DefaultNetstreamDriverKeyFile="{tls["key"]}")\n')
        tls_lines = ('       StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"\n'
                     f'       StreamDriverPermittedPeers="{target}"\n')
    text += (f'action(type="omfwd" target="{target}" port="{port}" protocol="tcp"\n{tls_lines}'
             f'       queue.type="LinkedList" queue.filename="{queue_name}" queue.maxDiskSpace="50m"\n'
             '       queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="5")\n')
    return text


def render_imfile_conf(file: str, tag: str, facility: str = "local7", severity: str = "info",
                       stop: bool = True) -> str:
    text = (f'module(load="imfile")\n'
            f'input(type="imfile" File="{file}" Tag="{tag}" Facility="{facility}" Severity="{severity}")\n')
    if stop:
        text += f'if $syslogtag == "{tag}" then stop\n'
    return text


def render_facility_rules(facility: str, file: str, alert_file: str) -> str:
    return (f'if $syslogfacility-text == "{facility}" then {{\n'
            f'    action(type="omfile" file="{file}")\n'
            f'    if $syslogseverity <= 4 then action(type="omfile" file="{alert_file}")\n'
            '    stop\n}\n')


def render_logrotate(pattern: str, rotate: int, frequency: str = "daily") -> str:
    return f"""{pattern} {{
    {frequency}
    rotate {int(rotate)}
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        {RSYSLOG_ROTATE}
    endscript
}}
"""


def render_shopd(facility: str, audit_file: str) -> str:
    """The application of app1: logs through syslog every 10 s and appends to its audit file."""
    return f"""#!/bin/bash
# shop: order processing (demo application of the lab)
while :; do
    order=$((RANDOM * 7 % 90000 + 10000))
    logger -t shop -p {facility}.info "order $order processed"
    case $((RANDOM % 6)) in
        0) logger -t shop -p {facility}.warning "payment gateway slow for order $order" ;;
        1) logger -t shop -p {facility}.err "order $order rejected: stock unavailable" ;;
    esac
    echo "$(date '+%F %T') AUDIT order $order by user$((RANDOM % 50))" >> {audit_file}
    sleep 10
done
"""


def render_shopd_unit(script: str) -> str:
    return f"""[Unit]
Description=Online shop order processing (demo application of the lab)
After=rsyslog.service

[Service]
ExecStart={script}
Restart=always

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------------------
# installers and wrappers
# ---------------------------------------------------------------------------


def install_syslog_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    script = Path(__file__).with_name("syslog_probe.py").read_text()
    net_scheme.file(machine, SYSLOG_PROBE_PATH, script, permissions=0o755, step=step)


def syslog_probe(grade: Grade0, machine: str, messages: Sequence[dict], step: int = 1,
                 timeout: int = 40) -> Dict[str, dict]:
    out, _ = grade.test(machine, syslog_probe_cmd(messages), step=step, timeout=timeout, allow_error=True)
    return parse_syslog_probe(out)


def get_t0(grade: Grade0, machine: str, step: int = 1) -> Optional[int]:
    out, _ = grade.test(machine, t0_cmd(), step=step, allow_error=True)
    return parse_t0(out)


def collect_lines(grade: Grade0, machine: str, token: str, paths: Sequence[str], step: int = 2,
                  wait_root: Optional[str] = None, expected: int = 0, max_wait: int = 0) -> List[MarkedLine]:
    out, _ = grade.test(machine, collect_cmd(token, paths, wait_root, expected, max_wait), step=step,
                        timeout=max_wait + 20, allow_error=True)
    body, rc = split_rc(out)
    return parse_marked_lines(body, token) if rc is not None else []


def get_established(grade: Grade0, machine: str, step: int = 2) -> List[Tuple[int, str]]:
    out, _ = grade.test(machine, established_cmd(), step=step, allow_error=True)
    return parse_established(split_rc(out)[0])


def get_active_config(grade: Grade0, machine: str, step: int = 1) -> List[str]:
    out, _ = grade.test(machine, config_dump_cmd(), step=step, allow_error=True)
    return active_config_lines(out) if split_rc(out)[1] is not None else []


def get_file(grade: Grade0, machine: str, path: str, step: int = 1) -> Optional[str]:
    out, _ = grade.test(machine, cat_cmd(path), step=step, allow_error=True)
    body, rc = split_rc(out)
    return body if rc == 0 else None


def get_logrotate_debug(grade: Grade0, machine: str, path: str = LOGROTATE_FILE, step: int = 1) -> dict:
    out, _ = grade.test(machine, logrotate_debug_cmd(path), step=step, allow_error=True)
    return parse_logrotate_debug(out)


def run_logrotate_sandbox(grade: Grade0, machine: str, source: str, directory: str, step: int = 2) -> Optional[int]:
    out, _ = grade.test(machine, logrotate_sandbox_cmd(source, directory), step=step, allow_error=True)
    return split_rc(out)[1]


def get_rotated(grade: Grade0, machine: str, directory: str, token: str, step: int = 4) -> List[MarkedLine]:
    out, _ = grade.test(machine, rotated_cmd(directory, token), step=step, allow_error=True)
    body, rc = split_rc(out)
    return parse_marked_lines(body, token) if rc is not None else []
