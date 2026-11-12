"""Nagios grading and state helpers of the Nagios lab (``lab/sre/_DRAFT_misc/nagios.py``).

Facts and formats are those of Nagios Core 4.4.6, monitoring-plugins 2.3.3 and NRPE 4.1.0 (Debian
12, in the ``sysreseval/monitoring`` image built on ``init``); the fixtures of
``tests/mock_data/nagios/`` were captured in those containers.

**Object and status files**: :func:`parse_blocks` reads both ``/var/lib/nagios4/objects.cache``
(``define host {`` … tab-separated directives: what Nagios really loaded, templates resolved) and
``/var/lib/nagios4/status.dat`` (``servicestatus {`` … ``key=value``).  :class:`NagiosObjects`
(:func:`parse_objects_cache`) gives hosts, services, the members of host / service / contact
groups, contacts and command lines; :class:`NagiosStatus` (:func:`parse_status_dat`) the current
state of a host or a service.  :func:`split_check_command` / :func:`expand_command_line` /
:meth:`NagiosObjects.effective_command` rebuild the command a check runs (``$ARGn$``,
``$HOSTADDRESS$``, ``$USER1$``…), :func:`options_set` compares notification options.

**Plugins**: :func:`parse_plugin_output` → :class:`PluginResult` (state word of the first line,
exit status from the ``===RC`` marker, :func:`parse_perfdata` of what follows ``|``).

**External commands**: :func:`external_commands_cmd` writes commands (built with
:func:`external_command`) to the command pipe without ever blocking nor creating a regular file in
its place, and prints the time of the write as ``===T0 epoch``: the log lines
(:func:`parse_nagios_log`, :func:`notifications`) and the notifications received
(:func:`parse_sms_outbox`) are then filtered on it, the token of a lab being the same at every
evaluation.

**NRPE**: :func:`check_nrpe_cmd`, :func:`parse_nrpe_config` (``allowed_hosts``, the last
``command[name]`` wins), :func:`render_nrpe_conf`.

**States**: :func:`render_object`, :func:`render_lab_templates` (host / service templates with
sub-minute intervals), :func:`render_localhost_cfg`, :func:`render_sms_send` (the notification
target of the lab: one line per message in a file), :func:`render_labdb_script` /
:func:`render_labdb_unit` (a TCP server whose process has a name), :func:`render_check_queue`.

Facts (verified 2026-11-11 in the containers):

- ``nagios4.service`` starts under the systemd of an init machine; the command pipe
  ``/var/lib/nagios4/rw/nagios.cmd`` is ``nagios:www-data 0660`` and is removed when the service
  stops; ``check_external_commands=1`` and ``use_authentication=0`` are the Debian defaults;
- Apache serves the CGIs as downloads (the ELF binary) until ``a2enmod cgi``; the interface is
  then at ``/nagios4/`` without login from private addresses;
- intervals are fractions of ``interval_length`` (60 s): ``check_interval 0.5`` checks every 30 s;
  the first checks of a dozen services are done within a minute of a restart;
- ``SCHEDULE_FORCED_SVC_CHECK`` / ``SCHEDULE_FORCED_HOST_CHECK`` run at once; with
  ``status_update_interval=5`` the result is in ``status.dat`` within ten seconds;
- ``SEND_CUSTOM_SVC_NOTIFICATION;host;svc;0;author;comment`` is logged ``SERVICE NOTIFICATION:
  contact;host;svc;CUSTOM (STATE);command;output;author;comment`` and runs the contact's command
  whatever its notification options;
- ``PROCESS_SERVICE_CHECK_RESULT`` gives ``check_type=1`` and the output in ``status.dat`` (the
  log line reads ``PASSIVE SERVICE CHECK: …;(null)``); a passive service older than its
  ``freshness_threshold`` runs its ``check_command`` (checked every
  ``service_freshness_check_interval`` seconds);
- NRPE closes the connection of a host missing from ``allowed_hosts``: ``CHECK_NRPE: Error - Could
  not connect to X: Connection reset by peer`` (exit 2); an allowed one gets ``NRPE v4.1.0``; an
  undefined command ``NRPE: Command 'x' not defined`` (exit 3);
- ``check_ping`` works as the user ``nagios`` (capability on ``ping``), ``check_disk -p /`` on the
  overlay root too; ``check_load -r`` prints its thresholds in the ``scaled_loadN`` perfdata;
- ``runuser -u nagios -- /missing/plugin`` exits 1, like a WARNING: a plugin test must also read
  the state word of the output;
- macros lose the characters of ``illegal_macro_output_chars`` (quotes…) in a notification.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from SRE.lib_sre import Grade0

RC_MARK = "===RC"
_RC_RE = re.compile(r"^===RC (-?\d+)\s*$", re.M)
RC_SUFFIX = f' 2>&1; echo "{RC_MARK} $?"'  #: appended to a command: stderr merged, exit status kept
ASCII_ONLY = " | tr -cd '\\11\\12\\15\\40-\\176'"  #: the outputs of the tests must be UTF-8

NAGIOS_CFG = "/etc/nagios4/nagios.cfg"
CONF_D = "/etc/nagios4/conf.d"
OBJECTS_CACHE = "/var/lib/nagios4/objects.cache"
STATUS_DAT = "/var/lib/nagios4/status.dat"
COMMAND_FILE = "/var/lib/nagios4/rw/nagios.cmd"
NAGIOS_LOG = "/var/log/nagios4/nagios.log"
PLUGIN_DIR = "/usr/lib/nagios/plugins"
LOCAL_PLUGIN_DIR = "/usr/local/lib/nagios/plugins"
NRPE_D = "/etc/nagios/nrpe.d"
SMS_SEND = "/usr/local/bin/sms-send"
SMS_OUTBOX = "/var/spool/sms/outbox.log"
LABDB_SCRIPT = "/usr/local/sbin/labdb"
LABDB_UNIT = "/etc/systemd/system/labdb.service"
SERVICE_STATES = ("OK", "WARNING", "CRITICAL", "UNKNOWN")
HOST_STATES = ("UP", "DOWN", "UNREACHABLE")


# ---------------------------------------------------------------------------
# objects.cache and status.dat
# ---------------------------------------------------------------------------

_BLOCK_START_RE = re.compile(r"^\s*(define\s+)?([a-z]+)\s*\{\s*$")


def parse_blocks(text: str) -> List[Tuple[str, Dict[str, str]]]:
    """``[(kind, {directive: value})]`` of an object file or of ``objects.cache`` (``define host {``,
    directive and value separated by blanks) or of ``status.dat`` (``hoststatus {``, ``key=value``).
    Comments (``#`` lines, and ``;`` to the end of a line in the ``define`` blocks) are dropped."""
    blocks: List[Tuple[str, Dict[str, str]]] = []
    current: Optional[Tuple[str, Dict[str, str]]] = None
    define = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if current is None:
            m = _BLOCK_START_RE.match(line)
            if m:
                current, define = (m.group(2), {}), bool(m.group(1))
            continue
        if line == "}":
            blocks.append(current)
            current = None
            continue
        if not line or line.startswith("#"):
            continue
        if define:
            line = line.split(";", 1)[0].rstrip()
            parts = line.split(None, 1)
            if not parts:
                continue
            key, value = parts[0], parts[1] if len(parts) > 1 else ""
        else:
            key, _, value = line.partition("=")
        current[1][key.strip()] = value.strip()
    return blocks


def _names(value: Optional[str]) -> List[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def options_set(value: Optional[str]) -> frozenset:
    """Notification options as a set (``'r,c'`` → ``{'r', 'c'}``; the order of the cache differs
    from the one of the source files)."""
    return frozenset(_names(value))


def split_check_command(value: Optional[str]) -> Tuple[str, List[str]]:
    """``'check_ping!100.0,20%!500.0,60%'`` → ``('check_ping', ['100.0,20%', '500.0,60%'])``."""
    parts = (value or "").split("!")
    return parts[0].strip(), parts[1:]


def expand_command_line(command_line: Optional[str], args: Sequence[str] = (), macros: Optional[dict] = None) -> str:
    """*command_line* with ``$ARG1$``… replaced by *args* and the macros of *macros* (``{'USER1':
    …, 'HOSTADDRESS': …}``) replaced; an unknown macro is left as written."""
    values = {f"ARG{i}": a for i, a in enumerate(args, 1)}
    values.update(macros or {})

    def sub(m):
        return str(values.get(m.group(1), m.group(0)))

    return re.sub(r"\$([A-Z0-9_]+)\$", sub, command_line or "")


@dataclass
class NagiosObjects:
    """The objects Nagios loaded (``objects.cache``)."""
    blocks: List[Tuple[str, Dict[str, str]]] = field(default_factory=list)
    ran: bool = False       #: the file was read (False for a placeholder or a missing file)

    def of_kind(self, kind: str) -> List[Dict[str, str]]:
        return [b for k, b in self.blocks if k == kind]

    def host(self, name: str) -> Optional[Dict[str, str]]:
        return next((b for b in self.of_kind("host") if b.get("host_name") == name), None)

    def service(self, host: str, description: str) -> Optional[Dict[str, str]]:
        return next((b for b in self.of_kind("service")
                     if b.get("host_name") == host and b.get("service_description") == description), None)

    def services_of(self, host: str) -> List[Dict[str, str]]:
        return [b for b in self.of_kind("service") if b.get("host_name") == host]

    def contact(self, name: str) -> Optional[Dict[str, str]]:
        return next((b for b in self.of_kind("contact") if b.get("contact_name") == name), None)

    def hostgroup_members(self, name: str) -> Optional[Set[str]]:
        """Member hosts of a hostgroup (``None`` when it does not exist)."""
        block = next((b for b in self.of_kind("hostgroup") if b.get("hostgroup_name") == name), None)
        return None if block is None else set(_names(block.get("members")))

    def servicegroup_members(self, name: str) -> Optional[Set[Tuple[str, str]]]:
        """``{(host, service description)}`` of a servicegroup (``None`` when it does not exist)."""
        block = next((b for b in self.of_kind("servicegroup") if b.get("servicegroup_name") == name), None)
        if block is None:
            return None
        flat = _names(block.get("members"))
        return set(zip(flat[0::2], flat[1::2]))

    def contactgroup_members(self, name: str) -> Optional[Set[str]]:
        block = next((b for b in self.of_kind("contactgroup") if b.get("contactgroup_name") == name), None)
        return None if block is None else set(_names(block.get("members")))

    def command_line(self, name: str) -> Optional[str]:
        block = next((b for b in self.of_kind("command") if b.get("command_name") == name), None)
        return None if block is None else block.get("command_line")

    def effective_command(self, block: Optional[Dict[str, str]], macros: Optional[dict] = None) -> str:
        """The command line a host or service block runs, its ``$ARGn$`` and the given macros
        expanded (``''`` when the block or its command is missing)."""
        if not block:
            return ""
        name, args = split_check_command(block.get("check_command"))
        line = self.command_line(name)
        return expand_command_line(line, args, macros) if line else ""


def parse_objects_cache(text: str) -> NagiosObjects:
    blocks = parse_blocks(text)
    return NagiosObjects(blocks=blocks, ran=bool(blocks))


def number(block: Optional[Dict[str, str]], key: str, default: Optional[float] = None) -> Optional[float]:
    """A numeric directive of a block (``check_interval	0.500000`` → 0.5)."""
    try:
        return float((block or {}).get(key, ""))
    except ValueError:
        return default


@dataclass
class NagiosStatus:
    """The current states (``status.dat``)."""
    blocks: List[Tuple[str, Dict[str, str]]] = field(default_factory=list)
    ran: bool = False

    def host(self, name: str) -> Optional[Dict[str, str]]:
        return next((b for k, b in self.blocks if k == "hoststatus" and b.get("host_name") == name), None)

    def service(self, host: str, description: str) -> Optional[Dict[str, str]]:
        return next((b for k, b in self.blocks if k == "servicestatus" and b.get("host_name") == host
                     and b.get("service_description") == description), None)

    def created(self) -> Optional[int]:
        info = next((b for k, b in self.blocks if k == "info"), None)
        value = number(info, "created")
        return int(value) if value is not None else None


def parse_status_dat(text: str) -> NagiosStatus:
    blocks = parse_blocks(text)
    return NagiosStatus(blocks=blocks, ran=any(k == "programstatus" for k, _ in blocks))


def checked_state(block: Optional[Dict[str, str]], since: Optional[int] = None) -> Optional[int]:
    """``current_state`` of a status block that has been checked (at or after *since* when given),
    ``None`` otherwise: 0 OK / UP, 1 WARNING / DOWN, 2 CRITICAL / UNREACHABLE, 3 UNKNOWN."""
    if not block or number(block, "has_been_checked") != 1:
        return None
    if since is not None and (number(block, "last_check", 0) or 0) < since:
        return None
    state = number(block, "current_state")
    return int(state) if state is not None else None


# ---------------------------------------------------------------------------
# plugins
# ---------------------------------------------------------------------------

_PERF_RE = re.compile(r"(?:'([^']+)'|([^\s=']+))=([^\s;]*)((?:;[^\s;]*)*)")
_NUM_RE = re.compile(r"^(-?\d+(?:\.\d+)?)(.*)$")


@dataclass
class PerfValue:
    value: Optional[float]
    unit: str = ""
    warn: str = ""
    crit: str = ""
    minimum: str = ""
    maximum: str = ""


def parse_perfdata(text: str) -> Dict[str, PerfValue]:
    """``'time=0.004s;;;0.000;10.000 /=440B;73;79;0;85'`` → ``{label: PerfValue}``."""
    result: Dict[str, PerfValue] = {}
    for m in _PERF_RE.finditer(text or ""):
        label = m.group(1) or m.group(2)
        num = _NUM_RE.match(m.group(3))
        rest = (m.group(4) or "").split(";")[1:] + [""] * 4
        result[label] = PerfValue(value=float(num.group(1)) if num else None, unit=num.group(2) if num else "",
                                  warn=rest[0], crit=rest[1], minimum=rest[2], maximum=rest[3])
    return result


@dataclass
class PluginResult:
    """What a plugin (run by hand, or through ``check_nrpe``) printed."""
    ran: bool = False        #: the ``===RC`` marker is in the output
    rc: Optional[int] = None
    line: str = ""           #: first line, before the ``|``
    state: str = ""          #: OK / WARNING / CRITICAL / UNKNOWN when the first line names one
    perfdata: Dict[str, PerfValue] = field(default_factory=dict)
    output: str = ""

    @property
    def ok(self) -> bool:
        return self.ran and self.rc == 0


def parse_plugin_output(output: str) -> PluginResult:
    text = output or ""
    m = _RC_RE.search(text)
    body = _RC_RE.sub("", text).strip("\n")
    first = body.splitlines()[0] if body else ""
    line, _, perf = first.partition("|")
    # the first state word of the line ("HTTP CRITICAL: HTTP/1.1 200 OK - …" is CRITICAL)
    found = re.search(r"\b(" + "|".join(SERVICE_STATES) + r")\b", line)
    state = found.group(1) if found else ""
    return PluginResult(ran=m is not None, rc=int(m.group(1)) if m else None, line=line.strip(), state=state,
                        perfdata=parse_perfdata(perf), output=text)


# ---------------------------------------------------------------------------
# log, notifications, NRPE configuration
# ---------------------------------------------------------------------------

_LOG_RE = re.compile(r"^\[(\d+)\] ([A-Z][A-Z ]+?): (.*)$")
_T0_RE = re.compile(r"^===T0 (\d+)\s*$", re.M)


@dataclass
class LogEntry:
    time: int
    kind: str                 #: ``SERVICE NOTIFICATION``, ``HOST ALERT``, ``EXTERNAL COMMAND``…
    fields: List[str]         #: the ``;``-separated fields after the kind


def parse_nagios_log(text: str) -> List[LogEntry]:
    """The ``[epoch] KIND: a;b;c`` lines of ``nagios.log`` (other lines are skipped)."""
    entries = []
    for line in (text or "").splitlines():
        m = _LOG_RE.match(line.strip())
        if m:
            entries.append(LogEntry(time=int(m.group(1)), kind=m.group(2), fields=m.group(3).split(";")))
    return entries


def notifications(entries: Iterable[LogEntry], kind: str = "SERVICE", contact: Optional[str] = None,
                  host: Optional[str] = None, service: Optional[str] = None, since: int = 0) -> List[LogEntry]:
    """Notification entries of *kind* (``'SERVICE'``: contact;host;service;type;command;output…,
    ``'HOST'``: contact;host;type;command;output…) at or after *since*."""
    wanted = f"{kind} NOTIFICATION"
    result = []
    for e in entries:
        if e.kind != wanted or e.time < since or len(e.fields) < (5 if kind == "SERVICE" else 4):
            continue
        if contact is not None and e.fields[0] != contact:
            continue
        if host is not None and e.fields[1] != host:
            continue
        if kind == "SERVICE" and service is not None and e.fields[2] != service:
            continue
        result.append(e)
    return result


def notification_type(entry: LogEntry) -> str:
    """Type field of a notification entry (``CRITICAL``, ``OK``, ``CUSTOM (OK)``, ``DOWN``…)."""
    index = 3 if entry.kind.startswith("SERVICE") else 2
    return entry.fields[index] if len(entry.fields) > index else ""


def parse_t0(text: str) -> Optional[int]:
    """Epoch printed by :func:`external_commands_cmd` (``None`` when it did not run)."""
    m = _T0_RE.search(text or "")
    return int(m.group(1)) if m else None


def parse_written(text: str) -> bool:
    """True when :func:`external_commands_cmd` wrote its commands to the pipe."""
    return bool(re.search(r"^written=0\s*$", text or "", re.M))


@dataclass
class Sms:
    time: int
    number: str
    message: str


def parse_sms_outbox(text: str) -> List[Sms]:
    """Lines of the outbox written by ``sms-send``: epoch, number and message, tab-separated."""
    result = []
    for line in _RC_RE.sub("", text or "").splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3 and parts[0].isdigit():
            result.append(Sms(time=int(parts[0]), number=parts[1].strip(), message=parts[2]))
    return result


def parse_nrpe_config(text: str) -> dict:
    """Active lines of the NRPE files in reading order → ``{'allowed_hosts': [addresses of the
    last line], 'commands': {name: command line}}`` (a later definition replaces an earlier one)."""
    allowed: List[str] = []
    commands: Dict[str, str] = {}
    for raw in _RC_RE.sub("", text or "").splitlines():
        line = raw.strip()
        m = re.match(r"^command\[([^\]]+)\]\s*=\s*(.*)$", line)
        if m:
            commands[m.group(1).strip()] = m.group(2).strip()
            continue
        m = re.match(r"^allowed_hosts\s*=\s*(.*)$", line)
        if m:
            allowed = _names(m.group(1))
    return {"allowed_hosts": allowed, "commands": commands}


# ---------------------------------------------------------------------------
# command lines
# ---------------------------------------------------------------------------

_SAFE_COMMAND_RE = re.compile(r"^[A-Za-z0-9_;:.,/()%+= -]+$")


def external_command(name: str, *args) -> str:
    """``NAME;arg;arg`` of an external command; the placeholder ``{now}`` in an argument becomes
    the time of the write."""
    return ";".join([name, *(str(a) for a in args)])


def external_commands_cmd(commands: Sequence[str]) -> str:
    """One shell line writing *commands* to the command pipe of Nagios, each prefixed by
    ``[epoch]``; prints ``===T0 epoch`` then ``written=0`` on success.  Nothing is written unless
    the path is a pipe (a regular file there would stop Nagios from starting) and the write is
    bounded (a pipe nobody reads would block for ever)."""
    words = []
    for command in commands:
        if not _SAFE_COMMAND_RE.match(command.replace("{now}", "")):
            raise ValueError(f"external_commands_cmd: unsafe characters in {command!r}")
        words.append('"$n" "' + command.replace("{now}", "$n") + '"')
    return (f'f={COMMAND_FILE}; n=$(date +%s); echo "===T0 $n"; if [ -p $f ]; then'
            f" printf '[%s] %s\\n' {' '.join(words)} | timeout 5 tee $f > /dev/null; echo \"written=$?\";"
            f' else echo "written=nopipe"; fi{RC_SUFFIX}')


def objects_cmd() -> str:
    """The object cache of Nagios (ASCII only)."""
    return f"cat {OBJECTS_CACHE} 2>&1{ASCII_ONLY}; echo \"{RC_MARK} $?\""


def status_cmd(wait: int = 12) -> str:
    """``status.dat`` after *wait* seconds: the time forced checks take to run and to be written
    (``status_update_interval``)."""
    return f"sleep {int(wait)}; cat {STATUS_DAT} 2>&1{ASCII_ONLY}; echo \"{RC_MARK} $?\""


def preflight_cmd() -> str:
    """``nagios4 -v`` (the end of its report and its exit status)."""
    return f'out=$(/usr/sbin/nagios4 -v {NAGIOS_CFG} 2>&1); rc=$?; echo "$out" | tail -n 25; echo "{RC_MARK} $rc"'


def check_nrpe_cmd(host: str, command: Optional[str] = None, timeout: int = 5) -> str:
    """``check_nrpe -H host [-c command]`` (without command: the version of the daemon, the test
    of ``allowed_hosts``)."""
    c = f" -c {shlex.quote(command)}" if command else ""
    return f"{PLUGIN_DIR}/check_nrpe -H {host} -t {int(timeout)}{c}{RC_SUFFIX}"


def plugin_case_cmd(plugin: str, args: str, content: Optional[str] = None, user: str = "nagios") -> str:
    """Run *plugin* as *user* with *args* then ``-f FILE``, FILE being a temporary file holding
    *content* (no ``-f`` at all when *content* is ``None``): a test of a plugin reading a file,
    the real one untouched."""
    run = f"runuser -u {user} -- {plugin} {args}".rstrip()
    if content is None:
        return f"{run}{RC_SUFFIX}"
    return (f"f=$(mktemp /tmp/sreq.XXXXXX); echo {shlex.quote(str(content))} > $f; chmod 644 $f;"
            f' {run} -f $f 2>&1; echo "{RC_MARK} $?"; rm -f $f')


def notification_log_cmd(marker: str, lines: int = 20) -> str:
    """The last notification lines of the log holding *marker*."""
    return (f"grep -F 'NOTIFICATION: ' {NAGIOS_LOG} 2>/dev/null | grep -F {shlex.quote(marker)} | tail -n {int(lines)}"
            f"{ASCII_ONLY}; echo \"{RC_MARK} $?\"")


def sms_outbox_cmd(lines: int = 40) -> str:
    return f"tail -n {int(lines)} {SMS_OUTBOX} 2>&1{ASCII_ONLY}; echo \"{RC_MARK} $?\""


def nrpe_config_cmd() -> str:
    """The ``allowed_hosts`` and ``command[]`` lines of the NRPE files, in reading order."""
    return ("grep -hvE '^[[:space:]]*(#|$)' /etc/nagios/nrpe.cfg /etc/nagios/nrpe_local.cfg"
            f" {NRPE_D}/*.cfg 2>/dev/null | grep -E '^(allowed_hosts|command\\[)'; echo \"{RC_MARK} $?\"")


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def render_object(kind: str, directives: Sequence[Tuple[str, object]]) -> str:
    """``define kind { … }`` with aligned directives (``(name, value)`` pairs, in order)."""
    width = max((len(name) for name, _ in directives), default=0) + 4
    body = "".join(f"    {name.ljust(width)}{value}\n" for name, value in directives)
    return f"define {kind} {{\n{body}}}\n"


def render_lab_templates(host_template: str = "lab-host", service_template: str = "lab-service") -> str:
    """Host and service templates checking every 30 s (15 s while a problem is being confirmed,
    three attempts), independent of Debian's ``generic-*`` ones (which notify by e-mail)."""
    common = [("register", 0), ("check_period", "24x7"), ("check_interval", 0.5), ("retry_interval", 0.25),
              ("max_check_attempts", 3), ("flap_detection_enabled", 0), ("notifications_enabled", 1),
              ("notification_period", "24x7"), ("notification_interval", 0)]
    host = [("name", host_template), ("check_command", "check-host-alive"), *common, ("notification_options", "d,u,r")]
    service = [("name", service_template), *common, ("active_checks_enabled", 1), ("passive_checks_enabled", 1),
               ("process_perf_data", 1), ("notification_options", "w,u,c,r")]
    return render_object("host", host) + render_object("service", service)


def render_localhost_cfg() -> str:
    """Debian's ``localhost.cfg`` reduced to the host and three checks that are green in a container
    (swap, load and SSH of the stock file depend on the Docker host or on services not started)."""
    host = render_object("host", [("use", "linux-server"), ("host_name", "localhost"), ("alias", "localhost"),
                                  ("address", "127.0.0.1")])
    group = render_object("hostgroup", [("hostgroup_name", "linux-servers"), ("alias", "Linux Servers"),
                                        ("members", "localhost")])
    services = "".join(
        render_object("service", [("use", "local-service"), ("host_name", "localhost"),
                                  ("service_description", description), ("check_command", command)])
        for description, command in (("PING", "check_ping!100.0,20%!500.0,60%"),
                                     ("Current Users", "check_local_users!20!50"),
                                     ("Total Processes", "check_local_procs!250!400!RSZDT")))
    return host + group + services


def render_sms_send(outbox: str = SMS_OUTBOX) -> str:
    """The "SMS gateway" of the lab: ``sms-send NUMBER MESSAGE`` appends ``epoch<TAB>number<TAB>
    message`` to *outbox*."""
    return ("#!/bin/sh\n"
            '[ $# -ge 2 ] || { echo "usage: sms-send NUMBER MESSAGE" >&2; exit 2; }\n'
            "n=$1; shift\n"
            f"printf '%s\\t%s\\t%s\\n' \"$(date +%s)\" \"$n\" \"$*\" >> {outbox}\n")


def render_labdb_script() -> str:
    """A stand-in for a database: a TCP server answering a banner, whose process is named ``labdb``
    (``check_procs -C labdb`` finds it)."""
    return ('#!/usr/bin/env python3\n'
            '"""A stand-in for a database: a TCP banner server whose process is named labdb."""\n'
            'import ctypes\nimport socket\nimport sys\n\n'
            'ctypes.CDLL(None).prctl(15, b"labdb", 0, 0, 0)\n'
            'port = int(sys.argv[1])\n'
            's = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'
            's.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n'
            's.bind(("0.0.0.0", port))\n'
            's.listen(16)\n'
            'while True:\n'
            '    conn, _ = s.accept()\n'
            '    try:\n'
            '        conn.sendall(b"labdb 1.4 ready\\n")\n'
            '    except OSError:\n'
            '        pass\n'
            '    conn.close()\n')


def render_labdb_unit(port: int) -> str:
    return ("[Unit]\nDescription=Lab database\n\n[Service]\n"
            f"ExecStart={LABDB_SCRIPT} {int(port)}\nRestart=no\n\n[Install]\nWantedBy=multi-user.target\n")


def render_check_queue(default_file: str) -> str:
    """Reference plugin ``check_queue -w W -c C [-f FILE]``: the number held by FILE against two
    thresholds, the four exit codes and a performance value."""
    return f"""#!/bin/sh
FILE={default_file}
while getopts "w:c:f:" o; do
  case $o in w) W=$OPTARG ;; c) C=$OPTARG ;; f) FILE=$OPTARG ;;
    *) echo "QUEUE UNKNOWN - usage: check_queue -w W -c C [-f FILE]"; exit 3 ;; esac
done
case "x$W" in x|x*[!0-9]*) echo "QUEUE UNKNOWN - seuil -w absent ou invalide"; exit 3 ;; esac
case "x$C" in x|x*[!0-9]*) echo "QUEUE UNKNOWN - seuil -c absent ou invalide"; exit 3 ;; esac
[ -r "$FILE" ] || {{ echo "QUEUE UNKNOWN - $FILE illisible"; exit 3; }}
N=$(head -n 1 "$FILE" | tr -d ' \\t\\r')
case "x$N" in x|x*[!0-9]*) echo "QUEUE UNKNOWN - contenu de $FILE invalide"; exit 3 ;; esac
P="queue=$N;$W;$C;0"
if [ "$N" -ge "$C" ]; then echo "QUEUE CRITICAL - $N travaux en attente | $P"; exit 2; fi
if [ "$N" -ge "$W" ]; then echo "QUEUE WARNING - $N travaux en attente | $P"; exit 1; fi
echo "QUEUE OK - $N travaux en attente | $P"; exit 0
"""


def render_nrpe_conf(allowed_hosts: Sequence[str], commands: Sequence[Tuple[str, str]]) -> str:
    """A file of ``/etc/nagios/nrpe.d``: who may ask, and the named commands."""
    lines = ["allowed_hosts=" + ",".join(str(h) for h in allowed_hosts)]
    lines += [f"command[{name}]={line}" for name, line in commands]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


def submit_external_commands(grade: Grade0, machine: str, commands: Sequence[str], step: int = 1) -> Tuple[Optional[int], bool]:
    """Write *commands* to the command pipe of *machine*: ``(t0, written)`` — the epoch of the
    write (``None`` until the command has run) and whether Nagios was there to read."""
    out, _ = grade.test(machine, external_commands_cmd(commands), step=step, allow_error=True)
    return parse_t0(out), parse_written(out)


def get_objects(grade: Grade0, machine: str, step: int = 1) -> NagiosObjects:
    out, _ = grade.test(machine, objects_cmd(), step=step, allow_error=True)
    return parse_objects_cache(out)


def get_status(grade: Grade0, machine: str, wait: int = 12, step: int = 2) -> NagiosStatus:
    out, _ = grade.test(machine, status_cmd(wait), step=step, timeout=wait + 20, allow_error=True)
    return parse_status_dat(out)


def check_nrpe(grade: Grade0, machine: str, host: str, command: Optional[str] = None, step: int = 1,
               timeout: int = 5) -> PluginResult:
    out, _ = grade.test(machine, check_nrpe_cmd(host, command, timeout), step=step, timeout=timeout + 15,
                        allow_error=True)
    return parse_plugin_output(out)


def plugin_case(grade: Grade0, machine: str, plugin: str, args: str, content: Optional[str] = None,
                user: str = "nagios", step: int = 1) -> PluginResult:
    out, _ = grade.test(machine, plugin_case_cmd(plugin, args, content, user), step=step, allow_error=True)
    return parse_plugin_output(out)


def get_nrpe_config(grade: Grade0, machine: str, step: int = 1) -> dict:
    out, _ = grade.test(machine, nrpe_config_cmd(), step=step, allow_error=True)
    return parse_nrpe_config(out)


def get_notifications(grade: Grade0, machine: str, marker: str, step: int = 2) -> List[LogEntry]:
    out, _ = grade.test(machine, notification_log_cmd(marker), step=step, allow_error=True)
    return parse_nagios_log(out)


def get_sms(grade: Grade0, machine: str, step: int = 2) -> List[Sms]:
    out, _ = grade.test(machine, sms_outbox_cmd(), step=step, allow_error=True)
    return parse_sms_outbox(out)
