"""Net-SNMP grading and state helpers of the SNMP lab (``lab/sre/_DRAFT_misc/snmp.py``).

Facts and formats are those of Net-SNMP 5.9.3 (Debian 12: ``snmp``, ``snmpd``, ``snmptrapd`` in the
``sysreseval/monitoring`` image built on ``init``); the fixtures of ``tests/mock_data/snmp/`` were
captured in those containers.  The Nagios and Prometheus labs use :func:`set_snmp_agent` to give
their router a ready agent.

**Client outputs**: the grader runs the Net-SNMP tools with ``-m '' -On`` (:data:`GRADER_OPTS`: no
MIB loaded, numeric OIDs, the same text whatever the MIB files and the ``snmp.conf`` of the
machine) and :func:`parse_snmp_output` reads the ``OID = TYPE: value`` lines into :class:`SnmpVar`
(quoted and multi-line strings, ``Hex-STRING``, ``Timeticks``, the per-variable exceptions
``No Such Object`` / ``No Such Instance`` / ``No more variables``); :func:`parse_snmp_error` names
what a whole command reported (``timeout``, ``auth_failure``, ``unknown_user``, ``authorization``,
``no_access``, ``not_writable``, ``wrong_type``…); :func:`snmp_result` combines both into a
:class:`SnmpResult`.  Helpers: :func:`normalize_oid`, :func:`oid_under`, :func:`table_rows`,
:func:`extend_index` / :func:`extend_oid` (the string index of ``NET-SNMP-EXTEND-MIB``),
:func:`normalize_mac`.

**Commands** (one shell line each, ``2>&1; echo "===RC $?"`` appended: the exetests of a machine
capture stdout only, and the marker tells a command that ran from a placeholder):
:func:`snmpget_cmd`, :func:`snmpwalk_cmd`, :func:`snmpset_cmd`, :func:`snmptrap_cmd`, with the
credentials of :func:`snmp_auth_args` (``community=`` for v2c, ``user=`` … for SNMPv3 USM);
``isolate=True`` (default) sets ``SNMPCONFPATH`` to a missing directory so that a ``snmp.conf``
written by a student changes nothing.  :func:`rate_sample_cmd` samples the kernel counters of an
interface twice (:func:`parse_rate_sample`: the bit rate a student must find with two readings of
``ifHCOutOctets``).

**Agent configuration**: :func:`parse_snmpd_conf` → ``[(directive, [arguments])]`` with
:func:`conf_values`, :func:`conf_communities`, :func:`conf_trap_sinks`.

**Traps**: :func:`parse_trap_log` groups the lines of a ``snmptrapd`` log into records (the default
format prints two lines per notification, a ``format2`` line one), :func:`trap_log_window` keeps
the records added between two line counts, :func:`is_authentication_failure` recognises the
``authenticationFailure`` notification with or without MIB names.

**States**: :func:`render_snmpd_conf`, :func:`render_snmptrapd_conf`, :func:`render_snmp_client_conf`,
:func:`render_snmptrapd_dropin`, :func:`create_v3_user_cmd`, :func:`set_snmp_agent` (writes the
agent's file and (re)starts it, under systemd or directly) and :func:`set_snmptrapd_service`.

Facts (verified 2026-11-11 in the containers, IPv6 disabled as Kathara does):

- the Debian default ``agentaddress 127.0.0.1,[::1]`` makes ``snmpd`` exit (``Error opening
  specified endpoint "[::1]"``); ``agentaddress udp:161`` listens on every IPv4 address;
- ``rocommunity C NET`` answers a source outside *NET* with silence (the client times out); a v2c
  request outside the view of a community gets ``No Such Object`` per variable, exit status 0;
- ``sysName.0`` is writable through a ``rwcommunity`` and kept in ``/var/lib/snmp/snmpd.conf``
  across restarts; a ``sysLocation`` set in ``snmpd.conf`` answers ``notWritable``; a write with a
  read-only community answers ``noAccess``;
- ``createUser U SHA-256 "…" AES "…"`` in ``/var/lib/snmp/snmpd.conf`` (agent stopped) is replaced
  by a hashed ``usmUser`` line at the next start; with ``rouser U priv`` a request at a lower level
  gets ``authorizationError``, a wrong authentication passphrase ``Authentication failure``, a
  wrong privacy passphrase a time-out, an unknown user ``Unknown user name``;
  ``net-snmp-create-v3-user`` (package ``snmpd``) appends a plain ``rouser U`` (level ``auth``);
- the unit of ``snmptrapd`` (``-LOw``, user ``Debian-snmp``) starts but logs no notification:
  :func:`render_snmptrapd_dropin` runs it with ``-A -Lf FILE`` (appending); a notification with a
  community that no ``authCommunity`` line accepts is dropped silently;
- ``authtrapenable 1`` + ``trap2sink`` send one ``authenticationFailure`` per request with a wrong
  community, ``coldStart`` at each start and ``nsNotifyShutdown`` at each stop;
- ``disk /`` gives no row when ``/`` is an overlay file system (every container): use a bind mount
  such as ``/shared``; ``load`` thresholds are compared with the load of the Docker host.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0, NetScheme0

RC_MARK = "===RC"
_RC_RE = re.compile(r"^===RC (-?\d+)\s*$", re.M)
RC_SUFFIX = f' 2>&1; echo "{RC_MARK} $?"'  #: appended to every command: stderr merged, exit status kept

SNMPD_CONF = "/etc/snmp/snmpd.conf"
SNMPD_PERSISTENT = "/var/lib/snmp/snmpd.conf"  #: createUser lines, values written with snmpset
SNMPTRAPD_CONF = "/etc/snmp/snmptrapd.conf"
SNMPTRAPD_LOG = "/var/log/snmptrapd.log"
SNMPTRAPD_DROPIN = "/etc/systemd/system/snmptrapd.service.d/sre.conf"
SNMP_CLIENT_CONF = "/root/.snmp/snmp.conf"
#: what the Debian unit passes to snmpd (the DisMan event MIB is left out: no ``monitor`` directive)
DEBIAN_SNMPD_ARGS = "-u Debian-snmp -g Debian-snmp -I -smux,mteTrigger,mteTriggerConf"
GRADER_OPTS = "-m '' -On"  #: no MIB loaded, numeric OIDs: one output form on every machine
ISOLATE = "SNMPCONFPATH=/nonexistent "  #: no snmp.conf read: a student's defaults change nothing

#: numeric OIDs of the objects the labs name (scalars carry their ``.0``)
OID = {
    "sysDescr": ".1.3.6.1.2.1.1.1.0",
    "sysObjectID": ".1.3.6.1.2.1.1.2.0",
    "sysUpTime": ".1.3.6.1.2.1.1.3.0",
    "sysContact": ".1.3.6.1.2.1.1.4.0",
    "sysName": ".1.3.6.1.2.1.1.5.0",
    "sysLocation": ".1.3.6.1.2.1.1.6.0",
    "sysServices": ".1.3.6.1.2.1.1.7.0",
    "system": ".1.3.6.1.2.1.1",
    "interfaces": ".1.3.6.1.2.1.2",
    "ifNumber": ".1.3.6.1.2.1.2.1.0",
    "ifDescr": ".1.3.6.1.2.1.2.2.1.2",
    "ifPhysAddress": ".1.3.6.1.2.1.2.2.1.6",
    "ifOperStatus": ".1.3.6.1.2.1.2.2.1.8",
    "ifInOctets": ".1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": ".1.3.6.1.2.1.2.2.1.16",
    "ipForwarding": ".1.3.6.1.2.1.4.1.0",
    "ipAdEntIfIndex": ".1.3.6.1.2.1.4.20.1.2",
    "tcpCurrEstab": ".1.3.6.1.2.1.6.9.0",
    "udpInDatagrams": ".1.3.6.1.2.1.7.1.0",
    "snmpInPkts": ".1.3.6.1.2.1.11.1.0",
    "snmpEnableAuthenTraps": ".1.3.6.1.2.1.11.30.0",
    "hrSystemUptime": ".1.3.6.1.2.1.25.1.1.0",
    "ifHCInOctets": ".1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": ".1.3.6.1.2.1.31.1.1.1.10",
    "ifHCOutUcastPkts": ".1.3.6.1.2.1.31.1.1.1.11",
    "memTotalReal": ".1.3.6.1.4.1.2021.4.5.0",
    "prTable": ".1.3.6.1.4.1.2021.2",
    "prEntry": ".1.3.6.1.4.1.2021.2.1",
    "dskTable": ".1.3.6.1.4.1.2021.9",
    "dskEntry": ".1.3.6.1.4.1.2021.9.1",
    "laTable": ".1.3.6.1.4.1.2021.10",
    "laEntry": ".1.3.6.1.4.1.2021.10.1",
    "nsExtendCommand": ".1.3.6.1.4.1.8072.1.3.2.2.1.2",
    "nsExtendOutput1Line": ".1.3.6.1.4.1.8072.1.3.2.3.1.1",
    "nsExtendResult": ".1.3.6.1.4.1.8072.1.3.2.3.1.4",
    "netSnmpPlaypen": ".1.3.6.1.4.1.8072.9999.9999",  # reserved for experiments: the grader's own traps
    "authenticationFailure": ".1.3.6.1.6.3.1.1.5.5",
    "coldStart": ".1.3.6.1.6.3.1.1.5.1",
}
# columns of the UCD-SNMP-MIB tables read by the labs
PR_NAMES, PR_MIN, PR_MAX, PR_COUNT, PR_ERROR_FLAG = 2, 3, 4, 5, 100
DSK_PATH, DSK_MIN_PERCENT, DSK_PERCENT = 2, 5, 9
LA_LOAD, LA_CONFIG = 3, 4


# ---------------------------------------------------------------------------
# OIDs, MAC addresses
# ---------------------------------------------------------------------------


def normalize_oid(oid) -> str:
    """Numeric OID with one leading dot and no trailing dot (``'1.3.6.1'`` → ``'.1.3.6.1'``);
    ``''`` for something that is not a numeric OID."""
    text = str(oid or "").strip().strip(".")
    if not re.fullmatch(r"\d+(\.\d+)*", text):
        return ""
    return "." + text


def oid_under(oid, base) -> bool:
    """True when *oid* is *base* or below it."""
    o, b = normalize_oid(oid), normalize_oid(base)
    return bool(o and b) and (o == b or o.startswith(b + "."))


def extend_index(name: str) -> str:
    """Index of a row of the ``NET-SNMP-EXTEND-MIB`` tables: the name of the ``extend`` line as a
    length-prefixed string (``'asset'`` → ``'5.97.115.115.101.116'``)."""
    data = str(name).encode()
    return ".".join(str(n) for n in (len(data), *data))


def extend_oid(column: str, name: str) -> str:
    """OID of one cell of an ``extend`` entry; *column* is ``'nsExtendOutput1Line'``,
    ``'nsExtendResult'`` or ``'nsExtendCommand'``."""
    return f"{OID[column]}.{extend_index(name)}"


def normalize_mac(text) -> str:
    """``aa:bb:cc:dd:ee:ff`` form of a MAC address written as Net-SNMP prints it
    (``CA 9F DC E5 C7 2A``, ``2:53:4e:a:1b:2c``) or as a student types it (``02-53-4E-0A-1B-2C``,
    ``02534e0a1b2c``); ``''`` when it is not one."""
    s = str(text or "").strip().strip('"').strip()
    parts = [p for p in re.split(r"[:\-\s.]+", s) if p]
    if len(parts) == 1 and re.fullmatch(r"[0-9A-Fa-f]{12}", parts[0]):
        parts = [parts[0][i:i + 2] for i in range(0, 12, 2)]
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
        return ""
    return ":".join(p.lower().zfill(2) for p in parts)


# ---------------------------------------------------------------------------
# client outputs
# ---------------------------------------------------------------------------

EXCEPTIONS = {
    "No Such Object available on this agent at this OID": "noSuchObject",
    "No Such Instance currently exists at this OID": "noSuchInstance",
    "No more variables left in this MIB View (It is past the end of the MIB tree)": "endOfMibView",
}
_VAR_RE = re.compile(r"^(?P<oid>\S+) = (?P<rest>.*)$")
_TYPED_RE = re.compile(r"^(?P<type>[A-Za-z][A-Za-z0-9\- ]*?): (?P<value>.*)$", re.S)
_TICKS_RE = re.compile(r"^\((\d+)\)")
_HEX_LINE_RE = re.compile(r"^\s*[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2})*\s*$")
_ERRORS = (
    ("timeout", re.compile(r"Timeout: No Response from")),
    ("auth_failure", re.compile(r"Authentication failure")),
    ("unknown_user", re.compile(r"Unknown user name")),
    ("unsupported_level", re.compile(r"Unsupported security level")),
    ("no_security_name", re.compile(r"No securityName specified")),
    ("authorization", re.compile(r"Reason: authorizationError")),
    ("not_writable", re.compile(r"Reason: notWritable")),
    ("no_access", re.compile(r"Reason: noAccess")),
    ("wrong_type", re.compile(r"Reason: wrong(Type|Length|Value|Encoding)")),
    ("no_such_name", re.compile(r"Reason: \(noSuchName\)")),
    ("other", re.compile(r"Error in packet|^snmp\w+: ", re.M)),
)


@dataclass
class SnmpVar:
    """One variable binding of a client output."""
    oid: str
    type: str = ""          #: ``STRING``, ``INTEGER``, ``Timeticks``, ``Hex-STRING``, ``OID``… ('' for an untyped ``""``)
    value: str = ""         #: the text after the type, quotes removed
    exception: str = ""     #: ``noSuchObject`` / ``noSuchInstance`` / ``endOfMibView`` when the agent gave no value

    @property
    def has_value(self) -> bool:
        return not self.exception

    @property
    def text(self) -> str:
        return self.value if self.has_value else ""

    @property
    def int(self) -> Optional[int]:
        """The value as an integer (the ticks of a ``Timeticks``, the number before an enumeration
        label such as ``up(1)`` is not expected with ``-m ''``); ``None`` when it is not one."""
        if not self.has_value:
            return None
        m = _TICKS_RE.match(self.value)
        if m:
            return int(m.group(1))
        m = re.match(r"^-?\d+$", self.value.strip())
        return int(m.group(0)) if m else None


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


def _open_string(rest: str) -> bool:
    """True when *rest* starts a quoted string that its line does not close."""
    m = _TYPED_RE.match(rest)
    value = (m.group("value") if m else rest).strip()
    if not value.startswith('"'):
        return False
    body = value[1:]
    return len(re.findall(r'(?<!\\)"', body)) == 0


def parse_snmp_output(text: str) -> List[SnmpVar]:
    """The variable bindings printed by ``snmpget`` / ``snmpwalk`` / ``snmpset``.

    Lines that are not ``OID = …`` (errors, ``Created directory``…) are skipped, except the
    continuation lines of a multi-line string or of a wrapped ``Hex-STRING``.  OIDs are kept as
    printed (numeric ones normalised with a leading dot)."""
    result: List[SnmpVar] = []
    state = {"oid": None, "rest": "", "kind": None}  # a value going on: kind 'string' or 'hex'

    def flush():
        if state["oid"] is not None:
            result.append(_make_var(state["oid"], state["rest"]))
        state.update(oid=None, rest="", kind=None)

    for line in _RC_RE.sub("", text or "").splitlines():
        if state["kind"] == "string":
            state["rest"] += "\n" + line
            if not _open_string(state["rest"]):
                flush()
            continue
        if state["kind"] == "hex" and _HEX_LINE_RE.match(line):
            state["rest"] += " " + line.strip()
            continue
        flush()
        m = _VAR_RE.match(line)
        if not m or not (normalize_oid(m.group("oid")) or "::" in m.group("oid")):
            continue
        state.update(oid=m.group("oid"), rest=m.group("rest"))
        if _open_string(state["rest"]):
            state["kind"] = "string"
        elif state["rest"].startswith("Hex-STRING:"):
            state["kind"] = "hex"
        else:
            flush()
    flush()
    return result


def _make_var(oid: str, rest: str) -> SnmpVar:
    oid = normalize_oid(oid) or oid
    rest = rest.rstrip()
    if rest in EXCEPTIONS:
        return SnmpVar(oid=oid, exception=EXCEPTIONS[rest])
    m = _TYPED_RE.match(rest)
    if m and not rest.startswith('"'):
        type_, value = m.group("type"), m.group("value")
        if type_ == "Hex-STRING":
            value = " ".join(value.split())
        return SnmpVar(oid=oid, type=type_, value=_unquote(value))
    return SnmpVar(oid=oid, value=_unquote(rest))


def parse_snmp_error(text: str) -> Optional[str]:
    """What a whole command reported, ``None`` when nothing: ``timeout`` (no answer: wrong
    community, refused source, wrong privacy key, agent down), ``auth_failure`` (wrong SNMPv3
    authentication key), ``unknown_user``, ``authorization`` (security level or view refused),
    ``no_access`` / ``not_writable`` / ``wrong_type`` (a refused write), ``no_such_name`` (SNMPv1),
    ``no_security_name``, ``unsupported_level``, ``other``."""
    for name, regexp in _ERRORS:
        if regexp.search(text or ""):
            return name
    return None


@dataclass
class SnmpResult:
    """What a Net-SNMP client command gave."""
    ran: bool = False            #: its ``===RC`` marker is in the output: False for a placeholder
    exit_code: int = 0
    vars: List[SnmpVar] = field(default_factory=list)
    error: Optional[str] = None  #: see :func:`parse_snmp_error`
    output: str = ""

    @property
    def ok(self) -> bool:
        """The command ran, exited 0 and reported no error (a variable may still be an exception)."""
        return self.ran and self.exit_code == 0 and self.error is None

    @property
    def timed_out(self) -> bool:
        return self.ran and self.error == "timeout"

    @property
    def refused(self) -> bool:
        """The command ran and the agent gave nothing: an error, or no value at all."""
        return self.ran and (self.error is not None or not any(v.has_value for v in self.vars))

    def get(self, oid) -> Optional[SnmpVar]:
        wanted = normalize_oid(oid) or str(oid)
        for var in self.vars:
            if var.oid == wanted:
                return var
        return None

    def has_value(self, oid) -> bool:
        var = self.get(oid)
        return self.ran and var is not None and var.has_value

    def value(self, oid) -> Optional[str]:
        """Text of the variable, ``None`` when absent or an exception."""
        var = self.get(oid)
        return var.value if self.ran and var is not None and var.has_value else None

    def int(self, oid) -> Optional[int]:
        var = self.get(oid)
        return var.int if self.ran and var is not None else None


def snmp_result(output: str, exit_code: int = 0) -> SnmpResult:
    """The :class:`SnmpResult` of a command built here: the ``===RC N`` line gives the exit status
    of the Net-SNMP tool and proves the command ran."""
    text = output or ""
    m = _RC_RE.search(text)
    if m:
        exit_code = int(m.group(1))
    return SnmpResult(ran=m is not None, exit_code=exit_code, vars=parse_snmp_output(text),
                      error=parse_snmp_error(text), output=text)


def table_rows(variables: Iterable[SnmpVar], entry_oid) -> Dict[str, Dict[int, SnmpVar]]:
    """Rows of a table walked numerically: ``{index: {column: SnmpVar}}`` for the variables below
    *entry_oid* (``OID['prEntry']``…), the index being the OID components after the column."""
    base = normalize_oid(entry_oid)
    rows: Dict[str, Dict[int, SnmpVar]] = {}
    for var in variables:
        if not (base and var.oid.startswith(base + ".")):
            continue
        column, _, index = var.oid[len(base) + 1:].partition(".")
        if column.isdigit() and index:
            rows.setdefault(index, {})[int(column)] = var
    return rows


def column_values(variables: Iterable[SnmpVar], entry_oid, column: int) -> Dict[str, str]:
    """``{index: text}`` of one column of a walked table."""
    return {index: row[column].text for index, row in table_rows(variables, entry_oid).items()
            if column in row and row[column].has_value}


# ---------------------------------------------------------------------------
# snmpd.conf
# ---------------------------------------------------------------------------


def parse_snmpd_conf(text: str) -> List[Tuple[str, List[str]]]:
    """``[(directive, [arguments])]`` of a ``snmpd.conf`` / ``snmptrapd.conf`` text (comments and
    empty lines dropped, quotes honoured, directive names lower-cased)."""
    result = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            words = line.split()
        if words:
            result.append((words[0].lower(), words[1:]))
    return result


def conf_values(conf: Sequence[Tuple[str, List[str]]], directive: str) -> List[List[str]]:
    """Argument lists of every *directive* line."""
    return [args for name, args in conf if name == directive.lower()]


def conf_communities(conf: Sequence[Tuple[str, List[str]]]) -> List[dict]:
    """``rocommunity`` / ``rwcommunity`` lines → ``{'community', 'source', 'view', 'oid', 'write'}``
    (``source`` is ``'default'`` when absent; ``view`` the name after ``-V``, ``oid`` a subtree
    given in its place)."""
    result = []
    for name, args in conf:
        if name not in ("rocommunity", "rwcommunity") or not args:
            continue
        entry = {"community": args[0], "source": args[1] if len(args) > 1 else "default",
                 "view": None, "oid": None, "write": name == "rwcommunity"}
        rest = args[2:]
        if rest[:1] == ["-V"] and len(rest) > 1:
            entry["view"] = rest[1]
        elif rest:
            entry["oid"] = rest[0]
        result.append(entry)
    return result


def conf_trap_sinks(conf: Sequence[Tuple[str, List[str]]]) -> List[dict]:
    """``trapsink`` / ``trap2sink`` / ``informsink`` lines → ``{'kind', 'host', 'port', 'community'}``
    (the port from ``host:port`` or from the third argument, 162 otherwise)."""
    result = []
    for name, args in conf:
        if name not in ("trapsink", "trap2sink", "informsink") or not args:
            continue
        host, _, port = args[0].partition(":")
        if host.lower() in ("udp", "tcp") and port:  # udp:host:port
            host, _, port = port.partition(":")
        if len(args) > 2 and args[2].isdigit():
            port = args[2]
        result.append({"kind": name, "host": host, "port": int(port) if port.isdigit() else 162,
                       "community": args[1] if len(args) > 1 else None})
    return result


# ---------------------------------------------------------------------------
# snmptrapd log
# ---------------------------------------------------------------------------

_LOG_HEADER_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ")
_LOG_DAEMON_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )?(NET-SNMP version|Stopping snmptrapd)")
_AUTHFAIL_RE = re.compile(r"authenticationFailure|\.1\.3\.6\.1\.6\.3\.1\.1\.5\.5(?!\d)|snmpTraps\.5(?!\d)")
_LINES_RE = re.compile(r"^===LINES\s+(\d*)\s*$", re.M)


def parse_trap_log(text: str) -> List[str]:
    """The notifications of a ``snmptrapd`` log, one string each: a line starting with a date opens
    a record and the lines after it belong to it (the default format prints the source on a first
    line and the variables on a second one); in a log without any dated line every line is a
    record.  The daemon's own lines (``NET-SNMP version …``, ``Stopping snmptrapd``) are dropped."""
    lines = [line for line in (text or "").splitlines() if line.strip() and not _LOG_DAEMON_RE.match(line)]
    if not any(_LOG_HEADER_RE.match(line) for line in lines):
        return lines
    records: List[str] = []
    for line in lines:
        if _LOG_HEADER_RE.match(line) or not records:
            records.append(line)
        else:
            records[-1] += "\n" + line
    return records


def is_authentication_failure(record: str) -> bool:
    """True when a log record is an ``authenticationFailure`` notification (name or numeric OID)."""
    return bool(_AUTHFAIL_RE.search(record or ""))


def parse_marked_lines(text: str) -> Optional[int]:
    """The number after the ``===LINES`` marker of :func:`trap_log_lines_cmd` /
    :func:`trap_log_tail_cmd` (``None`` when the command did not run, 0 for a missing file)."""
    m = _LINES_RE.search(text or "")
    if not m:
        return None
    return int(m.group(1)) if m.group(1) else 0


def trap_log_window(tail_output: str, before: Optional[int]) -> List[str]:
    """Records of the lines added to the log since it had *before* lines, from the output of
    :func:`trap_log_tail_cmd` (the whole tail when *before* is unknown or the log was rotated)."""
    after = parse_marked_lines(tail_output)
    body = (tail_output or "").split("===TAIL", 1)[-1]
    body = _RC_RE.sub("", body)
    lines = body.splitlines()
    if lines and not lines[0].strip():
        lines = lines[1:]
    if before is not None and after is not None and after >= before:
        new = after - before
        lines = lines[-new:] if new else []
    return parse_trap_log("\n".join(lines))


# ---------------------------------------------------------------------------
# rate samples
# ---------------------------------------------------------------------------

_RATE_RE = re.compile(r"^===RATE (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)\s*$", re.M)


def parse_rate_sample(text: str) -> Optional[dict]:
    """Output of :func:`rate_sample_cmd` → ``{'bps', 'pps', 'frame', 'seconds', 'bytes', 'packets'}``
    (bits and packets per second, mean frame size in bytes), ``None`` when the sample is missing
    or empty (no packet went through)."""
    m = _RATE_RE.search(text or "")
    if not m:
        return None
    b1, p1, t1, b2, p2, t2 = (int(g) for g in m.groups())
    seconds = (t2 - t1) / 1e9
    octets, packets = b2 - b1, p2 - p1
    if seconds <= 0 or octets <= 0 or packets <= 0:
        return None
    return {"bps": octets * 8 / seconds, "pps": packets / seconds, "frame": octets / packets,
            "seconds": seconds, "bytes": octets, "packets": packets}


# ---------------------------------------------------------------------------
# command lines
# ---------------------------------------------------------------------------


def snmp_auth_args(community: Optional[str] = None, *, user: Optional[str] = None, level: str = "authPriv",
                   auth_proto: str = "SHA-256", auth_pass: Optional[str] = None, priv_proto: str = "AES",
                   priv_pass: Optional[str] = None, version: Optional[str] = None) -> str:
    """Credentials of a client command: ``community=`` gives ``-v2c -c C`` (``version='1'`` for
    SNMPv1), ``user=`` gives ``-v3 -u U -l LEVEL`` with the passphrases the level needs."""
    if user is None:
        if community is None:
            raise ValueError("snmp_auth_args: a community or a user is needed")
        return f"-v{version or '2c'} -c {shlex.quote(community)}"
    words = ["-v3", "-u", shlex.quote(user), "-l", level]
    if level in ("authNoPriv", "authPriv"):
        words += ["-a", auth_proto, "-A", shlex.quote(auth_pass or "")]
    if level == "authPriv":
        words += ["-x", priv_proto, "-X", shlex.quote(priv_pass or "")]
    return " ".join(words)


def _client(tool: str, host: str, tail: str, timeout: int, retries: int, isolate: bool, env: str, auth: dict) -> str:
    prefix = ISOLATE if isolate else ""
    credentials = snmp_auth_args(**auth) + " " if auth else ""  # none: the defaults of the user's snmp.conf
    return (f"{env}{prefix}{tool} {credentials}{GRADER_OPTS} -t {int(timeout)} -r {int(retries)}"
            f" {host} {tail}{RC_SUFFIX}")


def snmpget_cmd(host: str, oids, *, timeout: int = 1, retries: int = 1, isolate: bool = True, env: str = "",
                **auth) -> str:
    """``snmpget`` of one or several numeric OIDs (*oids*: a string or a sequence).  Pass
    ``retries=0`` to a request expected to be refused (one second instead of two).  Without any
    credential keyword the command carries none: with ``isolate=False, env='HOME=/root '`` it
    tests the defaults a user wrote in ``~/.snmp/snmp.conf``."""
    if isinstance(oids, str):
        oids = [oids]
    return _client("snmpget", host, " ".join(normalize_oid(o) or str(o) for o in oids), timeout, retries,
                   isolate, env, auth)


def snmpwalk_cmd(host: str, base, *, timeout: int = 1, retries: int = 1, isolate: bool = True, env: str = "",
                 **auth) -> str:
    """``snmpwalk`` of the subtree *base*."""
    return _client("snmpwalk", host, normalize_oid(base) or str(base), timeout, retries, isolate, env, auth)


def snmpset_cmd(host: str, oid, type_char: str, value, *, timeout: int = 1, retries: int = 1, isolate: bool = True,
                env: str = "", **auth) -> str:
    """``snmpset OID TYPE VALUE`` (*type_char*: ``s`` string, ``i`` integer…)."""
    tail = f"{normalize_oid(oid) or oid} {type_char} {shlex.quote(str(value))}"
    return _client("snmpset", host, tail, timeout, retries, isolate, env, auth)


class raw(str):
    """A shell word given as is to a command builder (already quoted by the caller): a value
    holding ``$(…)`` or ``$VAR`` that the shell of the container must expand."""


def snmptrap_cmd(host: str, community: str, trap_oid, varbinds: Sequence[Tuple[str, str, str]] = (),
                 port: int = 162, inform: bool = False) -> str:
    """``snmptrap -v2c`` (``snmpinform`` with *inform*) to *host*, without the ``===RC`` suffix (the
    caller chains several of them); *varbinds*: ``(oid, type, value)`` triples, each value one
    shell word (quoted here, or given as a :class:`raw` word)."""
    tool = "snmpinform" if inform else "snmptrap"
    binds = " ".join(f"{normalize_oid(o) or o} {t} {v if isinstance(v, raw) else shlex.quote(str(v))}"
                     for o, t, v in varbinds)
    return (f"{ISOLATE}{tool} -v2c -c {shlex.quote(community)} -m '' {host}:{int(port)} ''"
            f" {normalize_oid(trap_oid) or trap_oid} {binds}").rstrip()


def rate_sample_cmd(dev: str, direction: str = "tx", seconds: int = 5) -> str:
    """Two readings of the kernel counters of *dev* (``/sys/class/net/DEV/statistics``), *seconds*
    apart, printed as ``===RATE bytes1 packets1 ns1 bytes2 packets2 ns2`` (the clock is the
    container's: an archived evaluation re-grades the same)."""
    d = f"/sys/class/net/{dev}/statistics"
    return (f"a=$(cat {d}/{direction}_bytes); p=$(cat {d}/{direction}_packets); t=$(date +%s%N); sleep {int(seconds)};"
            f' echo "===RATE $a $p $t $(cat {d}/{direction}_bytes) $(cat {d}/{direction}_packets) $(date +%s%N)"'
            f'{RC_SUFFIX}')


def trap_log_lines_cmd(path: str = SNMPTRAPD_LOG) -> str:
    """Number of lines of the trap log, as ``===LINES N`` (nothing after the marker when the file
    is missing)."""
    return f'echo "===LINES $(wc -l < {shlex.quote(path)} 2>/dev/null)"{RC_SUFFIX}'


def trap_log_tail_cmd(path: str = SNMPTRAPD_LOG, lines: int = 200, wait: int = 1) -> str:
    """The line count then the last *lines* lines of the trap log (after *wait* seconds: the daemon
    writes a notification as it arrives), non-ASCII bytes removed: the outputs must be UTF-8."""
    q = shlex.quote(path)
    return (f'sleep {int(wait)}; echo "===LINES $(wc -l < {q} 2>/dev/null)"; echo "===TAIL";'
            f" tail -n {int(lines)} {q} 2>/dev/null | tr -cd '\\11\\12\\15\\40-\\176'{RC_SUFFIX}")


def snmpd_conf_dump_cmd() -> str:
    """The active lines of the agent's configuration (``snmpd.conf`` and ``snmpd.conf.d``)."""
    return (f"cat {SNMPD_CONF} /etc/snmp/snmpd.conf.d/*.conf 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)'"
            f"{RC_SUFFIX}")


def create_v3_user_cmd(user: str, auth_pass: str, priv_pass: str, auth_proto: str = "SHA-256",
                       priv_proto: str = "AES", systemd: bool = True, reset: bool = True) -> str:
    """One shell line creating a USM user the documented way: agent stopped, a ``createUser`` line
    in the persistent file (emptied first with *reset*: other users and written values are lost),
    agent started (it replaces the line by the hashed ``usmUser`` one)."""
    line = f'createUser {user} {auth_proto} "{auth_pass}" {priv_proto} "{priv_pass}"'
    stop = "systemctl stop snmpd" if systemd else "pkill -x snmpd; sleep 0.3"
    start = "systemctl start snmpd" if systemd else snmpd_start_cmd()
    clean = f"rm -f {SNMPD_PERSISTENT}; " if reset else ""
    return (f"{stop}; {clean}printf '%s\\n' {shlex.quote(line)} >> {SNMPD_PERSISTENT};"
            f" chown Debian-snmp:Debian-snmp {SNMPD_PERSISTENT}; chmod 600 {SNMPD_PERSISTENT}; {start}")


def snmpd_start_cmd() -> str:
    """Start the agent without systemd (it detaches by itself), any previous one stopped first."""
    return f"pkill -x snmpd; sleep 0.3; /usr/sbin/snmpd -Lsd {DEBIAN_SNMPD_ARGS} -p /run/snmpd.pid"


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def render_snmpd_conf(*, agentaddress: str = "udp:161", name: Optional[str] = None, location: Optional[str] = None,
                      contact: Optional[str] = None, services: Optional[int] = None,
                      communities: Sequence[dict] = (), views: Sequence[Tuple[str, str]] = (),
                      v3_users: Sequence[Tuple[str, str]] = (), extends: Sequence[Tuple[str, str]] = (),
                      procs: Sequence[str] = (), disks: Sequence[Tuple[str, str]] = (),
                      load: Optional[Sequence] = None, trap_sinks: Sequence[Tuple[str, str]] = (),
                      authtrapenable: bool = False, extra: Sequence[str] = ()) -> str:
    """Text of a ``snmpd.conf``.

    *communities*: dicts ``{'community', 'source' (optional), 'view' (optional), 'write' (bool)}``;
    *views*: ``(name, subtree)`` pairs (``view NAME included SUBTREE``); *v3_users*: ``(user,
    level)`` pairs (``rouser USER LEVEL``); *extends*: ``(name, command)``; *disks*: ``(path,
    minimum)``; *trap_sinks*: ``(host, community)`` (``trap2sink``)."""
    lines = [f"agentaddress {agentaddress}"]
    if name:
        lines.append(f"sysName     {name}")
    if location:
        lines.append(f"sysLocation {location}")
    if contact:
        lines.append(f"sysContact  {contact}")
    if services is not None:
        lines.append(f"sysServices {int(services)}")
    for view, subtree in views:
        lines.append(f"view {view} included {subtree}")
    for c in communities:
        word = "rwcommunity" if c.get("write") else "rocommunity"
        line = f"{word} {c['community']} {c.get('source') or 'default'}"
        if c.get("view"):
            line += f" -V {c['view']}"
        lines.append(line)
    for user, level in v3_users:
        lines.append(f"rouser {user} {level}")
    for ext_name, command in extends:
        lines.append(f"extend {ext_name} {command}")
    for proc in procs:
        lines.append(f"proc {proc}")
    for path, minimum in disks:
        lines.append(f"disk {path} {minimum}")
    if load:
        lines.append("load " + " ".join(str(v) for v in load))
    for host, community in trap_sinks:
        lines.append(f"trap2sink {host} {community}")
    if authtrapenable:
        lines.append("authtrapenable 1")
    lines.extend(extra)
    return "\n".join(lines) + "\n"


def render_snmptrapd_conf(communities: Sequence[str], extra: Sequence[str] = ()) -> str:
    """Text of a ``snmptrapd.conf`` logging the notifications of the given communities."""
    return "\n".join([f"authCommunity log {c}" for c in communities] + list(extra)) + "\n"


def render_snmp_client_conf(user: str, auth_pass: str, priv_pass: str, auth_proto: str = "SHA-256",
                            priv_proto: str = "AES", level: str = "authPriv") -> str:
    """Text of a ``~/.snmp/snmp.conf`` holding the SNMPv3 defaults of a user of the tools."""
    return (f"defVersion 3\ndefSecurityName {user}\ndefSecurityLevel {level}\ndefAuthType {auth_proto}\n"
            f"defAuthPassphrase {auth_pass}\ndefPrivType {priv_proto}\ndefPrivPassphrase {priv_pass}\n")


def render_snmptrapd_dropin(log_file: str = SNMPTRAPD_LOG) -> str:
    """Drop-in of ``snmptrapd.service`` writing the notifications to *log_file* (appending): the
    Debian unit logs warnings only (``-LOw``), so that nothing received ever shows."""
    return ("[Service]\nUser=root\nExecStart=\n"
            f"ExecStart=/usr/sbin/snmptrapd -f -A -Lf {log_file} udp:162\n")


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def set_snmp_agent(net_scheme: NetScheme0, machine: str, community: Optional[str] = None,
                   location: Optional[str] = None, contact: Optional[str] = None, *, name: Optional[str] = None,
                   sources: Optional[Sequence] = None, extends: Sequence[Tuple[str, str]] = (),
                   systemd: bool = False, step: int = 1, **render_kwargs) -> None:
    """Give *machine* a running SNMP agent: listening on UDP 161 of every address, the whole tree
    readable with *community* from *sources* (networks or addresses; everywhere when omitted).

    ``systemd=False`` (default) starts ``snmpd`` directly: a machine of the monitoring image
    without ``/sbin/init`` (a router, a hidden probe).  The other keywords are those of
    :func:`render_snmpd_conf`."""
    communities = list(render_kwargs.pop("communities", ()))
    if community:
        for source in (sources or ["default"]):
            communities.append({"community": community, "source": str(source)})
    text = render_snmpd_conf(name=name, location=location, contact=contact, communities=communities,
                             extends=extends, **render_kwargs)
    net_scheme.file(machine, SNMPD_CONF, text, permissions=0o640, owner="root:Debian-snmp", step=step)
    net_scheme.cmd(machine, "systemctl restart snmpd" if systemd else snmpd_start_cmd(), step=step)


def set_snmptrapd_service(net_scheme: NetScheme0, machine: str, log_file: str = SNMPTRAPD_LOG, step: int = 1) -> None:
    """Make ``systemctl start snmptrapd`` of an init machine log what it receives to *log_file*
    (the socket unit, which also binds ``[::]:162``, is masked).  The daemon is not started."""
    net_scheme.cmd(machine, "mkdir -p /etc/systemd/system/snmptrapd.service.d", step=step)
    net_scheme.file(machine, SNMPTRAPD_DROPIN, render_snmptrapd_dropin(log_file), step=step)
    net_scheme.cmd(machine, "systemctl mask snmptrapd.socket >/dev/null 2>&1; systemctl daemon-reload", step=step)


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


def snmp_get(grade: Grade0, machine: str, host: str, oids, step: int = 1, test_timeout: int = 20, **kwargs) -> SnmpResult:
    """``snmpget`` run on *machine* toward *host* (keywords of :func:`snmpget_cmd`)."""
    out, code = grade.test(machine, snmpget_cmd(host, oids, **kwargs), step=step, timeout=test_timeout,
                           allow_error=True)
    return snmp_result(out, code)


def snmp_walk(grade: Grade0, machine: str, host: str, base, step: int = 1, test_timeout: int = 20, **kwargs) -> SnmpResult:
    """``snmpwalk`` run on *machine* toward *host* (keywords of :func:`snmpwalk_cmd`)."""
    out, code = grade.test(machine, snmpwalk_cmd(host, base, **kwargs), step=step, timeout=test_timeout,
                           allow_error=True)
    return snmp_result(out, code)


def snmp_set(grade: Grade0, machine: str, host: str, oid, type_char: str, value, step: int = 1,
             test_timeout: int = 20, **kwargs) -> SnmpResult:
    """``snmpset`` run on *machine* toward *host* (keywords of :func:`snmpset_cmd`)."""
    out, code = grade.test(machine, snmpset_cmd(host, oid, type_char, value, **kwargs), step=step,
                           timeout=test_timeout, allow_error=True)
    return snmp_result(out, code)


def get_snmpd_conf(grade: Grade0, machine: str, step: int = 1) -> List[Tuple[str, List[str]]]:
    """Active lines of the agent's configuration files of *machine*, parsed (``[]`` until the
    command has run)."""
    out, _ = grade.test(machine, snmpd_conf_dump_cmd(), step=step, allow_error=True)
    if not _RC_RE.search(out or ""):
        return []
    return parse_snmpd_conf(_RC_RE.sub("", out))


def get_interface_rate(grade: Grade0, machine: str, dev: str, direction: str = "tx", seconds: int = 5,
                       step: int = 1) -> Optional[dict]:
    """Bit rate through *dev* of *machine* measured on its kernel counters during *seconds*
    (see :func:`parse_rate_sample`)."""
    out, _ = grade.test(machine, rate_sample_cmd(dev, direction, seconds), step=step, timeout=seconds + 15,
                        allow_error=True)
    return parse_rate_sample(out)
