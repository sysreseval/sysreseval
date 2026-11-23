"""NTP / chrony helpers of the NTP lab (``lab/sre/_DRAFT_misc/ntp.py``).

The machines run the image ``sysreseval/ntp`` (``images/ntp/Dockerfile``): Debian 13's chrony 4.6,
``chronyd -x`` (the clock of a container is the clock of the Docker host and cannot be changed
without ``CAP_SYS_TIME``: chronyd measures, selects and serves time without touching it), its
messages in ``/var/log/chrony/chronyd.log``, ``systemctl`` / ``service chrony`` usable.

State side::

    install_ntp_probe(net_scheme, 'probe')                 # lib/ntp_probe.py into the machine
    start_fake_servers(net_scheme, 'internet', personas)   # wrong clocks on demand (ntp_probe serve)
    net_scheme.file(m, CHRONY_CONF, base_chrony_conf())     # Debian's file without its pool line

Grade side::

    snap = get_chrony_snapshot(grade, 'pc1')               # pidof + chronyc -c -n ... + chronyd -p
    snap.synced_to('10.1.2.3'); snap.source('10.1.2.4').state; snap.auth('10.1.2.3').mode
    results = ntp_probe_check(grade, 'probe', [query_spec('q', '10.1.2.3', source='10.9.9.9'),
                                               chrony_spec('k', ['server 10.1.2.3 iburst key 7', ...])])

The ``chronyc -c`` formats were captured on s17 (chrony 4.6.1, 2026-11-23): ``tests/mock_data/ntp/``.
"""
import json
import re
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from SRE.lib_sre import Grade0, NetScheme0

CHRONY_CONF = "/etc/chrony/chrony.conf"
CHRONY_CONF_DIR = "/etc/chrony/conf.d"
CHRONY_SOURCES_DIR = "/etc/chrony/sources.d"
CHRONY_KEYS = "/etc/chrony/chrony.keys"
CHRONY_DEFAULTS = "/etc/default/chrony"
CHRONY_LOG = "/var/log/chrony/chronyd.log"
DAEMON_OPTS = "-F 1 -x -l /var/log/chrony/chronyd.log"
CHRONY_USER = "_chrony"
NTS_DIR = "/etc/chrony/nts"
DRIFT_FILE = "/var/lib/chrony/chrony.drift"
# Frequency error 0 ppm, uncertainty 1 ppm: the clock of a container is the clock of the host,
# disciplined by the host's own daemon.  Without it, a chronyd starting for the first time knows
# its frequency to +/- 1000000 ppm: once synchronised, it announces a root dispersion growing by
# one second per second until its next update (about 64 s later), and its clients reject it as
# too far (seen live on s17: NTS and keyed requests to a fresh server failed for a minute).
DRIFT_SEED = "0.000000 1.000000\n"
NTP_PROBE_PATH = "/usr/local/sbin/sre_ntp_probe.py"
FAKE_PID_FILE = "/run/sre_ntp_fake.pid"
NTS_KE_PORT = 4460
NOT_SYNCHRONISED = "Not synchronised"
LOCAL_REFID = "7F7F0101"  # 127.127.1.1: the reference of chronyd's `local` directive
_SEP = "==SRE-NTP=="  # never "@@@": the separator of the commands of exetests.py
_SECTIONS = ("pid", "tracking", "sources", "authdata", "config")


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def base_chrony_conf(comment: str = "") -> str:
    """Debian's /etc/chrony/chrony.conf without its ``pool`` line (no Internet in a lab)."""
    head = "".join(f"# {line}\n" for line in comment.splitlines()) if comment else ""
    return head + (
        "confdir /etc/chrony/conf.d\n"
        "sourcedir /run/chrony-dhcp\n"
        "sourcedir /etc/chrony/sources.d\n"
        "keyfile /etc/chrony/chrony.keys\n"
        "driftfile /var/lib/chrony/chrony.drift\n"
        "ntsdumpdir /var/lib/chrony\n"
        "logdir /var/log/chrony\n"
        "maxupdateskew 100.0\n"
        "rtcsync\n"
        "makestep 1 3\n"
        "leapseclist /usr/share/zoneinfo/leap-seconds.list\n")


def daemon_defaults(opts: str = DAEMON_OPTS) -> str:
    """/etc/default/chrony with *opts* (the image's file: -x and the log file)."""
    return ("# Options of chronyd (read by /etc/init.d/chrony and the chrony unit).\n"
            "# -x: no control of the clock (the clock of a container is the clock of the host)\n"
            "# -l: the messages of chronyd in this file (no syslog daemon in the container)\n"
            f'DAEMON_OPTS="{opts}"\n')


def chrony_restart_cmd() -> str:
    return "systemctl restart chrony >/dev/null 2>&1 || service chrony restart >/dev/null 2>&1; true"


def install_ntp_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    script = Path(__file__).with_name("ntp_probe.py").read_text()
    net_scheme.file(machine, NTP_PROBE_PATH, script, permissions=0o755, step=step)


def fake_server_cmd(personas: Sequence[dict]) -> str:
    """The command (re)starting the fake NTP server of ``ntp_probe.py serve`` with *personas*."""
    config = shlex.quote(json.dumps(list(personas), sort_keys=True))
    return (f"[ -f {FAKE_PID_FILE} ] && kill $(cat {FAKE_PID_FILE}) 2>/dev/null; "
            f"nohup setsid python3 {NTP_PROBE_PATH} serve {config} >/dev/null 2>&1 < /dev/null & "
            f"echo $! > {FAKE_PID_FILE}")


def start_fake_servers(net_scheme: NetScheme0, machine: str, personas: Sequence[dict], step: int = 1) -> None:
    install_ntp_probe(net_scheme, machine, step=step)
    net_scheme.cmd(machine, fake_server_cmd(personas), step=step)


def persona(address, *, offset: float = 0.0, stratum: int = 1, refid: str = "GPS", leap: int = 0,
            precision: int = -20, root_delay: float = 0.0, root_dispersion: float = 0.0005) -> dict:
    """One personality of the fake server (see ``ntp_probe.py``)."""
    return {"address": str(getattr(address, "ip", address)), "offset": float(offset), "stratum": int(stratum),
            "refid": str(refid), "leap": int(leap), "precision": int(precision), "root_delay": float(root_delay),
            "root_dispersion": float(root_dispersion)}


# ---------------------------------------------------------------------------
# chronyc parsers
# ---------------------------------------------------------------------------


def _float(text, default=None):
    try:
        return float(text)
    except (TypeError, ValueError):
        return default


def _int(text, default=None, base=10):
    try:
        return int(str(text), base)
    except (TypeError, ValueError):
        return default


@dataclass
class Tracking:
    refid: str            # hex, 00000000 when not synchronised, 7F7F0101 for `local`
    address: str          # the selected source ('' for none or for `local`)
    stratum: int
    leap: str             # Normal, Insert second, Delete second, Not synchronised
    root_delay: float = 0.0
    root_dispersion: float = 0.0

    @property
    def synced(self) -> bool:
        return self.leap != NOT_SYNCHRONISED and self.refid not in ("", "00000000")


@dataclass
class Source:
    mode: str             # ^ server, = peer, # reference clock
    state: str            # * selected, + combined, - not combined, x falseticker, ~ too variable, ? unusable
    address: str
    stratum: int
    poll: int
    reach: int            # the reachability register (8 bits)
    offset: float = 0.0   # adjusted offset of the local clock relative to the source (s)


@dataclass
class AuthData:
    address: str
    mode: str             # NTS, SK, or - (none)
    keyid: int
    key_type: int
    key_length: int
    naks: int = 0
    cookies: int = 0


def parse_tracking(text: str) -> Optional[Tracking]:
    """``chronyc -c -n tracking`` → Tracking (None when chronyd does not answer)."""
    for line in (text or "").splitlines():
        f = line.strip().split(",")
        if len(f) >= 14 and re.fullmatch(r"[0-9A-Fa-f]{8}", f[0]):
            return Tracking(refid=f[0].upper(), address=f[1], stratum=_int(f[2], 0), leap=f[13],
                            root_delay=_float(f[10], 0.0), root_dispersion=_float(f[11], 0.0))
    return None


def parse_sources(text: str) -> List[Source]:
    """``chronyc -c -n sources`` → [Source] (the reach register is printed in octal)."""
    sources = []
    for line in (text or "").splitlines():
        f = line.strip().split(",")
        if len(f) >= 10 and len(f[0]) == 1 and len(f[1]) == 1:
            sources.append(Source(mode=f[0], state=f[1], address=f[2], stratum=_int(f[3], 0), poll=_int(f[4], 0),
                                  reach=_int(f[5], 0, base=8), offset=_float(f[7], 0.0)))
    return sources


def parse_authdata(text: str) -> List[AuthData]:
    """``chronyc -c -n authdata`` → [AuthData]."""
    rows = []
    for line in (text or "").splitlines():
        f = line.strip().split(",")
        if len(f) >= 10 and f[1] in ("NTS", "SK", "-"):
            rows.append(AuthData(address=f[0], mode=f[1], keyid=_int(f[2], 0), key_type=_int(f[3], 0),
                                 key_length=_int(f[4], 0), naks=_int(f[7], 0), cookies=_int(f[8], 0)))
    return rows


def parse_config(text: str) -> List[List[str]]:
    """``chronyd -p`` (the configuration once the included files are read) → [[directive, args...]]."""
    lines = []
    for line in (text or "").splitlines():
        words = line.split()
        if words and not words[0].startswith(("#", "!", ";", "%")) and re.fullmatch(r"[a-z][a-z0-9]*", words[0]):
            lines.append(words)
    return lines


@dataclass
class ChronySnapshot:
    running: bool = False
    tracking: Optional[Tracking] = None
    sources: List[Source] = field(default_factory=list)
    authdata: List[AuthData] = field(default_factory=list)
    config: List[List[str]] = field(default_factory=list)

    def source(self, address) -> Optional[Source]:
        address = str(getattr(address, "ip", address))
        return next((s for s in self.sources if s.address == address), None)

    def selected(self) -> Optional[Source]:
        return next((s for s in self.sources if s.state == "*"), None)

    def auth(self, address) -> Optional[AuthData]:
        address = str(getattr(address, "ip", address))
        return next((a for a in self.authdata if a.address == address), None)

    def synced_to(self, address) -> bool:
        """chronyd runs and is synchronised to *address* (the selected source of tracking)."""
        address = str(getattr(address, "ip", address))
        t = self.tracking
        return self.running and t is not None and t.synced and t.address == address

    def directives(self, name: str) -> List[List[str]]:
        return [words for words in self.config if words[0] == name]


def snapshot_cmd(config: bool = True) -> str:
    """One command giving everything a ChronySnapshot holds (chronyc answers fast when chronyd
    does not run: 506 Cannot talk to daemon)."""
    parts = [f"echo {_SEP}pid; pidof chronyd",
             f"echo {_SEP}tracking; chronyc -c -n tracking 2>&1",
             f"echo {_SEP}sources; chronyc -c -n sources 2>&1",
             f"echo {_SEP}authdata; chronyc -c -n authdata 2>&1"]
    if config:
        parts.append(f"echo {_SEP}config; chronyd -p 2>&1")
    return "; ".join(parts) + "; true"


def parse_snapshot(text: str) -> ChronySnapshot:
    sections: Dict[str, str] = {}
    for chunk in (text or "").split(_SEP)[1:]:
        name, _, body = chunk.partition("\n")
        if name.strip() in _SECTIONS:
            sections[name.strip()] = body
    return ChronySnapshot(running=bool(sections.get("pid", "").split()),
                          tracking=parse_tracking(sections.get("tracking", "")),
                          sources=parse_sources(sections.get("sources", "")),
                          authdata=parse_authdata(sections.get("authdata", "")),
                          config=parse_config(sections.get("config", "")))


def get_chrony_snapshot(grade: Grade0, machine: str, step: int = 1, config: bool = True) -> ChronySnapshot:
    out, _ = grade.test(machine, snapshot_cmd(config), step=step, timeout=30, allow_error=True)
    return parse_snapshot(out)


# ---------------------------------------------------------------------------
# the probe (ntp_probe.py check)
# ---------------------------------------------------------------------------


def _addr(value) -> Optional[str]:
    return None if value is None else str(getattr(value, "ip", value))


def query_spec(ident: str, server, source=None, timeout: float = 2.0) -> dict:
    spec = {"id": ident, "kind": "query", "server": _addr(server), "timeout": timeout}
    if source is not None:
        spec["source"] = _addr(source)
    return spec


def burst_spec(ident: str, server, source=None, count: int = 30, interval: float = 0.05) -> dict:
    spec = {"id": ident, "kind": "burst", "server": _addr(server), "count": count, "interval": interval}
    if source is not None:
        spec["source"] = _addr(source)
    return spec


def chrony_spec(ident: str, directives: Sequence[str], timeout: int = 12) -> dict:
    """``chronyd -Q`` with *directives* as its whole configuration (``bindacqaddress`` picks the
    source address)."""
    return {"id": ident, "kind": "chrony", "directives": list(directives), "timeout": timeout}


def ntp_probe_check_cmd(spec: Sequence[dict]) -> str:
    return f"python3 {NTP_PROBE_PATH} check {shlex.quote(json.dumps(list(spec), sort_keys=True))}"


def parse_probe_check(text: str) -> Dict[str, dict]:
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if isinstance(data, dict):
                return data
    return {}


def ntp_probe_check(grade: Grade0, machine: str, spec: Sequence[dict], step: int = 1,
                    timeout: int = 60) -> Dict[str, dict]:
    """The results of the probes of *spec*, run concurrently on *machine* ({} until they have run)."""
    out, _ = grade.test(machine, ntp_probe_check_cmd(spec), step=step, timeout=timeout, allow_error=True)
    return parse_probe_check(out)


def answered(result: Optional[dict], synchronised: Optional[bool] = None) -> bool:
    """A query result answered (and, if asked, with the leap indicator of a synchronised server)."""
    if not result or not result.get("answered"):
        return False
    if synchronised is None:
        return True
    return (result.get("leap") != 3) == synchronised


# ---------------------------------------------------------------------------
# reference configuration
# ---------------------------------------------------------------------------


def server_line(host, *options: str) -> str:
    return " ".join(["server", str(getattr(host, "ip", host)), *[o for o in options if o]])


def refid_of(address) -> str:
    """The reference identifier (hex) a server synchronised to *address* announces."""
    return f"{int(IPv4Address(str(getattr(address, 'ip', address)))):08X}"


def key_line(keyid: int, secret_hex: str, hash_name: str = "SHA256") -> str:
    return f"{int(keyid)} {hash_name} HEX:{secret_hex.upper()}"
