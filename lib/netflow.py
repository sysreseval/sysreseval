"""Flow metrology lab helpers (lab/sre/_DRAFT_misc/netflow.py): softflowd 1.1.0 and nfdump 1.7.1 of
Debian 12 in the ``sysreseval/monitoring`` image; fixtures captured live in tests/mock_data/netflow/.

Grade side: the command lines of the running daemons (:func:`parse_softflowd_cmdline`,
:func:`parse_nfcapd_cmdline`), ``softflowctl`` (:func:`parse_softflowctl`), the flow files and the
flows read by ``nfdump`` with a fixed output format (:func:`parse_flow_files`,
:func:`parse_nfdump_rows`), ``nfexpire -l`` (:func:`parse_nfexpire`) and one export datagram
captured on the collector (:func:`parse_tcpdump_hex`, :func:`netflow_header`).  Every freshness
check compares times printed by the same container (``===NOW`` next to the flow times), never the
grader's clock.  State side: :func:`render_softflowd_conf`, :func:`render_nfcapd_conf`.

Facts (verified live on 2026-11-12, images 1.32):

- ``softflowd@default`` (``/etc/softflowd/default.conf``: ``interface=''``, ``options=''``) starts
  under systemd in a privileged container, drops to ``nobody``, control socket
  ``/run/softflowd/default.ctl``; ``Restart=always``;
- ``nfdump@default`` (``/etc/nfdump/default.conf``: ``options='-l /var/cache/nfdump -p 2055'``)
  takes ``-w`` (``-l`` is no longer in ``nfcapd -h``), ``-t``, ``-I``, ``-e`` (a launcher process
  with the same command line expires the directory at each cycle); a file
  ``nfcapd.YYYYmmddHHMM`` is written every interval, even without flows; ``nfexpire -u DIR -t 12H``
  then ``nfexpire -l DIR`` prints ``Max Life:  43200 = 12.0 hours``;
- softflowd's NetFlow v9 data FlowSet for IPv4 is id 1024; the export to nfcapd works at once; a
  UDP burst of N datagrams of P bytes is one flow of N packets and N × (P + 28) bytes; a TCP
  connection attempt answered by RST is one 1-packet flow each way; a long flow is cut every
  ``maxlife``; the measured rate of a TCP stream of R kbit/s of payload is about 1.05 R (headers);
- ``nfdump -q -N -o 'fmt:%tsr|%ter|%pr|%sa|%sp|%da|%dp|%pkt|%byt|%ra'`` prints epoch times with
  milliseconds, the protocol number padded, the exporter address; ``%ter`` may be a fraction of
  a second before ``%tsr`` for a short flow;
- the first exports leave the router only once flows expire (inactive timeout + expiry interval):
  a capture started with the traffic may see nothing for 25 s.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0

SOFTFLOWD_CONF = "/etc/softflowd/default.conf"
NFCAPD_CONF = "/etc/nfdump/default.conf"
FLOW_DIR = "/var/cache/nfdump"
SOFTFLOWD_CTL = "/run/softflowd/default.ctl"
SOFTFLOWD_V9_IPV4_TEMPLATE = 1024
INACTIVE_TIMEOUTS = ("general", "tcp", "tcp.rst", "tcp.fin", "udp", "icmp")
NFDUMP_FMT = "fmt:%tsr|%ter|%pr|%sa|%sp|%da|%dp|%pkt|%byt|%ra"
END = "===END"
UDP_IP_OVERHEAD, ETHERNET_OVERHEAD = 28, 42


def _section(text: Optional[str]) -> str:
    """The text before ``===END`` (empty when the marker is absent: the command did not run)."""
    body = text or ""
    return body.split(END, 1)[0] if END in body else ""


def ran(text: Optional[str]) -> bool:
    return END in (text or "")


# ---------------------------------------------------------------------------
# daemons
# ---------------------------------------------------------------------------


def parse_cmdlines(text: Optional[str]) -> List[List[str]]:
    return [line.split() for line in _section(text).splitlines() if line.strip()]


def _duration(value: str) -> Optional[int]:
    m = re.fullmatch(r"(\d+)([smhd]?)", value.strip())
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)] if m else None


def parse_softflowd_cmdline(text: Optional[str]) -> List[dict]:
    """Per softflowd process: ``interface``, ``destinations`` (``-n``), ``version``, ``timeouts``
    (``-t name=value``), ``sampling``, ``control``."""
    found = []
    for argv in parse_cmdlines(text):
        if not argv or not argv[0].endswith("softflowd"):
            continue
        entry = {"interface": None, "destinations": [], "version": None, "timeouts": {}, "sampling": None,
                 "control": None}
        i = 1
        while i < len(argv):
            flag, value = argv[i], argv[i + 1] if i + 1 < len(argv) else ""
            if flag in ("-i", "-n", "-v", "-t", "-s", "-c", "-p", "-T", "-m", "-P", "-L", "-A"):
                if flag == "-i":
                    entry["interface"] = value
                elif flag == "-n":
                    entry["destinations"].append(value)
                elif flag == "-v":
                    entry["version"] = value
                elif flag == "-t" and "=" in value:
                    name, _, raw = value.partition("=")
                    entry["timeouts"][name] = _duration(raw)
                elif flag == "-s":
                    entry["sampling"] = value
                elif flag == "-c":
                    entry["control"] = value
                i += 2
            else:
                i += 1
        found.append(entry)
    return found


SOFTFLOWCTL_TIMEOUTS = {"TCP timeout": "tcp", "TCP post-RST timeout": "tcp.rst", "TCP post-FIN timeout": "tcp.fin",
                        "UDP timeout": "udp", "ICMP timeout": "icmp", "General timeout": "general",
                        "Maximum lifetime": "maxlife", "Expiry interval": "expint"}


def parse_softflowctl(text: Optional[str]) -> Tuple[Dict[str, int], Dict[str, int]]:
    """``(timeouts, statistics)`` of ``softflowctl timeouts`` then ``statistics`` (separated by
    ``===STATS``): timeouts in seconds by softflowd's names; statistics ``active_flows``,
    ``packets_processed``, ``flows_expired``, ``flows_exported``, ``export_packets``,
    ``export_failures``."""
    body = _section(text)
    head, _, tail = body.partition("===STATS")
    timeouts = {}
    for label, name in SOFTFLOWCTL_TIMEOUTS.items():
        m = re.search(rf"^\s*{re.escape(label)}:\s*(\d+)s", head, re.M)
        if m:
            timeouts[name] = int(m.group(1))
    stats = {}
    for key, pattern in (("active_flows", r"Number of active flows:\s*(\d+)"),
                         ("packets_processed", r"Packets processed:\s*(\d+)"),
                         ("flows_expired", r"Flows expired:\s*(\d+)")):
        m = re.search(pattern, tail)
        if m:
            stats[key] = int(m.group(1))
    m = re.search(r"Flows exported:\s*(\d+)\s*\((\d+) records\) in (\d+) packets \((\d+) failures\)", tail)
    if m:
        stats.update(flows_exported=int(m.group(1)), export_records=int(m.group(2)), export_packets=int(m.group(3)),
                     export_failures=int(m.group(4)))
    return timeouts, stats


def parse_nfcapd_cmdline(text: Optional[str]) -> List[dict]:
    """Per nfcapd process: ``port``, ``flowdir`` (``-w`` or the old ``-l``), ``interval``,
    ``ident``, ``expire``, ``subdir``."""
    found = []
    for argv in parse_cmdlines(text):
        if not argv or not argv[0].endswith("nfcapd"):
            continue
        entry = {"port": None, "flowdir": None, "interval": None, "ident": None, "expire": False, "subdir": None}
        i = 1
        while i < len(argv):
            flag = argv[i]
            value = argv[i + 1] if i + 1 < len(argv) else ""
            if flag == "-e":
                entry["expire"] = True
                i += 1
                continue
            if flag in ("-p", "-w", "-l", "-t", "-I", "-S", "-P", "-b", "-u", "-g", "-B", "-n", "-M", "-z"):
                if flag == "-p" and value.isdigit():
                    entry["port"] = int(value)
                elif flag in ("-w", "-l"):
                    entry["flowdir"] = value.rstrip("/") or "/"
                elif flag == "-t" and value.isdigit():
                    entry["interval"] = int(value)
                elif flag == "-I":
                    entry["ident"] = value
                elif flag == "-S":
                    entry["subdir"] = value
                i += 2
            else:
                i += 1
        found.append(entry)
    return found


def parse_udp_listeners(text: Optional[str]) -> List[Tuple[int, str]]:
    """``(port, process)`` of ``ss -H -ulnp`` lines."""
    found = []
    for line in _section(text).splitlines():
        words = line.split()
        if len(words) >= 4 and ":" in words[3]:
            port = words[3].rsplit(":", 1)[1]
            process = re.search(r'\(\("([^"]+)"', line)
            if port.isdigit():
                found.append((int(port), process.group(1) if process else ""))
    return found


def parse_nfexpire(text: Optional[str]) -> dict:
    body = _section(text)
    result = {}
    m = re.search(r"^Max Life:\s*(\d+)", body, re.M)
    if m:
        result["max_life"] = int(m.group(1))
    m = re.search(r"^Max Size:\s*(\d+)", body, re.M)
    if m:
        result["max_size"] = int(m.group(1))
    m = re.search(r"^Numfiles:\s*(\d+)", body, re.M)
    if m:
        result["numfiles"] = int(m.group(1))
    return result


# ---------------------------------------------------------------------------
# flow files and flows
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowFile:
    mtime: float
    size: int
    path: str


@dataclass(frozen=True)
class FlowRow:
    first: float
    last: float
    proto: int
    src: str
    sport: int
    dst: str
    dport: int
    packets: int
    bytes: int
    exporter: str
    file: str = ""

    @property
    def seen(self) -> float:
        """The latest time of the flow (``%ter`` may be a little before ``%tsr``)."""
        return max(self.first, self.last)


def parse_now(text: Optional[str]) -> Optional[int]:
    m = re.search(r"^===NOW (\d+)", text or "", re.M)
    return int(m.group(1)) if m else None


def parse_flow_files(text: Optional[str]) -> Tuple[Optional[int], List[FlowFile]]:
    """``find ... -printf '%T@ %s %p'`` after ``===NOW``: the rotated files (``nfcapd.<date>``)."""
    files = []
    for line in _section(text).splitlines():
        words = line.split()
        if len(words) == 3 and re.search(r"/nfcapd\.\d{12}$", words[2]):
            try:
                files.append(FlowFile(float(words[0]), int(words[1]), words[2]))
            except ValueError:
                continue
    return parse_now(text), files


def parse_nfdump_rows(text: Optional[str]) -> Tuple[Optional[int], List[FlowRow]]:
    """Rows of ``nfdump -q -N -o NFDUMP_FMT`` (``===FILE path`` sections)."""
    rows, current = [], ""
    for line in _section(text).splitlines():
        if line.startswith("===FILE "):
            current = line[8:].strip()
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) != 10:
            continue
        try:
            rows.append(FlowRow(float(fields[0]), float(fields[1]), int(fields[2]), fields[3], int(fields[4]),
                                fields[5], int(fields[6]), int(fields[7]), int(fields[8]), fields[9], current))
        except ValueError:
            continue
    return parse_now(text), rows


def parse_tcpdump_hex(text: Optional[str]) -> bytes:
    """The bytes of the first packet of a ``tcpdump -x`` output (the IP packet)."""
    data = bytearray()
    started = False
    for line in (text or "").splitlines():
        m = re.match(r"\s+0x([0-9a-f]{4}):\s+((?:[0-9a-f]{2,4}\s?)+)", line)
        if m:
            if int(m.group(1), 16) == 0 and started:
                break
            started = True
            data += bytes.fromhex(m.group(2).replace(" ", ""))
        elif started and not line.startswith((" ", "\t")):
            break
    return bytes(data)


def netflow_header(packet: bytes) -> Optional[dict]:
    """``{"version", "count", "flowset_ids"}`` of the NetFlow datagram carried by an IPv4/UDP
    *packet*; None when it is not one."""
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != 17:
        return None
    payload = packet[(packet[0] & 0x0F) * 4 + 8:]
    if len(payload) < 4:
        return None
    version, count = int.from_bytes(payload[0:2], "big"), int.from_bytes(payload[2:4], "big")
    ids = []
    if version == 9:
        offset = 20
        while offset + 4 <= len(payload):
            flowset_id = int.from_bytes(payload[offset:offset + 2], "big")
            length = int.from_bytes(payload[offset + 2:offset + 4], "big")
            ids.append(flowset_id)
            if length < 4:
                break
            offset += length
    return {"version": version, "count": count, "flowset_ids": ids}


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _cmdline_cmd(program: str) -> str:
    return f"for p in $(pidof {program}); do tr '\\0' ' ' < /proc/$p/cmdline; echo; done; echo \"{END}\""


def softflowd_cmdline_cmd() -> str:
    return _cmdline_cmd("softflowd")


def nfcapd_cmdline_cmd() -> str:
    return _cmdline_cmd("nfcapd")


def softflowctl_cmd(control: str = SOFTFLOWD_CTL) -> str:
    c = shlex.quote(control)
    return f"softflowctl -c {c} timeouts 2>&1; echo \"===STATS\"; softflowctl -c {c} statistics 2>&1; echo \"{END}\""


def udp_listeners_cmd() -> str:
    return f'ss -H -ulnp 2>&1; echo "{END}"'


def nfexpire_list_cmd(flowdir: str = FLOW_DIR) -> str:
    return f'nfexpire -l {shlex.quote(flowdir)} 2>&1; echo "{END}"'


def flow_files_cmd(flowdir: str = FLOW_DIR, last: int = 6) -> str:
    return (f"echo \"===NOW $(date +%s)\"; find {shlex.quote(flowdir)} -type f -name 'nfcapd.[0-9]*'"
            f" -printf '%T@ %s %p\\n' 2>/dev/null | sort -n | tail -n {int(last)}; echo \"{END}\"")


def nfdump_rows_cmd(flt: str, flowdir: str = FLOW_DIR, minutes: int = 10, last: int = 8) -> str:
    """The flows matching *flt* in the rotated files of the last *minutes* minutes."""
    return (f"echo \"===NOW $(date +%s)\"; for f in $(find {shlex.quote(flowdir)} -type f -name 'nfcapd.[0-9]*'"
            f" -mmin -{int(minutes)} 2>/dev/null | sort | tail -n {int(last)}); do echo \"===FILE $f\";"
            f" nfdump -r \"$f\" -q -N -o {shlex.quote(NFDUMP_FMT)} {shlex.quote(flt)} 2>&1 | head -n 40; done;"
            f" echo \"{END}\"")


def export_capture_cmd(interface: str, exporter_ip: str, port: int, seconds: int = 25) -> str:
    """One export datagram from the exporter, in hexadecimal (``tcpdump -x``)."""
    bpf = f"udp and src host {exporter_ip} and dst port {int(port)}"
    return (f"timeout {int(seconds)} tcpdump -ni {shlex.quote(interface)} --immediate-mode -c 1 -x -s 400"
            f" {shlex.quote(bpf)} 2>/dev/null; echo \"{END}\"")


def wait_for_flow_cmd(flt: str, flowdir: str = FLOW_DIR, tries: int = 60, pause: int = 3,
                      newer: Optional[str] = None) -> str:
    """Wait until a rotated file (newer than the file *newer*, when given) holds a flow matching
    *flt* (the reference solution); ``nfdump`` prints "No matching flows" for an empty file, so only
    a number counts."""
    newer_test = f" -newer {shlex.quote(newer)}" if newer else ""
    return (f"i=0; while [ $i -lt {int(tries)} ]; do for f in $(find {shlex.quote(flowdir)} -type f"
            f" -name 'nfcapd.[0-9]*'{newer_test} 2>/dev/null | sort | tail -n 3); do nfdump -r \"$f\" -q -o 'fmt:%pkt' {shlex.quote(flt)}"
            f" 2>/dev/null; done | grep -qE '^[[:space:]]*[0-9]+[[:space:]]*$' && break; sleep {int(pause)}; i=$((i+1)); done; true")


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def softflowd_options(collector: str, port: int, version: int = 9, timeouts: Optional[Dict[str, int]] = None,
                      sampling: Optional[int] = None) -> str:
    words = [f"-n {collector}:{int(port)}", f"-v {int(version)}"]
    words += [f"-t {name}={int(value)}" for name, value in (timeouts or {}).items()]
    if sampling:
        words.append(f"-s {int(sampling)}")
    return " ".join(words)


def render_softflowd_conf(interface: str, collector: str, port: int, version: int = 9,
                          timeouts: Optional[Dict[str, int]] = None) -> str:
    return f"interface='{interface}'\noptions='{softflowd_options(collector, port, version, timeouts)}'\n"


def render_nfcapd_conf(port: int, flowdir: str = FLOW_DIR, interval: int = 60, ident: Optional[str] = None,
                       expire: bool = True) -> str:
    words = [f"-w {flowdir}", f"-p {int(port)}", f"-t {int(interval)}"]
    if ident:
        words.append(f"-I {ident}")
    if expire:
        words.append("-e")
    return f"options='{' '.join(words)}'\n"


# ---------------------------------------------------------------------------
# wrappers
# ---------------------------------------------------------------------------


def get_softflowd(grade: Grade0, machine: str, step: int = 1) -> List[dict]:
    out, _ = grade.test(machine, softflowd_cmdline_cmd(), step=step, allow_error=True)
    return parse_softflowd_cmdline(out)


def get_softflowctl(grade: Grade0, machine: str, step: int = 1) -> Tuple[Dict[str, int], Dict[str, int]]:
    out, _ = grade.test(machine, softflowctl_cmd(), step=step, allow_error=True)
    return parse_softflowctl(out)


def get_nfcapd(grade: Grade0, machine: str, step: int = 1) -> List[dict]:
    out, _ = grade.test(machine, nfcapd_cmdline_cmd(), step=step, allow_error=True)
    return parse_nfcapd_cmdline(out)


def get_udp_listeners(grade: Grade0, machine: str, step: int = 1) -> List[Tuple[int, str]]:
    out, _ = grade.test(machine, udp_listeners_cmd(), step=step, allow_error=True)
    return parse_udp_listeners(out)


def get_nfexpire(grade: Grade0, machine: str, flowdir: str = FLOW_DIR, step: int = 1) -> dict:
    out, _ = grade.test(machine, nfexpire_list_cmd(flowdir), step=step, allow_error=True)
    return parse_nfexpire(out)


def get_flow_files(grade: Grade0, machine: str, flowdir: str = FLOW_DIR, step: int = 1):
    out, _ = grade.test(machine, flow_files_cmd(flowdir), step=step, allow_error=True)
    return parse_flow_files(out)


def get_flows(grade: Grade0, machine: str, flt: str, flowdir: str = FLOW_DIR, step: int = 1):
    out, _ = grade.test(machine, nfdump_rows_cmd(flt, flowdir), step=step, timeout=40, allow_error=True)
    return parse_nfdump_rows(out)


def get_export_header(grade: Grade0, machine: str, interface: str, exporter_ip: str, port: int,
                      step: int = 1) -> Optional[dict]:
    out, _ = grade.test(machine, export_capture_cmd(interface, exporter_ip, port), step=step, timeout=40,
                        allow_error=True)
    return netflow_header(parse_tcpdump_hex(out))
