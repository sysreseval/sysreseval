"""Zeek helpers for the labs (the image ``nsm13``: Zeek 9.0 LTS under ``/opt/zeek``; the lab
``lab/sre/_DRAFT_misc/nsm-forensics.py``).

State side:

- :func:`render_node_cfg`, :func:`render_networks_cfg`: the two zeekctl files of a standalone sensor;
- :func:`render_intel_file`: an Intel framework file (the header line, then one indicator per line,
  tab-separated: the format the input framework reads).

Grade side:

- :func:`get_processes` lists the running ``zeek`` command lines (``pgrep -a -x zeek``) and
  :func:`capture_interface` reads the interface of one (``-i eth1``, ``-i af_packet::eth1``);
- :func:`zeek_log_cmd` prints the lines of a live log that contain given strings, after the
  ``#fields`` line of a TSV log; :func:`parse_zeek_log` reads them back as dicts, JSON or TSV alike
  (the keys are Zeek's flat names: ``id.orig_h``, ``local_resp``...), :func:`entries_since` keeps
  those of the current evaluation (``ts`` after the ``t0`` read at step 1 with
  ``suricata.get_epoch``) and :func:`zeek_bool` reads a boolean of either format;
- :func:`offline_zeek` writes a fresh capture in the machine (``lib/suricata_pcap.py``, installed by
  ``suricata.install_pcap_tool``, from a spec built by the lab), runs ``zeek -C -r`` on it with the
  scripts given and ``LogAscii::use_json=T``, in a working directory of its own, and returns the
  entries of the logs asked for (``notice``, ``intel``...) and the errors of the run;
  ``pseudo_realtime=True`` replays the capture at its own pace (``--pseudo-realtime=1``): the input
  framework (an Intel file) reads its file in a thread of its own, and a plain ``-r`` run is over
  before the indicators are loaded.

Facts verified in the nsm13 image (Zeek 9.0.1, 2026-11-25): ``zeek-cut`` is in zeek-9.0-core; a plain
offline run on a few dozen packets takes about 0.3 s, with the site policy (``local``) too; a table
with ``&create_expire`` expires on the network time of the capture; ``new_connection`` gives the
originator of a UDP exchange too; the Intel framework matches nothing in a plain ``-r`` run and
everything with ``--pseudo-realtime=1`` when the indicators come a few seconds into the capture
(``-E`` takes an optional argument: write the long form); ``Site::private_address_space_is_local`` is T
by default, so every address of ``Site::private_address_space`` (RFC 1918, but also 198.18.0.0/15,
the documentation ranges and the other IANA special ranges) is local whatever ``networks.cfg`` says.
"""
import json
import shlex
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0
from suricata_pcap import encode_spec

ZEEK_PREFIX = "/opt/zeek"
ZEEK_BIN = f"{ZEEK_PREFIX}/bin/zeek"
ZEEKCTL = f"{ZEEK_PREFIX}/bin/zeekctl"
NODE_CFG = f"{ZEEK_PREFIX}/etc/node.cfg"
NETWORKS_CFG = f"{ZEEK_PREFIX}/etc/networks.cfg"
SITE_DIR = f"{ZEEK_PREFIX}/share/zeek/site"
LOCAL_ZEEK = f"{SITE_DIR}/local.zeek"
CURRENT_LOGS = f"{ZEEK_PREFIX}/logs/current"
PCAP_TOOL_PATH = "/usr/local/sbin/sre_suricata_pcap.py"     # suricata.PCAP_TOOL_PATH
OFFLINE_DIR = "/tmp/sre-zeek-offline"
RC_MARK = "SRE-ZEEK-RC="
LOG_MARK = "SRE-ZEEK-LOG "
ERROR_MARK = "SRE-ZEEK-ERROR "
INTEL_FIELDS = ("indicator", "indicator_type", "meta.source", "meta.desc")


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------

def render_node_cfg(interface: str, host: str = "localhost") -> str:
    """``node.cfg`` of a standalone sensor capturing on *interface*."""
    return f"[zeek]\ntype=standalone\nhost={host}\ninterface={interface}\n"


def render_networks_cfg(networks: Iterable[Tuple[Any, str]]) -> str:
    """``networks.cfg``: one ``<network> <description>`` line per ``(network, description)``."""
    return "".join(f"{net}\t{desc}\n" for net, desc in networks)


def render_intel_file(indicators: Iterable[Sequence[str]]) -> str:
    """An Intel framework file: ``#fields`` then one line per ``(indicator, type, source, desc)``,
    every field separated by **one tab** (the input framework splits on tabs only)."""
    lines = ["#fields\t" + "\t".join(INTEL_FIELDS)]
    lines += ["\t".join(str(v) for v in row) for row in indicators]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# processes
# ---------------------------------------------------------------------------

def get_processes(grade: Grade0, machine: str, step: int = 1) -> List[str]:
    """The command lines of the running ``zeek`` processes (``pgrep -a -x zeek``, pid removed)."""
    out, _ = grade.test(machine, "pgrep -a -x zeek", step=step, allow_error=True)
    return [line.split(None, 1)[1] for line in (out or "").splitlines() if len(line.split(None, 1)) == 2]


def capture_interface(cmdline: str) -> Optional[str]:
    """The interface a Zeek command line captures on (``-i X``, ``-iX``, ``--iface X`` /
    ``--iface=X``), the packet source prefix removed (``af_packet::eth1`` → ``eth1``); None when it
    reads no interface."""
    tokens = cmdline.split()
    value = None
    for i, token in enumerate(tokens):
        if token in ("-i", "--iface") and i + 1 < len(tokens):
            value = tokens[i + 1]
            break
        if token.startswith("--iface="):
            value = token.split("=", 1)[1]
            break
        if token.startswith("-i") and len(token) > 2 and not token.startswith("--"):
            value = token[2:]
            break
    if value is None:
        return None
    return value.rsplit("::", 1)[-1]


# ---------------------------------------------------------------------------
# live logs
# ---------------------------------------------------------------------------

def zeek_log_cmd(log: str, needles: Iterable[str] = (), logdir: str = CURRENT_LOGS, lines: int = 400) -> str:
    """The shell command printing the ``#fields`` line of ``<logdir>/<log>.log`` (TSV logs) and its
    last *lines* lines containing one of *needles* (every line without needles)."""
    path = shlex.quote(f"{logdir}/{log}.log")
    needles = [n for n in needles if n]
    select = (f"grep -F {' '.join('-e ' + shlex.quote(str(n)) for n in needles)} {path} | tail -n {int(lines)}"
              if needles else f"grep -v '^#' {path} | tail -n {int(lines)}")
    return f"if [ -f {path} ]; then grep -m 1 '^#fields' {path}; {select}; fi"


def _tsv_value(value: str) -> Any:
    if value == "-":
        return None
    if value == "(empty)":
        return ""
    return value


def parse_zeek_log(text: str) -> List[Dict[str, Any]]:
    """The entries of a Zeek log extract: JSON lines, or TSV lines after a ``#fields`` line (unset
    ``-`` → None, ``(empty)`` → ''). Bad lines are skipped."""
    entries: List[Dict[str, Any]] = []
    fields: Optional[List[str]] = None
    for line in (text or "").splitlines():
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if line.lstrip().startswith("{"):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
            continue
        if fields:
            values = line.split("\t")
            if len(values) == len(fields):
                entries.append({k: _tsv_value(v) for k, v in zip(fields, values)})
    return entries


def is_json_log(text: str) -> bool:
    """True when the extract holds at least one JSON entry and no TSV header."""
    lines = [l for l in (text or "").splitlines() if l.strip()]
    return any(l.lstrip().startswith("{") for l in lines) and not any(l.startswith("#fields") for l in lines)


def zeek_bool(value: Any) -> Optional[bool]:
    """A Zeek boolean of a JSON (true / false) or TSV (T / F) entry; None when unset."""
    if isinstance(value, bool):
        return value
    if value in ("T", "true"):
        return True
    if value in ("F", "false"):
        return False
    return None


def entry_ts(entry: Dict[str, Any]) -> Optional[float]:
    try:
        return float(entry.get("ts"))
    except (TypeError, ValueError):
        return None


def entries_since(entries: List[Dict[str, Any]], t0: Optional[float], margin: float = 1.0) -> List[Dict[str, Any]]:
    """The entries whose ``ts`` is after *t0* (minus *margin* seconds); none when *t0* is unknown."""
    if t0 is None:
        return []
    return [e for e in entries if (entry_ts(e) or 0.0) >= t0 - margin]


def get_log(grade: Grade0, machine: str, log: str, needles: Iterable[str] = (), logdir: str = CURRENT_LOGS,
            step: int = 1) -> Tuple[List[Dict[str, Any]], bool]:
    """``(entries, json)`` of the lines of a live log holding one of *needles*."""
    out, _ = grade.test(machine, zeek_log_cmd(log, needles, logdir), step=step, allow_error=True)
    return parse_zeek_log(out or ""), is_json_log(out or "")


# ---------------------------------------------------------------------------
# offline runs
# ---------------------------------------------------------------------------

def offline_zeek_cmd(spec: dict, scripts: Iterable[str], name: str = "run", logs: Iterable[str] = ("notice",),
                     pseudo_realtime: bool = False, extra: Iterable[str] = ()) -> str:
    """The shell command of :func:`offline_zeek` (one working directory per *name*)."""
    work = f"{OFFLINE_DIR}/{name}"
    realtime = " --pseudo-realtime=1" if pseudo_realtime else ""
    args = " ".join(shlex.quote(s) for s in list(scripts) + list(extra))
    dump = "; ".join(f"[ -f {work}/{log}.log ] && tail -n 200 {work}/{log}.log | sed 's/^/{LOG_MARK}{log} /'"
                     for log in logs)
    return (f"rm -rf {work}; mkdir -p {work} && cd {work} && "
            f"python3 {PCAP_TOOL_PATH} {encode_spec(spec)} {work}/probe.pcap && "
            f"{ZEEK_BIN} -C{realtime} -r {work}/probe.pcap {args} LogAscii::use_json=T > {work}/stdout 2>&1; "
            f"echo {RC_MARK}$?; {dump}; "
            f"grep -h -i -E 'error|fatal' {work}/stdout {work}/reporter.log 2>/dev/null | head -n 8 "
            f"| cut -c 1-300 | sed 's/^/{ERROR_MARK}/'; cd /; rm -rf {work}")


def parse_offline_output(text: str) -> Dict[str, Any]:
    """``{'rc': int | None, 'logs': {log: [entries]}, 'errors': [str]}``."""
    result: Dict[str, Any] = {'rc': None, 'logs': {}, 'errors': []}
    for line in (text or "").splitlines():
        if line.startswith(RC_MARK):
            try:
                result['rc'] = int(line[len(RC_MARK):].strip())
            except ValueError:
                pass
        elif line.startswith(LOG_MARK):
            log, _, payload = line[len(LOG_MARK):].partition(" ")
            entries = parse_zeek_log(payload)
            if entries:
                result['logs'].setdefault(log, []).extend(entries)
        elif line.startswith(ERROR_MARK):
            result['errors'].append(line[len(ERROR_MARK):].strip())
    return result


def offline_zeek(grade: Grade0, machine: str, spec: dict, scripts: Iterable[str], name: str = "run",
                 logs: Iterable[str] = ("notice",), pseudo_realtime: bool = False, extra: Iterable[str] = (),
                 step: int = 1, timeout: int = 60) -> Dict[str, Any]:
    """Run Zeek offline on *machine* on a fresh capture of *spec* (see :func:`parse_offline_output`)."""
    out, _ = grade.test(machine, offline_zeek_cmd(spec, scripts, name, logs, pseudo_realtime, extra),
                        step=step, timeout=timeout, allow_error=True)
    return parse_offline_output(out or "")


def notices(entries: List[Dict[str, Any]], note: str) -> List[Dict[str, Any]]:
    """The ``notice.log`` entries of the notice type *note* (``SRE::Web_Scan``)."""
    return [e for e in entries if e.get("note") == note]


def intel_hits(entries: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """``{indicator: [where, ...]}`` of ``intel.log`` entries."""
    hits: Dict[str, List[str]] = {}
    for e in entries:
        indicator = e.get("seen.indicator")
        if indicator:
            hits.setdefault(str(indicator), []).append(str(e.get("seen.where") or ""))
    return hits
