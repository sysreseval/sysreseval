"""Suricata helpers for the labs (the Suricata / fail2ban lab ``lab/sre/_DRAFT_misc/suricata-fail2ban.py``).

State side:

- :func:`install_pcap_tool` copies ``lib/suricata_pcap.py`` (stdlib capture generator) into a machine,
  :func:`write_pcap` runs it there to leave a capture for the students (``suricata -r``);
- :func:`save_offline_config` keeps a copy of the configuration as installed, so that the grader
  can run Suricata offline with a configuration the students never edit;
- :func:`render_minimal_yaml` writes a short, complete ``suricata.yaml`` (a reference sensor started
  by a lab, alerts only in ``eve.json``).

Grade side:

- :func:`offline_alerts` generates a capture in the machine (fresh at every evaluation, from a spec
  built by the lab), runs ``suricata -r`` on it with one rule file (``-S``), a ``HOME_NET`` forced
  on the command line and an optional threshold file, and returns the alerts as dicts
  (``sid``, ``src``, ``dst``, ``action``), the rule errors of the run in ``errors``;
- :func:`eve_alerts` reads the alerts of one signature from a live ``eve.json`` and
  :func:`alerts_since` keeps those of the current evaluation (timestamp after the ``t0`` read at
  step 1 with :func:`get_epoch`);
- :func:`get_dump_config` / :func:`parse_dump_config` read ``suricata --dump-config`` (the
  configuration as Suricata understands it: ``af-packet.0.interface``, ``rule-files.N``,
  ``vars.address-groups.HOME_NET``...), :func:`address_group` parses an address group;
- :func:`get_processes` lists the running Suricata command lines (``pgrep -a``), with
  :func:`nfq_mode` / :func:`af_packet_mode`;
- :func:`queue_statements` finds the ``queue`` statements of a hook in a ruleset parsed by
  ``firewall.get_nft_json`` (number and flags: ``bypass`` = fail-open).

Facts verified in the Debian 13 images (Suricata 7.0.10, 2026-11-23): the Debian ``suricata.yaml``
captures on ``eth0`` with ``af-packet`` threads ``auto`` (one per core: 90 MB of RSS on 12 cores,
50 MB with ``threads: 1``), loads ``/var/lib/suricata/rules/suricata.rules`` (absent until
``suricata-update`` has run: a warning only) and enables the unix socket
``/var/run/suricata-command.socket`` (an offline run must disable it: ``--set unix-command.enabled=no``);
its unit runs ``suricata -D --af-packet``; the NFQUEUE modules (``nft_queue``, ``nfnetlink_queue``) load
on demand from a container; ``http.uri`` is the normalised URI (``%2F`` decoded, ``../`` resolved, in
the query string too) while ``http.uri.raw`` and a plain ``content`` see the bytes; ``endswith`` on
``dns.query``; ``detection_filter: count 5`` alerts from the 6th match on, ``threshold: type threshold,
count 5`` on the 5th; a ``suppress ... track by_src, ip X`` line of the threshold file silences X
only; an offline run on a few hundred packets takes well under a second.
"""
import json
from datetime import datetime
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from SRE.lib_sre import Grade0, NetScheme0
from suricata_pcap import encode_spec

PCAP_TOOL_PATH = "/usr/local/sbin/sre_suricata_pcap.py"
OFFLINE_YAML = "/usr/local/share/sre/suricata-offline.yaml"
SURICATA_YAML = "/etc/suricata/suricata.yaml"
EVE_PATH = "/var/log/suricata/eve.json"
OFFLINE_DIR = "/tmp/sre-suricata-offline"
ALERT_MARK = "SRE-ALERT "
ERROR_MARK = "SRE-ERROR "
RC_MARK = "SRE-RC="


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------

def install_pcap_tool(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy ``lib/suricata_pcap.py`` to :data:`PCAP_TOOL_PATH` on *machine*."""
    script = Path(__file__).with_name("suricata_pcap.py").read_text()
    net_scheme.file(machine=machine, filename=PCAP_TOOL_PATH, content=script, permissions=0o755, step=step)


def write_pcap(net_scheme: NetScheme0, machine: str, path: str, spec: dict, step: int = 1) -> None:
    """Write the capture of *spec* to *path* on *machine* (the tool must be installed at an earlier
    or the same step)."""
    directory = path.rsplit("/", 1)[0] or "/"
    net_scheme.cmd(machine, f"mkdir -p {directory} && python3 {PCAP_TOOL_PATH} {encode_spec(spec)} {path}",
                   step=step)


def save_offline_config(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Keep the configuration as installed in :data:`OFFLINE_YAML` (what the grader runs offline)."""
    net_scheme.cmd(machine, f"mkdir -p {OFFLINE_YAML.rsplit('/', 1)[0]} && cp {SURICATA_YAML} {OFFLINE_YAML}",
                   step=step)


def render_minimal_yaml(home_net: Iterable, interface: str, rule_files: Iterable[str],
                        rule_path: str = "/etc/suricata/rules") -> str:
    """A complete ``suricata.yaml`` for a sensor on *interface* (af-packet, one thread) writing only
    its alerts to ``/var/log/suricata/eve.json``, without unix socket."""
    nets = ",".join(str(n) for n in home_net)
    rules = "".join(f"  - {r}\n" for r in rule_files)
    return f"""%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[{nets}]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SSH_PORTS: "22"
default-log-dir: /var/log/suricata/
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
af-packet:
  - interface: {interface}
    threads: 1
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: {rule_path}
rule-files:
{rules}classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
unix-command:
  enabled: no
"""


# ---------------------------------------------------------------------------
# offline runs
# ---------------------------------------------------------------------------

def offline_alerts_cmd(spec: dict, rule_file: str, home_net: Iterable, threshold_file: Optional[str] = None,
                       name: str = "run", yaml: str = OFFLINE_YAML) -> str:
    """The shell command of :func:`offline_alerts` (one working directory per *name*)."""
    work = f"{OFFLINE_DIR}/{name}"
    nets = ",".join(str(n) for n in home_net)
    threshold = threshold_file or f"{work}/empty.threshold"
    return (f"rm -rf {work}; mkdir -p {work}; : > {work}/empty.threshold; "
            f"python3 {PCAP_TOOL_PATH} {encode_spec(spec)} {work}/probe.pcap && "
            f"suricata -c {yaml} --runmode single -r {work}/probe.pcap -S {rule_file} -l {work} -k none "
            f"--set unix-command.enabled=no --set threshold-file={threshold} "
            f"--set 'vars.address-groups.HOME_NET=[{nets}]' > {work}/stdout 2>&1; "
            f"echo {RC_MARK}$?; "
            f"jq -c 'select(.event_type==\"alert\") | {{sid: .alert.signature_id, src: .src_ip, dst: .dest_ip, "
            f"action: .alert.action}}' {work}/eve.json 2>/dev/null | sed 's/^/{ALERT_MARK}/'; "
            f"grep -h -E 'Error|error' {work}/suricata.log {work}/stdout 2>/dev/null | head -8 | sed 's/^/{ERROR_MARK}/'; "
            f"rm -rf {work}")


def parse_offline_output(text: str) -> Dict[str, Any]:
    """``{'rc': int | None, 'alerts': [{'sid', 'src', 'dst', 'action'}], 'errors': [str]}``."""
    result: Dict[str, Any] = {'rc': None, 'alerts': [], 'errors': []}
    for line in (text or "").splitlines():
        if line.startswith(RC_MARK):
            try:
                result['rc'] = int(line[len(RC_MARK):].strip())
            except ValueError:
                pass
        elif line.startswith(ALERT_MARK):
            try:
                alert = json.loads(line[len(ALERT_MARK):])
            except ValueError:
                continue
            if isinstance(alert, dict):
                result['alerts'].append(alert)
        elif line.startswith(ERROR_MARK):
            result['errors'].append(line[len(ERROR_MARK):].strip())
    return result


def offline_alerts(grade: Grade0, machine: str, spec: dict, rule_file: str, home_net: Iterable,
                   threshold_file: Optional[str] = None, name: str = "run", step: int = 1,
                   timeout: int = 60) -> Dict[str, Any]:
    """Run Suricata offline on *machine* on a fresh capture of *spec* (see :func:`parse_offline_output`)."""
    out, _ = grade.test(machine, offline_alerts_cmd(spec, rule_file, home_net, threshold_file, name),
                        step=step, timeout=timeout, allow_error=True)
    return parse_offline_output(out or "")


def alert_sources(alerts: List[Dict[str, Any]], sid: int) -> set:
    """The source addresses of the alerts of signature *sid*."""
    return {a.get('src') for a in alerts if a.get('sid') == sid}


# ---------------------------------------------------------------------------
# live eve.json
# ---------------------------------------------------------------------------

def get_epoch(grade: Grade0, machine: str, step: int = 1) -> Optional[float]:
    """The clock of *machine* (``date +%s.%N``), ``None`` until the test has run."""
    out, _ = grade.test(machine, "date +%s.%N", step=step, allow_error=True)
    try:
        return float((out or "").strip())
    except ValueError:
        return None


def eve_alerts_cmd(sid: int, eve: str = EVE_PATH, lines: int = 200) -> str:
    return f"grep -F '\"signature_id\":{int(sid)},' {eve} 2>/dev/null | tail -n {int(lines)}"


def parse_eve_lines(text: str) -> List[Dict[str, Any]]:
    """The JSON events of an ``eve.json`` extract (bad lines skipped)."""
    events = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def eve_epoch(timestamp: str) -> Optional[float]:
    """``2026-11-23T14:37:48.619138+0000`` → epoch seconds (``None`` when unreadable)."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(timestamp or "", fmt).timestamp()
        except ValueError:
            continue
    return None


def eve_alerts(grade: Grade0, machine: str, sid: int, eve: str = EVE_PATH, step: int = 1) -> List[Dict[str, Any]]:
    """The last alert events of signature *sid* in the live *eve* file of *machine*."""
    out, _ = grade.test(machine, eve_alerts_cmd(sid, eve), step=step, allow_error=True)
    return [e for e in parse_eve_lines(out or "") if e.get("event_type") == "alert"]


def alerts_since(events: List[Dict[str, Any]], t0: Optional[float], src: Optional[str] = None,
                 action: Optional[str] = None, margin: float = 1.0) -> List[Dict[str, Any]]:
    """The alert events written after *t0* (minus *margin* seconds), from *src*, of *action*."""
    if t0 is None:
        return []
    kept = []
    for event in events:
        ts = eve_epoch(event.get("timestamp", ""))
        if ts is None or ts < t0 - margin:
            continue
        if src is not None and event.get("src_ip") != str(src):
            continue
        if action is not None and (event.get("alert") or {}).get("action") != action:
            continue
        kept.append(event)
    return kept


# ---------------------------------------------------------------------------
# configuration and processes
# ---------------------------------------------------------------------------

def dump_config_cmd(yaml: str = SURICATA_YAML) -> str:
    return f"suricata --dump-config -c {yaml} 2>/dev/null"


def parse_dump_config(text: str) -> Dict[str, str]:
    """``suricata --dump-config`` → ``{key: value}`` (``(null)`` values kept as ``''``)."""
    config = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(" = ")
        if not sep:
            continue
        value = value.strip()
        config[key.strip()] = "" if value == "(null)" else value
    return config


def get_dump_config(grade: Grade0, machine: str, yaml: str = SURICATA_YAML, step: int = 1) -> Dict[str, str]:
    out, _ = grade.test(machine, dump_config_cmd(yaml), step=step, allow_error=True)
    return parse_dump_config(out or "")


def config_list(config: Dict[str, str], prefix: str) -> List[str]:
    """The values of a YAML list (``rule-files.0``, ``rule-files.1``...), in order."""
    items = []
    i = 0
    while f"{prefix}.{i}" in config:
        items.append(config[f"{prefix}.{i}"])
        i += 1
    return items


def address_group(value: str) -> Optional[List[IPv4Network]]:
    """``[10.1.2.0/24,10.3.4.0/24]`` → networks; ``None`` when a member is not a plain network or
    address (a negation, a variable, ``any``)."""
    text = (value or "").strip().strip('"').strip("'").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    nets = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ip_network(item, strict=False))
        except ValueError:
            return None
    return nets


def same_networks(value: str, expected: Iterable) -> bool:
    """True when the address group *value* holds exactly the *expected* networks (any order)."""
    nets = address_group(value)
    if nets is None:
        return False
    return sorted(set(str(n) for n in nets)) == sorted(set(str(ip_network(str(e), strict=False)) for e in expected))


def rule_file_loaded(config: Dict[str, str], path: str) -> bool:
    """True when ``rule-files`` names *path* (absolute, or relative to ``default-rule-path``)."""
    base = (config.get("default-rule-path") or "").rstrip("/")
    for item in config_list(config, "rule-files"):
        full = item if item.startswith("/") else f"{base}/{item}"
        if full.replace("//", "/") == path:
            return True
    return False


def get_processes(grade: Grade0, machine: str, step: int = 1) -> List[str]:
    """The command lines of the running Suricata processes (``pgrep -a suricata``)."""
    out, _ = grade.test(machine, "pgrep -a -x suricata || pgrep -a Suricata-Main", step=step, allow_error=True)
    return [line.split(" ", 1)[1] for line in (out or "").splitlines() if " " in line.strip()]


def nfq_mode(cmdline: str) -> bool:
    """True when a Suricata command line reads an NFQUEUE (``-q N`` / ``--nfqueue``)."""
    tokens = cmdline.split()
    return any(t == "-q" or t.startswith("-q") and t[2:].isdigit() or t.startswith("--nfqueue")
               for t in tokens)


def af_packet_mode(cmdline: str) -> Optional[str]:
    """``''`` for ``--af-packet`` (interfaces of the configuration), the interface of
    ``--af-packet=ethN``, ``None`` when the command line does not capture with af-packet."""
    for token in cmdline.split():
        if token == "--af-packet":
            return ""
        if token.startswith("--af-packet="):
            return token.split("=", 1)[1]
    return None


def queue_statements(parsed: Dict[str, Any], hook: str = "forward") -> List[Dict[str, Any]]:
    """The ``queue`` statements of the rules of *hook* (``firewall.get_nft_json`` form):
    ``[{'num': int | None, 'flags': [str], 'family', 'table', 'chain'}]``."""
    found = []
    for rule in parsed.get("rules", []):
        if rule.get("hook") != hook:
            continue
        for expr in rule.get("expr", []):
            if isinstance(expr, dict) and "queue" in expr:
                queue = expr["queue"] or {}
                flags = queue.get("flags") or []
                if isinstance(flags, str):
                    flags = [flags]
                num = queue.get("num")
                found.append({"num": num if isinstance(num, int) else None, "flags": list(flags),
                              "family": rule.get("family"), "table": rule.get("table"),
                              "chain": rule.get("chain")})
    return found
