"""SD-WAN helpers of the SD-WAN lab (``lab/sre/_DRAFT_misc/sdwan.py``).

Which transport carried which application?  The hub of the lab sees the **decrypted** inner packets of
its two tunnels (``wg-mpls``, ``wg-inet``): an nftables table of its own, ``inet sre_count``, counts
them per (branch host, tunnel, application probe), each rule named by its comment ``host|tunnel|app``.
The grader reads the counters before and after a burst of probe packets sent by a branch host, and
compares the two tunnels: no background traffic (keepalives, BGP, BFD, the agent's pings) is counted.

State side::

    net_scheme.file('hub', COUNT_FILE, counter_ruleset({'pc1': '10.1.1.10', ...}, ef_port=40000))
    net_scheme.cmd('hub', f'nft -f {COUNT_FILE}')
    install_agent(net_scheme, 'edge6', 'http://10.0.0.5', 'edge6')       # lib/sdwan_agent.py
    net_scheme.cmd('mpls', brownout_cmd('eth5', 250))                     # netem on a provider link

Grade side::

    before = get_counters(grade, 'hub', step=1)
    grade.test('pc3', probe_cmd('sip', '10.0.0.10'), step=2)
    after = get_counters(grade, 'hub', step=3)
    carried_by(tunnel_delta(before, after, 'pc3', 'sip'), 'mpls', PROBE_COUNT)
    status = get_agent_status(grade, 'edge6')                            # sdwan-agent status --json

The formats were captured on s17 (nftables 1.1.3, hping3 3.a2, 2026-11-24): ``tests/mock_data/sdwan/``.
"""
import json
from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple

from SRE.lib_sre import Grade0, NetScheme0

COUNT_TABLE = "sre_count"
COUNT_FILE = "/etc/sre-count.nft"
TUNNELS = {"mpls": "wg-mpls", "inet": "wg-inet"}
PROBE_COUNT = 20
PROBE_INTERVAL_US = 10000
SIP_PORT, ERP_PORT, BULK_PORT, WEB_PORT = 5060, 8443, 873, 80
AGENT_PATH = "/usr/local/sbin/sdwan-agent"
AGENT_CONF = "/etc/sdwan-agent.conf"
AGENT_LOG = "/var/log/sdwan-agent.log"

#: probe name -> the nftables expression that recognises it on the hub (EF_PORT filled by counter_ruleset)
APPS = {
    "sip": f"udp dport {SIP_PORT}",
    "ef": "ip dscp ef udp dport {ef_port}",
    "udp": "ip dscp cs0 udp dport {ef_port}",
    "erp": f"tcp dport {ERP_PORT}",
    "bulk": f"tcp dport {BULK_PORT}",
    "web": f"tcp dport {WEB_PORT}",
    "icmp": "icmp type echo-request",
}


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def counter_ruleset(hosts: Mapping[str, str], ef_port: int) -> str:
    """The nftables file of the hub's counters: for each branch host (name → address), each tunnel
    and each probe, a counting rule whose comment is ``host|tunnel|app``."""
    rules = []
    for host, address in hosts.items():
        for tunnel, device in TUNNELS.items():
            for app, expr in APPS.items():
                match = expr.format(ef_port=int(ef_port))
                rules.append(f'\t\tiifname "{device}" ip saddr {address} {match} counter comment "{host}|{tunnel}|{app}"')
    return (f"table inet {COUNT_TABLE}\ndelete table inet {COUNT_TABLE}\n"
            f"table inet {COUNT_TABLE} {{\n\tchain count {{\n"
            f"\t\ttype filter hook prerouting priority raw; policy accept;\n"
            + "\n".join(rules) + "\n\t}\n}\n")


def install_agent(net_scheme: NetScheme0, machine: str, controller: str, site: str, start: bool = True,
                  step: int = 1) -> None:
    """Copy lib/sdwan_agent.py to AGENT_PATH, write its configuration and start it."""
    script = Path(__file__).with_name("sdwan_agent.py").read_text()
    net_scheme.file(machine, AGENT_PATH, script, permissions=0o755, step=step)
    net_scheme.file(machine, AGENT_CONF, f"# the orchestrator and the name of this site\ncontroller={controller}\n"
                                         f"site={site}\n", step=step)
    if start:
        net_scheme.cmd(machine, f"{AGENT_PATH} start", step=step)


def brownout_cmd(device: str, delay_ms: int) -> str:
    """Add (or change) a netem delay on the egress of *device*: the hosts behind it see their RTT grow."""
    return (f"tc qdisc replace dev {device} root netem delay {int(delay_ms)}ms")


def restore_cmd(device: str) -> str:
    return f"tc qdisc del dev {device} root 2>/dev/null; true"


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


def counters_cmd() -> str:
    """One line ``host|tunnel|app packets`` per counter (the JSON of the table is 40 kB)."""
    return (f"nft -j list table inet {COUNT_TABLE} | jq -r '.nftables[] | select(.rule) | .rule | "
            "\"\\(.comment) \\(.expr[] | select(.counter) | .counter.packets)\"'")


def parse_counters(text: str) -> Dict[Tuple[str, str, str], int]:
    """The lines of :func:`counters_cmd` (or the whole ``nft -j list table inet sre_count``) →
    ``{(host, tunnel, app): packets}``."""
    text = text or ""
    if not text.lstrip().startswith("{"):
        result = {}
        for line in text.splitlines():
            words = line.split()
            parts = words[0].split("|") if len(words) == 2 else []
            if len(parts) == 3 and words[1].isdigit():
                result[tuple(parts)] = int(words[1])
        return result
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {}
    result = {}
    for item in data.get("nftables", []) if isinstance(data, dict) else []:
        rule = item.get("rule") if isinstance(item, dict) else None
        if not isinstance(rule, dict):
            continue
        parts = str(rule.get("comment", "")).split("|")
        if len(parts) != 3:
            continue
        packets = next((e["counter"].get("packets", 0) for e in rule.get("expr", [])
                        if isinstance(e, dict) and isinstance(e.get("counter"), dict)), None)
        if packets is not None:
            result[tuple(parts)] = int(packets)
    return result


def get_counters(grade: Grade0, machine: str = "hub", step: int = 1) -> Dict[Tuple[str, str, str], int]:
    out, _ = grade.test(machine, counters_cmd(), step=step, timeout=15, allow_error=True)
    return parse_counters(out)


def tunnel_delta(before: Mapping, after: Mapping, host: str, app: str) -> Dict[str, Optional[int]]:
    """The packets of *app* from *host* counted on each tunnel between two readings (None when a
    reading misses the counter: the hub's table was not read)."""
    result = {}
    for tunnel in TUNNELS:
        key = (host, tunnel, app)
        result[tunnel] = after[key] - before[key] if key in after and key in before else None
    return result


def carried_by(delta: Mapping[str, Optional[int]], tunnel: str, sent: int = PROBE_COUNT,
               min_ratio: float = 0.75, max_other: int = 3) -> bool:
    """True when most of the *sent* probes went through *tunnel* and almost none through the other."""
    mine = delta.get(tunnel)
    others = [v for t, v in delta.items() if t != tunnel]
    if mine is None or any(v is None for v in others):
        return False
    return mine >= min_ratio * sent and all(v <= max_other for v in others)


def probe_cmd(app: str, dst, count: int = PROBE_COUNT, ef_port: int = 40000) -> str:
    """A burst of *count* probe packets of *app* towards *dst* (hping3; ping for icmp)."""
    dst = str(dst).split("/")[0]
    gap = f"-i u{PROBE_INTERVAL_US}"
    if app == "icmp":
        return f"ping -n -q -c {int(count)} -i 0.02 -W 1 {dst} >/dev/null 2>&1; true"
    args = {"sip": f"--udp -p {SIP_PORT}", "ef": f"--udp -p {int(ef_port)} -o b8", "udp": f"--udp -p {int(ef_port)}",
            "erp": f"-S -p {ERP_PORT}", "bulk": f"-S -p {BULK_PORT}", "web": f"-S -p {WEB_PORT}"}[app]
    # hping3 reads the TOS in hexadecimal without 0x: "-o b8" is EF (46 << 2)
    return f"hping3 {args} -c {int(count)} {gap} -q {dst} >/dev/null 2>&1; true"


def agent_status_cmd() -> str:
    return f"{AGENT_PATH} status --json"


def parse_agent_status(text: str) -> dict:
    """``sdwan-agent status --json`` → its document ({} when there is none)."""
    start = (text or "").find("{")
    if start < 0:
        return {}
    try:
        data = json.loads(text[start:])
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def get_agent_status(grade: Grade0, machine: str, step: int = 1) -> dict:
    out, _ = grade.test(machine, agent_status_cmd(), step=step, timeout=10, allow_error=True)
    return parse_agent_status(out)


def policy_json(paths: Mapping[str, Tuple[str, str]], sla_classes: Mapping[str, Mapping], applications,
                version: int = 1) -> str:
    """A policy document of the agent (paths: name → (device, probe address))."""
    doc = {"version": version,
           "paths": {name: {"device": dev, "probe": str(probe)} for name, (dev, probe) in paths.items()},
           "sla_classes": {name: dict(c) for name, c in sla_classes.items()},
           "applications": list(applications)}
    return json.dumps(doc, indent=2) + "\n"


