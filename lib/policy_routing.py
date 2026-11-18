"""Policy routing helpers of the policy routing lab (``lab/sre/_DRAFT_misc/policy-routing.py``):
what the other modules do not read yet.

The rules are those of ``wireguard.get_ip_rules`` (``ip -j rule``), the packet marks of nftables
those of ``tc.nft_mark_rules``, the links those of ``bridging.get_ip_links``.  Here:

* the routes of **every table** (``ip -j route show table all``: ``parse_route_tables`` /
  ``get_route_tables`` → ``{table: [route, ...]}``, the table being the number or the name ``ip``
  prints, ``main`` for a route without a ``table`` key), the next hops of a route with their weights
  (``route_nexthops``: a plain route, a multipath route or a nexthop object ``nhid``),
  ``default_route`` / ``default_nexthops`` / ``leaves_by``;
* the **fwmark rules** (``fwmark_rules`` → ``[{'mark', 'mask', 'table', 'priority'}]``,
  ``rule_selects_mark``, ``tables_of_mark``);
* the **VRF devices** of ``ip -j -d link`` (``vrf_devices`` → ``{name: {'table', 'up', 'ports'}}``);
* the **spread probe** of a multipath route: ``spread_cmd`` asks the echo server of
  ``server_echo_helpers`` on consecutive addresses, a few requests at a time, ``parse_spread``
  counts who answered (``SERVER_IP=``) and under which client address (``CLIENT_IP=``).

Fixtures captured live (iproute2 6.19, nftables 1.0.6, Linux 6.12) in
``tests/mock_data/policy_routing/``, tests ``tests/test_policy_routing.py``.
"""
from ipaddress import ip_address
from typing import Any, Dict, List, Optional, Set

from SRE.lib_sre import Grade0
from bridging import links_by_name
from wireguard import parse_ip_routes_json

MAIN_TABLE = "main"
ROUTE_TABLES_CMD = "ip -j route show table all 2>/dev/null"
FULL_MASK = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# routes of every table
# ---------------------------------------------------------------------------


def parse_route_tables(text: str) -> Dict[str, List[dict]]:
    """``ip -j route show table all`` → ``{table: [route, ...]}`` in the order of the listing.
    The key is what ``ip`` prints (``'102'``, or the name given in ``rt_tables``: ``'isp2'``,
    ``'local'``); the routes of the main table carry no ``table`` key and go to ``'main'``."""
    tables: Dict[str, List[dict]] = {}
    for route in parse_ip_routes_json(text):
        tables.setdefault(str(route.get("table", MAIN_TABLE)), []).append(route)
    return tables


def get_route_tables(grade: Grade0, machine_name: str, step: int = 1) -> Dict[str, List[dict]]:
    """The routes of every table of *machine_name* (``{}`` on failure or until the tests have run)."""
    text, code = grade.test(machine_name, ROUTE_TABLES_CMD, step=step, allow_error=True)
    return parse_route_tables(text) if code == 0 else {}


def route_nexthops(route: Optional[dict]) -> List[Dict[str, Any]]:
    """``[{'gateway', 'dev', 'weight'}]`` of a route: the ``nexthops`` of a multipath route (or of
    a nexthop group, ``nhid``), else its own gateway and device with the weight 1; ``[]`` for a
    route that forwards nothing (``unreachable``, ``blackhole``...) or for ``None``."""
    if not route or "type" in route and route["type"] != "unicast":
        return []
    hops = route.get("nexthops")
    if not isinstance(hops, list):
        hops = [route] if route.get("gateway") or route.get("dev") else []
    return [{"gateway": str(hop.get("gateway", "")), "dev": str(hop.get("dev", "")),
             "weight": int(hop.get("weight", 1) or 1)}
            for hop in hops if isinstance(hop, dict)]


def default_route(routes: List[dict]) -> Optional[dict]:
    """The default route of a table: the one of the lowest metric, whatever its type (``None``
    when the table has none)."""
    defaults = [route for route in routes or [] if route.get("dst") == "default"]
    return min(defaults, key=lambda route: int(route.get("metric", 0) or 0)) if defaults else None


def default_nexthops(routes: List[dict]) -> List[Dict[str, Any]]:
    """The next hops of the default route of a table (``[]`` without one, or when it is
    ``unreachable`` and the like)."""
    return route_nexthops(default_route(routes))


def leaves_by(routes: List[dict], dev: str) -> bool:
    """True when the default route of the table forwards, and by *dev* only."""
    hops = default_nexthops(routes)
    return bool(hops) and all(hop["dev"] == dev for hop in hops)


# ---------------------------------------------------------------------------
# rules selecting a mark
# ---------------------------------------------------------------------------


def _number(text) -> Optional[int]:
    try:
        return int(str(text), 0)
    except ValueError:
        return None


def fwmark_rules(rules: List[dict]) -> List[Dict[str, Any]]:
    """The rules of ``ip -j rule`` that select a mark and look a table up:
    ``[{'mark', 'mask', 'table', 'priority'}]`` (``fwmark 0x2/0xff`` → mark 2, mask 255; no mask:
    every bit).  Negated rules (``not fwmark``) and rules without a table are left out."""
    selected = []
    for rule in rules or []:
        if "fwmark" not in rule or "not" in rule or "table" not in rule:
            continue
        value, _, mask = str(rule["fwmark"]).partition("/")
        mark = _number(value)
        mask_value = _number(rule.get("fwmask", mask or FULL_MASK))
        if mark is None or mask_value is None:
            continue
        selected.append({"mark": mark, "mask": mask_value, "table": str(rule["table"]),
                         "priority": int(rule.get("priority", 0) or 0)})
    return selected


def rule_selects_mark(rule: Dict[str, Any], mark: int) -> bool:
    """True when a rule of :func:`fwmark_rules` selects the packets carrying *mark*."""
    return (mark & rule["mask"]) == (rule["mark"] & rule["mask"])


def tables_of_mark(rules: List[dict], mark: int) -> List[str]:
    """The tables the fwmark rules send a packet marked *mark* to, by increasing priority."""
    selected = [rule for rule in fwmark_rules(rules) if rule_selects_mark(rule, mark)]
    return [rule["table"] for rule in sorted(selected, key=lambda rule: rule["priority"])]


# ---------------------------------------------------------------------------
# VRF devices
# ---------------------------------------------------------------------------


def vrf_devices(links: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """The VRF devices of ``ip -j -d link`` (``bridging.get_ip_links``):
    ``{name: {'table': int, 'up': bool, 'ports': [ifname, ...]}}``, the ports being the interfaces
    whose master is the device."""
    by_name = links_by_name(links)
    devices: Dict[str, Dict[str, Any]] = {}
    for name, link in by_name.items():
        info = link.get("linkinfo") or {}
        if info.get("info_kind") == "vrf":
            table = (info.get("info_data") or {}).get("table")
            devices[name] = {"table": int(table) if isinstance(table, int) else 0,
                             "up": "UP" in (link.get("flags") or []), "ports": []}
    for name, link in by_name.items():
        if link.get("master") in devices:
            devices[link["master"]]["ports"].append(name)
    return devices


def vrf_of_port(devices: Dict[str, Dict[str, Any]], ifname: str) -> Optional[str]:
    """The VRF device *ifname* is enslaved to (``None`` when it is in the default VRF)."""
    for name, device in devices.items():
        if ifname in device["ports"]:
            return name
    return None


# ---------------------------------------------------------------------------
# the spread probe of a multipath route
# ---------------------------------------------------------------------------


def spread_cmd(first_address, count: int, port: int = 80, parallel: int = 8, timeout: int = 3) -> str:
    """One command line asking the echo server of *count* consecutive addresses starting at
    *first_address* (all in the same /24), *parallel* requests at a time.  The pages come out in
    any order, each one whole."""
    first = ip_address(str(first_address).split("/")[0])
    prefix, _, start = str(first).rpartition(".")
    last = int(start) + int(count) - 1
    if not 0 < int(count) or last > 254:
        raise ValueError(f"spread_cmd: {count} addresses from {first} leave the /24")
    return (f"seq {int(start)} {last} | xargs -P {int(parallel)} -I {{}} "
            f"curl -s -m {int(timeout)} http://{prefix}.{{}}:{int(port)}/")


def parse_spread(output: str) -> Dict[str, Any]:
    """``{'servers': {address, ...}, 'clients': {address: number of pages}}`` of the output of
    :func:`spread_cmd`: the addresses that answered (``SERVER_IP=``) and the client addresses
    their server saw (``CLIENT_IP=``)."""
    servers: Set[str] = set()
    clients: Dict[str, int] = {}
    for line in (output or "").splitlines():
        key, _, value = line.strip().partition("=")
        if key == "SERVER_IP" and value:
            servers.add(value)
        elif key == "CLIENT_IP" and value:
            clients[value] = clients.get(value, 0) + 1
    return {"servers": servers, "clients": clients}
