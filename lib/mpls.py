"""MPLS helpers on the Linux side (kernel tables, sysctls, counters), for the MPLS labs.

The routing daemons (LDP, segment routing in OSPF) are read through lib/frr.py; this module reads
what the kernel does with labels:

- the label space and the per-interface switches of ``net.mpls`` (``get_mpls_sysctls``);
- the incoming label table, ``ip -j -f mpls route`` (``get_kernel_mpls_routes``);
- the per-interface MPLS counters of ``ip -j stats ... group afstats subgroup mpls``
  (``get_mpls_counters``), the proof that labelled packets crossed an interface (the routing
  protocols speak IP and never count there);

and gives the state command that makes the host load its MPLS modules
(``trigger_mpls_modules_cmd``).

Every ``get_*`` helper registers one command with ``grade.test()`` and parses its output with a
pure ``parse_*`` function (fixtures in tests/mock_data/mpls/).
"""
import json
from typing import Any, Dict, List

from SRE.lib_sre import Grade0

# A route with an MPLS encapsulation makes the kernel load mpls_iptunnel (alias rtnl-lwt-MPLS),
# which needs mpls_router: the host's modprobe runs in the initial namespace, no capability is
# checked, so a container loads them.  The net.mpls sysctls then exist in every namespace.
_TRIGGER_ROUTE = "198.51.100.255/32"
MPLS_SYSCTL_DIR = "/proc/sys/net/mpls"


def trigger_mpls_modules_cmd(wait_tenths: int = 50) -> str:
    """Shell command of a state: load the host's MPLS modules through the module autoload (an
    ``encap mpls`` route, deleted at once) and wait up to *wait_tenths* tenths of a second for the
    ``net.mpls`` sysctls of the container.  Exit status 0 when they exist."""
    return (f"ip route add {_TRIGGER_ROUTE} encap mpls 16 dev lo 2>/dev/null; "
            f"ip route del {_TRIGGER_ROUTE} 2>/dev/null; "
            f"i=0; while [ ! -e {MPLS_SYSCTL_DIR}/platform_labels ] && [ $i -lt {wait_tenths} ]; "
            f"do sleep 0.1; i=$((i+1)); done; test -e {MPLS_SYSCTL_DIR}/platform_labels")


def _test(grade: Grade0, machine_name: str, command: str, step: int, allow_error: bool):
    output, code = grade.test(machine_name, command, step=step, allow_error=allow_error)
    return output if code == 0 else ""


def _int_or_none(value) -> Any:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_mpls_sysctls(output: str) -> Dict[str, Any]:
    """``grep -r . /proc/sys/net/mpls`` → ``{'platform_labels': int, 'ip_ttl_propagate': int,
    'default_ttl': int, 'input': {ifname: int}}`` (missing keys when the modules are absent)."""
    result: Dict[str, Any] = {'input': {}}
    for line in (output or "").splitlines():
        path, sep, value = line.partition(':')
        if not sep or not path.startswith(MPLS_SYSCTL_DIR + '/'):
            continue
        key = path[len(MPLS_SYSCTL_DIR) + 1:].split('/')
        if key[0] == 'conf' and len(key) == 3 and key[2] == 'input':
            result['input'][key[1]] = _int_or_none(value)
        elif len(key) == 1:
            result[key[0]] = _int_or_none(value)
    return result


def get_mpls_sysctls(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[str, Any]:
    """The ``net.mpls`` sysctls of *machine_name* (see :func:`parse_mpls_sysctls`)."""
    output = _test(grade, machine_name, f"grep -r . {MPLS_SYSCTL_DIR}", step, allow_error)
    return parse_mpls_sysctls(output)


def parse_labels(text) -> List[int]:
    """A label stack as iproute2 writes it (``"381"``, ``"16003/16005"``) → ``[381]``,
    ``[16003, 16005]``; ``[]`` when there is none."""
    labels = []
    for part in str(text or "").split('/'):
        value = _int_or_none(part)
        if value is not None:
            labels.append(value)
    return labels


def _mpls_nexthop(entry: Dict[str, Any]) -> Dict[str, Any]:
    via = entry.get('via')
    gateway = via.get('host') if isinstance(via, dict) else (via if isinstance(via, str) else None)
    return {'out_labels': parse_labels(entry.get('to') or entry.get('newdst')), 'via': gateway,
            'dev': entry.get('dev')}


def parse_kernel_mpls_routes(output: str) -> Dict[int, Dict[str, Any]]:
    """The json of ``ip -j -f mpls route`` (the incoming label map of the kernel) →
    ``{label: {'protocol': str | None, 'nexthops': [{'out_labels': [int], 'via': str | None,
    'dev': str | None}]}}``.  An empty ``out_labels`` is a pop (``via`` the next hop of the IP
    packet, or ``dev lo`` alone for a local delivery), otherwise a swap to that stack."""
    try:
        routes = json.loads(output)
    except (ValueError, TypeError):
        return {}
    if not isinstance(routes, list):
        return {}
    result: Dict[int, Dict[str, Any]] = {}
    for r in routes:
        if not isinstance(r, dict):
            continue
        label = _int_or_none(r.get('dst'))
        if label is None or label in result:
            continue
        if isinstance(r.get('nexthops'), list):
            nexthops = [_mpls_nexthop(n) for n in r['nexthops'] if isinstance(n, dict)]
        else:
            nexthops = [_mpls_nexthop(r)]
        result[label] = {'protocol': r.get('protocol'), 'nexthops': nexthops}
    return result


def get_kernel_mpls_routes(grade: Grade0, machine_name: str, step: int = 1,
                           allow_error: bool = True) -> Dict[int, Dict[str, Any]]:
    """The incoming label map of the kernel of *machine_name* (see :func:`parse_kernel_mpls_routes`)."""
    return parse_kernel_mpls_routes(_test(grade, machine_name, "ip -j -f mpls route", step, allow_error))


def mpls_route_is_swap(routes: Dict[int, Dict[str, Any]], label: int, out_labels, via=None) -> bool:
    """True when *label* is swapped to *out_labels* (a list or one label), towards *via* if given."""
    expected = list(out_labels) if isinstance(out_labels, (list, tuple)) else [out_labels]
    entry = routes.get(label) or {}
    return any(n['out_labels'] == expected and (via is None or str(n['via']) == str(via))
               for n in entry.get('nexthops', []))


def mpls_route_is_pop(routes: Dict[int, Dict[str, Any]], label: int, via=None, dev: str = None) -> bool:
    """True when *label* is popped (no outgoing label), towards *via* / out of *dev* if given."""
    entry = routes.get(label) or {}
    return any(not n['out_labels'] and (via is None or str(n['via']) == str(via))
               and (dev is None or n['dev'] == dev)
               for n in entry.get('nexthops', []))


def parse_mpls_counters(output: str) -> Dict[str, Dict[str, int]]:
    """The json of ``ip -j stats show group afstats subgroup mpls`` → ``{ifname: {'rx_packets',
    'rx_bytes', 'rx_errors', 'rx_dropped', 'rx_noroute', 'tx_packets', 'tx_bytes', 'tx_errors',
    'tx_dropped'}}`` (the MPLS packets of each interface: a TTL expiry counts as an rx error)."""
    try:
        entries = json.loads(output)
    except (ValueError, TypeError):
        return {}
    if not isinstance(entries, list):
        return {}
    result: Dict[str, Dict[str, int]] = {}
    for e in entries:
        if not isinstance(e, dict) or not e.get('ifname'):
            continue
        stats = e.get('mpls_stats') or {}
        counters = {}
        for direction in ('rx', 'tx'):
            for key, value in (stats.get(direction) or {}).items():
                number = _int_or_none(value)
                if number is not None:
                    counters[f"{direction}_{key}"] = number
        result[e['ifname']] = counters
    return result


MPLS_COUNTERS_CMD = "ip -j stats show group afstats subgroup mpls"


def get_mpls_counters(grade: Grade0, machine_name: str, step: int = 1,
                      allow_error: bool = True) -> Dict[str, Dict[str, int]]:
    """The MPLS counters of every interface of *machine_name* (see :func:`parse_mpls_counters`).
    Read at two steps around some traffic, :func:`mpls_counter_delta` tells whether labelled
    packets crossed an interface."""
    return parse_mpls_counters(_test(grade, machine_name, MPLS_COUNTERS_CMD, step, allow_error))


def mpls_counter_delta(before: Dict[str, Dict[str, int]], after: Dict[str, Dict[str, int]], ifname: str,
                       key: str = 'rx_packets') -> int:
    """How much the counter *key* of *ifname* grew between two :func:`get_mpls_counters`
    results (0 when either is missing)."""
    if ifname not in before or ifname not in after:
        return 0
    return max(0, after[ifname].get(key, 0) - before[ifname].get(key, 0))
