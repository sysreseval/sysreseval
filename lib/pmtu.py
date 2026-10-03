"""Path MTU discovery helpers for the MTU labs (``lab/em/_DRAFT_/mtu.py`` and ``mtu6.py``).

Pure functions only: header-size arithmetic, ``ping -M do`` command builder and parser of
the iputils error strings, ``ip -j -d link`` parsers (tunnel devices), nftables rule texts
(black hole on ICMP errors, TCP MSS clamping) and a parser of the clamping rules of a
``nft list ruleset`` output.  Fixtures in ``tests/mock_data/pmtu/`` (iputils 20221126,
iproute2 6.19, nftables 1.0.6 in ``sysreseval/base:1.28``).
"""
import json
import re
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any, Dict, List, Optional

IPV4_HDR = 20
IPV6_HDR = 40
ICMP_HDR = 8        # echo request / reply, ICMP and ICMPv6 alike
TCP_HDR = 20
GRE_OVERHEAD = IPV4_HDR + 4   # GRE over IPv4 without key, checksum or sequence number
SIT_OVERHEAD = IPV4_HDR       # 6in4: IPv6 packet inside a plain IPv4 packet
IPV6_MIN_MTU = 1280


# ---------------------------------------------------------------------------
# arithmetic
# ---------------------------------------------------------------------------

def ip_header(ipv6: bool = False) -> int:
    return IPV6_HDR if ipv6 else IPV4_HDR


def max_ping_payload(mtu: int, ipv6: bool = False) -> int:
    """Largest ``ping -s`` payload that fits in one packet of *mtu* bytes."""
    return int(mtu) - ip_header(ipv6) - ICMP_HDR


def mss_for(mtu: int, ipv6: bool = False) -> int:
    """TCP MSS matching a path MTU (no IP or TCP options)."""
    return int(mtu) - ip_header(ipv6) - TCP_HDR


# ---------------------------------------------------------------------------
# ping -M do
# ---------------------------------------------------------------------------

def pmtu_ping_cmd(dest, size: int, ipv6: bool = False, count: int = 1, deadline: int = 2,
                  interval: float = None) -> str:
    """``ping`` with the DF bit set (``-M do``) and a payload of *size* bytes."""
    family = '-6' if ipv6 else '-4'
    every = f" -i {interval}" if interval else ''
    return f"ping {family} -n -M do -s {int(size)} -c {int(count)}{every} -w {int(deadline)} {dest}"


_PING_STATS_RE = re.compile(r'(\d+) packets transmitted, (\d+) (?:packets )?received')
# "From 10.0.0.1 icmp_seq=1 Frag needed and DF set (mtu = 1400)"
_FRAG_NEEDED_RE = re.compile(r'Frag needed and DF set \(mtu\s*=\s*(\d+)\)')
# "ping: local error: message too long, mtu=1400" (IPv4) / "..., mtu: 1400" (IPv6)
_TOO_LONG_RE = re.compile(r'message too long, mtu[=:]\s*(\d+)')
# "From fd00::1 icmp_seq=1 Packet too big: mtu=1400"
_PACKET_TOO_BIG_RE = re.compile(r'Packet too big: mtu[=:]\s*(\d+)')


def parse_ping_errors(output: str) -> Dict[str, Any]:
    """Summary and PMTU-related errors of a ``ping`` output.

    ``{'sent', 'received', 'frag_needed_mtu', 'too_long_mtu', 'packet_too_big_mtu'}``:
    the counters are ``None`` without a statistics block; each ``*_mtu`` is the MTU quoted
    by the first error of that kind, ``None`` when the error did not occur
    (``frag_needed_mtu``: ICMP "fragmentation needed" from a router; ``too_long_mtu``: the
    local stack refused the packet, i.e. the interface MTU or a cached path MTU is smaller;
    ``packet_too_big_mtu``: ICMPv6 Packet Too Big from a router)."""
    text = output or ''
    result: Dict[str, Any] = {'sent': None, 'received': None, 'frag_needed_mtu': None,
                              'too_long_mtu': None, 'packet_too_big_mtu': None}
    m = _PING_STATS_RE.search(text)
    if m:
        result['sent'], result['received'] = int(m.group(1)), int(m.group(2))
    for key, regex in (('frag_needed_mtu', _FRAG_NEEDED_RE), ('too_long_mtu', _TOO_LONG_RE),
                       ('packet_too_big_mtu', _PACKET_TOO_BIG_RE)):
        m = regex.search(text)
        if m:
            result[key] = int(m.group(1))
    return result


def ping_received(output: str) -> int:
    """Number of replies of a ``ping`` output (0 without a statistics block)."""
    return parse_ping_errors(output)['received'] or 0


# ---------------------------------------------------------------------------
# ip -j -d link
# ---------------------------------------------------------------------------

def ip_link_json_cmd(dev: str = None) -> str:
    """``ip -j -d link show [DEV]`` (JSON, with the tunnel parameters)."""
    return f"ip -j -d link show {dev}" if dev else "ip -j -d link show"


def parse_ip_links_json(output: str) -> List[Dict[str, Any]]:
    """The objects of an ``ip -j link show`` output (``[]`` when absent or invalid)."""
    try:
        links = json.loads(output or '[]')
    except ValueError:
        return []
    return [l for l in links if isinstance(l, dict)] if isinstance(links, list) else []


def parse_ip_link_json(output: str) -> Dict[str, Any]:
    """The first object of an ``ip -j -d link show DEV`` output (``{}`` when the device does not exist)."""
    links = parse_ip_links_json(output)
    return links[0] if links else {}


def iface_mtus(output: str) -> Dict[str, Optional[int]]:
    """``{ifname: mtu}`` of an ``ip -j link show`` output."""
    return {l.get('ifname'): l.get('mtu') for l in parse_ip_links_json(output) if l.get('ifname')}


def tunnel_info(link: Dict[str, Any]) -> Dict[str, Any]:
    """``{'kind', 'mtu', 'local', 'remote', 'pmtudisc', 'up'}`` of a parsed link object
    (``kind`` is ``'gre'``, ``'sit'``, ``'ipip'``...; everything is ``None`` for a plain interface
    or an empty object)."""
    info = link.get('linkinfo') or {}
    data = info.get('info_data') or {}
    flags = link.get('flags') or []
    return {'kind': info.get('info_kind'), 'mtu': link.get('mtu'), 'local': data.get('local'),
            'remote': data.get('remote'), 'pmtudisc': data.get('pmtudisc'),
            'up': 'UP' in flags if link else None}


# ---------------------------------------------------------------------------
# nftables texts
# ---------------------------------------------------------------------------

def _addr(a) -> str:
    return str(a.ip) if isinstance(a, (IPv4Interface, IPv6Interface)) else str(a)


def _set(addresses) -> str:
    return "{ " + ", ".join(_addr(a) for a in addresses) + " }"


def nft_drop_pmtu_errors(table: str, daddr4=None, daddr6=None, ipv6: bool = True,
                         chain: str = 'output', hook: str = 'output') -> str:
    """An ``inet`` table whose *chain* drops the ICMP errors that path MTU discovery relies on:
    ICMP "fragmentation needed" (type 3 code 4) and, with *ipv6*, ICMPv6 "packet too big"
    (type 2).  *daddr4* / *daddr6* restrict the drop to the errors sent to those addresses
    (a black hole for the grading probes only); without them every such error is dropped."""
    lines = [f"table inet {table} {{",
             f"    chain {chain} {{",
             f"        type filter hook {hook} priority filter; policy accept;"]
    sel4 = f"ip daddr {_set(daddr4)} " if daddr4 else ''
    lines.append(f"        {sel4}icmp type destination-unreachable icmp code frag-needed drop")
    if ipv6:
        sel6 = f"ip6 daddr {_set(daddr6)} " if daddr6 else ''
        lines.append(f"        {sel6}icmpv6 type packet-too-big drop")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


def nft_mss_clamp(table: str, mss4: int = None, mss6: int = None,
                  chain: str = 'forward', hook: str = 'forward') -> str:
    """An ``inet`` table clamping the MSS of the forwarded SYN segments (``tcp flags syn``
    matches SYN and SYN/ACK, so one router fixes both directions)."""
    lines = [f"table inet {table} {{",
             f"    chain {chain} {{",
             f"        type filter hook {hook} priority mangle; policy accept;"]
    if mss4 is not None:
        lines.append(f"        meta nfproto ipv4 tcp flags syn tcp option maxseg size set {int(mss4)}")
    if mss6 is not None:
        lines.append(f"        meta nfproto ipv6 tcp flags syn tcp option maxseg size set {int(mss6)}")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


_TABLE_RE = re.compile(r'^\s*table\s+(ip6|ip|inet|bridge|arp|netdev)\s+(\S+)\s*\{')
_CHAIN_HOOK_RE = re.compile(r'\btype\s+\w+\s+hook\s+(\w+)\b')
_CLAMP_RE = re.compile(r'tcp option maxseg size set (rt mtu|\d+)')
_NFPROTO_RE = re.compile(r'\bmeta nfproto (ipv4|ipv6)\b')

_FAMILY_OF_TABLE = {'ip': 4, 'ip6': 6}


def mss_clamp_rules(ruleset: str) -> List[Dict[str, Any]]:
    """The MSS clamping rules of a ``nft list ruleset`` output.

    ``[{'family': 4 | 6 | None, 'value': int | 'rt mtu', 'hook': str | None, 'table': str}]``;
    ``family`` is ``None`` for an ``inet`` rule without ``meta nfproto`` (both families)."""
    rules = []
    table_family: Optional[int] = None
    table_name = ''
    hook = None
    for line in (ruleset or '').splitlines():
        m = _TABLE_RE.match(line)
        if m:
            table_family, table_name, hook = _FAMILY_OF_TABLE.get(m.group(1)), m.group(2), None
            continue
        m = _CHAIN_HOOK_RE.search(line)
        if m:
            hook = m.group(1)
            continue
        m = _CLAMP_RE.search(line)
        if not m:
            continue
        family = table_family
        p = _NFPROTO_RE.search(line)
        if p:
            family = 6 if p.group(1) == 'ipv6' else 4
        value = m.group(1)
        rules.append({'family': family, 'value': value if value == 'rt mtu' else int(value),
                      'hook': hook, 'table': table_name})
    return rules


def mss_clamped(rules: List[Dict[str, Any]], family: int, max_mss: int, rt_mtu_ok: bool = False) -> bool:
    """True when a rule of *rules* (``mss_clamp_rules``) clamps the MSS of *family* (4 or 6) to
    at most *max_mss* in a routed hook (``forward`` or ``prerouting``/``postrouting``, not
    ``output``/``input``).  A ``rt mtu`` rule counts only with *rt_mtu_ok* (the caller knows
    whether the route MTU of the router is small enough)."""
    for r in rules:
        if r['family'] not in (family, None):
            continue
        if r['hook'] in ('output', 'input'):
            continue
        if r['value'] == 'rt mtu':
            if rt_mtu_ok:
                return True
        elif r['value'] <= max_mss:
            return True
    return False
