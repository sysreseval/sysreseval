"""Multicast helpers: the grading probe ``lib/mcast_probe.py`` and group address arithmetic.

The probe runs on the hosts of a lab (it is not a hidden machine: the receivers are the hosts the
students see).  State side: :func:`install_mcast_probe`.  Grade side, three steps of one
evaluation: :func:`mcast_recv_cmd` / :func:`mcast_sniff_cmd` start daemons that return at once
(step 1), :func:`mcast_send_cmd` sends a burst of datagrams carrying a token (step 2, blocking),
:func:`get_mcast_dump` reads what the daemons saw (step 3) as :class:`McastProbe` objects
(``ran=False`` on the placeholder of the registration pass or for a daemon that did not run).

Address side: :func:`group_mac` (``01:00:5e`` + the low 23 bits of an IPv4 group),
:func:`mac_aliases` (the 32 groups of 224/4 sharing a MAC address), :func:`multicast_scope`
(the class of an IPv4 or IPv6 multicast address).  The IPv6 solicited-node address and its
``33:33`` MAC address are in ``lib/ipv6.py``.  Tests: ``tests/test_mcast.py``.
"""
import base64
import json
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, ip_address
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from SRE.lib_sre import Grade0, NetScheme0
from bridging import normalize_mac  # noqa: F401  (re-exported for the labs)

#: where install_mcast_probe() copies lib/mcast_probe.py
MCAST_PROBE_PATH = '/usr/local/sbin/mcast_probe.py'
#: default lifetime of a recv / sniff daemon: longer than the three steps of an evaluation
MCAST_LISTEN_DURATION = 30
#: default burst of mcast_send_cmd(): 20 datagrams over 7.6 s after a delay of 2 s, enough for an
#: IGMP report, the PIM joins and an MSDP SA to go through before the end of the burst
MCAST_SEND_COUNT = 20
MCAST_SEND_INTERVAL = 0.4
MCAST_SEND_DELAY = 2
MCAST_SEND_TTL = 16

ALL_MULTICAST = IPv4Network('224.0.0.0/4')
LINK_LOCAL_BLOCK = IPv4Network('224.0.0.0/24')
INTERNETWORK_CONTROL_BLOCK = IPv4Network('224.0.1.0/24')
SSM_BLOCK = IPv4Network('232.0.0.0/8')
GLOP_BLOCK = IPv4Network('233.0.0.0/8')
ADMIN_BLOCK = IPv4Network('239.0.0.0/8')
LOCAL_SCOPE_BLOCK = IPv4Network('239.255.0.0/16')
ORGANIZATION_SCOPE_BLOCK = IPv4Network('239.192.0.0/14')
#: names of multicast_scope()
SCOPE_NAMES = ('link-local', 'internetwork-control', 'ssm', 'glop', 'local-scope', 'organization-scope',
               'admin-scoped', 'global', 'not-multicast')
#: scope nibble of an IPv6 multicast address (RFC 4291 / RFC 7346)
IPV6_SCOPES = {1: 'interface-local', 2: 'link-local', 3: 'realm-local', 4: 'admin-local', 5: 'site-local',
               8: 'organization-local', 0xE: 'global'}


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def _encode(spec: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).decode()


def install_mcast_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy lib/mcast_probe.py to MCAST_PROBE_PATH on *machine*."""
    script = Path(__file__).with_name('mcast_probe.py').read_text()
    net_scheme.file(machine, MCAST_PROBE_PATH, script, permissions=0o755, step=step)


# ---------------------------------------------------------------------------
# command builders (static for given arguments: the grader registers them on every pass)
# ---------------------------------------------------------------------------

Join = Union[str, IPv4Address, IPv6Address, Tuple]


def _joins(joins: Iterable[Join]) -> List[dict]:
    """``[group | (group, source | None)]`` → the "joins" list of a recv spec."""
    result = []
    for join in joins:
        if isinstance(join, (tuple, list)):
            group, source = join[0], (join[1] if len(join) > 1 else None)
        else:
            group, source = join, None
        entry = {'group': str(ip_address(str(group)))}
        if source is not None:
            entry['source'] = str(ip_address(str(source).split('/')[0]))
        result.append(entry)
    return result


def _family(address) -> int:
    return ip_address(str(address).split('/')[0]).version


def mcast_recv_cmd(tag: str, port: int, joins: Sequence[Join], iface: str = 'eth0',
                   duration: float = MCAST_LISTEN_DURATION) -> str:
    """Shell command (re)starting a receiver daemon *tag* on *iface*: joins every group of
    *joins* (a group, or ``(group, source)`` for a source-specific join) and counts what reaches
    UDP *port*.  The family is the one of the first group."""
    spec_joins = _joins(joins)
    family = _family(spec_joins[0]['group']) if spec_joins else 4
    spec = {'tag': tag, 'family': family, 'port': int(port), 'iface': iface, 'duration': duration,
            'joins': spec_joins}
    return f"python3 {MCAST_PROBE_PATH} recv {_encode(spec)}"


def mcast_sniff_cmd(tag: str, iface: str, groups: Iterable, duration: float = MCAST_LISTEN_DURATION) -> str:
    """Shell command (re)starting a sniffer daemon *tag*: counts the frames received on *iface*
    for each of *groups* (no join, nothing sent) and the IGMP messages seen."""
    spec = {'tag': tag, 'iface': iface, 'duration': duration,
            'groups': [str(ip_address(str(g))) for g in groups]}
    return f"python3 {MCAST_PROBE_PATH} sniff {_encode(spec)}"


def mcast_send_cmd(group, port: int, token: str, count: int = MCAST_SEND_COUNT,
                   interval: float = MCAST_SEND_INTERVAL, delay: float = MCAST_SEND_DELAY,
                   ttl: int = MCAST_SEND_TTL, source=None, iface: Optional[str] = None,
                   background: Optional[str] = None) -> str:
    """Shell command sending *count* datagrams carrying *token* to *group*:*port* (blocking:
    ``delay + (count - 1) * interval`` seconds), from the address *source* of the machine when
    given (the source address of the datagrams) and / or out of *iface*.  *background*: a tag,
    the burst is then sent by a daemon and the command returns at once (two bursts of one
    machine at the same time: the first one in the background)."""
    spec = {'family': _family(group), 'group': str(ip_address(str(group))), 'port': int(port), 'token': token,
            'count': count, 'interval': interval, 'delay': delay, 'ttl': ttl}
    if source is not None:
        spec['source'] = str(ip_address(str(source).split('/')[0]))
    if iface:
        spec['iface'] = iface
    if background:
        spec['background'] = True
        spec['tag'] = background
    return f"python3 {MCAST_PROBE_PATH} send {_encode(spec)}"


def mcast_send_duration(count: int = MCAST_SEND_COUNT, interval: float = MCAST_SEND_INTERVAL,
                        delay: float = MCAST_SEND_DELAY) -> float:
    """How long mcast_send_cmd() blocks."""
    return delay + max(0, count - 1) * interval


def mcast_dump_cmd(*tags: str) -> str:
    return f"python3 {MCAST_PROBE_PATH} dump {' '.join(tags)}"


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


@dataclass
class McastGroup:
    count: int = 0
    sources: Dict[str, int] = field(default_factory=dict)
    tokens: Dict[str, int] = field(default_factory=dict)
    ttl_min: Optional[int] = None
    ttl_max: Optional[int] = None
    first_age: Optional[float] = None
    last_age: Optional[float] = None


@dataclass
class McastProbe:
    tag: str
    ran: bool = False
    kind: Optional[str] = None
    uptime: Optional[float] = None
    heartbeat_age: Optional[float] = None
    done: bool = False
    groups: Dict[str, McastGroup] = field(default_factory=dict)
    igmp: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


def _canonical(address) -> str:
    try:
        return str(ip_address(str(address).split('/')[0]))
    except ValueError:
        return str(address)


def _int_or_none(value) -> Optional[int]:
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value) -> Optional[float]:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def _counts(raw) -> Dict[str, int]:
    result = {}
    for key, value in (raw or {}).items() if isinstance(raw, dict) else ():
        number = _int_or_none(value)
        if number is not None:
            result[_canonical(key) if '.' in str(key) or ':' in str(key) else str(key)] = number
    return result


def _parse_one(tag: str, raw) -> McastProbe:
    if not isinstance(raw, dict) or raw.get('kind') not in ('recv', 'sniff') or raw.get('uptime') is None:
        errors = list(raw.get('errors') or []) if isinstance(raw, dict) else []
        return McastProbe(tag=tag, errors=[str(e) for e in errors])
    groups = {}
    for group, g in (raw.get('groups') or {}).items():
        if not isinstance(g, dict):
            continue
        groups[_canonical(group)] = McastGroup(
            count=_int_or_none(g.get('count')) or 0,
            sources=_counts(g.get('sources')),
            tokens={str(k): v for k, v in _counts(g.get('tokens')).items()},
            ttl_min=_int_or_none(g.get('ttl_min')), ttl_max=_int_or_none(g.get('ttl_max')),
            first_age=_float_or_none(g.get('first_age')), last_age=_float_or_none(g.get('last_age')))
    return McastProbe(tag=tag, ran=True, kind=raw.get('kind'), uptime=_float_or_none(raw.get('uptime')),
                      heartbeat_age=_float_or_none(raw.get('heartbeat_age')), done=bool(raw.get('done')),
                      groups=groups, igmp={str(k): v for k, v in _counts(raw.get('igmp')).items()},
                      errors=[str(e) for e in raw.get('errors') or []])


def parse_mcast_dump(output: str, tags: Iterable[str] = ()) -> Dict[str, McastProbe]:
    """The document of ``mcast_probe.py dump`` → ``{tag: McastProbe}``; every tag of *tags*
    missing from the output (the placeholder, garbage) is a ``McastProbe(ran=False)``."""
    try:
        document = json.loads(output)
    except (TypeError, ValueError):
        document = {}
    if not isinstance(document, dict):
        document = {}
    result = {tag: _parse_one(tag, raw) for tag, raw in document.items()}
    for tag in tags:
        result.setdefault(tag, McastProbe(tag=tag))
    return result


def get_mcast_dump(grade: Grade0, machine: str, tags: Sequence[str], step: int = 1,
                   timeout: int = 20) -> Dict[str, McastProbe]:
    output, _ = grade.test(machine, mcast_dump_cmd(*tags), step=step, timeout=timeout, allow_error=True)
    return parse_mcast_dump(output, tags)


def received(probe: McastProbe, group, token: Optional[str] = None, source=None) -> int:
    """Datagrams of *group* the probe got (or saw), only those carrying *token* when given, only
    those from *source* when given (both: the smaller count)."""
    entry = probe.groups.get(_canonical(group)) if probe is not None and probe.ran else None
    if entry is None:
        return 0
    counts = [entry.count]
    if token is not None:
        counts.append(entry.tokens.get(str(token), 0))
    if source is not None:
        counts.append(entry.sources.get(_canonical(source), 0))
    return min(counts)


# ---------------------------------------------------------------------------
# addresses
# ---------------------------------------------------------------------------


def group_mac(group) -> str:
    """Ethernet address of an IPv4 group: ``01:00:5e`` + its low 23 bits (RFC 1112 6.4); of an
    IPv6 group: ``33:33`` + its last four bytes (RFC 2464)."""
    address = ip_address(str(group).split('/')[0])
    if address.version == 6:
        return '33:33:' + ':'.join(f'{b:02x}' for b in address.packed[12:])
    low = int(address) & 0x7FFFFF
    return '01:00:5e:' + ':'.join(f'{b:02x}' for b in low.to_bytes(3, 'big'))


def mac_aliases(group, within: IPv4Network = ALL_MULTICAST) -> List[IPv4Address]:
    """The groups of *within* with the same Ethernet address as *group* (itself included): the
    32 groups of 224/4 differing only by the five bits the mapping drops."""
    address = IPv4Address(str(group).split('/')[0])
    low = int(address) & 0x7FFFFF
    candidates = (IPv4Address((0xE0 << 24) | (high << 23) | low) for high in range(32))
    return [c for c in candidates if c in within]


def multicast_scope(address) -> str:
    """Class of a multicast address: one of SCOPE_NAMES for IPv4 (RFC 5771, 2365, 4607, 3180),
    the name of the scope nibble (IPV6_SCOPES) for IPv6."""
    addr = ip_address(str(address).split('/')[0])
    if addr.version == 6:
        if not addr.is_multicast:
            return 'not-multicast'
        return IPV6_SCOPES.get(addr.packed[1] & 0x0F, f"scope-{addr.packed[1] & 0x0F:x}")
    if addr not in ALL_MULTICAST:
        return 'not-multicast'
    for block, name in ((LINK_LOCAL_BLOCK, 'link-local'), (INTERNETWORK_CONTROL_BLOCK, 'internetwork-control'),
                        (SSM_BLOCK, 'ssm'), (GLOP_BLOCK, 'glop'), (LOCAL_SCOPE_BLOCK, 'local-scope'),
                        (ORGANIZATION_SCOPE_BLOCK, 'organization-scope'), (ADMIN_BLOCK, 'admin-scoped')):
        if addr in block:
            return name
    return 'global'


def glop_block(asn: int) -> IPv4Network:
    """The /24 of 233/8 of a 16-bit AS number (GLOP, RFC 3180): 233.<AS high>.<AS low>.0/24."""
    if not 0 < int(asn) < 65536:
        raise ValueError(f"glop_block: {asn} is not a 16-bit AS number")
    return IPv4Network(f"233.{int(asn) >> 8}.{int(asn) & 0xFF}.0/24")
