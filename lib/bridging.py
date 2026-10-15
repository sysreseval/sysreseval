"""Linux bridging helpers of the VLAN / bridges / brouter lab (``lab/sre/_DRAFT_misc/vlan.py``)
and of the bridge / STP lab (``lab/sre/_DRAFT_misc/bridge.py``).

Grade side (the HTTP / UDP echo server both labs install is in ``lib/server_echo_helpers.py``):
wrappers around one command each (``ip -j -d link``, ``ip -j -4 addr``, ``bridge -j fdb``,
``nft list ruleset``, ``iptables -t mangle -S``, ``/proc/sys``) and the pure parsers
they rely on: VLAN sub-interfaces, bridges, their ports and their STP state from the JSON of
``ip -d link`` (:func:`bridge_info`), the forwarding database of a bridge (:func:`parse_fdb_json`),
the rules of the nftables *bridge* family (:func:`parse_bridge_rules`: filtering by MAC or IP
address, :func:`drop_rules_for`; the rules that divert a frame to the IP stack, ``meta pkttype
set host`` + ``ether daddr set <bridge MAC>`` or ``meta broute set 1`` of newer nftables,
:func:`parse_broute_rules`), the ``TTL`` target of iptables.  Fixtures of the parsers:
``tests/mock_data/vlan/`` and ``tests/mock_data/bridge/`` (iproute2 6.19, nftables 1.0.6,
iptables 1.8.9 nft, Linux 6.12, in ``sysreseval/base:1.30``).

Facts (iproute2 and kernel sources, confirmed in the containers): the bridge timers
(``ageing_time``, ``hello_time``, ``forward_delay``, ``max_age``) are given and printed in
**centiseconds** (``ip link set br0 type bridge ageing_time 3000`` = 30 s; the ``ip-link`` man
page says seconds); bridge ids are printed ``8000.1a:a:93:41:14:f3`` with unpadded octets; a
learned fdb entry has an empty ``state``, the ports' own addresses are ``permanent``; a bridge
with STP off floods the BPDUs (loop detection by the other bridges) and a lone STP bridge
receiving its own BPDU blocks its port with the higher port id; a port takes 2 x forward_delay
(30 s) to reach ``forwarding``.
"""
import json
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from SRE.lib_sre import Grade0
from firewall import get_ruleset
from openvpn import get_ip_addresses_json, interface_of_address, parse_ip_addr_json  # noqa: F401
from pmtu import ip_link_json_cmd, parse_ip_links_json  # noqa: F401

MANGLE_RULES_CMD = "iptables -t mangle -S 2>/dev/null"

_IIF_RE = re.compile(r'\biif(?:name)?\s+"?([^\s"]+)"?')
_OIF_RE = re.compile(r'\boif(?:name)?\s+"?([^\s"]+)"?')
_SADDR_RE = re.compile(r'\bip saddr\s+(!=\s*)?(\S+)')
_DADDR_RE = re.compile(r'\bip daddr\s+(!=\s*)?(\S+)')
_ETHER_SADDR_RE = re.compile(r'\bether saddr\s+(?!set\b)([0-9a-fA-F:]{17})')
_ETHER_DADDR_RE = re.compile(r'\bether daddr\s+(?!set\b)([0-9a-fA-F:]{17})')
_DPORT_RE = re.compile(r'\b(tcp|udp)\s+dport\s+(\d+)')
_MAC_SET_RE = re.compile(r'\bether daddr set\s+([0-9a-fA-F:]{17})')
_VERDICT_RE = re.compile(r'(?:^|\s)(accept|drop|reject|continue|return|jump\s+\S+|goto\s+\S+)(?:\s+with\s+.*)?\s*$')
_TABLE_RE = re.compile(r'^table\s+(\S+)\s+(\S+)\s*\{')
_CHAIN_RE = re.compile(r'^\s*chain\s+(\S+)\s*\{')
_HOOK_RE = re.compile(r'^\s*type\s+\S+\s+hook\s+(\S+)')
_BRIDGE_ID_RE = re.compile(r'^\s*([0-9a-fA-F]{1,4})\.((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})\s*$')
_IPT_RULE_RE = re.compile(r'^-A\s+(\S+)\s*(.*)$')
_BPDU_RE = re.compile(r'STP 802\.1d, (Config|Topology Change Notification), (?:Flags \[([^\]]*)\], )?'
                      r'(?:bridge-id (\S+)\.([0-9a-fA-F]{4}), )?length (\d+)')
_BPDU_TIMERS_RE = re.compile(r'message-age ([\d.]+)s, max-age ([\d.]+)s, hello-time ([\d.]+)s, forwarding-delay ([\d.]+)s')
_BPDU_ROOT_RE = re.compile(r'root-id (\S+), root-pathcost (\d+)')


# ---------------------------------------------------------------------------
# ip link: VLAN sub-interfaces and bridges
# ---------------------------------------------------------------------------


def get_ip_links(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """The objects of ``ip -j -d link show`` on *machine_name* (``[]`` on failure)."""
    out, code = grade.test(machine_name, ip_link_json_cmd(), step=step, allow_error=True)
    return parse_ip_links_json(out) if code == 0 else []


def links_by_name(links: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """``{ifname: link object}`` (the ``@parent`` suffix of the text output never appears in JSON)."""
    return {str(link.get('ifname', '')).split('@', 1)[0]: link for link in links if link.get('ifname')}


def link_up(links: List[Dict[str, Any]], ifname: str) -> bool:
    """True iff *ifname* exists and has the ``UP`` flag."""
    link = links_by_name(links).get(ifname)
    return bool(link) and 'UP' in (link.get('flags') or [])


def link_master(links: List[Dict[str, Any]], ifname: str) -> Optional[str]:
    """The ``master`` (bridge or bond) of *ifname*, ``None`` when it has none or does not exist."""
    link = links_by_name(links).get(ifname)
    return link.get('master') if link else None


def link_address(links: List[Dict[str, Any]], ifname: str) -> str:
    """The MAC address of *ifname* (``''`` when unknown)."""
    link = links_by_name(links).get(ifname)
    return str(link.get('address', '')) if link else ''


def vlan_links(links: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """The 802.1Q sub-interfaces of an ``ip -j -d link`` output:
    ``{'eth0.111': {'id': 111, 'link': 'eth0', 'up': True, 'master': 'brodd' | None}}``."""
    result = {}
    for name, link in links_by_name(links).items():
        info = link.get('linkinfo') or {}
        if info.get('info_kind') != 'vlan':
            continue
        data = info.get('info_data') or {}
        result[name] = {'id': data.get('id'), 'link': link.get('link'), 'up': 'UP' in (link.get('flags') or []),
                        'master': link.get('master')}
    return result


def bridge_ports(links: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """The bridges of an ``ip -j -d link`` output with their ports: ``{'brodd': ['eth0.111', 'eth1']}``
    (a bridge without port has an empty list)."""
    by_name = links_by_name(links)
    bridges = {name for name, link in by_name.items() if (link.get('linkinfo') or {}).get('info_kind') == 'bridge'}
    result = {name: [] for name in sorted(bridges)}
    for name, link in by_name.items():
        master = link.get('master')
        if master in result:
            result[master].append(name)
    for ports in result.values():
        ports.sort()
    return result


def addresses_of(addresses: Dict[str, List[dict]], ifname: str) -> List[str]:
    """The ``a.b.c.d/n`` addresses of *ifname* in a ``parse_ip_addr_json()`` result."""
    return [f"{entry['local']}/{entry['prefixlen']}" for entry in addresses.get(ifname, [])]


# ---------------------------------------------------------------------------
# ip link: bridges and their STP state
# ---------------------------------------------------------------------------


def normalize_mac(text) -> str:
    """``aa:bb:cc:dd:ee:ff`` (lower case, zero-padded octets) of a MAC address written with
    ``:`` or ``-`` separators, an ``EUI`` object included; unpadded octets are accepted
    (iproute2 prints the bridge ids as ``8000.1a:a:93:41:14:f3``).  ``''`` when unreadable."""
    parts = re.split(r'[:-]', str(text or '').strip().lower())
    if len(parts) != 6 or not all(re.fullmatch(r'[0-9a-f]{1,2}', part) for part in parts):
        return ''
    return ':'.join(part.zfill(2) for part in parts)


def parse_bridge_id(text) -> Tuple[Optional[int], str]:
    """``(priority, mac)`` of a bridge id as iproute2 (``'8000.1a:a:93:41:14:f3'``) or tcpdump
    (``'1000.02:53:52:aa:bb:cc'``) print it: the priority is the hexadecimal prefix (``0x8000``
    = 32768), the MAC is normalised.  ``(None, '')`` when unreadable."""
    m = _BRIDGE_ID_RE.match(str(text or ''))
    if not m:
        return None, ''
    return int(m.group(1), 16), normalize_mac(m.group(2))


def _int_or_none(value) -> Optional[int]:
    """The integer of a JSON number or of a ``"0x1"`` / ``"1"`` string, ``None`` otherwise."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _centiseconds(value) -> Optional[float]:
    """Seconds of a bridge timer printed by ``ip -d link`` (centiseconds, kernel clock_t)."""
    number = _int_or_none(value)
    return None if number is None else number / 100


def bridge_info(links: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    """The bridge *name* of an ``ip -j -d link`` output with its STP state, ``None`` when it
    does not exist or is not a bridge:

    - ``address`` (the MAC of the bridge: the lowest of its ports unless set by hand), ``up``,
    - ``stp`` (``stp_state == 1``), ``priority`` (32768 by default),
    - ``bridge_id`` / ``root_id`` as ``(priority, mac)`` tuples (:func:`parse_bridge_id`),
      ``bridge_id_text`` / ``root_id_text`` as printed, ``is_root`` (the two ids are equal),
    - ``root_port`` (the name of the port towards the root bridge, ``None`` on the root bridge
      or when STP is off), ``root_path_cost``, ``topology_change``,
    - ``ageing_time``, ``hello_time``, ``forward_delay``, ``max_age`` **in seconds** (the
      JSON holds centiseconds: ``ageing_time 30000`` = 300 s),
    - ``ports``: ``{ifname: {'state' ('disabled' | 'listening' | 'learning' | 'forwarding' |
      'blocking', None without ``-d``), 'up', 'priority', 'cost', 'id' ('0x8001'), 'no' (1),
      'designated_root', 'designated_bridge' (tuples), 'designated_port', 'designated_cost'}}``.
    """
    by_name = links_by_name(links)
    link = by_name.get(name)
    if not link or (link.get('linkinfo') or {}).get('info_kind') != 'bridge':
        return None
    data = (link.get('linkinfo') or {}).get('info_data') or {}
    ports: Dict[str, Dict[str, Any]] = {}
    for ifname, port in by_name.items():
        if port.get('master') != name:
            continue
        slave = (port.get('linkinfo') or {}).get('info_slave_data') or {}
        ports[ifname] = {
            'state': slave.get('state'), 'up': 'UP' in (port.get('flags') or []),
            'priority': _int_or_none(slave.get('priority')), 'cost': _int_or_none(slave.get('cost')),
            'id': slave.get('id'), 'no': _int_or_none(slave.get('no')),
            'designated_root': parse_bridge_id(slave.get('root_id')),
            'designated_bridge': parse_bridge_id(slave.get('bridge_id')),
            'designated_port': _int_or_none(slave.get('designated_port')),
            'designated_cost': _int_or_none(slave.get('designated_cost')),
        }
    bridge_id = parse_bridge_id(data.get('bridge_id'))
    root_id = parse_bridge_id(data.get('root_id'))
    root_port_no = _int_or_none(data.get('root_port'))
    root_port = None
    if root_port_no:
        root_port = next((ifname for ifname, port in ports.items() if port['no'] == root_port_no), None)
    return {
        'address': normalize_mac(link.get('address')), 'up': 'UP' in (link.get('flags') or []),
        'stp': _int_or_none(data.get('stp_state')) == 1, 'priority': _int_or_none(data.get('priority')),
        'bridge_id': bridge_id, 'root_id': root_id,
        'bridge_id_text': data.get('bridge_id'), 'root_id_text': data.get('root_id'),
        'is_root': bridge_id[1] != '' and bridge_id == root_id,
        'root_port': root_port, 'root_path_cost': _int_or_none(data.get('root_path_cost')),
        'topology_change': _int_or_none(data.get('topology_change')),
        'ageing_time': _centiseconds(data.get('ageing_time')), 'hello_time': _centiseconds(data.get('hello_time')),
        'forward_delay': _centiseconds(data.get('forward_delay')), 'max_age': _centiseconds(data.get('max_age')),
        'ports': ports,
    }


def port_states(info: Optional[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    """``{port: STP state}`` of a :func:`bridge_info` result (``{}`` for ``None``)."""
    return {ifname: port['state'] for ifname, port in (info or {}).get('ports', {}).items()}


def parse_tcpdump_stp(output: str) -> List[Dict[str, Any]]:
    """The BPDUs of a ``tcpdump -n [-v] -i eth0 stp`` output (tcpdump 4.99): one dict per frame with
    ``type`` (``'Config'`` or ``'Topology Change Notification'``), ``flags`` (``'none'``,
    ``'Topology change'``...), ``bridge_id`` (the sender, a :func:`parse_bridge_id` tuple),
    ``port_id`` (``0x8001``, int), ``length``, and with ``-v`` ``root_id`` (tuple),
    ``root_path_cost``, ``message_age``, ``max_age``, ``hello_time``, ``forward_delay`` (seconds,
    ``None`` without ``-v``)."""
    frames: List[Dict[str, Any]] = []
    for raw in (output or '').splitlines():
        line = raw.strip()
        m = _BPDU_RE.search(line)
        if m:
            frames.append({'type': m.group(1), 'flags': m.group(2) or 'none',
                           'bridge_id': parse_bridge_id(m.group(3)) if m.group(3) else (None, ''),
                           'port_id': int(m.group(4), 16) if m.group(4) else None, 'length': int(m.group(5)),
                           'root_id': (None, ''), 'root_path_cost': None, 'message_age': None, 'max_age': None,
                           'hello_time': None, 'forward_delay': None})
            continue
        if not frames:
            continue
        m = _BPDU_TIMERS_RE.search(line)
        if m:
            frames[-1].update(message_age=float(m.group(1)), max_age=float(m.group(2)), hello_time=float(m.group(3)),
                              forward_delay=float(m.group(4)))
            continue
        m = _BPDU_ROOT_RE.search(line)
        if m:
            frames[-1].update(root_id=parse_bridge_id(m.group(1)), root_path_cost=int(m.group(2)))
    return frames


# ---------------------------------------------------------------------------
# bridge fdb: the forwarding database (MAC table) of a bridge
# ---------------------------------------------------------------------------


def fdb_cmd(bridge: str) -> str:
    """``bridge -j fdb show br <bridge>`` (the entries of one bridge, JSON)."""
    return f"bridge -j fdb show br {shlex.quote(str(bridge))}"


def parse_fdb_json(output: str) -> List[Dict[str, Any]]:
    """The entries of a ``bridge -j fdb show`` output: one dict per entry with ``mac``
    (normalised), ``ifname`` (the port), ``master`` (the bridge, ``None`` for a ``self``
    entry of a device), ``vlan`` (``None`` when absent), ``flags`` (list: ``self``,
    ``master``, ``router``, ``extern_learn``...) and ``state`` (``''`` for a learned entry,
    ``'permanent'`` for the own addresses of the ports and of the bridge, ``'static'``,
    ``'stale'`` for an expired one).  Each port address appears for VLAN 0 and for the
    default PVID.  ``[]`` when invalid."""
    try:
        entries = json.loads(output or '[]')
    except ValueError:
        return []
    if not isinstance(entries, list):
        return []
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or not normalize_mac(entry.get('mac')):
            continue
        result.append({'mac': normalize_mac(entry.get('mac')), 'ifname': entry.get('ifname'),
                       'master': entry.get('master'), 'vlan': _int_or_none(entry.get('vlan')),
                       'flags': [str(f) for f in (entry.get('flags') or [])], 'state': str(entry.get('state') or '')})
    return result


def learned_fdb_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The entries learned from the traffic (neither ``permanent`` nor ``static``, not ``self``)."""
    return [e for e in entries if e['state'] not in ('permanent', 'static') and 'self' not in e['flags']]


def fdb_port_of(entries: List[Dict[str, Any]], mac, learned_only: bool = True) -> Optional[str]:
    """The port (``ifname``) on which *mac* (a string or an ``EUI``) is known, ``None`` when it
    is not; *learned_only* ignores the ``permanent`` / ``static`` entries."""
    wanted = normalize_mac(mac)
    candidates = learned_fdb_entries(entries) if learned_only else entries
    for entry in candidates:
        if entry['mac'] == wanted:
            return entry['ifname']
    return None


def get_fdb(grade: Grade0, machine_name: str, bridge: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_fdb_json` of ``bridge -j fdb show br <bridge>`` on *machine_name* (``[]`` on
    failure)."""
    out, code = grade.test(machine_name, fdb_cmd(bridge), step=step, allow_error=True)
    return parse_fdb_json(out) if code == 0 else []


# ---------------------------------------------------------------------------
# nftables bridge family: filtering rules, and the rules diverting frames to the IP stack
# ---------------------------------------------------------------------------


def parse_bridge_rules(ruleset: str) -> List[Dict[str, Any]]:
    """Every rule of the *bridge* family of an ``nft list ruleset`` output (the *ip* / *inet*
    families, e.g. the NAT tables of Docker, are ignored).  One dict per rule: ``table``,
    ``chain``, ``hook`` (``'forward'``..., ``None`` in a regular chain), ``iif`` / ``oif``
    (``iifname "eth1"``), ``ether_saddr`` / ``ether_daddr`` (the MAC matched, normalised;
    not the ``ether daddr set`` action), ``saddr`` / ``daddr`` (``ip saddr`` / ``ip daddr`` as
    written: an address or a prefix) with ``saddr_neg`` / ``daddr_neg`` (``!=``), ``l4proto``
    and ``dport``, ``verdict`` (``'drop'``, ``'accept'``, ``'reject'``, ``'jump X'``...,
    ``None``), the brouter actions ``pkttype_host`` (``meta pkttype set host``), ``daddr_mac``
    (the MAC of ``ether daddr set``, lower case) and ``broute`` (``meta broute set 1``), and
    ``text`` (the line)."""
    rules: List[Dict[str, Any]] = []
    family = table = chain = hook = None
    for raw in (ruleset or '').splitlines():
        line = raw.strip()
        m = _TABLE_RE.match(line)
        if m:
            family, table, chain, hook = m.group(1), m.group(2), None, None
            continue
        m = _CHAIN_RE.match(line)
        if m:
            chain, hook = m.group(1), None
            continue
        m = _HOOK_RE.match(line)
        if m:
            hook = m.group(1)
            continue
        if family != 'bridge' or chain is None or not line or line.startswith(('}', '#', 'policy', 'type ')):
            continue
        dport = _DPORT_RE.search(line)
        iif, oif = _IIF_RE.search(line), _OIF_RE.search(line)
        saddr, daddr = _SADDR_RE.search(line), _DADDR_RE.search(line)
        ether_saddr, ether_daddr = _ETHER_SADDR_RE.search(line), _ETHER_DADDR_RE.search(line)
        mac_set = _MAC_SET_RE.search(line)
        verdict = _VERDICT_RE.search(line)
        rules.append({
            'table': table, 'chain': chain, 'hook': hook,
            'iif': iif.group(1) if iif else None, 'oif': oif.group(1) if oif else None,
            'ether_saddr': normalize_mac(ether_saddr.group(1)) if ether_saddr else None,
            'ether_daddr': normalize_mac(ether_daddr.group(1)) if ether_daddr else None,
            'saddr': saddr.group(2) if saddr else None, 'saddr_neg': bool(saddr and saddr.group(1)),
            'daddr': daddr.group(2) if daddr else None, 'daddr_neg': bool(daddr and daddr.group(1)),
            'l4proto': dport.group(1) if dport else None, 'dport': int(dport.group(2)) if dport else None,
            'verdict': ' '.join(verdict.group(1).split()) if verdict else None,
            'pkttype_host': 'meta pkttype set host' in line,
            'daddr_mac': mac_set.group(1).lower() if mac_set else None,
            'broute': re.search(r'\bmeta broute set 1\b', line) is not None,
            'text': line,
        })
    return rules


_BROUTE_KEYS = ('table', 'chain', 'hook', 'iif', 'saddr', 'daddr', 'l4proto', 'dport', 'pkttype_host', 'daddr_mac',
                'broute', 'text')


def parse_broute_rules(ruleset: str) -> List[Dict[str, Any]]:
    """The rules of the *bridge* family of an ``nft list ruleset`` output that divert a frame to
    the IP stack of the bridge (a *brouter*): ``meta pkttype set host`` with ``ether daddr set``,
    or ``meta broute set 1`` (nftables >= 1.0.7).

    One dict per such rule: ``table``, ``chain``, ``hook`` (``'prerouting'``...), ``iif``,
    ``saddr``, ``daddr`` (as written: an address or a prefix, ``None`` when absent), ``l4proto``
    and ``dport`` (``'tcp'``, 8080), ``pkttype_host``, ``daddr_mac`` (the MAC set, lower case),
    ``broute`` (``meta broute set 1`` seen), ``text`` (the line).  The *ip* and *inet* families
    (the NAT and mangle tables of the routers) are ignored.  A projection of
    :func:`parse_bridge_rules` on the rules carrying one of the three actions.
    """
    return [{key: rule[key] for key in _BROUTE_KEYS} for rule in parse_bridge_rules(ruleset)
            if rule['broute'] or rule['pkttype_host'] or rule['daddr_mac']]


def rule_diverts(rule: Dict[str, Any]) -> bool:
    """True iff the rule really hands the frame to the IP stack: ``meta broute set 1``, or
    ``meta pkttype set host`` together with ``ether daddr set``."""
    return bool(rule.get('broute') or (rule.get('pkttype_host') and rule.get('daddr_mac')))


def _covers(written: Optional[str], address) -> bool:
    """True iff the address or prefix *written* in a rule covers *address*."""
    if not written:
        return False
    from ipaddress import ip_address, ip_network
    try:
        wanted = ip_address(str(address).split('/')[0])
        if '/' in written:
            return wanted in ip_network(written, strict=False)
        return ip_address(written) == wanted
    except ValueError:
        return False


def broute_rules_for(rules: List[Dict[str, Any]], src=None, dst=None, dport: int = None,
                     diverting: bool = True) -> List[Dict[str, Any]]:
    """The rules of :func:`parse_broute_rules` matching the given source address, destination
    address and destination port (an absent match in the rule is not a constraint; a given
    *src* / *dst* must be covered by the rule's prefix).  *diverting* keeps the complete rules
    only (:func:`rule_diverts`)."""
    result = []
    for rule in rules:
        if diverting and not rule_diverts(rule):
            continue
        if src is not None and not _covers(rule['saddr'], src):
            continue
        if dst is not None and not _covers(rule['daddr'], dst):
            continue
        if dport is not None and rule['dport'] != dport:
            continue
        result.append(rule)
    return result


def get_broute_rules(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_broute_rules` of ``nft list ruleset`` on *machine_name*."""
    return parse_broute_rules(get_ruleset(grade, machine_name, step=step))


def drop_rules_for(rules: List[Dict[str, Any]], mac=None, ip=None, hook: str = None) -> List[Dict[str, Any]]:
    """The rules of :func:`parse_bridge_rules` with the verdict ``drop`` that concern *mac*
    (``ether saddr`` or ``ether daddr`` equal to it, a string or an ``EUI``) **or** *ip* (a
    non-negated ``ip saddr`` / ``ip daddr`` covering it), in the chains of *hook* when given
    (``'forward'``).  With neither *mac* nor *ip*, every drop rule."""
    wanted_mac = normalize_mac(mac) if mac is not None else None
    result = []
    for rule in rules:
        if rule['verdict'] != 'drop' or (hook is not None and rule['hook'] != hook):
            continue
        by_mac = wanted_mac is not None and wanted_mac in (rule['ether_saddr'], rule['ether_daddr'])
        by_ip = ip is not None and ((not rule['saddr_neg'] and _covers(rule['saddr'], ip))
                                    or (not rule['daddr_neg'] and _covers(rule['daddr'], ip)))
        if mac is None and ip is None or by_mac or by_ip:
            result.append(rule)
    return result


def get_bridge_rules(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_bridge_rules` of ``nft list ruleset`` on *machine_name*."""
    return parse_bridge_rules(get_ruleset(grade, machine_name, step=step))


# ---------------------------------------------------------------------------
# iptables: the TTL target of the mangle table
# ---------------------------------------------------------------------------


def parse_iptables_save(text: str) -> List[Dict[str, Any]]:
    """The ``-A`` rules of an ``iptables -S`` / ``iptables-save`` output: one dict per rule with
    ``chain``, ``src``, ``dst``, ``in``, ``out``, ``proto`` (as written, ``None`` when absent),
    ``target`` (``-j``), ``args`` (the words after the target) and ``text``."""
    rules = []
    for raw in (text or '').splitlines():
        m = _IPT_RULE_RE.match(raw.strip())
        if not m:
            continue
        chain, rest = m.group(1), m.group(2)
        try:
            tokens = shlex.split(rest)
        except ValueError:
            tokens = rest.split()
        rule = {'chain': chain, 'src': None, 'dst': None, 'in': None, 'out': None, 'proto': None, 'target': None,
                'args': [], 'text': raw.strip()}
        options = {'-s': 'src', '--source': 'src', '-d': 'dst', '--destination': 'dst', '-i': 'in',
                   '--in-interface': 'in', '-o': 'out', '--out-interface': 'out', '-p': 'proto', '--protocol': 'proto'}
        i, after_target = 0, False
        while i < len(tokens):
            token = tokens[i]
            if after_target:
                rule['args'].append(token)
            elif token in ('-j', '--jump', '-g', '--goto') and i + 1 < len(tokens):
                rule['target'] = tokens[i + 1]
                after_target = True
                i += 1
            elif token in options and i + 1 < len(tokens):
                rule[options[token]] = tokens[i + 1]
                i += 1
            elif token == '!':
                pass
            else:
                rule['args'].append(token)
            i += 1
        rules.append(rule)
    return rules


def ttl_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The rules of :func:`parse_iptables_save` whose target is ``TTL``, with ``op``
    (``'inc'``, ``'dec'`` or ``'set'``) and ``value`` added (``None`` when unreadable)."""
    result = []
    for rule in rules:
        if rule.get('target') != 'TTL':
            continue
        op = value = None
        args = rule.get('args') or []
        for i, arg in enumerate(args):
            if arg in ('--ttl-inc', '--ttl-dec', '--ttl-set') and i + 1 < len(args) and args[i + 1].isdigit():
                op, value = arg[6:], int(args[i + 1])
        result.append({**rule, 'op': op, 'value': value})
    return result


def get_mangle_rules(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_iptables_save` of ``iptables -t mangle -S`` on *machine_name*."""
    out, code = grade.test(machine_name, MANGLE_RULES_CMD, step=step, allow_error=True)
    return parse_iptables_save(out) if code == 0 else []


# ---------------------------------------------------------------------------
# /proc/sys
# ---------------------------------------------------------------------------


def get_sysctl_int(grade: Grade0, machine_name: str, name: str, step: int = 1) -> Optional[int]:
    """The integer value of the kernel parameter *name* (``net.ipv4.ip_default_ttl``) read in
    ``/proc/sys``, ``None`` when unreadable."""
    path = '/proc/sys/' + name.strip().replace('.', '/')
    out, code = grade.test(machine_name, f"cat {path}", step=step, allow_error=True)
    value = (out or '').strip()
    return int(value) if code == 0 and re.fullmatch(r'-?\d+', value) else None
