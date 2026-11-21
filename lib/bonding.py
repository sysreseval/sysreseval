"""Bonding (link aggregation) and LACP helpers for the grading of the labs.

Readers of the Linux bonding driver as iproute2 and ``/proc/net/bonding`` show it (fixtures
captured on Debian 13, Linux 6.12, iproute2 6.x, in ``tests/mock_data/bonding/``):

- ``bond_info(links, 'bond0')`` on the objects of ``ip -j -d link show`` (``bridging.get_ip_links``):
  the options of the bond (``linkinfo.info_data``), its 802.3ad aggregator (``ad_info``) and its
  slaves (``info_slave_data``); ``get_bond_info(grade, m, 'bond0')`` reads them on a machine;
- ``lacp_aggregated(info)``: the slaves that LACP really aggregates (members of the active
  aggregator, in sync, collecting and distributing, with a partner);
- ``parse_proc_bonding(text)`` / ``get_proc_bonding()``: the text of ``/proc/net/bonding/<bond>``,
  which also gives the partner system of each slave (``ip -j -d link`` only gives the partner MAC
  of the active aggregator);
- ``get_tx_packets(grade, m, ifaces)`` + ``packets_delta()``: the transmit counters of interfaces,
  read before and after a burst of flows (``hping_flows_cmd()``), to see whether the flows are spread
  over the members of an aggregate.

Facts verified live (2026-11-21, s17, Kathara VDE links): the bonding module is loaded by the first
``ip link add ... type bond`` of a container (Debian's ``/lib/modprobe.d`` sets ``max_bonds=0``: no
``bond0`` appears on the host); an interface must be down to be enslaved (``Device can not be
enslaved while up``); the bond takes the MAC address of its first slave; Kathara's tap interfaces
report 10000 Mb/s full duplex, so the LACP key of a port is 15; the system priority is 65535 and
the port priority 255 by default; a link set down at one end stays up at the other end (no carrier
on a VDE link), so ``miimon`` never sees it there while LACP (``lacp_rate fast``) takes the port out
of sync after 3 s and out of the aggregator a few seconds later.
"""
import re
import shlex
from typing import Any, Dict, Iterable, List, Optional

from SRE.lib_sre import Grade0
from bridging import get_ip_links, links_by_name, normalize_mac

#: the modes of the Linux bonding driver, as iproute2 names them
BOND_MODES = ('balance-rr', 'active-backup', 'balance-xor', 'broadcast', '802.3ad', 'balance-tlb', 'balance-alb')
#: the state bits an aggregated port shows (``ad_actor_oper_port_state_str``)
LACP_AGGREGATED_STATE = ('in_sync', 'collecting', 'distributing')
NO_MAC = '00:00:00:00:00:00'


def _mac(text) -> str:
    """``normalize_mac()``, with the all-zero address (no partner) read as ``''``."""
    mac = normalize_mac(text)
    return '' if mac == NO_MAC else mac


def _int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# ip -j -d link show
# ---------------------------------------------------------------------------


def _slave_info(link: Dict[str, Any]) -> Dict[str, Any]:
    data = (link.get('linkinfo') or {}).get('info_slave_data') or {}
    flags = link.get('flags') or []
    return {
        'state': data.get('state'),                     # ACTIVE / BACKUP
        'mii_status': data.get('mii_status'),           # UP / DOWN / GOING_DOWN...
        'up': 'UP' in flags,
        'perm_hwaddr': normalize_mac(data.get('perm_hwaddr')),
        'link_failure_count': _int(data.get('link_failure_count')),
        'aggregator_id': _int(data.get('ad_aggregator_id')),
        'actor_state': _int(data.get('ad_actor_oper_port_state')),
        'actor_state_str': list(data.get('ad_actor_oper_port_state_str') or []),
        'partner_state': _int(data.get('ad_partner_oper_port_state')),
        'partner_state_str': list(data.get('ad_partner_oper_port_state_str') or []),
    }


def bond_info(links: List[Dict[str, Any]], bond: str = 'bond0') -> Optional[Dict[str, Any]]:
    """The bond *bond* of an ``ip -j -d link show`` output, ``None`` when it does not exist or is
    not a bond.  Keys: ``name``, ``address``, ``up`` (flag UP), ``carrier`` (LOWER_UP and not
    NO-CARRIER: a bond whose ``min_links`` is not reached has none), ``mode``, ``miimon``,
    ``arp_interval``, ``arp_ip_target`` (list of strings), ``arp_validate``, ``primary``,
    ``active_slave``, ``xmit_hash_policy``, ``lacp_rate`` (``slow`` / ``fast``), ``lacp_active``
    (bool), ``min_links``, ``ad_select``, ``actor_sys_prio``, the active aggregator (``aggregator``,
    ``num_ports``, ``actor_key``, ``partner_key``, ``partner_mac``: ``''`` without partner) and
    ``slaves``: ``{ifname: {state, mii_status, up, perm_hwaddr, link_failure_count, aggregator_id,
    actor_state, actor_state_str, partner_state, partner_state_str}}``.  The options of another
    mode are still present (the driver keeps them all), with their default values."""
    by_name = links_by_name(links)
    link = by_name.get(bond)
    linkinfo = (link or {}).get('linkinfo') or {}
    if not link or linkinfo.get('info_kind') != 'bond':
        return None
    data = linkinfo.get('info_data') or {}
    ad = data.get('ad_info') or {}
    flags = link.get('flags') or []
    targets = data.get('arp_ip_target') or []
    if isinstance(targets, str):
        targets = [targets]
    slaves = {name: _slave_info(other) for name, other in by_name.items()
              if other.get('master') == bond and (other.get('linkinfo') or {}).get('info_slave_kind') == 'bond'}
    return {
        'name': bond,
        'address': normalize_mac(link.get('address')),
        'up': 'UP' in flags,
        'carrier': 'LOWER_UP' in flags and 'NO-CARRIER' not in flags,
        'mode': data.get('mode'),
        'miimon': _int(data.get('miimon')) or 0,
        'arp_interval': _int(data.get('arp_interval')) or 0,
        'arp_ip_target': [str(t) for t in targets],
        'arp_validate': data.get('arp_validate'),
        'primary': data.get('primary'),
        'active_slave': data.get('active_slave'),
        'xmit_hash_policy': data.get('xmit_hash_policy'),
        'lacp_rate': data.get('ad_lacp_rate'),
        'lacp_active': data.get('ad_lacp_active', 'on') == 'on',
        'min_links': _int(data.get('min_links')) or 0,
        'ad_select': data.get('ad_select'),
        'actor_sys_prio': _int(data.get('ad_actor_sys_prio')),
        'aggregator': _int(ad.get('aggregator')),
        'num_ports': _int(ad.get('num_ports')) or 0,
        'actor_key': _int(ad.get('actor_key')),
        'partner_key': _int(ad.get('partner_key')),
        'partner_mac': _mac(ad.get('partner_mac')),
        'slaves': slaves,
    }


def get_bond_info(grade: Grade0, machine_name: str, bond: str = 'bond0', step: int = 1) -> Optional[Dict[str, Any]]:
    """``bond_info()`` of *bond* on *machine_name* (one ``ip -j -d link show``, shared with the
    other readers of ``bridging.get_ip_links`` of the same step)."""
    return bond_info(get_ip_links(grade, machine_name, step=step), bond)


def bond_slaves(info: Optional[Dict[str, Any]]) -> List[str]:
    """The sorted names of the slaves of a ``bond_info()`` (``[]`` without bond)."""
    return sorted((info or {}).get('slaves', {}))


def lacp_aggregated(info: Optional[Dict[str, Any]]) -> List[str]:
    """The sorted slaves an 802.3ad bond really aggregates: members of its active aggregator, in
    sync, collecting and distributing, the aggregator having a partner.  ``[]`` for any other mode,
    a bond without partner (a static peer: each port then sits alone in its own aggregator) or no
    bond."""
    if not info or info.get('mode') != '802.3ad' or not info.get('partner_mac') or info.get('aggregator') is None:
        return []
    return sorted(name for name, slave in info.get('slaves', {}).items()
                  if slave.get('aggregator_id') == info['aggregator']
                  and all(bit in slave.get('actor_state_str', []) for bit in LACP_AGGREGATED_STATE))


def lacp_partner_is(info: Optional[Dict[str, Any]], macs: Iterable) -> bool:
    """True iff the partner of the active aggregator is one of *macs* (any MAC notation)."""
    wanted = {normalize_mac(mac) for mac in macs if normalize_mac(mac)}
    return bool(info) and bool(info.get('partner_mac')) and info['partner_mac'] in wanted


# ---------------------------------------------------------------------------
# /proc/net/bonding/<bond>
# ---------------------------------------------------------------------------

_PROC_KEYS = {
    'Bonding Mode': 'mode',
    'Transmit Hash Policy': 'xmit_hash_policy',
    'Primary Slave': 'primary',
    'Currently Active Slave': 'active_slave',
    'MII Status': 'mii_status',
    'MII Polling Interval (ms)': 'miimon',
    'ARP Polling Interval (ms)': 'arp_interval',
    'ARP IP target/s (n.n.n.n form)': 'arp_ip_target',
    'LACP active': 'lacp_active',
    'LACP rate': 'lacp_rate',
    'Min links': 'min_links',
    'Aggregator selection policy (ad_select)': 'ad_select',
    'System priority': 'system_priority',
    'System MAC address': 'system_mac',
}
_AGG_KEYS = {'Aggregator ID': 'id', 'Number of ports': 'num_ports', 'Actor Key': 'actor_key',
             'Partner Key': 'partner_key', 'Partner Mac Address': 'partner_mac'}
_SLAVE_KEYS = {'MII Status': 'mii_status', 'Speed': 'speed', 'Duplex': 'duplex',
               'Link Failure Count': 'link_failure_count', 'Permanent HW addr': 'perm_hwaddr',
               'Aggregator ID': 'aggregator_id'}
_PDU_KEYS = {'system priority': 'system_priority', 'system mac address': 'system_mac', 'port key': 'key',
             'oper key': 'key', 'port priority': 'port_priority', 'port number': 'port_number',
             'port state': 'port_state'}
_INT_FIELDS = {'miimon', 'arp_interval', 'min_links', 'system_priority', 'id', 'num_ports', 'actor_key',
               'partner_key', 'link_failure_count', 'aggregator_id', 'key', 'port_priority', 'port_number',
               'port_state'}
_MAC_FIELDS = {'system_mac', 'partner_mac', 'perm_hwaddr'}


def _proc_value(field: str, value: str):
    value = value.strip()
    if field in _INT_FIELDS:
        m = re.match(r'-?\d+', value)
        return int(m.group(0)) if m else None
    if field in _MAC_FIELDS:
        return _mac(value) if field != 'perm_hwaddr' else normalize_mac(value)
    if field == 'primary':
        return value.split(' ', 1)[0] or None          # "eth0 (primary_reselect always)"
    if field == 'xmit_hash_policy':
        return value.split(' ', 1)[0]                  # "layer3+4 (1)"
    if field == 'arp_ip_target':
        return [t.strip() for t in value.split(',') if t.strip()]
    if field == 'active_slave':
        return None if value == 'None' else value
    return value


def parse_proc_bonding(text: str) -> Dict[str, Any]:
    """The content of ``/proc/net/bonding/<bond>``: the bond's own lines (``mode`` is the long name,
    e.g. ``IEEE 802.3ad Dynamic link aggregation``), ``aggregator`` (the *Active Aggregator Info*:
    ``id``, ``num_ports``, ``actor_key``, ``partner_key``, ``partner_mac``) and ``slaves``:
    ``{ifname: {mii_status, speed, duplex, link_failure_count, perm_hwaddr, aggregator_id, actor,
    partner}}``, ``actor`` / ``partner`` being the *details actor / partner lacp pdu* blocks
    (``system_priority``, ``system_mac``, ``key``, ``port_priority``, ``port_number``,
    ``port_state``).  ``{}`` for an empty text."""
    result: Dict[str, Any] = {}
    if not (text or '').strip():
        return result
    result['slaves'] = {}
    section, slave, pdu = 'bond', None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('Active Aggregator Info'):
            section, pdu = 'aggregator', None
            result['aggregator'] = {}
            continue
        if stripped.startswith('Slave Interface:'):
            name = stripped.split(':', 1)[1].strip()
            slave = result['slaves'].setdefault(name, {'actor': {}, 'partner': {}})
            section, pdu = 'slave', None
            continue
        if stripped.startswith('details actor lacp pdu'):
            pdu = 'actor'
            continue
        if stripped.startswith('details partner lacp pdu'):
            pdu = 'partner'
            continue
        if ':' not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split(':', 1))
        if section == 'slave' and pdu:
            field = _PDU_KEYS.get(key)
            if field:
                slave[pdu][field] = _proc_value(field, value)
        elif section == 'slave':
            field = _SLAVE_KEYS.get(key)
            if field:
                slave[field] = _proc_value(field, value)
        elif section == 'aggregator' and key in _AGG_KEYS:
            field = _AGG_KEYS[key]
            result['aggregator'][field] = _proc_value(field, value)
        else:
            field = _PROC_KEYS.get(key)
            if field and field not in result:
                result[field] = _proc_value(field, value)
    return result


def get_proc_bonding(grade: Grade0, machine_name: str, bond: str = 'bond0', step: int = 1) -> Dict[str, Any]:
    """``parse_proc_bonding()`` of ``/proc/net/bonding/<bond>`` on *machine_name* (``{}`` when the
    bond does not exist)."""
    out, code = grade.test(machine_name, f"cat /proc/net/bonding/{shlex.quote(bond)}", step=step, allow_error=True)
    return parse_proc_bonding(out) if code == 0 else {}


# ---------------------------------------------------------------------------
# spreading of the flows over the members
# ---------------------------------------------------------------------------


def tx_packets_cmd(ifaces: Iterable[str]) -> str:
    """One line ``<ifname> <tx_packets>`` per interface (``-`` for a missing one)."""
    names = ' '.join(shlex.quote(i) for i in ifaces)
    return (f"for i in {names}; do printf '%s %s\\n' \"$i\" "
            "\"$(cat /sys/class/net/$i/statistics/tx_packets 2>/dev/null || echo -)\"; done")


def parse_tx_packets(text: str) -> Dict[str, Optional[int]]:
    """``{ifname: packets}`` of ``tx_packets_cmd()`` (``None`` for a missing interface)."""
    counters: Dict[str, Optional[int]] = {}
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) == 2:
            counters[parts[0]] = int(parts[1]) if parts[1].isdigit() else None
    return counters


def get_tx_packets(grade: Grade0, machine_name: str, ifaces: Iterable[str], step: int = 1) -> Dict[str, Optional[int]]:
    """The transmit packet counters of *ifaces* on *machine_name* at *step*."""
    ifaces = list(ifaces)
    out, code = grade.test(machine_name, tx_packets_cmd(ifaces), step=step, allow_error=True)
    counters = parse_tx_packets(out) if code == 0 else {}
    return {i: counters.get(i) for i in ifaces}


def packets_delta(before: Dict[str, Optional[int]], after: Dict[str, Optional[int]]) -> Dict[str, Optional[int]]:
    """``after - before`` per interface (``None`` when either is unknown)."""
    return {i: (after[i] - before[i]) if before.get(i) is not None and after.get(i) is not None else None
            for i in after}


def hping_flows_cmd(dest, count: int = 64, base_port: int = 20000, interval_us: int = 2000,
                    source_port: int = 33000) -> str:
    """*count* UDP datagrams to *dest*, each to the next destination port from *base_port* on, all
    from *source_port*: as many flows for a ``layer3+4`` hash, spread evenly over the members (a
    ``layer2`` hash puts them all on one member).  The source port is kept (``-k``): by default
    hping3 increments it with the destination port, and the hash, which mixes the two ports, then
    put most of the flows on one member (seen live: 9 / 72)."""
    return (f"hping3 --udp -s {source_port} -k -p ++{base_port} -c {count} -i u{interval_us} {dest} "
            ">/dev/null 2>&1; true")
