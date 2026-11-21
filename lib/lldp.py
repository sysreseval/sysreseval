"""LLDP helpers for the grading of the labs: the neighbours lldpd has learned.

``get_lldp_neighbors(grade, m)`` runs ``lldpcli -f json0 show neighbors details`` on a machine where
``lldpd`` runs and ``parse_lldp_neighbors()`` turns it into one dict per neighbour.  The ``json0``
format is used because its structure never changes (every value is a list); the plain ``json``
format gives a dict for one neighbour and a list for several, and keys a chassis by its name.
Fixtures captured with lldpd 1.0.18 (Debian 13) in ``tests/mock_data/lldp/``.

Facts verified live (2026-11-21, s17, Kathara VDE links, lldpd 1.0.18): lldpd uses the tap
interfaces of Kathara without any ``interface pattern``; it sends every 30 s with a TTL of 120 s
(``tx-hold`` 4); the port ID is the MAC address of the interface (``portidsubtype local <id>``
replaces it, ``description`` sets the port description); on the slaves of a bond it sends from a
fixed source MAC (``00:60:08:69:97:ef``, the bond MAC being on several ports), adds the 802.3 *link
aggregation* TLV (``aggregation`` = ifindex of the bond) and the management address is the first
IPv4 address of the system (``configure system ip management pattern``); the VLAN sub-interfaces
of a port are announced on it (802.1 *VLAN name* TLV: ``vlan`` = ``[{id, pvid, name}]``); a port
put in ``rx-only`` stops sending but sends no *shutdown* LLDPDU (the neighbour keeps it until the
TTL expires), while stopping lldpd sends one on every transmitting port (the neighbour forgets it at
once); ``/etc/lldpd.d/*.conf`` (lldpcli commands) is read when lldpd starts.
"""
import json
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0

LLDP_NEIGHBORS_CMD = "lldpcli -f json0 show neighbors details"
#: the multicast destination of LLDP (nearest bridge) and its EtherType
LLDP_MAC = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88cc


def _first(items, key: str = 'value'):
    """``items[0][key]`` of a json0 list (``None`` when absent)."""
    if isinstance(items, list) and items and isinstance(items[0], dict):
        return items[0].get(key)
    return None


def _values(items, key: str = 'value') -> List[Any]:
    return [item.get(key) for item in items if isinstance(item, dict) and key in item] if isinstance(items, list) else []


def _int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _neighbor(entry: Dict[str, Any]) -> Dict[str, Any]:
    chassis = (entry.get('chassis') or [{}])[0]
    port = (entry.get('port') or [{}])[0]
    chassis_id = (chassis.get('id') or [{}])[0]
    port_id = (port.get('id') or [{}])[0]
    capabilities = {item.get('type'): bool(item.get('enabled')) for item in chassis.get('capability') or []
                    if isinstance(item, dict) and item.get('type')}
    vlans = [{'id': _int(item.get('vlan-id')), 'pvid': bool(item.get('pvid')), 'name': item.get('value')}
             for item in entry.get('vlan') or [] if isinstance(item, dict)]
    return {
        'interface': entry.get('name'),
        'via': entry.get('via'),
        'chassis_id': chassis_id.get('value'),
        'chassis_id_type': chassis_id.get('type'),
        'chassis_name': _first(chassis.get('name')),
        'descr': _first(chassis.get('descr')),
        'mgmt_ips': [str(v) for v in _values(chassis.get('mgmt-ip'))],
        'capabilities': capabilities,
        'port_id': port_id.get('value'),
        'port_id_type': port_id.get('type'),
        'port_descr': _first(port.get('descr')),
        'ttl': _int(_first(port.get('ttl'))),
        'aggregation': _int(_first(port.get('aggregation'))),
        'vlans': vlans,
    }


def parse_lldp_neighbors(text: str) -> List[Dict[str, Any]]:
    """One dict per neighbour of ``lldpcli -f json0 show neighbors details``: ``interface`` (the
    local port), ``via``, ``chassis_id`` / ``chassis_id_type`` (``mac``...), ``chassis_name`` (the
    system name), ``descr`` (system description), ``mgmt_ips``, ``capabilities`` (``{'Bridge':
    True, ...}``: capability -> enabled), ``port_id`` / ``port_id_type`` (``mac``, ``ifname``,
    ``local``), ``port_descr``, ``ttl`` (int), ``aggregation`` (ifindex of the neighbour's bond for a
    bond slave, else ``None``) and ``vlans`` (``[{id, pvid, name}]``).  ``[]`` without neighbour or
    on unreadable text."""
    try:
        document = json.loads(text or '')
    except ValueError:
        return []
    neighbors = []
    for block in (document.get('lldp') or []) if isinstance(document, dict) else []:
        for entry in (block.get('interface') or []) if isinstance(block, dict) else []:
            if isinstance(entry, dict):
                neighbors.append(_neighbor(entry))
    return neighbors


def get_lldp_neighbors(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """``parse_lldp_neighbors()`` on *machine_name* (``[]`` when lldpd does not run there)."""
    out, code = grade.test(machine_name, LLDP_NEIGHBORS_CMD, step=step, allow_error=True)
    return parse_lldp_neighbors(out) if code == 0 else []


def lldp_neighbor(neighbors: List[Dict[str, Any]], interface: str = None, name: str = None) -> Optional[Dict[str, Any]]:
    """The first neighbour seen on *interface* and / or whose system name is *name* (a name
    followed by a domain, ``name.example``, matches too); ``None`` when there is none."""
    for neighbor in neighbors:
        if interface is not None and neighbor.get('interface') != interface:
            continue
        if name is not None:
            chassis = str(neighbor.get('chassis_name') or '')
            if chassis != name and not chassis.startswith(name + '.'):
                continue
        return neighbor
    return None
