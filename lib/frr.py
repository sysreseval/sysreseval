"""FRR / OSPF / BGP / RIP / PIM grading helpers.

Every ``get_*`` function registers one command through ``grade.test()`` -- so it
follows the two-pass contract of ``Grade.grade()`` (placeholder result on the
registration pass, real output afterwards) -- and hands the text to a pure
``parse_*`` function.  The parsers are unit-tested on captured FRR 9 output in
``tests/test_frr.py``; the labs run on the FRR 10.3 of Debian 13 since 2026-11-19, whose output
they read the same (the OSPF, BGP, RIP, multicast and OSPFv3 labs reach full marks on it).  The OSPF and RIP helpers parse the text output of ``vtysh``
(``show ip rip`` and ``show ip rip status`` have no json form), the BGP helpers its
``json`` output (``show bgp ipv4 unicast ... json``).  On the placeholder output
every parser returns its empty shape (``{}``/``[]``), never an exception.  What a
RIP router really announces on a link is read by the passive probe of ``lib/rip.py``.
The PIM / IGMP / MSDP / MLD helpers parse the ``json`` output of pimd and pim6d; what
multicast traffic really reaches a host is read by ``lib/mcast.py``.  The OSPFv3 helpers (end
of the file) parse the ``json`` output of ospf6d (``show ipv6 ospf6 ... json``) and the text of
``show ipv6 ospf6 border-routers``; the BGP helpers take ``afi='ipv6'`` for the IPv6 unicast
address family.

Pass ``allow_error=True`` when the router may not run OSPF/BGP/RIP yet (``vtysh``
then exits non-zero and the error would otherwise be recorded in the archive).
"""
import json
import re
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0

_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

#: kernel route protocol values that mean "installed by ospfd" (name from
#: /etc/iproute2/rt_protos.d/frr.conf, or the raw number when that file is missing)
OSPF_ROUTE_PROTOCOLS = ('ospf', '188')
#: kernel route protocol values that mean "installed by bgpd"
BGP_ROUTE_PROTOCOLS = ('bgp', '186')
#: kernel route protocol values that mean "installed by ripd" / "by ripngd"
RIP_ROUTE_PROTOCOLS = ('rip', '189')
RIPNG_ROUTE_PROTOCOLS = ('ripng', '190')


def _test(grade: Grade0, machine_name: str, command: str, step: int, allow_error: bool):
    if allow_error:
        return grade.test(machine_name, command, step=step, allow_error=True)
    return grade.test(machine_name, command, step=step)


def normalize_area(area: str) -> str:
    """Return an OSPF area id in dotted form: ``'1'`` -> ``'0.0.0.1'``, ``'0.0.0.1'`` unchanged."""
    area = str(area).strip()
    if area.isdigit():
        return str(IPv4Address(int(area)))
    return area


def is_ospf_protocol(protocol) -> bool:
    """True when a kernel route ``protocol`` field (``ip -j route``) denotes an OSPF route."""
    return str(protocol) in OSPF_ROUTE_PROTOCOLS


def is_bgp_protocol(protocol) -> bool:
    """True when a kernel route ``protocol`` field (``ip -j route``) denotes a BGP route."""
    return str(protocol) in BGP_ROUTE_PROTOCOLS


def is_rip_protocol(protocol) -> bool:
    """True when a kernel route ``protocol`` field (``ip -j route``) denotes a RIP route."""
    return str(protocol) in RIP_ROUTE_PROTOCOLS


def is_ripng_protocol(protocol) -> bool:
    """True when a kernel route ``protocol`` field (``ip -j -6 route``) denotes a RIPng route."""
    return str(protocol) in RIPNG_ROUTE_PROTOCOLS


# ---------------------------------------------------------------------------
# show ip ospf interface
# ---------------------------------------------------------------------------

def parse_ospf_interfaces(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse the text of ``show ip ospf interface`` (see :func:`get_ospf_interfaces`)."""
    result: Dict[str, Dict[str, Any]] = {}
    current: Dict[str, Any] | None = None

    for line in output.splitlines():
        # Interface header: "ethX is up"
        m = re.match(r'^(\S+) is (up|down)', line)
        if m:
            current = {
                'state': m.group(2),
                'ospf_enabled': True,
                'mtu': None, 'bandwidth': None,
                'internet_address': None, 'broadcast': None, 'area': None,
                'router_id': None, 'network_type': None, 'cost': None,
                'ospf_state': None, 'priority': None, 'passive': False,
                'hello_interval': None, 'dead_interval': None, 'retransmit_interval': None,
                'neighbor_count': None, 'adjacent_neighbor_count': None,
                'dr_id': None, 'dr_address': None,
                'bdr_id': None, 'bdr_address': None,
            }
            result[m.group(1)] = current
            continue

        if current is None:
            continue

        if 'OSPF not enabled on this interface' in line:
            current['ospf_enabled'] = False
            continue

        # ifindex 13, MTU 1500 bytes, BW 10000 Mbit <UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>
        m = re.search(r'MTU (\d+) bytes,\s*BW (\d+) Mbit', line)
        if m:
            current['mtu'] = int(m.group(1))
            current['bandwidth'] = int(m.group(2))
            continue

        # Internet Address 10.150.180.224/28, Broadcast 10.150.180.239, Area 0.0.0.0
        m = re.search(r'Internet Address (\S+?),\s*Broadcast (\S+?),\s*Area (\S+)', line)
        if m:
            current['internet_address'] = m.group(1)
            current['broadcast'] = m.group(2)
            current['area'] = m.group(3)
            continue

        # Internet Address 10.0.0.1/30, Area 0.0.0.0   (point-to-point, no broadcast)
        m = re.search(r'Internet Address (\S+?),\s*Area (\S+)', line)
        if m:
            current['internet_address'] = m.group(1)
            current['area'] = m.group(2)
            continue

        # Router ID 10.150.180.224, Network Type BROADCAST, Cost: 10
        m = re.search(r'Router ID (\S+?),\s*Network Type (\S+?),\s*Cost:\s*(\d+)', line)
        if m:
            current['router_id'] = m.group(1)
            current['network_type'] = m.group(2)
            current['cost'] = int(m.group(3))
            continue

        # Transmit Delay is 1 sec, State Backup, Priority 1
        m = re.search(r'State (\S+?),\s*Priority (\d+)', line)
        if m:
            current['ospf_state'] = m.group(1).rstrip(',')
            current['priority'] = int(m.group(2))
            continue

        # Designated Router (ID) 172.23.52.228 Interface Address 10.150.180.230/28
        m = re.search(r'Designated Router \(ID\) (\S+)\s+Interface Address (\S+)', line)
        if m and 'Backup' not in line:
            current['dr_id'] = m.group(1)
            current['dr_address'] = m.group(2)
            continue

        # Backup Designated Router (ID) 10.150.180.224, Interface Address 10.150.180.224
        m = re.search(r'Backup Designated Router \(ID\) (\S+?),\s*Interface Address (\S+)', line)
        if m:
            current['bdr_id'] = m.group(1)
            current['bdr_address'] = m.group(2)
            continue

        # Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
        m = re.search(r'Hello (\d+)s,\s*Dead (\d+)s,.*Retransmit (\d+)', line)
        if m:
            current['hello_interval'] = int(m.group(1))
            current['dead_interval'] = int(m.group(2))
            current['retransmit_interval'] = int(m.group(3))
            continue

        # No Hellos (Passive interface)
        if 'No Hellos (Passive interface)' in line:
            current['passive'] = True
            continue

        # Neighbor Count is 1, Adjacent neighbor count is 1
        m = re.search(r'Neighbor Count is (\d+),\s*Adjacent neighbor count is (\d+)', line)
        if m:
            current['neighbor_count'] = int(m.group(1))
            current['adjacent_neighbor_count'] = int(m.group(2))
            continue

    return result


def get_ospf_interfaces(grade: Grade0, machine_name: str, step: int = 1,
                        allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show ip ospf interface"' and parse the output.

    Returns a dict mapping interface name -> dict of parsed fields:
      state            : 'up' | 'down'
      ospf_enabled     : bool  (False for "OSPF not enabled on this interface" entries)
      mtu              : int
      bandwidth        : int   (Mbit, the "BW" field: interface speed or `bandwidth` setting)
      internet_address : str  e.g. '10.150.180.224/28'
      broadcast        : str  e.g. '10.150.180.239'
      area             : str  e.g. '0.0.0.0'
      router_id        : str
      network_type     : str  e.g. 'BROADCAST'
      cost             : int
      ospf_state       : str  e.g. 'Backup', 'DR', 'DROther'
      priority         : int
      passive          : bool ("No Hellos (Passive interface)")
      hello_interval   : int  (seconds)
      dead_interval    : int  (seconds)
      retransmit_interval : int (seconds)
      neighbor_count          : int
      adjacent_neighbor_count : int
      dr_id            : str | None
      dr_address       : str | None
      bdr_id           : str | None
      bdr_address      : str | None

    Returns {} on error or empty output.
    """
    output, code = _test(grade, machine_name, 'vtysh -c "show ip ospf interface"', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_ospf_interfaces(output)


# ---------------------------------------------------------------------------
# show ip ospf neighbor
# ---------------------------------------------------------------------------

def parse_ospf_neighbors(output: str) -> List[Dict[str, Any]]:
    """Parse the text of ``show ip ospf neighbor``.

    Data rows look like (the "Up Time" column exists in FRR >= 7.5 only)::

        Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL
        10.0.0.2          1 Full/DR         2m34s             36.245s 10.0.12.2       eth0:10.0.12.1                       0     0     0

    Rows are parsed from the end (three counters, interface, address, dead time) so
    both layouts work.  Non-data lines are skipped.
    """
    result: List[Dict[str, Any]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 9 or not _IPV4_RE.match(fields[0]):
            continue
        state, _, role = fields[2].partition('/')
        interface, _, local_address = fields[-4].partition(':')
        try:
            priority: Optional[int] = int(fields[1])
        except ValueError:
            priority = None
        result.append({
            'neighbor_id': fields[0],
            'priority': priority,
            'state': state,
            'role': role or None,
            'up_time': fields[3] if len(fields) >= 10 else None,
            'dead_time': fields[-6],
            'address': fields[-5],
            'interface': interface,
            'local_address': local_address or None,
        })
    return result


def get_ospf_neighbors(grade: Grade0, machine_name: str, step: int = 1,
                       allow_error: bool = False) -> List[Dict[str, Any]]:
    """Run 'vtysh -c "show ip ospf neighbor"' and return one dict per neighbour:
    ``neighbor_id, priority, state ('Full', '2-Way', ...), role ('DR', 'Backup',
    'DROther', '-'), up_time, dead_time, address, interface, local_address``.
    Returns [] on error or empty output."""
    output, code = _test(grade, machine_name, 'vtysh -c "show ip ospf neighbor"', step, allow_error)
    if code != 0 or not output:
        return []
    return parse_ospf_neighbors(output)


def find_neighbor(neighbors: List[Dict[str, Any]], neighbor_id: str = None, interface: str = None,
                  address: str = None) -> Optional[Dict[str, Any]]:
    """Return the first neighbour of :func:`get_ospf_neighbors` matching every given criterion."""
    for n in neighbors:
        if neighbor_id is not None and n['neighbor_id'] != str(neighbor_id):
            continue
        if interface is not None and n['interface'] != interface:
            continue
        if address is not None and n['address'] != str(address):
            continue
        return n
    return None


def neighbor_is_full(neighbors: List[Dict[str, Any]], neighbor_id: str = None, interface: str = None,
                     address: str = None) -> bool:
    """True when a neighbour matching the criteria exists and is in state Full."""
    n = find_neighbor(neighbors, neighbor_id=neighbor_id, interface=interface, address=address)
    return n is not None and n['state'] == 'Full'


# ---------------------------------------------------------------------------
# show ip ospf
# ---------------------------------------------------------------------------

def parse_ospf_info(output: str) -> Dict[str, Any]:
    """Parse the text of ``show ip ospf``.

    Returns ``{}`` when no router id is found (OSPF not running), else::

        {'router_id': '10.0.0.4', 'abr': True, 'asbr': False,
         'areas': {'0.0.0.0': {'type': 'backbone', 'no_summary': False, 'interfaces': 3,
                               'active_interfaces': 3, 'full_neighbors': 2,
                               'authentication': 'no'}, ...}}

    ``type`` is ``'backbone'``, ``'stub'``, ``'nssa'`` or ``'normal'``;
    ``authentication`` is ``'no'``, ``'simple password'`` or ``'message digest'``.
    """
    info: Dict[str, Any] = {'router_id': None, 'abr': False, 'asbr': False, 'areas': {}}
    current: Dict[str, Any] | None = None

    for line in output.splitlines():
        m = re.search(r'OSPF Routing Process, Router ID:\s*(\S+)', line)
        if m:
            info['router_id'] = m.group(1)
            continue
        if 'This router is an ABR' in line:
            info['abr'] = True
            continue
        if 'This router is an ASBR' in line:
            info['asbr'] = True
            continue
        m = re.match(r'^\s*Area ID:\s*(\S+)(?:\s*\((.*?)\))?', line)
        if m:
            desc = (m.group(2) or '').strip()
            low = desc.lower()
            if low.startswith('backbone'):
                area_type = 'backbone'
            elif low.startswith('stub'):
                area_type = 'stub'
            elif low.startswith('nssa'):
                area_type = 'nssa'
            else:
                area_type = 'normal'
            current = {
                'type': area_type,
                'no_summary': 'no summary' in low,
                'interfaces': None, 'active_interfaces': None,
                'full_neighbors': None, 'authentication': None,
            }
            info['areas'][m.group(1)] = current
            continue
        if current is None:
            continue
        m = re.search(r'Number of interfaces in this area:\s*Total:\s*(\d+),\s*Active:\s*(\d+)', line)
        if m:
            current['interfaces'] = int(m.group(1))
            current['active_interfaces'] = int(m.group(2))
            continue
        m = re.search(r'Number of fully adjacent neighbors in this area:\s*(\d+)', line)
        if m:
            current['full_neighbors'] = int(m.group(1))
            continue
        m = re.search(r'Area has (.+?) authentication', line)
        if m:
            current['authentication'] = m.group(1).strip()
            continue

    if info['router_id'] is None:
        return {}
    return info


def get_ospf_info(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Any]:
    """Run 'vtysh -c "show ip ospf"' and return the router-level state (see :func:`parse_ospf_info`).
    Returns {} when OSPF is not running."""
    output, code = _test(grade, machine_name, 'vtysh -c "show ip ospf"', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_ospf_info(output)


def router_id_map(grade: Grade0, machine_names, step: int = 1, allow_error: bool = True) -> Dict[str, str]:
    """Return ``{router_id: machine_name}`` for every machine whose OSPF process answers."""
    result: Dict[str, str] = {}
    for m in machine_names:
        rid = get_ospf_info(grade, m, step=step, allow_error=allow_error).get('router_id')
        if rid:
            result[rid] = m
    return result


# ---------------------------------------------------------------------------
# show ip ospf route
# ---------------------------------------------------------------------------

# "N IA 10.0.5.0/24 [30] area: 0.0.0.0", "D IA 10.37.4.0/22 Discard entry",
# "N E2 203.0.113.0/24 [10/20] tag: 0" and, in the router table, "R 1.1.1.1 IA [400] area: 0.0.0.2, ASBR"
# (the type marker follows the router id there).
_OSPF_ROUTE_RE = re.compile(
    r'^(?P<kind>[NRD])\s+(?P<type>IA|E1|E2|N1|N2)?\s*'
    r'(?P<dest>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\s+'
    r'(?:(?P<type2>IA|E1|E2|N1|N2)\s+)?'
    r'(?:\[(?P<cost>\d+)(?:/(?P<ext_cost>\d+))?\]|(?P<discard>Discard entry))'
    r'(?P<rest>.*)$'
)


def parse_ospf_routes(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse the text of ``show ip ospf route``.

    Network entries (``N``) and discard entries (``D``, created by ``area range``) are
    keyed by prefix, router entries (``R``) by router id::

        {'10.0.5.0/24': {'kind': 'N', 'type': 'IA', 'cost': 30, 'ext_cost': None, 'tag': None,
                         'area': '0.0.0.0', 'abr': False, 'asbr': False,
                         'nexthops': [('10.0.12.3', 'eth0')]},
         '203.0.113.0/24': {'kind': 'N', 'type': 'E2', 'cost': 10, 'ext_cost': 20, 'tag': 0, ...},
         '10.0.0.3': {'kind': 'R', 'type': 'intra', 'cost': 10, 'area': '0.0.0.0', 'abr': True, ...}}

    ``type`` is ``'intra'`` for plain intra-area entries, ``'IA'``, ``'E1'``, ``'E2'``,
    ``'N1'`` or ``'N2'``.  ``nexthops`` holds ``(ip, interface)`` pairs, ``ip`` being
    ``None`` for ``directly attached to`` entries.
    """
    result: Dict[str, Dict[str, Any]] = {}
    current: Dict[str, Any] | None = None

    for line in output.splitlines():
        m = _OSPF_ROUTE_RE.match(line.strip())
        if m:
            rest = m.group('rest') or ''
            area_m = re.search(r'area:\s*(\S+?)(?:,|\s|$)', rest)
            tag_m = re.search(r'tag:\s*(\d+)', rest)
            current = {
                'kind': m.group('kind'),
                'type': m.group('type') or m.group('type2') or 'intra',
                'cost': int(m.group('cost')) if m.group('cost') else None,
                'ext_cost': int(m.group('ext_cost')) if m.group('ext_cost') else None,
                'tag': int(tag_m.group(1)) if tag_m else None,
                'area': area_m.group(1) if area_m else None,
                'abr': 'ABR' in rest,
                'asbr': 'ASBR' in rest,
                'discard': bool(m.group('discard')),
                'nexthops': [],
            }
            result[m.group('dest')] = current
            continue
        if current is None:
            continue
        m = re.search(r'via (\S+?),\s*(\S+)', line)
        if m:
            current['nexthops'].append((m.group(1), m.group(2)))
            continue
        m = re.search(r'directly attached to (\S+)', line)
        if m:
            current['nexthops'].append((None, m.group(1)))
            continue

    return result


def get_ospf_routes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show ip ospf route"' and parse it (see :func:`parse_ospf_routes`).
    Returns {} on error or empty output."""
    output, code = _test(grade, machine_name, 'vtysh -c "show ip ospf route"', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_ospf_routes(output)


# ---------------------------------------------------------------------------
# show ip ospf database external json  (type 5 LSAs)
# ---------------------------------------------------------------------------

def _external_lsa_entries(data: Any) -> List[Dict[str, Any]]:
    """Every dict of *data* (nested lists / dicts, whatever the grouping keys of the FRR
    version) that describes one AS-external LSA."""
    found: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        if 'linkStateId' in data and 'advertisingRouter' in data:
            return [data]
        for value in data.values():
            found += _external_lsa_entries(value)
    elif isinstance(data, list):
        for value in data:
            found += _external_lsa_entries(value)
    return found


def _mask_length(value) -> Optional[int]:
    """``32``, ``'32'``, ``'/32'`` or ``'255.255.255.255'`` → 32."""
    if value is None:
        return None
    text = str(value).strip().lstrip('/')
    if '.' in text:
        try:
            return IPv4Network(f"0.0.0.0/{text}").prefixlen
        except ValueError:
            return None
    return _int_or_none(text)


def parse_ospf_external_lsas(data: Any) -> Dict[tuple, Dict[str, Any]]:
    """Parse the JSON of ``show ip ospf database external``.

    Returns ``{(prefix, advertising router): {'prefix': '172.20.5.53/32', 'adv_router':
    '10.0.32.2', 'metric_type': 1 | 2, 'metric': 10, 'forward': '0.0.0.0', 'tag': 0,
    'age': 12}}`` (``{}`` without OSPF or without external LSA)."""
    result: Dict[tuple, Dict[str, Any]] = {}
    for e in _external_lsa_entries(data):
        length = _mask_length(e.get('networkMask'))
        lsid = e.get('linkStateId')
        try:
            prefix = str(IPv4Network(f"{lsid}/{length if length is not None else 32}", strict=False))
        except ValueError:
            continue
        mtype = str(e.get('metricType') or '')
        m = re.search(r'E?([12])', mtype)
        metric_type = int(m.group(1)) if m else None
        adv = str(e.get('advertisingRouter'))
        result[(prefix, adv)] = {
            'prefix': prefix, 'adv_router': adv, 'metric_type': metric_type,
            'metric': _int_or_none(e.get('metric')),
            'forward': e.get('forwardAddress', e.get('nssaForwardAddress')),
            'tag': _int_or_none(e.get('externalRouteTag', e.get('routeTag'))),
            'age': _int_or_none(e.get('lsaAge')),
        }
    return result


def get_ospf_external_lsas(grade: Grade0, machine_name: str, step: int = 1,
                           allow_error: bool = True) -> Dict[tuple, Dict[str, Any]]:
    """The AS-external LSAs in the database of *machine_name* (see
    :func:`parse_ospf_external_lsas`)."""
    return parse_ospf_external_lsas(_vtysh_json(grade, machine_name, 'show ip ospf database external', step,
                                                allow_error))


def get_ospf_nssa_lsas(grade: Grade0, machine_name: str, step: int = 1,
                       allow_error: bool = True) -> Dict[tuple, Dict[str, Any]]:
    """The NSSA-external LSAs (type 7) in the database of *machine_name*, every NSSA area
    together: ``show ip ospf database nssa-external json`` (FRR 10.3 shape
    ``nssaExternalLinkStates: {areas: {area: [...]}}``), parsed by
    :func:`parse_ospf_external_lsas` (``forward`` from ``nssaForwardAddress``).  An ABR shows
    the routes these LSAs give as ``N E2`` in ``show ip ospf route``, not ``N2``: read the LSAs."""
    return parse_ospf_external_lsas(_vtysh_json(grade, machine_name, 'show ip ospf database nssa-external', step,
                                                allow_error))


# ---------------------------------------------------------------------------
# ip -j route  (kernel routing table)
# ---------------------------------------------------------------------------

def parse_kernel_routes(output: str, ipv6: bool = False) -> Dict[str, Dict[str, Any]]:
    """Parse the JSON of ``ip -j route`` (``ip -j -6 route`` with ``ipv6=True``).

    Returns ``{prefix: {'protocol': str, 'metric': int, 'scope': str | None,
    'nexthops': [(gateway | None, dev)], 'labels': [[int]], 'type': 'unicast' | 'blackhole' | ...}}``; ``default`` becomes
    ``0.0.0.0/0`` (``::/0``) and host routes get ``/32`` (``/128``).  ECMP routes list every
    next hop.  ``labels`` holds, for each next hop in the same order, the MPLS label stack it
    pushes (``encap mpls 16003/16005`` → ``[16003, 16005]``; ``[]`` without encapsulation).
    When the same prefix appears several times (different metrics, or ``fe80::/64`` on every
    interface) the first entry wins.
    """
    try:
        routes = json.loads(output)
    except (ValueError, TypeError):
        return {}
    if not isinstance(routes, list):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for r in routes:
        if not isinstance(r, dict):
            continue
        dst = r.get('dst')
        if not dst:
            continue
        if dst == 'default':
            dst = '::/0' if ipv6 else '0.0.0.0/0'
        elif '/' not in dst:
            dst += '/128' if ipv6 or ':' in dst else '/32'
        if dst in result:
            continue
        if isinstance(r.get('nexthops'), list):
            hops = [n for n in r['nexthops'] if isinstance(n, dict)]
        else:
            hops = [r]
        result[dst] = {
            'protocol': str(r.get('protocol', '')),
            'metric': int(r.get('metric', 0) or 0),
            'scope': r.get('scope'),
            'nexthops': [(n.get('gateway'), n.get('dev')) for n in hops],
            'labels': [_encap_labels(n.get('encap')) for n in hops],
            'type': r.get('type') or 'unicast',     # 'blackhole' / 'unreachable' / 'prohibit': no device
        }
    return result


def _encap_labels(encap) -> List[int]:
    """The label stack of an ``encap`` object of ``ip -j route`` (``{"encap_type": "mpls",
    "dst": "16003/16005"}``); ``[]`` for no or another encapsulation."""
    if not isinstance(encap, dict) or encap.get('encap_type') != 'mpls':
        return []
    labels = []
    for part in str(encap.get('dst') or '').split('/'):
        value = _int_or_none(part)
        if value is not None:
            labels.append(value)
    return labels


def kernel_route_labels(routes: Dict[str, Dict[str, Any]], prefix) -> List[List[int]]:
    """The label stacks pushed by the next hops of ``prefix`` in a :func:`parse_kernel_routes`
    result (``[]`` when the prefix is absent)."""
    entry = routes.get(str(prefix))
    return list(entry.get('labels', [])) if entry else []


def get_kernel_routes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                      ipv6: bool = False, vrf: str = None) -> Dict[str, Dict[str, Any]]:
    """Run 'ip -j route' ('ip -j -6 route' with ``ipv6=True``; ``vrf``: the table of that VRF
    device, ``ip -j route show vrf X``) and parse it (see :func:`parse_kernel_routes`). Returns {}
    on error."""
    command = 'ip -j -6 route' if ipv6 else 'ip -j route'
    if vrf:
        command += f' show vrf {vrf}'
    output, code = _test(grade, machine_name, command, step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_kernel_routes(output, ipv6=ipv6)


def kernel_route_gateways(routes: Dict[str, Dict[str, Any]], prefix, ospf_only: bool = True,
                          protocols=None) -> List[str]:
    """Return the gateway list of ``prefix`` in a :func:`parse_kernel_routes` result.

    ``[]`` when the prefix is absent or when its protocol is not accepted: by default
    only OSPF routes are (``ospf_only``); ``protocols`` (e.g. ``BGP_ROUTE_PROTOCOLS``)
    replaces that filter, ``ospf_only=False`` and ``protocols=None`` accept any route.
    """
    entry = routes.get(str(prefix))
    if entry is None:
        return []
    if protocols is not None:
        if str(entry['protocol']) not in protocols:
            return []
    elif ospf_only and not is_ospf_protocol(entry['protocol']):
        return []
    return [gw for gw, _dev in entry['nexthops'] if gw]


# ---------------------------------------------------------------------------
# show running-config
# ---------------------------------------------------------------------------

def _empty_interface_config() -> Dict[str, Any]:
    return {
        'cost': None, 'priority': None, 'hello_interval': None, 'dead_interval': None,
        'authentication': None, 'message_digest_keys': {}, 'authentication_key': None,
        'area': None, 'bandwidth': None, 'passive': None, 'network_type': None,
        'addresses': [], 'pim': False, 'igmp': False, 'multicast_boundary': None,
        'addresses6': [], 'ospf6': _empty_ospf6_interface_config(),
        'isis': _empty_isis_interface_config(),
    }


def _empty_ospf6_interface_config() -> Dict[str, Any]:
    return {'area': None, 'cost': None, 'passive': None, 'mtu_ignore': False, 'priority': None,
            'hello_interval': None, 'dead_interval': None, 'network_type': None, 'authentication': None}


def _empty_router_ospf6_config() -> Dict[str, Any]:
    return {'present': False, 'router_id': None, 'areas': {}, 'redistribute': [],
            'default_information_originate': False, 'default_information_always': False,
            'interface_areas': {}}


def _empty_area_config() -> Dict[str, Any]:
    return {'stub': False, 'nssa': False, 'no_summary': False, 'ranges': [], 'authentication': None,
            'default_cost': None}


def _empty_bgp_neighbor_config() -> Dict[str, Any]:
    return {
        'remote_as': None, 'peer_group': None, 'description': None, 'update_source': None,
        'timers': None, 'shutdown': False, 'password': None, 'ebgp_multihop': None,
        'next_hop_self': False, 'route_reflector_client': False, 'default_originate': False,
        'default_originate_route_map': None, 'route_map_in': None, 'route_map_out': None,
        'prefix_list_in': None, 'prefix_list_out': None, 'filter_list_in': None, 'filter_list_out': None,
        'soft_reconfiguration': False, 'send_community': True, 'activate': None,
        'interface': False,
        # BGP operations: maximum-prefix (address family), GTSM, BFD, graceful shutdown
        'maximum_prefix': None, 'maximum_prefix_out': None, 'ttl_security': None,
        'bfd': False, 'bfd_profile': None, 'graceful_shutdown': False,
    }


#: neighbour statements that belong to an address family (``address-family X unicast`` block,
#: or the IPv4 unicast family at router level): the per-family view of ``router_bgp``
_BGP_AF_NEIGHBOR_KEYS = ('activate', 'next_hop_self', 'route_reflector_client', 'default_originate',
                         'default_originate_route_map', 'route_map_in', 'route_map_out', 'prefix_list_in',
                         'prefix_list_out', 'filter_list_in', 'filter_list_out', 'soft_reconfiguration',
                         'send_community', 'maximum_prefix', 'maximum_prefix_out')


def _empty_bgp_af_config() -> Dict[str, Any]:
    return {'neighbors': {}, 'networks': [], 'aggregate_addresses': [], 'redistribute': [],
            'maximum_paths': None, 'maximum_paths_ibgp': None, 'dampening': None}


def _empty_router_bgp_config() -> Dict[str, Any]:
    return {
        'present': False, 'as': None, 'router_id': None, 'ebgp_requires_policy': True,
        'network_import_check': True, 'default_ipv4_unicast': True, 'bestpath': [], 'cluster_id': None,
        'default_local_preference': None, 'timers': None, 'neighbors': {}, 'networks': [],
        'aggregate_addresses': [], 'redistribute': [], 'address_families': {},
        'confederation_identifier': None, 'confederation_peers': [], 'graceful_shutdown': False,
        'maximum_paths': None, 'maximum_paths_ibgp': None, 'dampening': None,
    }


#: values of a bare ``bgp dampening`` (half-life and max-suppress in minutes, the penalties): FRR
#: prints the statement without its values when they are these defaults
BGP_DAMPENING_DEFAULTS = (15, 750, 2000, 60)


def _parse_router_bgp_line(rb: Dict[str, Any], words: List[str], neighbor_cfg, af: str = None) -> None:
    """Apply one indented ``router bgp`` statement (router level or address-family) to ``rb``.

    *af* is the address family of the enclosing ``address-family`` block (``'ipv6 unicast'``),
    ``None`` at router level: the family statements found there (``network``, ``neighbor X
    route-map``...) belong to IPv4 unicast.  They are applied to the merged view (the
    neighbour / router keys, as before) and to ``rb['address_families'][family]``."""
    if not words:
        return
    negated = words[0] == 'no'
    w = words[1:] if negated else words
    if not w:
        return
    if w[0] in ('address-family', 'exit-address-family'):
        return
    family = af or 'ipv4 unicast'

    def af_cfg() -> Dict[str, Any]:
        return rb['address_families'].setdefault(family, _empty_bgp_af_config())

    if w[0] == 'neighbor' and len(w) >= 3:
        n = neighbor_cfg(w[1])
        kw, arg = w[2], (w[3] if len(w) >= 4 else None)
        if kw == 'interface':
            # unnumbered peer: ``neighbor eth0 interface [remote-as external|internal|N]``
            n['interface'] = not negated
            if len(w) >= 5 and w[3] == 'remote-as':
                n['remote_as'] = int(w[4]) if w[4].isdigit() else w[4]
            return
        before = {k: n[k] for k in _BGP_AF_NEIGHBOR_KEYS}
        _apply_bgp_neighbor_keyword(n, w, kw, arg, negated)
        changed = {k: n[k] for k in _BGP_AF_NEIGHBOR_KEYS if n[k] != before[k]}
        if changed or kw in ('activate', 'send-community'):
            per_af = af_cfg()['neighbors'].setdefault(w[1], {})
            per_af.update(changed)
            if kw == 'activate':
                per_af['activate'] = not negated
        return
    _apply_bgp_router_keyword(rb, w, negated, af_cfg)


def _apply_bgp_neighbor_keyword(n: Dict[str, Any], w: List[str], kw: str, arg, negated: bool) -> None:
    """One ``neighbor PEER <kw> ...`` statement applied to the merged neighbour config *n*."""
    if kw == 'remote-as' and arg:
        n['remote_as'] = int(arg) if arg.isdigit() else arg
    elif kw == 'peer-group' and arg:
        n['peer_group'] = arg
    elif kw == 'description':
        n['description'] = " ".join(w[3:]) or None
    elif kw == 'update-source' and arg:
        n['update_source'] = arg
    elif kw == 'timers' and len(w) >= 5 and w[3].isdigit() and w[4].isdigit():
        n['timers'] = (int(w[3]), int(w[4]))
    elif kw == 'shutdown':
        n['shutdown'] = not negated
    elif kw == 'password':
        n['password'] = None if negated else arg
    elif kw == 'ebgp-multihop':
        n['ebgp_multihop'] = None if negated else (int(arg) if arg and arg.isdigit() else 255)
    elif kw == 'next-hop-self':
        n['next_hop_self'] = not negated
    elif kw == 'route-reflector-client':
        n['route_reflector_client'] = not negated
    elif kw == 'default-originate':
        n['default_originate'] = not negated
        if not negated and len(w) >= 5 and w[3] == 'route-map':
            n['default_originate_route_map'] = w[4]
    elif kw == 'route-map' and len(w) >= 5 and w[4] in ('in', 'out'):
        n[f'route_map_{w[4]}'] = None if negated else w[3]
    elif kw == 'prefix-list' and len(w) >= 5 and w[4] in ('in', 'out'):
        n[f'prefix_list_{w[4]}'] = None if negated else w[3]
    elif kw == 'filter-list' and len(w) >= 5 and w[4] in ('in', 'out'):
        n[f'filter_list_{w[4]}'] = None if negated else w[3]
    elif kw == 'soft-reconfiguration':
        n['soft_reconfiguration'] = not negated
    elif kw == 'send-community':
        n['send_community'] = not negated
    elif kw == 'activate':
        n['activate'] = not negated
    elif kw == 'maximum-prefix':
        n['maximum_prefix'] = None if negated else _maximum_prefix(w[3:])
    elif kw == 'maximum-prefix-out':
        n['maximum_prefix_out'] = None if negated else _int_or_none(arg)
    elif kw == 'ttl-security':
        # neighbor X ttl-security hops N
        n['ttl_security'] = None if negated else (_int_or_none(w[4]) if len(w) >= 5 and w[3] == 'hops' else None)
    elif kw == 'bfd':
        if len(w) >= 5 and w[3] == 'profile':
            n['bfd_profile'] = None if negated else w[4]
            if not negated:
                n['bfd'] = True
        else:
            n['bfd'] = not negated
            if negated:
                n['bfd_profile'] = None
    elif kw == 'graceful-shutdown':
        n['graceful_shutdown'] = not negated


def _maximum_prefix(words: List[str]) -> Optional[Dict[str, Any]]:
    """``N [THRESHOLD] [warning-only | restart MIN] [force]`` (the words after ``maximum-prefix``) ->
    ``{'limit', 'threshold', 'warning_only', 'restart', 'force'}`` (threshold / restart ``None`` when
    not given; FRR's default threshold is 75 %)."""
    if not words or not words[0].isdigit():
        return None
    result = {'limit': int(words[0]), 'threshold': None, 'warning_only': False, 'restart': None, 'force': False}
    rest = words[1:]
    if rest and rest[0].isdigit():
        result['threshold'] = int(rest[0])
        rest = rest[1:]
    for i, word in enumerate(rest):
        if word == 'warning-only':
            result['warning_only'] = True
        elif word == 'restart' and i + 1 < len(rest):
            result['restart'] = _int_or_none(rest[i + 1])
        elif word == 'force':
            result['force'] = True
    return result


def _apply_bgp_router_keyword(rb: Dict[str, Any], w: List[str], negated: bool, af_cfg) -> None:
    """A ``router bgp`` statement that is not a neighbour one; *af_cfg* returns the per-family
    view for the family statements (``network``, ``aggregate-address``, ``redistribute``)."""
    if w[0] == 'bgp' and len(w) >= 2:
        if w[1] == 'router-id' and len(w) >= 3:
            rb['router_id'] = None if negated else w[2]
        elif w[1] == 'ebgp-requires-policy':
            rb['ebgp_requires_policy'] = not negated
        elif w[1] == 'network' and len(w) >= 3 and w[2] == 'import-check':
            rb['network_import_check'] = not negated
        elif w[1] == 'default' and len(w) >= 3 and w[2] == 'ipv4-unicast':
            rb['default_ipv4_unicast'] = not negated
        elif w[1] == 'default' and len(w) >= 4 and w[2] == 'local-preference':
            rb['default_local_preference'] = None if negated else int(w[3])
        elif w[1] == 'bestpath' and len(w) >= 3:
            rb['bestpath'].append(" ".join(w[2:]))
        elif w[1] == 'cluster-id' and len(w) >= 3:
            rb['cluster_id'] = None if negated else w[2]
        elif w[1] == 'confederation' and len(w) >= 3 and w[2] == 'identifier':
            rb['confederation_identifier'] = None if negated else (_int_or_none(w[3]) if len(w) >= 4 else None)
        elif w[1] == 'confederation' and len(w) >= 3 and w[2] == 'peers':
            peers = [int(x) for x in w[3:] if x.isdigit()]
            if negated:
                rb['confederation_peers'] = [x for x in rb['confederation_peers'] if x not in peers] if peers else []
            else:
                rb['confederation_peers'] += [x for x in peers if x not in rb['confederation_peers']]
        elif w[1] == 'graceful-shutdown':
            rb['graceful_shutdown'] = not negated
        elif w[1] == 'dampening':
            values = None
            if not negated:
                numbers = [int(x) for x in w[2:6] if x.isdigit()]
                values = tuple(numbers) if len(numbers) == 4 else BGP_DAMPENING_DEFAULTS
            rb['dampening'] = values
            af_cfg()['dampening'] = values
        return
    if w[0] == 'maximum-paths' and len(w) >= 2:
        key = 'maximum_paths_ibgp' if w[1] == 'ibgp' else 'maximum_paths'
        value = w[2] if key == 'maximum_paths_ibgp' and len(w) >= 3 else w[1]
        number = None if negated else _int_or_none(value)
        rb[key] = number
        af_cfg()[key] = number
        return
    if w[0] == 'network' and len(w) >= 2:
        for target in (rb, af_cfg()):
            if negated:
                if w[1] in target['networks']:
                    target['networks'].remove(w[1])
            else:
                target['networks'].append(w[1])
    elif w[0] == 'aggregate-address' and len(w) >= 2 and not negated:
        rb['aggregate_addresses'].append((w[1], w[2:]))
        af_cfg()['aggregate_addresses'].append((w[1], w[2:]))
    elif w[0] == 'redistribute' and len(w) >= 2 and not negated:
        rb['redistribute'].append(w[1])
        af_cfg()['redistribute'].append(w[1])
    elif w[0] == 'timers' and len(w) >= 4 and w[1] == 'bgp' and w[2].isdigit() and w[3].isdigit():
        rb['timers'] = (int(w[2]), int(w[3]))


def parse_frr_config(text: str) -> Dict[str, Any]:
    """Parse an FRR configuration (``show running-config`` or ``frr.conf``).

    Returns::

        {'hostname': str | None,
         'static_routes': [(prefix, nexthop)],       # nexthop may be 'blackhole' / 'Null0'
         'router_ospf': {'present': bool, 'router_id': str | None,
                         'networks': [(prefix, area)], 'passive_interfaces': [...],
                         'passive_default': bool,
                         'areas': {area: {'stub', 'nssa', 'no_summary', 'ranges': [prefix],
                                          'authentication', 'default_cost'}},
                         'redistribute': [protocol, ...],
                         'default_information_originate': bool,
                         'default_information_always': bool,
                         'auto_cost_reference_bandwidth': int | None},
         'interfaces': {name: {'cost', 'priority', 'hello_interval', 'dead_interval',
                               'authentication' ('message-digest' | 'simple' | 'null' | 'key-chain'),
                               'message_digest_keys': {id: key}, 'authentication_key',
                               'area', 'bandwidth', 'passive' (True/False/None), 'network_type',
                               'addresses': ['10.0.0.1/32', ...]}},
         'router_bgp': {'present': bool, 'as': int | None, 'router_id': str | None,
                        'ebgp_requires_policy': bool, 'network_import_check': bool,
                        'default_ipv4_unicast': bool, 'bestpath': ['compare-routerid', ...],
                        'cluster_id', 'default_local_preference', 'timers': (keepalive, hold) | None,
                        'neighbors': {peer: {'remote_as': int | str | None, 'peer_group', 'description',
                                             'update_source', 'timers': (keepalive, hold) | None,
                                             'shutdown': bool, 'password', 'ebgp_multihop': int | None,
                                             'next_hop_self': bool, 'route_reflector_client': bool,
                                             'default_originate': bool, 'default_originate_route_map',
                                             'route_map_in', 'route_map_out', 'prefix_list_in',
                                             'prefix_list_out', 'filter_list_in', 'filter_list_out',
                                             'soft_reconfiguration': bool, 'send_community': bool,
                                             'activate': bool | None}},
                        'networks': [prefix], 'aggregate_addresses': [(prefix, [option, ...])],
                        'redistribute': [protocol, ...]},
         'prefix_lists': {name: [{'seq': int | None, 'action': 'permit' | 'deny', 'prefix': str,
                                  'ge': int | None, 'le': int | None}]},
         'route_maps': {name: [{'seq': int, 'action': 'permit' | 'deny',
                                'match': ['ip address prefix-list P', ...],
                                'set': ['local-preference 200', ...]}]},
         'as_path_lists': {name: [(seq | None, action, regexp)]},
         'community_lists': {name: [(seq | None, action, 'community ...')]},
         # IPv6 (separate keys: the IPv4 ones above are unchanged)
         'static_routes6': [(prefix, nexthop)],      # ``ipv6 route P blackhole`` -> (P, 'blackhole')
         'prefix_lists6': {name: [...same entries as prefix_lists...]},
         'router_ospf6': {'present': bool, 'router_id': str | None,
                          'areas': {area: {'stub', 'nssa', 'no_summary', 'ranges': [prefix], ...}},
                          'redistribute': [protocol, ...], 'default_information_originate': bool,
                          'default_information_always': bool,
                          'interface_areas': {ifname: area}},   # old ``interface X area A`` form
         # MPLS
         'access_lists': {name: [{'seq': int | None, 'action': 'permit' | 'deny', 'prefix': str,
                                  'exact': bool}]},
         'mpls_ldp': {'present': bool, 'router_id': str | None,
                      'transport_address': str | None,     # IPv4 family
                      'interfaces': [ifname],              # IPv4 family
                      'label_allocate': str | None,        # 'host-routes' | 'for ACL'
                      'label_advertise': [str],            # 'for ACL' | 'to ACL' | ...
                      'explicit_null': bool},
         # the BGP instances of the VRFs (``router bgp AS vrf NAME``): the keys of router_bgp
         # plus their VPN export / import (IPv4 unicast family)
         'router_bgp_vrfs': {vrf: {...router_bgp keys..., 'vpn': {'rd': str | None,
                                   'rt_import': [str], 'rt_export': [str], 'label': str | None,
                                   'export_vpn': bool, 'import_vpn': bool,
                                   'route_map_export': str | None, 'route_map_import': str | None}}},
         # EVPN: the ``vrf NAME`` blocks of zebra (their L3VNI)
         'vrfs': {vrf: {'vni': int | None}},
         }

    The ``address-family l2vpn evpn`` statements of ``router bgp`` and of the VRF instances go
    to ``address_families['l2vpn evpn']`` (read it with :func:`evpn_family`): ``advertise_all_vni``,
    ``advertise_ipv4_unicast``, ``autort_rfc8365``, ``rd`` / ``rt_import`` / ``rt_export`` (the
    L3VNI of a VRF instance) and ``vnis`` (the ``vni N`` blocks with their own RD and RTs);
    ``bgp_neighbor_activated(router_bgp, peer, 'l2vpn evpn')`` tells whether a neighbour is
    active in the family.

    ``router_ospf`` also gets ``'capability_opaque': bool``, ``'ti_lfa': None | 'link' |
    'node'`` (``fast-reroute ti-lfa [node-protection]``) and ``'segment_routing': {'enabled':
    bool, 'srgb': (low, high) | None, 'srlb': (low, high) | None, 'node_msd': int | None,
    'prefixes': {prefix: {'index': int, 'no_php': bool, 'explicit_null': bool}}}``.

    Interfaces also get ``'addresses6'`` (``ipv6 address``) and ``'ospf6'``: ``{'area', 'cost',
    'passive', 'mtu_ignore', 'priority', 'hello_interval', 'dead_interval', 'network_type',
    'authentication': {'key_id', 'hash_algo', 'key'} | {'keychain'} | None}`` (``ipv6 ospf6 ...``).
    ``router_bgp['address_families']`` is the per-family view of ``router bgp``:
    ``{'ipv4 unicast' | 'ipv6 unicast': {'neighbors': {peer: {'activate', 'route_map_in', ...
    only the keys set in that family}}, 'networks', 'aggregate_addresses', 'redistribute'}}``
    (router-level family statements count for IPv4 unicast); :func:`bgp_neighbor_activated`
    tells whether a neighbour is active in a family.  An unnumbered neighbour
    (``neighbor eth0 interface remote-as external``) has ``'interface': True``.

    BGP operations: a neighbour also has ``'maximum_prefix'`` (``None`` or ``{'limit', 'threshold',
    'warning_only', 'restart', 'force'}``), ``'maximum_prefix_out'``, ``'ttl_security'`` (the hops of
    GTSM), ``'bfd'`` / ``'bfd_profile'`` and ``'graceful_shutdown'``; ``router_bgp`` has
    ``'confederation_identifier'``, ``'confederation_peers'`` (ASNs), ``'graceful_shutdown'`` (the
    global form), ``'maximum_paths'`` / ``'maximum_paths_ibgp'`` and ``'dampening'`` (``(half-life,
    reuse, suppress, max-suppress)``, :data:`BGP_DAMPENING_DEFAULTS` for a bare ``bgp dampening``),
    the last three also in their family's view; ``cfg['rpki']`` = ``{'present', 'cache_servers':
    [{'mode', 'host', 'port', 'preference'}], 'polling_period', 'retry_interval',
    'expire_interval'}``.

    Area ids are normalised to dotted form (``area 1`` -> ``'0.0.0.1'``).  Both the
    router-level ``passive-interface X`` and the interface-level ``ip ospf passive``
    syntaxes are recognised; ``interfaces[X]['passive']`` reflects only the
    interface-level statement, ``router_ospf['passive_interfaces']`` the router-level one.
    In ``router bgp`` the statements of the ``address-family ipv4 unicast`` block and the
    router-level ones are merged (FRR moves ``network``, ``next-hop-self``, ``route-map``...
    into the address-family block in ``show running-config``).
    """
    cfg: Dict[str, Any] = {
        'hostname': None,
        'static_routes': [],
        'router_ospf': {
            'present': False, 'router_id': None, 'networks': [], 'passive_interfaces': [],
            'passive_default': False, 'areas': {}, 'redistribute': [],
            'default_information_originate': False, 'default_information_always': False,
            'auto_cost_reference_bandwidth': None,
            'capability_opaque': False, 'ti_lfa': None,
            'segment_routing': {'enabled': False, 'srgb': None, 'srlb': None, 'node_msd': None, 'prefixes': {}},
        },
        'interfaces': {},
        'router_bgp': _empty_router_bgp_config(),
        'prefix_lists': {},
        'route_maps': {},
        'as_path_lists': {},
        'community_lists': {},
        'static_routes6': [],
        'prefix_lists6': {},
        'router_ospf6': _empty_router_ospf6_config(),
        'access_lists': {},
        'mpls_ldp': {'present': False, 'router_id': None, 'transport_address': None, 'interfaces': [],
                     'label_allocate': None, 'label_advertise': [], 'explicit_null': False},
        'router_bgp_vrfs': {},
        'router_isis': _empty_router_isis_config(),
        'bfd': {'profiles': {}},
        'vrfs': {},
        'rpki': {'present': False, 'cache_servers': [], 'polling_period': None, 'retry_interval': None,
                 'expire_interval': None},
    }
    # 'router_ospf' | 'router_ospf6' | 'router_bgp' | 'interface' | 'route_map' | 'mpls_ldp' |
    # 'router_isis' | 'bfd' | 'vrf' | 'rpki' | 'other' | None
    section: Optional[str] = None
    ri = cfg['router_isis']
    bfd_profile: Dict[str, Any] | None = None   # the open ``profile NAME`` block of bfd
    iface: Dict[str, Any] | None = None
    rm_entry: Dict[str, Any] | None = None
    bgp_af: Optional[str] = None   # address family of the open ``address-family`` block of router bgp
    ldp_af: Optional[str] = None   # address family of the open ``address-family`` block of mpls ldp
    ro = cfg['router_ospf']
    ro6 = cfg['router_ospf6']
    rb = cfg['router_bgp']
    ml = cfg['mpls_ldp']
    vrb: Dict[str, Any] | None = None   # the open ``router bgp AS vrf NAME`` block
    vrf_cfg: Dict[str, Any] | None = None   # the open ``vrf NAME`` block (its L3VNI)
    evpn_vni: Dict[str, Any] | None = None  # the open ``vni N`` block of ``address-family l2vpn evpn``

    def vrf_neighbor_cfg(peer: str) -> Dict[str, Any]:
        if peer not in vrb['neighbors']:
            vrb['neighbors'][peer] = _empty_bgp_neighbor_config()
        return vrb['neighbors'][peer]

    def neighbor_cfg(peer: str) -> Dict[str, Any]:
        if peer not in rb['neighbors']:
            rb['neighbors'][peer] = _empty_bgp_neighbor_config()
        return rb['neighbors'][peer]

    def seq_of(w: List[str]):
        """Return (seq, rest) for a 'seq N ...' prefix of the word list."""
        if len(w) >= 2 and w[0] == 'seq' and w[1].isdigit():
            return int(w[1]), w[2:]
        return None, w

    def area_cfg(area: str, router: Dict[str, Any] = None) -> Dict[str, Any]:
        router = ro if router is None else router
        key = normalize_area(area)
        if key not in router['areas']:
            router['areas'][key] = _empty_area_config()
        return router['areas'][key]

    def prefix_list_entry(words: List[str], target: Dict[str, List[Dict[str, Any]]]) -> None:
        # (ip|ipv6) prefix-list NAME [seq N] permit|deny PREFIX [ge X] [le Y]
        seq, rest = seq_of(words[3:])
        if len(rest) >= 2 and rest[0] in ('permit', 'deny'):
            entry = {'seq': seq, 'action': rest[0], 'prefix': rest[1], 'ge': None, 'le': None}
            for i in range(2, len(rest) - 1):
                if rest[i] in ('ge', 'le') and rest[i + 1].isdigit():
                    entry[rest[i]] = int(rest[i + 1])
            target.setdefault(words[2], []).append(entry)

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip() == '!':
            continue
        stripped = line.strip()
        words = stripped.split()

        if not line[0].isspace():
            # top-level line: opens a section or is a global statement
            if stripped in ('exit', 'end', 'exit-address-family'):
                section, iface, rm_entry = None, None, None
                continue
            if words[0] == 'interface' and len(words) >= 2:
                section = 'interface'
                iface = cfg['interfaces'].setdefault(words[1], _empty_interface_config())
                continue
            if words[0] == 'router' and len(words) >= 2 and words[1] == 'ospf':
                section = 'router_ospf'
                iface = None
                ro['present'] = True
                continue
            if words[0] == 'router' and len(words) >= 2 and words[1] == 'ospf6':
                section, iface = 'router_ospf6', None
                ro6['present'] = True
                continue
            if words[0] == 'router' and len(words) >= 5 and words[1] == 'bgp' and words[3] == 'vrf':
                section, iface, bgp_af = 'router_bgp_vrf', None, None
                vrb = cfg['router_bgp_vrfs'].setdefault(words[4], _empty_router_bgp_vrf_config())
                vrb['present'] = True
                vrb['as'] = int(words[2]) if words[2].isdigit() else words[2]
                continue
            if words[0] == 'router' and len(words) >= 3 and words[1] == 'bgp':
                section, iface, bgp_af = 'router_bgp', None, None
                rb['present'] = True
                rb['as'] = int(words[2]) if words[2].isdigit() else words[2]
                continue
            if words[0] == 'route-map' and len(words) >= 4 and words[2] in ('permit', 'deny'):
                section, iface = 'route_map', None
                rm_entry = {'seq': int(words[3]) if words[3].isdigit() else words[3], 'action': words[2],
                            'match': [], 'set': []}
                cfg['route_maps'].setdefault(words[1], []).append(rm_entry)
                continue
            if words[:2] == ['mpls', 'ldp']:
                section, iface, ldp_af = 'mpls_ldp', None, None
                ml['present'] = True
                continue
            if words[:2] == ['router', 'isis'] and len(words) >= 3:
                section, iface = 'router_isis', None
                ri['present'] = True
                ri['name'] = words[2]
                continue
            if words == ['bfd']:
                section, iface, bfd_profile = 'bfd', None, None
                continue
            if words == ['rpki']:
                section, iface = 'rpki', None
                cfg['rpki']['present'] = True
                continue
            if words[0] == 'vrf' and len(words) >= 2:
                section, iface = 'vrf', None
                vrf_cfg = cfg['vrfs'].setdefault(words[1], {'vni': None})
                continue
            if words[0] == 'router' or words[0] in ('vrf', 'route-map', 'key', 'line', 'segment-routing'):
                section, iface = 'other', None
                continue
            section, iface, rm_entry = None, None, None
            if words[0] == 'hostname' and len(words) >= 2:
                cfg['hostname'] = words[1]
            elif words[0] == 'access-list' and len(words) >= 4:
                # access-list NAME [seq N] permit|deny PREFIX [exact-match]
                seq, rest = seq_of(words[2:])
                if len(rest) >= 2 and rest[0] in ('permit', 'deny'):
                    cfg['access_lists'].setdefault(words[1], []).append(
                        {'seq': seq, 'action': rest[0], 'prefix': rest[1], 'exact': 'exact-match' in rest[2:]})
            elif words[0] == 'ip' and len(words) >= 4 and words[1] == 'route':
                cfg['static_routes'].append((words[2], words[3]))
            elif words[0] == 'ipv6' and len(words) >= 4 and words[1] == 'route':
                cfg['static_routes6'].append((words[2], words[3]))
            elif words[:2] == ['ip', 'prefix-list'] and len(words) >= 5:
                prefix_list_entry(words, cfg['prefix_lists'])
            elif words[:2] == ['ipv6', 'prefix-list'] and len(words) >= 5:
                prefix_list_entry(words, cfg['prefix_lists6'])
            elif words[:3] == ['bgp', 'as-path', 'access-list'] and len(words) >= 6:
                # bgp as-path access-list NAME [seq N] permit|deny REGEXP
                seq, rest = seq_of(words[4:])
                if len(rest) >= 2 and rest[0] in ('permit', 'deny'):
                    cfg['as_path_lists'].setdefault(words[3], []).append((seq, rest[0], " ".join(rest[1:])))
            elif words[:2] == ['bgp', 'community-list'] and len(words) >= 5:
                # bgp community-list [standard|expanded] NAME [seq N] permit|deny COMMUNITY...
                rest = words[2:]
                if rest and rest[0] in ('standard', 'expanded'):
                    rest = rest[1:]
                if len(rest) >= 3:
                    name = rest[0]
                    seq, rest2 = seq_of(rest[1:])
                    if len(rest2) >= 2 and rest2[0] in ('permit', 'deny'):
                        cfg['community_lists'].setdefault(name, []).append((seq, rest2[0], " ".join(rest2[1:])))
            continue

        # indented line: belongs to the current section
        if section == 'interface' and iface is not None:
            if words[:2] == ['ip', 'ospf'] and len(words) >= 3:
                sub = words[2]
                arg = words[3] if len(words) >= 4 else None
                if sub == 'cost' and arg:
                    iface['cost'] = int(arg)
                elif sub == 'priority' and arg:
                    iface['priority'] = int(arg)
                elif sub == 'hello-interval' and arg:
                    iface['hello_interval'] = int(arg)
                elif sub == 'dead-interval' and arg:
                    iface['dead_interval'] = int(arg) if arg.isdigit() else arg
                elif sub == 'authentication':
                    iface['authentication'] = arg if arg else 'simple'
                elif sub == 'authentication-key' and arg:
                    iface['authentication_key'] = arg
                elif sub == 'message-digest-key' and len(words) >= 6 and words[4] == 'md5':
                    iface['message_digest_keys'][int(arg)] = words[5]
                elif sub == 'area' and arg:
                    iface['area'] = normalize_area(arg)
                elif sub == 'passive':
                    iface['passive'] = True
                elif sub == 'network' and arg:
                    iface['network_type'] = arg
            elif words[:3] == ['no', 'ip', 'ospf'] and len(words) >= 4 and words[3] == 'passive':
                iface['passive'] = False
            elif words[0] == 'bandwidth' and len(words) >= 2:
                iface['bandwidth'] = int(words[1])
            elif words[:2] == ['ip', 'address'] and len(words) >= 3:
                iface['addresses'].append(words[2])
            elif words == ['ip', 'pim']:
                iface['pim'] = True
            elif words == ['ip', 'igmp']:
                iface['igmp'] = True
            elif words[:4] == ['ip', 'multicast', 'boundary', 'oil'] and len(words) >= 5:
                iface['multicast_boundary'] = words[4]
            elif words[:2] == ['ipv6', 'address'] and len(words) >= 3:
                iface['addresses6'].append(words[2])
            elif words[:2] == ['ipv6', 'ospf6'] and len(words) >= 3:
                _parse_ospf6_interface_line(iface['ospf6'], words[2:], negated=False)
            elif words[:3] == ['no', 'ipv6', 'ospf6'] and len(words) >= 4:
                _parse_ospf6_interface_line(iface['ospf6'], words[3:], negated=True)
            elif words[0] == 'isis' or words[1:3] == ['router', 'isis']:
                _parse_isis_interface_line(iface['isis'], words, negated=False)
            elif words[0] == 'no' and len(words) >= 2 and (words[1] == 'isis' or words[2:4] == ['router', 'isis']):
                _parse_isis_interface_line(iface['isis'], words[1:], negated=True)
            continue

        if section == 'router_isis':
            _parse_router_isis_line(ri, words)
            continue

        if section == 'rpki':
            _parse_rpki_line(cfg['rpki'], words)
            continue

        if section == 'bfd':
            if words[0] in ('profile', 'peer') and len(words) >= 2:
                bfd_profile = cfg['bfd']['profiles'].setdefault(words[1], {}) if words[0] == 'profile' else None
            elif words == ['exit']:
                bfd_profile = None
            else:
                _parse_bfd_line(cfg['bfd'], bfd_profile, words)
            continue

        if section == 'mpls_ldp':
            if words[0] == 'address-family' and len(words) >= 2:
                ldp_af = words[1]
            elif words[0] == 'exit-address-family':
                ldp_af = None
            elif words[0] == 'router-id' and len(words) >= 2:
                ml['router_id'] = words[1]
            elif ldp_af == 'ipv4':
                if words[:2] == ['discovery', 'transport-address'] and len(words) >= 3:
                    ml['transport_address'] = words[2]
                elif words[0] == 'interface' and len(words) >= 2:
                    ml['interfaces'].append(words[1])
                elif words[:3] == ['label', 'local', 'allocate'] and len(words) >= 4:
                    ml['label_allocate'] = " ".join(words[3:])
                elif words[:3] == ['label', 'local', 'advertise']:
                    if 'explicit-null' in words:
                        ml['explicit_null'] = True
                    elif len(words) >= 4:
                        ml['label_advertise'].append(" ".join(words[3:]))
            continue

        if section == 'route_map' and rm_entry is not None:
            if words[0] == 'match' and len(words) >= 2:
                rm_entry['match'].append(" ".join(words[1:]))
            elif words[0] == 'set' and len(words) >= 2:
                rm_entry['set'].append(" ".join(words[1:]))
            continue

        if section == 'vrf' and vrf_cfg is not None:
            if words[0] == 'vni' and len(words) >= 2 and words[1].isdigit():
                vrf_cfg['vni'] = int(words[1])
            elif words[:2] == ['no', 'vni']:
                vrf_cfg['vni'] = None
            continue

        if section == 'router_bgp_vrf' and vrb is not None:
            if words[0] == 'address-family' and len(words) >= 2:
                bgp_af = " ".join(words[1:3]) if len(words) >= 3 else f"{words[1]} unicast"
                evpn_vni = None
            elif words[0] == 'exit-address-family':
                bgp_af, evpn_vni = None, None
            if bgp_af == 'l2vpn evpn':
                handled, evpn_vni = _parse_evpn_line(vrb, words, evpn_vni)
                if handled:
                    continue
            if not _parse_bgp_vpn_line(vrb['vpn'], words):
                _parse_router_bgp_line(vrb, words, vrf_neighbor_cfg, af=bgp_af)
            continue

        if section == 'router_bgp':
            if words[0] == 'address-family' and len(words) >= 2:
                bgp_af = " ".join(words[1:3]) if len(words) >= 3 else f"{words[1]} unicast"
                evpn_vni = None
            elif words[0] == 'exit-address-family':
                bgp_af, evpn_vni = None, None
            if bgp_af == 'l2vpn evpn':
                handled, evpn_vni = _parse_evpn_line(rb, words, evpn_vni)
                if handled:
                    continue
            _parse_router_bgp_line(rb, words, neighbor_cfg, af=bgp_af)
            continue

        if section == 'router_ospf6':
            if words[:2] == ['ospf6', 'router-id'] and len(words) >= 3:
                ro6['router_id'] = words[2]
            elif words[0] == 'area' and len(words) >= 3:
                a = area_cfg(words[1], ro6)
                kw = words[2]
                if kw == 'stub':
                    a['stub'] = True
                    a['no_summary'] = 'no-summary' in words[3:]
                elif kw == 'nssa':
                    a['nssa'] = True
                    a['no_summary'] = 'no-summary' in words[3:]
                elif kw == 'range' and len(words) >= 4:
                    a['ranges'].append(words[3])
            elif words[0] == 'redistribute' and len(words) >= 2:
                ro6['redistribute'].append(words[1])
            elif words[:2] == ['default-information', 'originate']:
                ro6['default_information_originate'] = True
                ro6['default_information_always'] = 'always' in words[2:]
            elif words[0] == 'interface' and len(words) >= 4 and words[2] == 'area':
                ro6['interface_areas'][words[1]] = normalize_area(words[3])
            continue

        if section == 'router_ospf':
            if words[0] in ('ospf', 'router-id') and 'router-id' in words:
                ro['router_id'] = words[-1]
            elif words[0] == 'network' and len(words) >= 4 and words[2] == 'area':
                ro['networks'].append((words[1], normalize_area(words[3])))
            elif words[0] == 'passive-interface' and len(words) >= 2:
                if words[1] == 'default':
                    ro['passive_default'] = True
                else:
                    ro['passive_interfaces'].append(words[1])
            elif words[0] == 'no' and len(words) >= 3 and words[1] == 'passive-interface':
                if words[2] in ro['passive_interfaces']:
                    ro['passive_interfaces'].remove(words[2])
            elif words[0] == 'area' and len(words) >= 3:
                a = area_cfg(words[1])
                kw = words[2]
                if kw == 'stub':
                    a['stub'] = True
                    a['no_summary'] = 'no-summary' in words[3:]
                elif kw == 'nssa':
                    a['nssa'] = True
                    a['no_summary'] = 'no-summary' in words[3:]
                elif kw == 'range' and len(words) >= 4:
                    a['ranges'].append(words[3])
                elif kw == 'authentication':
                    a['authentication'] = words[3] if len(words) >= 4 else 'simple'
                elif kw == 'default-cost' and len(words) >= 4:
                    a['default_cost'] = int(words[3])
            elif words[0] == 'redistribute' and len(words) >= 2:
                ro['redistribute'].append(words[1])
            elif words[:2] == ['default-information', 'originate']:
                ro['default_information_originate'] = True
                ro['default_information_always'] = 'always' in words[2:]
            elif words[:2] == ['auto-cost', 'reference-bandwidth'] and len(words) >= 3:
                ro['auto_cost_reference_bandwidth'] = int(words[2])
            elif words[:2] == ['capability', 'opaque']:
                ro['capability_opaque'] = True
            elif words[:2] == ['fast-reroute', 'ti-lfa']:
                ro['ti_lfa'] = 'node' if 'node-protection' in words else 'link'
            elif words[0] == 'segment-routing' and len(words) >= 2:
                _parse_ospf_sr_line(ro['segment_routing'], words[1:])
            continue

    return cfg


def _parse_rpki_line(rpki: Dict[str, Any], words: List[str]) -> None:
    """One statement of the ``rpki`` block: ``rpki cache tcp HOST PORT [source A] preference N``,
    ``rpki polling_period N`` (also the ``retry_interval`` / ``expire_interval`` timers)."""
    negated = words[0] == 'no'
    w = words[1:] if negated else words
    if len(w) < 3 or w[0] != 'rpki':
        return
    if w[1] == 'cache':
        rest = w[2:]
        mode = 'tcp'
        if rest and rest[0] in ('tcp', 'ssh'):
            mode, rest = rest[0], rest[1:]
        if len(rest) < 2:
            return
        server = {'mode': mode, 'host': rest[0], 'port': _int_or_none(rest[1]), 'preference': None}
        if 'preference' in rest[:-1]:
            server['preference'] = _int_or_none(rest[rest.index('preference') + 1])
        rpki['cache_servers'] = [s for s in rpki['cache_servers']
                                 if (s['host'], s['port']) != (server['host'], server['port'])]
        if not negated:
            rpki['cache_servers'].append(server)
    elif w[1] in ('polling_period', 'retry_interval', 'expire_interval'):
        rpki[w[1]] = None if negated else _int_or_none(w[2])


def _empty_router_bgp_vrf_config() -> Dict[str, Any]:
    cfg = _empty_router_bgp_config()
    cfg['vpn'] = {'rd': None, 'rt_import': [], 'rt_export': [], 'label': None, 'export_vpn': False,
                  'import_vpn': False, 'route_map_export': None, 'route_map_import': None}
    return cfg


def _parse_bgp_vpn_line(vpn: Dict[str, Any], words: List[str]) -> bool:
    """A VPN statement of the IPv4 unicast family of a VRF instance applied to *vpn* (``rd vpn
    export``, ``rt vpn both|import|export``, ``label vpn export``, ``export vpn``, ``import vpn``,
    their ``no`` forms); False for any other statement."""
    negated = bool(words) and words[0] == 'no'
    w = words[1:] if negated else words
    if w[:3] == ['rd', 'vpn', 'export']:
        vpn['rd'] = None if negated else (w[3] if len(w) >= 4 else None)
    elif w[:2] == ['rt', 'vpn'] and len(w) >= 3 and w[2] in ('both', 'import', 'export'):
        keys = ['rt_import', 'rt_export'] if w[2] == 'both' else [f"rt_{w[2]}"]
        for key in keys:
            if negated:
                vpn[key] = [x for x in vpn[key] if x not in w[3:]] if w[3:] else []
            else:
                vpn[key] = list(w[3:])
    elif w[:3] == ['label', 'vpn', 'export']:
        vpn['label'] = None if negated else (w[3] if len(w) >= 4 else None)
    elif w == ['export', 'vpn']:
        vpn['export_vpn'] = not negated
    elif w == ['import', 'vpn']:
        vpn['import_vpn'] = not negated
    elif w[:2] == ['route-map', 'vpn'] and len(w) >= 3 and w[2] in ('export', 'import'):
        vpn[f"route_map_{w[2]}"] = None if negated else (w[3] if len(w) >= 4 else None)
    else:
        return False
    return True


def _parse_ospf_sr_line(sr: Dict[str, Any], w: List[str]) -> None:
    """``segment-routing <w...>`` of ``router ospf`` applied to *sr*."""
    def block(i: int):
        if len(w) > i + 2 and w[i + 1].isdigit() and w[i + 2].isdigit():
            return int(w[i + 1]), int(w[i + 2])
        return None
    if w[0] == 'on':
        sr['enabled'] = True
    elif w[0] in ('global-block', 'local-block'):
        for i, word in enumerate(w):
            if word == 'global-block':
                sr['srgb'] = block(i)
            elif word == 'local-block':
                sr['srlb'] = block(i)
    elif w[0] == 'node-msd' and len(w) >= 2 and w[1].isdigit():
        sr['node_msd'] = int(w[1])
    elif w[0] == 'prefix' and len(w) >= 4 and w[2] == 'index' and w[3].isdigit():
        sr['prefixes'][w[1]] = {'index': int(w[3]), 'no_php': 'no-php-flag' in w[4:],
                                'explicit_null': 'explicit-null' in w[4:]}


def _parse_ospf6_interface_line(o6: Dict[str, Any], w: List[str], negated: bool) -> None:
    """``ipv6 ospf6 <w...>`` (or its ``no`` form) of an interface block applied to *o6*."""
    sub = w[0]
    arg = w[1] if len(w) >= 2 else None
    if sub == 'area':
        o6['area'] = None if negated or not arg else normalize_area(arg)
    elif sub == 'passive':
        o6['passive'] = not negated
    elif sub == 'mtu-ignore':
        o6['mtu_ignore'] = not negated
    elif sub in ('cost', 'priority', 'hello-interval', 'dead-interval'):
        key = sub.replace('-', '_')
        o6[key] = None if negated or not (arg and arg.isdigit()) else int(arg)
    elif sub == 'network':
        o6['network_type'] = None if negated else arg
    elif sub == 'authentication':
        if negated:
            o6['authentication'] = None
        elif arg == 'keychain' and len(w) >= 3:
            o6['authentication'] = {'keychain': w[2]}
        else:
            # ipv6 ospf6 authentication key-id N hash-algo ALGO key KEY
            auth = {'key_id': None, 'hash_algo': None, 'key': None}
            for i in range(1, len(w) - 1):
                if w[i] == 'key-id' and w[i + 1].isdigit():
                    auth['key_id'] = int(w[i + 1])
                elif w[i] == 'hash-algo':
                    auth['hash_algo'] = w[i + 1]
                elif w[i] == 'key':
                    auth['key'] = w[i + 1]
            o6['authentication'] = auth


def bgp_neighbor_activated(router_bgp: Dict[str, Any], peer, afi: str = 'ipv4') -> bool:
    """Whether the neighbour *peer* of a ``router_bgp`` of :func:`parse_frr_config` is active in
    the unicast family *afi* (``'ipv4'``, ``'ipv6'``) or in the family named in full (``'ipv4
    vpn'``): an explicit ``[no] neighbor X activate`` of that family wins; else IPv4 unicast
    follows ``bgp default ipv4-unicast`` (on by default in FRR's traditional profile) and the
    other families are off."""
    peer = str(peer)
    if peer not in (router_bgp or {}).get('neighbors', {}):
        return False
    family = afi if ' ' in afi else f"{afi} unicast"
    per_af = router_bgp.get('address_families', {}).get(family, {}).get('neighbors', {}).get(peer, {})
    if per_af.get('activate') is not None:
        return bool(per_af['activate'])
    return afi == 'ipv4' and bool(router_bgp.get('default_ipv4_unicast', True))


def prefix_list_permits(prefix_lists: Dict[str, List[Dict[str, Any]]], name: str, prefix) -> Optional[bool]:
    """How the prefix-list *name* of :func:`parse_frr_config` treats *prefix* (an address or a
    network): True for permit, False for deny (the first matching entry in ``seq`` order, an
    implicit deny when none matches), ``None`` when the list does not exist.  An address is the
    host prefix (/32 or /128), which is how pimd matches a group."""
    entries = prefix_lists.get(name)
    if entries is None:
        return None
    try:
        target = ip_network(str(prefix), strict=False)
    except ValueError:
        return False
    ordered = sorted(entries, key=lambda e: (e['seq'] is None, e['seq'] if isinstance(e['seq'], int) else 0))
    for entry in ordered:
        try:
            network = ip_network(entry['prefix'], strict=False)
        except ValueError:
            continue
        if network.version != target.version or not target.subnet_of(network):
            continue
        low = entry['ge'] if entry['ge'] is not None else network.prefixlen
        high = entry['le'] if entry['le'] is not None else (network.max_prefixlen if entry['ge'] is not None
                                                            else network.prefixlen)
        if low <= target.prefixlen <= high:
            return entry['action'] == 'permit'
    return False


def get_frr_running_config(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Any]:
    """Run 'vtysh -c "show running-config"' and parse it (see :func:`parse_frr_config`).
    Returns {} on error or empty output."""
    output, code = _test(grade, machine_name, 'vtysh -c "show running-config"', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_frr_config(output)


def expected_auto_cost(reference_bandwidth: int, interface_bandwidth: int) -> int:
    """OSPF cost FRR computes for an interface: ``round(reference / bandwidth)`` clamped to
    ``[1, 65535]`` (both in Mbit/s; the default reference is 100000 and a veth reports 10000,
    hence the default cost of 10)."""
    if not interface_bandwidth:
        return 10
    cost = int(reference_bandwidth / interface_bandwidth + 0.5)
    return max(1, min(65535, cost))


# ---------------------------------------------------------------------------
# BGP (json output of vtysh)
# ---------------------------------------------------------------------------

def _vtysh_json(grade: Grade0, machine_name: str, command: str, step: int = 1, allow_error: bool = False) -> Any:
    """Run ``vtysh -c "<command> json"`` and return the decoded JSON object.

    Returns ``{}`` on the registration-pass placeholder, on a non-zero exit code, when
    BGP is not configured (``% ...`` error line) or when the output is not a JSON object.
    """
    output, code = _test(grade, machine_name, f'vtysh -c "{command} json"', step, allow_error)
    if code != 0 or not output:
        return {}
    start = output.find('{')
    if start < 0:
        return {}
    try:
        data = json.loads(output[start:])
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _int_or_none(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _afi_safi(afi: str) -> str:
    """``'ipv4'`` / ``'ipv6'`` -> the ``show bgp`` keywords of that unicast family."""
    if afi not in ('ipv4', 'ipv6'):
        raise ValueError(f"afi must be 'ipv4' or 'ipv6', not {afi!r}")
    return f"{afi} unicast"


def _af_key(afi: str) -> str:
    """``'ipv4'`` -> ``'ipv4Unicast'`` (the key of a family in the json of bgpd)."""
    return 'ipv6Unicast' if afi == 'ipv6' else 'ipv4Unicast'


def as_list_from_string(path) -> List[int]:
    """``'65100 65000'`` -> ``[65100, 65000]`` (AS sets ``{65100,65000}`` keep their members, and so
    do the confederation segments ``(65101 65102)``: see :func:`confed_as_list_from_string`)."""
    if not path:
        return []
    return [int(tok) for tok in re.findall(r'\d+', str(path))]


def confed_as_list_from_string(path) -> List[int]:
    """The member ASes of a confederation crossed by a path: the numbers between parentheses
    (``'(65101 65102) 64500'`` -> ``[65101, 65102]``; ``[]`` outside a confederation)."""
    if not path:
        return []
    return [int(tok) for seg in re.findall(r'\(([^)]*)\)', str(path)) for tok in re.findall(r'\d+', seg)]


#: the validation states of a path (``rpki`` of :func:`parse_bgp_routes` / :func:`parse_bgp_prefix`)
RPKI_STATES = ('valid', 'invalid', 'notfound')


def _rpki_state(e: Dict[str, Any]) -> Optional[str]:
    """``'valid'`` / ``'invalid'`` / ``'notfound'`` from ``rpkiValidationState`` (one prefix: ``'not
    found'``) or the ``rpkiValid`` / ``rpkiInvalid`` / ``rpkiNotFound`` booleans (whole table);
    ``None`` without RPKI (bgpd started without ``-M rpki``)."""
    state = e.get('rpkiValidationState')
    if isinstance(state, str):
        state = state.replace(' ', '').lower()
        return state if state in RPKI_STATES else None
    for key, value in (('rpkiValid', 'valid'), ('rpkiInvalid', 'invalid'), ('rpkiNotFound', 'notfound')):
        if e.get(key):
            return value
    return None


# -- show bgp ipv4 unicast summary ------------------------------------------

def parse_bgp_summary(data: Any) -> Dict[str, Any]:
    """Parse the JSON of ``show bgp ipv4 unicast summary``.

    Accepts the flat address-family object or the ``{'ipv4Unicast': {...}}`` /
    ``{'ipv6Unicast': {...}}`` wrapper of ``show bgp summary json`` (IPv4 first).  Peers are
    keyed by address, or by interface name for an unnumbered neighbour (``'eth1'``).
    Returns ``{}`` when no BGP process answers, else::

        {'router_id': '10.0.0.1', 'as': 65001,
         'peers': {'10.1.1.2': {'remote_as': 65100, 'state': 'Established', 'established': True,
                                'policy_blocked': False,   # eBGP peer without in/out policy (RFC 8212)
                                'pfx_rcd': 3, 'pfx_snt': 1, 'description': 'ISP-A',
                                'uptime': '00:12:34'}}}
    """
    if not isinstance(data, dict):
        return {}
    for key in ('ipv4Unicast', 'ipv6Unicast'):
        if key in data and isinstance(data[key], dict):
            data = data[key]
            break
    if 'routerId' not in data and 'peers' not in data:
        return {}
    peers: Dict[str, Dict[str, Any]] = {}
    for ip, p in (data.get('peers') or {}).items():
        if not isinstance(p, dict):
            continue
        state = p.get('state')
        peers[ip] = {
            'remote_as': _int_or_none(p.get('remoteAs')),
            'state': state,
            'established': state == 'Established',
            'policy_blocked': p.get('peerState') == 'Policy',
            'pfx_rcd': _int_or_none(p.get('pfxRcd')) or 0,
            'pfx_snt': _int_or_none(p.get('pfxSnt')) or 0,
            'description': p.get('desc'),
            'uptime': p.get('peerUptime'),
            'id_type': p.get('idType'),
            'peer_state': p.get('peerState'),
            # the session was closed because the peer sent more prefixes than maximum-prefix
            'prefix_limit_exceeded': p.get('peerState') == 'PfxCt',
        }
    return {'router_id': data.get('routerId'), 'as': _int_or_none(data.get('as')), 'peers': peers,
            'dampening_enabled': bool(data.get('dampeningEnabled'))}


def get_bgp_summary(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                    afi: str = 'ipv4', vrf: str = None) -> Dict[str, Any]:
    """Run 'vtysh -c "show bgp ipv4 unicast summary json"' (``afi='ipv6'``: the IPv6 unicast
    family; ``vrf``: the instance of that VRF, ``show bgp vrf X ipv4 unicast summary``; see
    :func:`parse_bgp_summary`).  Returns {} when BGP is not running, and when no neighbour is
    active in that family."""
    return parse_bgp_summary(_vtysh_json(grade, machine_name, f'show bgp {_vrf_words(vrf)}{_afi_safi(afi)} summary',
                                         step, allow_error))


def _vrf_words(vrf: str = None) -> str:
    return f"vrf {vrf} " if vrf else ""


def get_bgp_vpn_summary(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[str, Any]:
    """The neighbours of the IPv4 VPN family (``show bgp ipv4 vpn summary json``, the shape of
    :func:`parse_bgp_summary`); {} when no neighbour is active in it."""
    return parse_bgp_summary(_vtysh_json(grade, machine_name, 'show bgp ipv4 vpn summary', step, allow_error))


# -- show bgp neighbors X -----------------------------------------------------

def parse_bgp_neighbor(data: Any, peer: str = None, afi: str = 'ipv4') -> Dict[str, Any]:
    """Parse the JSON of ``show bgp neighbors <peer>``.

    The output is keyed by peer address (interface name for an unnumbered neighbour);
    ``peer`` selects an entry (the first one when omitted).  The per-family fields (prefix
    counters, policies, next-hop-self...) are those of the unicast family *afi*
    (``addressFamilyInfo.ipv4Unicast`` / ``ipv6Unicast``; ``af`` = ``{}`` when the neighbour is
    not active in it).  ``nexthop_global`` / ``nexthop_local`` are the IPv6 next hops the
    router sends this peer.  Returns ``{}`` when the neighbour does not exist, else::

        {'peer': '10.1.1.2', 'remote_as': 65100, 'local_as': 65001, 'state': 'Established',
         'established': True, 'link': 'external' | 'internal', 'description': 'ISP-A',
         'remote_router_id': '100.100.100.100', 'local_router_id': '10.0.3.1',
         'hold_time': 30, 'keepalive': 10,                    # negotiated, seconds
         'configured_hold_time': 30, 'configured_keepalive': 10,
         'local_host': '10.0.3.1', 'foreign_host': '10.0.3.2', 'update_source': 'lo' | None,
         'accepted_prefixes': 3, 'sent_prefixes': 1,
         'route_reflector_client': False, 'next_hop_self': False, 'default_originate': False,
         'default_originate_route_map': None,
         'route_map_in': 'LP-IN', 'route_map_out': None, 'prefix_list_in': None, 'prefix_list_out': None,
         'send_community': True, 'nexthop_global': None, 'nexthop_local': None,
         'af': {...ipv4Unicast...}, 'raw': {...}}
    """
    if not isinstance(data, dict) or not data:
        return {}
    if 'bgpNoSuchNeighbor' in data or 'warning' in data:
        return {}
    if peer is not None:
        entry = data.get(str(peer))
    else:
        entry = next((v for v in data.values() if isinstance(v, dict)), None)
    if not isinstance(entry, dict) or 'bgpState' not in entry:
        return {}
    af = ((entry.get('addressFamilyInfo') or {}).get(_af_key(afi))) or {}
    if not isinstance(af, dict):
        af = {}
    peer_ip = peer if peer is not None else next(iter(data))

    def msecs(key) -> Optional[int]:
        v = _int_or_none(entry.get(key))
        return None if v is None else v // 1000

    if entry.get('nbrExternalLink'):
        link = 'external'
    elif entry.get('nbrInternalLink'):
        link = 'internal'
    elif entry.get('nbrConfedExternalLink'):
        link = 'confed-external'      # a member AS of the same confederation
    elif entry.get('nbrConfedInternalLink'):
        link = 'confed-internal'
    else:
        link = None
    restart_ms = _int_or_none(af.get('prefixAllowedRestartIntervalMsecs'))
    bfd = entry.get('peerBfdInfo') if isinstance(entry.get('peerBfdInfo'), dict) else {}
    return {
        'peer': peer_ip,
        'remote_as': _int_or_none(entry.get('remoteAs')),
        'local_as': _int_or_none(entry.get('localAs')),
        'state': entry.get('bgpState'),
        'established': entry.get('bgpState') == 'Established',
        'link': link,
        'description': entry.get('nbrDesc'),
        'remote_router_id': entry.get('remoteRouterId'),
        'local_router_id': entry.get('localRouterId'),
        'hold_time': msecs('bgpTimerHoldTimeMsecs'),
        'keepalive': msecs('bgpTimerKeepAliveIntervalMsecs'),
        'configured_hold_time': msecs('bgpTimerConfiguredHoldTimeMsecs'),
        'configured_keepalive': msecs('bgpTimerConfiguredKeepAliveIntervalMsecs'),
        'local_host': entry.get('hostLocal'),
        'foreign_host': entry.get('hostForeign'),
        'update_source': entry.get('updateSource'),
        'accepted_prefixes': _int_or_none(af.get('acceptedPrefixCounter')) or 0,
        'sent_prefixes': _int_or_none(af.get('sentPrefixCounter')) or 0,
        'route_reflector_client': bool(af.get('routeReflectorClient')),
        'next_hop_self': bool(af.get('routerAlwaysNextHop') or af.get('nextHopSelf')),
        'default_originate': bool(af.get('defaultSent') or af.get('defaultNotSent')),
        'default_originate_route_map': af.get('defaultRouteMap'),
        'route_map_in': af.get('routeMapForIncomingAdvertisements'),
        'route_map_out': af.get('routeMapForOutgoingAdvertisements'),
        'prefix_list_in': af.get('incomingUpdatePrefixFilterList'),
        'prefix_list_out': af.get('outgoingUpdatePrefixFilterList'),
        'send_community': 'commAttriSentToNbr' in af if af else True,
        'nexthop_global': entry.get('nexthopGlobal'),
        'nexthop_local': entry.get('nexthopLocal'),
        # maximum-prefix (the family's limit) and why the session was last closed
        'max_prefix': _int_or_none(af.get('prefixAllowedMax')),
        'max_prefix_threshold': _int_or_none(af.get('prefixAllowedWarningThresh')),
        'max_prefix_warning_only': bool(af.get('prefixAllowedMaxWarning')),
        'max_prefix_restart': None if restart_ms is None else restart_ms // 60000,   # minutes
        'max_prefix_exceeded': bool(entry.get('prefixesConfigExceedMax')),
        'last_notification': entry.get('lastNotificationReason'),
        'last_reset': entry.get('lastResetDueTo'),
        'bfd_status': bfd.get('status'),             # 'Up' / 'Down' / None without BFD
        'af': af,
        'raw': entry,
    }


def get_bgp_neighbor(grade: Grade0, machine_name: str, peer, step: int = 1, allow_error: bool = False,
                     afi: str = 'ipv4') -> Dict[str, Any]:
    """Run 'vtysh -c "show bgp neighbors <peer> json"' (see :func:`parse_bgp_neighbor`; *afi*
    picks the family of the per-family fields).  Returns {} when BGP is not running or the
    neighbour is unknown."""
    _afi_safi(afi)
    return parse_bgp_neighbor(_vtysh_json(grade, machine_name, f'show bgp neighbors {peer}', step, allow_error),
                              peer=str(peer), afi=afi)


# -- show bgp ipv4 unicast (whole table) --------------------------------------

def _parse_bgp_path_entry(e: Dict[str, Any]) -> Dict[str, Any]:
    """Common fields of a path in ``show bgp ipv4 unicast json`` and ``show bgp ipv4 unicast X json``."""
    aspath = e.get('aspath')
    if isinstance(aspath, dict):
        aspath_str = aspath.get('string') or ''
    else:
        aspath_str = e.get('path') or ''
    if aspath_str == 'Local':
        aspath_str = ''
    best = e.get('bestpath')
    if isinstance(best, dict):
        reason = best.get('selectionReason')
        best = bool(best.get('overall'))
    else:
        reason = e.get('selectionReason')
        best = bool(best)
    nexthops = [n for n in (e.get('nexthops') or []) if isinstance(n, dict)]
    used = next((n for n in nexthops if n.get('used')), nexthops[0] if nexthops else {})
    # IPv6: the global next hop of MP_REACH_NLRI and the link-local one (eBGP on a link; the
    # link-local one is ``used``).  An unnumbered peer's link-local comes as ``scope: global``.
    global_nh = next((n for n in nexthops if n.get('scope') == 'global'), nexthops[0] if nexthops else {})
    link_local_nh = next((n for n in nexthops if n.get('scope') == 'link-local'), {})
    peer = e.get('peer')
    if isinstance(peer, dict):
        peer_id, peer_router_id = peer.get('peerId'), peer.get('routerId')
        path_from = peer.get('type') or e.get('pathFrom')
    else:
        peer_id, peer_router_id = e.get('peerId'), None
        path_from = e.get('pathFrom')
    community = e.get('community')
    if isinstance(community, dict):
        communities = list(community.get('list') or [])
        if not communities and community.get('string'):
            communities = str(community['string']).split()
    else:
        communities = []
    cluster = e.get('clusterList')
    if isinstance(cluster, dict):
        cluster_list = list(cluster.get('list') or [])
    elif isinstance(cluster, list):
        cluster_list = list(cluster)
    else:
        cluster_list = []
    return {
        'valid': bool(e.get('valid')),
        'best': best,
        'multipath': bool(e.get('multipath')),
        'rpki': _rpki_state(e),
        # dampening: suppressed (``damped``) or kept only as flap history (``history``)
        'damped': bool(e.get('damped') or e.get('dampeningSuppressed')),
        'history': bool(e.get('history') or e.get('dampeningHistoryEntry')),
        'dampening_penalty': _int_or_none(e.get('dampeningPenalty')),
        'reason': reason,
        'path_from': path_from,
        'nexthop': used.get('ip'),
        'nexthop_used': bool(used.get('used')),
        'nexthop_global': global_nh.get('ip'),
        'nexthop_link_local': link_local_nh.get('ip'),
        'accessible': used.get('accessible'),
        'peer': peer_id,
        'peer_router_id': peer_router_id,
        'aspath': aspath_str,
        'as_list': as_list_from_string(aspath_str),
        'confed_as_list': confed_as_list_from_string(aspath_str),
        'locprf': _int_or_none(e.get('locPrf')),
        'med': _int_or_none(e.get('metric')),
        'weight': _int_or_none(e.get('weight')) or 0,
        'origin': e.get('origin'),
        'local': bool(e.get('local') or e.get('sourced') or peer_id in ('(unspec)', '0.0.0.0')),
        'originator_id': e.get('originatorId'),
        'cluster_list': cluster_list,
        'communities': communities,
    }


def parse_bgp_routes(data: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Parse the JSON of ``show bgp ipv4 unicast`` (or ``ipv6 unicast``: the whole BGP table).

    Returns ``{prefix: [path, ...]}`` (``{}`` when BGP is not running), each path being::

        {'valid': True, 'best': True, 'reason': 'Local Pref', 'path_from': 'internal',
         'nexthop': '10.0.3.3', 'nexthop_used': True, 'accessible': None,
         'nexthop_global': '10.0.3.3', 'nexthop_link_local': None,   # IPv6: both next hops
         'peer': '10.0.3.2', 'peer_router_id': None, 'aspath': '65200 65000',
         'as_list': [65200, 65000], 'locprf': 200, 'med': 0, 'weight': 0, 'origin': 'IGP',
         'local': False, 'originator_id': None, 'cluster_list': [], 'communities': []}

    A ``network`` statement whose prefix has no route in the RIB (``bgp network
    import-check``) yields a path with ``valid`` and ``best`` both ``False``.

    Every path also has ``multipath`` (installed with the best path, ``=`` in the text),
    ``rpki`` (``'valid'`` / ``'invalid'`` / ``'notfound'``, ``None`` without the RPKI module),
    ``damped`` / ``history`` / ``dampening_penalty`` (dampening) and ``confed_as_list`` (the member
    ASes of a confederation, the ``(65101 65102)`` part of the AS path, also counted in ``as_list``).
    """
    if not isinstance(data, dict):
        return {}
    routes = data.get('routes')
    if not isinstance(routes, dict):
        return {}
    result: Dict[str, List[Dict[str, Any]]] = {}
    for prefix, entries in routes.items():
        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, list):
            continue
        result[prefix] = [_parse_bgp_path_entry(e) for e in entries if isinstance(e, dict)]
    return result


def get_bgp_routes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                   afi: str = 'ipv4', vrf: str = None) -> Dict[str, List[Dict[str, Any]]]:
    """Run 'vtysh -c "show bgp ipv4 unicast json"' (``afi='ipv6'``: ``ipv6 unicast``; ``vrf``: the
    table of that VRF's instance; see :func:`parse_bgp_routes`). Returns {} on error."""
    return parse_bgp_routes(_vtysh_json(grade, machine_name, f'show bgp {_vrf_words(vrf)}{_afi_safi(afi)}', step,
                                        allow_error))


def parse_bgp_vpn_routes(data: Any) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """The JSON of ``show bgp ipv4 vpn`` (the VPNv4 table) → ``{rd: {prefix: [path, ...]}}``, the
    paths of :func:`parse_bgp_routes`; ``{}`` without BGP (``{"warning": ...}``)."""
    if not isinstance(data, dict):
        return {}
    by_rd = (data.get('routes') or {}).get('routeDistinguishers') if isinstance(data.get('routes'), dict) else None
    if not isinstance(by_rd, dict):
        return {}
    return {rd: parse_bgp_routes({'routes': prefixes}) for rd, prefixes in by_rd.items() if isinstance(prefixes, dict)}


def get_bgp_vpn_routes(grade: Grade0, machine_name: str, step: int = 1,
                       allow_error: bool = True) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """The VPNv4 table of *machine_name* (see :func:`parse_bgp_vpn_routes`)."""
    return parse_bgp_vpn_routes(_vtysh_json(grade, machine_name, 'show bgp ipv4 vpn', step, allow_error))


def bgp_best_path(routes: Dict[str, List[Dict[str, Any]]], prefix) -> Dict[str, Any]:
    """Return the best path of ``prefix`` in a :func:`parse_bgp_routes` result (``{}`` when none)."""
    for p in routes.get(str(prefix), []):
        if p.get('best'):
            return p
    return {}


def bgp_paths(routes: Dict[str, List[Dict[str, Any]]], prefix, nexthop=None, peer=None, first_as: int = None,
              ends_with=None, path_from: str = None, valid: bool = None) -> List[Dict[str, Any]]:
    """Return the paths of ``prefix`` matching every given criterion (``ends_with`` is a
    list of AS numbers compared with the end of ``as_list``)."""
    result = []
    for p in routes.get(str(prefix), []):
        if nexthop is not None and p.get('nexthop') != str(nexthop):
            continue
        if peer is not None and p.get('peer') != str(peer):
            continue
        if first_as is not None and (not p['as_list'] or p['as_list'][0] != int(first_as)):
            continue
        if ends_with is not None:
            tail = [int(a) for a in ends_with]
            if p['as_list'][-len(tail):] != tail:
                continue
        if path_from is not None and p.get('path_from') != path_from:
            continue
        if valid is not None and bool(p.get('valid')) != valid:
            continue
        result.append(p)
    return result


# -- show bgp ipv4 unicast PREFIX ---------------------------------------------

def parse_bgp_prefix(data: Any) -> Dict[str, Any]:
    """Parse the JSON of ``show bgp ipv4 unicast <prefix>`` (detailed paths).

    Returns ``{'prefix': None, 'paths': []}`` when the prefix is unknown, else
    ``{'prefix': '10.1.0.0/24', 'paths': [path, ...]}`` with the fields of
    :func:`parse_bgp_routes` plus ``accessible``, ``peer_router_id``, ``originator_id``,
    ``cluster_list`` (route reflection) and ``communities`` (``['65001:300', ...]``).
    """
    if not isinstance(data, dict) or not isinstance(data.get('paths'), list):
        return {'prefix': None, 'paths': []}
    return {'prefix': data.get('prefix'),
            'paths': [_parse_bgp_path_entry(e) for e in data['paths'] if isinstance(e, dict)]}


def get_bgp_prefix(grade: Grade0, machine_name: str, prefix, step: int = 1, allow_error: bool = False,
                   afi: str = 'ipv4') -> Dict[str, Any]:
    """Run 'vtysh -c "show bgp ipv4 unicast <prefix> json"' (``afi='ipv6'``: ``ipv6 unicast``;
    see :func:`parse_bgp_prefix`)."""
    return parse_bgp_prefix(_vtysh_json(grade, machine_name, f'show bgp {_afi_safi(afi)} {prefix}', step,
                                        allow_error))


# -- show bgp ipv4 unicast neighbors X advertised-routes ------------------------

def parse_bgp_advertised_routes(data: Any) -> Dict[str, Dict[str, Any]]:
    """Parse the JSON of ``show bgp ipv4 unicast neighbors <peer> advertised-routes``
    (the routes sent to that peer, after the outbound policy).

    Returns ``{prefix: {'nexthop', 'aspath', 'as_list', 'locprf', 'med', 'weight', 'origin'}}``
    (``{}`` on error or when nothing is advertised); ``nexthop`` is ``nextHop`` (IPv4) or
    ``nextHopGlobal`` (IPv6).
    """
    if not isinstance(data, dict):
        return {}
    adv = data.get('advertisedRoutes')
    if not isinstance(adv, dict):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for prefix, e in adv.items():
        if not isinstance(e, dict):
            continue
        path = e.get('path') or ''
        result[prefix] = {
            'nexthop': e.get('nextHop') if 'nextHop' in e else e.get('nextHopGlobal'),
            'aspath': path,
            'as_list': as_list_from_string(path),
            'locprf': _int_or_none(e.get('locPrf')),
            'med': _int_or_none(e.get('metric')),
            'weight': _int_or_none(e.get('weight')) or 0,
            'origin': e.get('bgpOriginCode') or e.get('origin'),
        }
    return result


def get_bgp_advertised_routes(grade: Grade0, machine_name: str, peer, step: int = 1,
                              allow_error: bool = False, afi: str = 'ipv4') -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show bgp ipv4 unicast neighbors <peer> advertised-routes json"'
    (``afi='ipv6'``: ``ipv6 unicast``; see :func:`parse_bgp_advertised_routes`)."""
    return parse_bgp_advertised_routes(
        _vtysh_json(grade, machine_name, f'show bgp {_afi_safi(afi)} neighbors {peer} advertised-routes', step,
                    allow_error))


# ---------------------------------------------------------------------------
# RIP (text output of vtysh: ripd has no json form)
# ---------------------------------------------------------------------------

#: metric of an unreachable route
RIP_INFINITY = 16
#: sub-codes of `show ip rip`: where the route of the RIP table comes from
RIP_SUB_CODES = {'n': 'normal', 's': 'static', 'd': 'default', 'r': 'redistribute', 'i': 'interface'}

_RIP_ROUTE_RE = re.compile(
    r'^(?P<code>[A-Z])\((?P<sub>[a-z])\)\s+(?P<prefix>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+'
    r'(?P<nexthop>\d{1,3}(?:\.\d{1,3}){3}|blackhole|V6 Address Hidden)\s+(?P<metric>\d+)\s+'
    r'(?P<source>self(?:\s+\((?P<external>[^)]*)\))?|\d{1,3}(?:\.\d{1,3}){3})\s+(?P<tag>\d+)'
    r'(?:\s+(?P<time>\d\d:\d\d(?::\d\d)?))?\s*$')
_RIP_VERSION = r'(?:1 2|1|2|none)'
_RIP_INTERFACE_RE = re.compile(
    rf'^\s+(?P<name>\S+)\s+(?P<send>{_RIP_VERSION})\s+(?P<receive>{_RIP_VERSION})(?:\s+(?P<key_chain>\S+))?\s*$')
_RIP_SOURCE_RE = re.compile(
    r'^\s+(?P<gateway>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<bad_packets>\d+)\s+(?P<bad_routes>\d+)\s+'
    r'(?P<distance>\d+)\s+(?P<last_update>\S+)\s*$')


def parse_rip_routes(output: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parse ``show ip rip`` (the RIP table of ripd, not the kernel one).

    Returns ``{prefix: [path, ...]}`` — one path per row, an ECMP route has several — with
    ``code`` (``'R'`` RIP, ``'C'`` connected, ``'S'`` static, ``'K'`` kernel...), ``sub_code``
    (:data:`RIP_SUB_CODES`: ``'n'`` learned from a neighbour, ``'i'`` interface, ``'r'``
    redistributed, ``'d'`` default, ``'s'`` static RIP route), ``nexthop`` (``None`` for a local
    route), ``metric``, ``source`` (the neighbour the route was learned from, ``None`` for the
    router's own routes), ``external`` (``'static:20'`` of ``self (static:20)``), ``tag`` and
    ``time`` (the timeout or garbage-collection timer, ``None`` when the route has none).
    ``{}`` when ripd has no instance (``% RIP instance not found``) or on the placeholder.
    """
    result: Dict[str, List[Dict[str, Any]]] = {}
    for line in (output or '').splitlines():
        m = _RIP_ROUTE_RE.match(line)
        if not m:
            continue
        nexthop = m.group('nexthop')
        source = m.group('source')
        result.setdefault(m.group('prefix'), []).append({
            'code': m.group('code'),
            'sub_code': m.group('sub'),
            'nexthop': None if nexthop == '0.0.0.0' else nexthop,
            'metric': int(m.group('metric')),
            'source': None if source.startswith('self') else source,
            'external': m.group('external'),
            'tag': int(m.group('tag')),
            'time': m.group('time'),
        })
    return result


def get_rip_routes(grade: Grade0, machine_name: str, step: int = 1,
                   allow_error: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """Run 'vtysh -c "show ip rip"' and parse it (see :func:`parse_rip_routes`). ``{}`` on error."""
    output, code = _test(grade, machine_name, 'vtysh -c "show ip rip"', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_rip_routes(output)


def rip_route_metric(routes: Dict[str, List[Dict[str, Any]]], prefix, learned: bool = None) -> Optional[int]:
    """Smallest metric of *prefix* in a :func:`parse_rip_routes` result, ``None`` when the prefix
    is absent.  ``learned=True`` only looks at the paths learned from a neighbour (code ``R``,
    sub-code ``n``), ``learned=False`` at the router's own ones (interface, redistributed...)."""
    metrics = [p['metric'] for p in routes.get(str(prefix), [])
               if learned is None or learned == (p['source'] is not None)]
    return min(metrics) if metrics else None


def rip_route_sources(routes: Dict[str, List[Dict[str, Any]]], prefix) -> List[str]:
    """Neighbours *prefix* was learned from in a :func:`parse_rip_routes` result (reachable
    paths only: a route in garbage collection, metric 16, is left out)."""
    return [p['source'] for p in routes.get(str(prefix), [])
            if p['source'] is not None and p['metric'] < RIP_INFINITY]


def parse_rip_status(output: str) -> Dict[str, Any]:
    """Parse ``show ip rip status``.

    Returns ``{'update', 'timeout', 'garbage'}`` (the three timers of ``timers basic``, seconds),
    ``default_metric``, ``redistribute`` (``['connected', 'static']``), ``send_version`` /
    ``receive_version`` (``'1'``, ``'2'``, ``'1 2'``), ``interfaces`` (``{name: {'send',
    'receive', 'key_chain'}}``: the interfaces RIP runs on, passive ones included), ``networks``
    (the ``network`` statements: prefixes and interface names, then the ``neighbor`` addresses),
    ``passive_interfaces``, ``sources`` (``{gateway: {'bad_packets', 'bad_routes', 'distance',
    'last_update'}}``: every neighbour a packet was received from) and ``distance``.
    ``{}`` when ripd has no instance or on the placeholder.
    """
    text = output or ''
    if 'Routing Protocol is "rip"' not in text:
        return {}
    status: Dict[str, Any] = {
        'update': None, 'timeout': None, 'garbage': None, 'default_metric': None, 'redistribute': [],
        'send_version': None, 'receive_version': None, 'interfaces': {}, 'networks': [],
        'passive_interfaces': [], 'sources': {}, 'distance': None,
    }
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m = re.match(r'Sending updates every (\d+) seconds', stripped)
        if m:
            status['update'] = int(m.group(1))
            continue
        m = re.match(r'Timeout after (\d+) seconds, garbage collect after (\d+) seconds', stripped)
        if m:
            status['timeout'], status['garbage'] = int(m.group(1)), int(m.group(2))
            continue
        m = re.match(r'Default redistribution metric is (\d+)', stripped)
        if m:
            status['default_metric'] = int(m.group(1))
            continue
        if stripped.startswith('Redistributing:'):
            status['redistribute'] = stripped[len('Redistributing:'):].split()
            continue
        m = re.match(r'Default version control: send version (.+?), receive (any version|version (.+?))\s*$',
                     stripped)
        if m:
            status['send_version'] = m.group(1).strip()
            status['receive_version'] = '1 2' if m.group(2) == 'any version' else m.group(3).strip()
            continue
        m = re.match(r'Distance: \(default is (\d+)\)', stripped)
        if m:
            status['distance'] = int(m.group(1))
            section = None
            continue
        if re.match(r'Interface\s+Send\s+Recv', stripped):
            section = 'interfaces'
            continue
        if stripped == 'Routing for Networks:':
            section = 'networks'
            continue
        if stripped == 'Passive Interface(s):':
            section = 'passive'
            continue
        if stripped == 'Routing Information Sources:':
            section = 'sources'
            continue
        if section == 'interfaces':
            m = _RIP_INTERFACE_RE.match(line)
            if m:
                status['interfaces'][m.group('name')] = {
                    'send': m.group('send'), 'receive': m.group('receive'), 'key_chain': m.group('key_chain')}
        elif section == 'networks':
            status['networks'].append(stripped)
        elif section == 'passive':
            status['passive_interfaces'].append(stripped)
        elif section == 'sources':
            m = _RIP_SOURCE_RE.match(line)
            if m:
                status['sources'][m.group('gateway')] = {
                    'bad_packets': int(m.group('bad_packets')), 'bad_routes': int(m.group('bad_routes')),
                    'distance': int(m.group('distance')), 'last_update': m.group('last_update')}
    return status


def get_rip_status(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Any]:
    """Run 'vtysh -c "show ip rip status"' and parse it (see :func:`parse_rip_status`).
    ``{}`` on error or when RIP is not configured."""
    output, code = _test(grade, machine_name, 'vtysh -c "show ip rip status"', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_rip_status(output)


# ---------------------------------------------------------------------------
# PIM, IGMP, MSDP (pimd) and PIMv6, MLD (pim6d): json output of vtysh
# ---------------------------------------------------------------------------
#
# Shapes of FRR 9.1.3 (fixtures tests/mock_data/frr/pim_*.json, captured in the multicast lab).
# pimd adds a `pimreg` interface (`pim6reg` for pim6d), left out of every result.  Without
# `ip pim` / `ip igmp` anywhere, the show commands print `{}` (exit 0).

PIM_REGISTER_INTERFACES = ('pimreg', 'pim6reg')


def _str_or_none(value) -> Optional[str]:
    return None if value in (None, '', '-', '*') else str(value)


def _bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ('true', 'yes', 'local', '1')
    return bool(value)


def _vrf_default(data: Any) -> Dict[str, Any]:
    """Some pim6d outputs are wrapped in ``{"default": {...}}`` (the VRF): unwrap it."""
    if isinstance(data, dict) and set(data) == {'default'} and isinstance(data['default'], dict):
        return data['default']
    return data if isinstance(data, dict) else {}


def parse_pim_interfaces(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show ip pim interface json`` (or ``show ipv6 pim interface json``) → ``{ifname:
    {'address', 'up', 'neighbors' (count), 'dr' (address of the designated router), 'dr_local'}}``
    for every interface PIM is enabled on (the register interface left out)."""
    result = {}
    for ifname, entry in _vrf_default(data).items():
        if ifname in PIM_REGISTER_INTERFACES or not isinstance(entry, dict):
            continue
        result[ifname] = {
            'address': _str_or_none(entry.get('address')), 'up': entry.get('state') == 'up',
            'neighbors': _int_or_none(entry.get('pimNeighbors')) or 0,
            'dr': _str_or_none(entry.get('pimDesignatedRouter')), 'dr_local': _bool(entry.get('pimDesignatedRouterLocal')),
        }
    return result


def get_pim_interfaces(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                       ipv6: bool = False) -> Dict[str, Dict[str, Any]]:
    family = 'ipv6' if ipv6 else 'ip'
    return parse_pim_interfaces(_vtysh_json(grade, machine_name, f"show {family} pim interface", step, allow_error))


def parse_pim_neighbors(data: Any) -> Dict[str, List[str]]:
    """``show ip pim neighbor json`` (or the ipv6 one) → ``{ifname: [neighbor addresses]}``
    (interfaces without neighbour left out; IPv6 neighbours are link-local addresses)."""
    result = {}
    for ifname, neighbors in _vrf_default(data).items():
        if ifname in PIM_REGISTER_INTERFACES or not isinstance(neighbors, dict):
            continue
        addresses = []
        for key, entry in neighbors.items():
            address = entry.get('neighbor', key) if isinstance(entry, dict) else key
            if address:
                addresses.append(str(address))
        if addresses:
            result[ifname] = sorted(addresses)
    return result


def get_pim_neighbors(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                      ipv6: bool = False) -> Dict[str, List[str]]:
    family = 'ipv6' if ipv6 else 'ip'
    return parse_pim_neighbors(_vtysh_json(grade, machine_name, f"show {family} pim neighbor", step, allow_error))


def pim_neighbor_on(neighbors: Dict[str, List[str]], ifname: str, address=None) -> bool:
    """True when *ifname* has a PIM neighbour (*address* when given)."""
    found = neighbors.get(ifname) or []
    return bool(found) if address is None else str(address) in found


def parse_pim_rp_info(data: Any) -> List[Dict[str, Any]]:
    """``show ip pim rp-info json`` → ``[{'rp', 'group' (range), 'source' (Static, BSR...),
    'group_type' (ASM), 'iface' (the RPF interface towards the RP), 'i_am_rp'}]``."""
    result = []
    for rp, entries in _vrf_default(data).items():
        for entry in entries if isinstance(entries, list) else [entries]:
            if not isinstance(entry, dict):
                continue
            result.append({'rp': str(entry.get('rpAddress', rp)), 'group': _str_or_none(entry.get('group')),
                           'source': _str_or_none(entry.get('source')), 'group_type': _str_or_none(entry.get('groupType')),
                           'iface': _str_or_none(entry.get('outboundInterface')), 'i_am_rp': _bool(entry.get('iAmRP'))})
    return result


def get_pim_rp_info(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                    ipv6: bool = False) -> List[Dict[str, Any]]:
    family = 'ipv6' if ipv6 else 'ip'
    return parse_pim_rp_info(_vtysh_json(grade, machine_name, f"show {family} pim rp-info", step, allow_error))


def rp_for_group(rp_info: List[Dict[str, Any]], group) -> Optional[Dict[str, Any]]:
    """The entry of *rp_info* whose range holds *group* with the longest prefix (``None``)."""
    try:
        address = ip_address(str(group))
    except ValueError:
        return None
    best, best_len = None, -1
    for entry in rp_info:
        try:
            network = ip_network(entry['group'] or '', strict=False)
        except ValueError:
            continue
        if network.version == address.version and address in network and network.prefixlen > best_len:
            best, best_len = entry, network.prefixlen
    return best


def parse_pim_group_type(data: Any) -> Optional[str]:
    """``show ip pim group-type A.B.C.D json`` → ``'SSM'`` / ``'ASM'`` / ... (``None``)."""
    return _str_or_none(data.get('groupType')) if isinstance(data, dict) else None


def get_pim_group_type(grade: Grade0, machine_name: str, group, step: int = 1,
                       allow_error: bool = False) -> Optional[str]:
    return parse_pim_group_type(_vtysh_json(grade, machine_name, f"show ip pim group-type {group}", step, allow_error))


def parse_mroutes(data: Any) -> Dict[tuple, Dict[str, Any]]:
    """``show ip mroute json`` (or ``show ipv6 mroute json``) → ``{(source or '*', group):
    {'iif', 'oil' ([outgoing interfaces]), 'flags', 'installed'}}``."""
    result = {}
    for group, sources in _vrf_default(data).items():
        if not isinstance(sources, dict):
            continue
        for source, entry in sources.items():
            if not isinstance(entry, dict):
                continue
            oil = entry.get('oil') or {}
            result[(str(entry.get('source', source)), str(entry.get('group', group)))] = {
                'iif': _str_or_none(entry.get('iif')),
                'oil': sorted(str(name) for name in oil if name not in PIM_REGISTER_INTERFACES)
                if isinstance(oil, dict) else [],
                'flags': str(entry.get('flags') or ''), 'installed': _bool(entry.get('installed')),
            }
    return result


def get_mroutes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                ipv6: bool = False) -> Dict[tuple, Dict[str, Any]]:
    family = 'ipv6' if ipv6 else 'ip'
    return parse_mroutes(_vtysh_json(grade, machine_name, f"show {family} mroute", step, allow_error))


def parse_pim_upstream(data: Any) -> Dict[tuple, Dict[str, Any]]:
    """``show ip pim upstream json`` → ``{(source or '*', group): {'join_state', 'reg_state',
    'iif', 'rpf' (the RPF neighbour), 'spt' (the SPT bit)}}``."""
    result = {}
    for group, sources in _vrf_default(data).items():
        if not isinstance(sources, dict):
            continue
        for source, entry in sources.items():
            if not isinstance(entry, dict):
                continue
            result[(str(entry.get('source', source)), str(entry.get('group', group)))] = {
                'join_state': _str_or_none(entry.get('joinState')), 'reg_state': _str_or_none(entry.get('regState')),
                'iif': _str_or_none(entry.get('inboundInterface')),
                'rpf': _str_or_none(entry.get('rpfAddress')), 'spt': _bool(entry.get('sptBit')),
            }
    return result


def get_pim_upstream(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[tuple, Dict[str, Any]]:
    return parse_pim_upstream(_vtysh_json(grade, machine_name, "show ip pim upstream", step, allow_error))


def _seconds(value) -> Optional[float]:
    """Seconds of ``"00:02:05"`` / ``"00:00:29.743"`` / a number of seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    parts = str(value).strip().split(':')
    try:
        total = 0.0
        for part in parts:
            total = total * 60 + float(part)
        return total
    except ValueError:
        return None


def parse_igmp_interfaces(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show ip igmp interface [detail] json`` (or ``show ipv6 mld interface json``) →
    ``{ifname: {'address', 'up', 'version', 'querier' (this router is the querier),
    'querier_ip', 'query_interval' (s), 'query_response_interval' (s), 'last_member_interval'
    (s), 'last_member_count', 'robustness', 'mtrace_only'}}``.  The timers come from the
    ``detail`` form (``None`` in the short one); an interface with ``mtraceOnly`` has PIM but no
    ``ip igmp``."""
    result = {}
    for ifname, entry in _vrf_default(data).items():
        if not isinstance(entry, dict) or 'name' not in entry:
            continue
        querier = entry.get('querier')
        query_interval = entry.get('timerQueryInterval')
        if query_interval is None and entry.get('timerQueryIntervalMsec') is not None:
            query_interval = (_int_or_none(entry.get('timerQueryIntervalMsec')) or 0) / 1000
        response = entry.get('timerQueryResponseIntervalMsec', entry.get('timerQueryResponseTimerMsec'))
        last_member = entry.get('timerLastMemberQueryMsec', entry.get('timerLastMemberQueryIntervalMsec'))
        result[ifname] = {
            'address': _str_or_none(entry.get('address')), 'up': entry.get('state') == 'up',
            'version': _int_or_none(entry.get('version')),
            'querier': querier is True or str(querier).lower() in ('local', 'true'),
            'querier_ip': _str_or_none(entry.get('querierIp')),
            'query_interval': None if query_interval is None else float(query_interval),
            'query_response_interval': None if response is None else (_int_or_none(response) or 0) / 1000,
            'last_member_interval': None if last_member is None else (_int_or_none(last_member) or 0) / 1000,
            'last_member_count': _int_or_none(entry.get('lastMemberQueryCount')),
            'robustness': _int_or_none(entry.get('timerRobustnessVariable', entry.get('timerRobustnessValue'))),
            'mtrace_only': _bool(entry.get('mtraceOnly')),
        }
    return result


def igmp_enabled(interfaces: Dict[str, Dict[str, Any]], ifname: str) -> bool:
    """``ip igmp`` (``ipv6 mld``) is configured on *ifname* (not only PIM: ``mtraceOnly``)."""
    entry = interfaces.get(ifname)
    return bool(entry) and not entry['mtrace_only']


def get_igmp_interfaces(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False,
                        detail: bool = True) -> Dict[str, Dict[str, Any]]:
    command = "show ip igmp interface detail" if detail else "show ip igmp interface"
    return parse_igmp_interfaces(_vtysh_json(grade, machine_name, command, step, allow_error))


def get_mld_interfaces(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    return parse_igmp_interfaces(_vtysh_json(grade, machine_name, "show ipv6 mld interface", step, allow_error))


def parse_igmp_groups(data: Any) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """``show ip igmp groups json`` (or ``show ipv6 mld groups json``) → ``{ifname: {group:
    {'version', 'mode' (INCL / EXCL), 'sources_count', 'uptime' (s), 'reporter'}}}``."""
    result: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for ifname, entry in _vrf_default(data).items():
        if not isinstance(entry, dict) or not isinstance(entry.get('groups'), list):
            continue
        groups = result.setdefault(ifname, {})
        for g in entry['groups']:
            if not isinstance(g, dict) or not g.get('group'):
                continue
            groups[str(g['group'])] = {
                'version': _int_or_none(g.get('version')), 'mode': _str_or_none(g.get('mode')),
                'sources_count': _int_or_none(g.get('sourcesCount')), 'uptime': _seconds(g.get('uptime')),
                'reporter': _str_or_none(g.get('source', g.get('lastReporter'))),
            }
    return result


def get_igmp_groups(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, Dict[str, Any]]]:
    return parse_igmp_groups(_vtysh_json(grade, machine_name, "show ip igmp groups", step, allow_error))


def get_mld_groups(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, Dict[str, Any]]]:
    return parse_igmp_groups(_vtysh_json(grade, machine_name, "show ipv6 mld groups", step, allow_error))


def parse_igmp_sources(data: Any) -> Dict[str, Dict[str, List[str]]]:
    """``show ip igmp sources json`` → ``{ifname: {group: [sources]}}`` (the (S,G) records of the
    IGMPv3 INCLUDE reports; ``*`` for an EXCLUDE {} / IGMPv2 group is left out)."""
    result: Dict[str, Dict[str, List[str]]] = {}
    for ifname, entry in _vrf_default(data).items():
        if not isinstance(entry, dict):
            continue
        for group, g in entry.items():
            if not isinstance(g, dict) or not isinstance(g.get('sources'), list):
                continue
            sources = [str(s.get('source')) for s in g['sources']
                       if isinstance(s, dict) and _str_or_none(s.get('source'))]
            if sources:
                result.setdefault(ifname, {})[str(g.get('group', group))] = sorted(sources)
    return result


def get_igmp_sources(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, List[str]]]:
    return parse_igmp_sources(_vtysh_json(grade, machine_name, "show ip igmp sources", step, allow_error))


def parse_msdp_peers(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show ip msdp peer json`` → ``{peer: {'state' (inactive / listen / connecting /
    established), 'established', 'local', 'sa_count'}}``."""
    result = {}
    for peer, entry in _vrf_default(data).items():
        if not isinstance(entry, dict):
            continue
        state = str(entry.get('state') or '').lower()
        result[str(entry.get('peer', peer))] = {'state': state, 'established': state == 'established',
                                                'local': _str_or_none(entry.get('local')),
                                                'sa_count': _int_or_none(entry.get('saCount')) or 0}
    return result


def get_msdp_peers(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    return parse_msdp_peers(_vtysh_json(grade, machine_name, "show ip msdp peer", step, allow_error))


def parse_msdp_sa(data: Any) -> Dict[tuple, Dict[str, Any]]:
    """``show ip msdp sa json`` → ``{(source, group): {'rp' (the RP that originated it), 'local'
    (originated by this router), 'spt' (an (S,G) join was sent)}}``."""
    result = {}
    for group, sources in _vrf_default(data).items():
        if not isinstance(sources, dict):
            continue
        for source, entry in sources.items():
            if not isinstance(entry, dict):
                continue
            result[(str(entry.get('source', source)), str(entry.get('group', group)))] = {
                'rp': _str_or_none(entry.get('rp')), 'local': _bool(entry.get('local')),
                'spt': _bool(entry.get('sptSetup')),
            }
    return result


def get_msdp_sa(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[tuple, Dict[str, Any]]:
    return parse_msdp_sa(_vtysh_json(grade, machine_name, "show ip msdp sa", step, allow_error))


# ---------------------------------------------------------------------------
# OSPFv3 (ospf6d: json output, text of show ipv6 ospf6 border-routers)
# ---------------------------------------------------------------------------
#
# Captured on FRR 9.1.3 (tests/mock_data/frr/ospf6_*).  Without ospf6d (or without
# ``router ospf6``) the json commands print nothing and exit 0: every parser then returns
# its empty shape.  The areas of ``show ipv6 ospf6 json`` are keyed as they were typed
# (``"0"``, ``"0.0.0.1"``): they are normalised to the dotted form here.

#: ``pathType`` of ``show ipv6 ospf6 route json`` -> route type
OSPF6_PATH_TYPES = {'IA': 'intra-area', 'IE': 'inter-area', 'E1': 'external-1', 'E2': 'external-2'}


def parse_ospf6_info(data: Any) -> Dict[str, Any]:
    """Parse the JSON of ``show ipv6 ospf6``.

    Returns ``{}`` when ospf6d does not answer, else::

        {'router_id': '2.2.2.2',          # '0.0.0.0' when none could be chosen
         'abr': True,                     # interfaces attached to two areas or more
         'areas': {'0.0.0.1': {'stub': True, 'nssa': False, 'no_summary': False,
                               'interfaces': ['eth1'], 'lsa_count': 9}},
         'as_scoped_lsa_count': 4}

    The json has no ABR / ASBR flag: ``abr`` is computed from the areas, and what the other
    routers see is in :func:`get_ospf6_border_routers`.
    """
    if not isinstance(data, dict) or 'routerId' not in data:
        return {}
    areas: Dict[str, Dict[str, Any]] = {}
    for key, a in (data.get('areas') or {}).items():
        if not isinstance(a, dict):
            continue
        areas[normalize_area(key)] = {
            'stub': bool(a.get('areaIsStub')),
            'nssa': bool(a.get('areaIsNSSA')),
            'no_summary': bool(a.get('areaNoSummary')),
            'interfaces': [str(i) for i in (a.get('interfacesAttachedToArea') or [])],
            'lsa_count': _int_or_none(a.get('numberOfAreaScopedLsa')),
        }
    return {
        'router_id': data.get('routerId'),
        'abr': sum(1 for a in areas.values() if a['interfaces']) >= 2,
        'areas': areas,
        'as_scoped_lsa_count': _int_or_none(data.get('numberOfAsScopedLsa')),
    }


def get_ospf6_info(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Any]:
    """Run 'vtysh -c "show ipv6 ospf6 json"' (see :func:`parse_ospf6_info`)."""
    return parse_ospf6_info(_vtysh_json(grade, machine_name, 'show ipv6 ospf6', step, allow_error))


def parse_ospf6_neighbors(data: Any) -> List[Dict[str, Any]]:
    """Parse the JSON of ``show ipv6 ospf6 neighbor``: one dict per neighbour, with the keys
    of :func:`get_ospf_neighbors` (so :func:`find_neighbor` / :func:`neighbor_is_full` work)::

        {'neighbor_id': '1.1.1.1', 'priority': 1, 'state': 'Full',   # Init, Twoway, ExStart...
         'role': 'BDR',                   # the neighbour's role on the link
         'dead_time': '00:00:37', 'up_time': '00:00:32', 'interface': 'eth0',
         'interface_state': 'DR',         # this router's role on the link
         'address': None, 'local_address': None}

    OSPFv3 neighbours are named by router-id; their (link-local) address is not in the json.
    """
    if not isinstance(data, dict):
        return []
    result: List[Dict[str, Any]] = []
    for n in data.get('neighbors') or []:
        if not isinstance(n, dict):
            continue
        result.append({
            'neighbor_id': n.get('neighborId'),
            'priority': _int_or_none(n.get('priority')),
            'state': n.get('state'),
            'role': n.get('ifState'),
            'dead_time': n.get('deadTime'),
            'up_time': n.get('duration'),
            'interface': n.get('interfaceName'),
            'interface_state': n.get('interfaceState'),
            'address': None,
            'local_address': None,
        })
    return result


def get_ospf6_neighbors(grade: Grade0, machine_name: str, step: int = 1,
                        allow_error: bool = False) -> List[Dict[str, Any]]:
    """Run 'vtysh -c "show ipv6 ospf6 neighbor json"' (see :func:`parse_ospf6_neighbors`)."""
    return parse_ospf6_neighbors(_vtysh_json(grade, machine_name, 'show ipv6 ospf6 neighbor', step, allow_error))


def parse_ospf6_interfaces(data: Any) -> Dict[str, Dict[str, Any]]:
    """Parse the JSON of ``show ipv6 ospf6 interface``.

    Returns ``{ifname: {...}}`` for every interface ospf6d knows; ``enabled`` is false (and the
    other keys ``None``) for an interface not attached to an area::

        {'enabled': True, 'area': '0.0.0.1', 'cost': 10, 'state': 'DR',  # PointToPoint, Waiting...
         'type': 'BROADCAST', 'passive': False, 'mtu': 1500, 'mtu_ignore': False,
         'priority': 1, 'hello_interval': 10, 'dead_interval': 40, 'dr': '3.3.3.3', 'bdr': '2.2.2.2',
         'addresses': ['fe80::53:52ff:fe48:ead/64', '3fff:550:5cfb:23::3/64'],
         'auth_type': 'NULL',             # 'manualkey' / 'keychain' with an authentication trailer
         'auth_rx_drops': None}
    """
    if not isinstance(data, dict):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for ifname, e in data.items():
        if not isinstance(e, dict):
            continue
        enabled = bool(e.get('attachedToArea'))
        auth = e.get('authInfo') if isinstance(e.get('authInfo'), dict) else {}
        detection = e.get('mtuMismatchDetection')
        result[ifname] = {
            'enabled': enabled,
            'area': normalize_area(e['areaId']) if enabled and e.get('areaId') else None,
            'cost': _int_or_none(e.get('cost')),
            'state': e.get('ospf6InterfaceState'),
            'type': e.get('type'),
            'passive': bool(e.get('timerPassiveIface')) if enabled else None,
            'mtu': _int_or_none(e.get('interfaceMtu')),
            'mtu_ignore': (detection != 'enabled') if detection is not None else None,
            'priority': _int_or_none(e.get('priority')),
            'hello_interval': _int_or_none(e.get('timerIntervalsConfigHello')),
            'dead_interval': _int_or_none(e.get('timerIntervalsConfigDead')),
            'dr': e.get('dr'),
            'bdr': e.get('bdr'),
            'addresses': [a.get('address') for a in (e.get('internetAddress') or [])
                          if isinstance(a, dict) and a.get('address')],
            'auth_type': auth.get('authType'),
            'auth_rx_drops': _int_or_none(auth.get('rxPktDrop')),
        }
    return result


def get_ospf6_interfaces(grade: Grade0, machine_name: str, step: int = 1,
                         allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show ipv6 ospf6 interface json"' (see :func:`parse_ospf6_interfaces`)."""
    return parse_ospf6_interfaces(_vtysh_json(grade, machine_name, 'show ipv6 ospf6 interface', step, allow_error))


def parse_ospf6_routes(data: Any) -> Dict[str, Dict[str, Any]]:
    """Parse the JSON of ``show ipv6 ospf6 route``.

    Returns ``{prefix: {'type': 'intra-area' | 'inter-area' | 'external-1' | 'external-2',
    'code': 'IA' | 'IE' | 'E1' | 'E2', 'best': bool, 'nexthops': [(nexthop | None, ifname)]}}``;
    a directly connected network has the next hop ``None`` (``::`` in the json).  The default
    route a stub area receives from its ABR is ``'::/0'`` of type ``inter-area``.
    """
    if not isinstance(data, dict) or not isinstance(data.get('routes'), dict):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for prefix, e in data['routes'].items():
        if not isinstance(e, dict):
            continue
        code = e.get('pathType')
        nexthops = []
        for n in e.get('nextHops') or []:
            if isinstance(n, dict):
                nh = n.get('nextHop')
                nexthops.append((None if nh in (None, '', '::') else nh, n.get('interfaceName')))
        result[prefix] = {
            'type': OSPF6_PATH_TYPES.get(code, code),
            'code': code,
            'best': bool(e.get('isBestRoute')),
            'nexthops': nexthops,
        }
    return result


def get_ospf6_routes(grade: Grade0, machine_name: str, step: int = 1,
                     allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show ipv6 ospf6 route json"' (see :func:`parse_ospf6_routes`)."""
    return parse_ospf6_routes(_vtysh_json(grade, machine_name, 'show ipv6 ospf6 route', step, allow_error))


_OSPF6_BORDER_ROUTER_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S{8})\s+\S+\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$')


def parse_ospf6_border_routers(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse the text of ``show ipv6 ospf6 border-routers`` (no json form in FRR 9.1)::

        Router-ID       Rtr-Bits Options        Path-Type  Area
        1.1.1.1         ------E- --|-|--|-|-|--|R|-|--|E|V6 Intra-Area 0.0.0.0
        2.2.2.2         -------B --|-|--|-|-|--|R|-|--|E|V6 Intra-Area 0.0.0.0

    Returns ``{router_id: {'abr': bool, 'asbr': bool, 'path_type': 'Intra-Area', 'areas':
    ['0.0.0.0', ...]}}`` (an ABR is listed once per area); ``{}`` without ospf6d
    (``% OSPFv3 instance not found``).  The router itself appears when it is a border router.
    """
    result: Dict[str, Dict[str, Any]] = {}
    for line in (output or '').splitlines():
        m = _OSPF6_BORDER_ROUTER_RE.match(line.strip())
        if not m:
            continue
        rid, bits, path_type, area = m.groups()
        entry = result.setdefault(rid, {'abr': False, 'asbr': False, 'path_type': path_type, 'areas': []})
        entry['abr'] = entry['abr'] or 'B' in bits
        entry['asbr'] = entry['asbr'] or 'E' in bits
        if area not in entry['areas']:
            entry['areas'].append(area)
    return result


def get_ospf6_border_routers(grade: Grade0, machine_name: str, step: int = 1,
                             allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show ipv6 ospf6 border-routers"' (see :func:`parse_ospf6_border_routers`)."""
    output, code = _test(grade, machine_name, 'vtysh -c "show ipv6 ospf6 border-routers"', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_ospf6_border_routers(output)


# ---------------------------------------------------------------------------
# MPLS: LDP (ldpd), the label table of zebra, segment routing in OSPF, the RIB with labels
# (json output of FRR 10.3; fixtures ldp_*, mpls_table_*, ospf_sr_*, route_* captured in the
# MPLS lab).  The kernel side (net.mpls sysctls, ``ip -f mpls route``, MPLS counters) is
# read by lib/mpls.py.
# ---------------------------------------------------------------------------

#: label values of the reserved labels as ldpd and zebra write them
MPLS_IMPLICIT_NULL = 3
MPLS_EXPLICIT_NULL = 0
_LABEL_NAMES = {'imp-null': MPLS_IMPLICIT_NULL, 'implicit-null': MPLS_IMPLICIT_NULL,
                'exp-null': MPLS_EXPLICIT_NULL, 'explicit-null': MPLS_EXPLICIT_NULL}


def mpls_label_value(text) -> Optional[int]:
    """A label as ldpd / zebra print it (``"16"``, ``16``, ``"imp-null"``, ``"exp-null"``) → its
    value (``imp-null`` = 3, ``exp-null`` = 0); ``None`` for ``-`` or anything else."""
    if isinstance(text, int):
        return text
    word = str(text or '').strip().lower()
    if word in _LABEL_NAMES:
        return _LABEL_NAMES[word]
    return _int_or_none(word) if word.isdigit() else None


def parse_ldp_neighbors(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show mpls ldp neighbor json`` → ``{lsr_id: {'state': str, 'operational': bool,
    'transport_address': str | None, 'uptime': str | None}}`` (``{}`` without LDP)."""
    result: Dict[str, Dict[str, Any]] = {}
    for n in (data or {}).get('neighbors', []) if isinstance(data, dict) else []:
        if not isinstance(n, dict) or not n.get('neighborId'):
            continue
        state = str(n.get('state') or '')
        result[n['neighborId']] = {'state': state, 'operational': state.upper() == 'OPERATIONAL',
                                   'transport_address': n.get('transportAddress'), 'uptime': n.get('upTime')}
    return result


def get_ldp_neighbors(grade: Grade0, machine_name: str, step: int = 1,
                      allow_error: bool = True) -> Dict[str, Dict[str, Any]]:
    """The LDP sessions of *machine_name* (see :func:`parse_ldp_neighbors`)."""
    return parse_ldp_neighbors(_vtysh_json(grade, machine_name, "show mpls ldp neighbor", step, allow_error))


def ldp_session_up(neighbors: Dict[str, Dict[str, Any]], lsr_id) -> bool:
    return bool((neighbors.get(str(lsr_id)) or {}).get('operational'))


def parse_ldp_discovery(data: Any) -> Dict[str, List[str]]:
    """``show mpls ldp discovery json`` → ``{interface: [lsr_id]}`` for the link Hello
    adjacencies (targeted adjacencies under ``'targeted'``)."""
    result: Dict[str, List[str]] = {}
    for a in (data or {}).get('adjacencies', []) if isinstance(data, dict) else []:
        if not isinstance(a, dict) or not a.get('neighborId'):
            continue
        key = a.get('interface') if a.get('type') == 'link' else 'targeted'
        result.setdefault(str(key), []).append(a['neighborId'])
    return result


def get_ldp_discovery(grade: Grade0, machine_name: str, step: int = 1,
                      allow_error: bool = True) -> Dict[str, List[str]]:
    """The LDP Hello adjacencies of *machine_name* (see :func:`parse_ldp_discovery`)."""
    return parse_ldp_discovery(_vtysh_json(grade, machine_name, "show mpls ldp discovery", step, allow_error))


def parse_ldp_bindings(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show mpls ldp binding json`` (the LIB) → ``{prefix: {'local': int | None, 'remote':
    {lsr_id: int | None}, 'in_use': lsr_id | None}}``; labels are values (``imp-null`` = 3,
    ``exp-null`` = 0), ``in_use`` the neighbour whose label the router forwards with."""
    result: Dict[str, Dict[str, Any]] = {}
    for b in (data or {}).get('bindings', []) if isinstance(data, dict) else []:
        if not isinstance(b, dict) or not b.get('prefix'):
            continue
        entry = result.setdefault(b['prefix'], {'local': None, 'remote': {}, 'in_use': None})
        entry['local'] = mpls_label_value(b.get('localLabel'))
        if b.get('neighborId'):
            entry['remote'][b['neighborId']] = mpls_label_value(b.get('remoteLabel'))
            if b.get('inUse'):
                entry['in_use'] = b['neighborId']
    return result


def get_ldp_bindings(grade: Grade0, machine_name: str, step: int = 1,
                     allow_error: bool = True) -> Dict[str, Dict[str, Any]]:
    """The LDP label bindings of *machine_name* (see :func:`parse_ldp_bindings`)."""
    return parse_ldp_bindings(_vtysh_json(grade, machine_name, "show mpls ldp binding", step, allow_error))


def parse_mpls_table(data: Any) -> Dict[int, Dict[str, Any]]:
    """``show mpls table json`` (zebra's label table, LDP / SR / static) → ``{in_label:
    {'installed': bool, 'nexthops': [{'type': 'LDP' | 'SR (OSPF)' | ..., 'out_labels': [int],
    'nexthop': str | None, 'interface': str | None, 'installed': bool}]}}``.  ``installed`` is
    zebra's view: the kernel may still have refused the label (``ip -f mpls route``)."""
    result: Dict[int, Dict[str, Any]] = {}
    for key, entry in (data or {}).items() if isinstance(data, dict) else []:
        if not isinstance(entry, dict):
            continue
        label = _int_or_none(entry.get('inLabel', key))
        if label is None:
            continue
        nexthops = []
        for n in entry.get('nexthops', []):
            if not isinstance(n, dict):
                continue
            stack = n.get('outLabelStack')
            if not isinstance(stack, list):
                stack = [n.get('outLabel')] if n.get('outLabel') is not None else []
            nexthops.append({'type': n.get('type'), 'out_labels': [x for x in map(mpls_label_value, stack) if x is not None],
                             'nexthop': n.get('nexthop'), 'interface': n.get('interface'),
                             'installed': bool(n.get('installed'))})
        result[label] = {'installed': bool(entry.get('installed')), 'nexthops': nexthops}
    return result


def get_mpls_table(grade: Grade0, machine_name: str, step: int = 1,
                   allow_error: bool = True) -> Dict[int, Dict[str, Any]]:
    """Zebra's label table of *machine_name* (see :func:`parse_mpls_table`)."""
    return parse_mpls_table(_vtysh_json(grade, machine_name, "show mpls table", step, allow_error))


def parse_ospf_sr_database(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show ip ospf database segment-routing json`` → ``{router_id: {'srgb': (base, size),
    'srlb': (base, size), 'prefixes': {prefix: {'index': int, 'input_label': int,
    'routes': [{'out_label': int, 'interface': str, 'nexthop': str}]}}}}`` (``{}`` when segment
    routing is disabled on the router: FRR answers with a text line).  ``input_label`` and
    ``routes`` are those of the router that answers, which also lists itself."""
    result: Dict[str, Dict[str, Any]] = {}
    for node in (data or {}).get('srNodes', []) if isinstance(data, dict) else []:
        if not isinstance(node, dict) or not node.get('routerID'):
            continue
        prefixes = {}
        for p in node.get('extendedPrefix', []):
            if not isinstance(p, dict) or not p.get('prefix'):
                continue
            routes = [{'out_label': mpls_label_value(r.get('outputLabel')), 'interface': r.get('interface'),
                       'nexthop': r.get('nexthop')} for r in p.get('prefixRoute', []) if isinstance(r, dict)]
            prefixes[p['prefix']] = {'index': _int_or_none(p.get('sid')),
                                     'input_label': _int_or_none(p.get('inputLabel')), 'routes': routes}
        result[node['routerID']] = {
            'srgb': (_int_or_none(node.get('srgbLabel')), _int_or_none(node.get('srgbSize'))),
            'srlb': (_int_or_none(node.get('srlbLabel')), _int_or_none(node.get('srlbSize'))),
            'prefixes': prefixes,
        }
    return result


def get_ospf_sr_database(grade: Grade0, machine_name: str, step: int = 1,
                         allow_error: bool = True) -> Dict[str, Dict[str, Any]]:
    """The segment routing database of OSPF on *machine_name* (see :func:`parse_ospf_sr_database`)."""
    return parse_ospf_sr_database(_vtysh_json(grade, machine_name, "show ip ospf database segment-routing", step,
                                              allow_error))


def _route_nexthop(n: Dict[str, Any]) -> Dict[str, Any]:
    return {'ip': n.get('ip'), 'interface': n.get('interfaceName'), 'labels': list(n.get('labels') or []),
            'active': bool(n.get('active')), 'fib': bool(n.get('fib'))}


def parse_frr_routes(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show ip route [vrf X] json`` (zebra's RIB) → ``{prefix: {'protocol': str, 'selected':
    bool, 'installed': bool, 'metric': int | None, 'nexthops': [{'ip', 'interface', 'labels':
    [int], 'active', 'fib'}], 'backups': [same keys]}}``; ``backups`` are the backup next hops
    of a protected route (TI-LFA), which zebra keeps but does not install in the kernel.  Of
    several routes for a prefix the selected one wins (else the first)."""
    result: Dict[str, Dict[str, Any]] = {}
    for prefix, routes in (data or {}).items() if isinstance(data, dict) else []:
        if not isinstance(routes, list):
            continue
        candidates = [r for r in routes if isinstance(r, dict)]
        if not candidates:
            continue
        r = next((x for x in candidates if x.get('selected')), candidates[0])
        result[prefix] = {
            'protocol': r.get('protocol'), 'selected': bool(r.get('selected')), 'installed': bool(r.get('installed')),
            'metric': _int_or_none(r.get('metric')),
            'nexthops': [_route_nexthop(n) for n in r.get('nexthops', []) if isinstance(n, dict)],
            'backups': [_route_nexthop(n) for n in r.get('backupNexthops', []) if isinstance(n, dict)],
        }
    return result


def get_frr_routes(grade: Grade0, machine_name: str, vrf: str = None, step: int = 1,
                   allow_error: bool = True) -> Dict[str, Dict[str, Any]]:
    """Zebra's IPv4 RIB of *machine_name*, of the VRF *vrf* if given (see :func:`parse_frr_routes`)."""
    command = f"show ip route vrf {vrf}" if vrf else "show ip route"
    return parse_frr_routes(_vtysh_json(grade, machine_name, command, step, allow_error))


# ---------------------------------------------------------------------------
# IS-IS (isisd) and BFD (bfdd), FRR 10.3 (fixtures isis_*, bfd_*, config_isis_* captured on Debian 13).
# ``show isis neighbor [detail] json`` keeps one adjacency per broadcast circuit (the others are
# lost), so the neighbours come from the text of ``show isis neighbor detail``; the interfaces,
# the link-state database and the routes from the json output.  Segment routing over IS-IS is
# read from the database (SRGB, prefix-SIDs) and from the label tables (MPLS section above).
# ---------------------------------------------------------------------------

#: kernel route protocol values that mean "installed by isisd"
ISIS_ROUTE_PROTOCOLS = ('isis', '187')
#: FRR defaults of an IS-IS interface: hello interval (s), hello multiplier, metric, priority
ISIS_DEFAULT_HELLO_INTERVAL = 3
ISIS_DEFAULT_HELLO_MULTIPLIER = 10
ISIS_DEFAULT_METRIC = 10
ISIS_DEFAULT_PRIORITY = 64
#: FRR's default SRGB (``segment-routing global-block`` is not shown when it has this value)
ISIS_DEFAULT_SRGB = (16000, 23999)
#: FRR defaults of a BFD session: detect multiplier, receive and transmit intervals (ms)
BFD_DEFAULT_DETECT_MULTIPLIER = 3
BFD_DEFAULT_INTERVAL = 300

_SYSTEM_ID_RE = re.compile(r'^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$')
_NET_RE = re.compile(r'^(?P<area>[0-9a-f]{2}(?:\.[0-9a-f]{4}){0,6})\.(?P<sysid>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})'
                     r'\.(?P<nsel>[0-9a-f]{2})$')
_LSP_ID_RE = re.compile(r'^(?P<node>.+)\.(?P<pseudonode>[0-9a-fA-F]{2})-(?P<fragment>[0-9a-fA-F]{2})$')
_ISIS_LEVEL_KEYS = {'level-1': 1, 'level-2': 2, 'level-2-only': 2, 'level-1-2': 3}


def is_isis_protocol(protocol) -> bool:
    """True when a kernel route ``protocol`` field (``ip -j route``) denotes an IS-IS route."""
    return str(protocol) in ISIS_ROUTE_PROTOCOLS


def isis_system_id_from_ipv4(address) -> str:
    """The system-id made from an IPv4 address by the usual convention: each byte on three
    decimal digits, the twelve digits grouped by four (``10.0.31.2`` → ``0100.0003.1002``)."""
    digits = "".join(f"{int(b):03d}" for b in str(ip_address(str(address).split('/')[0])).split('.'))
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def isis_net(area: str, system_id: str, nsel: str = '00') -> str:
    """The NET of a router: ``isis_net('49.0001', '0100.0003.1002')`` → ``49.0001.0100.0003.1002.00``."""
    return f"{area}.{system_id}.{nsel}"


def parse_isis_net(net) -> Optional[Dict[str, str]]:
    """``'49.0001.0100.0003.1002.00'`` → ``{'area': '49.0001', 'system_id': '0100.0003.1002',
    'nsel': '00'}`` (lower case); ``None`` when *net* is not a NET."""
    m = _NET_RE.match(str(net or '').strip().lower())
    if not m:
        return None
    return {'area': m.group('area'), 'system_id': m.group('sysid'), 'nsel': m.group('nsel')}


def normalize_system_id(text) -> Optional[str]:
    """A system-id as typed (``0100.0003.1002``, ``010000031002``, upper case) in FRR's form, or
    ``None``."""
    word = str(text or '').strip().lower().replace('.', '')
    if len(word) != 12 or any(c not in '0123456789abcdef' for c in word):
        return None
    return f"{word[0:4]}.{word[4:8]}.{word[8:12]}"


def _isis_level(text) -> Optional[int]:
    """``'1'`` / ``'L1'`` → 1, ``'2'`` / ``'L2'`` → 2, ``'3'`` / ``'L1L2'`` → 3 (both levels)."""
    word = str(text or '').strip().upper()
    return {'1': 1, 'L1': 1, '2': 2, 'L2': 2, '3': 3, 'L1L2': 3}.get(word)


def _level_matches(level: Optional[int], wanted: Optional[int]) -> bool:
    """True when an adjacency / circuit of *level* (1, 2 or 3 = both) covers *wanted*
    (``None``: any level; 3: both levels required)."""
    if level is None:
        return False
    if wanted is None:
        return True
    return (level & wanted) == wanted


_NEIGHBOR_TABLE_RE = re.compile(r'^\s(?P<name>\S+)\s+(?P<ifname>\S+)\s+(?P<level>[123])\s+(?P<state>\S+)\s+'
                                r'(?P<hold>\d+)\s+(?P<snpa>\S+)\s*$')
_NEIGHBOR_ITEM_RE = re.compile(r'Interface:\s*(?P<ifname>[^,]+),\s*Level:\s*(?P<level>\d),\s*State:\s*(?P<state>[^,]+)'
                               r'(?:,\s*Expires in\s*(?P<hold>\d+)s)?')


def parse_isis_neighbors(output: str) -> List[Dict[str, Any]]:
    """Parse ``show isis neighbor detail`` (or the plain ``show isis neighbor`` table).

    Returns one dict per adjacency (a broadcast circuit lists one per neighbour and level):
    ``{'name': hostname or system-id, 'interface': str, 'level': 1 | 2 | 3 (both), 'state': 'Up' |
    'Initializing' | 'Down', 'up': bool, 'holdtime': int | None, 'snpa': str | None, and, from the
    detail form only: 'circuit_type': 'L1' | 'L2' | 'L1L2' | None, 'speaks': ['IPv4', 'IPv6'],
    'topologies': [str], 'lan_id': str | None, 'priority': int | None, 'is_dis': bool | None,
    'areas': [str], 'ipv4': [str], 'ipv6': [str] (link-local), 'ipv6_global': [str],
    'bfd': 'Up' | 'Down' | ... | None}``.  ``[]`` on an empty or placeholder output.
    """
    result: List[Dict[str, Any]] = []
    lines = (output or '').splitlines()
    if any(_NEIGHBOR_TABLE_RE.match(line) for line in lines) and not any('Interface:' in line for line in lines):
        for line in lines:
            m = _NEIGHBOR_TABLE_RE.match(line)
            if m and m.group('name') != 'System':
                state = m.group('state')
                result.append({'name': m.group('name'), 'interface': m.group('ifname'),
                               'level': int(m.group('level')), 'state': state, 'up': state == 'Up',
                               'holdtime': int(m.group('hold')), 'snpa': m.group('snpa')})
        return result

    current: Optional[Dict[str, Any]] = None
    pending_name: Optional[str] = None
    list_key: Optional[str] = None
    lists = {'Area Address(es):': 'areas', 'IPv4 Address(es):': 'ipv4', 'IPv6 Address(es):': 'ipv6',
             'Global IPv6 Address(es):': 'ipv6_global', 'Topologies:': 'topologies'}
    for raw in lines:
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if not stripped or indent == 0 and stripped.startswith('Area ') and stripped.endswith(':'):
            list_key = None
            continue
        if indent <= 2 and ' ' not in stripped:
            pending_name, current, list_key = stripped, None, None
            continue
        m = _NEIGHBOR_ITEM_RE.search(stripped)
        if m and pending_name:
            state = m.group('state').strip()
            current = {'name': pending_name, 'interface': m.group('ifname').strip(),
                       'level': int(m.group('level')), 'state': state, 'up': state == 'Up',
                       'holdtime': _int_or_none(m.group('hold')), 'snpa': None, 'circuit_type': None,
                       'speaks': [], 'topologies': [], 'lan_id': None, 'priority': None, 'is_dis': None,
                       'areas': [], 'ipv4': [], 'ipv6': [], 'ipv6_global': [], 'bfd': None}
            result.append(current)
            list_key = None
            continue
        if current is None:
            continue
        if stripped in lists:
            list_key = lists[stripped]
            continue
        if stripped.startswith('Circuit type:'):
            list_key = None
            ct, _, speaks = stripped.partition(',')
            current['circuit_type'] = ct.split(':', 1)[1].strip()
            if 'Speaks:' in speaks:
                current['speaks'] = [s.strip() for s in speaks.split(':', 1)[1].split(',') if s.strip()]
        elif stripped.startswith('SNPA:'):
            list_key = None
            snpa, _, lan = stripped.partition(',')
            current['snpa'] = snpa.split(':', 1)[1].strip()
            if 'LAN id:' in lan:
                current['lan_id'] = lan.split(':', 1)[1].strip()
        elif stripped.startswith('LAN Priority:'):
            list_key = None
            parts = [p.strip() for p in stripped.split(',')]
            current['priority'] = _int_or_none(parts[0].split(':', 1)[1])
            current['is_dis'] = any(p == 'is DIS' for p in parts)
        elif stripped.startswith('BFD is'):
            list_key = None
            m = re.search(r'status\s+(\S+)', stripped)
            current['bfd'] = m.group(1) if m else stripped
        elif list_key and indent >= 6:
            # the items of a list (areas, addresses, topologies) are the lines indented by six
            current[list_key].append(stripped)
        else:
            list_key = None
    return result


def get_isis_neighbors(grade: Grade0, machine_name: str, step: int = 1,
                       allow_error: bool = True) -> List[Dict[str, Any]]:
    """The IS-IS adjacencies of *machine_name* (``show isis neighbor detail``, see
    :func:`parse_isis_neighbors`)."""
    output, code = _test(grade, machine_name, 'vtysh -c "show isis neighbor detail"', step, allow_error)
    return parse_isis_neighbors(output) if code == 0 else []


def isis_adjacencies(neighbors: List[Dict[str, Any]], name=None, interface: str = None,
                     level: int = None, up: bool = True) -> List[Dict[str, Any]]:
    """The adjacencies of :func:`parse_isis_neighbors` with neighbour *name* (its hostname or its
    system-id), on *interface*, covering *level* (1, 2, or 3 for both), Up unless ``up=False``."""
    names = {str(n) for n in (name if isinstance(name, (list, tuple, set)) else [name]) if n is not None}
    result = []
    for n in neighbors:
        if names and n.get('name') not in names:
            continue
        if interface is not None and n.get('interface') != interface:
            continue
        if up and not n.get('up'):
            continue
        result.append(n)
    if level is None:
        return result
    # a broadcast circuit lists one adjacency per level: combine them before testing *level*
    by_key: Dict[tuple, int] = {}
    for n in result:
        key = (n.get('name'), n.get('interface'))
        by_key[key] = by_key.get(key, 0) | (n.get('level') or 0)
    return [n for n in result if _level_matches(by_key[(n.get('name'), n.get('interface'))], level)]


def isis_adjacency_up(neighbors: List[Dict[str, Any]], name=None, interface: str = None,
                      level: int = None) -> bool:
    """True when :func:`isis_adjacencies` finds an Up adjacency (see there for the filters)."""
    return bool(isis_adjacencies(neighbors, name=name, interface=interface, level=level))


def isis_adjacency_levels(neighbors: List[Dict[str, Any]], name=None, interface: str = None) -> int:
    """The levels of the Up adjacencies with *name* (on *interface*): 0, 1, 2 or 3 (both)."""
    levels = 0
    for n in isis_adjacencies(neighbors, name=name, interface=interface):
        levels |= n.get('level') or 0
    return levels


def _json_with_duplicates(output: str) -> Any:
    """Decode FRR json in which an object may repeat a key (several area addresses, several
    prefixes of an interface): a repeated key holds the list of its values."""
    def hook(pairs):
        obj: Dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                if not isinstance(obj[key], list) or not getattr(obj[key], '_dup', False):
                    obj[key] = _DupList([obj[key]])
                obj[key].append(value)
            else:
                obj[key] = value
        return obj
    start = min([i for i in (output.find('{'), output.find('[')) if i >= 0], default=-1)
    if start < 0:
        return None
    try:
        return json.loads(output[start:], object_pairs_hook=hook)
    except (ValueError, TypeError):
        return None


class _DupList(list):
    """The values of a key repeated in a json object (see :func:`_json_with_duplicates`)."""
    _dup = True


def _as_list(value) -> List[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _vtysh_json_any(grade: Grade0, machine_name: str, command: str, step: int, allow_error: bool) -> Any:
    """Run ``vtysh -c "<command> json"`` and decode it with :func:`_json_with_duplicates`
    (``None`` on an error, a placeholder or a text answer)."""
    output, code = _test(grade, machine_name, f'vtysh -c "{command} json"', step, allow_error)
    if code != 0 or not output:
        return None
    return _json_with_duplicates(output)


def _isis_circuits(data: Any) -> List[Dict[str, Any]]:
    circuits = []
    if isinstance(data, dict):
        for area in _as_list(data.get('areas')):
            if isinstance(area, dict):
                for c in _as_list(area.get('circuits')):
                    if isinstance(c, dict):
                        circuits.append((area.get('area'), c))
    return circuits


def parse_isis_interfaces(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show isis interface detail json`` → ``{ifname: {'area': str, 'state': str, 'passive': bool,
    'type': 'p2p' | 'lan' | 'loopback', 'level': 1 | 2 | 3, 'circuit_id': str, 'levels': {1 | 2:
    {'metric': int, 'hello_interval': int | None, 'hello_multiplier': int | None, 'padding': bool,
    'csnp_interval': int | None, 'neighbors': int | None, 'priority': int | None, 'is_dis': bool |
    None}}, 'ipv4': [prefix], 'ipv6': [prefix], 'ipv6_link_local': [prefix]}}``; ``{}`` when IS-IS
    does not run.  ``priority`` / ``is_dis`` are those of a broadcast circuit (``None`` on a point
    to point one)."""
    result: Dict[str, Dict[str, Any]] = {}
    for area, c in _isis_circuits(data):
        i = c.get('interface')
        if not isinstance(i, dict) or not i.get('name'):
            continue
        levels: Dict[int, Dict[str, Any]] = {}
        for lv in _as_list(i.get('levels')):
            if not isinstance(lv, dict):
                continue
            number = _isis_level(lv.get('level'))
            if number not in (1, 2):
                continue
            hold = lv.get('holddown') if isinstance(lv.get('holddown'), dict) else {}
            lan = lv.get('lan') if isinstance(lv.get('lan'), dict) else {}
            levels[number] = {
                'metric': _int_or_none(lv.get('metric')), 'hello_interval': _int_or_none(lv.get('hello-interval')),
                'hello_multiplier': _int_or_none(hold.get('count')), 'padding': hold.get('pad') == 'yes',
                'csnp_interval': _int_or_none(lv.get('cnsp-interval', lv.get('csnp-interval'))),
                'neighbors': _int_or_none(lv.get('active-neighbors')),
                'priority': _int_or_none(lan.get('priority')) if lan else None,
                'is_dis': (lan.get('is-dis') == 'yes') if lan else None,
            }

        def prefixes(key, sub):
            value = i.get(key)
            if not isinstance(value, dict):
                return []
            return [str(x) for x in _as_list(value.get(sub))]
        result[i['name']] = {
            'area': area, 'state': i.get('state'), 'passive': i.get('is-passive') == 'passive',
            'type': i.get('type'), 'level': _isis_level(i.get('level')), 'circuit_id': i.get('circuit-id'),
            'levels': levels, 'ipv4': prefixes('ip-prefix', 'ip'), 'ipv6': prefixes('ipv6-prefixes', 'ipv6'),
            'ipv6_link_local': prefixes('ipv6-link-locals', 'ipv6'),
        }
    return result


def get_isis_interfaces(grade: Grade0, machine_name: str, step: int = 1,
                        allow_error: bool = True) -> Dict[str, Dict[str, Any]]:
    """The IS-IS circuits of *machine_name* (see :func:`parse_isis_interfaces`)."""
    return parse_isis_interfaces(_vtysh_json_any(grade, machine_name, "show isis interface detail", step,
                                                 allow_error))


def isis_lsp_node(lsp_id: str):
    """``'r3.4d-00'`` → ``('r3', '4d', '00')`` (node = hostname or system-id, pseudonode id,
    fragment); ``None`` when *lsp_id* is not an LSP-ID."""
    m = _LSP_ID_RE.match(str(lsp_id or ''))
    if not m:
        return None
    return m.group('node'), m.group('pseudonode').lower(), m.group('fragment').lower()


def _flags_att_p_ol(text) -> tuple:
    parts = str(text or '').split('/')
    if len(parts) != 3:
        return False, False, False
    return tuple(p.strip() == '1' for p in parts)


def _mt_name(entry: Dict[str, Any]) -> Optional[str]:
    """``None`` for the standard topology, ``'ipv6-unicast'`` for a multi-topology entry."""
    name = entry.get('mtName') or entry.get('mt-name')
    if name:
        return str(name)
    return None if str(entry.get('mtId', '')).lower() in ('', 'extended', 'standard') else str(entry.get('mtId'))


def parse_isis_database(data: Any) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """``show isis database detail json`` (or the plain form, with fewer keys) → ``{level: {lsp_id:
    {'node': hostname or system-id, 'pseudonode': bool, 'own': bool, 'seq': int | None,
    'holdtime': int | None, 'att': bool, 'p': bool, 'ol': bool, 'hostname': str | None, 'areas':
    [str], 'protocols': [str], 'topologies': [int], 'router_id': str | None, 'srgb': (base, size) |
    None, 'srlb': (base, size) | None, 'is_reach': [{'id': system-id.pseudonode, 'metric': int,
    'mt': None | 'ipv6-unicast', 'adj_sids': [int]}], 'ip_reach': [{'prefix', 'metric', 'down',
    'sid': {'index', 'no_php', 'explicit_null'} | None}], 'ipv6_reach': [{'prefix', 'metric', 'mt',
    'external', 'down'}]}}}``; ``{}`` when IS-IS does not run."""
    result: Dict[int, Dict[str, Dict[str, Any]]] = {}
    if not isinstance(data, dict):
        return result
    for area in _as_list(data.get('areas')):
        if not isinstance(area, dict):
            continue
        for lv in _as_list(area.get('levels')):
            if not isinstance(lv, dict):
                continue
            level = _int_or_none(lv.get('id'))
            if level not in (1, 2):
                continue
            db = result.setdefault(level, {})
            for e in _as_list(lv.get('lsps')):
                if not isinstance(e, dict) or not isinstance(e.get('lsp'), dict):
                    continue
                lsp_id = e['lsp'].get('id')
                parts = isis_lsp_node(lsp_id)
                if not parts:
                    continue
                att, p, ol = _flags_att_p_ol(e.get('attPOl'))
                gb = e.get('segmentRoutingGb') if isinstance(e.get('segmentRoutingGb'), dict) else None
                lb = e.get('segmentRoutingLb') if isinstance(e.get('segmentRoutingLb'), dict) else None
                protocols = e.get('supportedProtocols')
                is_reach = []
                for r in _as_list(e.get('extReach')) + _as_list(e.get('isReach')):
                    if isinstance(r, dict) and r.get('id'):
                        is_reach.append({'id': str(r['id']), 'metric': _int_or_none(r.get('metric')), 'mt': _mt_name(r),
                                         'adj_sids': [_int_or_none(s.get('sid')) for s in _as_list(r.get('adjSid'))
                                                      if isinstance(s, dict)]})
                ip_reach = []
                for r in _as_list(e.get('extIpReach')) + _as_list(e.get('ipReach')):
                    if not isinstance(r, dict):
                        continue
                    prefix = r.get('ipReach') if isinstance(r.get('ipReach'), str) else r.get('prefix')
                    if not prefix:
                        continue
                    sid = None
                    subtlvs = r.get('subtlvs') if isinstance(r.get('subtlvs'), dict) else {}
                    for s in _as_list(subtlvs.get('sr')):
                        if isinstance(s, dict) and s.get('index') is not None:
                            flags = s.get('flags') if isinstance(s.get('flags'), dict) else {}
                            sid = {'index': _int_or_none(s.get('index')), 'no_php': bool(flags.get('noPHP')),
                                   'explicit_null': bool(flags.get('explicitNull'))}
                    ip_reach.append({'prefix': str(prefix), 'metric': _int_or_none(r.get('ipReachMetric', r.get('metric'))),
                                     'down': bool(r.get('down')), 'sid': sid})
                ipv6_reach = []
                for r in _as_list(e.get('ipv6Reach')):
                    if isinstance(r, dict) and r.get('prefix'):
                        ipv6_reach.append({'prefix': str(r['prefix']), 'metric': _int_or_none(r.get('metric')),
                                           'mt': _mt_name(r), 'external': bool(r.get('external')),
                                           'down': bool(r.get('down'))})
                db[lsp_id] = {
                    'node': parts[0], 'pseudonode': parts[1] != '00', 'own': bool(e['lsp'].get('ownLSP')),
                    'seq': int(e['seqNumber'], 16) if isinstance(e.get('seqNumber'), str)
                    and e['seqNumber'].startswith('0x') else _int_or_none(e.get('seqNumber')),
                    'holdtime': _int_or_none(e.get('holdtime')), 'att': att, 'p': p, 'ol': ol,
                    'hostname': e.get('hostname'), 'areas': [str(a) for a in _as_list(e.get('areaAddr'))],
                    'protocols': [str(v) for v in protocols.values()] if isinstance(protocols, dict) else [],
                    'topologies': [_int_or_none(t.get('mtid')) for t in _as_list(e.get('mt')) if isinstance(t, dict)],
                    'router_id': e.get('teRouterId'),
                    'srgb': (_int_or_none(gb.get('globalBlockBase')), _int_or_none(gb.get('globalBlockRange')))
                    if gb else None,
                    'srlb': (_int_or_none(lb.get('globalBlockBase')), _int_or_none(lb.get('globalBlockRange')))
                    if lb else None,
                    'is_reach': is_reach, 'ip_reach': ip_reach, 'ipv6_reach': ipv6_reach,
                }
    return result


def get_isis_database(grade: Grade0, machine_name: str, step: int = 1,
                      allow_error: bool = True) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """The IS-IS link-state database of *machine_name* (see :func:`parse_isis_database`)."""
    return parse_isis_database(_vtysh_json_any(grade, machine_name, "show isis database detail", step,
                                               allow_error))


def isis_lsps_of(database: Dict[int, Dict[str, Dict[str, Any]]], level: int, node,
                 pseudonode: bool = None) -> List[Dict[str, Any]]:
    """The LSPs of *level* whose node is *node* (a hostname or a system-id, or a list of them);
    ``pseudonode=False`` keeps the router's own LSPs, ``True`` its pseudonode LSPs."""
    nodes = {str(n) for n in (node if isinstance(node, (list, tuple, set)) else [node])}
    return [lsp for lsp in (database.get(level) or {}).values()
            if lsp['node'] in nodes and (pseudonode is None or lsp['pseudonode'] == pseudonode)]


def parse_isis_routes(data: Any, ipv6: bool = False) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """``show isis route json`` → ``{level: {prefix: {'metric': int | None, 'nexthops': [(address |
    None, ifname | None)], 'labels': [str | None]}}}`` for IPv4, or IPv6 with ``ipv6=True``.  An
    ECMP route lists every next hop; the router's own prefixes have no next hop."""
    result: Dict[int, Dict[str, Dict[str, Any]]] = {}
    family = 'ipv6' if ipv6 else 'ipv4'
    for area in _as_list(data):
        if not isinstance(area, dict):
            continue
        for key, level in (('level-1', 1), ('level-2', 2)):
            block = area.get(key)
            if not isinstance(block, dict):
                continue
            table = result.setdefault(level, {})
            for r in _as_list(block.get(family)):
                if not isinstance(r, dict) or not r.get('prefix'):
                    continue
                entry = table.setdefault(str(r['prefix']), {'metric': _int_or_none(r.get('metric')),
                                                            'nexthops': [], 'labels': []})
                hop = r.get('nextHop')
                ifname = r.get('interface')
                if hop and hop != '-':
                    entry['nexthops'].append((str(hop), ifname if ifname and ifname != '-' else None))
                    label = r.get('label(s)')
                    entry['labels'].append(None if label in (None, '-') else str(label))
    return result


def get_isis_routes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True,
                    ipv6: bool = False) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """The routes IS-IS computed on *machine_name*, per level (see :func:`parse_isis_routes`)."""
    return parse_isis_routes(_vtysh_json_any(grade, machine_name, "show isis route", step, allow_error),
                             ipv6=ipv6)


def parse_bfd_peers(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show bfd peers json`` → ``{peer address: {'status': 'up' | 'down' | 'init' | ...,
    'up': bool, 'local': str | None, 'interface': str | None, 'multihop': bool, 'receive_interval':
    int, 'transmit_interval': int, 'detect_multiplier': int, 'remote_receive_interval': int,
    'remote_transmit_interval': int, 'remote_detect_multiplier': int, 'uptime': int | None}}``
    (intervals in ms); ``{}`` without session."""
    result: Dict[str, Dict[str, Any]] = {}
    for p in _as_list(data):
        if not isinstance(p, dict) or not p.get('peer'):
            continue
        status = str(p.get('status') or '')
        result[str(p['peer'])] = {
            'status': status, 'up': status == 'up', 'local': p.get('local'), 'interface': p.get('interface'),
            'multihop': bool(p.get('multihop')),
            'receive_interval': _int_or_none(p.get('receive-interval')),
            'transmit_interval': _int_or_none(p.get('transmit-interval')),
            'detect_multiplier': _int_or_none(p.get('detect-multiplier')),
            'remote_receive_interval': _int_or_none(p.get('remote-receive-interval')),
            'remote_transmit_interval': _int_or_none(p.get('remote-transmit-interval')),
            'remote_detect_multiplier': _int_or_none(p.get('remote-detect-multiplier')),
            'uptime': _int_or_none(p.get('uptime')),
        }
    return result


def get_bfd_peers(grade: Grade0, machine_name: str, step: int = 1,
                  allow_error: bool = True) -> Dict[str, Dict[str, Any]]:
    """The BFD sessions of *machine_name* (see :func:`parse_bfd_peers`)."""
    return parse_bfd_peers(_vtysh_json_any(grade, machine_name, "show bfd peers", step, allow_error))


def bfd_detection_time(peer: Dict[str, Any]) -> Optional[int]:
    """The detection time (ms) of the local end of a session of :func:`parse_bfd_peers`: the
    remote multiplier times the interval at which the packets really arrive (the larger of our
    receive interval and the peer's transmit interval)."""
    try:
        return peer['remote_detect_multiplier'] * max(peer['receive_interval'], peer['remote_transmit_interval'])
    except (KeyError, TypeError):
        return None


# -- configuration (parse_frr_config) --------------------------------------------------

def _empty_isis_interface_config() -> Dict[str, Any]:
    return {'ipv4': None, 'ipv6': None, 'circuit_type': None, 'network_type': None, 'passive': False,
            'metric': {}, 'priority': {}, 'hello_interval': {}, 'hello_multiplier': {}, 'password': None,
            'bfd': False, 'bfd_profile': None, 'fast_reroute': {}}


def _empty_router_isis_config() -> Dict[str, Any]:
    return {'present': False, 'name': None, 'nets': [], 'is_type': None, 'metric_style': None,
            'overload': False, 'area_password': None, 'domain_password': None, 'redistribute': [],
            'default_information': [], 'topologies': [], 'hostname_dynamic': True,
            'lsp_gen_interval': None, 'log_adjacency_changes': False,
            'segment_routing': {'enabled': False, 'srgb': None, 'srlb': None, 'node_msd': None, 'prefixes': {}}}


def _isis_level_key(words: List[str]) -> str:
    """``'level-1'`` / ``'level-2'`` when the statement names one, else ``'all'``."""
    for w in words:
        if w in ('level-1', 'level-2'):
            return w
    return 'all'


def isis_interface_value(isis_cfg: Dict[str, Any], key: str, level: int):
    """The value of a per-level interface statement (``metric``, ``priority``,
    ``hello_interval``, ``hello_multiplier``) of *isis_cfg* for *level*: the level's own
    statement, else the statement for both levels, else ``None``."""
    values = isis_cfg.get(key) or {}
    return values.get(f'level-{level}', values.get('all'))


def _parse_isis_interface_line(ic: Dict[str, Any], w: List[str], negated: bool) -> None:
    """``ip router isis X`` / ``ipv6 router isis X`` / ``isis <w...>`` of an interface block."""
    if w[:3] == ['ip', 'router', 'isis']:
        ic['ipv4'] = None if negated else (w[3] if len(w) >= 4 else '')
        return
    if w[:3] == ['ipv6', 'router', 'isis']:
        ic['ipv6'] = None if negated else (w[3] if len(w) >= 4 else '')
        return
    if not w or w[0] != 'isis' or len(w) < 2:
        return
    sub, args = w[1], w[2:]
    if sub == 'circuit-type':
        ic['circuit_type'] = None if negated or not args else args[0]
    elif sub == 'network':
        ic['network_type'] = None if negated or not args else args[0]
    elif sub == 'passive':
        ic['passive'] = not negated
    elif sub in ('metric', 'priority', 'hello-interval', 'hello-multiplier'):
        key = sub.replace('-', '_')
        level = _isis_level_key(args)
        if negated:
            ic[key].pop(level, None)
        elif args and args[0].isdigit():
            ic[key][level] = int(args[0])
    elif sub == 'password':
        ic['password'] = None if negated or len(args) < 2 else {'type': args[0], 'key': args[1]}
    elif sub == 'bfd':
        if args[:1] == ['profile']:
            ic['bfd_profile'] = None if negated or len(args) < 2 else args[1]
        else:
            ic['bfd'] = not negated
    elif sub == 'fast-reroute' and args[:1] == ['ti-lfa']:
        level = _isis_level_key(args)
        if negated:
            ic['fast_reroute'].pop(level, None)
        else:
            ic['fast_reroute'][level] = 'node' if 'node-protection' in args else 'link'


def _parse_router_isis_line(ri: Dict[str, Any], w: List[str]) -> None:
    """A statement of a ``router isis NAME`` block applied to *ri*."""
    negated = w[0] == 'no'
    if negated:
        w = w[1:]
    if not w:
        return
    kw = w[0]
    if kw == 'net' and len(w) >= 2:
        if negated:
            if w[1] in ri['nets']:
                ri['nets'].remove(w[1])
        elif w[1] not in ri['nets']:
            ri['nets'].append(w[1])
    elif kw == 'is-type':
        ri['is_type'] = None if negated or len(w) < 2 else w[1]
    elif kw == 'metric-style':
        ri['metric_style'] = None if negated or len(w) < 2 else w[1]
    elif kw == 'set-overload-bit':
        ri['overload'] = not negated
    elif kw in ('area-password', 'domain-password'):
        key = kw.replace('-', '_')
        ri[key] = None if negated or len(w) < 3 else {'type': w[1], 'key': w[2]}
    elif kw == 'redistribute' and len(w) >= 4:
        entry = (w[1], w[2], w[3])
        if negated:
            ri['redistribute'] = [r for r in ri['redistribute'] if r != entry]
        elif entry not in ri['redistribute']:
            ri['redistribute'].append(entry)
    elif w[:2] == ['default-information', 'originate'] and len(w) >= 4:
        if negated:
            ri['default_information'] = [d for d in ri['default_information']
                                         if (d['afi'], d['level']) != (w[2], w[3])]
        else:
            ri['default_information'].append({'afi': w[2], 'level': w[3], 'always': 'always' in w[4:]})
    elif kw == 'topology' and len(w) >= 2:
        if negated:
            if w[1] in ri['topologies']:
                ri['topologies'].remove(w[1])
        elif w[1] not in ri['topologies']:
            ri['topologies'].append(w[1])
    elif w[:2] == ['hostname', 'dynamic']:
        ri['hostname_dynamic'] = not negated
    elif kw == 'lsp-gen-interval':
        values = [int(x) for x in w[1:] if x.isdigit()]
        ri['lsp_gen_interval'] = None if negated or not values else values[-1]
    elif kw == 'log-adjacency-changes':
        ri['log_adjacency_changes'] = not negated
    elif kw == 'segment-routing' and len(w) >= 2:
        if negated and w[1] == 'on':
            ri['segment_routing']['enabled'] = False
        elif not negated:
            _parse_ospf_sr_line(ri['segment_routing'], w[1:])


def _parse_bfd_line(bfd: Dict[str, Any], profile: Optional[Dict[str, Any]], w: List[str]) -> None:
    """A statement of a ``profile NAME`` (or ``peer X``) block of ``bfd``."""
    if profile is None or not w:
        return
    if w[0] in ('detect-multiplier', 'receive-interval', 'transmit-interval', 'echo-interval',
                'echo-receive-interval', 'echo-transmit-interval') and len(w) >= 2 and w[1].isdigit():
        profile[w[0].replace('-', '_')] = int(w[1])
    elif w[0] == 'echo-mode':
        profile['echo_mode'] = True
    elif w[0] == 'passive-mode':
        profile['passive_mode'] = True
    elif w[0] == 'shutdown':
        profile['shutdown'] = True


def bfd_profile_value(profile: Optional[Dict[str, Any]], key: str):
    """A setting of a BFD profile of ``parse_frr_config(...)['bfd']['profiles']`` with FRR's
    default when the profile does not set it (``show running-config`` leaves the defaults out):
    ``detect_multiplier`` 3, ``receive_interval`` / ``transmit_interval`` 300 ms."""
    if profile is None:
        return None
    if profile.get(key) is not None:
        return profile[key]
    return {'detect_multiplier': BFD_DEFAULT_DETECT_MULTIPLIER, 'receive_interval': BFD_DEFAULT_INTERVAL,
            'transmit_interval': BFD_DEFAULT_INTERVAL}.get(key)


def isis_srgb(router_isis: Dict[str, Any]) -> Optional[tuple]:
    """The SRGB of ``parse_frr_config(...)['router_isis']``: the configured block, FRR's default
    (16000, 23999) when segment routing is on without ``global-block``, ``None`` when it is off."""
    sr = (router_isis or {}).get('segment_routing') or {}
    if not sr.get('enabled'):
        return None
    return sr.get('srgb') or ISIS_DEFAULT_SRGB


# ---------------------------------------------------------------------------
# EVPN (bgpd l2vpn evpn family, zebra's VNI tables): the VXLAN / EVPN labs
# (lab/sre/_DRAFT_misc/vxlan-evpn.py, evpn-mpls.py; fixtures tests/mock_data/frr/*evpn*, captured on
# FRR 10.3 / Debian 13; facts in .claude/rules/lib-vxlan.md).  The kernel side is lib/vxlan.py.
# ---------------------------------------------------------------------------

_EVPN_TOKEN_RE = re.compile(r'\[([^\]]*)\]')


def get_bgp_evpn_summary(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[str, Any]:
    """The neighbours of the ``l2vpn evpn`` family (``show bgp l2vpn evpn summary json``, the shape
    of :func:`parse_bgp_summary`: ``policy_blocked`` for an eBGP neighbour without route-maps, RFC
    8212 applies to this family too); {} when no neighbour is active in it."""
    return parse_bgp_summary(_vtysh_json(grade, machine_name, 'show bgp l2vpn evpn summary', step, allow_error))


def parse_evpn_prefix(prefix: str) -> Dict[str, Any]:
    """An EVPN prefix as bgpd prints it → its fields::

        '[2]:[0]:[48]:[aa:bb:…]'                  → {'type': 2, 'eth_tag': 0, 'mac': 'aa:bb:…', 'ip': None}
        '[2]:[0]:[48]:[aa:bb:…]:[32]:[10.1.1.5]'  → {'type': 2, …, 'ip': '10.1.1.5'}
        '[3]:[0]:[32]:[10.255.0.11]'              → {'type': 3, 'eth_tag': 0, 'vtep': '10.255.0.11'}
        '[5]:[0]:[24]:[203.0.113.0]'              → {'type': 5, 'eth_tag': 0, 'network': '203.0.113.0/24'}

    ``{}`` when the text is not an EVPN prefix; other route types keep ``type`` and ``fields``."""
    tokens = _EVPN_TOKEN_RE.findall(str(prefix or ''))
    if not tokens or not tokens[0].isdigit():
        return {}
    rtype = int(tokens[0])
    eth_tag = _int_or_none(tokens[1]) if len(tokens) > 1 else None
    if rtype == 2 and len(tokens) >= 4:
        return {'type': 2, 'eth_tag': eth_tag, 'mac': tokens[3].lower(),
                'ip': tokens[5] if len(tokens) >= 6 else None}
    if rtype == 3 and len(tokens) >= 4:
        return {'type': 3, 'eth_tag': eth_tag, 'vtep': tokens[3]}
    if rtype == 5 and len(tokens) >= 4:
        return {'type': 5, 'eth_tag': eth_tag, 'network': f"{tokens[3]}/{tokens[2]}"}
    return {'type': rtype, 'eth_tag': eth_tag, 'fields': tokens[1:]}


def _evpn_vnis(value) -> List[int]:
    return [int(x) for x in re.findall(r'\d+', str(value))] if value not in (None, '') else []


def _evpn_path(rd: str, prefix: str, entry: Dict[str, Any], path: Dict[str, Any]) -> Dict[str, Any]:
    fields = parse_evpn_prefix(prefix)
    communities = str(((path.get('extendedCommunity') or {}).get('string')) or '').split()
    best = path.get('bestpath')
    nexthops = [n.get('ip') for n in (path.get('nexthops') or []) if isinstance(n, dict)]
    peer = path.get('peer') if isinstance(path.get('peer'), dict) else {}
    return {
        'rd': rd, 'prefix': prefix, 'type': fields.get('type'),
        'mac': fields.get('mac'), 'ip': fields.get('ip'), 'vtep': fields.get('vtep'), 'network': fields.get('network'),
        'vnis': _evpn_vnis(path.get('vni')),
        'rts': [c[3:] for c in communities if c.startswith('RT:')],
        'router_mac': next((c[5:].lower() for c in communities if c.startswith('Rmac:')), None),
        'nexthop': nexthops[0] if nexthops else None,
        'best': bool(best.get('overall')) if isinstance(best, dict) else bool(best),
        'valid': bool(path.get('valid')),
        'local': bool(path.get('local')) or path.get('peerId') == '(unspec)',
        'peer': peer.get('peerId') or path.get('peerId'),
        'pmsi': (path.get('pmsi') or {}).get('tunnelType'),
    }


def parse_bgp_evpn_routes(data: Any) -> List[Dict[str, Any]]:
    """Parse the JSON of ``show bgp l2vpn evpn route [detail]``: one dict per path::

        {'rd': '10.255.0.12:3', 'type': 2 | 3 | 5, 'prefix': '[2]:[0]:[48]:[…]:[32]:[…]',
         'mac': str | None, 'ip': str | None,          # type 2 (ip only for a MAC+IP route)
         'vtep': str | None,                           # type 3: the originating VTEP
         'network': '203.0.113.0/24' | None,           # type 5
         'vnis': [200, 4000],     # detail form only: L2VNI, and the L3VNI of a MAC+IP route
         'rts': ['65000:200', '65000:4000'], 'router_mac': str | None,
         'nexthop': '10.255.0.12', 'best': bool, 'valid': bool,
         'local': bool,           # originated by this router
         'peer': '10.255.0.1', 'pmsi': 'Ingress Replication' | None}

    ``[]`` when there is no route (or when bgpd printed its invalid JSON of a router without
    EVPN)."""
    routes: List[Dict[str, Any]] = []
    if not isinstance(data, dict):
        return routes
    for rd, block in data.items():
        if not isinstance(block, dict):
            continue
        for prefix, entry in block.items():
            if not isinstance(entry, dict) or 'paths' not in entry:
                continue
            for group in entry.get('paths') or []:
                for path in (group if isinstance(group, list) else [group]):
                    if isinstance(path, dict):
                        routes.append(_evpn_path(block.get('rd', rd), prefix, entry, path))
    return routes


def get_bgp_evpn_routes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> List[Dict[str, Any]]:
    """Every path of the EVPN table (``show bgp l2vpn evpn route detail json``, see
    :func:`parse_bgp_evpn_routes`; filter with :func:`evpn_routes`)."""
    return parse_bgp_evpn_routes(_vtysh_json(grade, machine_name, 'show bgp l2vpn evpn route detail', step,
                                             allow_error))


def evpn_routes(routes: List[Dict[str, Any]], route_type: int = None, mac=None, ip=None, network=None, vtep=None,
                nexthop=None, rt: str = None, best_only: bool = True, local: bool = None) -> List[Dict[str, Any]]:
    """The paths of a :func:`parse_bgp_evpn_routes` result that match every given criterion
    (*mac* compared case-insensitively; ``ip=False`` keeps the MAC-only type-2 routes);
    *best_only* keeps the best paths."""
    result = []
    for r in routes:
        if best_only and not r['best']:
            continue
        if route_type is not None and r['type'] != route_type:
            continue
        if mac is not None and (r['mac'] or '') != str(mac).lower():
            continue
        if ip is False and r['ip']:
            continue
        if ip not in (None, False) and r['ip'] != str(ip):
            continue
        if network is not None and r['network'] != str(network):
            continue
        if vtep is not None and r['vtep'] != str(vtep):
            continue
        if nexthop is not None and r['nexthop'] != str(nexthop):
            continue
        if rt is not None and rt not in r['rts']:
            continue
        if local is not None and r['local'] != local:
            continue
        result.append(r)
    return result


def parse_evpn_vnis(data: Any) -> Dict[int, Dict[str, Any]]:
    """Parse ``show evpn vni detail json`` (a list; ``{}`` without VNI) or ``show evpn vni json``
    (an object keyed by VNI) → ``{vni: {...}}``::

        {100: {'type': 'L2', 'vrf': 'TENANT', 'vxlan_if': 'vxlan100', 'svi': 'br100',
               'vtep_ip': '10.255.0.11', 'mcast_group': None, 'remote_vteps': ['10.255.0.12', …],
               'flood': {'10.255.0.12': 'HER'}, 'num_macs': 3, 'num_arp': 3,
               'state': None, 'router_mac': None, 'l2_vnis': []},
         4000: {'type': 'L3', 'vrf': 'TENANT', 'vxlan_if': 'vxlan4000', 'svi': 'br4000',
                'vtep_ip': '10.255.0.11', 'state': 'Up', 'router_mac': 'ce:d2:…', 'l2_vnis': [100, 200], …}}

    The brief form has no ``svi`` / ``vtep_ip`` / ``state``; ``mcast_group`` is ``None`` for
    ``0.0.0.0`` (head-end replication)."""
    items = data if isinstance(data, list) else list(data.values()) if isinstance(data, dict) else []
    result: Dict[int, Dict[str, Any]] = {}
    for v in items:
        if not isinstance(v, dict) or _int_or_none(v.get('vni')) is None:
            continue
        remotes = v.get('remoteVteps') if isinstance(v.get('remoteVteps'), list) else []
        flood = {}
        for r in remotes:
            if isinstance(r, dict):
                flood[r.get('ip')] = r.get('flood')
            else:
                flood[str(r)] = None
        group = v.get('mcastGroup')
        result[int(v['vni'])] = {
            'type': v.get('type'), 'vrf': v.get('tenantVrf'),
            'vxlan_if': v.get('vxlanInterface') or v.get('vxlanIntf') or v.get('vxlanIf'),
            'svi': v.get('sviInterface') or v.get('sviIntf'),
            'vtep_ip': v.get('vtepIp') or v.get('localVtepIp'),
            'mcast_group': None if group in (None, '', '0.0.0.0') else group,
            'remote_vteps': sorted(flood), 'flood': flood,
            'num_macs': _int_or_none(v.get('numMacs')), 'num_arp': _int_or_none(v.get('numArpNd')),
            'state': v.get('state'), 'router_mac': (v.get('routerMac') or None),
            'l2_vnis': [int(x) for x in (v.get('l2Vnis') or []) if _int_or_none(x) is not None],
        }
    return result


def get_evpn_vnis(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[int, Dict[str, Any]]:
    """The VNIs zebra knows (``show evpn vni detail json``, see :func:`parse_evpn_vnis`)."""
    return parse_evpn_vnis(_vtysh_json_any(grade, machine_name, 'show evpn vni detail', step, allow_error))


def parse_evpn_macs(data: Any) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """``show evpn mac vni all json`` → ``{vni: {mac: {'type': 'local' | 'remote', 'intf': str |
    None, 'remote_vtep': str | None}}}``."""
    result: Dict[int, Dict[str, Dict[str, Any]]] = {}
    for vni, block in (data or {}).items() if isinstance(data, dict) else []:
        if _int_or_none(vni) is None or not isinstance(block, dict):
            continue
        macs = {}
        for mac, m in (block.get('macs') or {}).items():
            if isinstance(m, dict):
                macs[mac.lower()] = {'type': m.get('type'), 'intf': m.get('intf'), 'remote_vtep': m.get('remoteVtep')}
        result[int(vni)] = macs
    return result


def get_evpn_macs(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[int, Dict[str, Dict[str, Any]]]:
    return parse_evpn_macs(_vtysh_json(grade, machine_name, 'show evpn mac vni all', step, allow_error))


def parse_evpn_arp_cache(data: Any) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """``show evpn arp-cache vni all json`` → ``{vni: {ip: {'type': 'local' | 'remote', 'state':
    'active' | 'inactive', 'mac', 'remote_vtep'}}}`` (a local entry turns *inactive* when the
    kernel's neighbour entry goes STALE: its MAC+IP route is then withdrawn)."""
    result: Dict[int, Dict[str, Dict[str, Any]]] = {}
    for vni, block in (data or {}).items() if isinstance(data, dict) else []:
        if _int_or_none(vni) is None or not isinstance(block, dict):
            continue
        result[int(vni)] = {ip: {'type': e.get('type'), 'state': e.get('state'), 'mac': (e.get('mac') or '').lower(),
                                 'remote_vtep': e.get('remoteVtep')}
                            for ip, e in block.items() if isinstance(e, dict)}
    return result


def get_evpn_arp_cache(grade: Grade0, machine_name: str, step: int = 1,
                       allow_error: bool = True) -> Dict[int, Dict[str, Dict[str, Any]]]:
    return parse_evpn_arp_cache(_vtysh_json(grade, machine_name, 'show evpn arp-cache vni all', step, allow_error))


def parse_vrf_vnis(data: Any) -> Dict[str, Dict[str, Any]]:
    """``show vrf vni json`` → ``{vrf: {'vni', 'vxlan_if', 'svi', 'state', 'router_mac'}}`` (the
    L3VNIs; ``{}`` without any)."""
    result = {}
    for v in (data or {}).get('vrfs', []) if isinstance(data, dict) else []:
        if isinstance(v, dict) and v.get('vrf'):
            result[v['vrf']] = {'vni': _int_or_none(v.get('vni')), 'vxlan_if': v.get('vxlanIntf'),
                                'svi': v.get('sviIntf'), 'state': v.get('state'),
                                'router_mac': (v.get('routerMac') or '').lower() or None}
    return result


def get_vrf_vnis(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[str, Dict[str, Any]]:
    return parse_vrf_vnis(_vtysh_json(grade, machine_name, 'show vrf vni', step, allow_error))


def parse_evpn_rmacs(data: Any) -> Dict[int, Dict[str, str]]:
    """``show evpn rmac vni all json`` → ``{l3vni: {router MAC: VTEP}}`` (the remote VTEPs a
    symmetric IRB leaf routes to)."""
    result: Dict[int, Dict[str, str]] = {}
    for vni, block in (data or {}).items() if isinstance(data, dict) else []:
        if _int_or_none(vni) is None or not isinstance(block, dict):
            continue
        result[int(vni)] = {mac.lower(): e.get('vtepIp') for mac, e in block.items() if isinstance(e, dict)}
    return result


def get_evpn_rmacs(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[int, Dict[str, str]]:
    return parse_evpn_rmacs(_vtysh_json(grade, machine_name, 'show evpn rmac vni all', step, allow_error))


def parse_bgp_evpn_vni(data: Any) -> Dict[str, Any]:
    """``show bgp l2vpn evpn vni json`` → ``{'advertise_all_vni': bool, 'flooding': str | None,
    'vnis': {vni: {'type': 'L2' | 'L3', 'rd', 'import_rts': [...], 'export_rts': [...],
    'rmac'}}}`` (``{}`` when bgpd has no EVPN instance)."""
    if not isinstance(data, dict) or not data:
        return {}
    vnis = {}
    for key, v in data.items():
        if _int_or_none(key) is None or not isinstance(v, dict):
            continue
        vnis[int(key)] = {'type': v.get('type'), 'rd': v.get('rd'), 'import_rts': list(v.get('importRTs') or []),
                          'export_rts': list(v.get('exportRTs') or []), 'rmac': v.get('rmac')}
    return {'advertise_all_vni': data.get('advertiseAllVnis') == 'Enabled', 'flooding': data.get('flooding'),
            'vnis': vnis}


def get_bgp_evpn_vni(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = True) -> Dict[str, Any]:
    return parse_bgp_evpn_vni(_vtysh_json(grade, machine_name, 'show bgp l2vpn evpn vni', step, allow_error))


def _evpn_af(af: Dict[str, Any]) -> Dict[str, Any]:
    """The ``l2vpn evpn`` keys of a per-family dict of ``parse_frr_config`` (added on first use)."""
    for key, default in (('advertise_all_vni', False), ('advertise_ipv4_unicast', False), ('autort_rfc8365', False),
                         ('advertise_svi_ip', False), ('advertise_default_gw', False), ('rd', None)):
        af.setdefault(key, default)
    af.setdefault('rt_import', [])
    af.setdefault('rt_export', [])
    af.setdefault('vnis', {})
    return af


def _apply_route_target(target: Dict[str, Any], w: List[str], negated: bool) -> None:
    # route-target import|export|both RT...
    keys = ['rt_import', 'rt_export'] if w[1] == 'both' else [f"rt_{w[1]}"]
    for key in keys:
        if negated:
            target[key] = [x for x in target[key] if x not in w[2:]] if w[2:] else []
        else:
            target[key] += [x for x in w[2:] if x not in target[key]]


def _parse_evpn_line(rb: Dict[str, Any], words: List[str], open_vni: Optional[Dict[str, Any]]):
    """An ``address-family l2vpn evpn`` statement of a ``router bgp`` block (default instance or
    VRF instance) → ``(handled, open_vni)``; ``open_vni`` is the dict of the open ``vni N`` block
    (its ``rd`` / ``route-target`` lines), ``None`` outside one.  Neighbour statements are left to
    the generic per-family code (``handled`` False)."""
    negated = bool(words) and words[0] == 'no'
    w = words[1:] if negated else words
    if not w or w[0] in ('neighbor', 'address-family', 'exit-address-family'):
        return False, open_vni
    af = _evpn_af(rb['address_families'].setdefault('l2vpn evpn', _empty_bgp_af_config()))
    if w[0] == 'exit-vni':
        return True, None
    if w[0] == 'vni' and len(w) >= 2 and w[1].isdigit():
        if negated:
            af['vnis'].pop(int(w[1]), None)
            return True, None
        vni = af['vnis'].setdefault(int(w[1]), {'rd': None, 'rt_import': [], 'rt_export': []})
        return True, vni
    target = open_vni if open_vni is not None else af
    if w[0] == 'rd' and len(w) >= 2:
        target['rd'] = None if negated else w[1]
    elif w[0] == 'route-target' and len(w) >= 2 and w[1] in ('import', 'export', 'both'):
        _apply_route_target(target, w, negated)
    elif w[0] == 'advertise-all-vni':
        af['advertise_all_vni'] = not negated
    elif w[:3] == ['advertise', 'ipv4', 'unicast']:
        af['advertise_ipv4_unicast'] = not negated
    elif w[:2] == ['autort', 'rfc8365-compatible']:
        af['autort_rfc8365'] = not negated
    elif w[0] == 'advertise-svi-ip':
        af['advertise_svi_ip'] = not negated
    elif w[0] == 'advertise-default-gw':
        af['advertise_default_gw'] = not negated
    else:
        return False, open_vni
    return True, open_vni


def evpn_family(router_bgp: Dict[str, Any]) -> Dict[str, Any]:
    """The ``l2vpn evpn`` view of a ``router_bgp`` (or ``router_bgp_vrfs[X]``) of
    :func:`parse_frr_config`, with every EVPN key present: ``advertise_all_vni``,
    ``advertise_ipv4_unicast``, ``autort_rfc8365``, ``advertise_svi_ip``, ``advertise_default_gw``,
    ``rd``, ``rt_import``, ``rt_export`` (the L3VNI of a VRF instance), ``vnis`` (``{vni: {'rd',
    'rt_import', 'rt_export'}}``, the ``vni N`` blocks) and ``neighbors``."""
    af = dict(((router_bgp or {}).get('address_families') or {}).get('l2vpn evpn') or _empty_bgp_af_config())
    return _evpn_af(af)


# ---------------------------------------------------------------------------
# BGP operations: RPKI (bgpd -M rpki), dampening
# ---------------------------------------------------------------------------

def parse_rpki_cache_connection(data: Any) -> Dict[str, Any]:
    """The JSON of ``show rpki cache-connection``: ``{'connected': bool, 'error': str | None,
    'connections': [{'mode', 'host', 'port', 'preference', 'state'}]}`` (``connected``: one cache
    server at least in state ``connected``; the error is FRR's message when none is,
    ``"No connection to RPKI cache server."``)."""
    result = {'connected': False, 'error': None, 'connections': []}
    if not isinstance(data, dict):
        return result
    result['error'] = data.get('error') if isinstance(data.get('error'), str) else None
    for c in data.get('connections') or []:
        if isinstance(c, dict):
            result['connections'].append({'mode': c.get('mode'), 'host': c.get('host'),
                                          'port': _int_or_none(c.get('port')),
                                          'preference': _int_or_none(c.get('preference')),
                                          'state': c.get('state')})
    result['connected'] = any(c['state'] == 'connected' for c in result['connections'])
    return result


def get_rpki_cache_connection(grade: Grade0, machine_name: str, step: int = 1,
                              allow_error: bool = True) -> Dict[str, Any]:
    """Run 'vtysh -c "show rpki cache-connection json"' (see :func:`parse_rpki_cache_connection`;
    not connected when bgpd has no RPKI module or no cache server)."""
    return parse_rpki_cache_connection(_vtysh_json(grade, machine_name, 'show rpki cache-connection', step,
                                                   allow_error))


def parse_rpki_prefix_table(data: Any) -> List[Dict[str, Any]]:
    """The JSON of ``show rpki prefix-table``: the validated ROA payloads (VRPs) the router got from
    its cache, ``[{'prefix': '172.16.4.0/22', 'max_length': 24, 'asn': 65002}]`` (``[]`` without
    connection: ``{"error": ...}``)."""
    if not isinstance(data, dict):
        return []
    result = []
    for v in data.get('prefixes') or []:
        if not isinstance(v, dict) or not v.get('prefix'):
            continue
        low = _int_or_none(v.get('prefixLenMin'))
        result.append({'prefix': f"{v['prefix']}/{low}" if low is not None else str(v['prefix']),
                       'max_length': _int_or_none(v.get('prefixLenMax')), 'asn': _int_or_none(v.get('asn'))})
    return result


def get_rpki_prefix_table(grade: Grade0, machine_name: str, step: int = 1,
                          allow_error: bool = True) -> List[Dict[str, Any]]:
    """Run 'vtysh -c "show rpki prefix-table json"' (see :func:`parse_rpki_prefix_table`)."""
    return parse_rpki_prefix_table(_vtysh_json(grade, machine_name, 'show rpki prefix-table', step, allow_error))


def rpki_origin_state(vrps: List[Dict[str, Any]], prefix, origin_as: int) -> str:
    """Route origin validation (RFC 6811) of *prefix* announced by *origin_as* against a list of
    VRPs (:func:`parse_rpki_prefix_table`, or the ROAs of a validator file in the same shape):
    ``'notfound'`` when no VRP covers the prefix, ``'valid'`` when one covering VRP has this origin
    and a max length at least the prefix length, else ``'invalid'``."""
    net = ip_network(str(prefix), strict=False)
    covered = False
    for v in vrps:
        try:
            vnet = ip_network(v["prefix"], strict=False)
        except (KeyError, ValueError):
            continue
        if vnet.version != net.version or not net.subnet_of(vnet):
            continue
        covered = True
        max_length = v.get('max_length') if v.get('max_length') is not None else vnet.prefixlen
        if v.get('asn') == origin_as and net.prefixlen <= max_length:
            return 'valid'
    return 'invalid' if covered else 'notfound'


def parse_bgp_dampening_parameters(data: Any) -> Dict[str, Any]:
    """The JSON of ``show bgp ipv4 unicast dampening parameters``: ``{'half_life': 15, 'reuse': 750,
    'suppress': 2000, 'max_suppress': 60}`` (half-life and max-suppress in minutes, as configured
    with ``bgp dampening``); ``{}`` when dampening is off."""
    if not isinstance(data, dict) or 'halfLifeSecs' not in data:
        return {}
    half, max_suppress = _int_or_none(data.get('halfLifeSecs')), _int_or_none(data.get('maxSuppressTimeSecs'))
    return {'half_life': None if half is None else half // 60, 'reuse': _int_or_none(data.get('reusePenalty')),
            'suppress': _int_or_none(data.get('suppressPenalty')),
            'max_suppress': None if max_suppress is None else max_suppress // 60,
            'max_penalty': _int_or_none(data.get('maxSuppressPenalty'))}


def get_bgp_dampening_parameters(grade: Grade0, machine_name: str, step: int = 1,
                                 allow_error: bool = True) -> Dict[str, Any]:
    """Run 'vtysh -c "show bgp ipv4 unicast dampening parameters json"' (see
    :func:`parse_bgp_dampening_parameters`)."""
    return parse_bgp_dampening_parameters(
        _vtysh_json(grade, machine_name, 'show bgp ipv4 unicast dampening parameters', step, allow_error))


def parse_bgp_dampening_paths(data: Any) -> Dict[str, List[Dict[str, Any]]]:
    """The JSON of ``show bgp ipv4 unicast dampening dampened-paths`` or ``... flap-statistics``:
    ``{prefix: [{'peer', 'aspath', 'damped', 'history', 'flaps', 'reuse_ms'}]}`` (``flaps``: only in
    the flap statistics; ``{}`` when nothing is listed or dampening is off)."""
    if not isinstance(data, dict) or not isinstance(data.get('routes'), dict):
        return {}
    result: Dict[str, List[Dict[str, Any]]] = {}
    for prefix, entries in data['routes'].items():
        if isinstance(entries, dict):
            entries = [entries]
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            result.setdefault(prefix, []).append({
                'peer': e.get('peerHost') or e.get('peerId'), 'aspath': e.get('asPath') or e.get('path') or '',
                'damped': bool(e.get('damped')), 'history': bool(e.get('history')),
                'flaps': _int_or_none(e.get('bdiFlap')), 'reuse_ms': _int_or_none(e.get('reuseTimerMsecs'))})
    return result


def get_bgp_dampened_paths(grade: Grade0, machine_name: str, step: int = 1,
                           allow_error: bool = True) -> Dict[str, List[Dict[str, Any]]]:
    """The suppressed paths: 'vtysh -c "show bgp ipv4 unicast dampening dampened-paths json"' (see
    :func:`parse_bgp_dampening_paths`)."""
    return parse_bgp_dampening_paths(
        _vtysh_json(grade, machine_name, 'show bgp ipv4 unicast dampening dampened-paths', step, allow_error))


def get_bgp_flap_statistics(grade: Grade0, machine_name: str, step: int = 1,
                            allow_error: bool = True) -> Dict[str, List[Dict[str, Any]]]:
    """The paths with a flap history: 'vtysh -c "show bgp ipv4 unicast dampening flap-statistics
    json"' (see :func:`parse_bgp_dampening_paths`)."""
    return parse_bgp_dampening_paths(
        _vtysh_json(grade, machine_name, 'show bgp ipv4 unicast dampening flap-statistics', step, allow_error))
