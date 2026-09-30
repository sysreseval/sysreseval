"""FRR / OSPF / BGP grading helpers.

Every ``get_*`` function registers one command through ``grade.test()`` -- so it
follows the two-pass contract of ``Grade.grade()`` (placeholder result on the
registration pass, real output afterwards) -- and hands the text to a pure
``parse_*`` function.  The parsers are unit-tested on captured FRR 9 output in
``tests/test_frr.py``.  The OSPF helpers parse the text output of ``vtysh``, the
BGP helpers its ``json`` output (``show bgp ipv4 unicast ... json``).  On the
placeholder output every parser returns its empty shape (``{}``/``[]``), never an
exception.

Pass ``allow_error=True`` when the router may not run OSPF/BGP yet (``vtysh`` then
exits non-zero and the error would otherwise be recorded in the archive).
"""
import json
import re
from ipaddress import IPv4Address
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0

_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

#: kernel route protocol values that mean "installed by ospfd" (name from
#: /etc/iproute2/rt_protos.d/frr.conf, or the raw number when that file is missing)
OSPF_ROUTE_PROTOCOLS = ('ospf', '188')
#: kernel route protocol values that mean "installed by bgpd"
BGP_ROUTE_PROTOCOLS = ('bgp', '186')


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
# ip -j route  (kernel routing table)
# ---------------------------------------------------------------------------

def parse_kernel_routes(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse the JSON of ``ip -j route``.

    Returns ``{prefix: {'protocol': str, 'metric': int, 'scope': str | None,
    'nexthops': [(gateway | None, dev)]}}``; ``default`` becomes ``0.0.0.0/0`` and
    host routes get ``/32``.  ECMP routes list every next hop.  When the same prefix
    appears several times (different metrics) the first entry wins.
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
            dst = '0.0.0.0/0'
        elif '/' not in dst:
            dst += '/32'
        if dst in result:
            continue
        if isinstance(r.get('nexthops'), list):
            nexthops = [(n.get('gateway'), n.get('dev')) for n in r['nexthops'] if isinstance(n, dict)]
        else:
            nexthops = [(r.get('gateway'), r.get('dev'))]
        result[dst] = {
            'protocol': str(r.get('protocol', '')),
            'metric': int(r.get('metric', 0) or 0),
            'scope': r.get('scope'),
            'nexthops': nexthops,
        }
    return result


def get_kernel_routes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run 'ip -j route' and parse it (see :func:`parse_kernel_routes`). Returns {} on error."""
    output, code = _test(grade, machine_name, 'ip -j route', step, allow_error)
    if code != 0 or not output:
        return {}
    return parse_kernel_routes(output)


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
        'addresses': [],
    }


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
    }


def _empty_router_bgp_config() -> Dict[str, Any]:
    return {
        'present': False, 'as': None, 'router_id': None, 'ebgp_requires_policy': True,
        'network_import_check': True, 'default_ipv4_unicast': True, 'bestpath': [], 'cluster_id': None,
        'default_local_preference': None, 'timers': None, 'neighbors': {}, 'networks': [],
        'aggregate_addresses': [], 'redistribute': [],
    }


def _parse_router_bgp_line(rb: Dict[str, Any], words: List[str], neighbor_cfg) -> None:
    """Apply one indented ``router bgp`` statement (router level or address-family) to ``rb``."""
    if not words:
        return
    negated = words[0] == 'no'
    w = words[1:] if negated else words
    if not w:
        return
    if w[0] in ('address-family', 'exit-address-family'):
        return
    if w[0] == 'neighbor' and len(w) >= 3:
        n = neighbor_cfg(w[1])
        kw, arg = w[2], (w[3] if len(w) >= 4 else None)
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
        return
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
        return
    if w[0] == 'network' and len(w) >= 2:
        if negated:
            if w[1] in rb['networks']:
                rb['networks'].remove(w[1])
        else:
            rb['networks'].append(w[1])
    elif w[0] == 'aggregate-address' and len(w) >= 2 and not negated:
        rb['aggregate_addresses'].append((w[1], w[2:]))
    elif w[0] == 'redistribute' and len(w) >= 2 and not negated:
        rb['redistribute'].append(w[1])
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
         'community_lists': {name: [(seq | None, action, 'community ...')]}}

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
        },
        'interfaces': {},
        'router_bgp': _empty_router_bgp_config(),
        'prefix_lists': {},
        'route_maps': {},
        'as_path_lists': {},
        'community_lists': {},
    }
    section: Optional[str] = None  # 'router_ospf' | 'router_bgp' | 'interface' | 'route_map' | 'other' | None
    iface: Dict[str, Any] | None = None
    rm_entry: Dict[str, Any] | None = None
    ro = cfg['router_ospf']
    rb = cfg['router_bgp']

    def neighbor_cfg(peer: str) -> Dict[str, Any]:
        if peer not in rb['neighbors']:
            rb['neighbors'][peer] = _empty_bgp_neighbor_config()
        return rb['neighbors'][peer]

    def seq_of(w: List[str]):
        """Return (seq, rest) for a 'seq N ...' prefix of the word list."""
        if len(w) >= 2 and w[0] == 'seq' and w[1].isdigit():
            return int(w[1]), w[2:]
        return None, w

    def area_cfg(area: str) -> Dict[str, Any]:
        key = normalize_area(area)
        if key not in ro['areas']:
            ro['areas'][key] = _empty_area_config()
        return ro['areas'][key]

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
            if words[0] == 'router' and len(words) >= 3 and words[1] == 'bgp':
                section, iface = 'router_bgp', None
                rb['present'] = True
                rb['as'] = int(words[2]) if words[2].isdigit() else words[2]
                continue
            if words[0] == 'route-map' and len(words) >= 4 and words[2] in ('permit', 'deny'):
                section, iface = 'route_map', None
                rm_entry = {'seq': int(words[3]) if words[3].isdigit() else words[3], 'action': words[2],
                            'match': [], 'set': []}
                cfg['route_maps'].setdefault(words[1], []).append(rm_entry)
                continue
            if words[0] == 'router' or words[0] in ('vrf', 'route-map', 'key', 'line', 'segment-routing'):
                section, iface = 'other', None
                continue
            section, iface, rm_entry = None, None, None
            if words[0] == 'hostname' and len(words) >= 2:
                cfg['hostname'] = words[1]
            elif words[0] == 'ip' and len(words) >= 4 and words[1] == 'route':
                cfg['static_routes'].append((words[2], words[3]))
            elif words[:2] == ['ip', 'prefix-list'] and len(words) >= 5:
                # ip prefix-list NAME [seq N] permit|deny PREFIX [ge X] [le Y]
                seq, rest = seq_of(words[3:])
                if len(rest) >= 2 and rest[0] in ('permit', 'deny'):
                    entry = {'seq': seq, 'action': rest[0], 'prefix': rest[1], 'ge': None, 'le': None}
                    for i in range(2, len(rest) - 1):
                        if rest[i] in ('ge', 'le') and rest[i + 1].isdigit():
                            entry[rest[i]] = int(rest[i + 1])
                    cfg['prefix_lists'].setdefault(words[2], []).append(entry)
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
            continue

        if section == 'route_map' and rm_entry is not None:
            if words[0] == 'match' and len(words) >= 2:
                rm_entry['match'].append(" ".join(words[1:]))
            elif words[0] == 'set' and len(words) >= 2:
                rm_entry['set'].append(" ".join(words[1:]))
            continue

        if section == 'router_bgp':
            _parse_router_bgp_line(rb, words, neighbor_cfg)
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
            continue

    return cfg


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


def as_list_from_string(path) -> List[int]:
    """``'65100 65000'`` -> ``[65100, 65000]`` (AS sets ``{65100,65000}`` keep their members)."""
    if not path:
        return []
    return [int(tok) for tok in re.findall(r'\d+', str(path))]


# -- show bgp ipv4 unicast summary ------------------------------------------

def parse_bgp_summary(data: Any) -> Dict[str, Any]:
    """Parse the JSON of ``show bgp ipv4 unicast summary``.

    Accepts the flat address-family object or the ``{'ipv4Unicast': {...}}`` wrapper of
    ``show bgp summary json``.  Returns ``{}`` when no BGP process answers, else::

        {'router_id': '10.0.0.1', 'as': 65001,
         'peers': {'10.1.1.2': {'remote_as': 65100, 'state': 'Established', 'established': True,
                                'policy_blocked': False,   # eBGP peer without in/out policy (RFC 8212)
                                'pfx_rcd': 3, 'pfx_snt': 1, 'description': 'ISP-A',
                                'uptime': '00:12:34'}}}
    """
    if not isinstance(data, dict):
        return {}
    if 'ipv4Unicast' in data and isinstance(data['ipv4Unicast'], dict):
        data = data['ipv4Unicast']
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
        }
    return {'router_id': data.get('routerId'), 'as': _int_or_none(data.get('as')), 'peers': peers}


def get_bgp_summary(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, Any]:
    """Run 'vtysh -c "show bgp ipv4 unicast summary json"' (see :func:`parse_bgp_summary`).
    Returns {} when BGP is not running."""
    return parse_bgp_summary(_vtysh_json(grade, machine_name, 'show bgp ipv4 unicast summary', step, allow_error))


# -- show bgp neighbors X -----------------------------------------------------

def parse_bgp_neighbor(data: Any, peer: str = None) -> Dict[str, Any]:
    """Parse the JSON of ``show bgp neighbors <peer>``.

    The output is keyed by peer address; ``peer`` selects an entry (the first one when
    omitted).  Returns ``{}`` when the neighbour does not exist, else::

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
         'send_community': True, 'af': {...ipv4Unicast...}, 'raw': {...}}
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
    af = ((entry.get('addressFamilyInfo') or {}).get('ipv4Unicast')) or {}
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
    else:
        link = None
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
        'af': af,
        'raw': entry,
    }


def get_bgp_neighbor(grade: Grade0, machine_name: str, peer, step: int = 1, allow_error: bool = False) -> Dict[str, Any]:
    """Run 'vtysh -c "show bgp neighbors <peer> json"' (see :func:`parse_bgp_neighbor`).
    Returns {} when BGP is not running or the neighbour is unknown."""
    return parse_bgp_neighbor(_vtysh_json(grade, machine_name, f'show bgp neighbors {peer}', step, allow_error),
                              peer=str(peer))


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
        'reason': reason,
        'path_from': path_from,
        'nexthop': used.get('ip'),
        'nexthop_used': bool(used.get('used')),
        'accessible': used.get('accessible'),
        'peer': peer_id,
        'peer_router_id': peer_router_id,
        'aspath': aspath_str,
        'as_list': as_list_from_string(aspath_str),
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
    """Parse the JSON of ``show bgp ipv4 unicast`` (the whole BGP table).

    Returns ``{prefix: [path, ...]}`` (``{}`` when BGP is not running), each path being::

        {'valid': True, 'best': True, 'reason': 'Local Pref', 'path_from': 'internal',
         'nexthop': '10.0.3.3', 'nexthop_used': True, 'accessible': None,
         'peer': '10.0.3.2', 'peer_router_id': None, 'aspath': '65200 65000',
         'as_list': [65200, 65000], 'locprf': 200, 'med': 0, 'weight': 0, 'origin': 'IGP',
         'local': False, 'originator_id': None, 'cluster_list': [], 'communities': []}

    A ``network`` statement whose prefix has no route in the RIB (``bgp network
    import-check``) yields a path with ``valid`` and ``best`` both ``False``.
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


def get_bgp_routes(grade: Grade0, machine_name: str, step: int = 1, allow_error: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """Run 'vtysh -c "show bgp ipv4 unicast json"' (see :func:`parse_bgp_routes`). Returns {} on error."""
    return parse_bgp_routes(_vtysh_json(grade, machine_name, 'show bgp ipv4 unicast', step, allow_error))


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


def get_bgp_prefix(grade: Grade0, machine_name: str, prefix, step: int = 1, allow_error: bool = False) -> Dict[str, Any]:
    """Run 'vtysh -c "show bgp ipv4 unicast <prefix> json"' (see :func:`parse_bgp_prefix`)."""
    return parse_bgp_prefix(_vtysh_json(grade, machine_name, f'show bgp ipv4 unicast {prefix}', step, allow_error))


# -- show bgp ipv4 unicast neighbors X advertised-routes ------------------------

def parse_bgp_advertised_routes(data: Any) -> Dict[str, Dict[str, Any]]:
    """Parse the JSON of ``show bgp ipv4 unicast neighbors <peer> advertised-routes``
    (the routes sent to that peer, after the outbound policy).

    Returns ``{prefix: {'nexthop', 'aspath', 'as_list', 'locprf', 'med', 'weight', 'origin'}}``
    (``{}`` on error or when nothing is advertised).
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
            'nexthop': e.get('nextHop'),
            'aspath': path,
            'as_list': as_list_from_string(path),
            'locprf': _int_or_none(e.get('locPrf')),
            'med': _int_or_none(e.get('metric')),
            'weight': _int_or_none(e.get('weight')) or 0,
            'origin': e.get('bgpOriginCode') or e.get('origin'),
        }
    return result


def get_bgp_advertised_routes(grade: Grade0, machine_name: str, peer, step: int = 1,
                              allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show bgp ipv4 unicast neighbors <peer> advertised-routes json"'
    (see :func:`parse_bgp_advertised_routes`)."""
    return parse_bgp_advertised_routes(
        _vtysh_json(grade, machine_name, f'show bgp ipv4 unicast neighbors {peer} advertised-routes', step, allow_error))
