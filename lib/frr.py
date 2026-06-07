import re
from typing import Dict, Any

from SRE.lib_sre import Grade0


def get_ospf_interfaces(grade: Grade0, machine_name: str, step: int = 1) -> Dict[str, Dict[str, Any]]:
    """Run 'vtysh -c "show ip ospf interface"' and parse the output.

    Returns a dict mapping interface name -> dict of parsed fields:
      state            : 'up' | 'down'
      internet_address : str  e.g. '10.150.180.224/28'
      broadcast        : str  e.g. '10.150.180.239'
      area             : str  e.g. '0.0.0.0'
      router_id        : str
      network_type     : str  e.g. 'BROADCAST'
      cost             : int
      ospf_state       : str  e.g. 'Backup', 'DR', 'DROther'
      priority         : int
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
    output, code = grade.test(machine_name, 'vtysh -c "show ip ospf interface"', step=step)
    if code != 0 or not output:
        return {}

    result: Dict[str, Dict[str, Any]] = {}
    current: Dict[str, Any] | None = None

    for line in output.splitlines():
        # Interface header: "ethX is up"
        m = re.match(r'^(\S+) is (up|down)', line)
        if m:
            current = {
                'state': m.group(2),
                'internet_address': None, 'broadcast': None, 'area': None,
                'router_id': None, 'network_type': None, 'cost': None,
                'ospf_state': None, 'priority': None,
                'hello_interval': None, 'dead_interval': None, 'retransmit_interval': None,
                'neighbor_count': None, 'adjacent_neighbor_count': None,
                'dr_id': None, 'dr_address': None,
                'bdr_id': None, 'bdr_address': None,
            }
            result[m.group(1)] = current
            continue

        if current is None:
            continue

        # Internet Address 10.150.180.224/28, Broadcast 10.150.180.239, Area 0.0.0.0
        m = re.search(r'Internet Address (\S+?),\s*Broadcast (\S+?),\s*Area (\S+)', line)
        if m:
            current['internet_address'] = m.group(1)
            current['broadcast'] = m.group(2)
            current['area'] = m.group(3)
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

        # Neighbor Count is 1, Adjacent neighbor count is 1
        m = re.search(r'Neighbor Count is (\d+),\s*Adjacent neighbor count is (\d+)', line)
        if m:
            current['neighbor_count'] = int(m.group(1))
            current['adjacent_neighbor_count'] = int(m.group(2))
            continue

    return result
