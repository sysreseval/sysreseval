"""Managed switches of a lab: grading helpers around ``Grade.test_switch()``.

A network declared with ``'mode': 'managed'`` in ``_network_specs`` is a ``vde_switch`` with VLANs
and a management console.  ``get_switch_ports(grade, 'lan')`` reads its port and VLAN tables and
gives the port of each machine; ``get_switch_vlans(grade, 'lan')`` gives the members of each
VLAN.  ``parse_switch_ports`` / ``parse_switch_vlans`` are the pure parsers of the
``port/allprint`` and ``vlan/allprint`` outputs (fixtures in ``tests/mock_data/switch/``:
VDE switch 2.3.3 behind the Kathara network plugin, which names each port's endpoint
``kathara <machine>:eth<N>``).
"""
import re
from typing import Any, Dict, List

SWITCH_PORTS_CMD = "port/allprint"
SWITCH_VLANS_CMD = "vlan/allprint"

_PORT_RE = re.compile(r"^Port (\d+) untagged_vlan=(\d+) (IN)?ACTIVE")
_ENDPOINT_RE = re.compile(r"^\s*-- endpoint ID \d+ module [^:]*: (.*?)(?: user=\S+ pid=\d+.*)?$")
_VLAN_RE = re.compile(r"^VLAN (\d+)")
_VLAN_PORT_RE = re.compile(r"^\s*-- Port (\d+) tagged=(\d)")
_MACHINE_ENDPOINT_RE = re.compile(r"^kathara (\S+):(eth\d+)$")


def parse_switch_vlans(vlans_output: str) -> Dict[int, Dict[str, List[int]]]:
    """Parse a ``vlan/allprint`` output: ``{vlan: {'untagged': [port, ...], 'tagged': [port, ...]}}``.

    VLAN 0 is the default VLAN of the switch (ports without configuration)."""
    vlans: Dict[int, Dict[str, List[int]]] = {}
    current = None
    for line in (vlans_output or '').splitlines():
        m = _VLAN_RE.match(line)
        if m:
            current = vlans.setdefault(int(m.group(1)), {'untagged': [], 'tagged': []})
            continue
        m = _VLAN_PORT_RE.match(line)
        if m and current is not None:
            current['tagged' if m.group(2) == '1' else 'untagged'].append(int(m.group(1)))
    return vlans


def parse_switch_ports(ports_output: str, vlans_output: str = '') -> Dict[int, Dict[str, Any]]:
    """Parse a ``port/allprint`` output (and the ``vlan/allprint`` one for the tagged VLANs).

    Returns ``{port number: {...}}`` with ``vlan`` (VLAN of the untagged frames, 0 = default),
    ``tagged_vlans`` (sorted), ``active`` (something is plugged), ``endpoints`` (descriptions of
    what is plugged) and, when it is the interface of a machine, ``machine`` and ``interface``
    (``'pc1'``, ``'eth0'``; ``None`` otherwise).
    """
    ports: Dict[int, Dict[str, Any]] = {}
    port = None
    for line in (ports_output or '').splitlines():
        m = _PORT_RE.match(line)
        if m:
            port = {'vlan': int(m.group(2)), 'tagged_vlans': [], 'active': not m.group(3),
                    'endpoints': [], 'machine': None, 'interface': None}
            ports[int(m.group(1))] = port
            continue
        m = _ENDPOINT_RE.match(line)
        if m and port is not None:
            description = m.group(1).strip()
            port['endpoints'].append(description)
            machine = _MACHINE_ENDPOINT_RE.match(description)
            if machine:
                port['machine'], port['interface'] = machine.group(1), machine.group(2)
    for vlan, members in parse_switch_vlans(vlans_output).items():
        for number in members['tagged']:
            if number in ports:
                ports[number]['tagged_vlans'].append(vlan)
    for port in ports.values():
        port['tagged_vlans'].sort()
    return ports


def ports_by_machine(ports: Dict[int, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """``{machine: {'port', 'interface', 'vlan', 'tagged_vlans'}}`` from :func:`parse_switch_ports`."""
    return {port['machine']: {'port': number, 'interface': port['interface'], 'vlan': port['vlan'],
                              'tagged_vlans': list(port['tagged_vlans'])}
            for number, port in sorted(ports.items()) if port['machine']}


def get_switch_ports(grade, network: str, step: int = 1, allow_error: bool = False) -> Dict[str, Dict[str, Any]]:
    """Ports of the managed switch *network*, by machine name.

    ``{'pc1': {'port': 2, 'interface': 'eth0', 'vlan': 10, 'tagged_vlans': []}, ...}``: ``vlan``
    is the VLAN of the untagged frames (0 = default VLAN of the switch), ``tagged_vlans`` the
    VLANs of a trunk port.  ``{}`` until the tests have run or when the console failed.
    """
    ports_out, ports_code = grade.test_switch(network, SWITCH_PORTS_CMD, step=step, allow_error=allow_error)
    vlans_out, vlans_code = grade.test_switch(network, SWITCH_VLANS_CMD, step=step, allow_error=allow_error)
    if ports_code != 0:
        return {}
    return ports_by_machine(parse_switch_ports(ports_out, vlans_out if vlans_code == 0 else ''))


def get_switch_vlans(grade, network: str, step: int = 1, allow_error: bool = False) -> Dict[int, Dict[str, List[int]]]:
    """VLANs of the managed switch *network*: ``{vlan: {'untagged': [ports], 'tagged': [ports]}}``
    (port numbers, see :func:`get_switch_ports` for the machines).  ``{}`` until the tests have
    run or when the console failed."""
    out, code = grade.test_switch(network, SWITCH_VLANS_CMD, step=step, allow_error=allow_error)
    return parse_switch_vlans(out) if code == 0 else {}
