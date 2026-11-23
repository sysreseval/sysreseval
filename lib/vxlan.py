"""VXLAN helpers on the Linux side, for the VXLAN / EVPN labs (``lab/sre/_DRAFT_misc/vxlan-evpn.py``,
``lab/sre/_DRAFT_misc/evpn-mpls.py``).

The EVPN control plane is read through lib/frr.py (``get_bgp_evpn_*``, ``get_evpn_*``); this module
reads what the kernel does:

- the VXLAN devices and their parameters (VNI, local address, multicast group, UDP port, TTL,
  learning, MTU, bridge) from the JSON of ``ip -d link`` (:func:`vxlan_devices`);
- the forwarding database of a VXLAN device: the flood list of head-end replication (the
  ``00:00:00:00:00:00`` entries, :func:`flood_list`) and the remote MACs with their VTEP
  (:func:`remote_macs`);
- the bridge port flags of ``bridge -d link`` (ARP suppression, :func:`bridge_port_flags`);
- the fragmentation counter of a router (``nstat``, :func:`parse_frag_creates`) and a ping with
  the DF bit after flushing the PMTU cache of the host (:func:`df_ping_cmd`): the two probes of the
  MTU questions;

and builds the shell commands of the states (:func:`vxlan_cmds`, :func:`bridge_cmds`,
:func:`flood_cmds`, :func:`l3vni_cmds`).

Facts (Debian 13 kernel 6.12, iproute2 7.3.0, checked in the containers; ``.claude/rules/lib-vxlan.md``):
a VXLAN device created without ``dev`` has an MTU of 1500, 1450 with ``dev eth0``; a host sending
oversized DF packets through it gets an ICMP *fragmentation needed* from the VTEP and caches a PMTU of
1450 for about ten minutes; a multicast VXLAN packet leaves with a TTL of 1 unless ``ttl`` is set.

Every ``get_*`` helper registers one command with ``grade.test()`` and parses its output with a
pure ``parse_*`` function (fixtures in tests/mock_data/vxlan/).
"""
import json
import shlex
from typing import Any, Dict, Iterable, List, Optional

from SRE.lib_sre import Grade0
from bridging import (  # noqa: F401  (re-exported for the labs)
    get_ip_links, link_address, link_master, link_up, links_by_name, normalize_mac, parse_fdb_json,
)

VXLAN_PORT = 4789
VXLAN_OVERHEAD = 50          # outer Ethernet 14 + IPv4 20 + UDP 8 + VXLAN 8
FLOOD_MAC = '00:00:00:00:00:00'
FRAG_CREATES_CMD = 'nstat -az IpFragCreates'
# Docker mounts /proc/sys read-only: remounted before flushing the route cache
_REMOUNT = 'test -w /proc/sys/net/ipv4/ip_forward || mount -o rw,remount /proc/sys'
FLUSH_PMTU_CMD = f'{_REMOUNT}; ip route flush cache'


def _test(grade: Grade0, machine_name: str, command: str, step: int, allow_error: bool):
    output, code = grade.test(machine_name, command, step=step, allow_error=allow_error)
    return output if code == 0 else ""


def _int_or_none(value) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# VXLAN devices (ip -j -d link)
# ---------------------------------------------------------------------------


def vxlan_devices(links: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """The VXLAN devices of a ``get_ip_links()`` result (``ip -j -d link``)::

        {'vxlan100': {'vni': 100, 'local': '10.255.0.11' | None, 'group': '239.1.1.5' | None,
                      'remote': None, 'dev': 'eth0' | None, 'port': 4789, 'ttl': 0,
                      'learning': True, 'mtu': 1500, 'master': 'br100' | None, 'up': True,
                      'neigh_suppress': False, 'address': '86:b5:…'}}

    ``ttl`` 0 means the default (1 for a multicast group, 64 otherwise); ``up`` is the
    administrative state (the ``UP`` flag: a VXLAN device stays ``UNKNOWN`` in ``operstate``);
    ``neigh_suppress`` comes from the bridge port data (False outside a bridge)."""
    result: Dict[str, Dict[str, Any]] = {}
    for link in links or []:
        if not isinstance(link, dict):
            continue
        info = link.get('linkinfo') or {}
        if info.get('info_kind') != 'vxlan':
            continue
        data = info.get('info_data') or {}
        slave = info.get('info_slave_data') or {}
        result[link.get('ifname')] = {
            'vni': _int_or_none(data.get('id')),
            'local': data.get('local'),
            'group': data.get('group'),
            'remote': data.get('remote'),
            'dev': data.get('link'),
            'port': _int_or_none(data.get('port')),
            'ttl': _int_or_none(data.get('ttl')) or 0,
            'learning': bool(data.get('learning')),
            'mtu': _int_or_none(link.get('mtu')),
            'master': link.get('master'),
            'up': 'UP' in (link.get('flags') or []),
            'neigh_suppress': bool(slave.get('neigh_suppress')),
            'address': normalize_mac(link.get('address')),
        }
    return result


def vxlan_of_vni(devices: Dict[str, Dict[str, Any]], vni: int) -> Optional[str]:
    """The name of the VXLAN device of *vni* in a :func:`vxlan_devices` result (``None``)."""
    for name, device in devices.items():
        if device['vni'] == vni:
            return name
    return None


def link_mtu(links: List[Dict[str, Any]], ifname: str) -> Optional[int]:
    """The MTU of *ifname* in a ``get_ip_links()`` result (``None`` when absent)."""
    link = links_by_name(links or []).get(ifname)
    return _int_or_none(link.get('mtu')) if link else None


# ---------------------------------------------------------------------------
# forwarding database of a VXLAN device (bridge -j fdb show dev X)
# ---------------------------------------------------------------------------


def vxlan_fdb_cmd(dev: str) -> str:
    """``bridge -j fdb show dev <dev>``: the entries of the VXLAN device (its own ``self``
    entries with ``dst``, and the bridge entries learned on that port)."""
    return f"bridge -j fdb show dev {shlex.quote(str(dev))}"


def _on_dev(entry: Dict[str, Any], dev: str) -> bool:
    # ``bridge fdb show dev X`` omits ifname; ``bridge fdb show br B`` gives it
    return entry.get('ifname') in (None, dev)


def flood_list(entries: List[Dict[str, Any]], dev: str) -> List[str]:
    """The destinations of the ``00:00:00:00:00:00`` entries of *dev* in a
    :func:`parse_fdb_json` result, sorted: the remote VTEPs of head-end replication (static or
    installed by EVPN type-3 routes), or the multicast group."""
    return sorted({e['dst'] for e in entries
                   if e['mac'] == FLOOD_MAC and e.get('dst') and _on_dev(e, dev)})


def remote_macs(entries: List[Dict[str, Any]], dev: str, extern_only: bool = False) -> Dict[str, str]:
    """``{mac: remote VTEP}`` of the ``self`` entries of *dev* with a ``dst`` (the flood entries
    left out): MACs learned from the traffic, or installed by EVPN (``extern_learn``, only those
    with *extern_only*)."""
    result = {}
    for e in entries:
        if e['mac'] == FLOOD_MAC or not e.get('dst') or 'self' not in e['flags'] or not _on_dev(e, dev):
            continue
        if extern_only and 'extern_learn' not in e['flags']:
            continue
        result[e['mac']] = e['dst']
    return result


def get_vxlan_fdb(grade: Grade0, machine_name: str, dev: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_fdb_json` of ``bridge -j fdb show dev <dev>`` on *machine_name* (``[]`` on
    failure, a missing device included)."""
    return parse_fdb_json(_test(grade, machine_name, vxlan_fdb_cmd(dev), step, True))


FDB_ALL_CMD = "bridge -j fdb show"


def get_fdb_all(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_fdb_json` of ``bridge -j fdb show`` (every entry of every device, each with its
    ``ifname``): for a grader that does not know the names the students gave their devices; filter
    with :func:`flood_list` / :func:`remote_macs` once the device of a VNI is known
    (:func:`vxlan_of_vni`)."""
    return parse_fdb_json(_test(grade, machine_name, FDB_ALL_CMD, step, True))


# ---------------------------------------------------------------------------
# bridge ports (bridge -j -d link show): ARP suppression
# ---------------------------------------------------------------------------

BRIDGE_PORTS_CMD = "bridge -j -d link show"


def bridge_port_flags(output: str) -> Dict[str, Dict[str, Any]]:
    """``bridge -j -d link show`` → ``{ifname: {'master', 'state', 'neigh_suppress', 'learning',
    'flood', 'mtu'}}`` (``{}`` when invalid)."""
    try:
        ports = json.loads(output or '[]')
    except ValueError:
        return {}
    result = {}
    for p in ports if isinstance(ports, list) else []:
        if not isinstance(p, dict) or not p.get('ifname'):
            continue
        result[p['ifname']] = {'master': p.get('master'), 'state': p.get('state'),
                               'neigh_suppress': bool(p.get('neigh_suppress')),
                               'learning': bool(p.get('learning')), 'flood': bool(p.get('flood')),
                               'mtu': _int_or_none(p.get('mtu'))}
    return result


def get_bridge_port_flags(grade: Grade0, machine_name: str, step: int = 1) -> Dict[str, Dict[str, Any]]:
    """:func:`bridge_port_flags` on *machine_name* (``{}`` on failure)."""
    return bridge_port_flags(_test(grade, machine_name, BRIDGE_PORTS_CMD, step, True))


# ---------------------------------------------------------------------------
# MTU probes
# ---------------------------------------------------------------------------


def parse_frag_creates(output: str) -> Optional[int]:
    """The value of ``IpFragCreates`` in the output of ``nstat -az IpFragCreates`` (``None``
    when absent): the IPv4 fragments the machine has created since it started."""
    for line in (output or '').splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == 'IpFragCreates':
            return _int_or_none(words[1])
    return None


def get_frag_creates(grade: Grade0, machine_name: str, step: int = 1) -> Optional[int]:
    """:func:`parse_frag_creates` on *machine_name*."""
    return parse_frag_creates(_test(grade, machine_name, FRAG_CREATES_CMD, step, True))


def frag_delta(before: Optional[int], after: Optional[int]) -> Optional[int]:
    """``after - before`` (``None`` when a counter is missing)."""
    if before is None or after is None:
        return None
    return after - before


def df_ping_cmd(dest, size: int = 1472, count: int = 3, deadline: int = 4) -> str:
    """Flush the PMTU cache of the host (an earlier ICMP *fragmentation needed* from a VTEP keeps
    a smaller PMTU for ten minutes), then ping *dest* with the DF bit and *size* bytes of payload
    (1472 = an IPv4 packet of 1500 bytes)."""
    return (f"{FLUSH_PMTU_CMD} 2>/dev/null; "
            f"ping -c {count} -i 0.2 -W 1 -w {deadline} -M do -s {size} {dest}")


# ---------------------------------------------------------------------------
# state commands
# ---------------------------------------------------------------------------


def vxlan_cmds(name: str, vni: int, local=None, group=None, dev: str = None, ttl: int = None,
               learning: bool = True, port: int = VXLAN_PORT, mtu: int = None) -> List[str]:
    """The commands that create the VXLAN device *name* and bring it up (``nolearning`` when
    *learning* is false: EVPN installs the remote MACs itself)."""
    words = [f"ip link add {name} type vxlan id {vni}"]
    if local is not None:
        words.append(f"local {local}")
    if group is not None:
        words.append(f"group {group}")
    if dev is not None:
        words.append(f"dev {dev}")
    if ttl is not None:
        words.append(f"ttl {ttl}")
    words.append(f"dstport {port}")
    if not learning:
        words.append("nolearning")
    cmds = [" ".join(words)]
    if mtu is not None:
        cmds.append(f"ip link set {name} mtu {mtu}")
    return cmds + [f"ip link set {name} up"]


def bridge_cmds(bridge: str, ports: Iterable[str], address=None, mac: str = None, vrf: str = None,
                neigh_suppress: Iterable[str] = ()) -> List[str]:
    """The commands that create the bridge *bridge*, enslave *ports*, and optionally give it a MAC
    address (an anycast gateway), an address (the SVI) and a VRF; ``neigh_suppress`` names the
    ports on which ARP suppression is turned on."""
    cmds = [f"ip link add {bridge} type bridge"]
    if mac:
        cmds.append(f"ip link set {bridge} address {mac}")
    if vrf:
        cmds.append(f"ip link set {bridge} master {vrf}")
    if address is not None:
        cmds.append(f"ip addr add {address} dev {bridge}")
    for port in ports:
        cmds.append(f"ip link set {port} master {bridge}")
    for port in neigh_suppress:
        cmds.append(f"ip link set {port} type bridge_slave neigh_suppress on")
    cmds += [f"ip link set {port} up" for port in ports]
    return cmds + [f"ip link set {bridge} up"]


def flood_cmds(dev: str, remotes: Iterable) -> List[str]:
    """The static flood list of head-end replication: one ``00:00:00:00:00:00`` entry per remote
    VTEP."""
    return [f"bridge fdb append {FLOOD_MAC} dev {dev} dst {r}" for r in remotes]


def vrf_cmds(vrf: str, table: int) -> List[str]:
    """The commands that create the VRF device *vrf* bound to *table*."""
    return [f"ip link add {vrf} type vrf table {table}", f"ip link set {vrf} up"]


def l3vni_cmds(vrf: str, table: int, vni: int, local, vxlan: str = None, bridge: str = None,
               create_vrf: bool = True) -> List[str]:
    """The kernel side of an L3VNI (symmetric IRB): the VRF (unless *create_vrf* is false), a
    VXLAN device without learning and its bridge, enslaved to the VRF.  FRR still needs ``vrf
    <vrf>`` / `` vni <vni>``."""
    vxlan = vxlan or f"vxlan{vni}"
    bridge = bridge or f"br{vni}"
    cmds = vrf_cmds(vrf, table) if create_vrf else []
    return (cmds + vxlan_cmds(vxlan, vni, local=local, learning=False)
            + bridge_cmds(bridge, [vxlan], vrf=vrf))
