"""Open vSwitch / OpenFlow helpers of the SDN lab (``lab/sre/_DRAFT_misc/sdn.py``).

The switches and controllers run the image ``sysreseval/netdev13`` (``images/netdev13/Dockerfile``):
Debian 13's Open vSwitch 3.5 (kernel datapath: the module ``openvswitch`` of the host, loaded by the
kernel on demand) and OS-Ken 3.0 with the two applications the image adds,
``os_ken.app.simple_switch_13`` and ``os_ken.app.ofctl_rest`` (Ryu's REST API).

State side::

    net_scheme.cmd('sw1', ovs_start_cmd())                          # ovsdb-server + ovs-vswitchd
    net_scheme.cmd('sw2', ovs_bridge_cmd('br0', [('eth0', 7), ('eth1', 3)], fail_mode='secure'))
    net_scheme.cmd('ctl', osken_start_cmd(['os_ken.app.ofctl_rest']))
    net_scheme.cmd('ops', rest_cmd('10.0.0.1', 'flowentry/add', {'dpid': 161, ...}))

Grade side::

    state = get_ovs_state(grade, 'sw1')          # bridges, ports (tags), interfaces (ofport), controllers
    state.bridge('br0').port('eth0').tag; state.bridge('br0').controllers[0].is_connected
    flows = get_flows(grade, 'sw3', 'br0')       # [Flow(table, priority, match, actions, n_packets...)]
    trace = get_trace(grade, 'sw2', 'br0', 'in_port=3,tcp,nw_src=...')   # trace.dropped
    meters = get_meters(grade, 'sw4a', 'br0')    # {meter_id: Meter(flags, bands)}

The formats were captured on s17 (Open vSwitch 3.5.0, OS-Ken 3.0.1, 2026-11-24): ``tests/mock_data/sdn/``.
"""
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0

OVS_CTL = "/usr/share/openvswitch/scripts/ovs-ctl"
OVS_START_LOG = "/var/log/sre-ovs-start.log"
OPENFLOW_PORT = 6653
OVSDB_PORT = 6640
REST_PORT = 8080
OSKEN_LOG = "/var/log/osken-manager.log"
OSKEN_PID_FILE = "/run/osken-manager.pid"
#: the priority of a flow entry written without ``priority=`` (ovs-ofctl prints none for it)
DEFAULT_PRIORITY = 32768
_SEP = "==SRE-SDN=="  # never "@@@": the separator of the commands of exetests.py
_OVS_TABLES = ("Bridge", "Port", "Interface", "Controller")

#: the protocol shortcuts of the ovs-ofctl flow syntax -> the fields they stand for
PROTOCOL_SHORTCUTS = {
    "ip": {"eth_type": 0x0800}, "ipv4": {"eth_type": 0x0800}, "ipv6": {"eth_type": 0x86DD},
    "arp": {"eth_type": 0x0806}, "rarp": {"eth_type": 0x8035},
    "icmp": {"eth_type": 0x0800, "ip_proto": 1}, "icmp6": {"eth_type": 0x86DD, "ip_proto": 58},
    "tcp": {"eth_type": 0x0800, "ip_proto": 6}, "tcp6": {"eth_type": 0x86DD, "ip_proto": 6},
    "udp": {"eth_type": 0x0800, "ip_proto": 17}, "udp6": {"eth_type": 0x86DD, "ip_proto": 17},
    "sctp": {"eth_type": 0x0800, "ip_proto": 132},
}
#: the older ovs-ofctl field names (what dump-flows prints) -> the OpenFlow 1.3 names
FIELD_ALIASES = {
    "dl_src": "eth_src", "dl_dst": "eth_dst", "dl_type": "eth_type",
    "nw_src": "ipv4_src", "nw_dst": "ipv4_dst", "nw_proto": "ip_proto",
}
_STATS_KEYS = ("cookie", "duration", "table", "n_packets", "n_bytes", "idle_timeout", "hard_timeout",
               "idle_age", "hard_age", "importance", "send_flow_rem", "reset_counts", "no_packet_counts",
               "no_byte_counts", "out_port", "out_group")


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def ovs_start_cmd() -> str:
    """Start ovsdb-server and ovs-vswitchd, then wait until ``ovs-vsctl`` answers.

    ``ovs-dpctl show`` first asks the kernel for the generic netlink family of the datapath, which
    makes the kernel load the module ``openvswitch`` (a container cannot load a module itself):
    ovs-ctl then skips its own ``modprobe`` (``/sys/module/openvswitch`` exists)."""
    return (f"ovs-dpctl show >/dev/null 2>&1; {OVS_CTL} --system-id=random start >{OVS_START_LOG} 2>&1; "
            "for i in $(seq 50); do ovs-vsctl --timeout=2 show >/dev/null 2>&1 && break; sleep 0.2; done; "
            "ovs-vsctl --timeout=2 show >/dev/null")


def dpid_text(dpid: int) -> str:
    """The 16 hexadecimal digits of a datapath ID (what ``other-config:datapath-id`` takes)."""
    return f"{int(dpid):016x}"


def ovs_bridge_cmd(bridge: str, ports: Sequence[Tuple[str, Optional[int]]] = (), *,
                   protocols: Optional[str] = "OpenFlow13", fail_mode: Optional[str] = None,
                   dpid: Optional[int] = None, controller: Optional[str] = None,
                   tags: Optional[Dict[str, int]] = None) -> str:
    """One ``ovs-vsctl`` transaction creating *bridge* (if missing) with its settings, then its
    *ports* ``(interface, ofport_request or None)`` in that order (access VLAN from *tags*).

    The fail mode, the protocols, the datapath ID and the controller are set in the same
    transaction as the bridge, before any port: a secure bridge never switches a packet by itself."""
    words = [f"--may-exist add-br {bridge}"]
    settings = []
    if protocols:
        settings.append(f"protocols={protocols}")
    if fail_mode:
        settings.append(f"fail-mode={fail_mode}")
    if dpid is not None:
        settings.append(f"other-config:datapath-id={dpid_text(dpid)}")
    if settings:
        words.append(f"set bridge {bridge} " + " ".join(settings))
    if controller:
        words.append(f"set-controller {bridge} {controller}")
    for iface, ofport in ports:
        words.append(f"--may-exist add-port {bridge} {iface}")
        if ofport is not None:
            words.append(f"set interface {iface} ofport_request={int(ofport)}")
        if tags and iface in tags:
            words.append(f"set port {iface} tag={int(tags[iface])}")
    return "ovs-vsctl --timeout=5 " + " -- ".join(words)


def _config_words(prefix: str, config: Optional[Dict[str, Any]]) -> List[str]:
    """``other_config:key=value`` words of an ovs-vsctl ``set`` (keys sorted)."""
    return [f"{prefix}:{k}={v}" for k, v in sorted((config or {}).items())]


def ovs_bond_cmd(bridge: str, bond: str, ifaces: Sequence[str], *, bond_mode: Optional[str] = "balance-tcp",
                 lacp: Optional[str] = "active", lacp_time: Optional[str] = "fast",
                 other_config: Optional[Dict[str, Any]] = None) -> str:
    """One ``ovs-vsctl`` transaction adding the bond *bond* (the interfaces *ifaces*) to *bridge*,
    then setting its mode, its LACP and ``other_config`` (``lacp-time``, ``lacp-system-id``...).
    Applying it again changes nothing (``--may-exist``)."""
    settings = []
    if bond_mode:
        settings.append(f"bond_mode={bond_mode}")
    if lacp:
        settings.append(f"lacp={lacp}")
    config = dict(other_config or {})
    if lacp_time:
        config["lacp-time"] = lacp_time
    settings += _config_words("other_config", config)
    words = [f"--may-exist add-bond {bridge} {bond} " + " ".join(ifaces)]
    if settings:
        words.append(f"set port {bond} " + " ".join(settings))
    return "ovs-vsctl --timeout=5 " + " -- ".join(words)


def ovs_tunnel_cmd(bridge: str, port: str, tunnel_type: str, remote_ip, key: Optional[int] = None, *,
                   tag: Optional[int] = None, options: Optional[Dict[str, Any]] = None) -> str:
    """A tunnel port of *bridge* (``vxlan``, ``geneve``, ``gre``...) towards *remote_ip*, its key
    (the VNI of VXLAN / Geneve) and, for an access tunnel port, its VLAN *tag*."""
    opts = {"remote_ip": str(remote_ip).split("/")[0], **(options or {})}
    if key is not None:
        opts["key"] = int(key)
    words = [f"--may-exist add-port {bridge} {port}",
             f"set interface {port} type={tunnel_type} " + " ".join(_config_words("options", opts))]
    if tag is not None:
        words.append(f"set port {port} tag={int(tag)}")
    return "ovs-vsctl --timeout=5 " + " -- ".join(words)


def ovs_internal_port_cmd(bridge: str, port: str, *, tag: Optional[int] = None) -> str:
    """An internal port of *bridge* (an interface of the switch's own IP stack), in the access
    VLAN *tag*."""
    words = [f"--may-exist add-port {bridge} {port}", f"set interface {port} type=internal"]
    if tag is not None:
        words.append(f"set port {port} tag={int(tag)}")
    return "ovs-vsctl --timeout=5 " + " -- ".join(words)


def ovs_mirror_cmd(bridge: str, name: str, ports: Sequence[str], output_port: str) -> str:
    """A mirror of *bridge* copying everything the *ports* send and receive to *output_port* (it
    replaces the mirrors of the bridge: applying it again leaves one mirror)."""
    words = []
    for i, port in enumerate(ports):
        words.append(f"--id=@p{i} get port {port}")
    words.append(f"--id=@out get port {output_port}")
    selected = ",".join(f"@p{i}" for i in range(len(ports)))
    words.append(f"--id=@m create mirror name={name} select_src_port={selected} select_dst_port={selected} "
                 f"output_port=@out")
    words.append(f"set bridge {bridge} mirrors=@m")
    return "ovs-vsctl --timeout=5 -- " + " -- ".join(words)


def ovs_policing_cmd(iface: str, rate_kbps: int, burst_kb: int) -> str:
    """Police what *iface* receives (what its host sends): *rate_kbps* kbit/s, a bucket of
    *burst_kb* kbit."""
    return (f"ovs-vsctl --timeout=5 set interface {iface} ingress_policing_rate={int(rate_kbps)} "
            f"ingress_policing_burst={int(burst_kb)}")


def ovs_qos_cmd(port: str, max_rate_bps: int, queues: Dict[int, int], qos_type: str = "linux-htb") -> str:
    """An egress QoS of *port* (``linux-htb``: *max_rate_bps* bit/s) and its queues
    ``{queue number: max-rate in bit/s}``; the former QoS row of the port is left unreferenced."""
    queue_words = " ".join(f"queues:{int(n)}=@q{int(n)}" for n in sorted(queues))
    words = [f"set port {port} qos=@qos",
             f"--id=@qos create qos type={qos_type} other_config:max-rate={int(max_rate_bps)} {queue_words}".rstrip()]
    for n in sorted(queues):
        words.append(f"--id=@q{int(n)} create queue other_config:max-rate={int(queues[n])}")
    return "ovs-vsctl --timeout=5 -- " + " -- ".join(words)


def osken_start_cmd(apps: Sequence[str], log_file: str = OSKEN_LOG, pid_file: str = OSKEN_PID_FILE,
                    env: Optional[Dict[str, str]] = None, wait_port: Optional[int] = OPENFLOW_PORT) -> str:
    """(Re)start ``osken-manager`` with *apps* in the background, then wait until it listens on
    *wait_port* (the OpenFlow port by default)."""
    env_words = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in (env or {}).items())
    prefix = f"env {env_words} " if env_words else ""
    wait = ""
    if wait_port:
        wait = (f"; for i in $(seq 50); do ss -ltnH | grep -q ':{int(wait_port)} ' && break; sleep 0.2; done; "
                f"ss -ltnH | grep -q ':{int(wait_port)} '")
    return (f"[ -f {pid_file} ] && kill $(cat {pid_file}) 2>/dev/null; sleep 0.3; "
            f"setsid -f {prefix}osken-manager --log-file {log_file} --pid-file {pid_file} "
            f"{' '.join(apps)} >/dev/null 2>&1 < /dev/null{wait}")


def rest_cmd(controller, path: str, body: Optional[dict] = None, method: Optional[str] = None,
             port: int = REST_PORT) -> str:
    """A ``curl`` call of the REST API of ``ofctl_rest`` (``path`` without the ``/stats/``
    prefix, e.g. ``flowentry/add``), POST with a JSON *body*, GET without."""
    host = str(controller).split("/")[0]
    url = f"http://{host}:{int(port)}/stats/{path}"
    if body is None:
        verb = f" -X {method}" if method else ""
        return f"curl -s -m 5{verb} {url}"
    data = shlex.quote(json.dumps(body, separators=(", ", ": ")))
    return f"curl -s -m 5 -X {method or 'POST'} -d {data} {url}"


# ---------------------------------------------------------------------------
# grade side: ovs-vsctl
# ---------------------------------------------------------------------------


def _ovs_value(value) -> Any:
    """An OVSDB JSON value → Python: ``["uuid", u]`` → u, ``["set", [...]]`` → list,
    ``["map", [[k, v], ...]]`` → dict, a scalar as it is."""
    if isinstance(value, list) and len(value) == 2 and isinstance(value[0], str):
        tag, payload = value
        if tag in ("uuid", "named-uuid"):
            return payload
        if tag == "set":
            return [_ovs_value(v) for v in payload]
        if tag == "map":
            return {_ovs_value(k): _ovs_value(v) for k, v in payload}
    return value


def _optional(value) -> Any:
    """An optional OVSDB column: an empty set is None, a one-element set its element."""
    if isinstance(value, list):
        if not value:
            return None
        if len(value) == 1:
            return value[0]
    return value


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_ovs_table(text: str) -> List[Dict[str, Any]]:
    """``ovs-vsctl --format=json list <Table>`` → one dict per row (values decoded)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    headings = data.get("headings") or []
    rows = []
    for row in data.get("data") or []:
        rows.append({h: _ovs_value(v) for h, v in zip(headings, row)})
    return rows


@dataclass
class OvsInterface:
    name: str
    uuid: str = ""
    ofport: Optional[int] = None
    type: str = ""
    mac_in_use: str = ""
    link_state: str = ""
    admin_state: str = ""
    error: Optional[str] = None
    options: Dict[str, str] = field(default_factory=dict)  # remote_ip, key... of a tunnel
    ingress_policing_rate: int = 0  # kbit/s, 0: no policing
    ingress_policing_burst: int = 0  # kbit
    mtu: Optional[int] = None
    status: Dict[str, str] = field(default_factory=dict)


@dataclass
class OvsQueue:
    number: int
    uuid: str = ""
    other_config: Dict[str, str] = field(default_factory=dict)  # min-rate, max-rate (bit/s)...


@dataclass
class OvsQos:
    uuid: str = ""
    type: str = ""
    other_config: Dict[str, str] = field(default_factory=dict)  # max-rate (bit/s)...
    queues: Dict[int, OvsQueue] = field(default_factory=dict)


@dataclass
class OvsPort:
    name: str
    uuid: str = ""
    tag: Optional[int] = None
    trunks: List[int] = field(default_factory=list)
    vlan_mode: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)  # interface names
    bond_mode: Optional[str] = None
    lacp: Optional[str] = None
    other_config: Dict[str, str] = field(default_factory=dict)
    qos: Optional[OvsQos] = None  # only with the table QoS read (OVS_TABLES_FULL)


@dataclass
class OvsMirror:
    name: str
    uuid: str = ""
    select_all: bool = False
    select_src_ports: List[str] = field(default_factory=list)  # port names
    select_dst_ports: List[str] = field(default_factory=list)
    select_vlans: List[int] = field(default_factory=list)
    output_port: Optional[str] = None  # port name
    output_vlan: Optional[int] = None


@dataclass
class OvsController:
    target: str
    uuid: str = ""
    is_connected: bool = False
    role: Optional[str] = None


@dataclass
class OvsBridge:
    name: str
    uuid: str = ""
    datapath_id: str = ""  # 16 hexadecimal digits, as ovs-vsctl prints it
    datapath_type: str = ""
    fail_mode: Optional[str] = None
    protocols: List[str] = field(default_factory=list)
    other_config: Dict[str, str] = field(default_factory=dict)
    ports: Dict[str, OvsPort] = field(default_factory=dict)
    controllers: List[OvsController] = field(default_factory=list)
    mirrors: List[OvsMirror] = field(default_factory=list)  # only with the table Mirror read

    def port(self, name: str) -> Optional[OvsPort]:
        return self.ports.get(name)

    def port_names(self) -> List[str]:
        return [p for p in self.ports if p != self.name]

    def controller(self, target: Optional[str] = None) -> Optional[OvsController]:
        for c in self.controllers:
            if target is None or c.target == target:
                return c
        return None

    @property
    def dpid(self) -> Optional[int]:
        try:
            return int(self.datapath_id, 16)
        except (TypeError, ValueError):
            return None


@dataclass
class OvsState:
    running: bool = False
    bridges: Dict[str, OvsBridge] = field(default_factory=dict)
    interfaces: Dict[str, OvsInterface] = field(default_factory=dict)

    def bridge(self, name: Optional[str] = None) -> Optional[OvsBridge]:
        """The bridge *name*; without a name, the only bridge (None if there are several)."""
        if name is not None:
            return self.bridges.get(name)
        return next(iter(self.bridges.values())) if len(self.bridges) == 1 else None

    def bridge_of(self, iface: str) -> Optional[OvsBridge]:
        """The bridge one of whose ports holds the interface *iface*."""
        for b in self.bridges.values():
            for p in b.ports.values():
                if iface in p.interfaces:
                    return b
        return None

    def port_of(self, iface: str) -> Optional[OvsPort]:
        for b in self.bridges.values():
            for p in b.ports.values():
                if iface in p.interfaces:
                    return p
        return None

    def ofport(self, iface: str) -> Optional[int]:
        i = self.interfaces.get(iface)
        return i.ofport if i is not None else None

    def ports_of_type(self, iface_type: str) -> List[OvsPort]:
        """The ports holding an interface of type *iface_type* (``vxlan``, ``internal``...)."""
        return [p for b in self.bridges.values() for p in b.ports.values()
                if any(self.interfaces.get(i) is not None and self.interfaces[i].type == iface_type
                       for i in p.interfaces)]


#: the four tables read by default (the SDN lab); OVS_TABLES_FULL adds mirrors and QoS
OVS_TABLES = _OVS_TABLES
OVS_TABLES_FULL = _OVS_TABLES + ("Mirror", "QoS", "Queue")


def ovs_state_cmd(tables: Sequence[str] = _OVS_TABLES) -> str:
    parts = [f"ovs-vsctl --timeout=3 --format=json list {t}" for t in tables]
    return f"; echo {_SEP}; ".join(parts)


def _map(value) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_ovs_state(text: str, tables: Sequence[str] = _OVS_TABLES) -> OvsState:
    """The output of :func:`ovs_state_cmd` (same *tables*) → :class:`OvsState` (``running``
    False when ovs-vsctl could not reach ovsdb-server)."""
    chunks = (text or "").split(_SEP)
    if len(chunks) < len(tables):
        return OvsState()
    rows = dict(zip(tables, (parse_ovs_table(c.strip()) for c in chunks)))
    if not chunks[0].strip().startswith("{"):
        return OvsState()
    state = OvsState(running=True)
    queues_by_uuid = {}
    qos_by_uuid = {}
    for row in rows.get("Queue", []):
        queues_by_uuid[row.get("_uuid", "")] = _map(row.get("other_config"))
    for row in rows.get("QoS", []):
        qos = OvsQos(uuid=row.get("_uuid", ""), type=row.get("type") or "", other_config=_map(row.get("other_config")))
        for number, u in _map(row.get("queues")).items():
            if isinstance(number, int) and u in queues_by_uuid:
                qos.queues[number] = OvsQueue(number=number, uuid=u, other_config=queues_by_uuid[u])
        qos_by_uuid[qos.uuid] = qos
    ifaces_by_uuid = {}
    for row in rows.get("Interface", []):
        ofport = _optional(row.get("ofport"))
        mtu = _optional(row.get("mtu"))
        iface = OvsInterface(
            name=row.get("name", ""), uuid=row.get("_uuid", ""),
            ofport=ofport if isinstance(ofport, int) and ofport >= 0 else None,
            type=row.get("type") or "", mac_in_use=_optional(row.get("mac_in_use")) or "",
            link_state=_optional(row.get("link_state")) or "", admin_state=_optional(row.get("admin_state")) or "",
            error=_optional(row.get("error")), options=_map(row.get("options")),
            ingress_policing_rate=row.get("ingress_policing_rate") if isinstance(row.get("ingress_policing_rate"), int) else 0,
            ingress_policing_burst=row.get("ingress_policing_burst") if isinstance(row.get("ingress_policing_burst"), int) else 0,
            mtu=mtu if isinstance(mtu, int) else None, status=_map(row.get("status")))
        ifaces_by_uuid[iface.uuid] = iface
        state.interfaces[iface.name] = iface
    ports_by_uuid = {}
    for row in rows.get("Port", []):
        tag = _optional(row.get("tag"))
        port = OvsPort(name=row.get("name", ""), uuid=row.get("_uuid", ""),
                       tag=tag if isinstance(tag, int) else None,
                       trunks=[t for t in _as_list(row.get("trunks")) if isinstance(t, int)],
                       vlan_mode=_optional(row.get("vlan_mode")),
                       interfaces=[ifaces_by_uuid[u].name for u in _as_list(row.get("interfaces"))
                                   if u in ifaces_by_uuid],
                       bond_mode=_optional(row.get("bond_mode")), lacp=_optional(row.get("lacp")),
                       other_config=_map(row.get("other_config")),
                       qos=qos_by_uuid.get(_optional(row.get("qos"))))
        ports_by_uuid[port.uuid] = port
    mirrors_by_uuid = {}
    for row in rows.get("Mirror", []):
        out_vlan = _optional(row.get("output_vlan"))
        mirror = OvsMirror(
            name=row.get("name", ""), uuid=row.get("_uuid", ""), select_all=bool(row.get("select_all")),
            select_src_ports=[ports_by_uuid[u].name for u in _as_list(row.get("select_src_port")) if u in ports_by_uuid],
            select_dst_ports=[ports_by_uuid[u].name for u in _as_list(row.get("select_dst_port")) if u in ports_by_uuid],
            select_vlans=[v for v in _as_list(row.get("select_vlan")) if isinstance(v, int)],
            output_port=(ports_by_uuid[_optional(row.get("output_port"))].name
                         if _optional(row.get("output_port")) in ports_by_uuid else None),
            output_vlan=out_vlan if isinstance(out_vlan, int) else None)
        mirrors_by_uuid[mirror.uuid] = mirror
    controllers_by_uuid = {}
    for row in rows.get("Controller", []):
        c = OvsController(target=row.get("target", ""), uuid=row.get("_uuid", ""),
                          is_connected=bool(row.get("is_connected")), role=_optional(row.get("role")))
        controllers_by_uuid[c.uuid] = c
    for row in rows.get("Bridge", []):
        b = OvsBridge(name=row.get("name", ""), uuid=row.get("_uuid", ""),
                      datapath_id=_optional(row.get("datapath_id")) or "",
                      datapath_type=row.get("datapath_type") or "",
                      fail_mode=_optional(row.get("fail_mode")),
                      protocols=[str(p) for p in _as_list(row.get("protocols"))],
                      other_config=_map(row.get("other_config")))
        for u in _as_list(row.get("ports")):
            if u in ports_by_uuid:
                p = ports_by_uuid[u]
                b.ports[p.name] = p
        b.controllers = [controllers_by_uuid[u] for u in _as_list(row.get("controller")) if u in controllers_by_uuid]
        b.mirrors = [mirrors_by_uuid[u] for u in _as_list(row.get("mirrors")) if u in mirrors_by_uuid]
        state.bridges[b.name] = b
    return state


def get_ovs_state(grade: Grade0, machine: str, step: int = 1, tables: Sequence[str] = _OVS_TABLES) -> OvsState:
    out, _ = grade.test(machine, ovs_state_cmd(tables), step=step, timeout=20, allow_error=True)
    return parse_ovs_state(out, tables)


# ---------------------------------------------------------------------------
# grade side: flows, traces, meters, ports
# ---------------------------------------------------------------------------


def _split_top(text: str, sep: str = ",") -> List[str]:
    """Split on *sep* outside parentheses (``ct(commit,zone=1),output:2``)."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _int(text, default=None):
    try:
        return int(str(text), 0)
    except (TypeError, ValueError):
        try:
            return int(float(str(text).rstrip("s")))
        except (TypeError, ValueError):
            return default


@dataclass
class Flow:
    table: int = 0
    priority: int = DEFAULT_PRIORITY
    cookie: int = 0
    match: Dict[str, Optional[str]] = field(default_factory=dict)  # as printed: key -> value (None: shortcut)
    actions: List[str] = field(default_factory=list)
    n_packets: int = 0
    n_bytes: int = 0
    idle_timeout: int = 0
    hard_timeout: int = 0
    text: str = ""

    def fields(self) -> Dict[str, Any]:
        """The match with the shortcuts expanded and the OpenFlow 1.3 names (``nw_dst`` → ``ipv4_dst``)."""
        result: Dict[str, Any] = {}
        for key, value in self.match.items():
            if value is None and key in PROTOCOL_SHORTCUTS:
                result.update(PROTOCOL_SHORTCUTS[key])
            else:
                result[FIELD_ALIASES.get(key, key)] = value
        return result

    @property
    def is_table_miss(self) -> bool:
        return self.priority == 0 and not self.match

    def outputs(self) -> List[str]:
        """The output targets of the actions: ``output:3`` → '3', ``NORMAL``, ``CONTROLLER``,
        ``FLOOD``, ``ALL``, ``IN_PORT``, ``LOCAL``; a bare number (OpenFlow 1.0 style) too."""
        result = []
        for a in self.actions:
            word = a.split(":", 1)
            head = word[0]
            if head == "output" and len(word) == 2:
                result.append(word[1].split("(")[0])
            elif head.upper() in ("NORMAL", "CONTROLLER", "FLOOD", "ALL", "IN_PORT", "LOCAL"):
                result.append(head.upper())
            elif head.isdigit():
                result.append(head)
        return result

    @property
    def drops(self) -> bool:
        return not self.actions or self.actions == ["drop"]

    def meter_ids(self) -> List[int]:
        return [i for i in (_int(a.split(":", 1)[1]) for a in self.actions if a.startswith("meter:")) if i is not None]


def parse_flow_line(line: str) -> Optional[Flow]:
    text = line.strip()
    if not text or text.startswith(("OFPST_", "NXST_", "OFPT_")) or "actions=" not in text:
        return None
    left, _, actions = text.partition(" actions=")
    if not _:
        if text.startswith("actions="):
            left, actions = "", text[len("actions="):]
        else:
            return None
    flow = Flow(text=text)
    flow.actions = [a for a in _split_top(actions.strip()) if a]
    # the statistics fields are separated by ", " and come first; the match is the last group
    for item in _split_top(left.replace(", ", ",")):
        key, eq, value = item.partition("=")
        key = key.strip()
        if not key:
            continue
        if key in _STATS_KEYS:
            if key == "table":
                flow.table = _int(value, 0)
            elif key == "cookie":
                flow.cookie = _int(value, 0)
            elif key == "n_packets":
                flow.n_packets = _int(value, 0)
            elif key == "n_bytes":
                flow.n_bytes = _int(value, 0)
            elif key == "idle_timeout":
                flow.idle_timeout = _int(value, 0)
            elif key == "hard_timeout":
                flow.hard_timeout = _int(value, 0)
            continue
        if key == "priority":
            flow.priority = _int(value, DEFAULT_PRIORITY)
            continue
        flow.match[key] = value.strip() if eq else None
    return flow


def parse_flows(text: str) -> List[Flow]:
    """``ovs-ofctl -O OpenFlow13 dump-flows <br>`` → the flow entries (statistics included)."""
    return [f for f in (parse_flow_line(line) for line in (text or "").splitlines()) if f is not None]


def flows_cmd(bridge: str = "br0") -> str:
    return f"ovs-ofctl -O OpenFlow13 --no-names dump-flows {bridge}"


def get_flows(grade: Grade0, machine: str, bridge: str = "br0", step: int = 1) -> List[Flow]:
    out, _ = grade.test(machine, flows_cmd(bridge), step=step, timeout=15, allow_error=True)
    return parse_flows(out)


def table_miss(flows: Sequence[Flow], table: int = 0) -> Optional[Flow]:
    return next((f for f in flows if f.table == table and f.is_table_miss), None)


@dataclass
class Trace:
    datapath_actions: Optional[str] = None  # the last "Datapath actions:" line, None if absent
    text: str = ""

    @property
    def dropped(self) -> bool:
        return self.datapath_actions is not None and self.datapath_actions.strip() == "drop"

    @property
    def forwarded(self) -> bool:
        return self.datapath_actions is not None and self.datapath_actions.strip() != "drop"


def parse_trace(text: str) -> Trace:
    """``ovs-appctl ofproto/trace`` → its verdict (the last ``Datapath actions:`` line: ``drop``,
    or the datapath ports and actions)."""
    actions = None
    for line in (text or "").splitlines():
        if line.startswith("Datapath actions:"):
            actions = line.split(":", 1)[1].strip()
    return Trace(datapath_actions=actions, text=text or "")


def trace_flow(*, in_port, proto: str, eth_src, eth_dst, ip_src=None, ip_dst=None, dport=None,
               vlan: Optional[int] = None, sport: int = 40000, tcp_flags: Optional[int] = None) -> str:
    """The flow description of an ``ofproto/trace`` (``in_port`` an OpenFlow port number).

    *tcp_flags*: the exact flags of a TCP segment (``0x002`` SYN, ``0x012`` SYN+ACK): a trace
    refuses the ``+syn+ack`` form of a match: wildcards not allowed here."""
    words = [f"in_port={in_port}"]
    if vlan is not None:
        words.append(f"dl_vlan={int(vlan)}")
    words += [f"dl_src={eth_src}", f"dl_dst={eth_dst}"]
    if proto == "arp":
        words.insert(1, "arp")
        if ip_src:
            words.append(f"arp_spa={ip_src}")
        if ip_dst:
            words.append(f"arp_tpa={ip_dst}")
        words.append("arp_op=1")
        return ",".join(words)
    words.insert(1, proto)
    if ip_src:
        words.append(f"nw_src={ip_src}")
    if ip_dst:
        words.append(f"nw_dst={ip_dst}")
    if proto in ("tcp", "udp") and dport is not None:
        # ofproto/trace of OVS 3.5 refuses tp_src / tp_dst after udp ("prerequisites not met"),
        # although add-flow takes them: the protocol's own field names work for both
        words.append(f"{proto}_src={int(sport)},{proto}_dst={int(dport)}")
    if proto == "tcp" and tcp_flags is not None:
        words.append(f"tcp_flags=0x{int(tcp_flags):03x}")
    if proto == "icmp":
        words.append("icmp_type=8,icmp_code=0")
    return ",".join(words)


def trace_cmd(bridge: str, flow: str, ct_next: Optional[Sequence[str]] = None) -> str:
    """``ovs-appctl ofproto/trace``; *ct_next*: the connection-tracking state given to the packet at
    each recirculation after a ``ct()`` action (``['trk,new']``), in order."""
    extra = "".join(f" --ct-next {shlex.quote(s)}" for s in (ct_next or ()))
    return f"ovs-appctl ofproto/trace {bridge} {shlex.quote(flow)}{extra}"


def get_trace(grade: Grade0, machine: str, bridge: str, flow: str, step: int = 1,
              ct_next: Optional[Sequence[str]] = None) -> Trace:
    out, _ = grade.test(machine, trace_cmd(bridge, flow, ct_next), step=step, timeout=15, allow_error=True)
    return parse_trace(out)


@dataclass
class Meter:
    meter_id: int
    flags: List[str] = field(default_factory=list)  # 'kbps', 'pktps', 'burst', 'stats'
    bands: List[Dict[str, Any]] = field(default_factory=list)  # {'type': 'drop', 'rate': 2000, ...}


def parse_meters(text: str) -> Dict[int, Meter]:
    """``ovs-ofctl -O OpenFlow13 dump-meters <br>`` → ``{meter_id: Meter}``."""
    meters: Dict[int, Meter] = {}
    current = None
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.match(r"meter=(\d+)\s*(.*?)\s*bands=(.*)$", line)
        if m:
            current = Meter(meter_id=int(m.group(1)), flags=m.group(2).split())
            meters[current.meter_id] = current
            rest = m.group(3).strip()
            if rest:
                line = rest
            else:
                continue
        if current is not None and line.startswith("type="):
            band: Dict[str, Any] = {}
            for word in line.split():
                k, _, v = word.partition("=")
                band[k] = _int(v, v) if k != "type" else v
            current.bands.append(band)
    return meters


def get_meters(grade: Grade0, machine: str, bridge: str = "br0", step: int = 1) -> Dict[int, Meter]:
    out, _ = grade.test(machine, f"ovs-ofctl -O OpenFlow13 dump-meters {bridge}", step=step, timeout=15,
                        allow_error=True)
    return parse_meters(out)


def parse_ofctl_show(text: str) -> Dict[str, Any]:
    """``ovs-ofctl -O OpenFlow13 show <br>`` → ``{'dpid': '00000000000000a1' or None,
    'ports': {name: number}}`` (``LOCAL`` for the bridge's own port)."""
    result: Dict[str, Any] = {"dpid": None, "ports": {}}
    for line in (text or "").splitlines():
        m = re.search(r"dpid:([0-9a-fA-F]{16})", line)
        if m:
            result["dpid"] = m.group(1).lower()
        m = re.match(r"\s*(\d+|LOCAL)\(([^)]+)\):\s*addr:", line)
        if m:
            result["ports"][m.group(2)] = m.group(1) if m.group(1) == "LOCAL" else int(m.group(1))
    return result


# ---------------------------------------------------------------------------
# grade side: bonds, LACP, connection tracking, captures
# ---------------------------------------------------------------------------


def _sections(text: str) -> Dict[str, List[str]]:
    """The ``---- name ----`` sections of ``bond/show`` / ``lacp/show`` → their lines."""
    sections: Dict[str, List[str]] = {}
    current = None
    for line in (text or "").splitlines():
        m = re.match(r"^---- (\S+) ----$", line.strip())
        if m:
            current = sections.setdefault(m.group(1), [])
        elif current is not None:
            current.append(line)
    return sections


@dataclass
class BondMember:
    name: str
    enabled: bool = False
    may_enable: bool = False
    active: bool = False


@dataclass
class BondStatus:
    name: str
    bond_mode: str = ""
    lacp_status: str = ""  # negotiated, configured, off
    members: Dict[str, BondMember] = field(default_factory=dict)

    def enabled_members(self) -> List[str]:
        return [m.name for m in self.members.values() if m.enabled]


def parse_bond_show(text: str) -> Dict[str, BondStatus]:
    """``ovs-appctl bond/show [bond]`` → ``{bond: BondStatus}`` (OVS 3.x: ``member eth0: enabled``)."""
    result = {}
    for name, lines in _sections(text).items():
        bond = BondStatus(name=name)
        member = None
        for line in lines:
            stripped = line.strip()
            m = re.match(r"^(?:member|slave) (\S+): (\S+)$", stripped)
            if m:
                member = BondMember(name=m.group(1), enabled=m.group(2) == "enabled")
                bond.members[member.name] = member
                continue
            key, _, value = stripped.partition(":")
            value = value.strip()
            if member is None:
                if key == "bond_mode":
                    bond.bond_mode = value
                elif key == "lacp_status":
                    bond.lacp_status = value
            elif key == "may_enable":
                member.may_enable = value == "true"
            elif stripped in ("active member", "active slave"):
                member.active = True
        result[name] = bond
    return result


def get_bond_show(grade: Grade0, machine: str, bond: Optional[str] = None, step: int = 1) -> Dict[str, BondStatus]:
    command = "ovs-appctl bond/show" + (f" {bond}" if bond else "")
    out, _ = grade.test(machine, command, step=step, timeout=15, allow_error=True)
    return parse_bond_show(out)


@dataclass
class LacpMember:
    name: str
    states: List[str] = field(default_factory=list)  # current / expired / defaulted, attached / detached
    may_enable: bool = False
    actor_state: List[str] = field(default_factory=list)
    partner_sys_id: str = ""
    partner_state: List[str] = field(default_factory=list)

    @property
    def aggregated(self) -> bool:
        """Current, attached, and both ends collecting and distributing."""
        wanted = {"synchronized", "collecting", "distributing"}
        return ("current" in self.states and "attached" in self.states
                and wanted <= set(self.actor_state) and wanted <= set(self.partner_state))


@dataclass
class LacpStatus:
    name: str
    status: List[str] = field(default_factory=list)  # active / passive, negotiated
    sys_id: str = ""
    sys_priority: Optional[int] = None
    lacp_time: str = ""
    members: Dict[str, LacpMember] = field(default_factory=dict)

    @property
    def negotiated(self) -> bool:
        return "negotiated" in self.status

    def partner_sys_ids(self) -> List[str]:
        return sorted({m.partner_sys_id for m in self.members.values() if m.partner_sys_id})


def parse_lacp_show(text: str) -> Dict[str, LacpStatus]:
    """``ovs-appctl lacp/show [bond]`` → ``{bond: LacpStatus}`` (OVS 3.x: ``member: eth0: current attached``)."""
    result = {}
    for name, lines in _sections(text).items():
        lacp = LacpStatus(name=name)
        member = None
        for line in lines:
            stripped = line.strip()
            m = re.match(r"^(?:member|slave): (\S+):\s*(.*)$", stripped)
            if m:
                member = LacpMember(name=m.group(1), states=m.group(2).split())
                lacp.members[member.name] = member
                continue
            key, _, value = stripped.partition(":")
            value = value.strip()
            if member is None:
                if key == "status":
                    lacp.status = value.split()
                elif key == "sys_id":
                    lacp.sys_id = value.lower()
                elif key == "sys_priority":
                    lacp.sys_priority = _int(value)
                elif key == "lacp_time":
                    lacp.lacp_time = value
            elif key == "may_enable":
                member.may_enable = value == "true"
            elif key == "actor state":
                member.actor_state = value.split()
            elif key == "partner sys_id":
                member.partner_sys_id = value.lower()
            elif key == "partner state":
                member.partner_state = value.split()
        result[name] = lacp
    return result


def get_lacp_show(grade: Grade0, machine: str, bond: Optional[str] = None, step: int = 1) -> Dict[str, LacpStatus]:
    command = "ovs-appctl lacp/show" + (f" {bond}" if bond else "")
    out, _ = grade.test(machine, command, step=step, timeout=15, allow_error=True)
    return parse_lacp_show(out)


@dataclass
class ConnEntry:
    proto: str
    orig: Dict[str, str] = field(default_factory=dict)  # src, dst, sport, dport (id, type, code for icmp)
    reply: Dict[str, str] = field(default_factory=dict)
    state: str = ""  # TCP state (protoinfo)
    zone: int = 0
    text: str = ""

    def matches(self, src=None, dst=None, dport=None, sport=None) -> bool:
        """The original direction goes from *src* (port *sport*) to *dst* (port *dport*)."""
        return ((src is None or self.orig.get("src") == str(src))
                and (dst is None or self.orig.get("dst") == str(dst))
                and (dport is None or self.orig.get("dport") == str(dport))
                and (sport is None or self.orig.get("sport") == str(sport)))


def _paren_fields(text: str) -> Dict[str, str]:
    return {k: v for k, _, v in (item.partition("=") for item in text.split(",") if item)}


def parse_conntrack(text: str) -> List[ConnEntry]:
    """``ovs-appctl dpctl/dump-conntrack`` → one entry per connection, e.g.
    ``tcp,orig=(src=A,dst=B,sport=40000,dport=80),reply=(...),protoinfo=(state=TIME_WAIT)``."""
    entries = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "orig=(" not in line:
            continue
        items = _split_top(line)
        entry = ConnEntry(proto=items[0], text=line)
        for item in items[1:]:
            key, _, value = item.partition("=")
            if value.startswith("(") and value.endswith(")"):
                fields = _paren_fields(value[1:-1])
                if key == "orig":
                    entry.orig = fields
                elif key == "reply":
                    entry.reply = fields
                elif key == "protoinfo":
                    entry.state = fields.get("state", "")
            elif key == "zone":
                entry.zone = _int(value, 0)
        entries.append(entry)
    return entries


def get_conntrack(grade: Grade0, machine: str, step: int = 1) -> List[ConnEntry]:
    out, _ = grade.test(machine, "ovs-appctl dpctl/dump-conntrack", step=step, timeout=15, allow_error=True)
    return parse_conntrack(out)


CAPTURE_DIR = "/tmp"


def capture_start_cmd(name: str, iface: str = "eth0", bpf: str = "", seconds: int = 30) -> str:
    """Start a background ``tcpdump`` writing ``/tmp/sre-<name>.pcap`` (packet-buffered) for at
    most *seconds*; its pid goes to ``/tmp/sre-<name>.pid``.  Read it in a later step with
    :func:`capture_read_cmd` (the steps of an evaluation run one after the other)."""
    base = f"{CAPTURE_DIR}/sre-{name}"
    inner = f"echo $$ > {base}.pid; exec timeout {int(seconds)} tcpdump -n -U -i {iface} -w {base}.pcap {bpf}".rstrip()
    return (f"rm -f {base}.pcap {base}.pid; setsid -f sh -c {shlex.quote(inner)} >/dev/null 2>&1 </dev/null; "
            f"sleep 1; test -s {base}.pid")


def capture_read_cmd(name: str, bpf: str = "") -> str:
    """Stop the capture of :func:`capture_start_cmd` and print it (``tcpdump -n -r``)."""
    base = f"{CAPTURE_DIR}/sre-{name}"
    return (f"sleep 0.5; [ -f {base}.pid ] && kill $(cat {base}.pid) 2>/dev/null; sleep 0.3; "
            f"tcpdump -n -r {base}.pcap {bpf} 2>/dev/null".rstrip())


def count_icmp_echo(text: str, src=None, dst=None) -> int:
    """The ICMP echo requests / replies of a ``tcpdump -n`` output (between *src* and *dst*,
    either way, when given)."""
    count = 0
    for line in (text or "").splitlines():
        m = re.search(r"IP (\S+) > (\S+): ICMP echo (?:request|reply)", line)
        if not m:
            continue
        ends = {m.group(1), m.group(2).rstrip(":")}
        if src is not None and dst is not None and ends != {str(src), str(dst)}:
            continue
        count += 1
    return count


# ---------------------------------------------------------------------------
# answers
# ---------------------------------------------------------------------------


def normalize_dpid(answer) -> Optional[int]:
    """A datapath ID typed by a student: ``00000000000000a1``, ``0xa1``, ``a1``, ``00:00:...:a1``
    (hexadecimal) → an int; None if it is not hexadecimal.  A decimal form is not accepted here
    (``161`` would be read as hexadecimal 0x161): see :func:`normalize_decimal_dpid`."""
    text = str(answer or "").strip().lower().replace(":", "").replace(" ", "")
    if text.startswith("dpid"):
        text = text[4:].lstrip("=:")
    if text.startswith("0x"):
        text = text[2:]
    if not text or len(text) > 16 or not re.fullmatch(r"[0-9a-f]+", text):
        return None
    return int(text, 16)


def normalize_decimal_dpid(answer) -> Optional[int]:
    """A datapath ID written in decimal (what the REST API of ofctl_rest takes) → an int."""
    text = str(answer or "").strip().replace(" ", "")
    return int(text) if text.isdigit() else None
