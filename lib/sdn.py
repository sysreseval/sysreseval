"""Open vSwitch / OpenFlow helpers of the SDN lab (``lab/sre/_DRAFT_misc/sdn.py``).

The switches and controllers run the image ``sysreseval/sdn`` (``images/sdn/Dockerfile``): Debian
13's Open vSwitch 3.5 (kernel datapath: the module ``openvswitch`` of the host, loaded by the
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


@dataclass
class OvsPort:
    name: str
    uuid: str = ""
    tag: Optional[int] = None
    trunks: List[int] = field(default_factory=list)
    vlan_mode: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)  # interface names


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


def ovs_state_cmd() -> str:
    parts = [f"ovs-vsctl --timeout=3 --format=json list {t}" for t in _OVS_TABLES]
    return f"; echo {_SEP}; ".join(parts)


def parse_ovs_state(text: str) -> OvsState:
    """The output of :func:`ovs_state_cmd` → :class:`OvsState` (``running`` False when
    ovs-vsctl could not reach ovsdb-server)."""
    chunks = (text or "").split(_SEP)
    if len(chunks) < len(_OVS_TABLES):
        return OvsState()
    tables = dict(zip(_OVS_TABLES, (parse_ovs_table(c.strip()) for c in chunks)))
    if not chunks[0].strip().startswith("{"):
        return OvsState()
    state = OvsState(running=True)
    ifaces_by_uuid = {}
    for row in tables["Interface"]:
        ofport = _optional(row.get("ofport"))
        iface = OvsInterface(
            name=row.get("name", ""), uuid=row.get("_uuid", ""),
            ofport=ofport if isinstance(ofport, int) and ofport >= 0 else None,
            type=row.get("type") or "", mac_in_use=_optional(row.get("mac_in_use")) or "",
            link_state=_optional(row.get("link_state")) or "", admin_state=_optional(row.get("admin_state")) or "",
            error=_optional(row.get("error")))
        ifaces_by_uuid[iface.uuid] = iface
        state.interfaces[iface.name] = iface
    ports_by_uuid = {}
    for row in tables["Port"]:
        tag = _optional(row.get("tag"))
        port = OvsPort(name=row.get("name", ""), uuid=row.get("_uuid", ""),
                       tag=tag if isinstance(tag, int) else None,
                       trunks=[t for t in _as_list(row.get("trunks")) if isinstance(t, int)],
                       vlan_mode=_optional(row.get("vlan_mode")),
                       interfaces=[ifaces_by_uuid[u].name for u in _as_list(row.get("interfaces"))
                                   if u in ifaces_by_uuid])
        ports_by_uuid[port.uuid] = port
    controllers_by_uuid = {}
    for row in tables["Controller"]:
        c = OvsController(target=row.get("target", ""), uuid=row.get("_uuid", ""),
                          is_connected=bool(row.get("is_connected")), role=_optional(row.get("role")))
        controllers_by_uuid[c.uuid] = c
    for row in tables["Bridge"]:
        b = OvsBridge(name=row.get("name", ""), uuid=row.get("_uuid", ""),
                      datapath_id=_optional(row.get("datapath_id")) or "",
                      datapath_type=row.get("datapath_type") or "",
                      fail_mode=_optional(row.get("fail_mode")),
                      protocols=[str(p) for p in _as_list(row.get("protocols"))],
                      other_config=row.get("other_config") if isinstance(row.get("other_config"), dict) else {})
        for u in _as_list(row.get("ports")):
            if u in ports_by_uuid:
                p = ports_by_uuid[u]
                b.ports[p.name] = p
        b.controllers = [controllers_by_uuid[u] for u in _as_list(row.get("controller")) if u in controllers_by_uuid]
        state.bridges[b.name] = b
    return state


def get_ovs_state(grade: Grade0, machine: str, step: int = 1) -> OvsState:
    out, _ = grade.test(machine, ovs_state_cmd(), step=step, timeout=20, allow_error=True)
    return parse_ovs_state(out)


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
               vlan: Optional[int] = None) -> str:
    """The flow description of an ``ofproto/trace`` (``in_port`` an OpenFlow port number)."""
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
        words.append(f"{proto}_src=40000,{proto}_dst={int(dport)}")
    if proto == "icmp":
        words.append("icmp_type=8,icmp_code=0")
    return ",".join(words)


def trace_cmd(bridge: str, flow: str) -> str:
    return f"ovs-appctl ofproto/trace {bridge} {shlex.quote(flow)}"


def get_trace(grade: Grade0, machine: str, bridge: str, flow: str, step: int = 1) -> Trace:
    out, _ = grade.test(machine, trace_cmd(bridge, flow), step=step, timeout=15, allow_error=True)
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
