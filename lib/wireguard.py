"""WireGuard grading helpers.

Pure parsers of what a WireGuard lab leaves behind (``wg show all dump``, ``wg showconf``,
``/etc/wireguard/*.conf`` files, ``ip -j rule``, ``ip -j route``) and thin ``(grade, machine,
step)`` wrappers around one command each, in the style of ``lib/openvpn.py``, plus the key
arithmetic (Curve25519 in pure Python) that lets a lab generate key pairs in ``Data.generate()``
and check that a configuration file matches a running interface.  Fixtures captured on
wireguard-tools 1.0.20210914 / Linux 6.12 (Debian 12 images 1.30) live in
``tests/mock_data/wireguard/``.

Every wrapper registers its command unconditionally (two-pass contract of ``Grade0.grade()``)
and returns an empty value until the command has run.

Facts verified in Kathara containers (2026-10-06):

- ``ip link add wg0 type wireguard`` autoloads the host module from a plain NET_ADMIN
  container; ``wg-quick up`` works there too **except** with a default route in
  ``AllowedIPs``: it then runs ``sysctl net.ipv4.conf.all.src_valid_mark=1``, refused on the
  read-only ``/proc/sys`` of a non-privileged container (the interface is torn down).  A full
  tunnel needs a privileged machine.
- ``wg show all dump``: one interface line (``ifname private public port fwmark``) then one
  line per peer (``ifname pubkey psk endpoint allowed-ips latest-handshake rx tx keepalive``),
  ``(none)`` for a missing psk/endpoint, ``off`` for no fwmark/keepalive, handshake ``0`` when
  none yet.  The kernel socket of a listening interface shows in ``ss -ulnH`` without any
  process name.
- A ping to an address no peer allows fails with ``ping: sendmsg: Required key not
  available``; to a peer without endpoint with ``Destination address required``.
- Changing a preshared key does not break the current session: it bites at the next
  handshake (≤ 2 min).  Removing a peer cuts it immediately.
- wg-quick with ``AllowedIPs = 0.0.0.0/0``: ``wg set wg0 fwmark 51820``, ``ip route add
  0.0.0.0/0 dev wg0 table 51820``, ``ip rule add not fwmark 51820 table 51820``, ``ip rule add
  table main suppress_prefixlength 0`` and an nft table ``wg-quick-wg0``; ``ip route get X``
  then answers ``dev wg0 table 51820``.
- ``systemctl start wg-quick@wg0`` while ``wg0`` exists (manual ``wg-quick up``) leaves the
  unit *failed* and the tunnel up; ``wg-quick up`` of a running interface says
  ```wg0' already exists``.  ``wg syncconf wg0 <(wg-quick strip wg0)`` applies a changed
  file without cutting the tunnel.
- tcpdump 4.99 prints WireGuard datagrams as plain ``UDP, length N`` (an 84-byte ping gives
  128: padding to a multiple of 16 plus the 32-byte header).
"""
from __future__ import annotations

import base64
import json
import os
import re
import shlex
from ipaddress import IPv4Interface, IPv4Network, ip_network
from typing import Dict, List, Optional

from SRE.lib_sre import Grade0
# tcpdump and file helpers shared with the OpenVPN lab
from openvpn import (  # noqa: F401  (re-exported for the labs)
    Frame, file_mode, file_sha256, frames_matching, get_ip_addresses_json, interface_of_address,
    parse_ip_addr_json, parse_ss_listeners, parse_tcpdump, tcpdump_capture_cmd, tcpdump_read_cmd,
)

#: default port of a WireGuard interface (and the routing table / fwmark used by wg-quick)
WG_PORT = 51820
WG_DIR = "/etc/wireguard"
#: a session is used for at most 180 s: with traffic, a new handshake every 120 s
REKEY_AFTER_TIME = 120
REJECT_AFTER_TIME = 180
#: `ping` errors of the cryptokey routing
NO_PEER_ERROR = "Required key not available"
NO_ENDPOINT_ERROR = "Destination address required"


# ---------------------------------------------------------------------------
# Keys: Curve25519 (RFC 7748) in pure Python
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_A24 = 121665


def _clamp(raw: bytes) -> bytearray:
    b = bytearray(raw)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return b


def _x25519(k: int, u: int) -> int:
    """Montgomery ladder of RFC 7748 (constant time is not a concern here)."""
    x1 = u
    x2, z2, x3, z3 = 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2 * pow(z2, _P - 2, _P) % _P


def decode_key(text: str) -> Optional[bytes]:
    """The 32 bytes of a base64 WireGuard key (``None`` when *text* is not one)."""
    try:
        raw = base64.b64decode((text or "").strip(), validate=True)
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == 32 else None


def is_wg_key(text: str) -> bool:
    """True for the base64 of 32 bytes (private, public or preshared key)."""
    return decode_key(text) is not None


def generate_private_key() -> str:
    """A new private key (base64), clamped like ``wg genkey``."""
    return base64.b64encode(bytes(_clamp(os.urandom(32)))).decode()


def generate_preshared_key() -> str:
    """A new preshared key (base64 of 32 random bytes), like ``wg genpsk``."""
    return base64.b64encode(os.urandom(32)).decode()


def public_key(private_b64: str) -> str:
    """The public key of a private key, as ``wg pubkey`` prints it (``''`` for a bad key).

    The private key is clamped first, as the kernel and ``wg pubkey`` do, so an unclamped key
    gives the same public key as the one ``wg`` derives."""
    raw = decode_key(private_b64)
    if raw is None:
        return ""
    k = int.from_bytes(bytes(_clamp(raw)), "little")
    return base64.b64encode(_x25519(k, 9).to_bytes(32, "little")).decode()


# ---------------------------------------------------------------------------
# Configuration files (wg-quick / wg setconf syntax)
# ---------------------------------------------------------------------------


def parse_wg_config(text: str) -> dict:
    """Parse an INI-like WireGuard configuration (``wg-quick``, ``wg setconf``, ``wg showconf``).

    Returns ``{'interface': {key: [values]}, 'peers': [{key: [values]}, ...]}`` with the keys
    lower-cased (``privatekey``, ``allowedips``, ``postup``...), one entry per line, the value
    stripped (``#`` comments removed).  Text before any section header is ignored, an unknown
    section too.  Use config_list() for the comma-separated values (``AllowedIPs``, ``Address``).
    """
    conf: dict = {"interface": {}, "peers": []}
    section: Optional[dict] = None
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^\[\s*([A-Za-z]+)\s*\]$", line)
        if m:
            name = m.group(1).lower()
            if name == "interface":
                section = conf["interface"]
            elif name == "peer":
                section = {}
                conf["peers"].append(section)
            else:
                section = None
            continue
        if section is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        section.setdefault(key.strip().lower(), []).append(value.strip())
    return conf


def config_value(section: dict, key: str) -> Optional[str]:
    """The first value of *key* in a section of parse_wg_config() (``None`` when absent)."""
    values = (section or {}).get(key.lower())
    return values[0] if values else None


def config_list(section: dict, key: str) -> List[str]:
    """Every value of *key*, the comma-separated ones split (``AllowedIPs = a/32, b/24``)."""
    result = []
    for value in (section or {}).get(key.lower(), []):
        result.extend(v.strip() for v in value.split(",") if v.strip())
    return result


def config_peer(conf: dict, pubkey: str) -> Optional[dict]:
    """The ``[Peer]`` section whose ``PublicKey`` is *pubkey* (``None`` when absent)."""
    for peer in conf.get("peers", []):
        if config_value(peer, "publickey") == (pubkey or "").strip():
            return peer
    return None


def config_networks(section: dict, key: str = "allowedips") -> List[IPv4Network]:
    """The IPv4 prefixes of *key* (``AllowedIPs`` by default), malformed ones skipped."""
    nets = []
    for text in config_list(section, key):
        try:
            net = ip_network(text, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    return nets


def get_wg_config(grade: Grade0, machine_name: str, path: str = f"{WG_DIR}/wg0.conf", step: int = 1) -> dict:
    """Read and parse the configuration file *path* (empty structure when missing)."""
    text, code = grade.test(machine_name, f"cat {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return parse_wg_config(text if code == 0 else "")


def get_file(grade: Grade0, machine_name: str, path: str, step: int = 1) -> str:
    """The text of *path* (``''`` when missing)."""
    text, code = grade.test(machine_name, f"cat {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return text if code == 0 else ""


# ---------------------------------------------------------------------------
# Running state: wg show all dump
# ---------------------------------------------------------------------------


def _none(value: str) -> str:
    return "" if value in ("(none)", "off", "") else value


def _int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_wg_dump(text: str, ifname: str = "wg0") -> Dict[str, dict]:
    """Parse ``wg show all dump`` (or ``wg show IF dump``, the lines then lacking the name).

    Returns ``{interface: {'private_key', 'public_key', 'listen_port' (int), 'fwmark' (str,
    ``''`` when off), 'peers': {public_key: {'preshared_key' ('' when none), 'endpoint'
    ('' when none), 'allowed_ips' [str], 'latest_handshake' (unix time, 0 when never),
    'rx', 'tx' (bytes), 'persistent_keepalive' (seconds, 0 when off)}}}}``.  A dump
    without interface names (``wg show wg0 dump``) is filed under *ifname*.  Lines that do
    not parse (``date`` output, errors) are ignored.
    """
    result: Dict[str, dict] = {}
    for line in (text or "").splitlines():
        fields = line.rstrip("\n").split("\t")
        if len(fields) in (4, 8):
            fields = [ifname] + fields
        if len(fields) == 5:
            name, private, public, port, fwmark = fields
            if not is_wg_key(public):
                continue
            result[name] = {
                "private_key": private if is_wg_key(private) else "",
                "public_key": public,
                "listen_port": _int(port),
                "fwmark": _none(fwmark),
                "peers": {},
            }
        elif len(fields) == 9:
            name, public, psk, endpoint, allowed, handshake, rx, tx, keepalive = fields
            if not is_wg_key(public):
                continue
            iface = result.setdefault(name, {"private_key": "", "public_key": "", "listen_port": 0,
                                             "fwmark": "", "peers": {}})
            iface["peers"][public] = {
                "preshared_key": _none(psk),
                "endpoint": _none(endpoint),
                "allowed_ips": [a for a in _none(allowed).split(",") if a],
                "latest_handshake": _int(handshake),
                "rx": _int(rx),
                "tx": _int(tx),
                "persistent_keepalive": _int(keepalive) if keepalive != "off" else 0,
            }
    return result


def get_wg_state(grade: Grade0, machine_name: str, step: int = 1) -> dict:
    """``wg show all dump`` of *machine_name* with the machine's clock.

    Returns ``{'now': unix time (0 until run), 'interfaces': parse_wg_dump()}``; the clock
    read in the same command makes handshake_age() exact whatever the host's clock."""
    text, code = grade.test(machine_name, "date +%s; wg show all dump 2>/dev/null", step=step, allow_error=True)
    lines = (text or "").splitlines()
    now = _int(lines[0].strip()) if lines else 0
    return {"now": now, "interfaces": parse_wg_dump("\n".join(lines[1:])) if code == 0 else {}}


def wg_interface(state: dict, name: str = "wg0", fallback: bool = True) -> Optional[dict]:
    """The interface *name* of a get_wg_state() result, or (``fallback``) the first one."""
    interfaces = state.get("interfaces", {}) if state else {}
    if name in interfaces:
        return interfaces[name]
    if fallback and interfaces:
        return next(iter(interfaces.values()))
    return None


def wg_peer(iface: Optional[dict], pubkey: str) -> Optional[dict]:
    """The peer *pubkey* of a wg_interface() (``None`` when absent)."""
    if not iface or not pubkey:
        return None
    return iface.get("peers", {}).get(pubkey.strip())


def allowed_ips_cover(allowed, net) -> bool:
    """True when one prefix of *allowed* (a peer dict, or a list of prefixes as strings or
    networks) contains *net* (a network, an address or a string): ``0.0.0.0/0`` covers all."""
    if isinstance(allowed, dict):
        allowed = allowed.get("allowed_ips", [])
    try:
        wanted = ip_network(str(net).split("/")[0] if isinstance(net, IPv4Interface) else net, strict=False)
    except ValueError:
        return False
    for text in allowed:
        try:
            prefix = text if isinstance(text, IPv4Network) else ip_network(text, strict=False)
        except ValueError:
            continue
        if prefix.version == wanted.version and wanted.subnet_of(prefix):
            return True
    return False


def handshake_age(state: dict, peer: Optional[dict]) -> Optional[int]:
    """Seconds since the latest handshake of *peer* (``None`` when none happened yet)."""
    if not peer or not peer.get("latest_handshake") or not state.get("now"):
        return None
    return max(0, state["now"] - peer["latest_handshake"])


def recent_handshake(state: dict, peer: Optional[dict], max_age: int = REJECT_AFTER_TIME) -> bool:
    """True when *peer* completed a handshake less than *max_age* seconds ago: with traffic
    flowing a live tunnel renews it every 120 s, so a session older than 180 s is dead."""
    age = handshake_age(state, peer)
    return age is not None and age <= max_age


def endpoint_host(peer: Optional[dict]) -> str:
    """The address of a peer's endpoint (``''`` when unknown): ``'203.0.113.5:51820'`` → address,
    ``'[2001:db8::1]:51820'`` → ``2001:db8::1``."""
    endpoint = (peer or {}).get("endpoint", "") or ""
    if endpoint.startswith("["):
        return endpoint[1:].split("]", 1)[0]
    return endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint


def endpoint_port(peer: Optional[dict]) -> int:
    """The port of a peer's endpoint (0 when unknown)."""
    endpoint = (peer or {}).get("endpoint", "") or ""
    return _int(endpoint.rsplit(":", 1)[1]) if ":" in endpoint else 0


def parse_wg_show(text: str) -> Dict[str, dict]:
    """Parse the human-readable ``wg show`` (every interface): ``{interface: {'public_key',
    'listen_port', 'fwmark', 'peers': {pubkey: {'endpoint', 'allowed_ips', 'latest_handshake'
    (the text, e.g. '6 seconds ago'), 'transfer', 'persistent_keepalive'}}}}``.  The dump
    form is preferred for grading; this one reads what a student pasted."""
    result: Dict[str, dict] = {}
    iface: Optional[dict] = None
    peer: Optional[dict] = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("interface:"):
            iface = result.setdefault(line.split(":", 1)[1].strip(), {
                "public_key": "", "listen_port": 0, "fwmark": "", "peers": {}})
            peer = None
        elif line.startswith("peer:") and iface is not None:
            peer = iface["peers"].setdefault(line.split(":", 1)[1].strip(), {
                "endpoint": "", "allowed_ips": [], "latest_handshake": "", "transfer": "",
                "persistent_keepalive": "", "preshared_key": ""})
        elif ":" in line and iface is not None:
            key, value = (s.strip() for s in line.split(":", 1))
            if peer is None:
                if key == "public key":
                    iface["public_key"] = value
                elif key == "listening port":
                    iface["listen_port"] = _int(value)
                elif key == "fwmark":
                    iface["fwmark"] = value
            else:
                if key == "allowed ips":
                    peer["allowed_ips"] = [a.strip() for a in value.split(",") if a.strip()]
                elif key == "latest handshake":
                    peer["latest_handshake"] = value
                elif key == "persistent keepalive":
                    peer["persistent_keepalive"] = value
                elif key == "preshared key":
                    peer["preshared_key"] = value
                elif key in ("endpoint", "transfer"):
                    peer[key] = value
    return result


# ---------------------------------------------------------------------------
# Routing: ip -j rule / route
# ---------------------------------------------------------------------------


def _json_list(text: str) -> list:
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def parse_ip_rules(text: str) -> List[dict]:
    """``ip -j rule`` as a list of dicts (``priority``, ``src``, ``table``, ``fwmark``,
    ``suppress_prefixlen``, ``not``...), ``[]`` when unparsable."""
    return [r for r in _json_list(text) if isinstance(r, dict)]


def get_ip_rules(grade: Grade0, machine_name: str, step: int = 1) -> List[dict]:
    """The policy routing rules of *machine_name* (``ip -j rule``)."""
    text, code = grade.test(machine_name, "ip -j rule 2>/dev/null", step=step, allow_error=True)
    return parse_ip_rules(text) if code == 0 else []


def fwmark_rule(rules: List[dict], table: int = WG_PORT) -> Optional[dict]:
    """The rule ``not from all fwmark 0x.. lookup TABLE`` that wg-quick adds for a default
    route (``None`` when absent): the encrypted packets, marked, stay in the main table."""
    for rule in rules:
        if str(rule.get("table")) != str(table) or "not" not in rule:
            continue
        mark = str(rule.get("fwmark", "")).split("/")[0]
        try:
            if int(mark, 0) == table:
                return rule
        except ValueError:
            continue
    return None


def suppress_prefix_rule(rules: List[dict]) -> Optional[dict]:
    """The rule ``from all lookup main suppress_prefixlength 0`` of wg-quick (``None`` when
    absent): the main table keeps every route but its default one."""
    for rule in rules:
        if rule.get("table") == "main" and str(rule.get("suppress_prefixlen", "")) == "0":
            return rule
    return None


def parse_ip_routes_json(text: str) -> List[dict]:
    """``ip -j route [show table N]`` as a list of dicts (``dst``, ``dev``, ``gateway``...)."""
    return [r for r in _json_list(text) if isinstance(r, dict)]


def get_routes_table(grade: Grade0, machine_name: str, table: int = WG_PORT, step: int = 1) -> List[dict]:
    """The routes of table *table* (``ip -j route show table N``; ``[]`` when empty)."""
    text, code = grade.test(machine_name, f"ip -j route show table {int(table)} 2>/dev/null", step=step,
                            allow_error=True)
    return parse_ip_routes_json(text) if code == 0 else []


def default_route_dev(routes: List[dict]) -> str:
    """The device of the default route of a route list (``''`` when none)."""
    for route in routes:
        if route.get("dst") == "default":
            return str(route.get("dev", ""))
    return ""


def parse_route_get(text: str) -> dict:
    """``ip -j route get ADDR``: ``{'dev', 'via' (gateway), 'table', 'src'}`` (all ``''`` when
    the kernel has no route)."""
    entries = parse_ip_routes_json(text)
    entry = entries[0] if entries else {}
    return {
        "dev": str(entry.get("dev", "")),
        "via": str(entry.get("gateway", "")),
        "table": str(entry.get("table", "")),
        "src": str(entry.get("prefsrc", "")),
    }


def get_route_get(grade: Grade0, machine_name: str, dest, step: int = 1) -> dict:
    """How *machine_name* would route a packet to *dest* (``ip -j route get``): the device is
    the one the policy routing of a full tunnel picks (``dev wg0 table 51820``)."""
    addr = str(dest).split("/")[0]
    text, code = grade.test(machine_name, f"ip -j route get {shlex.quote(addr)} 2>/dev/null", step=step,
                            allow_error=True)
    return parse_route_get(text) if code == 0 else parse_route_get("")


# ---------------------------------------------------------------------------
# systemd units
# ---------------------------------------------------------------------------


def get_unit_state(grade: Grade0, machine_name: str, unit: str, step: int = 1) -> dict:
    """``{'active': 'active'|'inactive'|'failed'|..., 'enabled': 'enabled'|'disabled'|...}``
    of a systemd unit (both ``''`` when systemctl is unavailable)."""
    q = shlex.quote(unit)
    text, code = grade.test(machine_name, f"systemctl is-active {q} 2>/dev/null; systemctl is-enabled {q} 2>/dev/null",
                            step=step, allow_error=True)
    lines = [ln.strip() for ln in (text or "").splitlines()]
    return {"active": lines[0] if lines else "", "enabled": lines[1] if len(lines) > 1 else ""}


# ---------------------------------------------------------------------------
# Probe: a throw-away peer run by the hidden machine
# ---------------------------------------------------------------------------


def wg_probe_cmd(private_key: str, address, peer_pubkey: str, endpoint: str, allowed_ips, ping_target,
                 preshared_key: Optional[str] = None, interface: str = "wg0", key_file: str = "/tmp/.sre_wg.key",
                 count: int = 2, deadline: int = 4) -> str:
    """One-line command setting up a WireGuard peer by hand on the probe, pinging through it
    and printing the dump of the interface, then removing it.

    *address* is the probe's tunnel address (``/32`` added), *allowed_ips* the prefixes
    accepted from / routed to the peer (list or one string), *endpoint* ``host:port``.  The
    output holds ``PING=<exit code>`` and the ``wg show IF dump`` lines: read it with
    parse_wg_probe().  Every step exits 0 so that the dump is always printed."""
    allowed = allowed_ips if isinstance(allowed_ips, str) else ",".join(str(a) for a in allowed_ips)
    q_if = shlex.quote(interface)
    q_key = shlex.quote(key_file)
    psk_file = key_file + ".psk"
    parts = [
        f"ip link del {q_if} 2>/dev/null",
        f"umask 077 && printf '%s\\n' {shlex.quote(private_key)} > {q_key}",
        f"ip link add {q_if} type wireguard",
        f"wg set {q_if} private-key {q_key} peer {shlex.quote(peer_pubkey)} endpoint {shlex.quote(endpoint)} "
        f"allowed-ips {shlex.quote(allowed)}" + (
            f" preshared-key {shlex.quote(psk_file)}" if preshared_key else ""),
        f"ip address add {shlex.quote(str(address).split('/')[0])}/32 dev {q_if}",
        f"ip link set {q_if} up",
    ]
    if preshared_key:
        parts.insert(2, f"printf '%s\\n' {shlex.quote(preshared_key)} > {shlex.quote(psk_file)}")
    for prefix in allowed.split(","):
        parts.append(f"ip route add {shlex.quote(prefix.strip())} dev {q_if} 2>/dev/null")
    setup = "; ".join(parts)
    return (f"{setup}; ping -c {int(count)} -w {int(deadline)} {shlex.quote(str(ping_target).split('/')[0])} "
            f">/dev/null 2>&1; echo PING=$?; wg show {q_if} dump 2>/dev/null; ip link del {q_if} 2>/dev/null; "
            f"rm -f {q_key} {shlex.quote(psk_file)}; true")


def parse_wg_probe(text: str, interface: str = "wg0") -> dict:
    """``{'ping': bool, 'handshake': bool, 'rx': int, 'tx': int}`` from the output of
    wg_probe_cmd(): ``handshake`` when the peer line of the dump has a latest-handshake."""
    m = re.search(r"^PING=(-?\d+)$", text or "", flags=re.MULTILINE)
    dump = parse_wg_dump(text or "", ifname=interface)
    iface = dump.get(interface) or (next(iter(dump.values())) if dump else None)
    peers = list((iface or {}).get("peers", {}).values())
    peer = peers[0] if peers else {}
    return {
        "ping": m is not None and m.group(1) == "0",
        "handshake": bool(peer.get("latest_handshake")),
        "rx": peer.get("rx", 0),
        "tx": peer.get("tx", 0),
    }
