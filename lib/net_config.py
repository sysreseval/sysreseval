import re
from collections import deque
from typing import List, Tuple, Dict, Any, Literal, TypeAlias
from ipaddress import (ip_address, ip_interface, ip_network,
                       IPv4Address, IPv4Interface, IPv4Network,
                       IPv6Address, IPv6Interface, IPv6Network)

from SRE.lib_sre import NetScheme0, Grade0

IPAddress: TypeAlias = IPv4Address | IPv6Address
IPInterface: TypeAlias = IPv4Interface | IPv6Interface
IPNetwork: TypeAlias = IPv4Network | IPv6Network

# One interface: (addresses, routes).  Both families may share one entry (dual stack), IPv4
# first by convention:
#   ([IPv4Interface('10.0.0.1/24'), IPv6Interface('fd00:1::1/64')],
#    [(IPv4Network('0.0.0.0/0'), gw4), (IPv6Network('::/0'), gw6)])
NetConfigInterface: TypeAlias = (
        Tuple[
            List[IPInterface],
            List[Tuple[IPNetwork, IPAddress | IPInterface]]
        ]
        | Literal['dhcp']
        | None
)

NetConfigEntry: TypeAlias = List[NetConfigInterface]  # indexed by eth number

NetConfig: TypeAlias = Dict[str, NetConfigEntry]  # machine name -> entry

SysctlConfig = Dict[str, Any]

_IFACE_TYPES = (IPv4Interface, IPv6Interface)
_DEFAULT_NETS = {'0.0.0.0/0', '::/0'}
_DEFAULT_NET_BY_VERSION = {4: IPv4Network('0.0.0.0/0'), 6: IPv6Network('::/0')}
_INET_RE = re.compile(r'^\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)')
# the inet6 line of `ip a` does not end with the interface name: "inet6 fd00::1/64 scope global"
_INET6_RE = re.compile(r'^\s+inet6\s+([0-9a-fA-F:.]+)/(\d+)(.*)$')
_SCOPE_LINK_RE = re.compile(r'\bscope\s+link\b')
_TEMPORARY_RE = re.compile(r'\btemporary\b')
# first word of `ip -6 route` lines that are not plain routes
_V6_ROUTE_TYPES = {'unreachable', 'blackhole', 'prohibit', 'throw', 'anycast', 'local', 'multicast',
                   'broadcast', 'nat'}


def _gw_ip(via):
    """Bare address of a next hop given either as an Address or as an Interface."""
    return via.ip if isinstance(via, _IFACE_TYPES) else via


def _skip_inet6_line(line: str, link_local: bool) -> bool:
    """True for the inet6 lines that are never part of a configuration: link-local addresses
    (unless *link_local*) and temporary (privacy) SLAAC addresses."""
    return (not link_local and bool(_SCOPE_LINK_RE.search(line))) or bool(_TEMPORARY_RE.search(line))


def get_ip_addresses(grade: Grade0, machine_name: str, step: int = 1, ipv6: bool = False,
                     link_local: bool = False) -> Dict[str, List[Tuple[str, int]]]:
    """Run 'ip a' on machine_name and parse the output.

    Returns a dict mapping interface name -> list of (address, prefix_len).

    Only IPv4 addresses are returned unless ``ipv6=True``, which adds the IPv6 addresses
    (``inet6`` lines) after the IPv4 ones: global addresses, SLAAC (``dynamic`` /
    ``mngtmpaddr``) addresses and ``::1``; link-local addresses (``scope link``) only with
    ``link_local=True``; temporary (privacy) addresses never.

    Addresses for each interface are sorted by:
      1. family (IPv4 before IPv6)
      2. prefix length descending
      3. IP address lexicographically ascending

    Edge cases:
      - virtual interfaces (e.g. eth0@if5) -> name stripped to 'eth0'
      - non-zero exit code or empty output  -> {}
    """
    output, code = grade.test(machine_name, 'ip a', step=step)
    if code != 0 or not output:
        return {}
    result: Dict[str, List[Tuple[str, int]]] = {}
    current_iface = None
    for line in output.splitlines():
        m = re.match(r'^\d+:\s+(\S+?)(?:@\S+)?:', line)
        if m:
            current_iface = m.group(1)
            result.setdefault(current_iface, [])
            continue
        m = _INET_RE.match(line)
        if m and current_iface is not None:
            result[current_iface].append((m.group(1), int(m.group(2))))
            continue
        if ipv6 and current_iface is not None:
            m = _INET6_RE.match(line)
            if m and not _skip_inet6_line(m.group(3), link_local):
                result[current_iface].append((m.group(1), int(m.group(2))))
    for iface in result:
        result[iface].sort(key=lambda x: (6 if ':' in x[0] else 4, -x[1], x[0]))
    return result


def _parse_ip_route(output: str, v6: bool) -> Dict[Tuple[str, int], Tuple[str, str, int]]:
    result: Dict[Tuple[str, int], Tuple[str, str, int]] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        dest = parts[0]
        if v6 and dest in _V6_ROUTE_TYPES:
            continue
        if dest == 'default':
            net, mask = ('::', 0) if v6 else ('0.0.0.0', 0)
        elif '/' in dest:
            net, mask_str = dest.split('/')
            mask = int(mask_str)
        else:
            net, mask = dest, (128 if v6 else 32)
        via, dev, metric = '', '', 0
        i = 1
        while i < len(parts):
            if parts[i] == 'via' and i + 1 < len(parts):
                via = parts[i + 1]
                i += 2
            elif parts[i] == 'dev' and i + 1 < len(parts):
                dev = parts[i + 1]
                i += 2
            elif parts[i] == 'metric' and i + 1 < len(parts):
                metric = int(parts[i + 1])
                i += 2
            else:
                i += 1
        result[(net, mask)] = (via, dev, metric)
    return result


def get_routes(grade: Grade0, machine_name: str, step: int = 1,
               ipv6: bool = False) -> Dict[Tuple[str, int], Tuple[str, str, int]]:
    """Run 'ip route' (and 'ip -6 route' with ``ipv6=True``) on machine_name and parse the output.

    Returns a dict mapping (network, mask) -> (via, dev, metric).

    Edge cases:
      - 'default' route              -> key ('0.0.0.0', 0), or ('::', 0) in the IPv6 table
      - host route without mask      -> mask 32 (128 in the IPv6 table)
      - direct route (no via)        -> via ''
      - no explicit metric           -> metric 0
      - non-zero exit code or empty output -> {} (IPv4 table; the IPv6 routes are still
        returned when the IPv4 command fails)
      - IPv6 table: 'unreachable', 'blackhole', ... entries are skipped; the kernel's
        connected routes (fd00::/64 dev eth0 proto kernel, fe80::/64) have no via, like
        the IPv4 ones, and the default route of a router advertisement is kept
        (default via fe80::... proto ra)
    """
    output, code = grade.test(machine_name, 'ip route', step=step)
    if ipv6:
        output6, code6 = grade.test(machine_name, 'ip -6 route', step=step)
    result = {} if (code != 0 or not output) else _parse_ip_route(output, False)
    if ipv6 and code6 == 0 and output6:
        result.update(_parse_ip_route(output6, True))
    return result


def get_sysctl_conf(grade: Grade0, machine_name: str, step: int = 1) -> Dict[str, str]:
    """Read /etc/sysctl.conf and all files under /etc/sysctl.d/ and parse kernel parameters.

    Returns a dict mapping parameter name -> value (both as strings).

    Parsing rules:
      - lines starting with '#' or ';' are comments and ignored
      - blank lines are ignored
      - accepted formats: 'key = value' and 'key=value'
      - later definitions override earlier ones (sysctl.d files override sysctl.conf)

    Edge cases:
      - non-zero exit code from any grade.test() -> {} immediately
      - first-pass empty output                  -> {} and continues to next call
    """
    result: Dict[str, str] = {}

    def _parse(text: str) -> None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in ('#', ';'):
                continue
            if '=' in line:
                key, _, value = line.partition('=')
                result[key.strip()] = value.strip()

    output, code = grade.test(machine_name, 'cat /etc/sysctl.conf', step=step)
    if code != 0:
        return {}
    _parse(output)

    output2, code = grade.test(machine_name, 'cat /etc/sysctl.d/*', step=step)
    if code != 0:
        return {}
    _parse(output2)

    return result


def get_net_config_entry(grade: Grade0, machine_name: str, step: int = 1, ipv6: bool = False) -> NetConfigEntry:
    """Run 'ip a', 'ip route', and 'ip link show' on machine_name and return a NetConfig.

    Each entry in the returned list corresponds to one interface (eth0, eth1, …)
    in index order.

    Entry types:
      - Tuple (addresses, routes): statically configured interface.
      - 'dhcp': interface whose address(es) were all assigned dynamically (DHCP).
      - None: interface present in the kernel but carrying no IP address.

    The list covers eth0 … ethN where N is the highest eth index reported by
    'ip link show'.  Interfaces beyond the highest present index are not included.

    ``ipv6=True`` adds the IPv6 addresses (see get_ip_addresses: no link-local, no
    temporary address) and the routes of the IPv6 table to the same entries, IPv4 first.
    A SLAAC address counts as dynamic: an interface with a static IPv4 address and a
    SLAAC IPv6 address is a tuple holding both, an IPv6-only SLAAC interface is 'dhcp'.
    The default route learnt from a router advertisement has a link-local next hop: it
    is attached to the interface named by its 'dev'.

    Edge cases:
      - non-zero exit code or empty output from any command -> []
      - interfaces whose name does not match eth\\d+  -> ignored
      - routes with an unknown gateway -> attached to the first interface, or
        dropped if there are no interfaces
    """
    raw_addrs = get_ip_addresses(grade, machine_name, step=step, ipv6=ipv6)
    raw_routes = get_routes(grade, machine_name, step=step, ipv6=ipv6)

    # Re-use the cached 'ip a' output to detect dynamic (DHCP) addresses.
    ip_a_out, _ = grade.test(machine_name, 'ip a', step=step)

    # Parse which interfaces have *all* their inet addresses marked dynamic.
    dynamic_ifaces: set[str] = set()
    current_iface: str | None = None
    iface_addr_flags: dict[str, list[bool]] = {}  # iface -> [is_dynamic, ...]
    addr_line_re = re.compile(r'^\s+inet6?\s+\S+') if ipv6 else re.compile(r'^\s+inet\s+\S+')
    for line in (ip_a_out or '').splitlines():
        m = re.match(r'^\d+:\s+(\S+?)(?:@\S+)?:', line)
        if m:
            current_iface = m.group(1)
            iface_addr_flags.setdefault(current_iface, [])
            continue
        m = addr_line_re.match(line)
        if m and current_iface is not None:
            if ipv6 and line.lstrip().startswith('inet6') and _skip_inet6_line(line, link_local=False):
                continue
            iface_addr_flags.setdefault(current_iface, []).append('dynamic' in line)
    for iface, flags in iface_addr_flags.items():
        if flags and all(flags):
            dynamic_ifaces.add(iface)

    # Discover all present eth<N> interfaces via 'ip link show'.
    ip_link_out, link_code = grade.test(machine_name, 'ip link show', step=step)
    if link_code != 0 or not ip_link_out:
        return []
    present_eths: set[str] = set(
        re.findall(r'^\d+:\s+(eth\d+)(?:@\S+)?:', ip_link_out, re.MULTILINE)
    )
    if not present_eths:
        return []

    max_n = max(int(name[3:]) for name in present_eths)

    # Build interface → addresses lookup from raw_addrs (only non-empty entries).
    eth_addrs: dict[str, list[tuple[str, int]]] = {
        name: addrs
        for name, addrs in raw_addrs.items()
        if name.startswith('eth') and name[3:].isdigit() and addrs
    }

    # Collect static eth interfaces in order (for route distribution).
    static_eth_ifaces: list[tuple[str, list[IPInterface]]] = []
    for n in range(max_n + 1):
        name = f'eth{n}'
        if name not in present_eths:
            continue
        if name in eth_addrs and name not in dynamic_ifaces:
            ifaces = [ip_interface(f"{addr}/{plen}") for addr, plen in eth_addrs[name]]
            if ifaces:
                static_eth_ifaces.append((name, ifaces))

    # Distribute routes among static interfaces (existing logic).
    iface_networks: list[list[IPNetwork]] = [
        [iface.network for iface in ifaces]
        for _, ifaces in static_eth_ifaces
    ]
    routes_per_iface: list[list[tuple[IPNetwork, IPAddress]]] = [
        [] for _ in static_eth_ifaces
    ]
    for (net_str, mask), (via, dev, _metric) in raw_routes.items():
        if not via:
            continue
        dest = ip_network(f"{net_str}/{mask}")
        gw = ip_address(via)
        matched = None
        for idx, nets in enumerate(iface_networks):
            if any(gw in net for net in nets):  # always False across families
                matched = idx
                break
        if matched is None and ipv6:
            # a router advertisement's default route: link-local next hop, in no configured prefix
            matched = next((idx for idx, (name, _) in enumerate(static_eth_ifaces) if name == dev), None)
        if matched is None:
            matched = 0
        if routes_per_iface:
            routes_per_iface[matched].append((dest, gw))

    static_map: dict[str, tuple[list[IPInterface], list[tuple[IPNetwork, IPAddress]]]] = {
        name: (ifaces, routes_per_iface[idx])
        for idx, (name, ifaces) in enumerate(static_eth_ifaces)
    }

    # Assemble final NetConfig list.
    result: NetConfigEntry = []
    for n in range(max_n + 1):
        name = f'eth{n}'
        if name not in present_eths:
            result.append(None)
            continue
        if name in dynamic_ifaces:
            result.append('dhcp')
        elif name in static_map:
            result.append(static_map[name])
        else:
            result.append(None)

    return result


def get_persistent_net_config_entry(grade: Grade0, machine_name: str, step: int = 1,
                                    ipv6: bool = False) -> tuple[NetConfigEntry, int]:
    """Parse /etc/network/interfaces (+ interfaces.d/) and return (NetConfig, error_count).

    Reconstructs the network configuration that would result from
    'systemctl networking start' (i.e. ifup -a).

    Entry types in the returned NetConfig:
      - Tuple (addresses, routes): inet-static stanza for eth<N>.
      - 'dhcp': inet-dhcp stanza for eth<N>.
      - None: eth<N> mentioned in an auto/allow-hotplug line but with no stanza.

    Only eth<N> interfaces are included, in index order.

    error_count counts lines that are syntactically wrong or have invalid
    values (bad IP/network, unknown stanza keywords, malformed iface lines…).

    Parsing rules:
      - 'address <ip>[/<prefix>]' — primary address; prefix may be absent
      - 'netmask <mask>'          — applied to primary address when it has no prefix
      - 'gateway <ip>'            — inserted as a 0.0.0.0/0 route
      - 'post-up / up ip addr add <addr> dev <iface>' — extra addresses
      - 'post-up / up ip route add <net> via <gw>'    — static routes
      - Other post-up/up/down commands are silently ignored

    ``ipv6=False`` (default): 'inet6' stanzas are ignored like 'manual' ones (not parsed,
    not counted).  ``ipv6=True``: 'iface ethN inet6 static' stanzas are parsed too
    ('address' with a prefix or 'netmask <prefixlen>', 'gateway' -> ::/0 route, 'post-up ip
    [-6] route add' / 'ip [-6] addr add'); the IPv4 and IPv6 parts of an interface are merged
    into one tuple (IPv4 first); 'inet6 dhcp' / 'inet6 auto' count as dynamic, so an
    interface that is dynamic in both families is 'dhcp'.
    """
    out1, code1 = grade.test(machine_name, 'cat /etc/network/interfaces', step=step, allow_error=True)
    out2, code2 = grade.test(machine_name, 'cat /etc/network/interfaces.d/*', step=step, allow_error=True)

    lines: list[str] = []
    include_interfaces_d = False
    if code1 == 0 and out1:
        lines.extend(out1.splitlines())
        for raw_line in out1.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            parts = stripped.split()
            if (parts[0] in ('source', 'source-directory')
                    and len(parts) >= 2
                    and '/etc/network/interfaces.d' in parts[1]):
                include_interfaces_d = True
                break
    if include_interfaces_d and code2 == 0 and out2:
        lines.extend(out2.splitlines())

    errors = 0

    # Known stanza-level options that ifup accepts — won't be counted as errors.
    _KNOWN_OPTS = {
        'address', 'netmask', 'broadcast', 'network', 'gateway',
        'metric', 'hwaddress', 'mtu', 'scope',
        'pre-up', 'up', 'post-up', 'down', 'pre-down', 'post-down',
        'dns-nameservers', 'dns-search', 'dns-domain',
        'vlan-raw-device', 'bridge_ports', 'bridge_stp', 'bridge_fd',
        'bond-master', 'bond-slaves', 'bond-mode', 'bond-miimon',
        'wpa-ssid', 'wpa-psk', 'wpa-conf',
    }
    # inet6-specific options (ifupdown's inet6.defn)
    _KNOWN_OPTS6 = _KNOWN_OPTS | {
        'accept_ra', 'autoconf', 'privext', 'dad-attempts', 'dad-interval', 'preferred-lifetime',
        'media',
    }

    def _new_bucket():
        return {
            'primary': None, 'has_prefix': False,
            'netmask': None, 'extras': [],
            'routes': [], 'gateway': None,
        }

    # Accumulate per-interface data keyed by (interface name, family).
    iface_data: dict[tuple[str, int], dict] = {}
    dhcp_ifaces: set[str] = set()  # interfaces with 'inet dhcp' stanza
    dyn6_ifaces: set[str] = set()  # interfaces with 'inet6 dhcp' / 'inet6 auto' stanza (ipv6=True)
    auto_ifaces: set[str] = set()  # interfaces seen in auto/allow-hotplug lines
    current: tuple[str, int] | None = None  # (name, family) of the active static stanza
    in_ignored_stanza: bool = False  # True inside loopback / dhcp / manual stanza

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        parts = stripped.split()
        kw = parts[0]

        if kw == 'iface':
            if len(parts) < 4:
                errors += 1
                current = None
                in_ignored_stanza = False
                continue
            iface_name, family, method = parts[1], parts[2], parts[3]
            if family == 'inet' and method == 'static':
                current = (iface_name, 4)
                in_ignored_stanza = False
                iface_data.setdefault(current, _new_bucket())
            elif family == 'inet' and method == 'dhcp':
                dhcp_ifaces.add(iface_name)
                current = None
                in_ignored_stanza = True
            elif ipv6 and family == 'inet6' and method == 'static':
                current = (iface_name, 6)
                in_ignored_stanza = False
                iface_data.setdefault(current, _new_bucket())
            elif ipv6 and family == 'inet6' and method in ('dhcp', 'auto'):
                dyn6_ifaces.add(iface_name)
                current = None
                in_ignored_stanza = True
            else:
                current = None  # loopback / manual / other — irrelevant
                in_ignored_stanza = True

        elif kw in ('auto', 'allow-hotplug', 'allow-auto'):
            for iface_name in parts[1:]:
                auto_ifaces.add(iface_name)

        elif kw in ('source', 'source-directory', 'mapping',
                    'no-auto-down', 'no-scripts'):
            pass  # Valid top-level directives, nothing to record

        else:
            # Option line within a stanza (indentation not required by ifupdown).
            # If outside any stanza entirely, count as an error.
            directive = kw

            if current is None:
                if not in_ignored_stanza:
                    errors += 1
                continue

            data = iface_data[current]
            fam = current[1]
            iface_cls = IPv4Interface if fam == 4 else IPv6Interface
            addr_cls = IPv4Address if fam == 4 else IPv6Address

            if directive == 'address':
                if len(parts) < 2:
                    errors += 1
                else:
                    try:
                        iface = iface_cls(parts[1])
                        data['primary'] = iface
                        data['has_prefix'] = '/' in parts[1]
                    except ValueError:
                        errors += 1

            elif directive == 'netmask':
                if len(parts) < 2:
                    errors += 1
                else:
                    data['netmask'] = parts[1]

            elif directive == 'gateway':
                if len(parts) < 2:
                    errors += 1
                else:
                    try:
                        data['gateway'] = addr_cls(parts[1])
                    except ValueError:
                        errors += 1

            elif directive in ('post-up', 'up'):
                cmd = stripped[len(directive):].strip()
                if not ipv6:
                    m = re.match(r'ip\s+route\s+add\s+(\S+)\s+via\s+(\S+)', cmd)
                    if m:
                        try:
                            net = IPv4Network(m.group(1), strict=False)
                            gw = IPv4Address(m.group(2))
                            data['routes'].append((net, gw))
                        except ValueError:
                            errors += 1
                        continue
                    m = re.match(r'ip\s+addr\s+add\s+(\S+)\s+dev\s+\S+', cmd)
                    if m:
                        try:
                            data['extras'].append(IPv4Interface(m.group(1)))
                        except ValueError:
                            errors += 1
                else:
                    m = re.match(r'ip\s+(?:-[46]\s+)?route\s+add\s+(\S+)\s+via\s+(\S+)', cmd)
                    if m:
                        try:
                            net = ip_network(m.group(1), strict=False)
                            gw = ip_address(m.group(2))
                            if net.version != gw.version:
                                raise ValueError("route and next hop of different families")
                            data['routes'].append((net, gw))
                        except ValueError:
                            errors += 1
                        continue
                    m = re.match(r'ip\s+(?:-[46]\s+)?addr\s+add\s+(\S+)\s+dev\s+\S+', cmd)
                    if m:
                        try:
                            data['extras'].append(ip_interface(m.group(1)))
                        except ValueError:
                            errors += 1
                # Other post-up / up commands (iptables, arp…) are not errors

            elif directive not in (_KNOWN_OPTS6 if fam == 6 else _KNOWN_OPTS):
                errors += 1

    # Collect all eth<N> interface names we know about, in index order.
    all_known = (
            {name for name, _ in iface_data} | dhcp_ifaces | dyn6_ifaces |
            {n for n in auto_ifaces if n.startswith('eth') and n[3:].isdigit()}
    )
    eth_names = sorted(
        [n for n in all_known if n.startswith('eth') and n[3:].isdigit()],
        key=lambda n: int(n[3:])
    )

    def _finalize(data: dict, fam: int):
        """(addresses, routes) of one family bucket, or None without a primary address."""
        nonlocal errors
        primary = data['primary']
        if primary is None:
            return None

        # Combine bare IP with netmask when no CIDR prefix was given.
        if not data['has_prefix'] and data['netmask']:
            try:
                if fam == 4:
                    prefix = IPv4Network(f'0.0.0.0/{data["netmask"]}').prefixlen
                    primary = IPv4Interface(f'{primary.ip}/{prefix}')
                else:
                    prefix = int(data['netmask'])
                    primary = IPv6Interface(f'{primary.ip}/{prefix}')  # ValueError beyond 128
            except ValueError:
                errors += 1

        addresses = [primary] + data['extras']

        routes = list(data['routes'])
        if data['gateway']:
            routes.insert(0, (_DEFAULT_NET_BY_VERSION[fam], data['gateway']))

        return addresses, routes

    result: NetConfigEntry = []
    for name in eth_names:
        if not ipv6:
            if name in dhcp_ifaces:
                result.append('dhcp')
            elif (name, 4) not in iface_data:
                # Mentioned in auto but no inet stanza — unconfigured.
                result.append(None)
            else:
                result.append(_finalize(iface_data[(name, 4)], 4))
            continue

        v4 = None if (name in dhcp_ifaces or (name, 4) not in iface_data) else _finalize(iface_data[(name, 4)], 4)
        v6 = None if (name in dyn6_ifaces or (name, 6) not in iface_data) else _finalize(iface_data[(name, 6)], 6)
        if v4 is None and v6 is None:
            result.append('dhcp' if (name in dhcp_ifaces or name in dyn6_ifaces) else None)
        else:
            addresses = (v4[0] if v4 else []) + (v6[0] if v6 else [])
            routes = (v4[1] if v4 else []) + (v6[1] if v6 else [])
            result.append((addresses, routes))

    return result, errors


class _AttrDict(dict):
    __getattr__ = dict.__getitem__


def net_config_entry_family(nc_entry: NetConfigEntry, version: int) -> NetConfigEntry:
    """Keep only the addresses and routes of IP *version* (4 or 6) in each tuple of
    *nc_entry*; 'dhcp' and None entries are returned unchanged.  Use it to grade the two
    families of a dual-stack configuration separately with eval_net_config()."""
    result: NetConfigEntry = []
    for entry in nc_entry:
        if not isinstance(entry, tuple):
            result.append(entry)
            continue
        ifaces, routes = entry
        result.append(([i for i in ifaces if i.version == version],
                       [(net, gw) for net, gw in routes if net.version == version]))
    return result


def eval_net_config(grade: Grade0, expected: NetConfigEntry, machine_name: str = None,
                    current: NetConfigEntry | None = None, step: int = 1) -> _AttrDict:
    """Compare current and expected NetConfig; return a dict with 10 keys:

    Existing keys (unchanged semantics — 'dhcp' and None entries are skipped):
    - "ips"                   : number of IP addresses that are correct
    - "default_route"         : 1 if the default route matches the expected one, 0 otherwise
    - "other_routes"          : number of correct non-default static routes
    - "wrong_routes"          : number of non-default static routes present in current but not in expected
    - "ips_expected"          : number of IP addresses in expected
    - "default_route_expected": 1 if expected has a default route, 0 otherwise
    - "other_routes_expected" : number of non-default static routes in expected

    New keys for DHCP/None tracking:
    - "dhcp_interfaces"         : positions where both expected and current are 'dhcp'
    - "dhcp_interfaces_expected": count of 'dhcp' entries in expected
    - "none_interfaces_expected": count of None entries in expected

    If *current* is None, get_net_config() is called first.
    IP addresses are compared as interface strings (address + prefix), IPv4 and IPv6 alike.
    Routes are compared as (network, gateway) pairs; 0.0.0.0/0 and ::/0 are both default
    routes ("default_route" is 1 only when every expected default route is present and no
    other one is: split the families with net_config_entry_family() to grade them apart).
    """
    if current is None:
        if machine_name is None:
            raise ValueError("eval_net_config: current and machine_name can't be both None")
        current = get_net_config_entry(grade, machine_name, step=step)

    def _collect_ips(nc: NetConfigEntry) -> set[str]:
        result = set()
        for entry in nc:
            if not isinstance(entry, tuple):
                continue
            ifaces, _ = entry
            for iface in ifaces:
                result.add(str(iface))
        return result

    def _collect_routes(nc: NetConfigEntry) -> set[tuple[str, str]]:
        result = set()
        for entry in nc:
            if not isinstance(entry, tuple):
                continue
            _, routes = entry
            for net, gw in routes:
                if gw is None:
                    gw_str = ''
                elif isinstance(gw, _IFACE_TYPES):
                    gw_str = str(gw.ip)
                else:
                    gw_str = str(gw)
                result.add((str(net), gw_str))
        return result

    exp_ips = _collect_ips(expected)
    cur_ips = _collect_ips(current)

    exp_routes = _collect_routes(expected)
    cur_routes = _collect_routes(current)

    exp_default = {r for r in exp_routes if r[0] in _DEFAULT_NETS}
    cur_default = {r for r in cur_routes if r[0] in _DEFAULT_NETS}
    exp_non_default = {r for r in exp_routes if r[0] not in _DEFAULT_NETS}
    cur_non_default = {r for r in cur_routes if r[0] not in _DEFAULT_NETS}

    dhcp_match = sum(
        1 for e, c in zip(expected, current)
        if e == 'dhcp' and c == 'dhcp'
    )

    return _AttrDict(
        ips=len(exp_ips & cur_ips),
        default_route=1 if exp_default == cur_default else 0,
        other_routes=len(exp_non_default & cur_non_default),
        wrong_routes=len(cur_non_default - exp_non_default),
        ips_expected=len(exp_ips),
        default_route_expected=1 if exp_default else 0,
        other_routes_expected=len(exp_non_default),
        dhcp_interfaces=dhcp_match,
        dhcp_interfaces_expected=sum(1 for e in expected if e == 'dhcp'),
        none_interfaces_expected=sum(1 for e in expected if e is None),
    )


def _route_line(interface: str, net, via) -> str:
    """'post-up' line adding a static route in /etc/network/interfaces."""
    via_addr = _gw_ip(via)
    if net.version == 6:
        line = f'    post-up ip -6 route add {net.compressed} via {via_addr}'
        if via_addr.is_link_local:
            line += f' dev {interface}'
        return line
    return f'    post-up ip route add {net.compressed} via {via_addr}'


def _static_stanza(interface: str, family: int, addresses: list, routes: list, extra_routes: list) -> list[str]:
    """Lines of one 'iface ethN inet|inet6 static' stanza.

    *routes* are the routes of the stanza's family (the default one becomes 'gateway');
    *extra_routes* are routes of the other family when that family has no address on the
    interface (they can only go through 'post-up' lines).
    """
    default_net = _DEFAULT_NET_BY_VERSION[family]
    lines = [
        f'iface {interface} {"inet" if family == 4 else "inet6"} static',
        f'    address {addresses[0]}',
    ]
    for extra in addresses[1:]:
        lines.append(f'    post-up ip addr add {extra} dev {interface}')
    for net, via in routes:
        if net == default_net:
            lines.append(f'    gateway {_gw_ip(via)}')
    for net, via in routes:
        if net != default_net:
            lines.append(_route_line(interface, net, via))
    for net, via in extra_routes:
        lines.append(_route_line(interface, net, via))
    return lines


def render_persistent_net_config_entry(nc_entry: NetConfigEntry, machine_name: str = '') -> str:
    """Content of /etc/network/interfaces for *nc_entry* (*machine_name* only names the machine
    in the error raised for an interface without address).

    One 'inet static' stanza per interface with IPv4 addresses and one 'inet6 static' stanza
    per interface with IPv6 addresses (both for a dual-stack entry): the first address goes
    to 'address', the others to 'post-up ip addr add', the default route to 'gateway' and
    the other routes to 'post-up ip [-6] route add'.
    """
    lines = ['auto lo', 'iface lo inet loopback', '']
    for i, entry in enumerate(nc_entry):
        interface = f'eth{i}'
        if entry is None:
            continue
        if entry == 'dhcp':
            lines += [
                f'auto {interface}',
                f'iface {interface} inet dhcp',
                '',
            ]
            continue
        iface_list, routes = entry
        addresses = {fam: [a for a in iface_list if a.version == fam] for fam in (4, 6)}
        fam_routes = {fam: [(net, via) for net, via in routes if net.version == fam] for fam in (4, 6)}
        families = [fam for fam in (4, 6) if addresses[fam]]
        if not families:
            raise ValueError(f"set_persistent_net_config_entry: {machine_name} {interface} has no address")
        lines.append(f'auto {interface}')
        for fam in families:
            other = 6 if fam == 4 else 4
            extra_routes = fam_routes[other] if other not in families else []
            lines += _static_stanza(interface, fam, addresses[fam], fam_routes[fam], extra_routes)
            lines.append('')
    return '\n'.join(lines)


def set_persistent_net_config_entry(net_scheme: NetScheme0, machine_name: str, nc_entry: NetConfigEntry):
    """Write /etc/network/interfaces on *machine_name* from *nc_entry* (content:
    render_persistent_net_config_entry())."""
    net_scheme.file(machine_name, '/etc/network/interfaces',
                    render_persistent_net_config_entry(nc_entry, machine_name))


def set_net_config_entry(net_scheme: NetScheme0, machine_name: str, nc_entry: NetConfigEntry):
    """Apply *nc_entry* on *machine_name* with 'ip link / ip addr add / ip route add' commands
    ('dhclient' for a 'dhcp' entry).  IPv4 and IPv6 addresses and routes are handled alike
    ('ip' infers the family); an IPv6 route through a link-local next hop gets 'dev ethN'."""
    for i, entry in enumerate(nc_entry):
        interface = f'eth{i}'
        if entry is None:
            continue
        if entry == 'dhcp':
            net_scheme.cmd(machine_name, f'ip link set {interface} up')
            net_scheme.cmd(machine_name, f'dhclient {interface}')
            continue
        iface_list, routes = entry
        net_scheme.cmd(machine_name, f'ip link set {interface} up')
        for iface in iface_list:
            net_scheme.cmd(machine_name, f'ip addr add {iface} dev {interface}')
        for net, via in routes:
            via_addr = _gw_ip(via)
            command = f'ip route add {net.compressed} via {str(via_addr)}'
            if net.version == 6 and via_addr.is_link_local:
                command += f' dev {interface}'
            net_scheme.cmd(machine_name, command)


def set_persistent_sysctl(net_scheme: NetScheme0, machine_name: str, sysctl_config: SysctlConfig):
    for name, value in sysctl_config.items():
        net_scheme.cmd(machine_name, f'echo "{name}={value}" >> /etc/sysctl.conf')
    if sysctl_config:
        remount_proc_sys(net_scheme, machine_name)
        net_scheme.cmd(machine_name, 'sysctl -p')

def remount_proc_sys(net_scheme: NetScheme0, machine_name: str):
    if not hasattr(net_scheme, "remount_proc_sys_done"):
        net_scheme.remount_proc_sys_done = {}
    if net_scheme.remount_proc_sys_done.get(machine_name):
        return
    net_scheme.cmd(machine_name, "mount -o rw,remount /proc/sys")
    net_scheme.remount_proc_sys_done[machine_name] = True


def set_sysctl(net_scheme: NetScheme0, machine_name: str, sysctl_config: SysctlConfig):
    if len(sysctl_config) > 0:
        remount_proc_sys(net_scheme, machine_name)
        for name, value in sysctl_config.items():
            net_scheme.cmd(machine_name, f'sysctl -w {name}={value}')


def set_ip_forward(net_scheme: NetScheme0, machine_name: str, ip_forward: bool, step: int = 1):
    value = 1 if ip_forward else 0
    remount_proc_sys(net_scheme, machine_name)
    net_scheme.cmd(machine_name, f'sysctl -w net.ipv4.ip_forward={value}', step=step)


def get_ip_forward(grade: Grade0, machine_name: str, step: int = 1) -> bool:
    output, code = grade.test(machine_name, 'cat /proc/sys/net/ipv4/ip_forward', step=step)
    if code != 0:
        return False
    return output.strip() == '1'


def set_ipv6_forward(net_scheme: NetScheme0, machine_name: str, ipv6_forward: bool, step: int = 1):
    """Set IPv6 forwarding on *machine_name* (``net.ipv6.conf.all.forwarding``, which the kernel
    propagates to every interface).  Kathara starts the machines of an IPv6 lab with forwarding
    enabled: call it with ``False`` on the hosts, as set_ip_forward() for IPv4."""
    value = 1 if ipv6_forward else 0
    remount_proc_sys(net_scheme, machine_name)
    net_scheme.cmd(machine_name, f'sysctl -w net.ipv6.conf.all.forwarding={value}', step=step)


def get_ipv6_forward(grade: Grade0, machine_name: str, step: int = 1) -> bool:
    """IPv6 forwarding state of *machine_name* (``/proc/sys/net/ipv6/conf/all/forwarding``)."""
    output, code = grade.test(machine_name, 'cat /proc/sys/net/ipv6/conf/all/forwarding', step=step)
    if code != 0:
        return False
    return output.strip() == '1'


def get_sys_parameter_bool(grade: Grade0, machine_name: str, parameter: str, step: int = 1) -> bool | None:
    """Read a boolean kernel parameter via sysctl and return its value.

    Returns True for '1', False for '0', None if the parameter does not exist or the command fails.
    """
    value = get_sys_parameter(grade, machine_name, parameter, step=step)
    if value is None:
        return None
    if value == '1':
        return True
    if value == '0':
        return False
    return None


def get_net_config_from_topology(
        net_scheme: NetScheme0,
        topology=None,
        gateway: str = None,
        default_route: IPv4Address | IPv4Interface = IPv4Interface("172.17.0.1/24"),
        *,
        ipv4: bool = True,
        ipv6: bool = False,
        default_route6: IPv6Address | IPv6Interface | None = None,
) -> NetConfig:
    """Build a NetConfig for every machine in the topology so they can all reach each other.

    Returns {machine_name: NetConfig}.

    Each machine gets:
    - One interface entry per network it belongs to, with the IP from net_scheme.data.ips.
    - Static routes to every non-directly-connected network (found via BFS through
      multi-homed router machines).

    If *gateway* is not None:
    - Every machine except the gateway gets a default route (0.0.0.0/0) toward the
      gateway machine via the appropriate next-hop IP.
    - The gateway itself gets a default route via *default_route* (typically the
      Docker host bridge, e.g. 172.17.0.1, reachable when the gateway is ``bridged=True``);
      ``default_route=None`` gives it none.

    The interface indices (eth0, eth1, …) are computed with the same counter logic as
    NetScheme0.__init__, so they match the actual Kathara deployment.

    IP names follow the convention set by random_ips_from_topology():
    - data.ips.m       when machine m is in exactly one network
    - data.ips.m_netX  when machine m is in multiple networks

    IPv6: ``ipv6=True`` adds, in the same entries, the IPv6 addresses of ``data.ips6`` and
    routes to the IPv6 prefixes of ``data.nets6`` (same naming).  A network without a prefix
    in ``data.nets6``, or a machine without an address in ``data.ips6`` for a network (a
    SLAAC host, an IPv4-only host), simply has no IPv6 part there (no address, no IPv6
    route through it).  The gateway gets a ``::/0`` route only when *default_route6* is
    given (the Docker bridge has no IPv6 by default).  ``ipv4=False`` builds an IPv6-only
    configuration (``data.ips6`` / ``data.nets6`` are then mandatory like their IPv4
    counterparts).
    """
    if not ipv4 and not ipv6:
        raise ValueError("get_net_config_from_topology: at least one of ipv4/ipv6 must be True")
    if topology is None:
        topology = net_scheme.get_topology()
    data = net_scheme.data
    families = [fam for fam, enabled in ((4, ipv4), (6, ipv6)) if enabled]
    ips_containers = {4: data.ips, 6: getattr(data, 'ips6', None)}
    nets_containers = {4: data.nets, 6: getattr(data, 'nets6', None)}

    # --- 1. Replicate NetScheme0 eth-index assignment ---
    # machine_iface: {machine: {net_name: eth_idx}}
    machine_iface: dict[str, dict[str, int]] = {}
    _ctr: dict[str, int] = {}
    for net_name, machines in topology.items():
        items = list(machines.items()) if isinstance(machines, dict) else [(m, None) for m in machines]
        for mname, iface_spec in items:
            iface = iface_spec[0] if isinstance(iface_spec, tuple) else iface_spec
            if iface is None:
                iface = _ctr.get(mname, 0)
            _ctr[mname] = max(_ctr.get(mname, 0), iface) + 1
            machine_iface.setdefault(mname, {})[net_name] = iface

    machine_nets: dict[str, list[str]] = {m: list(d.keys()) for m, d in machine_iface.items()}

    # --- 2. IP lookup (matches random_ips_from_topology naming) ---
    # IPv4 (or the only family): a missing entry is an error (AttributeError), as before.
    # IPv6 next to IPv4: a missing entry means "no IPv6 there" (SLAAC or IPv4-only host).
    def get_ip(machine: str, net_name: str, fam: int = 4) -> IPInterface | None:
        container = ips_containers[fam]
        attr = machine if len(machine_nets[machine]) == 1 else f"{machine}_{net_name}"
        if fam == 6 and ipv4:
            return getattr(container, attr, None)
        return getattr(container, attr)

    def net_has(net_name: str, fam: int) -> bool:
        """Whether *net_name* has a prefix of family *fam* (the prefix of the only family is
        mandatory, as before)."""
        if fam == 4 or not ipv4:
            return True
        return nets_containers[6] is not None and hasattr(nets_containers[6], net_name)

    # --- 3. Network routing graph ---
    # Multi-homed machines act as routers; each pair of their networks is an edge.
    net_graph: dict[str, list[tuple[str, str]]] = {n: [] for n in topology}
    for mname, nets in machine_nets.items():
        for i, n1 in enumerate(nets):
            for n2 in nets[i + 1:]:
                net_graph[n1].append((n2, mname))
                net_graph[n2].append((n1, mname))

    # --- 4. BFS: find (via_start_net, first_router) from start_nets to a target ---
    def _bfs(start_nets: set[str], is_target) -> tuple[str, str] | None:
        visited = set(start_nets)
        q: deque = deque()
        for n in start_nets:
            for adj, router in net_graph.get(n, []):
                if adj not in visited:
                    visited.add(adj)
                    q.append((adj, n, router))
        while q:
            cur, via, router = q.popleft()
            if is_target(cur):
                return (via, router)
            for adj, r in net_graph.get(cur, []):
                if adj not in visited:
                    visited.add(adj)
                    q.append((adj, via, router))
        return None

    def first_hop_to_net(start_nets: set[str], target_net: str) -> tuple[str, str] | None:
        """Return (via_net, router) for the first hop to reach target_net, or None if direct."""
        if target_net in start_nets:
            return None
        return _bfs(start_nets, lambda n: n == target_net)

    def first_hop_to_machine(start_nets: set[str], target: str) -> tuple[str, str] | None:
        """Return (via_net, router) for the first hop toward target machine.
        When directly connected, router is the target machine itself."""
        target_nets = set(machine_nets.get(target, []))
        shared = start_nets & target_nets
        if shared:
            return (next(iter(shared)), target)
        return _bfs(start_nets, lambda n: n in target_nets)

    # --- 5. external default routes as bare addresses (None: no external default route) ---
    external_hop = {
        4: None if default_route is None else _gw_ip(default_route),
        6: None if default_route6 is None else _gw_ip(default_route6),
    }

    # --- 6. Assemble NetConfig per machine ---
    result: dict[str, NetConfigEntry] = {}

    for machine, net_to_eth in machine_iface.items():
        start_nets = set(machine_nets[machine])

        # Collect all candidate routes as (net, eth_idx, next_hop).
        route_triples: list[tuple[IPNetwork, int, IPAddress]] = []

        for fam in families:
            if not any(net_has(n, fam) and get_ip(machine, n, fam) is not None for n in start_nets):
                continue  # no address of this family on the machine: no route of this family

            # Specific routes to every non-directly-connected network
            for target_net in topology:
                if target_net in start_nets or not net_has(target_net, fam):
                    continue
                hop = first_hop_to_net(start_nets, target_net)
                if hop is None:
                    continue
                via_net, router = hop
                if not net_has(via_net, fam):
                    continue
                next_hop = get_ip(router, via_net, fam)
                if next_hop is None:
                    continue
                route_triples.append((
                    getattr(nets_containers[fam], target_net),
                    net_to_eth[via_net],
                    next_hop.ip,
                ))

            # Default route
            if gateway is not None:
                default_net = _DEFAULT_NET_BY_VERSION[fam]
                if machine == gateway:
                    # External default route on the lowest-index interface
                    if external_hop[fam] is not None:
                        route_triples.append((default_net, min(net_to_eth.values()), external_hop[fam]))
                else:
                    hop = first_hop_to_machine(start_nets, gateway)
                    if hop is not None:
                        via_net, router = hop
                        next_hop = get_ip(router, via_net, fam) if net_has(via_net, fam) else None
                        if next_hop is not None:
                            route_triples.append((
                                default_net,
                                net_to_eth[via_net],
                                next_hop.ip,
                            ))

        # Drop redundant routes: a route (net, hop) is redundant when another route
        # (net2, hop2) exists with the same next-hop and net2 is a strict supernet of net
        # (i.e. net2 covers net entirely — the less-specific route already handles it).
        def _is_redundant(net: IPNetwork, hop: IPAddress) -> bool:
            return any(
                net2 != net and net2.version == net.version and net.subnet_of(net2) and hop == hop2
                for net2, _, hop2 in route_triples
            )

        eth_routes: dict[int, list] = {eth: [] for eth in net_to_eth.values()}
        for net, eth, hop in route_triples:
            if not _is_redundant(net, hop):
                eth_routes[eth].append((net, hop))

        # Build the NetConfig list indexed by eth number
        max_eth = max(net_to_eth.values())
        nc: NetConfigEntry = [None] * (max_eth + 1)
        for net_name, eth_idx in net_to_eth.items():
            addresses = [ip for fam in families if net_has(net_name, fam)
                         for ip in [get_ip(machine, net_name, fam)] if ip is not None]
            nc[eth_idx] = (addresses, eth_routes[eth_idx])
        result[machine] = nc

    return result


def get_sys_parameter(grade: Grade0, machine_name: str, parameter: str, step: int = 1) -> str | None:
    """Read a kernel parameter via sysctl and return its value as a string.

    Returns None if the parameter does not exist or the command fails.
    """
    output, code = grade.test(machine_name, f'sysctl -n {parameter}', step=step)
    if code != 0:
        return None
    return output.strip() or None
