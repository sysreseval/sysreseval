import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from SRE.lib_sre import Grade0, NetScheme0


@dataclass
class DhcpSubnet:
    """Configuration for a single DHCP subnet declaration."""
    subnet: IPv4Network
    range_start: IPv4Address
    range_end: IPv4Address
    routers: list[IPv4Address]            = field(default_factory=list)
    dns_servers: list[IPv4Address]        = field(default_factory=list)
    domain_name: str | None               = None
    broadcast_address: IPv4Address | None = None
    default_lease_time: int | None        = None  # subnet-level override; None = use global
    max_lease_time: int | None            = None  # subnet-level override; None = use global
    fixed_addresses: dict[str, str]       = field(default_factory=dict)  # MAC → IP string


@dataclass
class DhcpParameters:
    """All parameters required to configure an ISC DHCP server on a Debian machine.

    Covers both /etc/default/isc-dhcp-server (``interfaces_v4``, ``interfaces_v6``) and
    /etc/dhcp/dhcpd.conf (everything else).
    """
    interfaces_v4: list[str]            # written to INTERFACESv4 in /etc/default/isc-dhcp-server
    interfaces_v6: list[str]            = field(default_factory=list)  # written to INTERFACESv6
    subnets: list[DhcpSubnet]           = field(default_factory=list)
    authoritative: bool                 = True
    default_lease_time: int | None      = None  # omitted from global section when None
    max_lease_time: int | None          = None  # omitted from global section when None
    ddns_update_style: str              = 'none'


def set_dhcp_server(net_scheme: NetScheme0, machine: str,
                    dhcp_params: DhcpParameters, step: int = 1) -> None:
    """Write DHCP server configuration files and (re)start the service on *machine_name*.

    Writes:
    - /etc/default/isc-dhcp-server  (INTERFACESv4)
    - /etc/dhcp/dhcpd.conf          (generated from dhcp_params)

    Then runs ``systemctl enable`` and ``systemctl restart`` for isc-dhcp-server.
    """
    # /etc/default/isc-dhcp-server
    ifaces_v4 = ' '.join(dhcp_params.interfaces_v4)
    ifaces_v6 = ' '.join(dhcp_params.interfaces_v6)
    default_content = f'INTERFACESv4="{ifaces_v4}"\nINTERFACESv6="{ifaces_v6}"\n'
    net_scheme.file(machine, '/etc/default/isc-dhcp-server', default_content, step=step)

    # /etc/dhcp/dhcpd.conf
    lines = []
    auth = 'authoritative' if dhcp_params.authoritative else 'not authoritative'
    lines += [
        f'ddns-update-style {dhcp_params.ddns_update_style};',
        f'{auth};',
    ]
    if dhcp_params.default_lease_time is not None:
        lines.append(f'default-lease-time {dhcp_params.default_lease_time};')
    if dhcp_params.max_lease_time is not None:
        lines.append(f'max-lease-time {dhcp_params.max_lease_time};')
    for s in dhcp_params.subnets:
        lines.append('')
        lines.append(f'subnet {s.subnet.network_address} netmask {s.subnet.netmask} {{')
        lines.append(f'    range {s.range_start} {s.range_end};')
        if s.routers:
            lines.append(f'    option routers {", ".join(str(r) for r in s.routers)};')
        if s.dns_servers:
            lines.append(f'    option domain-name-servers {", ".join(str(d) for d in s.dns_servers)};')
        if s.domain_name is not None:
            lines.append(f'    option domain-name "{s.domain_name}";')
        if s.broadcast_address is not None:
            lines.append(f'    option broadcast-address {s.broadcast_address};')
        if s.default_lease_time is not None:
            lines.append(f'    default-lease-time {s.default_lease_time};')
        if s.max_lease_time is not None:
            lines.append(f'    max-lease-time {s.max_lease_time};')
        for mac, ip in s.fixed_addresses.items():
            safe = mac.replace(':', '-')
            lines += [
                f'    host {safe} {{',
                f'        hardware ethernet {mac};',
                f'        fixed-address {ip};',
                f'    }}',
            ]
        lines.append('}')
    net_scheme.file(machine, '/etc/dhcp/dhcpd.conf', '\n'.join(lines) + '\n', step=step)

    net_scheme.cmd(machine, 'systemctl enable isc-dhcp-server', step=step)
    net_scheme.cmd(machine, 'systemctl restart isc-dhcp-server', step=step)


def get_dhcp_server(grade: Grade0, machine: str,
                    step: int = 1) -> tuple[DhcpParameters | None, int]:
    """Read and parse the DHCP server configuration on *machine_name*.

    Returns ``(params, errors)`` where *params* is a :class:`DhcpParameters`
    instance (or ``None`` if /etc/default/isc-dhcp-server is absent/unreadable)
    and *errors* is the number of parse errors found in dhcpd.conf.
    """
    interfaces_v4 = parse_ipv4_interfaces_in_default_dhcp_server_file(grade, machine, step)
    if interfaces_v4 is None:
        return None, 1
    interfaces_v6 = parse_ipv6_interfaces_in_default_dhcp_server_file(grade, machine, step) or []

    parsed = _parse_dhcpd_config(grade, machine, step)
    errors: int = parsed['errors']
    gp = parsed['global_parameters']

    authoritative     = bool(gp.get('authoritative', False))
    _dlt = gp.get('default-lease-time', None)
    _mlt = gp.get('max-lease-time', None)
    default_lease_time: int | None = int(_dlt) if _dlt is not None else None
    max_lease_time: int | None     = int(_mlt) if _mlt is not None else None
    ddns_update_style = str(gp.get('ddns-update-style', 'none'))

    subnets: list[DhcpSubnet] = []
    for net_addr, sp in parsed['subnets'].items():
        # Reconstruct IPv4Network
        try:
            subnet_net = IPv4Network(f'{net_addr}/{sp["netmask"]}', strict=False)
        except (KeyError, ValueError):
            errors += 1
            continue

        # Parse pool range — stored as "start end" or "dynamic-bootp start end"
        range_val = sp.get('range', '')
        range_parts = range_val.split()
        if range_parts and range_parts[0].lower() == 'dynamic-bootp':
            range_parts = range_parts[1:]
        try:
            range_start = IPv4Address(range_parts[0])
            range_end   = IPv4Address(range_parts[1] if len(range_parts) > 1 else range_parts[0])
        except (IndexError, ValueError):
            errors += 1
            continue

        def _parse_addr_list(val: str) -> list[IPv4Address]:
            result = []
            for part in re.split(r'[,\s]+', val.strip()):
                if part:
                    try:
                        result.append(IPv4Address(part))
                    except ValueError:
                        pass
            return result

        routers = _parse_addr_list(sp.get('option routers', ''))
        dns_servers = _parse_addr_list(sp.get('option domain-name-servers', ''))

        domain_name = sp.get('option domain-name', None)
        if domain_name is not None:
            domain_name = domain_name.strip('"')

        bcast_str = sp.get('option broadcast-address', None)
        try:
            broadcast_address = IPv4Address(bcast_str) if bcast_str else None
        except ValueError:
            broadcast_address = None

        # Only set per-subnet overrides when they differ from the global values
        sub_dlt = sp.get('default-lease-time', None)
        sub_mlt = sp.get('max-lease-time', None)
        try:
            sub_dlt = int(sub_dlt) if sub_dlt is not None else None
            sub_mlt = int(sub_mlt) if sub_mlt is not None else None
        except ValueError:
            sub_dlt = sub_mlt = None
        subnet_default_lease = sub_dlt if sub_dlt != default_lease_time else None
        subnet_max_lease     = sub_mlt if sub_mlt != max_lease_time else None

        subnets.append(DhcpSubnet(
            subnet=subnet_net,
            range_start=range_start,
            range_end=range_end,
            routers=routers,
            dns_servers=dns_servers,
            domain_name=domain_name,
            broadcast_address=broadcast_address,
            default_lease_time=subnet_default_lease,
            max_lease_time=subnet_max_lease,
            fixed_addresses={str(k): str(v) for k, v in sp.get('fixed-addresses', {}).items()},
        ))

    params = DhcpParameters(
        interfaces_v4=interfaces_v4,
        interfaces_v6=interfaces_v6,
        subnets=subnets,
        authoritative=authoritative,
        default_lease_time=default_lease_time,
        max_lease_time=max_lease_time,
        ddns_update_style=ddns_update_style,
    )
    return params, errors


def _parse_dhcpd_interfaces(cmdline_output: str) -> list[str]:
    """Extract interface names from dhcpd cmdline tokens (one token per line).

    Returns the list of interface names passed to dhcpd, or ``["*"]`` if none
    were specified (meaning dhcpd listens on all interfaces).
    """
    # Flags that consume the next token as their value argument.
    VALUE_FLAGS = {
        '-cf', '-lf', '-pf', '-tf', '-sf', '-hpf',
        '-user', '-group', '-chroot', '-port', '-relay',
    }
    tokens = [t for t in cmdline_output.splitlines() if t.strip()]
    interfaces = []
    skip_next = False
    for i, tok in enumerate(tokens):
        if i == 0:
            continue  # executable path (e.g. /usr/sbin/dhcpd)
        if skip_next:
            skip_next = False
            continue
        if tok in VALUE_FLAGS:
            skip_next = True
            continue
        if tok.startswith('-'):
            continue
        interfaces.append(tok)
    return interfaces if interfaces else ['*']


def check_running_dhcp_server(grade: Grade0, machine: str) -> tuple[bool, list[str]]:
    """Check whether ISC DHCP server is running on *machine*.

    Returns a tuple ``(running, interfaces)`` where:

    - *running*: ``True`` if ``isc-dhcp-server`` is currently active.
    - *interfaces*: list of interface names dhcpd is bound to (e.g.
      ``["eth0", "eth1"]``), or ``["*"]`` if it listens on all interfaces.
      Empty list when *running* is ``False``.

    Listening interfaces are read from the running process command line so
    they reflect the actual state, not just the configuration file.
    """
    _, code = grade.test(machine, 'systemctl is-active isc-dhcp-server',
                         allow_error=True)
    if code != 0:
        return False, []

    cmdline_out, _ = grade.test(
        machine,
        r"tr '\000' '\n' < /proc/$(pidof -s dhcpd)/cmdline 2>/dev/null",
        allow_error=True,
    )
    return True, _parse_dhcpd_interfaces(cmdline_out)


def parse_ipv4_interfaces_in_default_dhcp_server_file(
        grade: Grade0, machine: str, step: int = 1) -> list[str] | None:
    """Return the list of interfaces from INTERFACESv4 in /etc/default/isc-dhcp-server.

    Returns None if the file is absent or unreadable.
    Returns an empty list if the file exists but INTERFACESv4 is not set.
    """
    output, code = grade.test(machine, 'cat /etc/default/isc-dhcp-server',
                              step=step, allow_error=True)
    if code != 0:
        return None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('#'):
            continue
        m = re.match(r'^INTERFACESv4\s*=\s*"([^"]*)"', line)
        if m:
            return m.group(1).split()
    return []


def parse_ipv6_interfaces_in_default_dhcp_server_file(
        grade: Grade0, machine: str, step: int = 1) -> list[str] | None:
    """Return the list of interfaces from INTERFACESv6 in /etc/default/isc-dhcp-server.

    Returns None if the file is absent or unreadable.
    Returns an empty list if the file exists but INTERFACESv6 is not set.
    """
    output, code = grade.test(machine, 'cat /etc/default/isc-dhcp-server',
                              step=step, allow_error=True)
    if code != 0:
        return None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('#'):
            continue
        m = re.match(r'^INTERFACESv6\s*=\s*"([^"]*)"', line)
        if m:
            return m.group(1).split()
    return []


def _parse_dhcpd_config(grade: Grade0, machine: str, step: int = 1) -> dict:
    """Parse /etc/dhcp/dhcpd.conf on *machine* via grade.test() and return a
    structured dict describing the ISC DHCP server configuration.

    Returns a dict with three keys:

    ``errors``
        Number of syntactically incorrect or unrecognised statements.

    ``global_parameters``
        Dict of top-level parameters (name → value).  ``option`` parameters are
        stored with their full two-word key, e.g. ``"option domain-name-servers"``.
        ``authoritative`` maps to ``True``/``False``.  All other parameters map
        to their value as a string (or space-joined string for multi-token values).

    ``subnets``
        Dict keyed by the network address string (e.g. ``"10.152.187.0"``).
        Each value is a dict of *effective* parameters: global parameters are
        copied first, then subnet-level declarations override them.  A special
        key ``"fixed-addresses"`` holds a ``{MAC: IP-or-hostname}`` mapping
        assembled from all ``host`` blocks whose ``fixed-address`` falls inside
        that subnet (or that were declared directly inside that subnet block).
    """
    output, code = grade.test(machine, 'cat /etc/dhcp/dhcpd.conf', step=step)

    empty: dict[str, Any] = {'errors': 0, 'global_parameters': {}, 'subnets': {}}
    if code != 0 or not output:
        return empty

    # ------------------------------------------------------------------ #
    # Strip comments: /* … */,  // … \n,  # … \n                         #
    # ------------------------------------------------------------------ #
    text = re.sub(r'/\*.*?\*/', '', output, flags=re.DOTALL)
    text = re.sub(r'(?:#|//).*', '', text)

    # ------------------------------------------------------------------ #
    # Tokenise: {  }  ;  are single-character tokens; quoted strings are  #
    # kept intact; everything else is split on whitespace.                #
    # ------------------------------------------------------------------ #
    token_re = re.compile(r'[{};]|"[^"]*"|[^\s{};]+')
    tokens = token_re.findall(text)

    # ------------------------------------------------------------------ #
    # Known single-value global / subnet keywords                         #
    # ------------------------------------------------------------------ #
    _KNOWN_PARAMS = {
        'default-lease-time', 'max-lease-time', 'min-lease-time',
        'ddns-update-style', 'log-facility', 'server-identifier',
        'filename', 'next-server', 'server-name',
        'use-host-decl-names', 'get-lease-hostnames', 'ping-check',
        'one-lease-per-client', 'dynamic-bootp-lease-length',
        'lease-file-name', 'pid-file-name', 'omapi-port',
        'update-conflict-detection', 'update-optimization',
        'stash-agent-options', 'local-port', 'remote-port',
        'db-time-format', 'bootp-lease-length', 'min-secs',
        'always-reply-rfc1048', 'server-name',
    }

    _KNOWN_HOST_PARAMS = {
        'hardware', 'fixed-address', 'filename', 'next-server',
        'server-name', 'client-identifier', 'ddns-hostname',
        'ddns-domainname', 'option', 'supersede', 'prepend', 'append',
        'default', 'deny', 'allow', 'ignore',
    }

    # ------------------------------------------------------------------ #
    # Parser state                                                         #
    # ------------------------------------------------------------------ #
    errors: int = 0

    # Collected raw data
    global_params: dict[str, Any] = {}
    # net_addr -> {'netmask': str, 'fixed-addresses': {}, param: val, ...}
    subnets: dict[str, dict[str, Any]] = {}

    # Hosts collected during parsing: (parent_subnet_net or None, mac, ip)
    all_hosts: list[tuple[str | None, str, str]] = []

    # Context stack: list of (kind, data)
    #   kind = 'global' | 'subnet' | 'host' | 'other'
    #   data = net_addr str for 'subnet', host-info dict for 'host', None otherwise
    context_stack: list[tuple[str, Any]] = [('global', None)]

    pending: list[str] = []   # words accumulated before the next ; or {

    def _find_parent_subnet() -> str | None:
        for frame in reversed(context_stack):
            if frame[0] == 'subnet':
                return frame[1]
        return None

    def _parse_param(words: list[str]) -> tuple[str, Any] | None:
        """Return (key, value) for a recognised parameter, or None on error."""
        if not words:
            return None
        kw = words[0].lower()
        rest = words[1:]

        if kw == 'authoritative':
            return 'authoritative', True

        if kw == 'not' and rest and rest[0].lower() == 'authoritative':
            return 'authoritative', False

        if kw == 'option':
            if not rest:
                return None
            opt_name = rest[0].lower()
            opt_val = ' '.join(v.strip('"') for v in rest[1:]) if len(rest) > 1 else ''
            return f'option {opt_name}', opt_val

        if kw in ('allow', 'deny', 'ignore'):
            if not rest:
                return None
            return f'{kw} {" ".join(rest)}', True

        if kw == 'range':
            # range [dynamic-bootp] start [end]
            return 'range', ' '.join(rest)

        if kw == 'include':
            # include "file"; — silently skip
            return 'include', ' '.join(v.strip('"') for v in rest)

        if kw in _KNOWN_PARAMS:
            val = ' '.join(v.strip('"') for v in rest) if rest else ''
            return kw, val

        return None  # unrecognised keyword

    # ------------------------------------------------------------------ #
    # Main token loop                                                      #
    # ------------------------------------------------------------------ #
    for tok in tokens:

        if tok == ';':
            if not pending:
                continue  # empty statement is fine

            kw = pending[0].lower()
            kind, data = context_stack[-1]

            if kind == 'host':
                if kw == 'hardware' and len(pending) >= 3 and pending[1].lower() == 'ethernet':
                    data['mac'] = pending[2].lower()
                elif kw == 'fixed-address' and len(pending) >= 2:
                    data['ip'] = pending[1]
                elif kw in _KNOWN_HOST_PARAMS:
                    pass  # valid host option, not needed for our output
                else:
                    errors += 1

            elif kind in ('global', 'subnet'):
                parsed = _parse_param(pending)
                if parsed is not None:
                    target = global_params if kind == 'global' else subnets[data]
                    key, val = parsed
                    if key != 'include':   # do not store include directives
                        target[key] = val
                else:
                    errors += 1

            # else: inside 'other' (pool, group, shared-network, …) — ignore content

            pending = []

        elif tok == '{':
            kw = pending[0].lower() if pending else ''

            if kw == 'subnet':
                if len(pending) >= 4 and pending[2].lower() == 'netmask':
                    net_addr = pending[1]
                    netmask = pending[3]
                    subnets[net_addr] = {'netmask': netmask, 'fixed-addresses': {}}
                    context_stack.append(('subnet', net_addr))
                else:
                    errors += 1
                    context_stack.append(('other', None))

            elif kw == 'host':
                if len(pending) >= 2:
                    host_info: dict[str, Any] = {
                        'mac': None,
                        'ip': None,
                        'parent_subnet': _find_parent_subnet(),
                    }
                    context_stack.append(('host', host_info))
                else:
                    errors += 1
                    context_stack.append(('other', None))

            elif kw in ('shared-network', 'group', 'class', 'subclass',
                        'pool', 'failover', 'peer', 'key', 'zone',
                        'on', 'if', 'elsif', 'else'):
                context_stack.append(('other', None))

            elif not pending:
                # Bare { with no preceding keyword
                errors += 1
                context_stack.append(('other', None))

            else:
                errors += 1
                context_stack.append(('other', None))

            pending = []

        elif tok == '}':
            if len(context_stack) <= 1:
                errors += 1   # unmatched closing brace
                pending = []
                continue

            kind, data = context_stack.pop()

            if kind == 'host' and data is not None:
                mac = data.get('mac')
                ip = data.get('ip')
                parent = data.get('parent_subnet')
                if mac and ip:
                    all_hosts.append((parent, mac, ip))

            pending = []

        else:
            pending.append(tok)

    # Unfinished statement at end of file (missing semicolon)
    if pending:
        errors += 1

    # Unclosed blocks (missing closing braces)
    errors += max(0, len(context_stack) - 1)

    # ------------------------------------------------------------------ #
    # Assign collected hosts to their subnets                             #
    # ------------------------------------------------------------------ #
    # Build (IPv4Network, net_addr_str) pairs for membership tests
    subnet_nets: list[tuple[IPv4Network, str]] = []
    for net_addr, subnet_data in subnets.items():
        netmask = subnet_data.get('netmask', '')
        try:
            subnet_nets.append((IPv4Network(f'{net_addr}/{netmask}', strict=False), net_addr))
        except ValueError:
            pass

    for parent, mac, ip in all_hosts:
        # If the host was declared directly inside a subnet block, use that subnet.
        if parent is not None and parent in subnets:
            subnets[parent]['fixed-addresses'][mac] = ip
            continue
        # Otherwise resolve by checking which subnet the fixed-address belongs to.
        try:
            host_ip = IPv4Address(ip)
        except ValueError:
            continue  # ip is a hostname — can't resolve to a subnet here
        for net, net_addr in subnet_nets:
            if host_ip in net:
                subnets[net_addr]['fixed-addresses'][mac] = ip
                break

    # ------------------------------------------------------------------ #
    # Build effective per-subnet parameters (global ← subnet overrides)  #
    # ------------------------------------------------------------------ #
    effective_subnets: dict[str, dict[str, Any]] = {}
    for net_addr, subnet_data in subnets.items():
        fixed = subnet_data.pop('fixed-addresses')
        effective: dict[str, Any] = {**global_params, **subnet_data}
        effective['fixed-addresses'] = fixed
        effective_subnets[net_addr] = effective

    return {
        'errors': errors,
        'global_parameters': global_params,
        'subnets': effective_subnets,
    }
