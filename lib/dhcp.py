import base64
import json
import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
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


# ---------------------------------------------------------------------------
# Running dhcpd (process command line)
# ---------------------------------------------------------------------------

def _parse_dhcpd_cmdlines(output: str) -> list[str] | None:
    """Interfaces of the running IPv4 dhcpd, from one command line per process.

    *output* holds one line per dhcpd process (arguments separated by spaces).  The
    DHCPv6 process (``-6``) is ignored.  Returns ``None`` when no IPv4 dhcpd is running,
    ``["*"]`` when it listens on every interface.
    """
    for line in output.splitlines():
        tokens = line.split()
        if not tokens or not tokens[0].endswith('dhcpd') or '-6' in tokens:
            continue
        return _parse_dhcpd_interfaces('\n'.join(tokens))
    return None


def get_dhcpd_interfaces(grade: Grade0, machine: str, step: int = 1) -> list[str] | None:
    """Return the interfaces the running ``dhcpd`` (IPv4) of *machine* listens on.

    ``None`` when dhcpd is not running, ``["*"]`` when it was started without interface.
    The process table is read directly: the Debian init script (and the systemd unit
    generated from it) can report a failed service while ``dhcpd -4`` is running.
    """
    output, _ = grade.test(
        machine,
        r"for p in $(pidof dhcpd); do tr '\000' ' ' < /proc/$p/cmdline; echo; done",
        step=step, allow_error=True)
    return _parse_dhcpd_cmdlines(output)


# ---------------------------------------------------------------------------
# DHCP relay (isc-dhcp-relay)
# ---------------------------------------------------------------------------

@dataclass
class DhcpRelayParameters:
    """Content of /etc/default/isc-dhcp-relay."""
    servers: list[Any]                                      # SERVERS: addresses of the DHCP servers
    interfaces: list[str] = field(default_factory=list)     # INTERFACES (-i, both directions); empty = all
    options: str = ''                                       # OPTIONS, e.g. "-id eth2 -iu eth1"


def render_dhcp_relay(relay_params: DhcpRelayParameters) -> str:
    """Content of /etc/default/isc-dhcp-relay for *relay_params*."""
    return (f'SERVERS="{" ".join(str(s) for s in relay_params.servers)}"\n'
            f'INTERFACES="{" ".join(relay_params.interfaces)}"\n'
            f'OPTIONS="{relay_params.options}"\n')


def set_dhcp_relay(net_scheme: NetScheme0, machine: str,
                   relay_params: DhcpRelayParameters, step: int = 1) -> None:
    """Write /etc/default/isc-dhcp-relay (content: render_dhcp_relay()) and (re)start the relay
    on *machine*."""
    net_scheme.file(machine, '/etc/default/isc-dhcp-relay', render_dhcp_relay(relay_params), step=step)
    net_scheme.cmd(machine, 'systemctl enable isc-dhcp-relay', step=step)
    net_scheme.cmd(machine, 'systemctl restart isc-dhcp-relay', step=step)


def _parse_dhcrelay_cmdline(cmdline_output: str) -> dict | None:
    """Parse the dhcrelay command line (one token per line, or space separated).

    Returns ``None`` when *cmdline_output* is not a dhcrelay command line (no running relay), else
    ``{'servers': [...], 'interfaces': [...], 'upstream': [...], 'downstream': [...]}``
    where *interfaces* are the ``-i`` (both directions) interfaces, *upstream* the ``-iu``
    ones (towards the servers) and *downstream* the ``-id`` ones (towards the clients).
    All three empty means that dhcrelay listens on every interface.
    """
    IFACE_FLAGS = {'-i': 'interfaces', '-iu': 'upstream', '-id': 'downstream'}
    VALUE_FLAGS = {'-p', '-rp', '-c', '-A', '-m', '-U', '-g', '-pf', '-l', '-u', '-s', '-I'}
    tokens = cmdline_output.split()
    if not tokens or not tokens[0].endswith('dhcrelay'):
        return None
    result = {'servers': [], 'interfaces': [], 'upstream': [], 'downstream': []}
    i = 1  # tokens[0] is the executable
    while i < len(tokens):
        tok = tokens[i]
        if tok in IFACE_FLAGS:
            if i + 1 < len(tokens):
                result[IFACE_FLAGS[tok]].append(tokens[i + 1])
            i += 2
        elif tok in VALUE_FLAGS:
            i += 2
        elif tok.startswith('-'):
            i += 1
        else:
            result['servers'].append(tok)
            i += 1
    return result


def check_running_dhcp_relay(grade: Grade0, machine: str, step: int = 1) -> tuple[bool, dict]:
    """Check whether ``dhcrelay`` is running on *machine*.

    Returns ``(running, args)`` where *args* is the dict of :func:`_parse_dhcrelay_cmdline`
    (empty lists when not running).  ``systemctl is-active isc-dhcp-relay`` is not used:
    the init script always exits 0, even when dhcrelay refused to start.
    """
    output, _ = grade.test(
        machine,
        r"tr '\000' '\n' < /proc/$(pidof -s dhcrelay)/cmdline 2>/dev/null",
        step=step, allow_error=True)
    parsed = _parse_dhcrelay_cmdline(output)
    if parsed is None:
        return False, {'servers': [], 'interfaces': [], 'upstream': [], 'downstream': []}
    return True, parsed


# ---------------------------------------------------------------------------
# Failover state and client leases
# ---------------------------------------------------------------------------

def parse_dhcpd_failover_state(leases_text: str) -> dict[str, dict[str, str]]:
    """Extract the failover states recorded in a dhcpd.leases file.

    Returns ``{peer_name: {'my_state': ..., 'partner_state': ...}}``; dhcpd appends a new
    ``failover peer "name" state { ... }`` block at each transition, the last one wins.
    """
    states: dict[str, dict[str, str]] = {}
    current = None
    for line in leases_text.splitlines():
        m = re.match(r'\s*failover\s+peer\s+"([^"]+)"\s+state\b', line)
        if m:
            current = states[m.group(1)] = {}
            continue
        m = re.match(r'\s*(my|partner)\s+state\s+([a-z-]+)', line)
        if m and current is not None:
            current[f'{m.group(1)}_state'] = m.group(2)
    return states


def get_dhcp_failover_state(grade: Grade0, machine: str, step: int = 1) -> dict[str, dict[str, str]]:
    """Return the failover states of the dhcpd of *machine* (see :func:`parse_dhcpd_failover_state`)."""
    output, _ = grade.test(
        machine, "grep -A 2 '^failover peer' /var/lib/dhcp/dhcpd.leases",
        step=step, allow_error=True)
    return parse_dhcpd_failover_state(output)


def parse_dhclient_leases(leases_text: str) -> list[dict]:
    """Parse dhclient lease files; returns one dict per ``lease { ... }`` block, in file order.

    Keys: ``interface``, ``fixed-address`` and every ``option`` by its name (values as
    strings, quotes removed), plus ``renew`` / ``rebind`` / ``expire``.
    """
    leases = []
    for m in re.finditer(r'lease\s*\{(.*?)\n\}', leases_text, re.DOTALL):
        lease: dict[str, str] = {}
        for statement in m.group(1).split(';'):
            words = statement.split(None, 1)
            if len(words) < 2:
                continue
            key, value = words[0], words[1].strip()
            if key == 'option':
                opt = value.split(None, 1)
                if len(opt) == 2:
                    lease[opt[0]] = opt[1].strip().strip('"')
            else:
                lease[key] = value.strip('"')
        leases.append(lease)
    return leases


def get_dhclient_leases(grade: Grade0, machine: str, step: int = 1) -> list[dict]:
    """Return the leases recorded by dhclient on *machine* (manual runs and ifup), oldest first."""
    output, _ = grade.test(machine, "cat /var/lib/dhcp/dhclient*.leases 2>/dev/null",
                           step=step, allow_error=True)
    return parse_dhclient_leases(output)


# ---------------------------------------------------------------------------
# Classless static routes (option 121, RFC 3442)
# ---------------------------------------------------------------------------

CLASSLESS_ROUTES_OPTION = 'rfc3442-classless-static-routes'   # the name Debian's dhclient gives it
# dhcpd does not know option 121 by name: dhcpd.conf has to declare it before giving it a value
CLASSLESS_ROUTES_DECLARATION = f'option {CLASSLESS_ROUTES_OPTION} code 121 = array of unsigned integer 8;'


def render_classless_routes(routes) -> str:
    """Value of option 121 in dhcpd.conf for *routes*, ``(destination network, router)`` pairs:
    ``24, 198,51,100, 192,0,2,254, 0, 192,0,2,1`` (prefix length, significant bytes of the
    destination, router).  The default route is the network ``0.0.0.0/0``."""
    parts = []
    for destination, gateway in routes:
        destination = IPv4Network(destination)
        length = destination.prefixlen
        significant = destination.network_address.packed[:(length + 7) // 8]
        parts.append(str(length))
        if significant:     # none for the default route
            parts.append(','.join(str(b) for b in significant))
        parts.append(','.join(str(b) for b in IPv4Address(gateway).packed))
    return ', '.join(parts)


def parse_classless_routes(value) -> list[tuple[IPv4Network, IPv4Address]]:
    """Decode a value of option 121 written as integers separated by commas and/or spaces, as in
    dhcpd.conf and in a dhclient lease file (``24,198,51,100,192,0,2,254,0,192,0,2,1``).
    Returns the ``(destination, router)`` pairs, or ``[]`` when the value is malformed."""
    try:
        numbers = [int(n) for n in re.split(r'[\s,]+', str(value or '').strip()) if n]
    except ValueError:
        return []
    routes, i = [], 0
    while i < len(numbers):
        length = numbers[i]
        size = (length + 7) // 8
        fields = numbers[i + 1:i + 5 + size]
        if not 0 <= length <= 32 or len(fields) != size + 4 or any(not 0 <= n <= 255 for n in fields):
            return []
        destination = bytes(fields[:size]) + bytes(4 - size)
        try:
            routes.append((IPv4Network((destination, length)), IPv4Address(bytes(fields[size:]))))
        except ValueError:      # host bits set in the destination
            return []
        i += 5 + size
    return routes


# ---------------------------------------------------------------------------
# Active probe (lib/dhcp_probe.py run inside a container)
# ---------------------------------------------------------------------------

DHCP_PROBE_PATH = '/usr/local/sbin/dhcp_probe.py'


@dataclass
class DhcpProbeReply:
    """One BOOTREPLY seen by the probe for a given query."""
    interface: str
    query: str
    msg_type: str | None                         # 'OFFER', 'ACK', 'NAK'
    yiaddr: IPv4Address | None = None
    giaddr: IPv4Address | None = None            # relay agent address (0.0.0.0 → None)
    server_id: IPv4Address | None = None         # option 54
    src_ip: IPv4Address | None = None
    subnet_mask: IPv4Address | None = None
    routers: list[IPv4Address] = field(default_factory=list)
    dns_servers: list[IPv4Address] = field(default_factory=list)
    domain_name: str | None = None
    lease_time: int | None = None
    # option 121 (RFC 3442): (destination, router) pairs, the default route being 0.0.0.0/0
    classless_routes: list[tuple[IPv4Network, IPv4Address]] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def install_dhcp_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy lib/dhcp_probe.py to DHCP_PROBE_PATH on *machine* (usually a hidden one)."""
    script = Path(__file__).with_name('dhcp_probe.py').read_text()
    net_scheme.file(machine, DHCP_PROBE_PATH, script, permissions=0o755, step=step)


def dhcp_probe_query(query_id: str, chaddr, msg_type: str = 'discover', lease: int | None = None,
                     requested=None, late: bool = False, hostname: str | None = None) -> dict:
    """Build one query of a probe spec (see lib/dhcp_probe.py).

    *chaddr* is the client MAC address announced in the query.  ``msg_type='request'``
    with *requested* sends an INIT-REBOOT DHCPREQUEST (an authoritative server answers
    DHCPNAK when the address does not belong to the network).  *late* queries are sent
    after the others: use it for a second DISCOVER of the same *chaddr*.
    """
    query = {'id': query_id, 'type': msg_type, 'chaddr': str(chaddr).replace('-', ':').lower()}
    if lease is not None:
        query['lease'] = lease
    if requested is not None:
        query['requested'] = str(requested)
    if late:
        query['late'] = True
    if hostname:
        query['hostname'] = hostname
    return query


def dhcp_probe_command(spec: dict) -> str:
    """Shell command running the probe with *spec*; depends on *spec* only (stable across passes)."""
    encoded = base64.urlsafe_b64encode(
        json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).decode()
    return f'python3 {DHCP_PROBE_PATH} {encoded}'


def _probe_ip(value) -> IPv4Address | None:
    try:
        ip = IPv4Address(value)
    except ValueError:
        return None
    return None if int(ip) == 0 else ip


def _probe_routes(value) -> list[tuple[IPv4Network, IPv4Address]]:
    routes = []
    for item in value if isinstance(value, list) else []:
        try:
            destination, gateway = item
            routes.append((IPv4Network(destination, strict=False), IPv4Address(gateway)))
        except (TypeError, ValueError):
            continue
    return routes


def parse_dhcp_probe(output: str) -> dict[str, dict[str, list[DhcpProbeReply]]]:
    """Parse the JSON printed by the probe into ``{interface: {query_id: [DhcpProbeReply]}}``.

    Returns ``{}`` on empty or malformed output.
    """
    try:
        document = json.loads(output)
        replies = document['replies']
    except (ValueError, KeyError, TypeError):
        return {}
    result: dict[str, dict[str, list[DhcpProbeReply]]] = {}
    if not isinstance(replies, dict):
        return result
    for iface, queries in replies.items():
        if not isinstance(queries, dict):
            continue
        result[iface] = {}
        for query_id, items in queries.items():
            parsed = []
            for r in items if isinstance(items, list) else []:
                if not isinstance(r, dict):
                    continue
                lease_time = r.get('lease_time')
                parsed.append(DhcpProbeReply(
                    interface=iface, query=query_id, msg_type=r.get('msg_type'),
                    yiaddr=_probe_ip(r.get('yiaddr')), giaddr=_probe_ip(r.get('giaddr')),
                    server_id=_probe_ip(r.get('server_id')), src_ip=_probe_ip(r.get('src_ip')),
                    subnet_mask=_probe_ip(r.get('subnet_mask')),
                    routers=[ip for ip in map(_probe_ip, r.get('routers') or []) if ip],
                    dns_servers=[ip for ip in map(_probe_ip, r.get('dns_servers') or []) if ip],
                    domain_name=r.get('domain_name'),
                    lease_time=lease_time if isinstance(lease_time, int) else None,
                    classless_routes=_probe_routes(r.get('classless_routes')),
                    raw=r))
            result[iface][query_id] = parsed
    return result


def dhcp_probe(grade: Grade0, machine: str, spec: dict, step: int = 1,
               timeout: int = 30) -> dict[str, dict[str, list[DhcpProbeReply]]]:
    """Run the probe installed on *machine* and return its replies.

    *spec* is ``{'interfaces': {'eth0': [dhcp_probe_query(...), ...]}, 'wait': 2.5,
    'late_wait': 1.5}``.  It must be built from lab data only (never from test results)
    so that the command is identical on every grade pass.
    """
    output, _ = grade.test(machine, dhcp_probe_command(spec), step=step, timeout=timeout, allow_error=True)
    return parse_dhcp_probe(output)
