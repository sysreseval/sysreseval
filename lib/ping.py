from ipaddress import ip_address, IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from typing import Union, Optional, Dict

from SRE.lib_sre import Grade0
from net_config import NetConfigEntry

_IFACE_TYPES = (IPv4Interface, IPv6Interface)
_ADDR_TYPES = (IPv4Address, IPv6Address)
IPArg = Union[str, IPv4Address, IPv6Address, IPv4Interface, IPv6Interface]


def _literal_ip(arg) -> Optional[str]:
    """The address as a string when *arg* is an address object or an IPv4/IPv6 literal, else None.

    Checked before the ``machine:iface`` syntax: an IPv6 literal contains colons too.
    """
    if isinstance(arg, _IFACE_TYPES):
        return str(arg.ip)
    if isinstance(arg, _ADDR_TYPES):
        return str(arg)
    try:
        return str(ip_address(arg))
    except ValueError:
        return None


def _first_ip(iface_list, ipv6: bool, what: str) -> str:
    """First address of the requested family in a net_config address list."""
    version = 6 if ipv6 else 4
    for iface in iface_list:
        if iface.version == version:
            return str(iface.ip)
    raise ValueError(f"{what} has no IPv{version} address in net_config (ipv6={ipv6})")


def _resolve_src_machine(arg: IPArg, get_nc) -> str:
    """Resolve arg to the machine name to run the ping from.

    - address object or IPv4/IPv6 literal → reverse-lookup in net_config (get_nc called)
    - "machine_name:interface"            → machine name is the left part (get_nc called to validate)
    - "machine_name"                      → used directly (get_nc called to validate)
    """
    ip_str = _literal_ip(arg)

    if ip_str is not None:
        for machine_name, ifaces in get_nc().items():
            for entry in ifaces:
                if not isinstance(entry, tuple):
                    continue
                for iface in entry[0]:
                    if str(iface.ip) == ip_str:
                        return machine_name
        raise ValueError(f"No machine with IP {ip_str} found in net_config")

    if ':' in arg:
        machine_name, _ = arg.split(':', 1)
    else:
        machine_name = arg

    if machine_name not in get_nc():
        raise ValueError(f"Machine '{machine_name}' not found in net_config")
    return machine_name


def _resolve_dest_ip(arg: IPArg, get_nc, ipv6: bool = False) -> str:
    """Resolve arg to the destination IP string.

    - address object or IPv4/IPv6 literal → returned directly (get_nc NOT called)
    - "machine_name:interface"            → first IPv4 (IPv6 with ipv6=True) address at that
                                            interface index (get_nc called)
    - "machine_name"                      → first IPv4 (IPv6 with ipv6=True) address of the
                                            first interface (get_nc called)
    """
    ip_str = _literal_ip(arg)
    if ip_str is not None:
        return ip_str

    if ':' in arg:
        machine_name, iface = arg.split(':', 1)
        idx = int(iface[3:]) if iface.startswith('eth') else int(iface)
        nc = get_nc()
        if machine_name not in nc:
            raise ValueError(f"Machine '{machine_name}' not found in net_config")
        ifaces = nc[machine_name]
        if idx >= len(ifaces):
            raise ValueError(f"Interface index {idx} out of range for machine '{machine_name}'")
        entry = ifaces[idx]
        if not isinstance(entry, tuple):
            raise ValueError(f"Interface {idx} of machine '{machine_name}' has no static address in net_config")
        return _first_ip(entry[0], ipv6, f"{machine_name}:eth{idx}")

    nc = get_nc()
    if arg not in nc:
        raise ValueError(f"Machine '{arg}' not found in net_config")
    entry = nc[arg][0]
    if not isinstance(entry, tuple):
        raise ValueError(f"Interface 0 of machine '{arg}' has no static address in net_config")
    return _first_ip(entry[0], ipv6, arg)


def eval_ping(grade: Grade0, src: IPArg, dest: IPArg,
              step: int = 1, net_config: Optional[Dict[str, NetConfigEntry]] = None,
              count: int = 1, deadline: int = 1, allow_error: bool = False,
              ipv6: bool = False) -> bool:
    """Ping dest from src machine; return True if successful ("bytes from" in output).

    count / deadline are passed to ``ping -c count -w deadline`` (default: one packet,
    one second -- raise them for multi-hop paths with cold ARP caches).  With
    allow_error=True a failed ping is not recorded as an error in the archive (use it
    when unreachability is an expected outcome rather than a test malfunction).

    src and dest can each be:
    - An IPv4Address / IPv6Address (or Interface) object, or a valid IPv4/IPv6 literal
      → used directly (no net_config needed for dest; the literal decides the family)
    - "machine_name:interface"  (e.g. "routeur1:1" or "routeur1:eth1") → resolved via net_config
    - "machine_name"            → resolved via net_config

    ipv6=True picks the IPv6 address of a dest given by machine name (default: its IPv4
    address) in a dual-stack net_config; ``ping`` itself handles both families.

    net_config is only fetched when actually needed for name resolution.
    If not provided, falls back to grade.net_scheme.net_config.
    Raises ValueError on any resolution failure.
    """
    def get_nc():
        nc = net_config if net_config is not None else getattr(grade.net_scheme, 'net_config', None)
        if nc is None:
            raise ValueError("net_config is required for eval_ping but is not available")
        return nc

    src_machine = _resolve_src_machine(src, get_nc)
    dest_ip = _resolve_dest_ip(dest, get_nc, ipv6=ipv6)

    command = f'ping -c {count} -w {deadline} {dest_ip}'
    if allow_error:
        output, _code = grade.test(src_machine, command, step=step, allow_error=True)
    else:
        output, _code = grade.test(src_machine, command, step=step)
    return 'bytes from' in output
