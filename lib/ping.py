from ipaddress import IPv4Address, IPv4Interface
from typing import Union, Optional, Dict

from SRE.lib_sre import Grade0
from net_config import NetConfigEntry


def _resolve_src_machine(arg: Union[str, IPv4Address], get_nc) -> str:
    """Resolve arg to the machine name to run the ping from.

    - IPv4Address or valid IPv4 string → reverse-lookup in net_config (get_nc called)
    - "machine_name:interface"         → machine name is the left part (get_nc called to validate)
    - "machine_name"                   → used directly (get_nc called to validate)
    """
    if isinstance(arg, IPv4Interface):
        ip_str = str(arg.ip)
    elif isinstance(arg, IPv4Address):
        ip_str = str(arg)
    else:
        try:
            ip_str = str(IPv4Address(arg))
        except ValueError:
            ip_str = None

    if ip_str is not None:
        for machine_name, ifaces in get_nc().items():
            for iface_list, _routes in ifaces:
                for iface in iface_list:
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


def _resolve_dest_ip(arg: Union[str, IPv4Address], get_nc) -> str:
    """Resolve arg to the destination IP string.

    - IPv4Address or valid IPv4 string → returned directly (get_nc NOT called)
    - "machine_name:interface"         → IP at that interface index (get_nc called)
    - "machine_name"                   → first interface IP (get_nc called)
    """
    if isinstance(arg, IPv4Interface):
        return str(arg.ip)
    elif isinstance(arg, IPv4Address):
        return str(arg)

    try:
        return str(IPv4Address(arg))
    except ValueError:
        pass

    if ':' in arg:
        machine_name, iface = arg.split(':', 1)
        idx = int(iface[3:]) if iface.startswith('eth') else int(iface)
        nc = get_nc()
        if machine_name not in nc:
            raise ValueError(f"Machine '{machine_name}' not found in net_config")
        ifaces = nc[machine_name]
        if idx >= len(ifaces):
            raise ValueError(f"Interface index {idx} out of range for machine '{machine_name}'")
        iface_list, _ = ifaces[idx]
        return str(iface_list[0].ip)

    nc = get_nc()
    if arg not in nc:
        raise ValueError(f"Machine '{arg}' not found in net_config")
    iface_list, _ = nc[arg][0]
    return str(iface_list[0].ip)


def eval_ping(grade: Grade0, src: Union[str, IPv4Address], dest: Union[str, IPv4Address],
              step: int = 1, net_config: Optional[Dict[str, NetConfigEntry]] = None) -> bool:
    """Ping dest from src machine; return True if successful ("bytes from" in output).

    src and dest can each be:
    - An IPv4Address object or a valid IPv4 string → used directly (no net_config needed for dest)
    - "machine_name:interface"  (e.g. "routeur1:1" or "routeur1:eth1") → resolved via net_config
    - "machine_name"            → resolved via net_config

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
    dest_ip = _resolve_dest_ip(dest, get_nc)

    output, _code = grade.test(src_machine, f'ping -c 1 -w 1 {dest_ip}', step=step)
    return 'bytes from' in output
