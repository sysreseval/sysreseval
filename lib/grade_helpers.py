import re
from ipaddress import IPv4Address, IPv4Interface
from typing import Union

from SRE.lib_sre import Grade0


def test_dig(grade: Grade0, machine_name: str,
             server_ip: Union[str, IPv4Address, IPv4Interface], *,
             proto: str = "udp", port: int = 53, request: str,
             timeout: int = 2, step: int = 1) -> tuple[str, int]:
    """Run a ``dig +short`` query from a container and return ``(stdout, exit_code)``.

    The command issued is::

        dig +time={timeout-1} +tries=1 +short [+tcp] -p {port} @{server_ip} {request}

    Args:
        grade:        the Grade0 instance — required so the command is
                      registered in the first pass and re-fetched in the second.
        machine_name: container the dig command is executed from.
        server_ip:    target DNS server. Accepts a dotted-quad string, an
                      ``IPv4Address`` or an ``IPv4Interface`` (the prefix is
                      stripped). Substituted as ``@server_ip``.
        proto:        ``"udp"`` (default) or ``"tcp"``; TCP adds ``+tcp``.
        port:         server port (default 53).
        request:      dig query body — everything that follows ``@server``,
                      e.g. ``"www.example.com A"`` or ``"example.com SOA"``.
        timeout:      total timeout in seconds passed to ``grade.test()`` (default 2).
                      ``dig`` itself is given ``+time={timeout-1}`` so it gives up
                      one second before the outer test, leaving room for clean exit.
        step:         step number passed to ``grade.test()`` (default 1).

    Returns:
        ``(stdout, exit_code)`` — stdout is stripped. On time-outs or unreachable
        servers the output may be empty; the exit code from ``grade.test()`` is
        passed through unchanged. Errors are not recorded (``allow_error=True``).
    """
    if isinstance(server_ip, IPv4Interface):
        server_ip_str = str(server_ip.ip)
    elif isinstance(server_ip, IPv4Address):
        server_ip_str = str(server_ip)
    else:
        server_ip_str = server_ip
    proto_flag = " +tcp" if proto.lower() == "tcp" else ""
    cmd = (f"dig +time={timeout - 1} +tries=1 +short{proto_flag} "
           f"-p {port} @{server_ip_str} {request}")
    out, code = grade.test(machine_name, cmd,
                           step=step, timeout=timeout, allow_error=True)
    return (out or "").strip(), code


def eval_tcp_server(grade: Grade0, machine_name: str, server_name: str,
                    step: int = 1) -> list[int] | None:
    """Check that a process matching server_name is running on machine_name and
    return the TCP ports it listens on.

    Args:
        grade:        the Grade0 instance.
        machine_name: name of the virtual machine to inspect.
        server_name:  substring to match against running process names (ps output).
        step:         step number passed to grade.test() (default: 1).

    Returns:
        A list of TCP port numbers in LISTEN state used by the process,
        or None if no matching process is found.
    """
    # All grade.test() calls must be made unconditionally so they are registered
    # in the first (registration) pass and carry real results in the second pass.
    pids_out, pids_code = grade.test(
        machine_name=machine_name,
        command=f"pgrep -f {server_name}",
        step=step,
    )
    ss_out, _ = grade.test(
        machine_name=machine_name,
        command=f"ss -tlnp",
        step=step,
    )

    if pids_code != 0:
        return None

    pids = set(pids_out.split())
    if not pids:
        return None

    ports = []
    for line in ss_out.splitlines():
        # ss -tlnp output has a "users:(("name",pid=NNN,...))" field
        if "LISTEN" not in line:
            continue
        if not any(f"pid={pid}" in line for pid in pids):
            continue
        # Extract port from the local address column (e.g. 0.0.0.0:443 or *:80)
        addr_m = re.search(r'\s+\*?[\d.:]+:(\d+)\s+', line)
        if addr_m:
            ports.append(int(addr_m.group(1)))

    return sorted(set(ports))
