import shlex
from ipaddress import IPv4Address, IPv4Interface

from SRE.lib_sre import NetScheme0


def set_unbound_server(net_scheme: NetScheme0, machine: str):
    """Write a permissive Unbound DNS config and start the service on *machine*."""
    set_basic_unbound_server(net_scheme=net_scheme, machine=machine)


def set_basic_unbound_server(net_scheme: NetScheme0, machine: str):
    """Write /etc/unbound/unbound.conf (listen on 0.0.0.0, allow all) and start unbound on *machine*."""
    net_scheme.file(machine=machine, filename='/etc/unbound/unbound.conf', content="""
# Unbound configuration file for Debian.
#
# See the unbound.conf(5) man page.
#
# See /usr/share/doc/unbound/examples/unbound.conf for a commented
# reference config file.
#
# The following line includes additional configuration files from the
# /etc/unbound/unbound.conf.d directory.
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 allow
""")
    net_scheme.cmd(machine, "systemctl start unbound")


def set_nat_gateway(net_scheme: NetScheme0, machine: str):
    """Add an iptables MASQUERADE rule on *machine*'s bridged interface.

    The machine must have been declared with ``bridged=True``; Kathara appends
    the bridged interface as the next ``eth{N}`` after all topology-defined
    adapters (i.e. its index equals the highest assigned interface number + 1).
    """
    m = net_scheme.get_machine(machine)
    iface_numbers = [a.interface for a in m.net_adapters.values()]
    bridged_iface = (max(iface_numbers) + 1) if iface_numbers else 0
    net_scheme.cmd(machine,
                   f"sh -c 'iptables -t nat -C POSTROUTING -o eth{bridged_iface} -j MASQUERADE 2>/dev/null"
                   f" || iptables -t nat -A POSTROUTING -o eth{bridged_iface} -j MASQUERADE'")


def hosts_file_content(net_scheme: NetScheme0, domain_extension: str, included=None, ips=None,
                       separator: str = "\t\t") -> str:
    """Return /etc/hosts lines for the given machines.

    Args:
        net_scheme: the NetScheme0 instance
        domain_extension: domain suffix (e.g. 'example.com')
        included: list of machine names; defaults to get_visibles_machines()
        ips: dict {machine_name: [IPv4Interface|IPv4Address, ...]} one ip per network,
             in the same order as host_interfaces_from_topology().
             If None, addresses are read from net_scheme.data.ips.*
        separator: string placed between fields (default: two tabs)
    """
    if included is None:
        included = [m.name for m in net_scheme.get_visibles_machines()]

    machine_nets = net_scheme.host_interfaces_from_topology()
    lines = []

    for machine_name in included:
        nets = machine_nets.get(machine_name, [])
        single = len(nets) == 1

        if ips is not None:
            addrs = ips.get(machine_name, [])
            for i, net_name in enumerate(nets):
                ip = str(addrs[i]).split('/')[0] if i < len(addrs) else None
                if ip is None:
                    continue
                if single:
                    lines.append(f"{ip}{separator}{machine_name}{separator}{machine_name}.{domain_extension}")
                else:
                    lines.append(
                        f"{ip}{separator}{machine_name}_{net_name}{separator}{machine_name}_{net_name}.{domain_extension}")
        else:
            for net_name in nets:
                attr = machine_name if single else f"{machine_name}_{net_name}"
                ip_obj = getattr(net_scheme.data.ips, attr, None)
                if ip_obj is None:
                    continue
                ip = str(ip_obj).split('/')[0]
                if single:
                    lines.append(f"{ip}{separator}{machine_name}{separator}{machine_name}.{domain_extension}")
                else:
                    lines.append(
                        f"{ip}{separator}{machine_name}_{net_name}{separator}{machine_name}_{net_name}.{domain_extension}")

    return '\n'.join(lines) + '\n' if lines else ''


def create_hosts_file(net_scheme: NetScheme0, domain_extension: str, machine_list=None, included=None, ips=None,
                      separator: str = "\t\t"):
    """Write /etc/hosts to each machine in machine_list.

    Each file starts with the standard loopback entries (127.0.0.1 localhost and
    127.0.1.1 for the machine itself), followed by the lines produced by
    hosts_file_content() for the machines in included.

    Args:
        net_scheme: the NetScheme0 instance
        domain_extension: domain suffix appended to every hostname (e.g. 'example.com')
        machine_list: machines that receive the /etc/hosts file; defaults to get_visibles_machines()
        included: machines whose entries appear in the hosts table; passed through to
                  hosts_file_content() — defaults to get_visibles_machines() when None
        ips: dict {machine_name: [IPv4Interface|IPv4Address, ...]} — see hosts_file_content()
        separator: string placed between fields (default: two tabs)
    """
    if machine_list is None:
        machine_list = included if included is not None else [m.name for m in net_scheme.get_visibles_machines()]

    hosts = hosts_file_content(net_scheme=net_scheme, domain_extension=domain_extension, included=included, ips=ips,
                               separator=separator)

    for m in machine_list:
        hosts_start = f"127.0.0.1\t\tlocalhost\n127.0.1.1\t\t{m}\t\t{m}.{domain_extension}\n"
        net_scheme.file(machine=m, filename='/etc/hosts', content=hosts_start + hosts, permissions=0o0644,
                        owner="root:root")


def change_password(net_scheme: NetScheme0, machine: str, username: str, password: str):
    """Set *username*'s password on *machine* via chpasswd.

    The password is written to a temporary file (never passed on the command line).
    """
    # Write "username:password" to a file so the password never appears in a shell command.
    net_scheme.file(machine=machine, filename='/tmp/.sre_chpasswd',
                    content=f'{username}:{password}\n', permissions=0o600)
    net_scheme.cmd(machine, 'sh -c "chpasswd < /tmp/.sre_chpasswd; rm -f /tmp/.sre_chpasswd"')


def create_user(net_scheme: NetScheme0, machine: str, username: str, password: str, uid: int = None, gid: int = None, shell: str = "/bin/bash"):
    """Create *username* on *machine* (if not already present) and set its password.

    Uses ``useradd -m`` with optional *uid*/*gid* and login *shell*.  The password is written to a
    temporary file; the username is passed via an environment variable to prevent shell injection.
    """
    # Write "username:password" to a file so the password never appears in a shell command.
    net_scheme.file(machine=machine, filename='/tmp/.sre_chpasswd',
                    content=f'{username}:{password}\n', permissions=0o600)
    useradd_opts = f" -s {shlex.quote(shell)}"
    if uid is not None:
        useradd_opts += f" -u {int(uid)}"
    if gid is not None:
        useradd_opts += f" -g {int(gid)}"
    # Pass the username via an env var so no user-controlled text appears inside the sh -c string.
    # "$SRE_USER" is double-quoted in the shell command to prevent word-splitting and glob expansion.
    net_scheme.cmd(machine,
                   f"env SRE_USER={shlex.quote(username)} "
                   f"sh -c 'id \"$SRE_USER\" >/dev/null 2>&1"
                   f" || useradd{useradd_opts} -m -k /etc/skel \"$SRE_USER\";"
                   f" chpasswd < /tmp/.sre_chpasswd; rm -f /tmp/.sre_chpasswd'")


def setup_simple_tcp_server(net_scheme: NetScheme0, machine: str, port: int, answer: str,
                            ip: "str | IPv4Interface | IPv4Address" = None):
    """Setup and (re)launch an idempotent TCP server on *machine*.

    The server listens on *port* — bound to *ip* if provided (the network prefix of an
    ``IPv4Interface`` is stripped), or to ``0.0.0.0`` otherwise. On each client connection
    it sends *answer* (UTF-8) and closes the socket. Calling this function again for the
    same *port* kills the previous instance before relaunching.
    """
    if ip is None:
        bind_addr = "0.0.0.0"
    elif isinstance(ip, IPv4Interface):
        bind_addr = str(ip.ip)
    else:
        bind_addr = str(ip).split('/')[0]

    script_path = f"/usr/local/sbin/sre_tcp_server_{port}.py"
    answer_file = f"/var/lib/sre_tcp_server_{port}.answer"
    log_file = f"/var/log/sre_tcp_server_{port}.log"
    pid_file = f"/run/sre_tcp_server_{port}.pid"

    net_scheme.file(machine=machine, filename=answer_file, content=answer, permissions=0o644)

    # The script double-forks AND closes the stdio fds inherited from docker exec —
    # otherwise exec_run keeps streaming and the state op hangs forever. After the
    # second fork, fds 0/1/2 are reopened on /dev/null (stdin) and the per-port log
    # file (stdout/stderr), so binding/startup failures land in the log. The daemon
    # also writes its PID to a per-port file so the launcher can kill the previous
    # instance without using `pkill -f` (which would match the launcher's own sh -c
    # argument and kill the shell before the python3 command runs).
    script_content = (
        "#!/usr/bin/env python3\n"
        "import os, socket, traceback\n"
        "if os.fork() != 0: os._exit(0)\n"
        "os.setsid()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "# detach from docker exec's stdio so exec_run can return\n"
        "for fd in (0, 1, 2):\n"
        "    try: os.close(fd)\n"
        "    except OSError: pass\n"
        "os.open(os.devnull, os.O_RDONLY)  # fd 0\n"
        f"_log = os.open({log_file!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)  # fd 1\n"
        "os.dup2(_log, 2)  # fd 2 = log\n"
        f"with open({pid_file!r}, 'w') as _pf: _pf.write(str(os.getpid()))\n"
        "try:\n"
        f"    with open({answer_file!r}, 'rb') as f:\n"
        "        answer = f.read()\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"    s.bind(({bind_addr!r}, {int(port)}))\n"
        "    s.listen(16)\n"
        "    while True:\n"
        "        conn, _ = s.accept()\n"
        "        try:\n"
        "            conn.sendall(answer)\n"
        "        finally:\n"
        "            conn.close()\n"
        "except Exception:\n"
        "    traceback.print_exc()\n"
        "    os._exit(1)\n"
    )
    net_scheme.file(machine=machine, filename=script_path, content=script_content, permissions=0o755)

    quoted_script = shlex.quote(script_path)
    quoted_pidfile = shlex.quote(pid_file)
    # If a previous instance left a PID file, kill it and give the kernel a moment
    # to release the port; ignore stale PIDs. Then launch the new daemon. The script
    # daemonizes itself, so this command returns immediately.
    net_scheme.cmd(machine,
                   f"sh -c '[ -f {quoted_pidfile} ] && kill $(cat {quoted_pidfile}) 2>/dev/null; "
                   f"sleep 0.2; "
                   f"python3 {quoted_script}'")
