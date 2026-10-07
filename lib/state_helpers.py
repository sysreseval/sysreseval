import shlex
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, IPv6Network

from SRE.lib_sre import NetScheme0
from net_config import remount_proc_sys, set_ipv6_forward


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


def _hosts_line(ip: str, name: str, domain_extension: str, separator: str) -> str:
    return f"{ip}{separator}{name}{separator}{name}.{domain_extension}"


def _hosts_address(table, container, machine_name: str, index: int, attr: str):
    """Address (without prefix) of one machine/network, from the explicit *table*
    ({machine: [addresses in topology order]}) when given, else from the data container
    attribute *attr*; None when absent."""
    if table is not None:
        addrs = table.get(machine_name, [])
        return str(addrs[index]).split('/')[0] if index < len(addrs) else None
    if container is None:
        return None
    ip_obj = getattr(container, attr, None)
    return None if ip_obj is None else str(ip_obj).split('/')[0]


def hosts_file_content(net_scheme: NetScheme0, domain_extension: str, included=None, ips=None,
                       separator: str = "\t\t", ipv6: bool = False, ips6=None) -> str:
    """Return /etc/hosts lines for the given machines.

    Args:
        net_scheme: the NetScheme0 instance
        domain_extension: domain suffix (e.g. 'example.com')
        included: list of machine names; defaults to get_visibles_machines()
        ips: dict {machine_name: [IPv4Interface|IPv4Address, ...]} one ip per network,
             in the same order as host_interfaces_from_topology().
             If None, addresses are read from net_scheme.data.ips.*
        separator: string placed between fields (default: two tabs)
        ipv6: also write an IPv6 line (right after the IPv4 one) for every machine/network
              that has one, from *ips6* or from net_scheme.data.ips6.*
        ips6: dict {machine_name: [IPv6Interface|IPv6Address, ...]} like *ips* (ipv6=True)
    """
    if included is None:
        included = [m.name for m in net_scheme.get_visibles_machines()]

    machine_nets = net_scheme.host_interfaces_from_topology()
    lines = []

    for machine_name in included:
        nets = machine_nets.get(machine_name, [])
        single = len(nets) == 1

        for i, net_name in enumerate(nets):
            name = machine_name if single else f"{machine_name}_{net_name}"
            ip = _hosts_address(ips, net_scheme.data.ips, machine_name, i, name)
            if ip is not None:
                lines.append(_hosts_line(ip, name, domain_extension, separator))
            if ipv6:
                ip6 = _hosts_address(ips6, getattr(net_scheme.data, 'ips6', None), machine_name, i, name)
                if ip6 is not None:
                    lines.append(_hosts_line(ip6, name, domain_extension, separator))

    return '\n'.join(lines) + '\n' if lines else ''


def create_hosts_file(net_scheme: NetScheme0, domain_extension: str, machine_list=None, included=None, ips=None,
                      separator: str = "\t\t", ipv6: bool = False, ips6=None):
    """Write /etc/hosts to each machine in machine_list.

    Each file starts with the standard loopback entries (127.0.0.1 localhost and
    127.0.1.1 for the machine itself, plus the ::1 / ff02::1 / ff02::2 lines of a
    Debian host when ipv6=True), followed by the lines produced by
    hosts_file_content() for the machines in included.

    Args:
        net_scheme: the NetScheme0 instance
        domain_extension: domain suffix appended to every hostname (e.g. 'example.com')
        machine_list: machines that receive the /etc/hosts file; defaults to get_visibles_machines()
        included: machines whose entries appear in the hosts table; passed through to
                  hosts_file_content() — defaults to get_visibles_machines() when None
        ips: dict {machine_name: [IPv4Interface|IPv4Address, ...]} — see hosts_file_content()
        separator: string placed between fields (default: two tabs)
        ipv6, ips6: see hosts_file_content()
    """
    if machine_list is None:
        machine_list = included if included is not None else [m.name for m in net_scheme.get_visibles_machines()]

    hosts = hosts_file_content(net_scheme=net_scheme, domain_extension=domain_extension, included=included, ips=ips,
                               separator=separator, ipv6=ipv6, ips6=ips6)

    for m in machine_list:
        hosts_start = f"127.0.0.1\t\tlocalhost\n127.0.1.1\t\t{m}\t\t{m}.{domain_extension}\n"
        if ipv6:
            hosts_start += ("::1\t\tlocalhost ip6-localhost ip6-loopback\n"
                            "ff02::1\t\tip6-allnodes\n"
                            "ff02::2\t\tip6-allrouters\n")
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
                            ip: "str | IPv4Interface | IPv4Address | IPv6Interface | IPv6Address" = None,
                            ipv6: bool = False):
    """Setup and (re)launch an idempotent TCP server on *machine*.

    The server listens on *port* — bound to *ip* if provided (the network prefix of an
    ``IPv4Interface`` / ``IPv6Interface`` is stripped; the address decides the family), to
    ``0.0.0.0`` otherwise, or to ``::`` (dual-stack: IPv4 clients too) with ``ipv6=True`` and
    no *ip*. On each client connection it sends *answer* (UTF-8) and closes the socket.
    Calling this function again for the same *port* kills the previous instance before
    relaunching.
    """
    if ip is None:
        bind_addr = "::" if ipv6 else "0.0.0.0"
    elif isinstance(ip, (IPv4Interface, IPv6Interface)):
        bind_addr = str(ip.ip)
    else:
        bind_addr = str(ip).split('/')[0]
    family = "AF_INET6" if ':' in bind_addr else "AF_INET"
    # a '::' listener also accepts IPv4 clients (mapped addresses) unless IPV6_V6ONLY is set
    v6only_line = "    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n" if bind_addr == "::" else ""

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
        f"    s = socket.socket(socket.{family}, socket.SOCK_STREAM)\n"
        "    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"{v6only_line}"
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


def _on_off(flag: bool) -> str:
    return "on" if flag else "off"


def _plain_v6(addr) -> str:
    """IPv6 address without prefix, from a string or an ipaddress object."""
    if isinstance(addr, IPv6Interface):
        return str(addr.ip)
    return str(addr).split('/')[0]


def render_radvd_conf(prefixes: dict, *, rdnss=None, dnssl=None, min_rtr_adv_interval: int = 3,
                      max_rtr_adv_interval: int = 10, adv_autonomous: bool = True, adv_on_link: bool = True,
                      adv_router_addr: bool = False, adv_managed: bool = False,
                      adv_other_config: bool = False) -> str:
    """Text of /etc/radvd.conf announcing *prefixes* (see set_radvd() for the arguments).

    *adv_managed* / *adv_other_config* set the M / O flags of the advertisements
    (``AdvManagedFlag on;`` / ``AdvOtherConfigFlag on;``: addresses / the other parameters are
    to be obtained by DHCPv6); the lines are written only when True.
    """
    if not prefixes:
        raise ValueError("set_radvd: no prefix to advertise")
    blocks = []
    for iface, plist in prefixes.items():
        iface_name = f"eth{iface}" if isinstance(iface, int) else str(iface)
        if isinstance(plist, (str, IPv6Network, IPv6Interface)):
            plist = [plist]
        nets = [IPv6Network(str(p), strict=False) for p in plist]
        if not nets:
            raise ValueError(f"set_radvd: no prefix for {iface_name}")
        for net in nets:
            if adv_autonomous and net.prefixlen != 64:
                raise ValueError(f"set_radvd: {net} is not a /64, SLAAC (adv_autonomous) needs 64-bit prefixes")
        lines = [
            f"interface {iface_name}",
            "{",
            "    AdvSendAdvert on;",
            f"    MinRtrAdvInterval {int(min_rtr_adv_interval)};",
            f"    MaxRtrAdvInterval {int(max_rtr_adv_interval)};",
        ]
        if adv_managed:
            lines.append("    AdvManagedFlag on;")
        if adv_other_config:
            lines.append("    AdvOtherConfigFlag on;")
        for net in nets:
            lines += [
                f"    prefix {net}",
                "    {",
                f"        AdvOnLink {_on_off(adv_on_link)};",
                f"        AdvAutonomous {_on_off(adv_autonomous)};",
                f"        AdvRouterAddr {_on_off(adv_router_addr)};",
                "    };",
            ]
        if rdnss:
            lines.append(f"    RDNSS {' '.join(_plain_v6(a) for a in rdnss)} {{ }};")
        if dnssl:
            lines.append(f"    DNSSL {' '.join(str(d) for d in dnssl)} {{ }};")
        lines.append("};")
        blocks.append('\n'.join(lines))
    return '\n\n'.join(blocks) + '\n'


def set_radvd(net_scheme: NetScheme0, machine: str, prefixes: dict, step: int = 1, *,
              rdnss=None, dnssl=None, min_rtr_adv_interval: int = 3, max_rtr_adv_interval: int = 10,
              adv_autonomous: bool = True, adv_on_link: bool = True, adv_router_addr: bool = False,
              adv_managed: bool = False, adv_other_config: bool = False,
              enable_forwarding: bool = True) -> str:
    """Write /etc/radvd.conf on *machine* and (re)start radvd: the machine then announces the
    given prefixes in router advertisements, so the hosts of those LANs configure themselves
    with SLAAC (see set_slaac_client()) and learn it as their default router.

    Args:
        prefixes: ``{interface: [prefix, ...]}`` — the interface as ``'eth1'`` or ``1``, each
                  prefix as an ``IPv6Network``, an ``IPv6Interface`` (its network is used) or
                  a string; with *adv_autonomous* every prefix must be a /64 (SLAAC).
        rdnss: optional list of recursive DNS server addresses announced in the RAs.
        dnssl: optional list of DNS search domains announced in the RAs.
        min_rtr_adv_interval, max_rtr_adv_interval: radvd timers in seconds (short by
                  default so that hosts configure themselves within seconds of the state).
        adv_autonomous, adv_on_link, adv_router_addr: the prefix flags (radvd.conf(5)).
        adv_managed, adv_other_config: the M and O flags of the advertisements (the hosts
                  are to get their addresses / their other parameters from DHCPv6).
        enable_forwarding: also set net.ipv6.conf.all.forwarding=1 (radvd requires it and a
                  router advertising a prefix forwards anyway); False to leave it as is.

    Returns the radvd.conf text (render_radvd_conf() gives it without applying it).  Hosts must
    accept RAs: Kathara starts every machine with forwarding enabled, which makes the kernel
    ignore RAs unless accept_ra=2 — call set_slaac_client() on them.
    """
    content = render_radvd_conf(prefixes, rdnss=rdnss, dnssl=dnssl, min_rtr_adv_interval=min_rtr_adv_interval,
                                max_rtr_adv_interval=max_rtr_adv_interval, adv_autonomous=adv_autonomous,
                                adv_on_link=adv_on_link, adv_router_addr=adv_router_addr,
                                adv_managed=adv_managed, adv_other_config=adv_other_config)
    net_scheme.file(machine=machine, filename='/etc/radvd.conf', content=content, permissions=0o644, step=step)
    if enable_forwarding:
        set_ipv6_forward(net_scheme, machine, True, step=step)
    net_scheme.cmd(machine, 'systemctl enable radvd', step=step)
    net_scheme.cmd(machine, 'systemctl restart radvd', step=step)
    return content


def set_slaac_client(net_scheme: NetScheme0, machine: str, interfaces=None, step: int = 1):
    """Make *machine* accept router advertisements (SLAAC address + default route) on
    *interfaces* (``'eth0'`` or ``0``; default: every interface of the topology).

    Sets ``accept_ra=2`` and ``autoconf=1`` per interface: Kathara starts the machines of an
    IPv6 lab with forwarding enabled, and a forwarding host ignores RAs unless accept_ra=2.
    It keeps working after set_ipv6_forward(net_scheme, machine, False).
    """
    if interfaces is None:
        m = net_scheme.get_machine(machine)
        interfaces = sorted(a.interface for a in m.net_adapters.values())
    names = [f"eth{i}" if isinstance(i, int) else str(i) for i in interfaces]
    remount_proc_sys(net_scheme, machine)
    for iface in names:
        net_scheme.cmd(machine, f'sysctl -w net.ipv6.conf.{iface}.accept_ra=2', step=step)
        net_scheme.cmd(machine, f'sysctl -w net.ipv6.conf.{iface}.autoconf=1', step=step)
