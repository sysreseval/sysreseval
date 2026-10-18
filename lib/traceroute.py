"""Traceroute / TTL helpers of the traceroute lab (``lab/sre/_DRAFT_misc/traceroute.py``), IPv4 only.

Pure functions: the network names of the hidden lines, the arithmetic of a routing loop (which router
answers a probe of a given TTL, how many times a packet crosses a router), ``ping`` / ``traceroute``
command builders and parsers of their outputs (iputils 20221126 and traceroute 2.1.2 of Debian 12),
the command removing every trace tool from a container, the UDP probe of a traceroute emulated with
``nc`` and the ICMP lines of a ``tcpdump`` / ``tshark`` capture, nftables texts (a router dropping its
own ICMP errors, a server dropping or rejecting UDP, a firewall dropping the echo requests of a small
TTL) and the scoring of a path typed by a student.
Fixtures in ``tests/mock_data/traceroute/`` captured on 2026-10-17 in the containers of the lab
(``sysreseval/base:1.30``: iputils 20221126, traceroute 2.1.2, tcpdump 4.99, Linux 6.12 host).
"""
import re
from ipaddress import IPv4Address, IPv4Interface, ip_address
from typing import Any, Dict, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0

ICMP_TIME_EXCEEDED = (11, 0)      # type, code of "time to live exceeded in transit"
ICMP_PORT_UNREACHABLE = (3, 3)    # what ends a UDP traceroute
DEFAULT_TTL = 64                  # net.ipv4.ip_default_ttl of Linux
PROBE_PORT = 33434                # first UDP port of traceroute: "unlikely" to be open
TIME_EXCEEDED_MESSAGE = 'Time to live exceeded'

#: alternatives groups of the Debian ``traceroute`` package (``/usr/bin/<name>.db`` behind each)
TRACE_ALTERNATIVES = ('traceroute', 'traceroute6', 'tcptraceroute', 'lft', 'traceproto')
#: the tools a student must not find on the machine without traceroute (``busybox`` has a traceroute
#: applet, ``tracert6`` is the IPv6 traceroute of ndisc6)
TRACE_TOOLS = ('traceroute', 'traceroute6', 'tcptraceroute', 'lft', 'traceproto', 'tracepath', 'tracepath6',
               'mtr', 'mtr-packet', 'dublin-traceroute', 'hping3', 'nmap', 'nping', 'busybox', 'tracert6')
TRACE_TOOL_GLOBS = ('/usr/bin/*traceroute*', '/usr/sbin/*traceroute*', '/usr/bin/lft*', '/usr/bin/traceproto*',
                    '/usr/bin/tracepath*', '/usr/bin/mtr*', '/usr/sbin/hping3', '/usr/bin/hping3',
                    '/usr/bin/nmap', '/usr/bin/nping', '/usr/bin/busybox', '/usr/bin/tracert6')


# ---------------------------------------------------------------------------
# topology and arithmetic
# ---------------------------------------------------------------------------

def link_name(i: int, j: int, prefix: str = 'c') -> str:
    """Name of the network between the routers *i* and *j* (``c12`` for h1 - h2; another *prefix*
    for another hidden line)."""
    a, b = sorted((int(i), int(j)))
    return f"{prefix}{a}{b}"


def hop_at(ttl: int, cycle: Sequence[str]) -> str:
    """The router at hop *ttl* of a routing loop entered at ``cycle[0]``: a packet sent with that
    TTL is dropped there (it arrives with TTL 1) and the ICMP time exceeded comes from it."""
    return cycle[(int(ttl) - 1) % len(cycle)]


def loop_passages(ttl0: int, cycle_len: int, position: int) -> List[int]:
    """The TTL values with which a packet sent with *ttl0* arrives at the router at *position*
    (0-based) of a loop of *cycle_len* routers entered at position 0: ``loop_passages(64, 3, 1)``
    is ``[63, 60, ..., 3]`` (21 passages on r2, the last one with TTL 3)."""
    n = int(cycle_len)
    return [int(ttl0) - k + 1 for k in range(int(position) + 1, int(ttl0) + 1, n)]


def reply_ttl(routers: int, default_ttl: int = DEFAULT_TTL) -> int:
    """TTL of an echo reply that crossed *routers* routers on its way back."""
    return int(default_ttl) - int(routers)


def min_ttl_to_reach(routers: int) -> int:
    """Smallest initial TTL that reaches a destination behind *routers* routers."""
    return int(routers) + 1


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def ping_ttl_cmd(dest, ttl: int = None, count: int = 1, wait: int = 1, deadline: int = None,
                 record_route: bool = False) -> str:
    """``ping -4 -n [-t TTL] [-R] -c COUNT -W WAIT -w DEADLINE DEST`` (numeric, one second per
    unanswered probe, *deadline* = count + wait by default)."""
    options = ['-4', '-n']
    if ttl is not None:
        options += ['-t', str(int(ttl))]
    if record_route:
        options.append('-R')
    total = int(deadline) if deadline is not None else int(count) + int(wait)
    options += ['-c', str(int(count)), '-W', str(int(wait)), '-w', str(total)]
    return "ping " + " ".join(options) + f" {dest}"


_TRACEROUTE_METHOD_FLAG = {'udp': '', 'icmp': '-I', 'tcp': '-T'}


def traceroute_cmd(dest, method: str = 'udp', port: int = None, max_hops: int = 6, queries: int = 1,
                   wait: int = 1, first: int = None) -> str:
    """``traceroute -4 -n -q QUERIES -w WAIT -m MAX_HOPS [-I|-T] [-p PORT] [-f FIRST] DEST``."""
    if method not in _TRACEROUTE_METHOD_FLAG:
        raise ValueError(f"unknown traceroute method {method!r}")
    options = ['-4', '-n', '-q', str(int(queries)), '-w', str(int(wait)), '-m', str(int(max_hops))]
    flag = _TRACEROUTE_METHOD_FLAG[method]
    if flag:
        options.append(flag)
    if port is not None:
        options += ['-p', str(int(port))]
    if first is not None:
        options += ['-f', str(int(first))]
    return "traceroute " + " ".join(options) + f" {dest}"


def nc_udp_cmd(dest, port: int = PROBE_PORT, wait: int = 1, ttl: int = None) -> str:
    """``printf x | nc -u -w WAIT [-M TTL] DEST PORT``: one UDP datagram to an unlikely port, the probe
    of a traceroute emulated without ICMP; ``-M`` (OpenBSD netcat 1.219 of Debian 12) sets the TTL of
    the datagram (otherwise ``net.ipv4.ip_default_ttl`` or an nftables ``ip ttl set`` rule does), and
    ``nc`` quits after *wait* seconds without an answer. It prints nothing, whether a router answers
    *time exceeded* (not reported to a UDP socket without ``IP_RECVERR``) or the destination answers
    *port unreachable*: the answers are read in a ``tcpdump`` / ``tshark`` capture."""
    ttl_option = f" -M {int(ttl)}" if ttl is not None else ""
    return f"printf x | nc -u -w {int(wait)}{ttl_option} {dest} {int(port)}"


def remove_tools_cmd(tools: Sequence[str] = TRACE_TOOLS, alternatives: Sequence[str] = TRACE_ALTERNATIVES,
                     globs: Sequence[str] = TRACE_TOOL_GLOBS) -> str:
    """One shell line removing every trace tool of a container: the Debian alternatives groups first
    (else dangling links stay in ``/usr/bin``), then the files, then one ``LEFT <name>`` line per tool
    still found by ``command -v`` (see :func:`tools_left`); always exits 0."""
    alt = " ".join(alternatives)
    names = " ".join(tools)
    return (f"for n in {alt}; do update-alternatives --remove-all $n >/dev/null 2>&1; done; "
            f"rm -rf {' '.join(globs)}; hash -r 2>/dev/null; "
            f"for n in {names}; do command -v $n >/dev/null 2>&1 && echo \"LEFT $n\"; done; echo DONE")


def tools_left(output: str) -> List[str]:
    """The tools reported by the ``LEFT`` lines of :func:`remove_tools_cmd` (``[]`` when none)."""
    return re.findall(r'^LEFT (\S+)\s*$', output or '', re.M)


# ---------------------------------------------------------------------------
# ping output
# ---------------------------------------------------------------------------

_IPV4 = r'\d{1,3}(?:\.\d{1,3}){3}'
# "64 bytes from 10.0.0.1: icmp_seq=1 ttl=61 time=0.123 ms" / "64 bytes from srv (10.0.0.1): icmp_seq=1 ttl=61 ..."
_REPLY_RE = re.compile(r'^\d+ bytes from (?:\S+ \()?(' + _IPV4 + r')\)?: icmp_seq=(\d+) ttl=(\d+)', re.M)
# "From 192.168.1.1 icmp_seq=1 Time to live exceeded" / "From r1 (192.168.1.1) icmp_seq=1 Destination Net Unreachable"
_ERROR_RE = re.compile(r'^From (?:\S+ \()?(' + _IPV4 + r')\)? icmp_seq=(\d+) (.+?)\s*$', re.M)
# "ping: connect: Network is unreachable" / "ping: sendmsg: Network is unreachable"
_LOCAL_ERROR_RE = re.compile(r'^ping: (?:connect|sendmsg|sendto): (.+?)\s*$', re.M)
# "1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms"
_PING_STATS_RE = re.compile(r'(\d+) packets transmitted, (\d+) (?:packets )?received')
# "RR: \t10.0.0.2" then "\t10.0.0.3" lines (a hostname may precede the address without -n)
_RR_START_RE = re.compile(r'^RR:\s*(.*)$')
_RR_LINE_RE = re.compile(r'^\s+(?:\S+ \()?(' + _IPV4 + r')\)?\s*$')


def parse_ping(output: str) -> Dict[str, Any]:
    """Summary of a ``ping`` output.

    ``{'sent', 'received'}`` from the statistics block (``None`` without it), ``'replies'``
    (``[{'from', 'seq', 'ttl'}]``), ``'reply_ttl'`` (TTL of the first reply or ``None``), ``'errors'``
    (``[{'from', 'seq', 'message'}]``: the ICMP errors printed as ``From X icmp_seq=N ...``), ``'from'``
    and ``'error'`` (address and text of the first ICMP error; a local error such as *Network is
    unreachable* gives ``from = None``), ``'rr'`` (the addresses of the first ``RR:`` block of
    ``ping -R``)."""
    text = output or ''
    result: Dict[str, Any] = {'sent': None, 'received': None, 'replies': [], 'reply_ttl': None, 'errors': [],
                              'from': None, 'error': None, 'rr': []}
    m = _PING_STATS_RE.search(text)
    if m:
        result['sent'], result['received'] = int(m.group(1)), int(m.group(2))
    for m in _REPLY_RE.finditer(text):
        result['replies'].append({'from': m.group(1), 'seq': int(m.group(2)), 'ttl': int(m.group(3))})
    if result['replies']:
        result['reply_ttl'] = result['replies'][0]['ttl']
    for m in _ERROR_RE.finditer(text):
        result['errors'].append({'from': m.group(1), 'seq': int(m.group(2)), 'message': m.group(3)})
    if result['errors']:
        result['from'], result['error'] = result['errors'][0]['from'], result['errors'][0]['message']
    else:
        m = _LOCAL_ERROR_RE.search(text)
        if m:
            result['error'] = m.group(1)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _RR_START_RE.match(line)
        if not m:
            continue
        first = re.search(_IPV4, m.group(1))
        if first:
            result['rr'].append(first.group(0))
        for nxt in lines[i + 1:]:
            m2 = _RR_LINE_RE.match(nxt)
            if not m2:
                break
            result['rr'].append(m2.group(1))
        break
    return result


def error_from(output: str, message: str = TIME_EXCEEDED_MESSAGE) -> Optional[str]:
    """Address of the first ICMP error of a ``ping`` output whose text starts with *message*."""
    for err in parse_ping(output)['errors']:
        if err['message'].lower().startswith(message.lower()):
            return err['from']
    return None


# ---------------------------------------------------------------------------
# traceroute output
# ---------------------------------------------------------------------------

# " 3  10.0.1.2  0.345 ms * 0.2 ms" / " 2  * * *" / " 4  10.0.2.2  0.5 ms !X" / " 1  gw (10.0.0.1)  0.1 ms"
_HOP_LINE_RE = re.compile(r'^\s*(\d+)\s+(.*?)\s*$')
_HOP_ADDR_RE = re.compile(r'(?:^|\s)(?:\S+ \()?(' + _IPV4 + r')\)?(?=\s|$)')
_HOP_FLAG_RE = re.compile(r'(?<=\s)(![A-Za-z0-9<>]+)')


def parse_traceroute(output: str) -> List[Dict[str, Any]]:
    """The hops of a ``traceroute`` output: ``[{'hop', 'addr', 'addrs', 'flags', 'timeouts'}]`` where
    ``addr`` is the first address that answered at that hop (``None`` for ``* * *``), ``addrs`` every
    distinct address of the line in order, ``flags`` the annotations (``!X``, ``!H``...) and ``timeouts``
    the number of ``*``."""
    hops = []
    for line in (output or '').splitlines():
        if line.startswith('traceroute to'):
            continue
        m = _HOP_LINE_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        addrs: List[str] = []
        for a in _HOP_ADDR_RE.findall(rest):
            if a not in addrs:
                addrs.append(a)
        hops.append({'hop': int(m.group(1)), 'addr': addrs[0] if addrs else None, 'addrs': addrs,
                     'flags': _HOP_FLAG_RE.findall(rest), 'timeouts': rest.count('*')})
    return hops


def traceroute_path(hops: List[Dict[str, Any]]) -> List[Optional[str]]:
    """The first address of every hop (``None`` for a silent hop)."""
    return [h['addr'] for h in hops]


# ---------------------------------------------------------------------------
# tcpdump -v
# ---------------------------------------------------------------------------

# "12:00:00.000000 IP (tos 0x0, ttl 63, id 1234, offset 0, flags [none], proto ICMP (1), length 84)"
_TCPDUMP_TTL_RE = re.compile(r'^\S+ IP \(tos \S+, ttl (\d+),', re.M)


def parse_tcpdump_ttls(output: str) -> List[int]:
    """The TTL of every IPv4 packet of a ``tcpdump -n -v`` output, in order."""
    return [int(t) for t in _TCPDUMP_TTL_RE.findall(output or '')]


# "15:00:46.980678 IP 172.26.62.250 > 192.168.226.55: ICMP time exceeded in-transit, length 37"
# (with -v the "src > dst: ICMP ..." part is on the indented line after "IP (tos ..., ttl 63, ...)")
# "... IP 10.86.81.159 > 192.168.241.64: ICMP 10.86.81.159 udp port 33434 unreachable, length 37"
_TCPDUMP_ICMP_RE = re.compile(r'^(?:\S+ IP |\s+)(' + _IPV4 + r') > (' + _IPV4 + r'): ICMP (.+?), length \d+\s*$', re.M)
# "    1 0.000000000 172.26.62.250 → 192.168.226.55 ICMP 70 Time-to-live exceeded (Time to live exceeded in transit)"
_TSHARK_ICMP_RE = re.compile(r'^\s*\d+\s+\S+\s+(' + _IPV4 + r')\s+(?:→|->)\s+(' + _IPV4 + r')\s+ICMP\s+\d+\s+(.+?)\s*$', re.M)
# tcpdump: "time exceeded in-transit", "10.5.0.9 udp port 33434 unreachable", "echo request, id 1, seq 1";
# tshark: "Time-to-live exceeded (...)", "Destination unreachable (Port unreachable)", "Echo (ping) request ..."
_ICMP_KINDS = ((re.compile(r'time(?: |-to-live )exceeded', re.I), 'time-exceeded'),
               (re.compile(r'port(?: \d+)? unreachable', re.I), 'port-unreachable'),
               (re.compile(r'echo (?:\(ping\) )?request', re.I), 'echo-request'),
               (re.compile(r'echo (?:\(ping\) )?reply', re.I), 'echo-reply'),
               (re.compile(r'unreachable', re.I), 'unreachable'))


def parse_icmp_capture(output: str) -> List[Dict[str, Any]]:
    """The ICMP messages of a ``tcpdump -n [-v] icmp`` or ``tshark -n icmp`` capture, in order:
    ``[{'src', 'dst', 'kind', 'text'}]`` with *kind* ``time-exceeded``, ``port-unreachable``,
    ``unreachable`` (another code), ``echo-request``, ``echo-reply`` or ``other``. The quoted
    header inside a tcpdump ``-v`` error (an indented ``IP (tos ...`` line followed by the original
    ``src > dst`` line) is skipped."""
    messages = []
    seen_lines = set()
    for regex in (_TCPDUMP_ICMP_RE, _TSHARK_ICMP_RE):
        for m in regex.finditer(output or ''):
            seen_lines.add(m.start())
            text = m.group(3)
            kind = 'other'
            for regex_kind, name in _ICMP_KINDS:
                if regex_kind.search(text):
                    kind = name
                    break
            messages.append({'src': m.group(1), 'dst': m.group(2), 'kind': kind, 'text': text, 'pos': m.start()})
    messages.sort(key=lambda x: x['pos'])
    # tcpdump -v quotes the offending packet after an error: an indented "src > dst: ICMP echo request"
    # line preceded by an indented "IP (tos" line (the copy inside the error, not a packet)
    lines = (output or '').splitlines(keepends=True)
    starts, pos = [], 0
    for line in lines:
        starts.append((pos, line))
        pos += len(line)
    quoted = set()
    for k, (start, line) in enumerate(starts):
        if k and line.startswith((' ', '\t')) and starts[k - 1][1].lstrip().startswith('IP (tos') \
                and starts[k - 1][1].startswith((' ', '\t')):
            quoted.add(start)
    return [{k: v for k, v in msg.items() if k != 'pos'} for msg in messages if msg['pos'] not in quoted]


def capture_sources(messages: Sequence[Dict[str, Any]], kind: str = 'time-exceeded') -> List[str]:
    """The source addresses of the messages of a *kind* (see :func:`parse_icmp_capture`), in order."""
    return [m['src'] for m in messages if m['kind'] == kind]


# ---------------------------------------------------------------------------
# nftables texts
# ---------------------------------------------------------------------------

def nft_drop_icmp_types(table: str, types: Sequence[str] = ('time-exceeded',), chain: str = 'output',
                        hook: str = 'output') -> str:
    """An ``ip`` table whose *chain* drops the ICMP messages of the given *types* that the machine
    itself emits (``output`` hook: a router that never says *time exceeded* is a silent hop of
    traceroute)."""
    lines = [f"table ip {table} {{",
             f"    chain {chain} {{",
             f"        type filter hook {hook} priority filter; policy accept;"]
    lines += [f"        icmp type {t} drop" for t in types]
    lines += ["    }", "}", ""]
    return "\n".join(lines)


def nft_udp_policy(table: str, policy: str = 'drop') -> str:
    """An ``ip`` table whose ``input`` chain drops every UDP datagram (*policy* ``'drop'``: the UDP
    probes of traceroute vanish, ``* * *`` until the hop limit) or rejects it with an ICMP
    *communication administratively prohibited* (``'reject'``: traceroute prints ``!X``)."""
    if policy not in ('drop', 'reject'):
        raise ValueError(f"unknown policy {policy!r}")
    verdict = 'drop' if policy == 'drop' else 'reject with icmp type admin-prohibited'
    return "\n".join([f"table ip {table} {{",
                      "    chain input {",
                      "        type filter hook input priority filter; policy accept;",
                      f"        meta l4proto udp {verdict}",
                      "    }", "}", ""])


def nft_ttl_firewall(table: str, min_ttl: int, iif: str = 'eth0', probe_ttl_limit: int = 8,
                     comment: str = 'probes') -> str:
    """An ``ip`` table whose ``prerouting`` chain (before the TTL is checked: a probe expiring on
    the firewall itself is dropped too) drops the ICMP echo requests coming in by *iif* with a TTL
    below *min_ttl* or carrying IP options (``ip hdrlength gt 5``: *record route*, timestamps) —
    ``ping -t`` / ``ping -R`` can no longer map the path behind it — and counts the other packets
    of a TTL below *probe_ttl_limit* (the UDP / TCP probes of an emulated traceroute, read back with
    :func:`nft_counter_packets`)."""
    return "\n".join([f"table ip {table} {{",
                      "    chain prerouting {",
                      "        type filter hook prerouting priority raw; policy accept;",
                      f'        iifname "{iif}" icmp type echo-request ip ttl lt {int(min_ttl)} drop',
                      f'        iifname "{iif}" icmp type echo-request ip hdrlength gt 5 drop',
                      f'        iifname "{iif}" ip ttl lt {int(probe_ttl_limit)} counter comment "{comment}"',
                      "    }", "}", ""])


_COUNTER_RE = re.compile(r'counter packets (\d+) bytes \d+')


def nft_counter_packets(output: str, comment: str = None) -> Optional[int]:
    """The packet count of the first ``counter`` of an ``nft list`` output (of the rule whose
    comment is *comment* when given), ``None`` when there is none."""
    for line in (output or '').splitlines():
        if comment is not None and f'comment "{comment}"' not in line:
            continue
        m = _COUNTER_RE.search(line)
        if m:
            return int(m.group(1))
    return None


# ---------------------------------------------------------------------------
# grading of a typed path
# ---------------------------------------------------------------------------

def _owner_map(ips) -> Dict[str, str]:
    """``{address: machine}`` from a ``data.ips`` container or a ``{name: IPv4Interface}`` dict
    (``h3_c34`` belongs to ``h3``)."""
    entries = ips if isinstance(ips, dict) else vars(ips)
    owners: Dict[str, str] = {}
    for name, value in entries.items():
        if isinstance(value, (IPv4Interface, IPv4Address)):
            owners[str(getattr(value, 'ip', value))] = name.split('_', 1)[0]
    return owners


def address_owner(address, ips) -> Optional[str]:
    """The machine owning *address* (any of its interfaces), ``None`` for an unknown or malformed one."""
    text = str(address).strip().strip('()').split('/')[0]
    try:
        key = str(ip_address(text))
    except ValueError:
        return None
    return _owner_map(ips).get(key)


_PATH_TOKEN_RE = re.compile(r'[*?]|' + _IPV4)


def parse_path_answer(text: str) -> List[str]:
    """The tokens of a path typed by a student: addresses and ``*`` (a silent hop; ``?`` counts as
    ``*``), whatever the separators."""
    return ['*' if t in ('*', '?') else t for t in _PATH_TOKEN_RE.findall(text or '')]


def score_path(tokens: Sequence[str], expected: Sequence[str], ips, silent_index: int = None) -> Tuple[int, int]:
    """``(matched, extra)``: *matched* positions of *tokens* that name the machine of *expected*
    (any of its addresses) — or hold ``*`` at *silent_index* —, and the number of *extra* tokens
    beyond the expected length."""
    owners = _owner_map(ips)
    matched = 0
    for i, machine in enumerate(expected):
        if i >= len(tokens):
            break
        token = tokens[i]
        if token == '*':
            matched += int(i == silent_index)
        elif owners.get(token) == machine:
            matched += 1
    return matched, max(0, len(tokens) - len(expected))


# ---------------------------------------------------------------------------
# wrappers
# ---------------------------------------------------------------------------

def ping_ttl(grade: Grade0, machine: str, dest, ttl: int = None, step: int = 1, count: int = 1,
             wait: int = 1, record_route: bool = False) -> Dict[str, Any]:
    """Run :func:`ping_ttl_cmd` on *machine* and parse it (``allow_error``: an error is the point)."""
    out, _ = grade.test(machine, ping_ttl_cmd(dest, ttl, count=count, wait=wait, record_route=record_route),
                        step=step, allow_error=True)
    return parse_ping(out)


def traceroute_run(grade: Grade0, machine: str, dest, method: str = 'udp', step: int = 1, max_hops: int = 6,
                   queries: int = 1, wait: int = 1, port: int = None) -> List[Dict[str, Any]]:
    """Run :func:`traceroute_cmd` on *machine* and parse it."""
    cmd = traceroute_cmd(dest, method=method, port=port, max_hops=max_hops, queries=queries, wait=wait)
    out, _ = grade.test(machine, cmd, step=step, timeout=max_hops * queries * wait + 10, allow_error=True)
    return parse_traceroute(out)
