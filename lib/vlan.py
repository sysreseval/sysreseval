"""Helpers of the VLAN / bridges / brouter lab (``lab/sre/_DRAFT_misc/vlan.py``).

State side: :func:`install_http_echo` copies ``lib/http_echo.py`` (an HTTP server echoing the
client address and the TTL of its SYN) into a machine and starts it on several ports.  Grade
side: wrappers around one command each (``ip -j -d link``, ``ip -j -4 addr``, ``curl``,
``nft list ruleset``, ``iptables -t mangle -S``, ``/proc/sys``) and the pure parsers they rely
on: VLAN sub-interfaces and bridge ports from the JSON of ``ip link``, the rules of the
nftables *bridge* family that divert a frame to the IP stack (``meta pkttype set host`` +
``ether daddr set <bridge MAC>``, or ``meta broute set 1`` of newer nftables), the ``TTL``
target of iptables.  Fixtures of the parsers: ``tests/mock_data/vlan/`` (iproute2 6.19,
nftables 1.0.6, iptables 1.8.9 nft, Linux 6.12, in ``sysreseval/base:1.30``).
"""
import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0, NetScheme0
from firewall import get_ruleset, http_field
from openvpn import get_ip_addresses_json, interface_of_address, parse_ip_addr_json  # noqa: F401
from pmtu import ip_link_json_cmd, parse_ip_links_json  # noqa: F401

#: where install_http_echo() copies lib/http_echo.py, and its pid file
ECHO_PATH = '/usr/local/sbin/sre_http_echo.py'
ECHO_PID_FILE = '/run/sre_http_echo.pid'
MANGLE_RULES_CMD = "iptables -t mangle -S 2>/dev/null"

_IIF_RE = re.compile(r'\biif(?:name)?\s+"?([^\s"]+)"?')
_SADDR_RE = re.compile(r'\bip saddr\s+(\S+)')
_DADDR_RE = re.compile(r'\bip daddr\s+(\S+)')
_DPORT_RE = re.compile(r'\b(tcp|udp)\s+dport\s+(\d+)')
_MAC_SET_RE = re.compile(r'\bether daddr set\s+([0-9a-fA-F:]{17})')
_TABLE_RE = re.compile(r'^table\s+(\S+)\s+(\S+)\s*\{')
_CHAIN_RE = re.compile(r'^\s*chain\s+(\S+)\s*\{')
_HOOK_RE = re.compile(r'^\s*type\s+\S+\s+hook\s+(\S+)')
_IPT_RULE_RE = re.compile(r'^-A\s+(\S+)\s*(.*)$')


# ---------------------------------------------------------------------------
# state side: the echo server
# ---------------------------------------------------------------------------


def echo_start_cmd(name: str, ports=(80, 8080)) -> str:
    """Shell command (re)starting the echo server *name* on *ports* (the previous instance,
    known by its pid file, is killed first)."""
    port_list = ' '.join(str(int(p)) for p in ports)
    return (f"sh -c '[ -f {ECHO_PID_FILE} ] && kill $(cat {ECHO_PID_FILE}) 2>/dev/null; sleep 0.2; "
            f"python3 {ECHO_PATH} {shlex.quote(str(name))} {port_list}'")


def install_http_echo(net_scheme: NetScheme0, machine: str, name: str = None, ports=(80, 8080),
                      step: int = 1) -> None:
    """Copy lib/http_echo.py to ECHO_PATH on *machine* and start it on *ports* (``SERVER=`` is
    *name*, the machine name by default)."""
    script = Path(__file__).with_name('http_echo.py').read_text()
    net_scheme.file(machine, ECHO_PATH, script, permissions=0o755, step=step)
    net_scheme.cmd(machine, echo_start_cmd(machine if name is None else name, ports), step=step)


# ---------------------------------------------------------------------------
# grade side: the echo server
# ---------------------------------------------------------------------------


def http_echo_cmd(host, port: int = 80, timeout: int = 5) -> str:
    """``curl`` of the echo page of *host* (a name, an address or an interface object)."""
    return f"curl -s -m {int(timeout)} http://{str(host).split('/')[0]}:{int(port)}/"


def parse_http_echo(body: str) -> Dict[str, Any]:
    """``{'server', 'server_ip', 'server_port', 'client_ip', 'client_port', 'ttl'}`` of an echo
    page (strings, ``''`` when missing; ``ttl`` is an int or ``None``)."""
    fields = {key: http_field(body, key.upper()) for key in ('server', 'server_ip', 'server_port', 'client_ip',
                                                              'client_port')}
    ttl = http_field(body, 'TTL')
    fields['ttl'] = int(ttl) if ttl.isdigit() else None
    return fields


def get_http_echo(grade: Grade0, src: str, host, port: int = 80, step: int = 1, timeout: int = 5) -> Dict[str, Any]:
    """The echo page of ``host:port`` fetched from *src*, parsed (every field empty when the
    request failed or until the tests have run)."""
    out, code = grade.test(src, http_echo_cmd(host, port, timeout), step=step, timeout=timeout + 5, allow_error=True)
    return parse_http_echo(out if code == 0 else '')


# ---------------------------------------------------------------------------
# ip link: VLAN sub-interfaces and bridges
# ---------------------------------------------------------------------------


def get_ip_links(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """The objects of ``ip -j -d link show`` on *machine_name* (``[]`` on failure)."""
    out, code = grade.test(machine_name, ip_link_json_cmd(), step=step, allow_error=True)
    return parse_ip_links_json(out) if code == 0 else []


def links_by_name(links: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """``{ifname: link object}`` (the ``@parent`` suffix of the text output never appears in JSON)."""
    return {str(link.get('ifname', '')).split('@', 1)[0]: link for link in links if link.get('ifname')}


def link_up(links: List[Dict[str, Any]], ifname: str) -> bool:
    """True iff *ifname* exists and has the ``UP`` flag."""
    link = links_by_name(links).get(ifname)
    return bool(link) and 'UP' in (link.get('flags') or [])


def link_master(links: List[Dict[str, Any]], ifname: str) -> Optional[str]:
    """The ``master`` (bridge or bond) of *ifname*, ``None`` when it has none or does not exist."""
    link = links_by_name(links).get(ifname)
    return link.get('master') if link else None


def link_address(links: List[Dict[str, Any]], ifname: str) -> str:
    """The MAC address of *ifname* (``''`` when unknown)."""
    link = links_by_name(links).get(ifname)
    return str(link.get('address', '')) if link else ''


def vlan_links(links: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """The 802.1Q sub-interfaces of an ``ip -j -d link`` output:
    ``{'eth0.111': {'id': 111, 'link': 'eth0', 'up': True, 'master': 'brodd' | None}}``."""
    result = {}
    for name, link in links_by_name(links).items():
        info = link.get('linkinfo') or {}
        if info.get('info_kind') != 'vlan':
            continue
        data = info.get('info_data') or {}
        result[name] = {'id': data.get('id'), 'link': link.get('link'), 'up': 'UP' in (link.get('flags') or []),
                        'master': link.get('master')}
    return result


def bridge_ports(links: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """The bridges of an ``ip -j -d link`` output with their ports: ``{'brodd': ['eth0.111', 'eth1']}``
    (a bridge without port has an empty list)."""
    by_name = links_by_name(links)
    bridges = {name for name, link in by_name.items() if (link.get('linkinfo') or {}).get('info_kind') == 'bridge'}
    result = {name: [] for name in sorted(bridges)}
    for name, link in by_name.items():
        master = link.get('master')
        if master in result:
            result[master].append(name)
    for ports in result.values():
        ports.sort()
    return result


def addresses_of(addresses: Dict[str, List[dict]], ifname: str) -> List[str]:
    """The ``a.b.c.d/n`` addresses of *ifname* in a ``parse_ip_addr_json()`` result."""
    return [f"{entry['local']}/{entry['prefixlen']}" for entry in addresses.get(ifname, [])]


# ---------------------------------------------------------------------------
# nftables bridge family: the rules diverting frames to the IP stack
# ---------------------------------------------------------------------------


def parse_broute_rules(ruleset: str) -> List[Dict[str, Any]]:
    """The rules of the *bridge* family of an ``nft list ruleset`` output that divert a frame to
    the IP stack of the bridge (a *brouter*): ``meta pkttype set host`` with ``ether daddr set``,
    or ``meta broute set 1`` (nftables >= 1.0.7).

    One dict per such rule: ``table``, ``chain``, ``hook`` (``'prerouting'``...), ``iif``,
    ``saddr``, ``daddr`` (as written: an address or a prefix, ``None`` when absent), ``l4proto``
    and ``dport`` (``'tcp'``, 8080), ``pkttype_host``, ``daddr_mac`` (the MAC set, lower case),
    ``broute`` (``meta broute set 1`` seen), ``text`` (the line).  The *ip* and *inet* families
    (the NAT and mangle tables of the routers) are ignored.
    """
    rules: List[Dict[str, Any]] = []
    family = table = chain = hook = None
    for raw in (ruleset or '').splitlines():
        line = raw.strip()
        m = _TABLE_RE.match(line)
        if m:
            family, table, chain, hook = m.group(1), m.group(2), None, None
            continue
        m = _CHAIN_RE.match(line)
        if m:
            chain, hook = m.group(1), None
            continue
        m = _HOOK_RE.match(line)
        if m:
            hook = m.group(1)
            continue
        if family != 'bridge' or chain is None or not line or line.startswith(('}', '#', 'policy', 'type ')):
            continue
        pkttype_host = 'meta pkttype set host' in line
        mac = _MAC_SET_RE.search(line)
        broute = re.search(r'\bmeta broute set 1\b', line) is not None
        if not broute and not (pkttype_host or mac):
            continue
        dport = _DPORT_RE.search(line)
        iif = _IIF_RE.search(line)
        saddr = _SADDR_RE.search(line)
        daddr = _DADDR_RE.search(line)
        rules.append({'table': table, 'chain': chain, 'hook': hook, 'iif': iif.group(1) if iif else None,
                      'saddr': saddr.group(1) if saddr else None, 'daddr': daddr.group(1) if daddr else None,
                      'l4proto': dport.group(1) if dport else None, 'dport': int(dport.group(2)) if dport else None,
                      'pkttype_host': pkttype_host, 'daddr_mac': mac.group(1).lower() if mac else None,
                      'broute': broute, 'text': line})
    return rules


def rule_diverts(rule: Dict[str, Any]) -> bool:
    """True iff the rule really hands the frame to the IP stack: ``meta broute set 1``, or
    ``meta pkttype set host`` together with ``ether daddr set``."""
    return bool(rule.get('broute') or (rule.get('pkttype_host') and rule.get('daddr_mac')))


def _covers(written: Optional[str], address) -> bool:
    """True iff the address or prefix *written* in a rule covers *address*."""
    if not written:
        return False
    from ipaddress import ip_address, ip_network
    try:
        wanted = ip_address(str(address).split('/')[0])
        if '/' in written:
            return wanted in ip_network(written, strict=False)
        return ip_address(written) == wanted
    except ValueError:
        return False


def broute_rules_for(rules: List[Dict[str, Any]], src=None, dst=None, dport: int = None,
                     diverting: bool = True) -> List[Dict[str, Any]]:
    """The rules of :func:`parse_broute_rules` matching the given source address, destination
    address and destination port (an absent match in the rule is not a constraint; a given
    *src* / *dst* must be covered by the rule's prefix).  *diverting* keeps the complete rules
    only (:func:`rule_diverts`)."""
    result = []
    for rule in rules:
        if diverting and not rule_diverts(rule):
            continue
        if src is not None and not _covers(rule['saddr'], src):
            continue
        if dst is not None and not _covers(rule['daddr'], dst):
            continue
        if dport is not None and rule['dport'] != dport:
            continue
        result.append(rule)
    return result


def get_broute_rules(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_broute_rules` of ``nft list ruleset`` on *machine_name*."""
    return parse_broute_rules(get_ruleset(grade, machine_name, step=step))


# ---------------------------------------------------------------------------
# iptables: the TTL target of the mangle table
# ---------------------------------------------------------------------------


def parse_iptables_save(text: str) -> List[Dict[str, Any]]:
    """The ``-A`` rules of an ``iptables -S`` / ``iptables-save`` output: one dict per rule with
    ``chain``, ``src``, ``dst``, ``in``, ``out``, ``proto`` (as written, ``None`` when absent),
    ``target`` (``-j``), ``args`` (the words after the target) and ``text``."""
    rules = []
    for raw in (text or '').splitlines():
        m = _IPT_RULE_RE.match(raw.strip())
        if not m:
            continue
        chain, rest = m.group(1), m.group(2)
        try:
            tokens = shlex.split(rest)
        except ValueError:
            tokens = rest.split()
        rule = {'chain': chain, 'src': None, 'dst': None, 'in': None, 'out': None, 'proto': None, 'target': None,
                'args': [], 'text': raw.strip()}
        options = {'-s': 'src', '--source': 'src', '-d': 'dst', '--destination': 'dst', '-i': 'in',
                   '--in-interface': 'in', '-o': 'out', '--out-interface': 'out', '-p': 'proto', '--protocol': 'proto'}
        i, after_target = 0, False
        while i < len(tokens):
            token = tokens[i]
            if after_target:
                rule['args'].append(token)
            elif token in ('-j', '--jump', '-g', '--goto') and i + 1 < len(tokens):
                rule['target'] = tokens[i + 1]
                after_target = True
                i += 1
            elif token in options and i + 1 < len(tokens):
                rule[options[token]] = tokens[i + 1]
                i += 1
            elif token == '!':
                pass
            else:
                rule['args'].append(token)
            i += 1
        rules.append(rule)
    return rules


def ttl_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The rules of :func:`parse_iptables_save` whose target is ``TTL``, with ``op``
    (``'inc'``, ``'dec'`` or ``'set'``) and ``value`` added (``None`` when unreadable)."""
    result = []
    for rule in rules:
        if rule.get('target') != 'TTL':
            continue
        op = value = None
        args = rule.get('args') or []
        for i, arg in enumerate(args):
            if arg in ('--ttl-inc', '--ttl-dec', '--ttl-set') and i + 1 < len(args) and args[i + 1].isdigit():
                op, value = arg[6:], int(args[i + 1])
        result.append({**rule, 'op': op, 'value': value})
    return result


def get_mangle_rules(grade: Grade0, machine_name: str, step: int = 1) -> List[Dict[str, Any]]:
    """:func:`parse_iptables_save` of ``iptables -t mangle -S`` on *machine_name*."""
    out, code = grade.test(machine_name, MANGLE_RULES_CMD, step=step, allow_error=True)
    return parse_iptables_save(out) if code == 0 else []


# ---------------------------------------------------------------------------
# /proc/sys
# ---------------------------------------------------------------------------


def get_sysctl_int(grade: Grade0, machine_name: str, name: str, step: int = 1) -> Optional[int]:
    """The integer value of the kernel parameter *name* (``net.ipv4.ip_default_ttl``) read in
    ``/proc/sys``, ``None`` when unreadable."""
    path = '/proc/sys/' + name.strip().replace('.', '/')
    out, code = grade.test(machine_name, f"cat {path}", step=step, allow_error=True)
    value = (out or '').strip()
    return int(value) if code == 0 and re.fullmatch(r'-?\d+', value) else None
