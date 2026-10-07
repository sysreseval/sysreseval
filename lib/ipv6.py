"""IPv6 helpers of the IPv6 lab (``lab/sre/_DRAFT_misc/ipv6.py``).

Addressing arithmetic (EUI-64 interface identifiers, link-local and SLAAC addresses,
solicited-node multicast, DUID-LL), typeable random addresses, reference configuration texts
of ``dhcpd -6``, parsers of ``ip -j -6`` outputs, ``/etc/resolv.conf``, ``dhclient -6`` lease
files and ``dhcpd`` command lines, and the wrappers of the router-advertisement / DHCPv6 probe
``lib/ipv6_probe.py`` run on a hidden machine of the lab.

The fixtures of ``tests/mock_data/ipv6/`` were captured on 2026-10-07 by a live evaluation of
the lab (sysreseval/base,init:1.30, ISC DHCP 4.4.3-P1, radvd, iproute2 6.x).
"""
import base64
import json
import random
import re
from dataclasses import dataclass, field
from ipaddress import IPv6Address, IPv6Interface, IPv6Network
from pathlib import Path

from SRE.lib_sre import NetScheme0, Grade0

#: locally administered prefix of the MAC addresses chosen by the lab ("SR" in ASCII)
MAC_PREFIX = "02:53:52"
DHCP6_CLIENT_PORT, DHCP6_SERVER_PORT = 546, 547
ALL_NODES, ALL_ROUTERS, ALL_DHCP_AGENTS = IPv6Address('ff02::1'), IPv6Address('ff02::2'), IPv6Address('ff02::1:2')
_SOLICITED_NODE_BASE = int(IPv6Address('ff02::1:ff00:0'))


# ---------------------------------------------------------------------------
# addressing arithmetic
# ---------------------------------------------------------------------------

def mac_bytes(mac) -> bytes:
    """The six bytes of a MAC address given as ``aa:bb:cc:dd:ee:ff``, ``aa-bb-...`` or a netaddr EUI."""
    raw = bytes(int(x, 16) for x in str(mac).replace('-', ':').split(':'))
    if len(raw) != 6:
        raise ValueError(f"not a MAC address: {mac!r}")
    return raw


def mac_str(mac) -> str:
    """``aa:bb:cc:dd:ee:ff`` form (lower case, colons) of a MAC address."""
    return ':'.join(f'{b:02x}' for b in mac_bytes(mac))


def mac_to_eui64(mac) -> int:
    """Modified EUI-64 interface identifier of a MAC address (RFC 4291 appendix A): the
    universal/local bit of the first byte is inverted and ``ff:fe`` is inserted in the middle."""
    b = mac_bytes(mac)
    return int.from_bytes(bytes([b[0] ^ 0x02, b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]]), 'big')


def link_local_from_mac(mac) -> IPv6Address:
    """``fe80::`` + EUI-64 of *mac*: the link-local address a Linux interface builds by default."""
    return IPv6Address((0xfe80 << 112) + mac_to_eui64(mac))


def slaac_address(prefix, mac) -> IPv6Interface:
    """The SLAAC address of an interface of MAC *mac* in *prefix* (a /64)."""
    net = IPv6Network(str(prefix), strict=False)
    if net.prefixlen != 64:
        raise ValueError(f"slaac_address: {net} is not a /64")
    return IPv6Interface((int(net.network_address) + mac_to_eui64(mac), 64))


def solicited_node_multicast(address) -> IPv6Address:
    """``ff02::1:ffxx:xxxx`` of an address (RFC 4291 2.7.1: its last 24 bits)."""
    addr = IPv6Address(str(address).split('/')[0])
    return IPv6Address(_SOLICITED_NODE_BASE | (int(addr) & 0xffffff))


def multicast_mac(address) -> str:
    """Ethernet address of an IPv6 multicast group: ``33:33`` + its last four bytes (RFC 2464)."""
    raw = IPv6Address(str(address).split('/')[0]).packed[12:]
    return '33:33:' + ':'.join(f'{b:02x}' for b in raw)


def duid_ll(mac) -> str:
    """DUID-LL of a client (RFC 8415 11.4): type 3, hardware type 1 (Ethernet), the MAC address;
    what ``dhclient -6 -D LL`` uses."""
    return '00:03:00:01:' + mac_str(mac)


def normalize_duid(text) -> str:
    """A DUID typed by a student (hex bytes separated by colons, dashes or spaces, with or
    without leading zeros) in the ``00:03:00:01:...`` form; ``''`` when not hexadecimal."""
    parts = [p for p in re.split(r'[:\s-]+', str(text or '').strip().lower()) if p]
    if not parts or not all(re.fullmatch(r'[0-9a-f]{1,2}', p) for p in parts):
        return ''
    return ':'.join(f'{int(p, 16):02x}' for p in parts)


def parse_ipv6(text):
    """The IPv6Address of a typed answer (brackets, a ``%zone`` and a ``/prefix`` are ignored),
    None when it is not an address."""
    value = str(text or '').strip().strip('[]').split('%')[0].split('/')[0]
    try:
        return IPv6Address(value)
    except ValueError:
        return None


def same_ipv6(answer, expected) -> bool:
    """True when the typed *answer* is the address *expected* (any textual form)."""
    parsed = parse_ipv6(answer)
    return parsed is not None and parsed == IPv6Address(str(expected).split('/')[0])


def ipv6_subnet(site, index: int, new_prefix: int = 64) -> IPv6Network:
    """Subnet number *index* (from 0) of *site* with the prefix length *new_prefix*."""
    site = IPv6Network(str(site), strict=False)
    if new_prefix < site.prefixlen:
        raise ValueError(f"ipv6_subnet: /{new_prefix} is shorter than {site}")
    return IPv6Network((int(site.network_address) + (index << (128 - new_prefix)), new_prefix))


def small_ipv6s(network, n: int = 1, low: int = 2, high: int = 0xfff, exclude=()) -> list:
    """*n* distinct random addresses of *network* with a short interface identifier (offsets
    ``low``..``high``, never 0: the subnet-router anycast address), so that students can type
    them; *exclude* lists addresses, interfaces or offsets to avoid."""
    net = IPv6Network(str(network), strict=False)
    base = int(net.network_address)
    taken = set()
    for item in exclude:
        if isinstance(item, int):
            taken.add(item)
        else:
            taken.add(int(IPv6Address(str(item).split('/')[0])) - base)
    candidates = [k for k in range(max(1, low), high + 1) if k not in taken]
    if len(candidates) < n:
        raise ValueError(f"small_ipv6s: only {len(candidates)} offsets available in {net}, {n} wanted")
    return [IPv6Interface((base + k, net.prefixlen)) for k in random.sample(candidates, n)]


# ---------------------------------------------------------------------------
# reference configuration texts
# ---------------------------------------------------------------------------

DHCPD6_DEFAULTS = 'INTERFACESv4=""\nINTERFACESv6="eth0"\n'  # /etc/default/isc-dhcp-server of a DHCPv6-only server
DHCPD6_CONF = '/etc/dhcp/dhcpd6.conf'
DHCPD6_LEASES = '/var/lib/dhcp/dhcpd6.leases'
DHCPD6_UNIT = 'isc-dhcp-server'   # Debian: one SysV service starts dhcpd -4 and/or -6 (INTERFACESv4 / INTERFACESv6)
DHCLIENT6_LEASES = '/var/lib/dhcp/dhclient6.leases'


def _plain(address) -> str:
    return str(address).split('/')[0]


def render_dhcpd6_conf(subnet6, *, range6=None, dns=(), domain_search=(), default_lease=None,
                       preferred_lifetime=None, hosts=(), comment: str = None) -> str:
    """Text of ``dhcpd6.conf``: the global lease times and options, one ``subnet6`` with an
    optional ``range6`` (a ``(first, last)`` pair), and ``host`` reservations given as
    ``(name, duid, fixed_address6)`` tuples."""
    lines = [f"# {comment}"] if comment else []
    if default_lease is not None:
        lines.append(f"default-lease-time {int(default_lease)};")
    if preferred_lifetime is not None:
        lines.append(f"preferred-lifetime {int(preferred_lifetime)};")
    if dns:
        lines.append(f"option dhcp6.name-servers {', '.join(_plain(a) for a in dns)};")
    if domain_search:
        lines.append(f"option dhcp6.domain-search {', '.join(chr(34) + str(d) + chr(34) for d in domain_search)};")
    if lines:
        lines.append("")
    net = IPv6Network(str(subnet6), strict=False)
    lines.append(f"subnet6 {net} {{")
    if range6:
        first, last = range6
        lines.append(f"    range6 {_plain(first)} {_plain(last)};")
    lines.append("}")
    for name, duid, fixed in hosts:
        lines += ["", f"host {name} {{",
                  f"    host-identifier option dhcp6.client-id {normalize_duid(duid)};",
                  f"    fixed-address6 {_plain(fixed)};",
                  "}"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# parsers of container outputs
# ---------------------------------------------------------------------------

def _json(output):
    try:
        return json.loads(output or '')
    except ValueError:
        return None


def parse_ip6_addrs(output: str) -> list:
    """Addresses of an ``ip -j -6 addr show`` output: ``[{'ifname', 'address' (IPv6Address),
    'prefixlen', 'scope', 'dynamic', 'mngtmpaddr', 'temporary', 'tentative', 'dadfailed',
    'protocol', 'valid', 'preferred'}]`` (``[]`` when empty or malformed)."""
    links = _json(output)
    result = []
    if not isinstance(links, list):
        return result
    for link in links:
        if not isinstance(link, dict):
            continue
        for info in link.get('addr_info') or []:
            if not isinstance(info, dict) or info.get('family') != 'inet6':
                continue
            try:
                address = IPv6Address(info.get('local'))
            except ValueError:
                continue
            result.append({
                'ifname': link.get('ifname'), 'address': address, 'prefixlen': info.get('prefixlen'),
                'scope': info.get('scope'), 'dynamic': bool(info.get('dynamic')),
                'mngtmpaddr': bool(info.get('mngtmpaddr')), 'temporary': bool(info.get('temporary')),
                'tentative': bool(info.get('tentative')), 'dadfailed': bool(info.get('dadfailed')),
                'protocol': info.get('protocol'),
                'valid': info.get('valid_life_time'), 'preferred': info.get('preferred_life_time'),
            })
    return result


def is_slaac(addr: dict) -> bool:
    """An address built from a router advertisement (``mngtmpaddr`` flag, ``proto kernel_ra``)."""
    return bool(addr.get('mngtmpaddr')) or addr.get('protocol') == 'kernel_ra'


def global_addresses(addrs: list, dynamic: bool = None, slaac: bool = None) -> list:
    """Global, non-temporary addresses of a ``parse_ip6_addrs`` list, as IPv6Address objects;
    *dynamic* / *slaac* keep only the addresses with (True) or without (False) that property."""
    result = []
    for a in addrs:
        if a.get('scope') != 'global' or a.get('temporary'):
            continue
        if dynamic is not None and bool(a.get('dynamic')) != dynamic:
            continue
        if slaac is not None and is_slaac(a) != slaac:
            continue
        result.append(a['address'])
    return result


def link_local_addresses(addrs: list) -> list:
    return [a['address'] for a in addrs if a.get('scope') == 'link']


def parse_ip6_routes(output: str) -> list:
    """Routes of an ``ip -j -6 route show`` output: ``[{'dst', 'gateway' (IPv6Address or None),
    'dev', 'protocol', 'metric', 'expires'}]``."""
    routes = _json(output)
    result = []
    if not isinstance(routes, list):
        return result
    for r in routes:
        if not isinstance(r, dict) or 'dst' not in r:
            continue
        gateway = None
        if r.get('gateway'):
            try:
                gateway = IPv6Address(str(r['gateway']).split('%')[0])
            except ValueError:
                gateway = None
        result.append({'dst': r.get('dst'), 'gateway': gateway, 'dev': r.get('dev'), 'protocol': r.get('protocol'),
                       'metric': r.get('metric'), 'expires': r.get('expires')})
    return result


def default_routes6(routes: list) -> list:
    return [r for r in routes if r.get('dst') in ('default', '::/0')]


def parse_resolv_conf(text: str) -> dict:
    """``{'nameservers': [str], 'search': [str]}`` of a resolv.conf text (``dhclient -6`` writes
    the search domains of ``dhcp6.domain-search`` with a trailing dot: it is removed)."""
    result = {'nameservers': [], 'search': []}
    for line in (text or '').splitlines():
        words = line.split('#')[0].split(';')[0].split()
        if not words:
            continue
        if words[0] == 'nameserver' and len(words) > 1:
            result['nameservers'].append(words[1].split('%')[0])
        elif words[0] in ('search', 'domain'):
            result['search'] += [w.rstrip('.') for w in words[1:]]
    return result


_OCTAL_RE = re.compile(r'\\([0-7]{3})')


def decode_lease_string(text: str) -> bytes:
    """Bytes of an ISC lease-file string (``"\\000\\003\\000\\001..."``: octal escapes)."""
    out = bytearray()
    i = 0
    while i < len(text):
        m = _OCTAL_RE.match(text, i)
        if m:
            out.append(int(m.group(1), 8))
            i = m.end()
        elif text[i] == '\\' and i + 1 < len(text):
            out.append(ord(text[i + 1]))
            i += 2
        else:
            out.append(ord(text[i]))
            i += 1
    return bytes(out)


def dhclient6_default_duid(text: str):
    """The ``default-duid`` of a dhclient lease file, as ``00:03:00:01:...`` (None when absent)."""
    m = re.search(r'default-duid\s+"((?:[^"\\]|\\.)*)"', text or '')
    if not m:
        return None
    return ':'.join(f'{b:02x}' for b in decode_lease_string(m.group(1)))


def parse_dhclient6_leases(text: str) -> list:
    """The ``lease6`` blocks of a ``dhclient -6`` lease file, oldest first:
    ``[{'interface', 'iaid', 'addresses': [{'address' (IPv6Address), 'preferred_life', 'max_life',
    'starts'}], 'options': {name: value}, 'name_servers': [IPv6Address], 'domain_search': [str],
    'server_id', 'client_id'}]`` (the last block is the current lease)."""
    leases = []
    for block in re.finditer(r'lease6\s*\{(.*?)\n\}', text or '', re.S):
        body = block.group(1)
        lease = {'interface': None, 'iaid': None, 'addresses': [], 'options': {}, 'name_servers': [],
                 'domain_search': [], 'server_id': None, 'client_id': None}
        m = re.search(r'interface\s+"([^"]*)"', body)
        if m:
            lease['interface'] = m.group(1)
        m = re.search(r'ia-na\s+([0-9a-fA-F:]+)', body)
        if m:
            lease['iaid'] = m.group(1)
        for addr_m in re.finditer(r'iaaddr\s+([0-9a-fA-F:.]+)\s*\{(.*?)\}', body, re.S):
            try:
                address = IPv6Address(addr_m.group(1))
            except ValueError:
                continue
            fields = addr_m.group(2)
            entry = {'address': address, 'preferred_life': None, 'max_life': None, 'starts': None}
            for key, attr in (('preferred-life', 'preferred_life'), ('max-life', 'max_life'), ('starts', 'starts')):
                f = re.search(rf'\b{key}\s+(\d+)', fields)
                if f:
                    entry[attr] = int(f.group(1))
            lease['addresses'].append(entry)
        for opt_m in re.finditer(r'^\s*option\s+(\S+)\s+(.*?);\s*$', body, re.M):
            name, value = opt_m.group(1), opt_m.group(2).strip()
            lease['options'][name] = value
            if name == 'dhcp6.name-servers':
                for item in value.split(','):
                    try:
                        lease['name_servers'].append(IPv6Address(item.strip()))
                    except ValueError:
                        pass
            elif name == 'dhcp6.domain-search':
                lease['domain_search'] = [s.strip().strip('"').rstrip('.') for s in value.split(',') if s.strip()]
            elif name == 'dhcp6.server-id':
                lease['server_id'] = normalize_duid(value)
            elif name == 'dhcp6.client-id':
                lease['client_id'] = normalize_duid(value)
        leases.append(lease)
    return leases


_DHCPD_VALUE_FLAGS = {'-cf', '-lf', '-pf', '-tf', '-sf', '-hpf', '-user', '-group', '-chroot', '-port', '-relay',
                      '-p', '-s'}


def _parse_dhcpd6_cmdlines(output: str):
    """Interfaces of the running ``dhcpd -6``, from one command line per dhcpd process
    (arguments separated by spaces): ``None`` when no DHCPv6 server runs, ``['*']`` when it was
    started without interface.  The IPv4 processes (``-4``, or without ``-6``) are ignored."""
    for line in (output or '').splitlines():
        tokens = line.split()
        if not tokens or not tokens[0].endswith('dhcpd') or '-6' not in tokens:
            continue
        interfaces, skip = [], False
        for tok in tokens[1:]:
            if skip:
                skip = False
                continue
            if tok in _DHCPD_VALUE_FLAGS:
                skip = True
                continue
            if tok.startswith('-'):
                continue
            interfaces.append(tok)
        return interfaces or ['*']
    return None


# ---------------------------------------------------------------------------
# wrappers (one grade.test() each, every call unconditional for the two-pass contract)
# ---------------------------------------------------------------------------

def get_ip6_addrs(grade: Grade0, machine: str, dev: str = None, step: int = 1) -> list:
    """``parse_ip6_addrs`` of ``ip -j -6 addr show [dev DEV]`` on *machine*."""
    cmd = f"ip -j -6 addr show dev {dev}" if dev else "ip -j -6 addr show"
    output, _ = grade.test(machine, cmd, step=step, allow_error=True)
    return parse_ip6_addrs(output)


def get_ip6_routes(grade: Grade0, machine: str, step: int = 1) -> list:
    """``parse_ip6_routes`` of ``ip -j -6 route show`` on *machine*."""
    output, _ = grade.test(machine, "ip -j -6 route show", step=step, allow_error=True)
    return parse_ip6_routes(output)


def get_resolv_conf(grade: Grade0, machine: str, step: int = 1) -> dict:
    output, _ = grade.test(machine, "cat /etc/resolv.conf", step=step, allow_error=True)
    return parse_resolv_conf(output)


def get_dhclient6_leases(grade: Grade0, machine: str, step: int = 1) -> tuple:
    """``(default_duid, leases)`` of every ``dhclient6*.leases`` file of *machine*."""
    output, _ = grade.test(machine, "cat /var/lib/dhcp/dhclient6*.leases 2>/dev/null", step=step, allow_error=True)
    return dhclient6_default_duid(output), parse_dhclient6_leases(output)


def get_dhcpd6_interfaces(grade: Grade0, machine: str, step: int = 1):
    """Interfaces the running ``dhcpd -6`` of *machine* listens on (``None`` when it does not
    run, ``['*']`` when started without interface): the process table is read, the unit state
    is not trusted (see get_dhcpd_interfaces in lib/dhcp.py)."""
    output, _ = grade.test(
        machine,
        r"for p in $(pidof dhcpd); do tr '\000' ' ' < /proc/$p/cmdline; echo; done",
        step=step, allow_error=True)
    return _parse_dhcpd6_cmdlines(output)


def radvd_running(grade: Grade0, machine: str, step: int = 1) -> bool:
    output, code = grade.test(machine, "pidof radvd", step=step, allow_error=True)
    return code == 0 and bool(output.strip())


# ---------------------------------------------------------------------------
# active probe (lib/ipv6_probe.py run inside a container)
# ---------------------------------------------------------------------------

IPV6_PROBE_PATH = '/usr/local/sbin/ipv6_probe.py'


@dataclass
class PrefixInfo:
    prefix: IPv6Network
    on_link: bool
    autonomous: bool
    valid: int
    preferred: int


@dataclass
class RouterAdvertisement:
    """One Router Advertisement seen by the probe."""
    src: IPv6Address | None
    managed: bool = False                # M flag
    other: bool = False                  # O flag
    router_lifetime: int = 0             # 0: not a default router
    hop_limit: int = 0
    mtu: int | None = None
    prefixes: list = field(default_factory=list)      # [PrefixInfo]
    rdnss: list = field(default_factory=list)         # [IPv6Address]
    dnssl: list = field(default_factory=list)         # [str]
    source_mac: str | None = None
    raw: dict = field(default_factory=dict)

    def prefix(self, prefix) -> PrefixInfo | None:
        """The prefix information option announcing *prefix*."""
        net = IPv6Network(str(prefix), strict=False)
        return next((p for p in self.prefixes if p.prefix == net), None)


@dataclass
class Dhcp6Address:
    address: IPv6Address
    preferred: int | None = None
    valid: int | None = None


@dataclass
class Dhcp6Reply:
    """One ADVERTISE / REPLY seen by the probe for a given query."""
    query: str
    msg_type: str | None                 # 'ADVERTISE', 'REPLY'
    src: IPv6Address | None = None
    server_duid: str | None = None
    addresses: list = field(default_factory=list)     # [Dhcp6Address] of the IA_NA options
    status_code: int | None = None
    status_message: str | None = None
    dns_servers: list = field(default_factory=list)   # [IPv6Address]
    domain_search: list = field(default_factory=list)  # [str]
    preference: int | None = None
    raw: dict = field(default_factory=dict)


def install_ipv6_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy lib/ipv6_probe.py to IPV6_PROBE_PATH on *machine* (usually a hidden one)."""
    script = Path(__file__).with_name('ipv6_probe.py').read_text()
    net_scheme.file(machine, IPV6_PROBE_PATH, script, permissions=0o755, step=step)


def dhcp6_query(query_id: str, msg_type: str = 'solicit', duid=None, iaid: int = 1) -> dict:
    """One DHCPv6 query of a probe spec: ``msg_type`` ``'solicit'`` (an IA_NA is asked) or
    ``'information-request'``; *duid* is the client identifier announced (``duid_ll(mac)``)."""
    if msg_type not in ('solicit', 'information-request'):
        raise ValueError(f"dhcp6_query: unknown type {msg_type!r}")
    if not duid:
        raise ValueError("dhcp6_query: a DUID is required")
    return {'id': query_id, 'type': msg_type, 'duid': normalize_duid(duid), 'iaid': int(iaid)}


def ipv6_probe_spec(interface: str = 'eth0', *, rs: bool = True, queries=(), wait: float = 4.0) -> dict:
    """Spec of one probe run (see lib/ipv6_probe.py); build it from lab data only."""
    return {'interface': interface, 'rs': bool(rs), 'wait': float(wait), 'queries': list(queries)}


def ipv6_probe_command(spec: dict) -> str:
    """Shell command running the probe with *spec*; depends on *spec* only (stable across passes)."""
    encoded = base64.urlsafe_b64encode(
        json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).decode()
    return f'python3 {IPV6_PROBE_PATH} {encoded}'


def _probe_ip(value):
    try:
        return IPv6Address(str(value).split('%')[0])
    except (ValueError, TypeError):
        return None


def _probe_ips(values) -> list:
    return [ip for ip in map(_probe_ip, values if isinstance(values, list) else []) if ip is not None]


def _probe_prefixes(values) -> list:
    result = []
    for p in values if isinstance(values, list) else []:
        if not isinstance(p, dict):
            continue
        try:
            net = IPv6Network(p.get('prefix'), strict=False)
        except (ValueError, TypeError):
            continue
        result.append(PrefixInfo(prefix=net, on_link=bool(p.get('on_link')), autonomous=bool(p.get('autonomous')),
                                 valid=int(p.get('valid') or 0), preferred=int(p.get('preferred') or 0)))
    return result


def parse_ipv6_probe(output: str) -> tuple:
    """Parse the JSON printed by the probe into ``(ras, replies)``: the RouterAdvertisement list
    and ``{query_id: [Dhcp6Reply]}``.  ``([], {})`` on empty or malformed output."""
    try:
        document = json.loads(output)
        raw_ras, raw_replies = document['ra'], document['dhcp6']
    except (ValueError, KeyError, TypeError):
        return [], {}
    ras = []
    for r in raw_ras if isinstance(raw_ras, list) else []:
        if not isinstance(r, dict):
            continue
        ras.append(RouterAdvertisement(
            src=_probe_ip(r.get('src')), managed=bool(r.get('managed')), other=bool(r.get('other')),
            router_lifetime=int(r.get('router_lifetime') or 0), hop_limit=int(r.get('hop_limit') or 0),
            mtu=r.get('mtu') if isinstance(r.get('mtu'), int) else None,
            prefixes=_probe_prefixes(r.get('prefixes')), rdnss=_probe_ips(r.get('rdnss')),
            dnssl=[str(d) for d in (r.get('dnssl') or [])], source_mac=r.get('source_mac'), raw=r))
    replies = {}
    if isinstance(raw_replies, dict):
        for query_id, items in raw_replies.items():
            parsed = []
            for r in items if isinstance(items, list) else []:
                if not isinstance(r, dict):
                    continue
                addresses = []
                for a in r.get('addresses') or []:
                    ip = _probe_ip(a.get('address')) if isinstance(a, dict) else None
                    if ip is not None:
                        addresses.append(Dhcp6Address(address=ip, preferred=a.get('preferred'), valid=a.get('valid')))
                parsed.append(Dhcp6Reply(
                    query=query_id, msg_type=r.get('msg_type'), src=_probe_ip(r.get('src')),
                    server_duid=r.get('server_duid'), addresses=addresses,
                    status_code=r.get('status_code'), status_message=r.get('status_message'),
                    dns_servers=_probe_ips(r.get('dns_servers')),
                    domain_search=[str(d).rstrip('.') for d in (r.get('domain_search') or [])],
                    preference=r.get('preference'), raw=r))
            replies[query_id] = parsed
    return ras, replies


def ipv6_probe(grade: Grade0, machine: str, spec: dict, step: int = 1, timeout: int = 30) -> tuple:
    """Run the probe installed on *machine* and return ``(ras, replies)`` (parse_ipv6_probe).

    *spec* comes from ``ipv6_probe_spec()`` and must be built from lab data only (never from
    test results) so that the command is identical on every grade pass.
    """
    output, _ = grade.test(machine, ipv6_probe_command(spec), step=step, timeout=timeout, allow_error=True)
    return parse_ipv6_probe(output)


def advertised(replies: list, msg_type: str = 'ADVERTISE') -> list:
    """The replies of a query of the given message type."""
    return [r for r in replies if r.msg_type == msg_type]
