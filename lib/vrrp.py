"""VRRP / keepalived helpers of the VRRP lab (``lab/sre/_DRAFT_misc/vrrp.py``).

Everything here was written from outputs captured live on 2026-11-11 (keepalived 2.2.7, tcpdump
4.99, radvd 2.19 on the Debian 12 images, Linux 6.12 host): fixtures in ``tests/mock_data/vrrp/``,
tests in ``tests/test_vrrp.py``.

* **Configuration**: :func:`parse_keepalived_conf` reads a ``keepalived.conf`` into
  ``{'global_defs', 'scripts', 'groups', 'instances', 'errors'}`` (typed fields: VRID, priority,
  virtual addresses, authentication, unicast peers, tracking, ``use_vmac``, notify scripts), queried
  with :func:`find_instance`, :func:`instance_group`, :func:`tracked_scripts`,
  :func:`tracked_interfaces`, :func:`notify_paths`, :func:`instance_addresses`.
* **Advertisements**: :func:`vrrp_capture_cmd` (a ``tcpdump -e -n -v`` of a few seconds) and
  :func:`parse_tcpdump_vrrp` (VRRPv2 and VRRPv3, IPv4 and IPv6, with or without ``-e`` / ``-v``:
  source, destination, VRID, priority, authentication type and password, interval, addresses, TTL,
  MAC addresses), :func:`adverts`, :func:`advert_interval`, :func:`is_multicast_advert`.
* **Arithmetic**: :func:`virtual_mac`, :func:`skew_time`, :func:`master_down_interval`.
* **Notify log**: :func:`parse_notify_log` for the lines a ``notify`` script writes from the four
  arguments keepalived gives it (``GROUP|INSTANCE name state priority``).
* **Hidden mirror**: the students' ``/etc/keepalived`` and ``/etc/radvd.conf`` travel as one base64
  tar archive (:func:`config_archive_cmd`, checked by :func:`read_archive` before anything is
  unpacked, :func:`apply_archive_cmd`); failures are injected with :func:`drop_echo_from_cmd` /
  :func:`fault_clear_cmd` and plain ``ip link`` commands, and measured after a bounded wait
  (:func:`wait_cmd` on :func:`holds_address` / :func:`echo_server_is`).
* **Forged advertisements**: :func:`install_vrrp_probe` copies ``lib/vrrp_probe.py`` into a (hidden)
  machine, :func:`forged_adverts_cmd` makes it announce a virtual router with priority 255 for a
  few seconds, :func:`parse_vrrp_probe` reads its JSON.

Facts (verified live on 2026-11-11):

* the Debian unit is ``Type=notify`` with ``ConditionFileNotEmpty=/etc/keepalived/keepalived.conf``;
  ``keepalived -t`` prints nothing and exits 0 on a valid file;
* with ``state MASTER`` and a priority below 255 an instance still starts as a backup and takes
  over after the master-down interval (3.4 to 3.7 s for ``advert_int 1``); a stopped master sends
  an advertisement of priority 0 and the backup takes over within 0.1 s; a link put down is
  noticed at once (``Netlink reports eth0 down``, FAULT state) but the backup waits the
  master-down interval, since no priority 0 advertisement can leave;
* in a sync group an unweighted tracked script puts the whole group in the FAULT state
  (``VRRP_Group(G_EDGE) Syncing instances to FAULT state``): 4 to 6 s after the upstream dies with
  ``interval 2`` / ``fall 2``, 6 to 8 s to come back with ``rise 2``; the group's ``notify`` script
  gets ``GROUP <name> <state> 0``;
* ``auth_type PASS``: tcpdump prints ``authtype simple`` and the password in clear
  (``auth "Btp3vVIY"``); an advertisement without it is logged ``received a 0 auth, expecting 1!``
  and ignored, one carrying it with a higher priority makes the master step down;
* ``unicast_peer``: the advertisements go to the peer's address instead of 224.0.0.18;
* ``use_vmac``: keepalived creates the macvlan ``vrrp.<vrid>`` (MAC ``00:00:5e:00:01:<vrid>``,
  ``inet6_addr_gen_mode none``) on every router, master or backup, sets ``arp_ignore=1`` and
  ``arp_filter=1`` on the base interface and adds an nft table ``ip keepalived``; the
  advertisements leave with the virtual MAC as source.  The backup keeps its macvlan up: on a hub
  it receives the frames sent to the virtual MAC too, forwards them a second time or answers
  ``net unreachable``, so the LAN must be a switch.  Unless ``arp_announce=2``, a router answering
  from the virtual address sends its ARP requests from its real MAC with the virtual address as
  sender, and the clients replace the virtual MAC by the real one in their cache;
* ``vde_switch`` (the Kathara switch) keeps a MAC address 3 s on its old port (``Min persistence``
  of ``hash/showinfo``): after a graceful handover a virtual MAC is unreachable for 3 to 4 s,
  unless ``hash/setminper 0`` was run on the console of a managed switch;
* an IPv6 instance is VRRPv3 (``intvl 100cs`` to ``ff02::12``, hop limit 255); radvd with
  ``AdvRASrcAddress { fe80::1; };`` sends its advertisements from the virtual link-local address
  on the master and stays silent on the backup, without any error.
"""
import base64
import binascii
import io
import json
import re
import shlex
import tarfile
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0, NetScheme0

#: where keepalived reads its configuration; the lab keeps its scripts there too (the whole
#: directory is replayed on the hidden mirror)
KEEPALIVED_DIR = "/etc/keepalived"
KEEPALIVED_CONF = f"{KEEPALIVED_DIR}/keepalived.conf"
KEEPALIVED_UNIT = "keepalived"
RADVD_CONF = "/etc/radvd.conf"
RADVD_UNIT = "radvd"
VRRP_GROUP4 = "224.0.0.18"
VRRP_GROUP6 = "ff02::12"
VRRP_PROTOCOL = 112
VRRP_TTL = 255
VMAC_PREFIX = "vrrp."            # default name of a use_vmac interface: vrrp.<vrid>


# ---------------------------------------------------------------------------
# arithmetic
# ---------------------------------------------------------------------------


def virtual_mac(vrid: int, ipv6: bool = False) -> str:
    """Virtual router MAC address of *vrid* (RFC 5798 §7.3): ``00:00:5e:00:01:<vrid>`` for
    IPv4, ``00:00:5e:00:02:<vrid>`` for IPv6."""
    if not 1 <= int(vrid) <= 255:
        raise ValueError(f"virtual_mac: VRID {vrid!r} is not in 1..255")
    return f"00:00:5e:00:{2 if ipv6 else 1:02x}:{int(vrid):02x}"


def skew_time(priority: int, advert_int: float = 1.0, version: int = 2) -> float:
    """Skew time in seconds: ``(256 - priority) / 256`` in VRRPv2 (RFC 3768), scaled by the
    advertisement interval of the master in VRRPv3 (RFC 5798)."""
    skew = (256 - int(priority)) / 256
    return skew * float(advert_int) if version == 3 else skew


def master_down_interval(advert_int: float = 1.0, priority: int = 100, version: int = 2) -> float:
    """Seconds without advertisement after which a backup of that *priority* takes over:
    ``3 * advert_int + skew_time``."""
    return 3 * float(advert_int) + skew_time(priority, advert_int, version)


# ---------------------------------------------------------------------------
# keepalived.conf
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'|([{}])|([^\s{}"\']+)')
NOTIFY_KEYS = ('notify', 'notify_master', 'notify_backup', 'notify_fault', 'notify_stop')


def _strip_comment(line: str) -> str:
    """*line* without its comment: ``#`` or ``!`` outside quotes."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in '"\'':
            quote = ch
        elif ch in '#!':
            return line[:i]
    return line


def parse_keepalived_statements(text: str) -> tuple:
    """Syntax tree of a keepalived configuration: ``(statements, errors)`` where a statement is
    ``{'words': [...], 'block': [statements] | None, 'line': n}``.  A block opens with ``{`` at
    the end of a line (or alone on the next one) and closes with ``}``."""
    root: List[dict] = []
    stack = [root]
    errors: List[str] = []
    last: Optional[dict] = None
    for number, raw in enumerate((text or '').splitlines(), 1):
        words = []
        for quoted, single, brace, word in _WORD_RE.findall(_strip_comment(raw)):
            words.append(('brace', brace) if brace else ('word', quoted or single or word))
        current: List[str] = []

        def flush():
            nonlocal last
            if current:
                last = {'words': list(current), 'block': None, 'line': number}
                stack[-1].append(last)
                current.clear()

        for kind, value in words:
            if kind == 'word':
                current.append(value)
            elif value == '{':
                flush()
                if last is None or last['block'] is not None:
                    errors.append(f"line {number}: '{{' without a keyword")
                    last = {'words': [], 'block': None, 'line': number}
                    stack[-1].append(last)
                last['block'] = []
                stack.append(last['block'])
                last = None
            else:
                flush()
                if len(stack) == 1:
                    errors.append(f"line {number}: unexpected '}}'")
                else:
                    stack.pop()
                last = None
        flush()
    if len(stack) > 1:
        errors.append("missing '}' at the end of the file")
    return root, errors


def _args(block: Optional[List[dict]], key: str) -> Optional[List[str]]:
    """Arguments of the first statement *key* of *block* (``None`` when absent)."""
    for statement in block or []:
        if statement['words'] and statement['words'][0] == key:
            return statement['words'][1:]
    return None


def _value(block, key: str) -> Optional[str]:
    args = _args(block, key)
    return args[0] if args else None


def _number(block, key: str, kind=int):
    value = _value(block, key)
    try:
        return kind(value) if value is not None else None
    except ValueError:
        return None


def _children(block: Optional[List[dict]], key: str) -> List[dict]:
    """Statements inside every sub-block *key* of *block*."""
    result: List[dict] = []
    for statement in block or []:
        if statement['words'] and statement['words'][0] == key and statement['block'] is not None:
            result.extend(statement['block'])
    return result


def _tracked(block, key: str) -> List[dict]:
    """Entries of a ``track_script`` / ``track_interface`` block: ``{'name', 'weight'}``
    (``weight`` 0 when none is given: a failure then means the FAULT state)."""
    entries = []
    for statement in _children(block, key):
        words = statement['words']
        weight = 0
        if 'weight' in words[1:]:
            try:
                weight = int(words[words.index('weight', 1) + 1])
            except (ValueError, IndexError):
                weight = 0
        entries.append({'name': words[0], 'weight': weight})
    return entries


def _addresses(block, key: str, errors: List[str]) -> List[dict]:
    """Entries of a ``virtual_ipaddress`` block: ``{'address', 'prefixlen', 'dev', 'family'}``
    (``prefixlen`` ``None`` when no mask is written: keepalived then installs a host address)."""
    entries = []
    for statement in _children(block, key):
        words = statement['words']
        text, _, mask = words[0].partition('/')
        try:
            address = ip_address(text)
            prefixlen = int(mask) if mask else None
        except ValueError:
            errors.append(f"line {statement['line']}: {words[0]!r} is not an address")
            continue
        dev = words[words.index('dev') + 1] if 'dev' in words[1:-1] else None
        entries.append({'address': str(address), 'prefixlen': prefixlen, 'dev': dev, 'family': address.version})
    return entries


def _notify(block) -> Dict[str, str]:
    """``{notify_master: path, ...}`` of a block (the script path alone, without its arguments)."""
    result = {}
    for key in NOTIFY_KEYS:
        args = _args(block, key)
        if args:
            result[key] = args[0].split()[0] if args[0].split() else ''
    return result


def parse_keepalived_conf(text: str) -> Dict[str, Any]:
    """Parse a ``keepalived.conf``.

    Returns ``{'global_defs': {...}, 'scripts': {name: {...}}, 'groups': {name: {...}},
    'instances': {name: {...}}, 'errors': [...]}``:

    * global_defs: ``router_id``, ``enable_script_security``, ``script_user``, ``vrrp_version``;
    * script: ``script`` (the command), ``interval``, ``timeout``, ``weight`` (0 by default),
      ``fall``, ``rise``, ``user``, ``init_fail``;
    * group: ``members``, ``track_scripts``, ``track_interfaces``, ``notify``;
    * instance: ``state``, ``interface``, ``vrid``, ``priority``, ``advert_int``, ``version``,
      ``auth_type``, ``auth_pass``, ``vips`` / ``excluded_vips`` (see :func:`_addresses`),
      ``unicast_src_ip``, ``unicast_peers``, ``track_scripts``, ``track_interfaces``,
      ``use_vmac``, ``vmac_name``, ``vmac_xmit_base``, ``nopreempt``, ``preempt_delay``, ``notify``.

    Unknown keywords are ignored; a missing value is ``None``.  Nothing is validated beyond the
    syntax: ``keepalived -t`` does that on the machine.
    """
    statements, errors = parse_keepalived_statements(text)
    conf: Dict[str, Any] = {'global_defs': {}, 'scripts': {}, 'groups': {}, 'instances': {}, 'errors': errors}
    for statement in statements:
        words, block = statement['words'], statement['block']
        if not words or block is None:
            continue
        kind, name = words[0], (words[1] if len(words) > 1 else '')
        if kind == 'global_defs':
            conf['global_defs'] = {
                'router_id': _value(block, 'router_id'),
                'enable_script_security': _args(block, 'enable_script_security') is not None,
                'script_user': _value(block, 'script_user'),
                'vrrp_version': _number(block, 'vrrp_version'),
            }
        elif kind == 'vrrp_script':
            conf['scripts'][name] = {
                'name': name, 'script': _value(block, 'script'),
                'interval': _number(block, 'interval', float), 'timeout': _number(block, 'timeout', float),
                'weight': _number(block, 'weight') or 0, 'fall': _number(block, 'fall'),
                'rise': _number(block, 'rise'), 'user': _value(block, 'user'),
                'init_fail': _args(block, 'init_fail') is not None,
            }
        elif kind == 'vrrp_sync_group':
            conf['groups'][name] = {
                'name': name, 'members': [s['words'][0] for s in _children(block, 'group')],
                'track_scripts': _tracked(block, 'track_script'),
                'track_interfaces': _tracked(block, 'track_interface'),
                'notify': _notify(block),
            }
        elif kind == 'vrrp_instance':
            authentication = _children(block, 'authentication')
            vmac = _args(block, 'use_vmac')
            conf['instances'][name] = {
                'name': name, 'state': _value(block, 'state'), 'interface': _value(block, 'interface'),
                'vrid': _number(block, 'virtual_router_id'), 'priority': _number(block, 'priority'),
                'advert_int': _number(block, 'advert_int', float), 'version': _number(block, 'version'),
                'auth_type': _value(authentication, 'auth_type'), 'auth_pass': _value(authentication, 'auth_pass'),
                'vips': _addresses(block, 'virtual_ipaddress', errors),
                'excluded_vips': _addresses(block, 'virtual_ipaddress_excluded', errors),
                'unicast_src_ip': _value(block, 'unicast_src_ip'),
                'unicast_peers': [s['words'][0] for s in _children(block, 'unicast_peer')],
                'track_scripts': _tracked(block, 'track_script'),
                'track_interfaces': _tracked(block, 'track_interface'),
                'use_vmac': vmac is not None, 'vmac_name': vmac[0] if vmac else None,
                'vmac_xmit_base': _args(block, 'vmac_xmit_base') is not None,
                'nopreempt': _args(block, 'nopreempt') is not None,
                'preempt_delay': _number(block, 'preempt_delay', float),
                'notify': _notify(block),
            }
    return conf


def instance_addresses(instance: Optional[dict], excluded: bool = False) -> List[str]:
    """Virtual addresses of an instance (``virtual_ipaddress``, or ``virtual_ipaddress_excluded``)."""
    if not instance:
        return []
    return [entry['address'] for entry in instance['excluded_vips' if excluded else 'vips']]


def find_instance(conf: dict, vrid: int = None, interface: str = None, vip=None) -> Optional[dict]:
    """The first instance of *conf* matching every given criterion: the VRID, the interface, a
    virtual address of its ``virtual_ipaddress`` block."""
    wanted = str(ip_address(str(vip).split('/')[0])) if vip is not None else None
    for instance in conf.get('instances', {}).values():
        if vrid is not None and instance['vrid'] != int(vrid):
            continue
        if interface is not None and instance['interface'] != interface:
            continue
        if wanted is not None and wanted not in instance_addresses(instance):
            continue
        return instance
    return None


def instance_group(conf: dict, instance: Optional[dict]) -> Optional[dict]:
    """The sync group *instance* belongs to (``None`` when it is in none)."""
    if not instance:
        return None
    return next((g for g in conf.get('groups', {}).values() if instance['name'] in g['members']), None)


def tracked_scripts(conf: dict, instance: Optional[dict]) -> List[dict]:
    """The scripts whose failure touches *instance*: its own ``track_script`` entries and those of
    its sync group, each as ``{'name', 'weight', 'via': 'instance' | 'group', 'script': the
    vrrp_script definition or None}``."""
    if not instance:
        return []
    group = instance_group(conf, instance)
    entries = [dict(e, via='instance') for e in instance['track_scripts']]
    entries += [dict(e, via='group') for e in (group['track_scripts'] if group else [])]
    for entry in entries:
        entry['script'] = conf.get('scripts', {}).get(entry['name'])
    return entries


def tracked_interfaces(conf: dict, instance: Optional[dict]) -> List[dict]:
    """``track_interface`` entries of *instance* and of its sync group (``{'name', 'weight', 'via'}``)."""
    if not instance:
        return []
    group = instance_group(conf, instance)
    return ([dict(e, via='instance') for e in instance['track_interfaces']]
            + [dict(e, via='group') for e in (group['track_interfaces'] if group else [])])


def notify_paths(conf: dict, instance: Optional[dict]) -> List[str]:
    """Paths of the notify scripts run for *instance*: its own and those of its sync group."""
    if not instance:
        return []
    group = instance_group(conf, instance)
    paths = list(instance['notify'].values()) + (list(group['notify'].values()) if group else [])
    return [p for p in dict.fromkeys(paths) if p]


# ---------------------------------------------------------------------------
# advertisements (tcpdump)
# ---------------------------------------------------------------------------

VRRP_CAPTURE_FILTER = "vrrp or ip6 proto 112"
_TIME_RE = re.compile(r'^(\d\d):(\d\d):(\d\d)\.(\d+)\s')
_ETHER_RE = re.compile(r'\s([0-9a-f]{2}(?::[0-9a-f]{2}){5}) > ([0-9a-f]{2}(?::[0-9a-f]{2}){5}), ethertype')
_TTL_RE = re.compile(r'\b(?:ttl|hlim) (\d+)')
_ADVERT_RE = re.compile(
    r'(?P<src>[0-9a-fA-F.:]+) > (?P<dst>[0-9a-fA-F.:]+): VRRPv(?P<version>\d), Advertisement, '
    r'vrid (?P<vrid>\d+), prio (?P<priority>\d+)(?:, authtype (?P<auth>[\w#-]+))?'
    r', intvl (?P<interval>\d+)(?P<unit>cs|s), length \d+'
    r'(?:, addrs(?:\(\d+\))?: (?P<addresses>[0-9a-fA-F.:,]+))?(?: auth "(?P<password>[^"]*)")?')


def vrrp_capture_cmd(interface: str = 'eth0', seconds: int = 4) -> str:
    """Capture of the VRRP advertisements seen on *interface* during *seconds* (IPv4 and IPv6),
    with the Ethernet header and the details: the text :func:`parse_tcpdump_vrrp` reads."""
    return (f"timeout {int(seconds)} tcpdump -i {shlex.quote(interface)} -e -n -v -l "
            f"'{VRRP_CAPTURE_FILTER}' 2>/dev/null")


def parse_tcpdump_vrrp(output: str) -> List[Dict[str, Any]]:
    """VRRP advertisements of a ``tcpdump -n [-e] [-v]`` output.

    Each one is ``{'time' (seconds of the day), 'src', 'dst', 'family' (4 | 6), 'version',
    'vrid', 'priority', 'auth_type' ('none' | 'simple' | 'ah', None in VRRPv3), 'password' (what a
    capture shows of ``auth_type PASS``, None otherwise), 'interval' (seconds), 'addresses',
    'ttl', 'src_mac', 'dst_mac'}``; ``ttl`` needs ``-v``, the MAC addresses need ``-e``, the
    addresses and the password need ``-v`` (``None`` / ``[]`` without them).
    """
    records: List[str] = []
    for line in (output or '').splitlines():
        if _TIME_RE.match(line):
            records.append(line)
        elif records and line[:1] in (' ', '\t'):
            records[-1] += ' ' + line.strip()
    frames = []
    for record in records:
        match = _ADVERT_RE.search(record)
        if not match:
            continue
        try:
            src, dst = ip_address(match['src']), ip_address(match['dst'])
        except ValueError:
            continue
        hours, minutes, seconds, fraction = _TIME_RE.match(record).groups()
        ether = _ETHER_RE.search(record)
        ttl = _TTL_RE.search(record)
        interval = int(match['interval']) / (100 if match['unit'] == 'cs' else 1)
        frames.append({
            'time': int(hours) * 3600 + int(minutes) * 60 + int(seconds) + float(f"0.{fraction}"),
            'src': str(src), 'dst': str(dst), 'family': src.version,
            'version': int(match['version']), 'vrid': int(match['vrid']), 'priority': int(match['priority']),
            'auth_type': match['auth'], 'password': match['password'], 'interval': interval,
            'addresses': [str(ip_address(a)) for a in (match['addresses'] or '').split(',') if a],
            'ttl': int(ttl[1]) if ttl else None,
            'src_mac': ether[1] if ether else None, 'dst_mac': ether[2] if ether else None,
        })
    return frames


def adverts(frames: List[dict], vrid: int = None, src=None, version: int = None) -> List[dict]:
    """The advertisements of *frames* for that virtual router, from that source, of that version."""
    source = str(ip_address(str(src).split('/')[0])) if src is not None else None
    return [f for f in frames
            if (vrid is None or f['vrid'] == int(vrid))
            and (source is None or f['src'] == source)
            and (version is None or f['version'] == int(version))]


def advert_interval(frames: List[dict]) -> Optional[float]:
    """Median time between two successive advertisements of *frames* (one virtual router, one
    source), ``None`` with fewer than two of them."""
    times = sorted(f['time'] for f in frames)
    gaps = sorted(b - a for a, b in zip(times, times[1:]))
    return gaps[len(gaps) // 2] if gaps else None


def is_multicast_advert(frame: dict) -> bool:
    """True when the advertisement went to the VRRP group (224.0.0.18 / ff02::12), False when
    it was sent to a unicast peer."""
    return frame['dst'] in (VRRP_GROUP4, VRRP_GROUP6)


# ---------------------------------------------------------------------------
# notify log
# ---------------------------------------------------------------------------

_NOTIFY_RE = re.compile(r'\b(GROUP|INSTANCE)\s+"?([\w.-]+)"?\s+(MASTER|BACKUP|FAULT|STOP|DELETED)\b(?:\s+(\d+))?')


def parse_notify_log(text: str) -> List[Dict[str, Any]]:
    """Transitions written by a ``notify`` script from its four arguments, whatever surrounds
    them on the line: ``[{'kind': 'GROUP' | 'INSTANCE', 'name', 'state', 'priority', 'line'}]``
    in file order (``priority`` is ``None`` when the script did not write it)."""
    entries = []
    for line in (text or '').splitlines():
        match = _NOTIFY_RE.search(line)
        if match:
            entries.append({'kind': match[1], 'name': match[2], 'state': match[3],
                            'priority': int(match[4]) if match[4] else None, 'line': line.strip()})
    return entries


def notify_states(entries: List[dict], name: str = None) -> List[str]:
    """The successive states of the log, for the group or instance *name* when given."""
    return [e['state'] for e in entries if name is None or e['name'] == name]


# ---------------------------------------------------------------------------
# hidden mirror: the configuration archive
# ---------------------------------------------------------------------------

#: what is replayed on the clone of a router, relative to /
ARCHIVE_PATHS = (KEEPALIVED_DIR.lstrip('/'), RADVD_CONF.lstrip('/'))
#: the commands of one machine and step travel in one environment variable (128 KiB on Linux)
MAX_ARCHIVE_B64 = 64 * 1024
MAX_ARCHIVE_MEMBERS = 64


def config_archive_cmd() -> str:
    """Shell command printing, in base64 on one line, a gzipped tar of ``/etc/keepalived`` and
    ``/etc/radvd.conf`` (whichever exists; nothing when neither does)."""
    paths = ' '.join(ARCHIVE_PATHS)
    return f"cd / && tar -czf - $(ls -d {paths} 2>/dev/null) 2>/dev/null | base64 -w0"


def _allowed_member(name: str) -> bool:
    name = name.rstrip('/')
    if name.startswith('/') or '..' in name.split('/'):
        return False
    directory, single_file = ARCHIVE_PATHS
    return name == directory or name.startswith(directory + '/') or name == single_file


def read_archive(encoded: str) -> Optional[Dict[str, Dict[str, Any]]]:
    """Check and read the output of :func:`config_archive_cmd`.

    Returns ``{path: {'content': bytes, 'mode': int}}`` for the regular files of the archive
    (paths relative to ``/``), or ``None`` when *encoded* is empty, too big, not a tar archive, or
    holds anything but plain files and directories under the expected paths: the archive is then
    never unpacked on a clone."""
    encoded = (encoded or '').strip()
    if not encoded or len(encoded) > MAX_ARCHIVE_B64:
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                return None
            files = {}
            for member in members:
                name = member.name[2:] if member.name.startswith('./') else member.name
                if not _allowed_member(name) or not (member.isfile() or member.isdir()):
                    return None
                if member.isfile():
                    files[name] = {'content': archive.extractfile(member).read(), 'mode': member.mode & 0o7777}
    except (binascii.Error, ValueError, tarfile.TarError, EOFError, OSError):
        return None
    return files


def archive_text(files: Optional[dict], path: str) -> str:
    """Text of the file *path* (absolute or relative to ``/``) of a :func:`read_archive` result,
    ``''`` when it is not there."""
    entry = (files or {}).get(path.lstrip('/'))
    return entry['content'].decode('utf-8', errors='replace') if entry else ''


def archive_mode(files: Optional[dict], path: str) -> Optional[int]:
    """Permission bits of *path* in the archive (``None`` when it is not there)."""
    entry = (files or {}).get(path.lstrip('/'))
    return entry['mode'] if entry else None


def apply_archive_cmd(encoded: str) -> str:
    """Shell command of a router clone: replace ``/etc/keepalived`` and ``/etc/radvd.conf`` by the
    content of the archive (files owned by root, modes kept) and restart both services.  Only
    for an archive :func:`read_archive` accepted."""
    return (f"rm -rf {KEEPALIVED_DIR} {RADVD_CONF}; "
            f"echo {encoded.strip()} | base64 -d | tar -xzf - -C / --no-same-owner 2>&1; "
            f"systemctl restart --no-block {KEEPALIVED_UNIT} {RADVD_UNIT} 2>&1; true")


def stop_cmd() -> str:
    """Shell command of a router clone: keepalived and radvd stopped, whatever state they were
    in, the leftovers of a killed keepalived removed (macvlan interfaces, its nft table)."""
    return (f"systemctl stop {KEEPALIVED_UNIT} {RADVD_UNIT} 2>/dev/null; pkill -9 -x keepalived 2>/dev/null; "
            f"for i in $(ls /sys/class/net | grep '^{re.escape(VMAC_PREFIX)}'); do ip link del $i 2>/dev/null; done; "
            "nft delete table ip keepalived 2>/dev/null; nft delete table ip6 keepalived 2>/dev/null; true")


# ---------------------------------------------------------------------------
# hidden mirror: failures and waits
# ---------------------------------------------------------------------------

FAULT_TABLE = "sre_vrrp_fault"


def drop_echo_from_cmd(source, table: str = FAULT_TABLE) -> str:
    """Shell command (nftables) making a machine ignore the echo requests of *source*: for the
    router at that address, the machine no longer answers its health check, while everything
    else, forwarding included, still works."""
    address = str(source).split('/')[0]
    return (f"nft add table ip {table}; "
            f"nft 'add chain ip {table} input {{ type filter hook input priority 0; }}'; "
            f"nft add rule ip {table} input ip saddr {address} icmp type echo-request drop")


def fault_clear_cmd(table: str = FAULT_TABLE) -> str:
    """Shell command undoing :func:`drop_echo_from_cmd` (a no-op when nothing was injected)."""
    return f"nft delete table ip {table} 2>/dev/null; true"


def holds_address(address) -> str:
    """Shell condition: this machine has *address* on one of its interfaces."""
    return f"ip -o addr show | grep -qF ' {str(address).split('/')[0]}/'"


def echo_server_is(host, name: str, timeout: int = 1) -> str:
    """Shell condition: the echo server (``lib/server_echo.py``) answering at *host* is *name*."""
    return f"curl -s -m {int(timeout)} http://{str(host).split('/')[0]}/ | grep -qx 'SERVER={name}'"


def wait_cmd(condition: str, seconds: int = 12, period: float = 0.5) -> str:
    """Shell command waiting until *condition* holds, *seconds* at most (it never fails: what is
    measured afterwards tells whether the state was reached).  Register it as a command of its
    own, before the measurements of the machine: retuning a wait then never changes their keys."""
    tries = max(1, int(round(seconds / period)))
    return f"for i in $(seq 1 {tries}); do {condition} && break; sleep {period}; done; true"


# ---------------------------------------------------------------------------
# forged advertisements (lib/vrrp_probe.py run inside a container)
# ---------------------------------------------------------------------------

VRRP_PROBE_PATH = '/usr/local/sbin/vrrp_probe.py'


def install_vrrp_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy ``lib/vrrp_probe.py`` to :data:`VRRP_PROBE_PATH` on *machine* (usually a hidden one)."""
    script = Path(__file__).with_name('vrrp_probe.py').read_text()
    net_scheme.file(machine, VRRP_PROBE_PATH, script, permissions=0o755, step=step)


def forged_adverts_cmd(vrid: int, vips, interface: str = 'eth0', priority: int = 255, seconds: int = 8,
                       password: str = None) -> str:
    """Shell command making the probe announce the virtual router *vrid* (addresses *vips*) with
    *priority* during *seconds*, one VRRPv2 advertisement per second, without password unless
    one is given.  It depends on its arguments only (lab data): the same on every grade pass."""
    command = f"python3 {VRRP_PROBE_PATH} send --iface {shlex.quote(interface)} --vrid {int(vrid)}"
    for vip in vips if isinstance(vips, (list, tuple)) else [vips]:
        command += f" --vip {str(vip).split('/')[0]}"
    command += f" --priority {int(priority)} --seconds {int(seconds)}"
    if password:
        command += f" --password {shlex.quote(password)}"
    return command


def parse_vrrp_probe(output: str) -> Dict[str, Any]:
    """Document printed by the probe: ``{'sent': n, 'error': text | None, 'heard': [{'src',
    'version', 'vrid', 'priority', 'auth_type', 'count'}]}`` (``sent`` 0 and an empty list on
    empty or malformed output)."""
    try:
        document = json.loads(output or '')
    except ValueError:
        document = None
    if not isinstance(document, dict):
        return {'sent': 0, 'error': None, 'heard': []}
    heard = [h for h in document.get('heard') or [] if isinstance(h, dict)]
    return {'sent': int(document.get('sent') or 0), 'error': document.get('error'), 'heard': heard}


def forged_adverts(grade: Grade0, machine: str, vrid: int, vips, step: int = 1, interface: str = 'eth0',
                   priority: int = 255, seconds: int = 8, password: str = None) -> Dict[str, Any]:
    """Run the probe installed on *machine* (:func:`forged_adverts_cmd`) and parse its answer."""
    output, _ = grade.test(machine, forged_adverts_cmd(vrid, vips, interface, priority, seconds, password),
                           step=step, timeout=int(seconds) + 12, allow_error=True)
    return parse_vrrp_probe(output)
