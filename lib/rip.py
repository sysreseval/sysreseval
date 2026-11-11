"""RIP grading helpers built on the passive probe ``lib/rip_probe.py``.

The probe is a daemon of a hidden machine that has an interface, without any address, on every
network to watch: it never sends a frame (so it is neither a RIP peer nor an ARP / ping target)
and records the RIP updates the routers really emit there.  Grading what is *announced* on a
link does not depend on the way a router was configured: a passive interface is one no update
is heard from, poisoned reverse shows as routes announced with metric 16, an ``offset-list out``
as a larger metric, MD5 authentication as a trailer whose digest matches the key of the lab.

State side: :func:`install_rip_probe`, :func:`rip_listen_cmd` (the listener),
:func:`rip_announce_cmd` (a rogue RIP speaker, e.g. on a second hidden machine).  Grade side:
:func:`get_rip_probe` runs the static ``dump`` command and returns a :class:`RipProbe`;
:func:`rip_window` gives how long ago an update still counts as current, :func:`probe_ready`
says whether a silence may be trusted, :func:`heard` / :func:`announced` / :func:`announced_metric`
/ :func:`md5_authenticated` read it.  The vtysh side (``show ip rip``, ``show ip rip status``) is
in ``lib/frr.py``.  Tests: ``tests/test_rip.py``.

An evaluation only sees a configuration change once the router has sent an update with it: at
most one update period later (30 s by default, plus a quarter of jitter).
"""
import base64
import json
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from SRE.lib_sre import Grade0, NetScheme0

#: where install_rip_probe() copies lib/rip_probe.py
RIP_PROBE_PATH = '/usr/local/sbin/rip_probe.py'
RIP_LISTEN_PID_FILE = '/run/rip_probe_listen.pid'
RIP_ANNOUNCE_PID_FILE = '/run/rip_probe_announce.pid'
#: metric of an unreachable route
RIP_INFINITY = 16
#: timers of ripd without `timers basic`
RIP_DEFAULT_UPDATE = 30
#: bounds of the update timer used for a window: `timers basic` refuses less than 5 s, and a huge
#: timer must not make old announcements count
RIP_MIN_UPDATE = 5
RIP_MAX_UPDATE = 30
#: seconds added to the longest gap between two updates (the update timer plus a quarter)
RIP_WINDOW_MARGIN = 3
#: the listener rewrites its state every second: an older heartbeat means it is dead
RIP_HEARTBEAT_MAX_AGE = 10


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def _encode(spec: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).decode()


def _restart(pid_file: str, mode: str, spec: dict) -> str:
    return (f"sh -c '[ -f {pid_file} ] && kill $(cat {pid_file}) 2>/dev/null; sleep 0.2; "
            f"python3 {RIP_PROBE_PATH} {mode} {_encode(spec)}'")


def install_rip_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy lib/rip_probe.py to RIP_PROBE_PATH on *machine* (usually a hidden one)."""
    script = Path(__file__).with_name('rip_probe.py').read_text()
    net_scheme.file(machine, RIP_PROBE_PATH, script, permissions=0o755, step=step)


def rip_listen_cmd(interfaces, keys: Optional[dict] = None) -> str:
    """Shell command (re)starting the listener on *interfaces* (names).  *keys*:
    ``{key id: secret}`` of the MD5 keys of the lab, to tell whether a digest is valid."""
    spec = {'interfaces': [str(i) for i in interfaces],
            'keys': {str(key_id): str(secret) for key_id, secret in (keys or {}).items()}}
    return _restart(RIP_LISTEN_PID_FILE, 'listen', spec)


def rip_announce_cmd(source, routes, interval: float = 2) -> str:
    """Shell command (re)starting a rogue RIP speaker: every *interval* seconds a RIPv2 response
    from port 520 of *source* (an address of the machine) to 224.0.0.9 announcing *routes*
    (``[(prefix, metric)]``).  ripd believes any host of a connected subnet of an interface RIP
    runs on, a passive one included."""
    spec = {'source': str(source).split('/')[0], 'interval': interval,
            'routes': [[str(prefix), int(metric)] for prefix, metric in routes]}
    return _restart(RIP_ANNOUNCE_PID_FILE, 'announce', spec)


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


def rip_dump_cmd() -> str:
    """The command printing what the listener heard; it never changes (stable across passes)."""
    return f'python3 {RIP_PROBE_PATH} dump'


@dataclass
class RipRoute:
    """One route of the updates of a source."""
    prefix: IPv4Network
    metric: int
    age: float
    next_hop: Optional[IPv4Address] = None
    tag: int = 0


@dataclass
class RipSource:
    """What one router sent on one interface of the probe (group-addressed responses only)."""
    interface: str
    address: IPv4Address
    age: Optional[float] = None         # seconds since its last update, None when it sent none
    packets: int = 0
    version: Optional[int] = None
    destination: Optional[str] = None
    auth_type: str = 'none'             # 'none', 'text', 'md5' of its last update
    key_id: Optional[int] = None
    auth_len: Optional[int] = None
    auth_valid: bool = False            # MD5 digest matching a key of the lab
    password: Optional[str] = None      # clear-text password of a 'text' authentication
    requests: int = 0
    unicast: int = 0
    routes: Dict[IPv4Network, RipRoute] = field(default_factory=dict)


@dataclass
class RipProbe:
    """Result of one ``dump``.  ``ran`` is False on the registration pass and whenever the probe
    did not answer with its JSON document."""
    ran: bool = False
    uptime: Optional[float] = None
    heartbeat_age: Optional[float] = None
    errors: List[str] = field(default_factory=list)
    sources: Dict[Tuple[str, IPv4Address], RipSource] = field(default_factory=dict)


def _float(value) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _int(value) -> Optional[int]:
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else None


def _address(value) -> Optional[IPv4Address]:
    try:
        return IPv4Address(value)
    except (ValueError, TypeError):
        return None


def _network(value) -> Optional[IPv4Network]:
    try:
        return IPv4Network(value)
    except (ValueError, TypeError):
        return None


def _parse_source(interface: str, address: IPv4Address, raw: dict) -> RipSource:
    auth = raw.get('auth') if isinstance(raw.get('auth'), dict) else {}
    source = RipSource(
        interface=interface, address=address, age=_float(raw.get('age')), packets=_int(raw.get('packets')) or 0,
        version=_int(raw.get('version')), destination=raw.get('dst') if isinstance(raw.get('dst'), str) else None,
        auth_type=str(auth.get('type', 'none')), key_id=_int(auth.get('key_id')), auth_len=_int(auth.get('auth_len')),
        auth_valid=auth.get('valid') is True,
        password=auth.get('password') if isinstance(auth.get('password'), str) else None,
        requests=_int(raw.get('requests')) or 0, unicast=_int(raw.get('unicast')) or 0)
    entries = raw.get('entries') if isinstance(raw.get('entries'), dict) else {}
    for prefix, entry in entries.items():
        network = _network(prefix)
        if network is None or not isinstance(entry, dict):
            continue
        metric, age = _int(entry.get('metric')), _float(entry.get('age'))
        if metric is None or age is None:
            continue
        source.routes[network] = RipRoute(prefix=network, metric=metric, age=age,
                                          next_hop=_address(entry.get('next_hop')), tag=_int(entry.get('tag')) or 0)
    return source


def parse_rip_probe(output: str) -> RipProbe:
    """Parse the JSON document of ``rip_probe.py dump`` (see lib/rip_probe.py).  Anything else —
    the placeholder of a registration pass, a traceback — gives ``RipProbe(ran=False)``."""
    try:
        data = json.loads(output)
    except (ValueError, TypeError):
        return RipProbe()
    if not isinstance(data, dict) or not isinstance(data.get('interfaces'), dict):
        return RipProbe()
    errors = [str(e) for e in data.get('errors') or []] if isinstance(data.get('errors'), list) else []
    probe = RipProbe(ran=True, uptime=_float(data.get('uptime')), heartbeat_age=_float(data.get('heartbeat_age')),
                     errors=errors)
    for interface, sources in data['interfaces'].items():
        if not isinstance(sources, dict):
            continue
        for src, raw in sources.items():
            address = _address(src)
            if address is not None and isinstance(raw, dict):
                probe.sources[(interface, address)] = _parse_source(interface, address, raw)
    return probe


def get_rip_probe(grade: Grade0, machine: str, step: int = 1, timeout: int = 20) -> RipProbe:
    """Read what the listener of *machine* heard (see :func:`parse_rip_probe`)."""
    output, _ = grade.test(machine, rip_dump_cmd(), step=step, timeout=timeout, allow_error=True)
    return parse_rip_probe(output)


def rip_window(update=None) -> int:
    """Seconds within which a router sending an update every *update* seconds must have been
    heard: ripd waits the update timer plus or minus a quarter.  *update* is what the router
    itself reports (``get_rip_status()['update']``); ``None`` (RIP not running) and out-of-range
    values fall back on the bounds, so that an announcement older than about 40 s never counts."""
    try:
        value = int(update)
    except (TypeError, ValueError):
        value = RIP_DEFAULT_UPDATE
    value = max(RIP_MIN_UPDATE, min(RIP_MAX_UPDATE, value))
    return value + value // 4 + RIP_WINDOW_MARGIN


def probe_ready(probe: RipProbe, window: float = 0) -> bool:
    """True when a silence of *window* seconds can be trusted: the listener is alive (fresh
    heartbeat) and has been listening for at least that long.  Every check of something that
    must *not* be heard needs it."""
    if not probe.ran or probe.uptime is None or probe.heartbeat_age is None:
        return False
    return probe.heartbeat_age <= RIP_HEARTBEAT_MAX_AGE and probe.uptime >= window


def rip_source(probe: RipProbe, interface: str, address) -> Optional[RipSource]:
    """What *address* (an address or interface object) sent on *interface*, or None."""
    host = _address(str(address).split('/')[0])
    return probe.sources.get((interface, host)) if host is not None else None


def heard(probe: RipProbe, interface: str, address, window: float) -> bool:
    """True when *address* sent an update on *interface* during the last *window* seconds."""
    source = rip_source(probe, interface, address)
    return source is not None and source.age is not None and source.age <= window


def announced(probe: RipProbe, interface: str, address, window: float) -> Dict[IPv4Network, int]:
    """``{prefix: metric}`` of the routes *address* announced on *interface* during the last
    *window* seconds.  A metric of 16 is a withdrawal (route poisoning, poisoned reverse): filter
    on ``< RIP_INFINITY`` for the routes really offered."""
    source = rip_source(probe, interface, address)
    if source is None:
        return {}
    return {prefix: route.metric for prefix, route in source.routes.items() if route.age <= window}


def announced_metric(probe: RipProbe, interface: str, address, prefix, window: float) -> Optional[int]:
    """Metric *address* announced for *prefix* on *interface* during the last *window* seconds,
    None when it did not announce it."""
    network = _network(str(prefix))
    return announced(probe, interface, address, window).get(network) if network is not None else None


def md5_authenticated(probe: RipProbe, interface: str, address, window: float, key_id: Optional[int] = None) -> bool:
    """True when the last update of *address* on *interface*, at most *window* seconds old,
    carries an MD5 trailer valid for a key of the lab (and announces *key_id* when given)."""
    source = rip_source(probe, interface, address)
    if source is None or source.age is None or source.age > window:
        return False
    if source.auth_type != 'md5' or not source.auth_valid:
        return False
    return key_id is None or source.key_id == int(key_id)
