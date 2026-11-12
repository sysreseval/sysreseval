"""Background traffic of the supervision labs: state-side helpers of ``lib/traffic_gen.py``.

``lib/traffic_gen.py`` (standard library only) is copied into a machine, usually a hidden one, by
:func:`install_traffic_gen` and started by :func:`start_traffic` with a *spec* built from the lab
data: listeners (:func:`listener`: UDP or TCP, ``discard`` / ``reply`` / ``http``) and jobs running
until the machine stops —

- :func:`cbr_job`: UDP datagrams at a constant rate (:func:`cbr_pps` gives the packet rate of a
  wanted bit rate on the wire, Ethernet header included): the traffic a student measures with two
  readings of an interface counter (SNMP lab);
- :func:`tcp_stream_job`: one long TCP connection at a given payload rate (a heavy talker);
- :func:`beacon_job`: a few datagrams from a new source port at a fixed period;
- :func:`scan_job`: connection attempts on successive ports, in a loop (a port scanner);
- :func:`web_job`, :func:`dns_job`: low-volume background requests from several source addresses.

The generator detaches by itself, replaces a previous instance using the same pid file (states are
idempotent) and logs to ``/var/log/sre_traffic_gen*.log``.  Sizes on the wire: a UDP datagram of
*payload* bytes is an IP packet of ``payload + 28`` bytes and an Ethernet frame of ``payload + 42``
(what the interface counters and ``ifHCOutOctets`` count; a flow exporter counts the IP packet).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional, Sequence

from SRE.lib_sre import NetScheme0

TRAFFIC_GEN_PATH = "/usr/local/sbin/sre_traffic_gen.py"
UDP_IP_OVERHEAD = 28        #: IPv4 + UDP headers
ETHERNET_OVERHEAD = 14      #: Ethernet header (the FCS is not counted by the kernel)
FRAME_OVERHEAD = UDP_IP_OVERHEAD + ETHERNET_OVERHEAD


def cbr_pps(kbps: float, payload: int) -> float:
    """Datagrams per second giving *kbps* kilobits per second of Ethernet frames."""
    return kbps * 1000 / 8 / (payload + FRAME_OVERHEAD)


def listener(port: int, proto: str = "udp", ip: str = "0.0.0.0", mode: str = "discard", reply_size: int = 64) -> dict:
    """A listener of the spec: *mode* ``discard`` (read and drop), ``reply`` (UDP: answer with
    *reply_size* bytes) or ``http`` (TCP: answer any request with a small page)."""
    return {"proto": proto, "ip": str(ip), "port": int(port), "mode": mode, "reply_size": int(reply_size)}


def _src(src) -> Optional[str]:
    return str(src) if src is not None else None


def cbr_job(dst, port: int, payload: int, pps: float, src=None) -> dict:
    """UDP datagrams of *payload* bytes, *pps* per second, to *dst*:*port*."""
    return {"type": "cbr_udp", "src": _src(src), "dst": str(dst), "port": int(port), "payload": int(payload),
            "pps": float(pps)}


def tcp_stream_job(dst, port: int, kbps: float, src=None) -> dict:
    """One long TCP connection to *dst*:*port* carrying *kbps* kilobits of payload per second."""
    return {"type": "tcp_stream", "src": _src(src), "dst": str(dst), "port": int(port), "kbps": float(kbps)}


def beacon_job(dst, port: int, period: float, count: int, payload: int, src=None) -> dict:
    """Every *period* seconds, *count* datagrams of *payload* bytes to *dst*:*port* from a new
    source port (one flow per burst)."""
    return {"type": "beacon_udp", "src": _src(src), "dst": str(dst), "port": int(port), "period": float(period),
            "count": int(count), "payload": int(payload)}


def scan_job(dst, first_port: int, ports: int, interval: float = 0.5, src=None) -> dict:
    """One TCP connection attempt every *interval* seconds on the *ports* ports from *first_port*,
    in a loop."""
    return {"type": "scan_tcp", "src": _src(src), "dst": str(dst), "first_port": int(first_port),
            "ports": int(ports), "interval": float(interval)}


def web_job(srcs: Sequence, dsts: Sequence, port: int = 80, mean_interval: float = 6.0) -> dict:
    """HTTP GET requests from random *srcs* to random *dsts*, *mean_interval* seconds apart on average."""
    return {"type": "web", "srcs": [str(s) for s in srcs], "dsts": [str(d) for d in dsts], "port": int(port),
            "mean_interval": float(mean_interval)}


def dns_job(srcs: Sequence, dst, port: int = 53, mean_interval: float = 9.0) -> dict:
    """Small UDP exchanges from random *srcs* to *dst*:*port*, *mean_interval* seconds apart on average."""
    return {"type": "dns", "srcs": [str(s) for s in srcs], "dst": str(dst), "port": int(port),
            "mean_interval": float(mean_interval)}


def traffic_spec(listen: Sequence[dict] = (), jobs: Sequence[dict] = (), seed: int = 0, name: str = "") -> dict:
    """The spec of one generator; *name* tells several generators of a machine apart (pid and log
    files)."""
    suffix = f"_{name}" if name else ""
    return {"pidfile": f"/run/sre_traffic_gen{suffix}.pid", "log": f"/var/log/sre_traffic_gen{suffix}.log",
            "seed": int(seed), "listen": list(listen), "jobs": list(jobs)}


def traffic_start_cmd(spec: dict) -> str:
    """Shell command starting the generator with *spec* (it detaches; depends on *spec* only)."""
    encoded = base64.urlsafe_b64encode(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).decode()
    return f"python3 {TRAFFIC_GEN_PATH} {encoded}"


def install_traffic_gen(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy ``lib/traffic_gen.py`` into *machine*."""
    script = Path(__file__).with_name("traffic_gen.py").read_text()
    net_scheme.file(machine, TRAFFIC_GEN_PATH, script, permissions=0o755, step=step)


def start_traffic(net_scheme: NetScheme0, machine: str, spec: dict, step: int = 1) -> None:
    """Start (or restart) the generator of *machine* with *spec*; :func:`install_traffic_gen` first."""
    net_scheme.cmd(machine, traffic_start_cmd(spec), step=step)
