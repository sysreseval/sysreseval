"""fail2ban helpers for the labs (the Suricata / fail2ban lab ``lab/sre/_DRAFT_misc/suricata-fail2ban.py``).

Grade side: :func:`get_jails` (``fail2ban-client status``), :func:`get_jail_status` (failures, banned
addresses), :func:`get_jail_value` (``fail2ban-client get <jail> maxretry|findtime|bantime``),
:func:`get_ignoreip`; the attempts the probes make: :func:`ssh_failures_cmd` (password logins with a
wrong password through ``lib/login_probe.py --bind``), :func:`http_logins_cmd` (``POST /login`` with
``curl --interface``), :func:`tcp_open_cmd` / :func:`parse_tcp_open` (is a port still reachable from a
given source address), :func:`unban_cmd`.  State side: :func:`render_jail` (a ``jail.d`` section).

Facts verified in the Debian 13 images (fail2ban 1.1.0, OpenSSH 10, 2026-11-23):
``/etc/fail2ban/jail.d/defaults-debian.conf`` sets ``banaction = nftables`` and enables ``[sshd]``
with ``backend = systemd`` (journal match ``_SYSTEMD_UNIT=ssh.service + _COMM=sshd``: sshd must run as
``ssh.service``; its ``sshd-session`` lines are seen); every other jail keeps ``backend = auto``
(pyinotify is installed); a ban adds the address to the set ``addr-set-<jail>`` of the table
``inet f2b-table`` (chain ``f2b-chain``, hook ``input``, ``reject``); a jail whose filter is missing
is skipped and the others start; ``fail2ban-client get <jail> ignoreip`` prints ``No IP
address/network is ignored`` or a ``|-`` / ``\\`-`` list; on an unknown jail the client exits 255.
A failed password login costs about 3.5 s (PAM delay).  In a ``failregex``, the date is cut out of
the line first: the rest begins with the blank that followed it (``^\\s*FAILED`` matches,
``^FAILED`` does not); a greedy ``user=.* from=<HOST>`` takes the last ``from=`` of the line, a lazy
``.*?`` or a bare ``from=<HOST>`` the first one (log injection).  ``eve.json`` lines are dated by the
default date detector (``"timestamp":"…+0000"``).
"""
import re
import shlex
from typing import Dict, Iterable, List, Optional

from SRE.lib_sre import Grade0

LOGIN_PROBE_PATH = "/usr/local/sbin/sre_login_probe.py"
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


def parse_jails(text: str) -> List[str]:
    """``fail2ban-client status`` → the jail names (``[]`` when the server does not answer)."""
    for line in (text or "").splitlines():
        if "Jail list:" in line:
            names = line.split("Jail list:", 1)[1]
            return [n.strip() for n in names.split(",") if n.strip()]
    return []


def get_jails(grade: Grade0, machine: str, step: int = 1) -> List[str]:
    out, _ = grade.test(machine, "fail2ban-client status 2>/dev/null", step=step, allow_error=True)
    return parse_jails(out or "")


def parse_jail_status(text: str) -> Dict[str, object]:
    """``fail2ban-client status <jail>`` → ``{'exists', 'currently_failed', 'total_failed',
    'currently_banned', 'banned'}``."""
    status: Dict[str, object] = {'exists': False, 'currently_failed': None, 'total_failed': None,
                                 'currently_banned': None, 'banned': []}
    for line in (text or "").splitlines():
        if line.startswith("Status for the jail"):
            status['exists'] = True
        for key, label in (('currently_failed', 'Currently failed:'), ('total_failed', 'Total failed:'),
                           ('currently_banned', 'Currently banned:')):
            if label in line:
                try:
                    status[key] = int(line.split(label, 1)[1].strip())
                except ValueError:
                    pass
        if "Banned IP list:" in line:
            status['banned'] = line.split("Banned IP list:", 1)[1].split()
    return status


def get_jail_status(grade: Grade0, machine: str, jail: str, step: int = 1) -> Dict[str, object]:
    out, _ = grade.test(machine, f"fail2ban-client status {shlex.quote(jail)} 2>/dev/null", step=step,
                        allow_error=True)
    return parse_jail_status(out or "")


def get_jail_value(grade: Grade0, machine: str, jail: str, key: str, step: int = 1) -> Optional[str]:
    """``fail2ban-client get <jail> <key>`` (one line), ``None`` when the jail does not exist."""
    out, code = grade.test(machine, f"fail2ban-client get {shlex.quote(jail)} {shlex.quote(key)} 2>/dev/null",
                           step=step, allow_error=True)
    if code != 0:
        return None
    lines = [line.strip() for line in (out or "").splitlines() if line.strip()]
    return lines[0] if lines else None


def parse_seconds(value: Optional[str]) -> Optional[int]:
    """A ``bantime`` / ``findtime`` as printed by the client (seconds) → int."""
    try:
        return int(float((value or "").strip()))
    except ValueError:
        return None


def parse_ignoreip(text: str) -> List[str]:
    """``fail2ban-client get <jail> ignoreip`` → the ignored addresses and networks."""
    if "No IP address/network is ignored" in (text or ""):
        return []
    return _IPV4.findall(text or "")


def get_ignoreip(grade: Grade0, machine: str, jail: str, step: int = 1) -> List[str]:
    out, _ = grade.test(machine, f"fail2ban-client get {shlex.quote(jail)} ignoreip 2>/dev/null", step=step,
                        allow_error=True)
    return parse_ignoreip(out or "")


def ssh_failures_cmd(host, user: str, password: str, count: int, bind=None, timeout: int = 12) -> str:
    """*count* password logins with a wrong *password*, one after the other (``login_probe.py``)."""
    bind_opt = f"--bind {bind} " if bind else ""
    one = (f"python3 {LOGIN_PROBE_PATH} --timeout {timeout} {bind_opt}ssh {host} "
           f"{shlex.quote(user)} {shlex.quote(password)} >/dev/null 2>&1")
    return f"for i in $(seq {int(count)}); do {one}; done"


def http_logins_cmd(url: str, user: str, password: str, count: int, bind=None, timeout: int = 5) -> str:
    """*count* ``POST`` logins to *url*, one after the other; prints the HTTP codes on one line."""
    iface = f"--interface {bind} " if bind else ""
    one = (f"curl -s -m {int(timeout)} {iface}-o /dev/null -w '%{{http_code}} ' "
           f"--data-urlencode user={shlex.quote(user)} --data-urlencode password={shlex.quote(password)} {url}")
    return f"for i in $(seq {int(count)}); do {one}; done; echo"


def tcp_open_cmd(host, port: int, bind=None, timeout: int = 3, tag: str = "") -> str:
    """Prints ``OPEN<tag>`` or ``CLOSED<tag>``: can *bind* still open a connection to *host*:*port*?"""
    src = f"-s {bind} " if bind else ""
    return (f"if nc -z -w {int(timeout)} {src}{host} {int(port)} >/dev/null 2>&1; "
            f"then echo OPEN{tag}; else echo CLOSED{tag}; fi")


def parse_tcp_open(text: str, tag: str = "") -> Optional[bool]:
    """True / False from the output of :func:`tcp_open_cmd`, ``None`` when it has not run."""
    for line in (text or "").splitlines():
        line = line.strip()
        if line == f"OPEN{tag}":
            return True
        if line == f"CLOSED{tag}":
            return False
    return None


def unban_cmd(addresses: Iterable) -> str:
    """Unban *addresses* in every jail (nothing happens when fail2ban does not run)."""
    addrs = " ".join(str(a) for a in addresses)
    return f"fail2ban-client unban {addrs} >/dev/null 2>&1; true"


def render_jail(name: str, **options) -> str:
    """A ``jail.d`` section: ``[name]`` then ``key = value`` lines (``enabled = true`` first)."""
    lines = [f"[{name}]", "enabled = true"]
    for key, value in options.items():
        lines.append(f"{key} = {value}")
    return "\n".join(lines) + "\n"
