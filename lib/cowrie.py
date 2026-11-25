"""Cowrie helpers for the labs (the image ``nsm13``: Cowrie 3.1.8 in ``/opt/cowrie``, run by the user
``cowrie``; the lab ``lab/sre/_DRAFT_misc/nsm-forensics.py``).

State side:

- :func:`render_cowrie_cfg` writes an overlay of ``etc/cowrie.cfg`` (Cowrie reads its bundled
  defaults first, then ``/etc/cowrie/cowrie.cfg``, ``etc/cowrie.cfg`` and ``cowrie.cfg`` of its
  working directory: a file naming only the keys it changes is enough);
- :func:`render_userdb` writes ``etc/userdb.txt`` (``user:x:password`` lines, the first match wins,
  ``*`` = anything, a password starting with ``!`` refuses, ``/regex/`` or ``/regex/i``);
- :func:`cowrie_event` builds one event as Cowrie writes it to ``cowrie.json`` (for a generated
  history: the evidence of an investigation).

Grade side:

- :func:`get_events` reads the ``cowrie.json`` events that name an address (``src_ip``), parsed by
  :func:`parse_events`; :func:`events_since` keeps those of the current evaluation (``timestamp``
  after the ``t0`` read at step 1 with ``suricata.get_epoch``);
- :func:`banner_cmd` / :func:`parse_banner` read the identification line an SSH server sends first
  (``nc`` from a chosen source address);
- :func:`get_owner` gives the user running Cowrie's ``twistd``.

Facts verified in the nsm13 image (2026-11-25): an OpenSSH 10.0 client logs in (password, exec
commands: ``cowrie.command.input`` holds the whole command line); without ``etc/userdb.txt`` Cowrie
uses its bundled ``userdb.example`` (``root`` with anything but ``root`` / ``123456`` / a password
holding "honeypot", then ``*:x:*``: every other account with any password); ``root:x:!*`` after the
accepted passwords refuses every other one; ``hostname``, ``uname -r`` print ``[honeypot] hostname``
and ``[shell] kernel_version``; every event carries ``sensor`` = ``[honeypot] sensor_name`` (the
machine's host name by default); the banner is ``[ssh] version``, sent at once, but lost when the client
half-closes before reading it (``nc -N``); ``cowrie start -n`` is refused
(``cowrie start -- -n`` passes ``-n`` to twistd) and ``cowrie start`` runs ``twistd`` from the PATH;
Cowrie's ``wget`` / ``curl`` refuse every non-global address (private networks, 198.18.0.0/15...):
no download from a lab server can be seen; a twistd of Cowrie holds about 90 MB.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from SRE.lib_sre import Grade0

COWRIE_HOME = "/opt/cowrie"
COWRIE_CFG = f"{COWRIE_HOME}/etc/cowrie.cfg"
COWRIE_CFG_DIST = f"{COWRIE_HOME}/etc/cowrie.cfg.dist"
USERDB = f"{COWRIE_HOME}/etc/userdb.txt"
COWRIE_JSON = f"{COWRIE_HOME}/var/log/cowrie/cowrie.json"
COWRIE_LOG = f"{COWRIE_HOME}/var/log/cowrie/cowrie.log"
COWRIE_UNIT = "cowrie"
COWRIE_PORT = 2222
BANNER_MARK = "SRE-BANNER-"


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------

def render_cowrie_cfg(sections: Dict[str, Dict[str, Any]]) -> str:
    """An INI overlay: ``{section: {key: value}}`` in the given order."""
    out = []
    for section, keys in sections.items():
        out.append(f"[{section}]")
        out += [f"{k} = {v}" for k, v in keys.items()]
        out.append("")
    return "\n".join(out)


def render_userdb(rules: Iterable[Tuple[str, str]]) -> str:
    """``etc/userdb.txt`` from ``(user, password)`` rules, in order (``!`` refuses, ``*`` = any)."""
    return "".join(f"{user}:x:{password}\n" for user, password in rules)


def cowrie_timestamp(epoch: float) -> str:
    """Cowrie's ISO 8601 UTC timestamp (``2026-11-24T08:15:02.123456Z``)."""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cowrie_event(eventid: str, epoch: float, session: str, src_ip: str, sensor: str,
                 message: str = "", **fields: Any) -> Dict[str, Any]:
    """One event of ``cowrie.json`` (the common fields, then *fields*)."""
    event: Dict[str, Any] = {"eventid": eventid}
    event.update(fields)
    event.update({"message": message, "sensor": sensor, "timestamp": cowrie_timestamp(epoch),
                  "src_ip": src_ip, "session": session})
    return event


def render_events(events: Iterable[Dict[str, Any]]) -> str:
    """The JSON lines of a ``cowrie.json``."""
    return "".join(json.dumps(e) + "\n" for e in events)


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------

def events_cmd(addresses: Iterable[str], path: str = COWRIE_JSON, lines: int = 300) -> str:
    """The shell command printing the last *lines* events of *path* that name one of *addresses*."""
    needles = " ".join(f"-e '\"{a}\"'" for a in addresses)
    return f"grep -F {needles} {path} 2>/dev/null | tail -n {int(lines)}"


def parse_events(text: str) -> List[Dict[str, Any]]:
    """The JSON events of a ``cowrie.json`` extract (bad lines skipped)."""
    events = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def event_epoch(event: Dict[str, Any]) -> Optional[float]:
    """The ``timestamp`` of an event in epoch seconds (ISO form, or a number with
    ``epoch_timestamp = true``); None when unreadable."""
    value = event.get("timestamp")
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def events_since(events: List[Dict[str, Any]], t0: Optional[float], src: Optional[str] = None,
                 margin: float = 1.0) -> List[Dict[str, Any]]:
    """The events written after *t0* (minus *margin* seconds), from *src* when given."""
    if t0 is None:
        return []
    kept = []
    for event in events:
        ts = event_epoch(event)
        if ts is None or ts < t0 - margin:
            continue
        if src is not None and event.get("src_ip") != str(src):
            continue
        kept.append(event)
    return kept


def get_events(grade: Grade0, machine: str, addresses: Iterable[str], path: str = COWRIE_JSON,
               step: int = 1) -> List[Dict[str, Any]]:
    out, _ = grade.test(machine, events_cmd(addresses, path), step=step, allow_error=True)
    return parse_events(out or "")


def login_results(events: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    """``{(username, password): 'success' | 'failed'}`` of the login events (the last one wins)."""
    results = {}
    for e in events:
        eventid = e.get("eventid", "")
        if eventid in ("cowrie.login.success", "cowrie.login.failed"):
            results[(str(e.get("username")), str(e.get("password")))] = eventid.rsplit(".", 1)[1]
    return results


def banner_cmd(host: str, port: int, tag: str, src: Optional[str] = None, timeout: int = 4) -> str:
    """Print ``SRE-BANNER-<tag>=<first line the server sends>`` (empty when nothing answers). No
    ``nc -N``: Cowrie (Twisted) drops the banner it has queued when the client half-closes at once; nc
    leaves after *timeout* seconds of silence."""
    bind = f"-s {src} " if src else ""
    return (f"echo \"{BANNER_MARK}{tag}=$(timeout {timeout + 2} nc -w {timeout} {bind}{host} {int(port)} "
            f"</dev/null 2>/dev/null | head -c 255 | head -n 1 | tr -d '\\r')\"")


def parse_banner(text: str, tag: str) -> str:
    """The banner printed by :func:`banner_cmd` for *tag* (``''`` when absent)."""
    prefix = f"{BANNER_MARK}{tag}="
    for line in (text or "").splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return ""


def owner_cmd() -> str:
    return "ps -eo user=,args= | grep '[t]wistd' | grep cowrie"


def parse_owners(text: str) -> List[str]:
    """The users of the Cowrie twistd processes listed by :func:`owner_cmd`."""
    return [line.split(None, 1)[0] for line in (text or "").splitlines() if line.strip()]


def get_owners(grade: Grade0, machine: str, step: int = 1) -> List[str]:
    out, _ = grade.test(machine, owner_cmd(), step=step, allow_error=True)
    return parse_owners(out or "")


def unit_enabled(grade: Grade0, machine: str, unit: str = COWRIE_UNIT, step: int = 1) -> bool:
    out, _ = grade.test(machine, f"systemctl is-enabled {unit} 2>/dev/null", step=step, allow_error=True)
    return (out or "").strip() in ("enabled", "enabled-runtime", "alias")


def session_output(probe_json: str) -> Tuple[bool, str]:
    """``(ok, output)`` of one ``login_probe.py --command`` JSON result."""
    for line in (probe_json or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                result = json.loads(line)
            except ValueError:
                continue
            if isinstance(result, dict):
                return bool(result.get("ok")), str(result.get("output") or "")
    return False, ""


def output_lines_after_mark(output: str, mark: str = "SRE_LOGIN_OK") -> List[str]:
    """The lines a session printed after the login marker (``\\r`` removed)."""
    lines = output.replace("\r", "").splitlines()
    for i, line in enumerate(lines):
        if line.strip() == mark:
            return [l.strip() for l in lines[i + 1:] if l.strip()]
    return []

