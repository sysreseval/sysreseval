"""MIT Kerberos helpers of the AAA lab (``lab/sre/_DRAFT_misc/aaa.py``): renderers of the
configuration files, one-line commands of the client tools and parsers of their output.

Formats of MIT krb5 1.20 (Debian 12, ``sysreseval/aaa``: krb5-kdc, krb5-admin-server, krb5-user,
libpam-krb5); fixtures in ``tests/mock_data/aaa/``.

**Renderers**: :func:`render_krb5_conf` (``[libdefaults]`` with ``rdns = false`` and
``dns_canonicalize_hostname = false``: the lab has no DNS, names come from ``/etc/hosts``),
:func:`render_kdc_conf`, :func:`render_kadm5_acl`; :func:`create_realm_cmds` (a realm from scratch on
a KDC: ``kdb5_util create -s``, the services restarted).

**Commands** (stderr merged, ``===RC`` marker): :func:`kinit_cmd` (the password piped to ``kinit``
— MIT kinit reads it from stdin when stdin is not a terminal — into a ccache of its own, then the
commands that use it: ``ssh`` with GSSAPI only, ``curl --negotiate``, ``kvno``),
:func:`kadmin_cmd` (remote, ``-w``), :func:`kadmin_local_cmd`.

**Parsers**: :func:`parse_kinit_error` (``revoked``, ``password``, ``unknown``, ``unreachable``…),
:func:`parse_klist` (``klist -e``: default principal, tickets with their enctypes),
:func:`parse_keytab` (``klist -k``), :func:`parse_getprinc`, :func:`parse_getpol`.
"""
import shlex
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0

RC_MARK = "===RC"
KDC_CONF = "/etc/krb5kdc/kdc.conf"
KADM5_ACL = "/etc/krb5kdc/kadm5.acl"
KRB5_CONF = "/etc/krb5.conf"
KDC_DB = "/var/lib/krb5kdc/principal"
STASH = "/etc/krb5kdc/stash"


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def render_krb5_conf(default_realm: str, realms: Dict[str, Tuple[str, Optional[str]]],
                     domain_realm: Sequence[Tuple[str, str]] = (), ticket_lifetime: Optional[str] = None) -> str:
    """``/etc/krb5.conf``: *realms* = ``{REALM: (kdc, admin_server or None)}``, *domain_realm* =
    ``[(".corp.lan", "CORP.LAN"), …]``."""
    lines = ["[libdefaults]", f"\tdefault_realm = {default_realm}", "\tdns_lookup_realm = false",
             "\tdns_lookup_kdc = false", "\trdns = false", "\tdns_canonicalize_hostname = false"]
    if ticket_lifetime:
        lines.append(f"\tticket_lifetime = {ticket_lifetime}")
    lines += ["", "[realms]"]
    for realm, (kdc, admin) in realms.items():
        lines.append(f"\t{realm} = {{")
        lines.append(f"\t\tkdc = {kdc}")
        if admin:
            lines.append(f"\t\tadmin_server = {admin}")
        lines.append("\t}")
    if domain_realm:
        lines += ["", "[domain_realm]"] + [f"\t{d} = {r}" for d, r in domain_realm]
    return "\n".join(lines) + "\n"


def render_kdc_conf(realm: str, max_life: str = "10h 0m 0s", max_renewable_life: str = "7d 0h 0m 0s") -> str:
    """``/etc/krb5kdc/kdc.conf`` of a KDC serving *realm* (the Debian layout)."""
    return f"""[kdcdefaults]
	kdc_ports = 750,88

[realms]
	{realm} = {{
		database_name = {KDC_DB}
		admin_keytab = FILE:/etc/krb5kdc/kadm5.keytab
		acl_file = {KADM5_ACL}
		key_stash_file = {STASH}
		kdc_ports = 750,88
		max_life = {max_life}
		max_renewable_life = {max_renewable_life}
		master_key_type = aes256-cts
		supported_enctypes = aes256-cts:normal aes128-cts:normal
		default_principal_flags = +preauth
	}}
"""


def render_kadm5_acl(entries: Sequence[Tuple[str, str, Optional[str]]]) -> str:
    """``kadm5.acl``: ``[(principal, permissions, target or None)]``."""
    return "".join(f"{p}\t{perms}" + (f"\t{t}" if t else "") + "\n" for p, perms, t in entries)


def create_realm_cmds(realm: str, master_password: str) -> List[str]:
    """A fresh realm database (the old one destroyed), then ``krb5kdc`` and ``kadmind`` restarted;
    the configuration files must be in place."""
    return [
        "systemctl stop krb5-admin-server krb5-kdc 2>/dev/null; true",
        f"kdb5_util destroy -f -r {realm} >/dev/null 2>&1; rm -f {KDC_DB}* {STASH}; true",
        f"kdb5_util create -s -r {realm} -P {shlex.quote(master_password)} 2>&1",
    ]


def start_kdc_cmd(admin_server: bool = True) -> str:
    services = "krb5-kdc krb5-admin-server" if admin_server else "krb5-kdc"
    return f"systemctl reset-failed {services} 2>/dev/null; systemctl restart {services}; sleep 1"


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def ccache_env(ccache: str) -> str:
    return f"KRB5CCNAME=FILE:{ccache}"


def kinit_cmd(principal: str, password: str, ccache: str, then: Sequence[str] = ()) -> str:
    """``kinit`` with the password on stdin into *ccache* (removed first), then each command of
    *then* run with that ccache (``KRB5CCNAME``) only if kinit succeeded; one ``===RC`` marker per
    command, the kinit output first."""
    env = ccache_env(ccache)
    cmd = (f"rm -f {ccache}; printf '%s\\n' {shlex.quote(password)} | {env} kinit {shlex.quote(principal)} 2>&1; "
           f"rc=$?; echo \"{RC_MARK} $rc\"")
    for c in then:
        cmd += f"; if [ $rc -eq 0 ]; then {env} {c} 2>&1; echo \"{RC_MARK} $?\"; else echo \"{RC_MARK} none\"; fi"
    return cmd + f"; rm -f {ccache}"


def gssapi_ssh(user_host: str, command: str = "id -un") -> str:
    """``ssh`` allowed to use GSSAPI only (no password, no key): what kinit's ticket opens."""
    return (f"ssh -o BatchMode=yes -o GSSAPIAuthentication=yes -o PreferredAuthentications=gssapi-with-mic "
            f"-o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o LogLevel=ERROR -o ConnectTimeout=5 {shlex.quote(user_host)} {shlex.quote(command)}")


def negotiate_curl(url: str) -> str:
    """``curl --negotiate`` printing the body then ``===HTTP <code>``."""
    return f"curl -s -m 5 --negotiate -u : -w '\\n===HTTP %{{http_code}}\\n' {shlex.quote(url)}"


def plain_curl(url: str) -> str:
    """``curl`` without credentials, the response headers included, then ``===HTTP <code>``."""
    return f"curl -s -m 5 -i -w '\\n===HTTP %{{http_code}}\\n' {shlex.quote(url)} 2>&1; echo \"{RC_MARK} $?\""


def kadmin_cmd(principal: str, password: str, query: str) -> str:
    """Remote ``kadmin -p PRINCIPAL -w PASSWORD -q QUERY``."""
    return (f"kadmin -p {shlex.quote(principal)} -w {shlex.quote(password)} -q {shlex.quote(query)} 2>&1; "
            f"echo \"{RC_MARK} $?\"")


def kadmin_local_cmd(query: str) -> str:
    return f"kadmin.local -q {shlex.quote(query)} 2>&1; echo \"{RC_MARK} $?\""


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


def split_markers(text: str) -> List[Tuple[str, Optional[str]]]:
    """``[(output, status)]`` of the commands of a line ending each with an ``===RC`` marker
    (status ``None`` for a marker ``none``: the command was skipped)."""
    parts: List[Tuple[str, Optional[str]]] = []
    buf: List[str] = []
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith(RC_MARK):
            status = s[len(RC_MARK):].strip()
            parts.append(("\n".join(buf), None if status == "none" else status))
            buf = []
        else:
            buf.append(line)
    return parts


def parse_kinit_error(text: str) -> str:
    """``ok`` (no message), ``revoked`` (disabled principal), ``password`` (wrong password),
    ``unknown`` (no such principal), ``expired``, ``unreachable`` (no KDC), ``policy`` or ``other``."""
    t = (text or "").lower()
    if not t.strip():
        return "ok"
    if "revoked" in t:
        return "revoked"
    if "password incorrect" in t or "preauthentication failed" in t:
        return "password"
    if "not found in kerberos database" in t:
        return "unknown"
    if "expired" in t:
        return "expired"
    if "cannot contact any kdc" in t or "cannot find kdc" in t or "connection refused" in t:
        return "unreachable"
    if "policy" in t:
        return "policy"
    return "other"


def kinit_result(text: str) -> Dict[str, Any]:
    """The parts of :func:`kinit_cmd`: ``{'ran', 'ok', 'error', 'then': [(output, status)]}``."""
    parts = split_markers(text)
    if not parts:
        return {"ran": False, "ok": False, "error": "", "then": []}
    out, status = parts[0]
    ok = status == "0"
    return {"ran": True, "ok": ok, "error": "ok" if ok else parse_kinit_error(out), "output": out,
            "then": parts[1:]}


def parse_http(text: str) -> Tuple[str, Optional[int]]:
    """``(body, status code)`` of :func:`negotiate_curl` / :func:`plain_curl`."""
    body, code = [], None
    for line in (text or "").splitlines():
        m = re.match(r"^===HTTP (\d{3})", line.strip())
        if m:
            code = int(m.group(1))
        else:
            body.append(line)
    return "\n".join(body), (code if code else None)


_TICKET = re.compile(r"^(\S+ \S+)\s+(\S+ \S+)\s+(\S+@\S+)\s*$")


def parse_klist(text: str) -> Dict[str, Any]:
    """``klist -e``: ``{'cache', 'principal', 'tickets': [{'start', 'expires', 'service', 'enctypes'}]}``."""
    result: Dict[str, Any] = {"cache": "", "principal": "", "tickets": []}
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("Ticket cache:"):
            result["cache"] = s.split(":", 1)[1].strip()
        elif s.startswith("Default principal:"):
            result["principal"] = s.split(":", 1)[1].strip()
        else:
            m = _TICKET.match(s)
            if m:
                result["tickets"].append({"start": m.group(1), "expires": m.group(2), "service": m.group(3),
                                          "enctypes": []})
            elif "Etype (skey, tkt):" in s and result["tickets"]:
                # "renew until 11/19/26 12:40:21, Etype (skey, tkt): aes256-…, aes256-…"
                etypes = s.split("Etype (skey, tkt):", 1)[1]
                result["tickets"][-1]["enctypes"] = [e.strip() for e in etypes.split(",") if e.strip()]
    return result


def parse_keytab(text: str) -> List[Tuple[int, str]]:
    """``klist -k``: ``[(kvno, principal)]`` (one line per key)."""
    entries = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d+)\s+(\S+@\S+)", line)
        if m:
            entries.append((int(m.group(1)), m.group(2)))
    return entries


def parse_getprinc(text: str) -> Optional[Dict[str, Any]]:
    """``getprinc``: ``{'principal', 'attributes': [...], 'policy', 'max_life', 'keys': [enctypes], …}``,
    ``None`` when the principal does not exist."""
    if "Principal does not exist" in (text or ""):
        return None
    info: Dict[str, Any] = {"attributes": [], "keys": [], "policy": None}
    found = False
    for line in (text or "").splitlines():
        s = line.strip()
        if ":" not in s:
            continue
        key, value = (x.strip() for x in s.split(":", 1))
        if key == "Principal":
            info["principal"] = value
            found = True
        elif key == "Attributes":
            info["attributes"] = value.split()
        elif key == "Policy":
            info["policy"] = None if value in ("[none]", "") else value
        elif key == "Maximum ticket life":
            info["max_life"] = value
        elif key == "Key":
            info["keys"].append(value.split(",")[-1].strip())
        elif key == "Expiration date":
            info["expiration"] = value
    return info if found else None


def parse_getpol(text: str) -> Optional[Dict[str, Any]]:
    """``getpol``: ``{'policy', 'min_length', 'min_classes', 'history'}``; ``None`` when absent."""
    if "Policy does not exist" in (text or ""):
        return None
    info: Dict[str, Any] = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if ":" not in s:
            continue
        key, value = (x.strip() for x in s.split(":", 1))
        if key == "Policy":
            info["policy"] = value
        elif key == "Minimum password length":
            info["min_length"] = _int(value)
        elif key == "Minimum number of password character classes":
            info["min_classes"] = _int(value)
        elif key == "Number of old keys kept":
            info["history"] = _int(value)
    return info if "policy" in info else None


def _int(value: str) -> Optional[int]:
    try:
        return int(value.split()[0])
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# grade-side wrappers
# ---------------------------------------------------------------------------


def kinit_test(grade: Grade0, machine: str, principal: str, password: str, ccache: str,
               then: Sequence[str] = (), step: int = 1, timeout: int = 30) -> Dict[str, Any]:
    out, _ = grade.test(machine, kinit_cmd(principal, password, ccache, then), step=step, timeout=timeout,
                        allow_error=True)
    return kinit_result(out)


def get_principal(grade: Grade0, machine: str, principal: str, step: int = 1) -> Optional[Dict[str, Any]]:
    out, _ = grade.test(machine, kadmin_local_cmd(f"getprinc {principal}"), step=step, allow_error=True)
    return parse_getprinc(out)


def get_policy(grade: Grade0, machine: str, policy: str, step: int = 1) -> Optional[Dict[str, Any]]:
    out, _ = grade.test(machine, kadmin_local_cmd(f"getpol {policy}"), step=step, allow_error=True)
    return parse_getpol(out)


def get_keytab(grade: Grade0, machine: str, keytab: str, step: int = 1) -> List[Tuple[int, str]]:
    out, _ = grade.test(machine, f"klist -k {shlex.quote(keytab)} 2>&1", step=step, allow_error=True)
    return parse_keytab(out)
