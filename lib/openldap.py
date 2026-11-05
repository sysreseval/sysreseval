"""OpenLDAP grading and state helpers of the LDAP lab (``lab/em/_DRAFT_/ldap.py``).

Facts and formats are those of slapd 2.5.13, ldap-utils 2.5.13 and nss-pam-ldapd 0.9.12 (Debian
12: ``slapd`` and ``ldap-utils`` in ``sysreseval/base``, ``nslcd``, ``libnss-ldapd`` and
``libpam-ldapd`` in the ``sysreseval/ldap-mail`` image built on ``init``); the fixtures of
``tests/mock_data/ldap/`` were captured in those containers.

**LDIF**: :func:`parse_ldif` reads what ``ldapsearch`` / ``slapcat`` print (continuation lines,
``::`` base64 values, the ``# …`` / ``search:`` / ``result:`` trailer), :func:`parse_ldap_error`
the ``ldap_bind: Invalid credentials (49)`` lines (the commands built here end with ``2>&1``: the
exetests of a machine capture stdout only).  :func:`ldap_result` combines both into a
:class:`LdapResult`.  Entry helpers: :func:`find_entry`, :func:`entry_values`, :func:`entry_value`,
:func:`has_object_class`, :func:`dn_equal`, :func:`normalize_dn`.

**cn=config**: :func:`config_search_cmd` dumps the global entry, the module lists, the databases
and the overlays through ``ldapi:///`` as root; :func:`parse_slapd_config` turns the entries into
a :class:`SlapdConfig` (``databases`` by suffix: ``rootdn``, ``rootpw_hashed``, ``directory``,
``access`` parsed by :func:`parse_olc_access`, ``security`` by :func:`parse_olc_security`,
``syncrepl`` by :func:`parse_syncrepl`, ``overlays``; ``modules``; ``tls`` = the
``olcTLS*`` values; ``loglevel``).

**Commands** (one shell line each, ``2>&1`` appended): :func:`ldapsearch_cmd`,
:func:`ldapwhoami_cmd`, :func:`ldapmodify_cmd` (the LDIF piped with ``printf``),
:func:`ldappasswd_cmd`, :func:`ldapdelete_cmd`, :func:`s_client_cmd` (``openssl s_client`` with
``-verify_hostname`` and ``-starttls ldap`` for STARTTLS: :func:`parse_s_client`).  Every command
takes an ``uri`` (``ldap://host``, ``ldaps://host``, ``ldapi:///``) and ``starttls=True`` for
``-ZZ``.

**Client side**: :func:`parse_nsswitch` / :func:`nsswitch_has`, :func:`parse_nslcd_conf` /
:func:`nslcd_tls`, :func:`parse_pam_file` / :func:`pam_modules`, :func:`parse_getent_passwd`,
:func:`parse_getent_group`, :func:`parse_id`, :func:`parse_listen_ports` (``ss -tlnp``) and the
interactive login probe ``lib/login_probe.py`` (:func:`install_login_probe`, :func:`login_probe_cmd`,
:func:`parse_login_probe`: a pseudo-terminal ``su`` run as the unprivileged ``student`` user, or
an ``ssh`` password login, answering the prompt and reporting the login name, the home directory
and whether it exists).

**Passwords**: :func:`ssha_hash` (``{SSHA}``, what ``slappasswd`` prints), :func:`password_hashed`,
:func:`check_password` (``{SSHA}`` / ``{SHA}`` / clear text).

**Renderers** for the states: :func:`render_slapd_config_ldif` (the whole ``cn=config`` tree of a
fresh server, what ``slapadd -n 0`` loads: the schemas of ``/etc/ldap/schema``, the frontend and
config databases with the Debian ``peercred`` rule, one ``mdb`` database with the Debian default
ACLs), :func:`render_person_ldif`, :func:`render_posix_group_ldif`, :func:`render_ou_ldif`,
:func:`render_base_ldif`, :func:`render_modify_ldif`, :func:`render_nslcd_conf`,
:func:`render_syncrepl`, :data:`PAM_MKHOMEDIR_PROFILE`.

Facts (verified 2026-11-05 in the containers): ``systemctl start slapd`` / ``nslcd`` / ``ssh``
work through the systemctl replacement of the base image (init.d scripts; ``SLAPD_SERVICES`` of
``/etc/default/slapd`` gives the listeners) but its ``stop`` leaves an init.d-started slapd
running (``pkill -x slapd``, or a real-systemd ``init`` machine where ``systemctl restart slapd``
behaves: what the lab uses for the servers and the client); root through ``ldapi:///`` has
``manage`` on ``cn=config`` but only what the database's own ``to *`` rule gives on the data
(the frontend's ``manage … by * break`` is overridden by the first matching clause of the
database: ``read`` with the Debian defaults, ``none`` for ``userPassword`` once the ACLs are
tightened), so the data operations of the states and of the grader bind as the rootdn
(``-x -D cn=admin,… -w … -H ldapi:///``, allowed under ``simple_bind=128`` by ``olcLocalSSF``);
``pam-auth-update --enable ldap`` and ``--enable mkhomedir`` (a profile written in
``/usr/share/pam-configs/``) edit the ``common-*`` files non-interactively; ``su`` run by root
asks no password (``pam_rootok``), so the login probe runs it as ``student``; ``ldapsearch``
prints ``No such object (32)`` alone (no ``ldap_search:`` prefix) with ``-LLL``; ``ldapdelete``
of a missing entry adds a ``matched DN:`` line; the ``olcTLSCertificateFile`` /
``olcTLSCertificateKeyFile`` pair must be set in one ``ldapmodify``; the commands of an exetests
batch are one line each (the LDIF of :func:`ldapmodify_cmd` travels base64-encoded).
"""
import base64
import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0, NetScheme0

LOGIN_PROBE_PATH = "/usr/local/sbin/sre_login_probe.py"
LDAPI_URI = "ldapi:///"
#: the entries of cn=config the grader reads (schemas left out: hundreds of lines)
CONFIG_FILTER = ("(|(objectClass=olcGlobal)(objectClass=olcModuleList)(objectClass=olcDatabaseConfig)"
                 "(objectClass=olcOverlayConfig))")
ACCESS_LEVELS = ("none", "disclose", "auth", "compare", "search", "read", "write", "manage")
ACCESS_CONTROLS = ("stop", "continue", "break")
HASH_SCHEMES = ("{SSHA}", "{SHA}", "{SSHA256}", "{SHA256}", "{SSHA384}", "{SSHA512}", "{SHA512}", "{CRYPT}",
                "{MD5}", "{SMD5}", "{ARGON2}", "{PBKDF2}", "{PBKDF2-SHA1}", "{PBKDF2-SHA256}", "{PBKDF2-SHA512}")
DEFAULT_SCHEMAS = ("core", "cosine", "nis", "inetorgperson")
#: the Debian default ACLs of a fresh database (slapd.init.ldif)
DEFAULT_ACCESS = ("to attrs=userPassword by self write by anonymous auth by * none",
                  "to attrs=shadowLastChange by self write by * read",
                  "to * by * read")
PEERCRED_ROOT = "dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
#: a pam-auth-update profile creating the home directory at the first login
PAM_MKHOMEDIR_PROFILE = """Name: Create home directory on login
Default: yes
Priority: 900
Session-Type: Additional
Session:
\trequired\tpam_mkhomedir.so umask=0077 skel=/etc/skel
"""

_ERROR_RE = re.compile(r"^(?:(?P<op>ldap_\w+(?:\([^)]*\))?): )?(?P<msg>[^\n]*?) \((?P<code>-?\d+)\)\s*$", re.M)
RC_MARK = "===RC"
_RC_RE = re.compile(r"^===RC (\d+)\s*$", re.M)
RC_SUFFIX = f' 2>&1; echo "{RC_MARK} $?"'   #: appended to every ldap-utils command: stderr merged, exit status kept
_CSN_RE = re.compile(r"^(\d{14})\.(\d{6})Z#([0-9a-f]{6})#([0-9a-f]{3})#([0-9a-f]{6})$")


# ---------------------------------------------------------------------------
# LDIF
# ---------------------------------------------------------------------------


def _unfold(text: str) -> List[str]:
    """The logical lines of an LDIF text (continuation lines joined, comments dropped)."""
    lines: List[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        elif raw.startswith("#"):
            continue
        else:
            lines.append(raw.rstrip("\r"))
    return lines


def parse_ldif(text: str) -> List[Dict[str, Any]]:
    """The entries of an LDIF text (``ldapsearch``, ``slapcat``, a file) as
    ``[{'dn': str, 'attrs': {name: [values]}}]``: continuation lines unfolded, ``name:: b64``
    values decoded (UTF-8, replacement characters), ``name:< url`` kept as ``'<url'``, comments,
    ``version:`` and the ``search:`` / ``result:`` trailer of ``ldapsearch`` ignored (a block
    without ``dn:`` is not an entry).  Attribute names keep their case (see :func:`entry_values`
    for a case-insensitive lookup)."""
    entries: List[Dict[str, Any]] = []
    block: List[str] = []

    def flush():
        if not block:
            return
        dn = None
        attrs: Dict[str, List[str]] = {}
        for line in block:
            if ":" not in line:
                continue
            name, _, rest = line.partition(":")
            name = name.strip()
            if rest.startswith(":"):
                raw = rest[1:].strip()
                try:
                    value = base64.b64decode(raw).decode("utf-8", errors="replace")
                except (ValueError, UnicodeDecodeError):
                    value = raw
            elif rest.startswith("<"):
                value = rest.strip()
            else:
                value = rest.strip()
            if name.lower() == "dn" and dn is None:
                dn = value
            elif name.lower() in ("version",):
                continue
            else:
                attrs.setdefault(name, []).append(value)
        if dn is not None:
            entries.append({"dn": dn, "attrs": attrs})

    for line in _unfold(text):
        if line.strip() == "":
            flush()
            block = []
        else:
            block.append(line)
    flush()
    return entries


def normalize_dn(dn: str) -> str:
    """A DN comparable with another: lower case, no space around the commas and the ``=``."""
    parts = [p.strip() for p in re.split(r"(?<!\\),", dn.strip())]
    norm = []
    for part in parts:
        attr, _, value = part.partition("=")
        norm.append(f"{attr.strip().lower()}={value.strip().lower()}")
    return ",".join(norm)


def dn_equal(a: str, b: str) -> bool:
    return normalize_dn(a) == normalize_dn(b)


def rdn_value(dn: str) -> str:
    """The value of the first RDN (``uid=alice,ou=people,…`` → ``alice``)."""
    first = re.split(r"(?<!\\),", dn.strip(), maxsplit=1)[0]
    return first.partition("=")[2].strip()


def parent_dn(dn: str) -> str:
    parts = re.split(r"(?<!\\),", dn.strip(), maxsplit=1)
    return parts[1].strip() if len(parts) == 2 else ""


def find_entry(entries: Sequence[Dict[str, Any]], dn: str) -> Optional[Dict[str, Any]]:
    """The entry of *dn* (case- and space-insensitive), ``None`` when absent."""
    wanted = normalize_dn(dn)
    for entry in entries:
        if normalize_dn(entry["dn"]) == wanted:
            return entry
    return None


def entry_values(entry: Optional[Dict[str, Any]], attr: str) -> List[str]:
    """The values of *attr* in *entry* (attribute names are case-insensitive), ``[]`` when absent."""
    if not entry:
        return []
    wanted = attr.lower()
    for name, values in entry["attrs"].items():
        if name.lower() == wanted:
            return list(values)
    return []


def entry_value(entry: Optional[Dict[str, Any]], attr: str, default: str = "") -> str:
    values = entry_values(entry, attr)
    return values[0] if values else default


def has_object_class(entry: Optional[Dict[str, Any]], object_class: str) -> bool:
    return object_class.lower() in {v.lower() for v in entry_values(entry, "objectClass")}


def entries_under(entries: Sequence[Dict[str, Any]], base: str) -> List[Dict[str, Any]]:
    """The entries whose parent is *base*."""
    wanted = normalize_dn(base)
    return [e for e in entries if normalize_dn(parent_dn(e["dn"])) == wanted]


# ---------------------------------------------------------------------------
# results of the ldap-utils commands
# ---------------------------------------------------------------------------


@dataclass
class LdapResult:
    """What a ldap-utils command gave: the entries printed, the LDAP error (code and message of the
    first ``… (N)`` line, ``None`` when none) and the exit status."""
    entries: List[Dict[str, Any]] = field(default_factory=list)
    error_code: Optional[int] = None
    error: str = ""
    exit_code: int = 0
    output: str = ""
    ran: bool = False      #: the command ran (its ``===RC`` marker is in the output): False for a placeholder

    @property
    def ok(self) -> bool:
        return self.ran and self.exit_code == 0 and self.error_code is None


def parse_ldap_error(text: str) -> Tuple[Optional[int], str]:
    """``(code, message)`` of the first LDAP error line of a ldap-utils output
    (``ldap_bind: Invalid credentials (49)``, ``No such object (32)``,
    ``ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)``), ``(None, '')`` when none."""
    for m in _ERROR_RE.finditer(text or ""):
        msg = m.group("msg").strip()
        if msg.lower().startswith(("result:", "# ")):
            continue
        return int(m.group("code")), msg
    return None, ""


def ldap_result(output: str, exit_code: int = 0) -> LdapResult:
    """The :class:`LdapResult` of a command built here: the ``===RC N`` line gives the exit status
    of the ldap-utils command (``exit_code`` is the one of the shell otherwise) and proves the
    command ran."""
    text = output or ""
    code, msg = parse_ldap_error(text)
    m = _RC_RE.search(text)
    if m:
        exit_code = int(m.group(1))
    return LdapResult(entries=parse_ldif(_RC_RE.sub("", text)), error_code=code, error=msg, exit_code=exit_code,
                      output=text, ran=m is not None)


# ---------------------------------------------------------------------------
# command lines
# ---------------------------------------------------------------------------


def _auth_options(binddn: Optional[str], password: Optional[str], external: bool = False) -> str:
    if external:
        return " -Y EXTERNAL -Q"
    opts = " -x"
    if binddn:
        opts += f" -D {shlex.quote(binddn)}"
        if password is not None:
            opts += f" -w {shlex.quote(password)}"
    return opts


def _common(uri: str, binddn: Optional[str], password: Optional[str], starttls: bool, external: bool) -> str:
    return f"{_auth_options(binddn, password, external)}{' -ZZ' if starttls else ''} -H {shlex.quote(uri)}"


def ldapsearch_cmd(uri: str, base: str, filter: str = "(objectClass=*)", attrs: Sequence[str] = (),
                   binddn: Optional[str] = None, password: Optional[str] = None, scope: Optional[str] = None,
                   starttls: bool = False, external: bool = False) -> str:
    """``ldapsearch -LLL`` of *filter* under *base* (anonymous, simple bind, or ``-Y EXTERNAL``
    for ``ldapi:///`` as root), stderr merged."""
    cmd = f"ldapsearch -LLL{_common(uri, binddn, password, starttls, external)} -b {shlex.quote(base)}"
    if scope:
        cmd += f" -s {scope}"
    cmd += f" {shlex.quote(filter)}"
    for a in attrs:
        cmd += f" {shlex.quote(a)}"
    return cmd + RC_SUFFIX


def ldapwhoami_cmd(uri: str, binddn: Optional[str] = None, password: Optional[str] = None,
                   starttls: bool = False, external: bool = False) -> str:
    return f"ldapwhoami{_common(uri, binddn, password, starttls, external)}{RC_SUFFIX}"


def ldapmodify_cmd(uri: str, ldif: str, binddn: Optional[str] = None, password: Optional[str] = None,
                   starttls: bool = False, external: bool = False, add: bool = False, cont: bool = False) -> str:
    """``ldapmodify`` (``-a``: ``ldapadd``) of *ldif*, piped base64-decoded (one shell line);
    ``cont``: ``-c``."""
    tool = "ldapmodify -a" if add else "ldapmodify"
    if cont:
        tool += " -c"
    # one line: the exetests batch of a machine carries one command per line
    b64 = base64.b64encode(ldif.encode()).decode()
    return f"echo {b64} | base64 -d | {tool}{_common(uri, binddn, password, starttls, external)}{RC_SUFFIX}"


def ldappasswd_cmd(uri: str, binddn: str, password: str, new_password: str, target_dn: Optional[str] = None,
                   starttls: bool = False) -> str:
    """``ldappasswd -s NEW [target]``: the own password without *target_dn*."""
    cmd = f"ldappasswd{_common(uri, binddn, password, starttls, False)} -s {shlex.quote(new_password)}"
    if target_dn:
        cmd += f" {shlex.quote(target_dn)}"
    return cmd + RC_SUFFIX


def ldapdelete_cmd(uri: str, dn: str, binddn: Optional[str] = None, password: Optional[str] = None,
                   starttls: bool = False, external: bool = False) -> str:
    return f"ldapdelete{_common(uri, binddn, password, starttls, external)} {shlex.quote(dn)}{RC_SUFFIX}"


def config_search_cmd(filter: str = CONFIG_FILTER, attrs: Sequence[str] = ()) -> str:
    """The cn=config entries of the local slapd, read as root through ``ldapi:///``."""
    return ldapsearch_cmd(LDAPI_URI, "cn=config", filter, attrs, external=True)


def s_client_cmd(host: str, port: int, cafile: Optional[str] = None, hostname: Optional[str] = None,
                 starttls: Optional[str] = None) -> str:
    """``openssl s_client`` to *host*:*port* (``-starttls ldap`` for STARTTLS on 389), the chain
    verified against *cafile* and the name against *hostname*; only the lines
    :func:`parse_s_client` reads are kept."""
    cmd = f"openssl s_client -connect {shlex.quote(f'{host}:{int(port)}')}"
    if cafile:
        cmd += f" -CAfile {shlex.quote(cafile)}"
    if hostname:
        cmd += f" -verify_hostname {shlex.quote(hostname)} -servername {shlex.quote(hostname)}"
    if starttls:
        cmd += f" -starttls {shlex.quote(starttls)}"
    return (cmd + " </dev/null 2>&1 | grep -E '^(CONNECTED|subject=|issuer=|Verify return code|verify error|"
                  "verify return|[0-9A-F]+:error|.*(onnect|refused|Connection))' | head -n 20; echo ===END")


def login_probe_cmd(mode: str, user: str, password: str, host: Optional[str] = None, timeout: int = 20,
                    as_user: str = "student") -> str:
    """``su`` (run as *as_user* on the machine itself) or ``ssh`` (to *host*) password login of
    *user* through :data:`LOGIN_PROBE_PATH`."""
    if mode == "ssh":
        if not host:
            raise ValueError("ssh mode needs a host")
        args = f"ssh {shlex.quote(host)} {shlex.quote(user)} {shlex.quote(password)}"
    elif mode == "su":
        args = f"--as {shlex.quote(as_user)} su {shlex.quote(user)} {shlex.quote(password)}"
    else:
        raise ValueError(f"unknown login probe mode {mode!r}")
    return f"python3 {LOGIN_PROBE_PATH} --timeout {int(timeout)} {args} 2>&1"


# ---------------------------------------------------------------------------
# cn=config
# ---------------------------------------------------------------------------


def strip_index(value: str) -> str:
    """``{0}back_mdb`` → ``back_mdb``."""
    return re.sub(r"^\{-?\d+\}", "", value.strip())


def parse_olc_access(value: str) -> Dict[str, Any]:
    """One ``olcAccess`` value → ``{'what', 'what_attrs', 'what_dn', 'what_dn_style', 'by': [{'who',
    'access', 'control'}]}``; the ``{n}`` index is dropped, quotes removed, an omitted access level
    is ``none`` (slapd.access(5))."""
    text = strip_index(value)
    try:
        tokens = shlex.split(text)
    except ValueError:
        tokens = text.split()
    what: List[str] = []
    by: List[Dict[str, Optional[str]]] = []
    i = 0
    if tokens and tokens[0].lower() == "to":
        i = 1
    while i < len(tokens) and tokens[i].lower() != "by":
        what.append(tokens[i])
        i += 1
    while i < len(tokens):
        if tokens[i].lower() != "by":
            i += 1
            continue
        i += 1
        if i >= len(tokens):
            break
        who = tokens[i]
        i += 1
        access = None
        control = None
        if i < len(tokens) and tokens[i].lower() != "by":
            tok = tokens[i]
            if tok.lower() in ACCESS_LEVELS or tok[:1] in "=+-" or tok.lower().startswith(("self", "realself")):
                access = tok
                i += 1
        if i < len(tokens) and tokens[i].lower() in ACCESS_CONTROLS:
            control = tokens[i].lower()
            i += 1
        by.append({"who": who, "access": (access or "none").lower(), "control": control})
    what_attrs: List[str] = []
    what_dn = None
    what_dn_style = None
    for token in what:
        if token.lower().startswith("attrs="):
            what_attrs = [a.strip().lower() for a in token[6:].split(",") if a.strip()]
        elif token.lower().startswith("dn."):
            style, _, dn = token[3:].partition("=")
            what_dn, what_dn_style = dn, style.lower()
        elif token.lower().startswith("dn="):
            what_dn, what_dn_style = token[3:], "regex"
    return {"what": " ".join(what), "what_attrs": what_attrs, "what_dn": what_dn, "what_dn_style": what_dn_style,
            "by": by}


def acl_access(acl: Dict[str, Any], who: str) -> Optional[str]:
    """The access level the parsed *acl* gives to the exact ``by`` clause *who* (``self``,
    ``anonymous``, ``users``, ``*``, ``dn.exact=…``), ``None`` when no clause names it."""
    wanted = who.strip().lower().replace('"', "")
    for clause in acl["by"]:
        if clause["who"].lower().replace('"', "") == wanted:
            return clause["access"]
    return None


def acl_for_attribute(acls: Sequence[Dict[str, Any]], attr: str) -> Optional[Dict[str, Any]]:
    """The first parsed ACL that applies to *attr* (``attrs=`` naming it, or ``*`` / no attrs
    clause): slapd stops at the first matching ``to`` clause."""
    wanted = attr.lower()
    for acl in acls:
        if not acl["what_attrs"] or wanted in acl["what_attrs"]:
            return acl
    return None


def parse_olc_security(value: str) -> Dict[str, int]:
    """``simple_bind=128 ssf=0`` → ``{'simple_bind': 128, 'ssf': 0}``."""
    result: Dict[str, int] = {}
    for token in strip_index(value).split():
        key, _, val = token.partition("=")
        try:
            result[key.strip().lower()] = int(val)
        except ValueError:
            continue
    return result


def parse_syncrepl(value: str) -> Dict[str, str]:
    """One ``olcSyncrepl`` value → ``{key: value}`` (keys lower case, quotes removed, the ``{n}``
    index dropped)."""
    text = strip_index(value)
    try:
        tokens = shlex.split(text)
    except ValueError:
        tokens = text.split()
    result: Dict[str, str] = {}
    for token in tokens:
        key, sep, val = token.partition("=")
        if sep:
            result[key.strip().lower()] = val
    return result


@dataclass
class SlapdConfig:
    loglevel: str = ""
    modules: List[str] = field(default_factory=list)
    tls: Dict[str, str] = field(default_factory=dict)
    security: Dict[str, int] = field(default_factory=dict)
    databases: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # by suffix (normalized)
    raw: List[Dict[str, Any]] = field(default_factory=list)

    def database(self, suffix: str) -> Optional[Dict[str, Any]]:
        return self.databases.get(normalize_dn(suffix))


def parse_slapd_config(entries: Sequence[Dict[str, Any]]) -> SlapdConfig:
    """The cn=config entries (:func:`config_search_cmd`) → :class:`SlapdConfig`.  A database is
    ``{'dn', 'type' ('mdb'), 'suffix', 'rootdn', 'rootpw', 'rootpw_hashed', 'directory',
    'access': [parsed olcAccess], 'access_raw', 'security', 'syncrepl': [parsed], 'overlays':
    [names], 'indexes', 'updateref', 'mirrormode'}``."""
    cfg = SlapdConfig(raw=list(entries))
    db_by_dn: Dict[str, Dict[str, Any]] = {}
    for e in entries:
        if has_object_class(e, "olcGlobal"):
            cfg.loglevel = " ".join(entry_values(e, "olcLogLevel"))
            for name, values in e["attrs"].items():
                if name.lower().startswith("olctls") and values:
                    cfg.tls[name] = values[0]
            cfg.security = parse_olc_security(entry_value(e, "olcSecurity")) if entry_values(e, "olcSecurity") else {}
        elif has_object_class(e, "olcModuleList"):
            for v in entry_values(e, "olcModuleLoad"):
                cfg.modules.append(re.sub(r"\.la$", "", strip_index(v)))
        elif has_object_class(e, "olcDatabaseConfig"):
            dbname = strip_index(entry_value(e, "olcDatabase"))
            suffix = entry_value(e, "olcSuffix")
            rootpw = entry_value(e, "olcRootPW")
            db = {
                "dn": e["dn"], "type": dbname, "suffix": suffix, "rootdn": entry_value(e, "olcRootDN"),
                "rootpw": rootpw, "rootpw_hashed": password_hashed(rootpw) if rootpw else False,
                "directory": entry_value(e, "olcDbDirectory"),
                "access_raw": [strip_index(v) for v in entry_values(e, "olcAccess")],
                "access": [parse_olc_access(v) for v in entry_values(e, "olcAccess")],
                "security": parse_olc_security(entry_value(e, "olcSecurity")) if entry_values(e, "olcSecurity") else {},
                "syncrepl": [parse_syncrepl(v) for v in entry_values(e, "olcSyncrepl")],
                "overlays": [],
                "indexes": [strip_index(v) for v in entry_values(e, "olcDbIndex")],
                "updateref": entry_value(e, "olcUpdateRef"),
                "mirrormode": entry_value(e, "olcMirrorMode").upper() == "TRUE",
            }
            db_by_dn[normalize_dn(e["dn"])] = db
            if suffix:
                cfg.databases[normalize_dn(suffix)] = db
    for e in entries:
        if has_object_class(e, "olcOverlayConfig"):
            parent = normalize_dn(parent_dn(e["dn"]))
            if parent in db_by_dn:
                db_by_dn[parent]["overlays"].append(strip_index(entry_value(e, "olcOverlay")))
    return cfg


# ---------------------------------------------------------------------------
# passwords
# ---------------------------------------------------------------------------


def ssha_hash(password: str, salt: Optional[bytes] = None) -> str:
    """``{SSHA}…`` of *password* as ``slappasswd`` prints it (4 random salt bytes)."""
    if salt is None:
        salt = os.urandom(4)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()


def password_hashed(value: str) -> bool:
    """True when a ``userPassword`` / ``olcRootPW`` value is a hash (``{SSHA}…``, ``{CRYPT}…``…)
    rather than clear text."""
    v = (value or "").strip()
    return any(v.upper().startswith(s) for s in HASH_SCHEMES)


def check_password(value: str, password: str) -> bool:
    """*password* matches the stored *value* (``{SSHA}``, ``{SHA}`` or clear text; other schemes
    give False)."""
    v = (value or "").strip()
    try:
        if v.upper().startswith("{SSHA}"):
            raw = base64.b64decode(v[6:])
            digest, salt = raw[:20], raw[20:]
            return hashlib.sha1(password.encode() + salt).digest() == digest
        if v.upper().startswith("{SHA}"):
            return base64.b64decode(v[5:]) == hashlib.sha1(password.encode()).digest()
    except ValueError:
        return False
    if v.startswith("{"):
        return False
    return v == password


# ---------------------------------------------------------------------------
# client side: NSS, nslcd, PAM, getent, id, ss
# ---------------------------------------------------------------------------


def parse_nsswitch(text: str) -> Dict[str, List[str]]:
    """``/etc/nsswitch.conf`` → ``{database: [sources]}`` (the ``[action]`` tokens dropped)."""
    result: Dict[str, List[str]] = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        db, _, rest = line.partition(":")
        sources = [t.lower() for t in rest.split() if not t.startswith("[") and not t.endswith("]")]
        result[db.strip().lower()] = sources
    return result


def nsswitch_has(conf: Dict[str, List[str]], database: str, source: str = "ldap") -> bool:
    return source.lower() in conf.get(database.lower(), [])


def parse_nslcd_conf(text: str) -> Dict[str, List[str]]:
    """``/etc/nslcd.conf`` → ``{option: [values]}`` (options lower case, one value per line as
    written: ``uri`` may have several)."""
    result: Dict[str, List[str]] = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        result.setdefault(key.strip().lower(), []).append(value.strip())
    return result


def nslcd_tls(conf: Dict[str, List[str]]) -> Dict[str, Any]:
    """How nslcd talks to the server: ``{'uris', 'ldaps' (an ldaps:// uri), 'starttls' (``ssl
    start_tls``), 'cacert' (tls_cacertfile), 'reqcert', 'binddn', 'base'}``."""
    uris = conf.get("uri", [])
    ssl = [v.lower() for v in conf.get("ssl", [])]
    return {
        "uris": uris,
        "ldaps": any(u.lower().startswith("ldaps://") for u in uris),
        "starttls": "start_tls" in ssl,
        "cacert": (conf.get("tls_cacertfile") or [None])[0],
        "reqcert": (conf.get("tls_reqcert") or [None])[0],
        "binddn": (conf.get("binddn") or [None])[0],
        "base": (conf.get("base") or [None])[0],
    }


@dataclass
class PamLine:
    type: str
    control: str
    module: str
    args: List[str]


def parse_pam_file(text: str) -> List[PamLine]:
    """A PAM configuration file (``/etc/pam.d/common-auth``…) → its rules (continuations joined,
    ``@include`` lines as type ``@include``)."""
    lines: List[PamLine] = []
    logical: List[str] = []
    for raw in (text or "").splitlines():
        raw = raw.rstrip()
        if logical and logical[-1].endswith("\\"):
            logical[-1] = logical[-1][:-1] + " " + raw.strip()
        else:
            logical.append(raw)
    for line in logical:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("@include"):
            lines.append(PamLine("@include", "", line.split(None, 1)[1] if " " in line else "", []))
            continue
        tokens = line.split()
        if len(tokens) < 3:
            continue
        ptype = tokens[0].lower()
        if tokens[1].startswith("["):
            j = 1
            control = tokens[1]
            while not tokens[j].endswith("]") and j + 1 < len(tokens):
                j += 1
                control += " " + tokens[j]
            rest = tokens[j + 1:]
        else:
            control = tokens[1]
            rest = tokens[2:]
        if not rest:
            continue
        lines.append(PamLine(ptype.lstrip("-"), control, rest[0], rest[1:]))
    return lines


def pam_modules(lines: Sequence[PamLine], ptype: str) -> List[str]:
    """The modules of the rules of type *ptype* (``auth``, ``account``, ``session``, ``password``)."""
    return [l.module for l in lines if l.type == ptype]


def pam_has(lines: Sequence[PamLine], ptype: str, module: str) -> bool:
    return module in pam_modules(lines, ptype)


def parse_getent_passwd(text: str) -> Dict[str, Dict[str, Any]]:
    """``getent passwd`` lines → ``{login: {'uid', 'gid', 'gecos', 'home', 'shell'}}``."""
    result: Dict[str, Dict[str, Any]] = {}
    for line in (text or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) != 7:
            continue
        try:
            result[parts[0]] = {"uid": int(parts[2]), "gid": int(parts[3]), "gecos": parts[4], "home": parts[5],
                                "shell": parts[6]}
        except ValueError:
            continue
    return result


def parse_getent_group(text: str) -> Dict[str, Dict[str, Any]]:
    """``getent group`` lines → ``{name: {'gid', 'members'}}``."""
    result: Dict[str, Dict[str, Any]] = {}
    for line in (text or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) != 4:
            continue
        try:
            result[parts[0]] = {"gid": int(parts[2]), "members": [m for m in parts[3].split(",") if m]}
        except ValueError:
            continue
    return result


def parse_id(text: str) -> Optional[Dict[str, Any]]:
    """``id LOGIN`` → ``{'uid', 'user', 'gid', 'group', 'groups': {gid: name}}``, ``None`` on an error."""
    m = re.search(r"uid=(\d+)\(([^)]*)\)\s+gid=(\d+)\(([^)]*)\)(?:\s+groups=(\S+))?", text or "")
    if not m:
        return None
    groups: Dict[int, str] = {}
    for g in (m.group(5) or "").split(","):
        gm = re.match(r"(\d+)\(([^)]*)\)", g)
        if gm:
            groups[int(gm.group(1))] = gm.group(2)
    return {"uid": int(m.group(1)), "user": m.group(2), "gid": int(m.group(3)), "group": m.group(4), "groups": groups}


def parse_listen_ports(text: str) -> Dict[int, str]:
    """``ss -tlnp`` → ``{port: process name or ''}`` of the TCP listeners."""
    result: Dict[int, str] = {}
    for line in (text or "").splitlines():
        if "LISTEN" not in line:
            continue
        m = re.search(r"\s(?:\*|\[[^\]]*\](?:%\w+)?|[0-9a-fA-F.:]+(?:%\w+)?):(\d+)\s", line)
        if not m:
            continue
        pm = re.search(r'users:\(\("([^"]+)"', line)
        port = int(m.group(1))
        result[port] = pm.group(1) if pm else result.get(port, "")
    return result


def parse_login_probe(text: str) -> Optional[Dict[str, Any]]:
    """The JSON document of ``login_probe.py`` (the last ``{…}`` line of *text*), ``None`` when none."""
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


def parse_s_client(text: str) -> Dict[str, Any]:
    """The lines kept by :func:`s_client_cmd` → ``{'connected', 'verify_code' (None when no
    verification result), 'verify_text', 'subject', 'issuer', 'errors': [verify error lines]}``."""
    out = text or ""
    result: Dict[str, Any] = {"connected": "CONNECTED" in out, "verify_code": None, "verify_text": "",
                              "subject": "", "issuer": "", "errors": []}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            result["subject"] = line[8:].strip()
        elif line.startswith("issuer="):
            result["issuer"] = line[7:].strip()
        elif line.startswith("Verify return code:"):
            m = re.match(r"Verify return code:\s*(\d+)\s*\((.*)\)", line)
            if m:
                result["verify_code"] = int(m.group(1))
                result["verify_text"] = m.group(2)
        elif line.startswith("verify error"):
            result["errors"].append(line)
    return result


def parse_csn(value: str) -> Optional[Tuple[str, str, str, str, str]]:
    """A ``contextCSN`` / ``entryCSN`` value → its fields ``(time, usec, count, sid, mod)``."""
    m = _CSN_RE.match((value or "").strip())
    return m.groups() if m else None


# ---------------------------------------------------------------------------
# renderers (states)
# ---------------------------------------------------------------------------


def _ldif_value(name: str, value: str) -> str:
    """One ``name: value`` line, base64-encoded when LDIF requires it."""
    safe = value.isascii() and value.isprintable() and not value.startswith((" ", ":", "<")) and not value.endswith(" ")
    if safe:
        return f"{name}: {value}"
    return f"{name}:: {base64.b64encode(value.encode()).decode()}"


def render_entry_ldif(dn: str, attrs: Sequence[Tuple[str, Any]]) -> str:
    """An LDIF entry (``attrs`` = ``[(name, value or [values])]``), blank line included."""
    lines = [f"dn: {dn}"]
    for name, value in attrs:
        values = value if isinstance(value, (list, tuple)) else [value]
        for v in values:
            lines.append(_ldif_value(name, str(v)))
    return "\n".join(lines) + "\n\n"


def render_base_ldif(suffix: str, organization: str, description: str = "") -> str:
    """The root entry of a ``dc=…`` suffix (``dcObject`` + ``organization``)."""
    dc = rdn_value(suffix)
    attrs: List[Tuple[str, Any]] = [("objectClass", ["top", "dcObject", "organization"]), ("dc", dc),
                                    ("o", organization)]
    if description:
        attrs.append(("description", description))
    return render_entry_ldif(suffix, attrs)


def render_ou_ldif(suffix: str, ou: str) -> str:
    return render_entry_ldif(f"ou={ou},{suffix}", [("objectClass", ["top", "organizationalUnit"]), ("ou", ou)])


def render_person_ldif(suffix: str, login: str, first_name: str, last_name: str, uid_number: int,
                       gid_number: int, password_hash: str, home: Optional[str] = None, shell: str = "/bin/bash",
                       mail: Optional[str] = None, people_ou: str = "people",
                       extra: Sequence[Tuple[str, Any]] = ()) -> str:
    """An ``inetOrgPerson`` + ``posixAccount`` + ``shadowAccount`` entry under ``ou=people``."""
    attrs: List[Tuple[str, Any]] = [
        ("objectClass", ["top", "inetOrgPerson", "posixAccount", "shadowAccount"]),
        ("uid", login), ("cn", f"{first_name} {last_name}"), ("sn", last_name), ("givenName", first_name),
        ("uidNumber", uid_number), ("gidNumber", gid_number), ("homeDirectory", home or f"/home/{login}"),
        ("loginShell", shell), ("userPassword", password_hash),
    ]
    if mail:
        attrs.append(("mail", mail))
    attrs.extend(extra)
    return render_entry_ldif(f"uid={login},ou={people_ou},{suffix}", attrs)


def render_posix_group_ldif(suffix: str, name: str, gid_number: int, members: Sequence[str] = (),
                            groups_ou: str = "groups", description: str = "") -> str:
    attrs: List[Tuple[str, Any]] = [("objectClass", ["top", "posixGroup"]), ("cn", name), ("gidNumber", gid_number)]
    if description:
        attrs.append(("description", description))
    for m in members:
        attrs.append(("memberUid", m))
    return render_entry_ldif(f"cn={name},ou={groups_ou},{suffix}", attrs)


def render_service_account_ldif(dn: str, password_hash: str, description: str = "") -> str:
    """A bind-only account (``simpleSecurityObject`` + ``organizationalRole``), e.g. ``cn=nslcd,…``."""
    attrs: List[Tuple[str, Any]] = [("objectClass", ["top", "simpleSecurityObject", "organizationalRole"]),
                                    ("cn", rdn_value(dn)), ("userPassword", password_hash)]
    if description:
        attrs.append(("description", description))
    return render_entry_ldif(dn, attrs)


def render_modify_ldif(dn: str, changes: Sequence[Tuple[str, str, Any]]) -> str:
    """An LDIF ``changetype: modify`` record: ``changes`` = ``[(op, attr, value or [values])]`` with
    *op* ``add`` / ``replace`` / ``delete`` (``delete`` with ``None`` removes the attribute)."""
    lines = [f"dn: {dn}", "changetype: modify"]
    for op, attr, value in changes:
        lines.append(f"{op}: {attr}")
        if value is not None:
            values = value if isinstance(value, (list, tuple)) else [value]
            for v in values:
                lines.append(_ldif_value(attr, str(v)))
        lines.append("-")
    return "\n".join(lines) + "\n\n"


def render_slapd_config_ldif(suffix: str, rootdn: str, rootpw_hash: str, directory: str = "/var/lib/ldap",
                             loglevel: str = "stats", schemas: Sequence[str] = DEFAULT_SCHEMAS,
                             access: Sequence[str] = DEFAULT_ACCESS, extra_modules: Sequence[str] = (),
                             indexes: Sequence[str] = ("objectClass eq", "cn,uid eq", "uidNumber,gidNumber eq",
                                                       "member,memberUid eq", "entryCSN,entryUUID eq"),
                             max_size: int = 1073741824, local_ssf: Optional[int] = 128) -> str:
    """The ``cn=config`` tree of a fresh slapd, for ``slapadd -n 0 -F /etc/ldap/slapd.d -l FILE``
    (the Debian ``slapd.init.ldif`` layout: the schemas included from ``/etc/ldap/schema``, the
    frontend and config databases administered by root through ``ldapi:///``, one ``mdb``
    database with the Debian default ACLs).  *local_ssf* (``olcLocalSSF``) makes the ``ldapi``
    sessions count as protected: the rootdn's simple binds over ``ldapi:///`` stay allowed under
    ``olcSecurity: simple_bind=128``."""
    modules = ["back_mdb", *extra_modules]
    lines = [
        "dn: cn=config", "objectClass: olcGlobal", "cn: config", "olcArgsFile: /var/run/slapd/slapd.args",
        f"olcLogLevel: {loglevel}", "olcPidFile: /var/run/slapd/slapd.pid", "olcToolThreads: 1",
    ]
    if local_ssf is not None:
        lines.append(f"olcLocalSSF: {local_ssf}")
    lines += [
        "",
        "dn: cn=module{0},cn=config", "objectClass: olcModuleList", "cn: module{0}", "olcModulePath: /usr/lib/ldap",
    ]
    lines += [f"olcModuleLoad: {m}" for m in modules]
    lines += ["", "dn: cn=schema,cn=config", "objectClass: olcSchemaConfig", "cn: schema", ""]
    lines += [f"include: file:///etc/ldap/schema/{s}.ldif" for s in schemas]
    lines += [
        "", "dn: olcDatabase={-1}frontend,cn=config", "objectClass: olcDatabaseConfig",
        "objectClass: olcFrontendConfig", "olcDatabase: {-1}frontend", "olcSizeLimit: 500",
        f"olcAccess: to * by {PEERCRED_ROOT} manage by * break", 'olcAccess: to dn.exact="" by * read',
        'olcAccess: to dn.base="cn=Subschema" by * read', "",
        "dn: olcDatabase={0}config,cn=config", "objectClass: olcDatabaseConfig", "olcDatabase: {0}config",
        f"olcAccess: to * by {PEERCRED_ROOT} manage by * break", "olcRootDN: cn=admin,cn=config", "",
        "dn: olcDatabase={1}mdb,cn=config", "objectClass: olcDatabaseConfig", "objectClass: olcMdbConfig",
        "olcDatabase: {1}mdb", f"olcDbDirectory: {directory}", f"olcSuffix: {suffix}", f"olcRootDN: {rootdn}",
        f"olcRootPW: {rootpw_hash}", f"olcDbMaxSize: {max_size}", "olcLastMod: TRUE", "olcDbCheckpoint: 512 30",
    ]
    lines += [f"olcDbIndex: {i}" for i in indexes]
    lines += [f"olcAccess: {a}" for a in access]
    return "\n".join(lines) + "\n"


def render_nslcd_conf(uri: str, base: str, binddn: Optional[str] = None, bindpw: Optional[str] = None,
                      starttls: bool = False, cacert: Optional[str] = None, reqcert: Optional[str] = None,
                      uid: str = "nslcd", gid: str = "nslcd") -> str:
    """An ``/etc/nslcd.conf`` (``ssl start_tls`` with *starttls*, ``tls_cacertfile`` with *cacert*)."""
    lines = [f"uid {uid}", f"gid {gid}", f"uri {uri}", f"base {base}"]
    if binddn:
        lines.append(f"binddn {binddn}")
        if bindpw is not None:
            lines.append(f"bindpw {bindpw}")
    if starttls:
        lines.append("ssl start_tls")
    if cacert:
        lines.append(f"tls_cacertfile {cacert}")
    if reqcert:
        lines.append(f"tls_reqcert {reqcert}")
    return "\n".join(lines) + "\n"


def render_syncrepl(rid: int, provider: str, binddn: str, credentials: str, searchbase: str,
                    type: str = "refreshAndPersist", retry: str = "5 +", starttls: Optional[str] = None,
                    tls_cacert: Optional[str] = None, bindmethod: str = "simple") -> str:
    """One ``olcSyncrepl`` value (a consumer of *provider*)."""
    value = (f"rid={rid:03d} provider={provider} bindmethod={bindmethod} binddn=\"{binddn}\" "
             f"credentials={credentials} searchbase=\"{searchbase}\" type={type} retry=\"{retry}\"")
    if starttls:
        value += f" starttls={starttls}"
    if tls_cacert:
        value += f" tls_cacert={tls_cacert}"
    return value


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def install_login_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy ``lib/login_probe.py`` to :data:`LOGIN_PROBE_PATH` on *machine*."""
    script = Path(__file__).with_name("login_probe.py").read_text()
    net_scheme.file(machine, LOGIN_PROBE_PATH, script, permissions=0o755, step=step)


# ---------------------------------------------------------------------------
# grade-side wrappers
# ---------------------------------------------------------------------------


def ldap_search(grade: Grade0, machine: str, uri: str, base: str, filter: str = "(objectClass=*)",
                attrs: Sequence[str] = (), binddn: Optional[str] = None, password: Optional[str] = None,
                scope: Optional[str] = None, starttls: bool = False, external: bool = False, step: int = 1,
                timeout: int = 20) -> LdapResult:
    out, code = grade.test(machine, ldapsearch_cmd(uri, base, filter, attrs, binddn, password, scope, starttls,
                                                   external), step=step, timeout=timeout, allow_error=True)
    return ldap_result(out, code)


def ldap_bind(grade: Grade0, machine: str, uri: str, binddn: str, password: str, starttls: bool = False,
              step: int = 1, timeout: int = 20) -> LdapResult:
    """``ldapwhoami`` as *binddn*: ``ok`` iff the password (and the transport) is accepted."""
    out, code = grade.test(machine, ldapwhoami_cmd(uri, binddn, password, starttls), step=step, timeout=timeout,
                           allow_error=True)
    return ldap_result(out, code)


def ldap_modify(grade: Grade0, machine: str, uri: str, ldif: str, binddn: Optional[str] = None,
                password: Optional[str] = None, starttls: bool = False, external: bool = False, add: bool = False,
                step: int = 1, timeout: int = 20) -> LdapResult:
    out, code = grade.test(machine, ldapmodify_cmd(uri, ldif, binddn, password, starttls, external, add),
                           step=step, timeout=timeout, allow_error=True)
    return ldap_result(out, code)


def get_slapd_config(grade: Grade0, machine: str, step: int = 1) -> SlapdConfig:
    out, _ = grade.test(machine, config_search_cmd(), step=step, allow_error=True)
    return parse_slapd_config(parse_ldif(out))


def get_file(grade: Grade0, machine: str, path: str, step: int = 1) -> str:
    """The text of *path* on *machine* (``''`` when missing)."""
    text, code = grade.test(machine, f"cat {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return text if code == 0 else ""


def get_nslcd_conf(grade: Grade0, machine: str, step: int = 1) -> Dict[str, List[str]]:
    return parse_nslcd_conf(get_file(grade, machine, "/etc/nslcd.conf", step))


def get_nsswitch(grade: Grade0, machine: str, step: int = 1) -> Dict[str, List[str]]:
    return parse_nsswitch(get_file(grade, machine, "/etc/nsswitch.conf", step))


def get_pam_file(grade: Grade0, machine: str, name: str, step: int = 1) -> List[PamLine]:
    return parse_pam_file(get_file(grade, machine, f"/etc/pam.d/{name}", step))


def getent_passwd(grade: Grade0, machine: str, login: str, step: int = 1) -> Optional[Dict[str, Any]]:
    """The ``getent passwd LOGIN`` entry of *login* on *machine* (``None`` when unknown)."""
    out, _ = grade.test(machine, f"getent passwd {shlex.quote(login)} 2>&1", step=step, allow_error=True)
    return parse_getent_passwd(out).get(login)


def getent_group(grade: Grade0, machine: str, name: str, step: int = 1) -> Optional[Dict[str, Any]]:
    out, _ = grade.test(machine, f"getent group {shlex.quote(name)} 2>&1", step=step, allow_error=True)
    return parse_getent_group(out).get(name)


def get_id(grade: Grade0, machine: str, login: str, step: int = 1) -> Optional[Dict[str, Any]]:
    out, _ = grade.test(machine, f"id {shlex.quote(login)} 2>&1", step=step, allow_error=True)
    return parse_id(out)


def get_listen_ports(grade: Grade0, machine: str, step: int = 1) -> Dict[int, str]:
    out, _ = grade.test(machine, "ss -tlnp 2>&1", step=step, allow_error=True)
    return parse_listen_ports(out)


def login_probe(grade: Grade0, machine: str, mode: str, user: str, password: str, host: Optional[str] = None,
                step: int = 1, timeout: int = 20) -> Optional[Dict[str, Any]]:
    """Run the login probe on *machine* (``su`` there, or ``ssh`` towards *host*); ``None`` until
    it ran or when it printed nothing."""
    out, _ = grade.test(machine, login_probe_cmd(mode, user, password, host, timeout), step=step,
                        timeout=timeout + 10, allow_error=True)
    return parse_login_probe(out)


def tls_check(grade: Grade0, machine: str, host: str, port: int, cafile: str, hostname: str,
              starttls: Optional[str] = None, step: int = 1) -> Dict[str, Any]:
    """:func:`parse_s_client` of an ``openssl s_client`` run on *machine* (``ran`` tells whether
    the command ran: the output ends with ``===END``)."""
    out, _ = grade.test(machine, s_client_cmd(host, port, cafile, hostname, starttls), step=step, timeout=30,
                        allow_error=True)
    result = parse_s_client(out)
    result["ran"] = (out or "").rstrip().endswith("===END")
    return result
