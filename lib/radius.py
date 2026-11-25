"""FreeRADIUS grading and state helpers of the AAA lab (``lab/sre/_DRAFT_misc/aaa.py``).

Facts and formats are those of FreeRADIUS 3.2.1 and freeradius-utils 3.2.1 (Debian 12, the
``sysreseval/aaa`` image built on ``init12``, which also keeps the configuration as installed in
:data:`PRISTINE_DIR`); the fixtures of ``tests/mock_data/aaa/`` were captured in those containers.

**Commands** (one shell line each, stderr merged, ``; echo "===RC $?"`` appended so that a
registration-pass placeholder is never taken for an answer): :func:`radclient_cmd` (the attribute
list piped to ``radclient -x``; a value may be a :class:`ShellExpr`, evaluated by the container's
shell, e.g. :func:`totp_shell` = ``$(oathtool --totp -b SECRET)``), :func:`detail_cmd` (the
accounting ``detail`` files), :func:`config_check_cmd` (``freeradius -XC``).

**Parsers**: :func:`parse_radclient` → :class:`RadiusResult` (the code of the answer, its attributes,
``no_reply`` when the server stayed silent: an unknown client, a wrong secret); :func:`parse_detail`
→ the accounting records.

**Renderers** for the states: :func:`render_client` (a ``clients.conf`` block),
:func:`render_users_entry` (the ``users`` file: check items on the first line, reply items below),
:func:`render_huntgroup`, :func:`render_ldap_module`, :func:`render_eap_module`,
:func:`render_default_site` (a complete ``default`` virtual server with optional LDAP, LDAP-group
policy and TOTP blocks), :func:`reset_cmd` (back to the installed configuration).

Facts (verified on the image, 2026-11-18): the ``totp`` module "can only be used in the
authenticate section", reads ``&control:TOTP-Secret`` (base32) and ``&request:TOTP-Password`` and
returns ``ok`` / ``fail``; rlm_ldap's group filter defaults to ``posixGroup`` with
``membership_attribute = memberOf`` and a commented ``membership_filter`` handling ``memberUid``;
the eap module of the package uses the snakeoil certificate and the system CA bundle
(``default_eap_type = md5``, ``tls_max_version = "1.2"``); ``clients.conf`` holds ``localhost``
(``127.0.0.1``, secret ``testing123``).
"""
import base64
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from SRE.lib_sre import Grade0

FREERADIUS_DIR = "/etc/freeradius/3.0"
PRISTINE_DIR = "/usr/local/share/sre/freeradius-pristine"   #: the configuration as installed (aaa13 image)
CLIENTS_FILE = f"{FREERADIUS_DIR}/clients.conf"
USERS_FILE = f"{FREERADIUS_DIR}/mods-config/files/authorize"  #: what ``users`` points to
HUNTGROUPS_FILE = f"{FREERADIUS_DIR}/mods-config/preprocess/huntgroups"
CERT_DIR = f"{FREERADIUS_DIR}/certs"
DETAIL_DIR = "/var/log/freeradius/radacct"
LOCALHOST_SECRET = "testing123"   #: the ``localhost`` client of the installed clients.conf
RC_MARK = "===RC"
RC_SUFFIX = f' 2>&1; echo "{RC_MARK} $?"'

ACCESS_ACCEPT = "Access-Accept"
ACCESS_REJECT = "Access-Reject"
ACCESS_CHALLENGE = "Access-Challenge"
ACCOUNTING_RESPONSE = "Accounting-Response"


class ShellExpr(str):
    """A piece of a :func:`radclient_cmd` value left to the container's shell (``$(…)``)."""


class Raw(str):
    """A value written without quotes in a FreeRADIUS file (``Tunnel-Type := VLAN``)."""


def random_base32_secret(nbytes: int = 10) -> str:
    """A TOTP secret: *nbytes* random bytes in base32 without padding (16 characters for 10)."""
    return base64.b32encode(os.urandom(nbytes)).decode().rstrip("=")


def totp_shell(secret: str, offset: Optional[str] = None) -> ShellExpr:
    """The current TOTP code of *secret* computed in the container (``oathtool``); *offset* such as
    ``"now + 10 minutes"`` gives the code of another time (a wrong code that looks right)."""
    when = f" -N {shlex.quote(offset)}" if offset else ""
    return ShellExpr(f"$(oathtool --totp -b{when} {shlex.quote(secret)})")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _dq(text: str) -> str:
    """*text* escaped for a double-quoted shell word."""
    return (text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`"))


def _radius_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def attrs_shell_word(attrs: Sequence[Tuple[str, Any]]) -> str:
    """The attribute list of a request as one double-quoted shell word: ``"User-Name = \\"x\\", …"``.
    A value is a string (quoted for radclient), an int, or a sequence of strings and
    :class:`ShellExpr` concatenated (``("pass", totp_shell(s))``)."""
    parts = []
    for name, value in attrs:
        if isinstance(value, int):
            parts.append(_dq(f"{name} = {value}"))
            continue
        pieces = value if isinstance(value, (list, tuple)) else [value]
        text = _dq(f'{name} = "')
        for piece in pieces:
            text += piece if isinstance(piece, ShellExpr) else _dq(_radius_string(str(piece)))
        text += _dq('"')
        parts.append(text)
    return '"' + ", ".join(parts) + '"'


def radclient_cmd(server: str, secret: str, attrs: Sequence[Tuple[str, Any]], code: str = "auth",
                  port: Optional[int] = None, timeout: int = 2, retries: int = 1) -> str:
    """``echo "<attrs>" | radclient -x -r N -t T server[:port] auth|acct|status SECRET`` (one line)."""
    target = f"{server}:{port}" if port else server
    return (f"echo {attrs_shell_word(attrs)} | radclient -x -r {int(retries)} -t {int(timeout)} "
            f"{shlex.quote(target)} {code} {shlex.quote(secret)}{RC_SUFFIX}")


def auth_attrs(user: str, password: Any = None, chap: bool = False,
               extra: Sequence[Tuple[str, Any]] = ()) -> List[Tuple[str, Any]]:
    """The attributes of an Access-Request: PAP (``User-Password``) or CHAP (radclient computes the
    CHAP response from a clear ``CHAP-Password``), with a ``Message-Authenticator``."""
    attrs: List[Tuple[str, Any]] = [("User-Name", user)]
    if password is not None:
        attrs.append(("CHAP-Password" if chap else "User-Password", password))
    attrs += list(extra)
    attrs.append(("Message-Authenticator", 0))
    return attrs


def detail_cmd(directory: str = DETAIL_DIR, lines: int = 600) -> str:
    """The accounting records written by the ``detail`` module (every client, every day)."""
    return f"cat {directory}/*/detail-* 2>/dev/null | tail -n {int(lines)}; echo \"{RC_MARK} 0\""


def config_check_cmd() -> str:
    """``freeradius -XC``: the configuration parsed without starting (the end of its output)."""
    return f"freeradius -XC 2>&1 | tail -n 15; echo \"{RC_MARK} $?\""


def reset_cmd() -> str:
    """Stop FreeRADIUS and put its configuration back as installed (logs kept)."""
    return (f"systemctl stop freeradius 2>/dev/null; pkill -x freeradius 2>/dev/null; "
            f"rm -rf /etc/freeradius && cp -a {PRISTINE_DIR} /etc/freeradius; "
            "systemctl reset-failed freeradius 2>/dev/null; true")


def restart_cmd() -> str:
    return "systemctl restart freeradius; sleep 1"


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


def split_rc(text: str) -> Tuple[str, Optional[int]]:
    """``(output without the marker line, exit status)``; status None when the marker is absent
    (the command did not run: registration pass, timeout)."""
    lines = (text or "").splitlines()
    for i in range(len(lines) - 1, -1, -1):
        line = lines[i].strip()
        if line.startswith(RC_MARK):
            try:
                code = int(line[len(RC_MARK):].strip())
            except ValueError:
                code = None
            return "\n".join(lines[:i]), code
    return text or "", None


_ATTR_LINE = re.compile(r"^\s+([A-Za-z0-9][\w.-]*)(?::(\d+))?\s*(=|:=|\+=|==)\s*(.*?)\s*$")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


@dataclass
class RadiusResult:
    ran: bool = False
    exit_code: Optional[int] = None
    sent: bool = False
    code: Optional[str] = None          #: the code of the answer (``Access-Accept``…), None without answer
    attrs: Dict[str, List[str]] = field(default_factory=dict)   #: the attributes of the answer
    no_reply: bool = False              #: radclient gave up (silent server)
    output: str = ""

    @property
    def accepted(self) -> bool:
        return self.code == ACCESS_ACCEPT

    @property
    def rejected(self) -> bool:
        return self.code == ACCESS_REJECT

    def attr(self, name: str) -> Optional[str]:
        values = self.attrs.get(name.lower())
        return values[0] if values else None


def parse_radclient(text: str) -> RadiusResult:
    """What ``radclient -x`` printed (:func:`radclient_cmd`)."""
    out, code = split_rc(text)
    result = RadiusResult(ran=code is not None, exit_code=code, output=out)
    in_answer = False
    for line in out.splitlines():
        m = re.match(r"^Sent (\S+) Id \d+", line)
        if m:
            result.sent = True
            in_answer = False
            continue
        m = re.match(r"^Received (\S+) Id \d+", line)
        if m:
            result.code = m.group(1)
            result.attrs = {}
            in_answer = True
            continue
        if "No reply from server" in line:
            result.no_reply = True
            in_answer = False
            continue
        if in_answer:
            a = _ATTR_LINE.match(line)
            if a:
                result.attrs.setdefault(a.group(1).lower(), []).append(_unquote(a.group(4)))
            elif line and not line[0].isspace():
                in_answer = False
    return result


def parse_detail(text: str) -> List[Dict[str, str]]:
    """The records of FreeRADIUS ``detail`` files: a date line, then tab-indented ``Attr = value``
    lines, a blank line between records.  Keys are lower-cased, ``date`` holds the first line."""
    out, _ = split_rc(text)
    records: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None
    for line in out.splitlines():
        if not line.strip():
            if current:
                records.append(current)
            current = None
            continue
        if not line[0].isspace():
            if current:
                records.append(current)
            current = {"date": line.strip()}
            continue
        a = _ATTR_LINE.match(line)
        if a and current is not None:
            current.setdefault(a.group(1).lower(), _unquote(a.group(4)))
    if current:
        records.append(current)
    return records


def normalize_station_id(value: str) -> str:
    """A ``Calling-Station-Id`` (``02-53-52-AA-BB-CC``, ``0253.52aa.bbcc``…) as ``02:53:52:aa:bb:cc``."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", value or "").lower()
    if len(hexdigits) != 12:
        return ""
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2))


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def rad_value(value: Any) -> str:
    """A value in a FreeRADIUS file: ints and :class:`Raw` as they are, strings quoted."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, Raw)):
        return str(value)
    return '"' + _radius_string(str(value)) + '"'


def render_client(name: str, ipaddr: str, secret: str, shortname: Optional[str] = None,
                  nas_type: Optional[str] = None) -> str:
    """A ``client NAME { ipaddr secret shortname }`` block of ``clients.conf``."""
    lines = [f"client {name} {{", f"\tipaddr = {ipaddr}", f"\tsecret = {secret}",
             f"\tshortname = {shortname or name}"]
    if nas_type:
        lines.append(f"\tnas_type = {nas_type}")
    return "\n" + "\n".join(lines) + "\n}\n"


AttrItem = Tuple[str, str, Any]


def render_users_entry(name: str, check: Sequence[AttrItem] = (), reply: Sequence[AttrItem] = (),
                       fall_through: bool = False) -> str:
    """An entry of the ``users`` file: *name* (or ``DEFAULT``) and the check items on the first line,
    the reply items indented below (``Fall-Through = Yes`` when asked)."""
    first = name
    if check:
        first += "\t" + ", ".join(f"{a} {op} {rad_value(v)}" for a, op, v in check)
    replies = [f"{a} {op} {rad_value(v)}" for a, op, v in reply]
    if fall_through:
        replies.append("Fall-Through = Yes")
    lines = [first] + [f"\t{r}" + ("," if i < len(replies) - 1 else "") for i, r in enumerate(replies)]
    return "\n".join(lines) + "\n\n"


def render_huntgroup(name: str, check: Sequence[AttrItem]) -> str:
    """A line of the ``huntgroups`` file: ``devices NAS-IP-Address == 192.0.2.1``."""
    return f"{name}\t" + ", ".join(f"{a} {op} {rad_value(v) if not _is_ip(v) else v}" for a, op, v in check) + "\n"


def _is_ip(v: Any) -> bool:
    return isinstance(v, str) and re.fullmatch(r"[0-9.]+(/\d+)?", v) is not None


def render_ldap_module(server: str, identity: str, password: str, base_dn: str, user_base: str,
                       group_base: str, name: str = "ldap") -> str:
    """A minimal ``mods-available/ldap``: the service account, the users under *user_base*
    (``uid``), the ``posixGroup`` groups under *group_base* (``memberUid`` through
    ``membership_filter``), no password read (the users bind: ``Auth-Type LDAP``)."""
    return f"""{name} {{
	server = '{server}'
	identity = '{identity}'
	password = '{password}'
	base_dn = '{base_dn}'
	update {{
		control:Password-With-Header	+= 'userPassword'
	}}
	user_dn = "LDAP-UserDn"
	user {{
		base_dn = "{user_base}"
		filter = "(uid=%{{%{{Stripped-User-Name}}:-%{{User-Name}}}})"
	}}
	group {{
		base_dn = "{group_base}"
		filter = '(objectClass=posixGroup)'
		membership_filter = "(|(member=%{{control:${{..user_dn}}}})(memberUid=%{{%{{Stripped-User-Name}}:-%{{User-Name}}}}))"
		membership_attribute = 'memberOf'
	}}
	options {{
		chase_referrals = yes
		rebind = yes
		res_timeout = 10
		srv_timelimit = 3
		net_timeout = 1
		idle = 60
		probes = 3
		interval = 3
		ldap_debug = 0x0000
	}}
	pool {{
		start = 0
		min = 0
		max = ${{thread[pool].max_servers}}
		spare = 1
		uses = 0
		retry_delay = 30
		lifetime = 0
		idle_timeout = 60
	}}
}}
"""


def render_eap_module(certificate_file: str, private_key_file: str, ca_file: str,
                      default_eap_type: str = "peap", check_cert_cn: Optional[str] = None) -> str:
    """A complete ``mods-available/eap``: one ``tls-common`` (the server certificate and the CA
    trusted for client certificates, *check_cert_cn* e.g. ``%{User-Name}`` for EAP-TLS), the ``md5``,
    ``tls``, ``ttls``, ``peap`` and ``mschapv2`` methods."""
    cn = f"\t\tcheck_cert_cn = {check_cert_cn}\n" if check_cert_cn else ""
    return f"""eap {{
	default_eap_type = {default_eap_type}
	timer_expire = 60
	ignore_unknown_eap_types = no
	cisco_accounting_username_bug = no
	max_sessions = ${{max_requests}}
	md5 {{
	}}
	tls-config tls-common {{
		private_key_file = {private_key_file}
		certificate_file = {certificate_file}
		ca_file = {ca_file}
{cn}		cipher_list = "DEFAULT"
		cipher_server_preference = no
		tls_min_version = "1.2"
		tls_max_version = "1.2"
		ecdh_curve = ""
		cache {{
			enable = no
		}}
		verify {{
		}}
		ocsp {{
			enable = no
		}}
	}}
	tls {{
		tls = tls-common
	}}
	ttls {{
		tls = tls-common
		default_eap_type = mschapv2
		copy_request_to_tunnel = no
		use_tunneled_reply = no
		virtual_server = "inner-tunnel"
	}}
	peap {{
		tls = tls-common
		default_eap_type = mschapv2
		copy_request_to_tunnel = no
		use_tunneled_reply = no
		virtual_server = "inner-tunnel"
	}}
	mschapv2 {{
	}}
}}
"""


def ldap_group_policy(groups: Sequence[Tuple[str, Sequence[AttrItem]]], ldap: str = "ldap") -> str:
    """The unlang block of the authorize section giving the users found in LDAP the reply items of
    their first matching group, rejecting those of no listed group."""
    lines = [f"\tif (&control:LDAP-UserDn) {{"]
    for i, (group, reply) in enumerate(groups):
        kw = "if" if i == 0 else "elsif"
        lines.append(f'\t\t{kw} (LDAP-Group == "{group}") {{')
        lines.append("\t\t\tupdate reply {")
        lines += [f"\t\t\t\t&{a} {op} {rad_value(v)}" for a, op, v in reply]
        lines.append("\t\t\t}")
        lines.append("\t\t}")
    lines += ["\t\telse {", "\t\t\treject", "\t\t}", "\t}"]
    return "\n".join(lines) + "\n"


TOTP_SPLIT = """	if (&control:TOTP-Secret) {
		if (&User-Password =~ /^(.*)([0-9]{6})$/) {
			update request {
				&User-Password := "%{1}"
				&TOTP-Password := "%{2}"
			}
		}
		else {
			reject
		}
	}
"""
"""The authorize block of the TOTP solution: for the users who have a secret, the six last digits
of the password are the code."""

TOTP_CHECK = """		if (&control:TOTP-Secret) {
			totp
		}
"""
"""Added to ``Auth-Type PAP`` after ``pap``: the code is checked once the password is."""


LDAP_AUTH_TYPE = """	if ((ok || updated) && User-Password && !control:Auth-Type) {
		update control {
			&Auth-Type := ldap
		}
	}
"""
"""Right after ``ldap`` in authorize (the commented block of the installed site): rlm_ldap 3.2 does
not set ``Auth-Type`` itself, the users found in the directory would be rejected with ``No
Auth-Type found``."""


def render_default_site(ldap: bool = False, ldap_policy: str = "", totp: bool = False) -> str:
    """A complete ``sites-available/default`` (the sections of the installed one without the
    comments and the unused modules) with the optional rlm_ldap lines (``ldap`` and
    :data:`LDAP_AUTH_TYPE` in authorize, ``Auth-Type LDAP``), the group policy *ldap_policy*
    (:func:`ldap_group_policy`) and the TOTP blocks (:data:`TOTP_SPLIT`, :data:`TOTP_CHECK`)."""
    authorize_ldap = "\tldap\n" + LDAP_AUTH_TYPE + ldap_policy if ldap else "\t-ldap\n"
    authorize_totp = TOTP_SPLIT if totp else ""
    pap_totp = TOTP_CHECK if totp else ""
    auth_ldap = "\tAuth-Type LDAP {\n\t\tldap\n\t}\n" if ldap else ""
    return f"""server default {{
listen {{
	type = auth
	ipaddr = *
	port = 0
	limit {{
		max_connections = 16
		lifetime = 0
		idle_timeout = 30
	}}
}}
listen {{
	ipaddr = *
	port = 0
	type = acct
}}
authorize {{
	filter_username
	preprocess
	chap
	mschap
	digest
	suffix
	eap {{
		ok = return
	}}
	files
	-sql
{authorize_ldap}{authorize_totp}	expiration
	logintime
	pap
}}
authenticate {{
	Auth-Type PAP {{
		pap
{pap_totp}	}}
	Auth-Type CHAP {{
		chap
	}}
	Auth-Type MS-CHAP {{
		mschap
	}}
	mschap
	digest
{auth_ldap}	eap
}}
preacct {{
	preprocess
	acct_unique
	suffix
	files
}}
accounting {{
	detail
	unix
	-sql
	exec
	attr_filter.accounting_response
}}
session {{
}}
post-auth {{
	if (session-state:User-Name && reply:User-Name && request:User-Name && (reply:User-Name == request:User-Name)) {{
		update reply {{
			&User-Name !* ANY
		}}
	}}
	update {{
		&reply: += &session-state:
	}}
	-sql
	exec
	remove_reply_message_if_eap
	Post-Auth-Type REJECT {{
		-sql
		attr_filter.access_reject
		eap
		remove_reply_message_if_eap
	}}
	Post-Auth-Type Challenge {{
	}}
	Post-Auth-Type Client-Lost {{
	}}
	if (EAP-Key-Name && &reply:EAP-Session-Id) {{
		update reply {{
			&EAP-Key-Name := &reply:EAP-Session-Id
		}}
	}}
}}
pre-proxy {{
}}
post-proxy {{
	eap
}}
}}
"""


# ---------------------------------------------------------------------------
# grade-side wrappers
# ---------------------------------------------------------------------------


def radius_request(grade: Grade0, machine: str, server: str, secret: str, attrs: Sequence[Tuple[str, Any]],
                   step: int = 1, code: str = "auth", timeout: int = 2, retries: int = 1) -> RadiusResult:
    """:func:`parse_radclient` of a request sent from *machine*."""
    out, _ = grade.test(machine, radclient_cmd(server, secret, attrs, code=code, timeout=timeout, retries=retries),
                        step=step, timeout=timeout * (retries + 1) + 10, allow_error=True)
    return parse_radclient(out)


def get_detail_records(grade: Grade0, machine: str, step: int = 1) -> List[Dict[str, str]]:
    out, _ = grade.test(machine, detail_cmd(), step=step, allow_error=True)
    return parse_detail(out)
