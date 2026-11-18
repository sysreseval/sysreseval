"""802.1X helpers of the AAA lab (``lab/sre/_DRAFT_misc/aaa.py``): a Linux switch as the
authenticator (``hostapd`` with its ``wired`` driver on the access ports of a bridge, the ports
opened by an nftables set that a ``hostapd_cli -a`` action script fills), wired supplicants
(``wpa_supplicant -D wired``) and ``eapol_test`` (an EAP client speaking RADIUS directly).

Formats of hostapd / wpa_supplicant / eapol_test 2.10 (Debian 12, ``sysreseval/aaa``); fixtures in
``tests/mock_data/aaa/``.

**Renderers**: :func:`render_hostapd_wired` (one ``/etc/hostapd/<port>.conf`` per access port, for
``hostapd@<port>``), :func:`render_port_control_nft` (a bridge-family table: an ``authorized`` set of
MAC addresses, the frames of the access ports from other addresses dropped, EAPOL always let in),
:func:`render_action_script` (``AP-STA-CONNECTED`` / ``AP-STA-DISCONNECTED`` → add / delete the
address), :func:`render_network_block` (the ``network={…}`` of ``wpa_supplicant`` and ``eapol_test``),
:func:`render_wpa_supplicant_wired` (``/etc/wpa_supplicant/wpa_supplicant-wired-<if>.conf`` for
``wpa_supplicant-wired@<if>``).

**Commands and parsers**: :func:`all_sta_cmd` / :func:`parse_all_sta` (``hostapd_cli all_sta``: one
block per station, the MAC address on its own line), :func:`wpa_status_cmd` /
:func:`parse_key_values` (``wpa_cli status``), :func:`eapol_test_cmd` / :func:`parse_eapol_test` (the
result and the subjects of the server certificate chain).
"""
import re
import shlex
from typing import Any, Dict, List, Optional, Sequence

from SRE.lib_sre import Grade0

RC_MARK = "===RC"
EAPOL_ETHERTYPE = 0x888E
PAE_GROUP_ADDRESS = "01:80:c2:00:00:03"
HOSTAPD_CTRL = "/var/run/hostapd"
WPA_CTRL = "/var/run/wpa_supplicant"
EAP_TYPES = {"md5": 4, "gtc": 6, "tls": 13, "ttls": 21, "peap": 25, "mschapv2": 26}


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def render_hostapd_wired(interface: str, own_ip: str, nas_identifier: str, auth_server: str, secret: str,
                         acct_server: Optional[str] = None, acct_secret: Optional[str] = None,
                         reauth_period: int = 3600) -> str:
    """The configuration of an 802.1X authenticator on one wired port (``driver=wired``), the
    RADIUS server for authentication and, when given, for accounting."""
    lines = [
        f"interface={interface}",
        "driver=wired",
        "logger_syslog=-1",
        "logger_syslog_level=2",
        f"ctrl_interface={HOSTAPD_CTRL}",
        "ieee8021x=1",
        "eapol_version=2",
        "use_pae_group_addr=1",
        f"eap_reauth_period={int(reauth_period)}",
        f"own_ip_addr={own_ip}",
        f"nas_identifier={nas_identifier}",
        f"auth_server_addr={auth_server}",
        "auth_server_port=1812",
        f"auth_server_shared_secret={secret}",
    ]
    if acct_server:
        lines += [f"acct_server_addr={acct_server}", "acct_server_port=1813",
                  f"acct_server_shared_secret={acct_secret or secret}"]
    return "\n".join(lines) + "\n"


def render_port_control_nft(ports: Sequence[str], table: str = "dot1x", set_name: str = "authorized") -> str:
    """``nft -f`` input: the frames entering through an access port pass the bridge only from an
    authorized MAC address; towards the switch itself only EAPOL (``0x888e``) passes from the
    others (the link-local EAPOL frames go through the bridge's ``input`` hook too)."""
    plist = ", ".join(f'"{p}"' for p in ports)
    return (f"table bridge {table} {{\n"
            f"\tset {set_name} {{\n\t\ttype ether_addr\n\t}}\n"
            f"\tchain forward {{\n\t\ttype filter hook forward priority 0; policy accept;\n"
            f"\t\tiifname {{ {plist} }} ether saddr != @{set_name} drop\n\t}}\n"
            f"\tchain input {{\n\t\ttype filter hook input priority 0; policy accept;\n"
            f"\t\tiifname {{ {plist} }} ether type != 0x888e ether saddr != @{set_name} drop\n\t}}\n"
            f"}}\n")


def render_action_script(table: str = "dot1x", set_name: str = "authorized") -> str:
    """The ``hostapd_cli -a`` script: called with the interface, the event and the station's
    address.  ``SCRIPT IFACE SYNC``, run once ``hostapd_cli`` is attached, adds the stations hostapd
    authorized before: an event that happens before ``hostapd_cli`` attaches is lost, and a station
    that authenticates again while authorized emits no new ``AP-STA-CONNECTED`` (seen live: a
    supplicant still running when hostapd restarts)."""
    return f"""#!/bin/sh
# hostapd_cli -a: $1 = interface, $2 = event, $3 = MAC address of the station
# "dot1x-port IFACE SYNC": add the stations already authorized (the events before hostapd_cli are lost)
case "$2" in
    AP-STA-CONNECTED)    nft add element bridge {table} {set_name} "{{ $3 }}" ;;
    AP-STA-DISCONNECTED) nft delete element bridge {table} {set_name} "{{ $3 }}" 2>/dev/null ;;
    SYNC)
        for mac in $(hostapd_cli -p {HOSTAPD_CTRL} -i "$1" all_sta | awk '/^[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:/ {{m = $0}} /^flags=.*AUTHORIZED/ {{print m}}'); do
            nft add element bridge {table} {set_name} "{{ $mac }}"
        done ;;
esac
exit 0
"""


def render_network_block(eap: str, identity: str, password: Optional[str] = None, ca_cert: Optional[str] = None,
                         domain_match: Optional[str] = None, client_cert: Optional[str] = None,
                         private_key: Optional[str] = None, anonymous_identity: Optional[str] = None,
                         phase2: Optional[str] = None) -> str:
    """``network={…}`` of a wired 802.1X client (``key_mgmt=IEEE8021X``, ``eapol_flags=0``):
    PEAP / TTLS with *password* and ``phase2`` (default ``auth=MSCHAPV2``), TLS with
    *client_cert* / *private_key*."""
    eap = eap.upper()
    lines = ["network={", "\tkey_mgmt=IEEE8021X", f"\teap={eap}", f'\tidentity="{identity}"']
    if anonymous_identity:
        lines.append(f'\tanonymous_identity="{anonymous_identity}"')
    if password is not None:
        lines.append(f'\tpassword="{password}"')
    if ca_cert:
        lines.append(f'\tca_cert="{ca_cert}"')
    if domain_match:
        lines.append(f'\tdomain_match="{domain_match}"')
    if client_cert:
        lines.append(f'\tclient_cert="{client_cert}"')
    if private_key:
        lines.append(f'\tprivate_key="{private_key}"')
    if eap in ("PEAP", "TTLS"):
        lines.append(f'\tphase2="{phase2 or "auth=MSCHAPV2"}"')
    lines += ["\teapol_flags=0", "}"]
    return "\n".join(lines) + "\n"


def render_wpa_supplicant_wired(network_block: str) -> str:
    """``wpa_supplicant-wired-<if>.conf``: the control socket (``wpa_cli``), ``ap_scan=0`` (wired)."""
    return f"ctrl_interface={WPA_CTRL}\nap_scan=0\n{network_block}"


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def all_sta_cmd(interface: str) -> str:
    return f"hostapd_cli -p {HOSTAPD_CTRL} -i {shlex.quote(interface)} all_sta 2>&1; echo \"{RC_MARK} $?\""


def wpa_status_cmd(interface: str = "eth0") -> str:
    return f"wpa_cli -p {WPA_CTRL} -i {shlex.quote(interface)} status 2>&1; echo \"{RC_MARK} $?\""


def wpa_command(command: str, interface: str = "eth0") -> str:
    """``wpa_cli logoff`` / ``logon`` / ``reauthenticate`` on *interface*."""
    return f"wpa_cli -p {WPA_CTRL} -i {shlex.quote(interface)} {command} 2>&1; echo \"{RC_MARK} $?\""


EAPOL_TEST_FILTER = r"CTRL-EVENT-EAP|^SUCCESS|^FAILURE|EAP-MSCHAPV2: |TLS: (Certificate verification|Failed)|alert|RADIUS packet matching"


def eapol_test_cmd(conf: str, server: str, secret: str, port: int = 1812, timeout: int = 8) -> str:
    """``eapol_test -c CONF -a SERVER -s SECRET`` with its long debug output reduced to the lines
    :func:`parse_eapol_test` reads (the exit status kept)."""
    log = "/tmp/.sre_eapol_test.log"
    return (f"eapol_test -c {shlex.quote(conf)} -a {shlex.quote(server)} -p {int(port)} -s {shlex.quote(secret)} "
            f"-t {int(timeout)} > {log} 2>&1; rc=$?; grep -E '{EAPOL_TEST_FILTER}' {log} | tail -n 40; "
            f"rm -f {log}; echo \"{RC_MARK} $rc\"")


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


def _split_rc(text: str):
    lines = (text or "").splitlines()
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip().startswith(RC_MARK):
            try:
                return "\n".join(lines[:i]), int(lines[i].strip()[len(RC_MARK):].strip())
            except ValueError:
                return "\n".join(lines[:i]), None
    return text or "", None


_MAC = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def parse_all_sta(text: str) -> Dict[str, Dict[str, str]]:
    """``{mac: {key: value}}`` of ``hostapd_cli all_sta`` (``flags``, ``dot1xAuthPaeState``,
    ``dot1xAuthSessionUserName``, ``last_eap_type_sta``…); a station is authorized when its flags
    hold ``[AUTHORIZED]`` (:func:`station_authorized`)."""
    out, _ = _split_rc(text)
    stations: Dict[str, Dict[str, str]] = {}
    current: Optional[Dict[str, str]] = None
    for line in out.splitlines():
        line = line.strip()
        if _MAC.match(line):
            current = stations.setdefault(line.lower(), {})
        elif current is not None and "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip()
    return stations


def station_authorized(station: Optional[Dict[str, str]]) -> bool:
    return bool(station) and "[AUTHORIZED]" in station.get("flags", "")


def parse_key_values(text: str) -> Dict[str, str]:
    """``key=value`` lines (``wpa_cli status``: ``wpa_state``, ``Supplicant PAE state``,
    ``suppPortStatus``, ``EAP state``, ``selectedMethod``…)."""
    out, code = _split_rc(text)
    values: Dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    if code is not None:
        values["__rc__"] = str(code)
    return values


def supplicant_authorized(status: Dict[str, str], method: Optional[str] = None) -> bool:
    """``wpa_cli status`` of an authenticated wired supplicant (and the EAP method, ``PEAP`` /
    ``TLS``, when given: ``selectedMethod=25 (EAP-PEAP)``)."""
    ok = status.get("suppPortStatus") == "Authorized" and status.get("EAP state") == "SUCCESS"
    if ok and method:
        number = EAP_TYPES.get(method.lower())
        selected = status.get("selectedMethod", "")
        ok = selected.split(" ")[0] == str(number) if number else method.upper() in selected.upper()
    return ok


def parse_eapol_test(text: str) -> Dict[str, Any]:
    """``{'ran', 'exit_code', 'success', 'failure', 'subjects': {depth: subject}, 'output'}`` of
    :func:`eapol_test_cmd` (``success``: the final ``SUCCESS`` line with exit status 0)."""
    out, code = _split_rc(text)
    subjects: Dict[int, str] = {}
    success = failure = False
    for line in out.splitlines():
        m = re.search(r"CTRL-EVENT-EAP-PEER-CERT depth=(\d+) subject='([^']*)'", line)
        if m:
            subjects[int(m.group(1))] = m.group(2)
        stripped = line.strip()
        if stripped == "SUCCESS":
            success = True
        elif stripped.startswith("FAILURE"):
            failure = True
    return {"ran": code is not None, "exit_code": code, "success": success and code == 0 and not failure,
            "failure": failure or (code not in (None, 0)), "subjects": subjects, "output": out}


def subject_cn(subject: str) -> str:
    """The CN of an OpenSSL subject (``/CN=radius.corp.lan`` or ``CN = radius.corp.lan, O = …``)."""
    m = re.search(r"CN\s*=\s*([^,/]+)", subject or "")
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# grade-side wrappers
# ---------------------------------------------------------------------------


def get_all_sta(grade: Grade0, machine: str, interface: str, step: int = 1) -> Dict[str, Dict[str, str]]:
    out, _ = grade.test(machine, all_sta_cmd(interface), step=step, allow_error=True)
    return parse_all_sta(out)


def get_wpa_status(grade: Grade0, machine: str, interface: str = "eth0", step: int = 1) -> Dict[str, str]:
    out, _ = grade.test(machine, wpa_status_cmd(interface), step=step, allow_error=True)
    return parse_key_values(out)


def eapol_test(grade: Grade0, machine: str, conf: str, server: str, secret: str, step: int = 1,
               timeout: int = 8) -> Dict[str, Any]:
    out, _ = grade.test(machine, eapol_test_cmd(conf, server, secret, timeout=timeout), step=step,
                        timeout=timeout + 15, allow_error=True)
    return parse_eapol_test(out)
