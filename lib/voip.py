"""VoIP lab helpers: SIP / RTP with Asterisk (chan_pjsip) and the baresip softphone.

Verified on Asterisk 22.12.0 (compiled in the ``voip`` image, ``images/voip/Dockerfile``) and
baresip 1.0.0 (Debian 12); the fixtures of ``tests/mock_data/voip/`` were captured live.

**Active probe** (``lib/sip_probe.py``, standard library only: a SIP user agent with G.711 audio).
State side: :func:`install_sip_probe`, :func:`start_sip_daemon` (the *persistent phones* of a hidden
machine, described by :func:`daemon_spec` / :func:`daemon_account`: each registers, answers its
calls with its own tone or with ``486 Busy Here``, and may call a number periodically).  Grade
side: :func:`sip_kick` (the phones register now and report), :func:`sip_probe` running the caller
scenarios of :func:`run_spec` (:func:`register_scenario`, :func:`call_scenario`) and returning
:class:`ScenarioResult` objects, :func:`get_phone_calls` reading what the phones received
(:class:`PhoneCall`).  Audio is checked by *tones*: every phone and every scenario sends its own
frequency among :data:`TONES` and reports the frequencies it heard, so a call tells who answered
and that the media flows in both directions; no sound device is involved.

**Asterisk console**: :func:`asterisk_rx_cmd` and pure parsers of ``pjsip show endpoint|aor``
(:func:`parse_parameters`), ``pjsip show contacts`` / ``transports`` / ``identifies``, ``rtp show
settings``, ``dialplan show <context>`` and of the voicemail message files, with thin
``(grade, machine, step)`` wrappers.  Every wrapper registers its command unconditionally (two-pass
contract of ``Grade0.test``) and returns an empty value until the command has run.

**baresip**: :func:`render_baresip_config` (no sound card: the microphone is a sine generator,
what is received is recorded by the ``sndfile`` filter), :func:`render_baresip_account`,
:func:`baresip_start_cmd` (daemon mode, for a reference solution).

Every command is a single line (the exetests runner carries one command per line) and only
depends on its arguments, never on a test result.

Facts (verified 2026-11-11 in the containers):

- a REGISTER for an unknown account or with a wrong password gets ``401`` again (never 403: an
  artificial endpoint hides which accounts exist); with an aor left at ``max_contacts = 0`` (the
  default) the answer is ``403``, even for a REGISTER without Contact (a query);
- an endpoint without ``allow`` refuses every call with ``488``; with ``allow = alaw`` the SDP
  answer is ``8 101``, an offer sharing no codec gets ``488`` (after 401, 404 and 100: the dialled
  number must exist);
- ``direct_media = yes`` (the default) on both parties: each receives a re-INVITE right after the
  answer and the RTP then flows phone to phone (source address and TOS byte of the peer);
- ``tos_audio = ef`` gives TOS byte 184 on the RTP sent by Asterisk, as root in a plain container;
- ``VoiceMail(box@ctx,b)``: ``#`` during the greeting skips to the beep; no RTP is sent while
  the message is recorded; a hang-up keeps the message (``INBOX/msg0000.txt`` with ``callerid=``,
  ``origtime=``, ``duration=``);
- a trunk endpoint with ``identify`` + ``auth``: the peer PBX whose ``outbound_auth`` is missing
  or wrong sees its call fail, and its own caller gets ``403``;
- ``media_encryption = sdes``: an ``RTP/SAVP`` offer with a crypto line is answered ``RTP/SAVP``
  with one, a plain ``RTP/AVP`` offer gets ``488``; an endpoint without it refuses ``RTP/SAVP``;
- without systemd ``asterisk`` goes to the background by itself but its control socket only
  exists a moment later (:func:`asterisk_start_cmd` waits for it); with the unit of the image
  (``Type=notify``) ``systemctl restart asterisk`` returns once it is fully booted;
- baresip finds ``~/.baresip`` through ``$LOGNAME`` or ``$USER`` (libre's ``fs_gethome``), which
  neither a state command nor a ``docker exec`` shell sets ("could not get config path"): the
  image puts a wrapper setting ``LOGNAME`` in ``/usr/local/bin``, and :func:`baresip_start_cmd`
  passes ``-f``; digits typed during a call are RFC 4733 events (in a terminal only: the key
  release that ends the event comes from the ``stdio`` module).
"""

import base64
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from SRE.lib_sre import Grade0, NetScheme0

PROBE_PATH = '/usr/local/sbin/sre_sip_probe.py'
PROBE_LOG = '/var/log/sre_sip_probe.jsonl'
RC_MARK = "===RC"
END_MARK = "===END"
MSG_MARK = "===MSG"
ASTERISK_CTL = '/var/run/asterisk/asterisk.ctl'
VOICEMAIL_SPOOL = '/var/spool/asterisk/voicemail'
BARESIP_DIR = '/root/.baresip'

#: Frequencies (Hz) the phones send and recognise: 80 Hz apart, on the bins of the detector.
TONES = tuple(range(400, 2320, 80))


# ---------------------------------------------------------------------------
# the probe: command lines
# ---------------------------------------------------------------------------

def encode_spec(spec: dict) -> str:
    """*spec* as the probe reads it: urlsafe base64 of its canonical JSON."""
    return base64.urlsafe_b64encode(json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).decode()


def daemon_calls(number, every: int = 25, duration: int = 5, codec: str = 'PCMA', ptime: int = 20) -> dict:
    """The periodic call of a phone: *number* every *every* seconds for *duration* seconds."""
    return {'number': str(number), 'every': every, 'duration': duration, 'codec': codec, 'ptime': ptime}


def daemon_account(user, password: str, server, sip_port: int, mode: str = 'answer', tone: Optional[int] = None,
                   display: str = '', user_agent: Optional[str] = None, expires: int = 120,
                   refresh: Optional[int] = None, retry: int = 10, rtp_port: Optional[int] = None,
                   port: int = 5060, calls: Optional[dict] = None, max_call: int = 120) -> dict:
    """One phone of a daemon: it registers *user* on *server* from its port *sip_port* (again
    every *refresh* seconds, half the granted time by default; every *retry* seconds while
    refused) and treats its incoming calls by *mode*: ``answer`` (its *tone* is sent), ``busy``
    (486) or ``none``; *calls* (:func:`daemon_calls`) makes it call a number periodically."""
    account = {'user': str(user), 'password': password, 'server': str(server), 'port': port,
               'sip_port': sip_port, 'mode': mode, 'expires': expires, 'retry': retry, 'max_call': max_call}
    for key, value in (('tone', tone), ('display', display), ('user_agent', user_agent), ('refresh', refresh),
                       ('rtp_port', rtp_port), ('calls', calls)):
        if value:
            account[key] = value
    return account


def daemon_spec(local_ip, accounts: List[dict], listen: Iterable[int] = TONES) -> dict:
    """The phones of one machine (its address *local_ip*)."""
    return {'local_ip': str(local_ip), 'listen': list(listen), 'accounts': list(accounts)}


def sip_daemon_cmd(spec: dict, ensure: bool = False) -> str:
    """Start the phones of *spec* in the background (in place of a previous instance; with
    *ensure*, only when none is running)."""
    return f"python3 {PROBE_PATH} {'ensure' if ensure else 'daemon'} {encode_spec(spec)} 2>&1"


def sip_kick_cmd() -> str:
    """Make the phones register now and print their status (one JSON document)."""
    return f"python3 {PROBE_PATH} kick 2>&1"


def register_scenario(scenario_id: str, server, user, password: str, contact: bool = False, expires: int = 60,
                      unregister: bool = True, port: int = 5060, transport: str = 'udp',
                      ca_file: Optional[str] = None, server_name: Optional[str] = None) -> dict:
    """A REGISTER of *user*.  Without *contact* it is a query: it is authenticated like any
    REGISTER but binds nothing (it never evicts the contact of a registered phone)."""
    return _scenario(scenario_id, 'register', server, user, password, port, transport, ca_file, server_name,
                     contact=contact, expires=expires, unregister=unregister)


def call_scenario(scenario_id: str, server, user, password: str, to, tone: Optional[int] = None,
                  duration: float = 4.0, display: Optional[str] = None, codecs: Optional[List[str]] = None,
                  ptime: int = 20, dtmf: Optional[List[dict]] = None, voicemail: bool = False, srtp: bool = False,
                  ring_timeout: float = 8.0, port: int = 5060, transport: str = 'udp',
                  ca_file: Optional[str] = None, server_name: Optional[str] = None) -> dict:
    """A call from *user* to the number *to*, kept *duration* seconds once answered: *tone* is
    sent, *codecs* is the offer (``['PCMA', 'PCMU']`` by default; also ``GSM``, ``G722``, which
    the probe offers but cannot send), *dtmf* a list of ``{'at': seconds, 'digits': '12#'}`` sent
    as RFC 4733 events, *display* the display name of the From header.  *voicemail*: the callee
    is expected to be a voice mailbox (``#`` while the greeting plays, then *duration* seconds of
    tone once the prompts stop).  *srtp*: the offer is ``RTP/SAVP`` with a crypto line (no audio
    is sent then)."""
    return _scenario(scenario_id, 'call', server, user, password, port, transport, ca_file, server_name,
                     to=str(to), tone=tone, duration=duration, display=display, codecs=codecs, ptime=ptime,
                     dtmf=dtmf, voicemail=voicemail, srtp=srtp, ring_timeout=ring_timeout)


def _scenario(scenario_id, kind, server, user, password, port, transport, ca_file, server_name, **more) -> dict:
    scenario = {'id': scenario_id, 'kind': kind, 'server': str(server), 'port': port, 'user': str(user),
                'password': password}
    if transport != 'udp':
        scenario.update(transport=transport, ca_file=ca_file, server_name=server_name)
    scenario.update({key: value for key, value in more.items() if value not in (None, False, [])})
    return scenario


def run_spec(local_ip, tracks: List[List[dict]], listen: Iterable[int] = TONES, deadline: int = 40) -> dict:
    """Scenarios to run from the machine of address *local_ip*: the *tracks* in parallel, the
    scenarios of a track one after the other; everything is cut after *deadline* seconds."""
    return {'local_ip': str(local_ip), 'listen': list(listen), 'deadline': deadline,
            'tracks': [list(track) for track in tracks]}


def sip_run_cmd(spec: dict) -> str:
    return f"python3 {PROBE_PATH} run {encode_spec(spec)} 2>&1"


# ---------------------------------------------------------------------------
# the probe: state side
# ---------------------------------------------------------------------------

def install_sip_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy ``lib/sip_probe.py`` to *machine*."""
    script = Path(__file__).with_name('sip_probe.py').read_text()
    net_scheme.file(machine, PROBE_PATH, script, permissions=0o755, step=step)


def start_sip_daemon(net_scheme: NetScheme0, machine: str, spec: dict, step: int = 1) -> None:
    """Install the probe on *machine* and start the phones of *spec* (:func:`daemon_spec`)."""
    install_sip_probe(net_scheme, machine, step=step)
    net_scheme.cmd(machine, sip_daemon_cmd(spec), step=step)


# ---------------------------------------------------------------------------
# the probe: results
# ---------------------------------------------------------------------------

def _hosts(sources: Dict[str, int]) -> Set[str]:
    return {source.rsplit(':', 1)[0] for source in sources or {}}


@dataclass
class ScenarioResult:
    """One scenario of a probe run.  ``ran`` is false for the placeholder of a registration pass
    and for a scenario the run does not report: every other field is then empty."""
    ran: bool = False
    status: Optional[int] = None    #: final SIP status (None: no final answer)
    error: Optional[str] = None
    answered: bool = False
    challenged: bool = False        #: a 401 / 407 was answered with credentials
    cancelled: bool = False
    pound: bool = False             #: voicemail scenario: '#' was sent during the greeting
    provisional: List[int] = field(default_factory=list)
    sdp: Dict[str, Any] = field(default_factory=dict)       #: the answer: address, port, profile, payloads, crypto
    rtp: Dict[str, Any] = field(default_factory=dict)       #: sent, received, sources, tail_sources, tos, heard...
    reinvites: List[dict] = field(default_factory=list)     #: media redirections asked by the other side
    tls: Optional[dict] = None      #: {'verified', 'version', 'error'} of a TLS scenario
    expires: Optional[int] = None   #: granted by a REGISTER
    realm: str = ''
    bye: Optional[str] = None       #: 'sent' | 'received'
    t_start: float = 0.0
    t_answer: Optional[float] = None
    t_end: float = 0.0

    @property
    def heard(self) -> List[int]:
        """Tones (Hz) recognised in the received audio."""
        return [int(freq) for freq in self.rtp.get('heard', [])]

    def hears(self, tone) -> bool:
        return tone is not None and int(tone) in self.heard

    @property
    def received(self) -> int:
        return int(self.rtp.get('received') or 0)

    def source_hosts(self, tail: bool = False) -> Set[str]:
        """Addresses the RTP came from (*tail*: during the last two seconds only)."""
        return _hosts(self.rtp.get('tail_sources' if tail else 'sources'))

    @property
    def tos_values(self) -> Set[int]:
        """TOS bytes of the received RTP packets."""
        return {int(tos) for tos in self.rtp.get('tos', {})}

    @property
    def payloads(self) -> List[int]:
        return list(self.sdp.get('payloads') or [])

    @property
    def media_port(self) -> Optional[int]:
        return self.sdp.get('port')

    @property
    def refused(self) -> bool:
        """A final negative answer came (the scenario ran and the call was not set up)."""
        return self.ran and self.status is not None and self.status >= 300

    @property
    def tls_verified(self) -> bool:
        return bool(self.tls and self.tls.get('verified'))


class ProbeRun(dict):
    """``{scenario id: ScenarioResult}``; an absent scenario reads as one that did not run."""

    def __init__(self, results=(), errors=()):
        super().__init__(results)
        self.errors = list(errors)

    def __missing__(self, key):
        return ScenarioResult()


def _last_json(output: str) -> Optional[dict]:
    """The last line of *output* that is a JSON object (text of stderr may precede it)."""
    for line in reversed((output or '').splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                document = json.loads(line)
            except ValueError:
                continue
            if isinstance(document, dict):
                return document
    return None


def parse_probe_run(output: str) -> ProbeRun:
    """Results of ``sip_probe.py run``; empty for anything else (a placeholder, a crash)."""
    document = _last_json(output)
    if document is None or not isinstance(document.get('results'), dict):
        return ProbeRun()
    known = set(ScenarioResult.__dataclass_fields__)
    run = ProbeRun(errors=document.get('errors') or [])
    for name, record in document['results'].items():
        if isinstance(record, dict):
            fields = {key: value for key, value in record.items() if key in known and value is not None}
            run[name] = ScenarioResult(**{**fields, 'ran': True})
    return run


def sip_probe(grade: Grade0, machine: str, spec: dict, step: int = 1, timeout: int = 60) -> ProbeRun:
    """Run the scenarios of *spec* (:func:`run_spec`) on *machine*.  *spec* must be built from
    lab data only, so that the command is the same on every grade pass."""
    output, _ = grade.test(machine, sip_run_cmd(spec), step=step, timeout=timeout, allow_error=True)
    return parse_probe_run(output)


@dataclass
class DaemonStatus:
    """Answer of ``sip_probe.py kick``: the registration of each phone of a daemon."""
    ran: bool = False
    alive: bool = False
    kicked: float = 0.0     #: time of the request
    phones: Dict[str, dict] = field(default_factory=dict)

    def registered(self, user) -> bool:
        """*user* is registered, and it registered again after the request."""
        phone = self.phones.get(str(user)) or {}
        return bool(phone.get('registered')) and float(phone.get('t') or 0) >= self.kicked

    def status(self, user) -> Optional[int]:
        return (self.phones.get(str(user)) or {}).get('status')


def parse_kick(output: str) -> DaemonStatus:
    document = _last_json(output)
    if document is None or 'alive' not in document:
        return DaemonStatus()
    phones = document.get('phones')
    return DaemonStatus(ran=True, alive=bool(document.get('alive')), kicked=float(document.get('kicked') or 0),
                        phones=phones if isinstance(phones, dict) else {})


def sip_kick(grade: Grade0, machine: str, spec: dict, step: int = 1, timeout: int = 30) -> DaemonStatus:
    """Start the phones of *spec* if they are not running, make them register now and return
    their status: an evaluation never waits for the retry period of a refused phone."""
    command = f"{sip_daemon_cmd(spec, ensure=True)}; {sip_kick_cmd()}"
    output, _ = grade.test(machine, command, step=step, timeout=timeout, allow_error=True)
    return parse_kick(output)


@dataclass
class PhoneCall:
    """A call received by a phone of a daemon (one line of its log)."""
    t: float = 0.0              #: when the line was written: the end of an answered call
    user: str = ''              #: the phone
    action: str = ''            #: answered | busy | refused | cancelled
    from_user: str = ''
    from_display: str = ''
    to_user: str = ''
    source: str = ''            #: where the INVITE came from
    duration: float = 0.0
    rtp: Dict[str, Any] = field(default_factory=dict)
    reinvites: List[dict] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def heard(self) -> List[int]:
        return [int(freq) for freq in self.rtp.get('heard', [])]

    def hears(self, tone) -> bool:
        return tone is not None and int(tone) in self.heard

    @property
    def digits(self) -> str:
        return str(self.rtp.get('digits') or '')

    def source_hosts(self, tail: bool = False) -> Set[str]:
        return _hosts(self.rtp.get('tail_sources' if tail else 'sources'))

    @property
    def tos_values(self) -> Set[int]:
        return {int(tos) for tos in self.rtp.get('tos', {})}


def parse_daemon_log(output: str) -> List[PhoneCall]:
    """The incoming calls of a daemon log (JSON lines; the other events are skipped)."""
    known = set(PhoneCall.__dataclass_fields__)
    calls = []
    for line in (output or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get('event') == 'call' and entry.get('direction') == 'in':
            calls.append(PhoneCall(**{key: value for key, value in entry.items() if key in known and value is not None}))
    return calls


def daemon_log_cmd(lines: int = 400, wait: int = 2) -> str:
    """The last *lines* of the phones' log, after *wait* seconds: a phone writes the line of a call
    once the call is over, a moment after the caller's hang-up, so the log of the step that follows
    a call would miss it."""
    pause = f"sleep {int(wait)}; " if wait else ""
    return f'{pause}tail -n {int(lines)} {PROBE_LOG} 2>/dev/null; echo "{END_MARK}"'


def get_phone_calls(grade: Grade0, machine: str, step: int = 1, lines: int = 400, wait: int = 2) -> List[PhoneCall]:
    """The last calls received by the phones of *machine* (see :func:`daemon_log_cmd`)."""
    output, _ = grade.test(machine, daemon_log_cmd(lines, wait), step=step, allow_error=True)
    return parse_daemon_log(output)


def find_calls(calls: List[PhoneCall], user=None, action: Optional[str] = None, heard: Optional[int] = None,
               from_user=None, since: Optional[float] = None, until: Optional[float] = None) -> List[PhoneCall]:
    """Calls of *calls* received by the phone *user*, with that *action*, in which the tone
    *heard* was recognised, coming from *from_user*, logged between *since* and *until*."""
    return [call for call in calls
            if (user is None or call.user == str(user))
            and (action is None or call.action == action)
            and (heard is None or call.hears(heard))
            and (from_user is None or call.from_user == str(from_user))
            and (since is None or call.t >= since)
            and (until is None or call.t <= until)]


# ---------------------------------------------------------------------------
# Asterisk: command lines
# ---------------------------------------------------------------------------

def asterisk_start_cmd() -> str:
    """(Re)start Asterisk on a machine without systemd and wait until it is fully booted (the
    daemon goes to the background by itself; its control socket appears a moment later)."""
    return (f"sh -c 'asterisk -rx \"core stop now\" >/dev/null 2>&1; pkill -x asterisk; sleep 1; rm -f {ASTERISK_CTL};"
            f" asterisk; for i in $(seq 100); do [ -S {ASTERISK_CTL} ] && break; sleep 0.1; done;"
            " asterisk -rx \"core waitfullybooted\" >/dev/null 2>&1'")


def asterisk_rx_cmd(command: str) -> str:
    """One console command (``asterisk -rx``); the marker tells that it ran and whether the
    console could be reached (exit status 1 when Asterisk is not running)."""
    return f'asterisk -rx {shlex.quote(command)} 2>&1; echo "{RC_MARK} $?"'


_RC_RE = re.compile(r"^===RC (\d+)\s*$", re.M)


def console_output(output: str) -> str:
    """Text printed by a command of :func:`asterisk_rx_cmd`; '' when it did not run or could not
    reach Asterisk."""
    match = _RC_RE.search(output or '')
    if match is None or int(match.group(1)) != 0:
        return ''
    return output[:match.start()]


def asterisk_rx(grade: Grade0, machine: str, command: str, step: int = 1, timeout: int = 20) -> str:
    output, _ = grade.test(machine, asterisk_rx_cmd(command), step=step, timeout=timeout, allow_error=True)
    return console_output(output)


def voicemail_dump_cmd(mailbox) -> str:
    """Print the information file of every message of *mailbox* (whatever its voicemail context)."""
    pattern = f"{VOICEMAIL_SPOOL}/*/{mailbox}/INBOX/msg*.txt"
    return (f"sh -c 'for f in {pattern}; do [ -f \"$f\" ] && echo \"{MSG_MARK} $f\" && cat \"$f\"; done;"
            f" echo \"{END_MARK}\"'")


def voicemail_cleanup_cmd(mailbox, caller) -> str:
    """Remove from *mailbox* the messages left by the number *caller* (their information and
    audio files), nothing else."""
    pattern = f"{VOICEMAIL_SPOOL}/*/{mailbox}/INBOX/msg*.txt"
    # callerid="Name" <1003> or, for a caller without a name, callerid=1003
    return (f"sh -c 'for f in {pattern}; do [ -f \"$f\" ] && grep -Eq \"^callerid=(.*<)?{caller}>?\\$\" \"$f\""
            " && rm -f \"${f%.txt}\".*; done; true'")


# ---------------------------------------------------------------------------
# Asterisk: parsers
# ---------------------------------------------------------------------------

_PARAMETER_RE = re.compile(r"^ (\w+)\s*: ?(.*?)\s*$")
_TRUE = ('true', 'yes', 'on', '1')


def parse_parameters(text: str) -> Dict[str, str]:
    """The ``ParameterName : ParameterValue`` table of ``pjsip show endpoint|aor|auth NAME``; {}
    when the object does not exist."""
    parameters = {}
    in_table = False
    for line in (text or '').splitlines():
        if line.strip().startswith('ParameterName'):
            in_table = True
            continue
        match = _PARAMETER_RE.match(line) if in_table else None
        if match:
            parameters[match.group(1)] = match.group(2)
    return parameters


def flag(parameters: Dict[str, str], name: str) -> bool:
    """Boolean option of a parameter table (printed ``true`` / ``false``, sometimes ``yes`` / ``no``)."""
    return parameters.get(name, '').strip().lower() in _TRUE


def codec_list(parameters: Dict[str, str]) -> List[str]:
    """Codecs of the ``allow`` option, printed ``(alaw|ulaw)``."""
    return [codec for codec in parameters.get('allow', '').strip('() ').split('|') if codec]


@dataclass
class Contact:
    aor: str = ''
    uri: str = ''
    user: str = ''
    host: str = ''
    port: Optional[int] = None
    status: str = ''


_CONTACT_RE = re.compile(r"^\s*Contact:\s+([^/\s<]+)/(sips?:\S+)\s+(\S+)\s+(\S+)")
_CONTACT_URI_RE = re.compile(r"^sips?:(?:([^@;]*)@)?([^:;>]+)(?::(\d+))?")


def parse_contacts(text: str) -> List[Contact]:
    """Lines of ``pjsip show contacts`` (also the Contact lines of ``pjsip show endpoint``)."""
    contacts = []
    for line in (text or '').splitlines():
        match = _CONTACT_RE.match(line)
        if not match:
            continue
        uri = _CONTACT_URI_RE.match(match.group(2))
        contacts.append(Contact(aor=match.group(1), uri=match.group(2), status=match.group(4),
                                user=(uri.group(1) or '') if uri else '', host=uri.group(2) if uri else '',
                                port=int(uri.group(3)) if uri and uri.group(3) else None))
    return contacts


def contacts_of(contacts: List[Contact], aor) -> List[Contact]:
    return [contact for contact in contacts if contact.aor == str(aor)]


_TRANSPORT_RE = re.compile(r"^\s*Transport:\s+(\S+)\s+(\w+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$")


def parse_transports(text: str) -> List[Dict[str, Any]]:
    """``pjsip show transports``: ``[{'id', 'type', 'cos', 'tos', 'bind'}]``."""
    return [{'id': m.group(1), 'type': m.group(2), 'cos': int(m.group(3)), 'tos': int(m.group(4)), 'bind': m.group(5)}
            for m in (_TRANSPORT_RE.match(line) for line in (text or '').splitlines()) if m]


def parse_identifies(text: str) -> List[Dict[str, Any]]:
    """``pjsip show identifies``: ``[{'name', 'endpoint', 'matches': ['10.0.0.1/32']}]``."""
    identifies = []
    for line in (text or '').splitlines():
        head = re.match(r"^\s*Identify:\s+([^/\s<]+)/(\S+)\s*$", line)
        match = re.match(r"^\s*Match:\s+(\S+)\s*$", line)
        if head:
            identifies.append({'name': head.group(1), 'endpoint': head.group(2), 'matches': []})
        elif match and identifies and not match.group(1).startswith('<'):
            identifies[-1]['matches'].append(match.group(1))
    return identifies


def parse_rtp_settings(text: str) -> Dict[str, int]:
    """``rtp show settings``: ``{'port_start', 'port_end'}`` ({} when absent)."""
    settings = {}
    for key, label in (('port_start', 'Port start'), ('port_end', 'Port end')):
        match = re.search(rf"^\s*{label}:\s*(\d+)", text or '', re.M)
        if match:
            settings[key] = int(match.group(1))
    return settings


@dataclass
class DialplanStep:
    priority: int
    application: str
    arguments: str = ''
    label: str = ''


_EXTEN_RE = re.compile(r"^\s*'([^']+)'\s*=>\s*(.*)$")
_STEP_RE = re.compile(r"^\s*(?:\[(\w+)\]\s*)?(\d+)\.\s*(\w+)\((.*)\)\s*(?:\[[^\]]*\])?\s*$")


def parse_dialplan(text: str) -> Dict[str, List[DialplanStep]]:
    """``dialplan show CONTEXT``: ``{extension: [steps]}`` in the order of the priorities
    ({} for a context that does not exist)."""
    dialplan: Dict[str, List[DialplanStep]] = {}
    current = None
    for line in (text or '').splitlines():
        exten = _EXTEN_RE.match(line)
        if exten:
            current = dialplan.setdefault(exten.group(1), [])
            line = exten.group(2)
        step = _STEP_RE.match(line)
        if step and current is not None:
            current.append(DialplanStep(priority=int(step.group(2)), application=step.group(3),
                                        arguments=step.group(4), label=step.group(1) or ''))
    return dialplan


def dialplan_applications(dialplan: Dict[str, List[DialplanStep]], extension: str) -> List[str]:
    """Names of the applications of *extension*, lower-cased, in order."""
    return [step.application.lower() for step in dialplan.get(str(extension), [])]


@dataclass
class VoiceMessage:
    file: str = ''
    mailbox: str = ''
    callerid: str = ''
    caller: str = ''        #: the number of the caller ID (between <> when it has a name)
    origtime: int = 0
    duration: int = 0


def parse_voicemail_messages(text: str) -> List[VoiceMessage]:
    """Output of :func:`voicemail_dump_cmd`."""
    messages = []
    for block in (text or '').split(MSG_MARK)[1:]:
        lines = block.splitlines()
        values = dict(line.split('=', 1) for line in lines[1:] if '=' in line and not line.startswith(';'))
        callerid = values.get('callerid', '')
        caller = re.search(r"<([^>]*)>", callerid)  # "Name" <1003>, or 1003 alone without a name
        messages.append(VoiceMessage(
            file=lines[0].strip() if lines else '', mailbox=values.get('origmailbox', ''),
            callerid=callerid, caller=caller.group(1) if caller else callerid.strip().strip('"'),
            origtime=int(values['origtime']) if values.get('origtime', '').isdigit() else 0,
            duration=int(values['duration']) if values.get('duration', '').isdigit() else 0))
    return messages


# ---------------------------------------------------------------------------
# Asterisk: grade-side wrappers
# ---------------------------------------------------------------------------

def get_endpoint(grade: Grade0, machine: str, name, step: int = 1) -> Dict[str, str]:
    """Options of the endpoint *name* ({} when it does not exist or Asterisk is down)."""
    return parse_parameters(asterisk_rx(grade, machine, f"pjsip show endpoint {name}", step=step))


def get_aor(grade: Grade0, machine: str, name, step: int = 1) -> Dict[str, str]:
    return parse_parameters(asterisk_rx(grade, machine, f"pjsip show aor {name}", step=step))


def get_contacts(grade: Grade0, machine: str, step: int = 1) -> List[Contact]:
    return parse_contacts(asterisk_rx(grade, machine, "pjsip show contacts", step=step))


def get_transports(grade: Grade0, machine: str, step: int = 1) -> List[Dict[str, Any]]:
    return parse_transports(asterisk_rx(grade, machine, "pjsip show transports", step=step))


def get_identifies(grade: Grade0, machine: str, step: int = 1) -> List[Dict[str, Any]]:
    return parse_identifies(asterisk_rx(grade, machine, "pjsip show identifies", step=step))


def get_rtp_settings(grade: Grade0, machine: str, step: int = 1) -> Dict[str, int]:
    return parse_rtp_settings(asterisk_rx(grade, machine, "rtp show settings", step=step))


def get_dialplan(grade: Grade0, machine: str, context: str, step: int = 1) -> Dict[str, List[DialplanStep]]:
    return parse_dialplan(asterisk_rx(grade, machine, f"dialplan show {context}", step=step))


def get_voicemail_messages(grade: Grade0, machine: str, mailbox, step: int = 1) -> List[VoiceMessage]:
    output, _ = grade.test(machine, voicemail_dump_cmd(mailbox), step=step, allow_error=True)
    return parse_voicemail_messages(output)


# ---------------------------------------------------------------------------
# baresip
# ---------------------------------------------------------------------------

def render_baresip_config(tone: int = 440, recordings: str = '/root/recordings', ca_file: Optional[str] = None,
                          srtp: bool = False) -> str:
    """``~/.baresip/config`` of a softphone without sound card: the microphone is a sine of
    *tone* Hz, the audio received is recorded (wav files in *recordings*) instead of being
    played.  *ca_file*: the authorities trusted for SIP over TLS; *srtp* loads the SRTP module."""
    lines = [
        "# baresip without a sound card: the microphone is a sine generator, what is received is",
        "# not played but recorded (wav files in snd_path, one pair per call: -enc = sent, -dec = received).",
        "",
        "poll_method\t\tepoll",
        "call_local_timeout\t120",
        "call_max_calls\t\t4",
    ]
    if ca_file:
        lines.append(f"sip_cafile\t\t{ca_file}")
    lines += [
        "",
        "audio_player\t\tnone",
        f"audio_source\t\tausine,{int(tone)}",
        "audio_alert\t\tnone",
        "ausrc_srate\t\t48000",
        "ausrc_channels\t\t2",
        "audio_level\t\tno",
        "",
        "rtp_tos\t\t\t184",
        "rtp_stats\t\tyes",
        "",
        "module_path\t\t/usr/lib/baresip/modules",
        "module\t\t\tstdio.so",
        "module\t\t\tg711.so",
        "module\t\t\tausine.so",
        "module\t\t\tsndfile.so",
    ]
    if srtp:
        lines.append("module\t\t\tsrtp.so")
    lines += [
        "module_tmp\t\tuuid.so",
        "module_tmp\t\taccount.so",
        "module_app\t\tcontact.so",
        "module_app\t\tdebug_cmd.so",
        "module_app\t\tmenu.so",
        "",
        f"snd_path\t\t{recordings}",
    ]
    return "\n".join(lines) + "\n"


def render_baresip_account(user, server, password: str, regint: int = 120, transport: Optional[str] = None,
                           mediaenc: Optional[str] = None) -> str:
    """One line of ``~/.baresip/accounts``."""
    uri = f"sip:{user}@{server}" + (f";transport={transport}" if transport else "")
    line = f"<{uri}>;auth_pass={password};regint={int(regint)}"
    if mediaenc:
        line += f";mediaenc={mediaenc}"
    return line + "\n"


def baresip_start_cmd(directory: str = BARESIP_DIR) -> str:
    """(Re)start baresip in the background with the configuration of *directory* (the state
    commands have no ``$HOME``)."""
    return (f"sh -c 'pkill -x baresip; sleep 0.3; cd /root && env -i HOME=/root /usr/bin/baresip -f {directory} -d"
            " >/dev/null 2>&1; true'")
