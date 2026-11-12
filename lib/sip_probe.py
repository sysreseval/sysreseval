#!/usr/bin/env python3
# SIP user agent of the VoIP labs (standard library only), run inside the lab containers by
# lib/voip.py: the hidden phones of the lab and the calls of the grader.
#
# usage:
#   sre_sip_probe.py daemon SPEC          start the persistent phones (goes to the background)
#   sre_sip_probe.py ensure SPEC          the same, unless they are already running
#   sre_sip_probe.py kick [STATUS [PID]]  make the phones register now, print their status (JSON)
#   sre_sip_probe.py run SPEC             run caller scenarios, print one JSON document
#
# SPEC is the urlsafe base64 of a JSON document.
#
#   daemon: {"local_ip", "log", "pid", "status", "listen": [Hz, ...],
#            "accounts": [{"user", "password", "server", "port", "sip_port", "rtp_port",
#                          "mode": "answer" | "busy" | "none", "tone": Hz, "display", "user_agent",
#                          "expires", "refresh", "retry", "codecs": ["PCMA", "PCMU"], "max_call",
#                          "calls": {"number", "every", "duration", "codec", "ptime"} | null}]}
#       One phone per account: it registers (again every "refresh" seconds, every "retry"
#       seconds while refused), answers the incoming calls ("answer": 180 then 200, its tone
#       sent, what it hears analysed; "busy": 486) and, with "calls", calls a number
#       periodically.  One JSON line per event is appended to "log".
#
#   run:    {"local_ip", "deadline", "listen": [Hz, ...], "tracks": [[scenario, ...], ...]}
#       The tracks run in parallel, the scenarios of a track one after the other:
#         {"id", "kind": "register", "server", "port", "user", "password", "contact": bool,
#          "expires", "unregister": bool, "transport": "udp" | "tls", "ca_file", "server_name"}
#         {"id", "kind": "call", "server", "port", "user", "password", "display", "to", "tone",
#          "duration", "codecs": [...], "ptime", "dtmf": [{"at": s, "digits": "12#"}],
#          "voicemail": bool, "srtp": bool, "ring_timeout", "transport", "ca_file", "server_name"}
#         {"id", "kind": "sleep", "seconds"}
#       Output: {"errors": [...], "results": {id: {...}}}; exit status 0 whatever happened.
#
# Audio is G.711 (A-law, mu-law) at 8 kHz.  A phone sends a sine tone and recognises the tones
# it receives among the "listen" frequencies (Goertzel on windows of 0.25 s: use multiples of
# 4 Hz), so a call tells who answered and whether the media flows, without any sound device.

import base64
import collections
import hashlib
import json
import math
import os
import queue
import random
import re
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time

SAMPLE_RATE = 8000
PAYLOAD_TYPES = {'PCMU': 0, 'GSM': 3, 'PCMA': 8, 'G722': 9}
TELEPHONE_EVENT = 101
DTMF_EVENTS = {**{str(d): d for d in range(10)}, '*': 10, '#': 11, 'A': 12, 'B': 13, 'C': 14, 'D': 15}
DTMF_DIGITS = {code: digit for digit, code in DTMF_EVENTS.items()}
USER_AGENT = 'sre-sip-probe'
ALLOW = 'INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, UPDATE, INFO'


# ---------------------------------------------------------------------------
# G.711
# ---------------------------------------------------------------------------

_SEG_AEND = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)
_SEG_UEND = (0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF)


def _segment(value, table):
    for index, end in enumerate(table):
        if value <= end:
            return index
    return len(table)


def lin2alaw(sample):
    """A-law byte of a 16-bit linear sample."""
    value = sample >> 3
    if value >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        value = -value - 1
    seg = _segment(value, _SEG_AEND)
    if seg >= 8:
        return 0x7F ^ mask
    code = seg << 4
    code |= (value >> 1) & 0x0F if seg < 2 else (value >> seg) & 0x0F
    return code ^ mask


def alaw2lin(code):
    code ^= 0x55
    value = (code & 0x0F) << 4
    seg = (code & 0x70) >> 4
    if seg == 0:
        value += 8
    elif seg == 1:
        value += 0x108
    else:
        value = (value + 0x108) << (seg - 1)
    return value if code & 0x80 else -value


def lin2ulaw(sample):
    """mu-law byte of a 16-bit linear sample."""
    value = sample >> 2
    if value < 0:
        value = -value
        mask = 0x7F
    else:
        mask = 0xFF
    value = min(value, 8159) + 33
    seg = _segment(value, _SEG_UEND)
    if seg >= 8:
        return 0x7F ^ mask
    return ((seg << 4) | ((value >> (seg + 1)) & 0x0F)) ^ mask


def ulaw2lin(code):
    code = ~code & 0xFF
    value = (((code & 0x0F) << 3) + 0x84) << ((code & 0x70) >> 4)
    return 0x84 - value if code & 0x80 else value - 0x84


ALAW_DECODE = tuple(alaw2lin(code) for code in range(256))
ULAW_DECODE = tuple(ulaw2lin(code) for code in range(256))
DECODERS = {PAYLOAD_TYPES['PCMA']: ALAW_DECODE, PAYLOAD_TYPES['PCMU']: ULAW_DECODE}
ENCODERS = {'PCMA': lin2alaw, 'PCMU': lin2ulaw}


# ---------------------------------------------------------------------------
# tones
# ---------------------------------------------------------------------------

class Tone:
    """Endless sine of *freq* Hz encoded in *codec*, cut in packets of *ptime* ms.  A frequency
    that is a multiple of 4 Hz has a whole number of periods in the 2000-sample ring."""

    RING = 2000

    def __init__(self, freq, codec='PCMA', ptime=20, amplitude=8000):
        encode = ENCODERS[codec]
        step = 2 * math.pi * freq / SAMPLE_RATE
        self.ring = bytes(encode(int(amplitude * math.sin(step * n))) for n in range(self.RING))
        self.samples = SAMPLE_RATE * ptime // 1000
        self.position = 0

    def next_payload(self):
        start = self.position
        end = start + self.samples
        self.position = end % self.RING
        if end <= self.RING:
            return self.ring[start:end]
        return self.ring[start:] + self.ring[:end - self.RING]


def goertzel_power(samples, freq, rate=SAMPLE_RATE):
    """Power of *samples* at *freq*: (N * A / 2) ** 2 for a sine of amplitude A on a bin centre."""
    coeff = 2 * math.cos(2 * math.pi * freq / rate)
    s1 = s2 = 0.0
    for x in samples:
        s1, s2 = x + coeff * s1 - s2, s1
    return s1 * s1 + s2 * s2 - coeff * s1 * s2


class ToneDetector:
    """Counts, among windows of 0.25 s, those dominated by each of the *freqs*."""

    WINDOW = 2000
    SILENCE = 60.0 ** 2  # mean square below which a window is silence
    DOMINANT = 0.5       # share of the energy a frequency must hold

    def __init__(self, freqs):
        self.freqs = sorted({int(f) for f in freqs or ()})
        self.pending = []
        self.windows = 0
        self.silent = 0
        self.other = 0
        self.tones = {}

    def feed(self, samples):
        self.pending.extend(samples)
        while len(self.pending) >= self.WINDOW:
            window, self.pending = self.pending[:self.WINDOW], self.pending[self.WINDOW:]
            self._window(window)

    def _window(self, window):
        self.windows += 1
        energy = float(sum(x * x for x in window))
        if energy / len(window) < self.SILENCE:
            self.silent += 1
            return
        best, best_share = None, 0.0
        for freq in self.freqs:
            share = goertzel_power(window, freq) / (len(window) / 2 * energy)
            if share > best_share:
                best, best_share = freq, share
        if best is not None and best_share >= self.DOMINANT:
            self.tones[best] = self.tones.get(best, 0) + 1
        else:
            self.other += 1

    def result(self):
        return {'windows': self.windows, 'silent': self.silent, 'other': self.other,
                'tones': {str(freq): count for freq, count in sorted(self.tones.items())}}


# ---------------------------------------------------------------------------
# RTP
# ---------------------------------------------------------------------------

def rtp_packet(payload_type, sequence, timestamp, ssrc, payload, marker=False):
    return struct.pack('!BBHII', 0x80, (0x80 if marker else 0) | payload_type, sequence & 0xFFFF,
                       timestamp & 0xFFFFFFFF, ssrc) + payload


def parse_rtp(data):
    """(payload type, marker, sequence, timestamp, ssrc, payload) or None."""
    if len(data) < 12 or data[0] >> 6 != 2:
        return None
    first, second, sequence, timestamp, ssrc = struct.unpack('!BBHII', data[:12])
    offset = 12 + 4 * (first & 0x0F)
    if first & 0x10:  # header extension
        if len(data) < offset + 4:
            return None
        offset += 4 + 4 * struct.unpack('!H', data[offset + 2:offset + 4])[0]
    payload = data[offset:]
    if first & 0x20 and payload:  # padding
        payload = payload[:-payload[-1]]
    return second & 0x7F, bool(second & 0x80), sequence, timestamp, ssrc, payload


def dtmf_payload(event, duration, end=False, volume=10):
    """RFC 4733 telephone-event payload."""
    return struct.pack('!BBH', event, (0x80 if end else 0) | volume, min(duration, 0xFFFF))


def parse_dtmf(payload):
    """(event, end, duration) or None."""
    if len(payload) < 4:
        return None
    event, flags, duration = struct.unpack('!BBH', payload[:4])
    return event, bool(flags & 0x80), duration


# ---------------------------------------------------------------------------
# SIP messages
# ---------------------------------------------------------------------------

COMPACT = {'v': 'via', 'f': 'from', 't': 'to', 'i': 'call-id', 'm': 'contact', 'l': 'content-length',
           'c': 'content-type', 'k': 'supported', 's': 'subject', 'e': 'content-encoding'}


class SipMessage:
    """A request (method, uri) or a response (status, reason); headers as (name, value) pairs."""

    def __init__(self, method=None, uri=None, status=None, reason='', headers=None, body=''):
        self.method = method
        self.uri = uri
        self.status = status
        self.reason = reason
        self.headers = list(headers or [])
        self.body = body

    @property
    def is_request(self):
        return self.status is None

    def get_all(self, name):
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    def get(self, name, default=''):
        values = self.get_all(name)
        return values[0] if values else default

    def cseq(self):
        """(number, method) of the CSeq header."""
        parts = self.get('cseq').split()
        if len(parts) == 2 and parts[0].isdigit():
            return int(parts[0]), parts[1].upper()
        return 0, ''

    def branch(self):
        match = re.search(r';\s*branch=([^;,\s]+)', self.get('via'))
        return match.group(1) if match else ''

    def encode(self):
        if self.is_request:
            lines = [f'{self.method} {self.uri} SIP/2.0']
        else:
            lines = [f'SIP/2.0 {self.status} {self.reason}']
        body = self.body.encode()
        headers = [(k, v) for k, v in self.headers if k.lower() != 'content-length']
        headers.append(('Content-Length', str(len(body))))
        lines += [f'{name}: {value}' for name, value in headers]
        return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def parse_message(data):
    """SipMessage of *data* (bytes), None when it is not a SIP message."""
    try:
        head, _, body = data.decode('utf-8', 'replace').partition('\r\n\r\n')
        lines = head.split('\r\n')
        start = lines[0].split(' ', 2)
        headers = []
        for line in lines[1:]:
            if line[:1] in ' \t' and headers:  # folded header
                headers[-1] = (headers[-1][0], headers[-1][1] + ' ' + line.strip())
                continue
            name, sep, value = line.partition(':')
            if not sep:
                continue
            name = name.strip()
            headers.append((COMPACT.get(name.lower(), name), value.strip()))
        if start[0] == 'SIP/2.0':
            return SipMessage(status=int(start[1]), reason=start[2] if len(start) > 2 else '',
                              headers=headers, body=body)
        if len(start) == 3 and start[2] == 'SIP/2.0':
            return SipMessage(method=start[0].upper(), uri=start[1], headers=headers, body=body)
    except (ValueError, IndexError):
        pass
    return None


_NAME_ADDR_RE = re.compile(r'^\s*(?:"((?:[^"\\]|\\.)*)"|([^<"]*?))\s*<([^>]*)>(.*)$')
_URI_RE = re.compile(r'^(sips?):(?:([^@;]*)@)?(\[[^\]]+\]|[^:;?]+)(?::(\d+))?(.*)$')


def parse_name_addr(value):
    """Parts of a From / To / Contact value: display, uri, user, host, port, tag, params."""
    result = {'display': '', 'uri': '', 'user': '', 'host': '', 'port': None, 'tag': '', 'params': ''}
    match = _NAME_ADDR_RE.match(value or '')
    if match:
        result['display'] = (match.group(1) if match.group(1) is not None else match.group(2) or '').strip()
        result['uri'], result['params'] = match.group(3).strip(), match.group(4)
    else:
        uri, sep, params = (value or '').strip().partition(';')
        result['uri'], result['params'] = uri, sep + params
    uri = _URI_RE.match(result['uri'])
    if uri:
        result['user'], result['host'] = uri.group(2) or '', uri.group(3)
        result['port'] = int(uri.group(4)) if uri.group(4) else None
    tag = re.search(r';\s*tag=([^;\s]+)', result['params'])
    if tag:
        result['tag'] = tag.group(1)
    return result


def new_branch():
    return 'z9hG4bK' + os.urandom(8).hex()


def new_tag():
    return os.urandom(6).hex()


# ---------------------------------------------------------------------------
# digest authentication (RFC 2617 / 7616)
# ---------------------------------------------------------------------------

_CHALLENGE_PARAM_RE = re.compile(r'(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))')
_DIGESTS = {'MD5': hashlib.md5, 'SHA-256': hashlib.sha256}


def parse_challenge(value):
    """Parameters of a WWW-Authenticate / Proxy-Authenticate value (lower-case keys)."""
    scheme, _, rest = (value or '').strip().partition(' ')
    params = {'scheme': scheme}
    for name, quoted, token in _CHALLENGE_PARAM_RE.findall(rest):
        params[name.lower()] = quoted if quoted or not token else token
    return params


def pick_challenge(values):
    """The first Digest challenge whose algorithm is known, or None."""
    for value in values:
        challenge = parse_challenge(value)
        if challenge['scheme'].lower() == 'digest' and challenge.get('algorithm', 'MD5').upper() in _DIGESTS:
            return challenge
    return None


def digest_authorization(challenge, method, uri, user, password, cnonce=None, nc=1):
    """Value of the Authorization header answering *challenge*."""
    algorithm = challenge.get('algorithm', 'MD5').upper()
    digest = _DIGESTS[algorithm]

    def h(text):
        return digest(text.encode()).hexdigest()

    realm, nonce = challenge.get('realm', ''), challenge.get('nonce', '')
    ha1 = h(f'{user}:{realm}:{password}')
    ha2 = h(f'{method}:{uri}')
    fields = [f'username="{user}"', f'realm="{realm}"', f'nonce="{nonce}"', f'uri="{uri}"']
    qop = [q.strip() for q in challenge.get('qop', '').split(',') if q.strip()]
    if 'auth' in qop:
        cnonce = cnonce or os.urandom(8).hex()
        count = f'{nc:08x}'
        response = h(f'{ha1}:{nonce}:{count}:{cnonce}:auth:{ha2}')
        fields += [f'response="{response}"', 'qop=auth', f'nc={count}', f'cnonce="{cnonce}"']
    else:
        fields.append(f'response="{h(f"{ha1}:{nonce}:{ha2}")}"')
    fields.append(f'algorithm={algorithm}')
    if 'opaque' in challenge:
        fields.append(f'opaque="{challenge["opaque"]}"')
    return 'Digest ' + ', '.join(fields)


# ---------------------------------------------------------------------------
# SDP
# ---------------------------------------------------------------------------

_RTPMAP = {0: 'PCMU/8000', 3: 'GSM/8000', 8: 'PCMA/8000', 9: 'G722/8000'}


def build_sdp(address, port, codecs, ptime=20, srtp_key=None, session_id=None):
    """Offer or answer for one audio stream; *srtp_key* (30 bytes) makes it RTP/SAVP with SDES."""
    session_id = session_id or random.randrange(1, 2 ** 31)
    payloads = [PAYLOAD_TYPES[codec] for codec in codecs] + [TELEPHONE_EVENT]
    lines = ['v=0', f'o=- {session_id} {session_id} IN IP4 {address}', 's=sre', f'c=IN IP4 {address}', 't=0 0',
             f'm=audio {port} {"RTP/SAVP" if srtp_key else "RTP/AVP"} {" ".join(str(p) for p in payloads)}']
    lines += [f'a=rtpmap:{p} {_RTPMAP[p]}' for p in payloads[:-1]]
    lines += [f'a=rtpmap:{TELEPHONE_EVENT} telephone-event/8000', f'a=fmtp:{TELEPHONE_EVENT} 0-16',
              f'a=ptime:{ptime}', 'a=sendrecv']
    if srtp_key:
        lines.append('a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:' + base64.b64encode(srtp_key).decode())
    return '\r\n'.join(lines) + '\r\n'


def parse_sdp(body):
    """The first audio stream of *body*: address, port, profile, payloads, codecs, ptime, crypto,
    telephone_event (its payload type); {} without one."""
    session_address = address = ''
    media = None
    for line in (body or '').replace('\r', '').split('\n'):
        kind, _, value = line.partition('=')
        if kind == 'c':
            parts = value.split()
            if len(parts) == 3:
                if media is None:
                    session_address = parts[2]
                else:
                    address = address or parts[2]
        elif kind == 'm':
            if media is not None:
                break
            parts = value.split()
            if len(parts) >= 4 and parts[0] == 'audio' and parts[1].isdigit():
                media = {'port': int(parts[1]), 'profile': parts[2],
                         'payloads': [int(p) for p in parts[3:] if p.isdigit()],
                         'codecs': {}, 'ptime': None, 'crypto': [], 'telephone_event': None}
        elif kind == 'a' and media is not None:
            name, _, arg = value.partition(':')
            if name == 'rtpmap':
                number, _, encoding = arg.partition(' ')
                if number.isdigit():
                    media['codecs'][int(number)] = encoding.strip()
                    if encoding.lower().startswith('telephone-event'):
                        media['telephone_event'] = int(number)
            elif name == 'ptime' and arg.strip().isdigit():
                media['ptime'] = int(arg)
            elif name == 'crypto':
                media['crypto'].append(arg.strip())
    if media is None:
        return {}
    media['address'] = address or session_address
    for payload in media['payloads']:
        media['codecs'].setdefault(payload, _RTPMAP.get(payload, ''))
    media['codecs'] = {str(k): v for k, v in media['codecs'].items()}
    return media


def pick_codec(sdp, accepted=('PCMA', 'PCMU')):
    """Name of the first payload of *sdp* this phone can send, or None."""
    names = {number: name for name, number in PAYLOAD_TYPES.items()}
    for payload in sdp.get('payloads', []):
        if names.get(payload) in accepted:
            return names[payload]
    return None


# ---------------------------------------------------------------------------
# one audio stream
# ---------------------------------------------------------------------------

_IP_RECVTOS = getattr(socket, 'IP_RECVTOS', 13)
_TOS_CMSG_TYPES = (socket.IP_TOS, _IP_RECVTOS)


class RtpSession:
    """The audio stream of a call: sends a tone (and RFC 4733 digits) every *ptime* ms, counts and
    analyses what arrives (sources, payload types, TOS byte, tones, digits)."""

    MAX_ARRIVALS = 20000
    DIGIT_PACKETS = 8  # 160 ms at 20 ms

    def __init__(self, local_ip, port=0, listen=()):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local_ip, port))
        self.sock.settimeout(0.2)
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, _IP_RECVTOS, 1)
        except OSError:
            pass
        self.port = self.sock.getsockname()[1]
        self.detector = ToneDetector(listen)
        self.sent = 0
        self.received = 0
        self.sources = {}
        self.payload_types = {}
        self.sizes = {}
        self.tos = {}
        self.digits = ''
        self.arrivals = collections.deque(maxlen=self.MAX_ARRIVALS)  # (monotonic time, source)
        self.last_arrival = None
        self.remote = None
        self.telephone_event = TELEPHONE_EVENT
        self._last_event = None
        self._tone = None
        self._payload_type = PAYLOAD_TYPES['PCMA']
        self._ptime = 20
        self._digits = collections.deque()
        self._stop = threading.Event()
        self._threads = []

    def start(self, remote, codec='PCMA', tone=None, ptime=20, telephone_event=None, send=True):
        """Start receiving, and sending to *remote* = (address, port) unless *send* is false."""
        self.remote = remote
        self._ptime = ptime
        self._payload_type = PAYLOAD_TYPES[codec]
        self._tone = Tone(tone, codec, ptime) if tone else None
        self._silence = bytes([ENCODERS[codec](0)]) * (SAMPLE_RATE * ptime // 1000)
        if telephone_event:
            self.telephone_event = telephone_event
        targets = [self._receive_loop] + ([self._send_loop] if send else [])
        self._threads = [threading.Thread(target=target, daemon=True) for target in targets]
        for thread in self._threads:
            thread.start()

    def set_remote(self, remote):
        self.remote = remote

    def send_digits(self, digits):
        self._digits.extend(d for d in digits.upper() if d in DTMF_EVENTS)

    def idle(self):
        """Seconds since the last packet arrived (None when none did)."""
        return None if self.last_arrival is None else time.monotonic() - self.last_arrival

    def stop(self):
        self._stop.set()
        for thread in self._threads:
            thread.join(1)
        try:
            self.sock.close()
        except OSError:
            pass

    # -- sending

    def _send(self, packet):
        try:
            self.sock.sendto(packet, self.remote)
            self.sent += 1
        except OSError:
            pass

    def _send_loop(self):
        interval = self._ptime / 1000.0
        samples = SAMPLE_RATE * self._ptime // 1000
        sequence, timestamp, ssrc = random.randrange(1 << 16), random.randrange(1 << 31), random.randrange(1, 1 << 32)
        marker = True
        gap = 0  # audio packets left before the next digit
        deadline = time.monotonic()

        def pace():
            nonlocal deadline
            deadline += interval
            delay = deadline - time.monotonic()
            if delay > 0:
                self._stop.wait(delay)
            elif delay < -1:
                deadline = time.monotonic()

        while not self._stop.is_set():
            if self._digits and gap <= 0:
                event, duration = DTMF_EVENTS[self._digits.popleft()], 0
                for index in range(self.DIGIT_PACKETS):
                    duration += samples
                    self._send(rtp_packet(self.telephone_event, sequence, timestamp, ssrc,
                                          dtmf_payload(event, duration), marker=index == 0))
                    sequence += 1
                    pace()
                for _ in range(3):  # the end of the event, sent three times (RFC 4733)
                    self._send(rtp_packet(self.telephone_event, sequence, timestamp, ssrc,
                                          dtmf_payload(event, duration, end=True)))
                    sequence += 1
                timestamp += duration
                gap = 6
                continue
            payload = self._tone.next_payload() if self._tone else self._silence
            self._send(rtp_packet(self._payload_type, sequence, timestamp, ssrc, payload, marker))
            marker = False
            sequence += 1
            timestamp += samples
            gap -= 1
            pace()

    # -- receiving

    def _receive_loop(self):
        while not self._stop.is_set():
            try:
                data, ancillary, _flags, source = self.sock.recvmsg(4096, 128)
            except socket.timeout:
                continue
            except OSError:
                return
            packet = parse_rtp(data)
            if packet is None:
                continue
            payload_type, _marker, _sequence, timestamp, _ssrc, payload = packet
            now = time.monotonic()
            where = f'{source[0]}:{source[1]}'
            self.received += 1
            self.last_arrival = now
            self.arrivals.append((now, where))
            self.sources[where] = self.sources.get(where, 0) + 1
            self.payload_types[payload_type] = self.payload_types.get(payload_type, 0) + 1
            self.sizes[len(payload)] = self.sizes.get(len(payload), 0) + 1
            for level, kind, value in ancillary:
                if level == socket.IPPROTO_IP and kind in _TOS_CMSG_TYPES and value:
                    self.tos[value[0]] = self.tos.get(value[0], 0) + 1
            table = DECODERS.get(payload_type)
            if table is not None:
                self.detector.feed([table[byte] for byte in payload])
            elif payload_type == self.telephone_event:
                event = parse_dtmf(payload)
                if event and timestamp != self._last_event:
                    self._last_event = timestamp
                    self.digits += DTMF_DIGITS.get(event[0], '?')

    def stats(self, tail=2.0):
        """What was sent and received; ``tail_sources`` only counts the last *tail* seconds."""
        tail_sources = {}
        if self.arrivals:
            limit = self.arrivals[-1][0] - tail
            for when, where in self.arrivals:
                if when >= limit:
                    tail_sources[where] = tail_sources.get(where, 0) + 1
        tones = self.detector.result()
        return {'sent': self.sent, 'received': self.received, 'sources': dict(self.sources),
                'tail_sources': tail_sources,
                'payload_types': {str(k): v for k, v in sorted(self.payload_types.items())},
                'sizes': {str(k): v for k, v in sorted(self.sizes.items())},
                'tos': {str(k): v for k, v in sorted(self.tos.items())},
                'digits': self.digits, 'tones': tones,
                'heard': [int(freq) for freq, count in tones['tones'].items() if count >= 2]}


# ---------------------------------------------------------------------------
# SIP transports
# ---------------------------------------------------------------------------

class UdpTransport:
    name = 'UDP'
    reliable = False

    def __init__(self, local_ip, port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local_ip, port))
        self.sock.settimeout(0.2)
        self.local = self.sock.getsockname()[:2]

    def send(self, data, address):
        try:
            self.sock.sendto(data, address)
        except OSError:
            pass

    def receive(self):
        """(data, source), or None when nothing came within 0.2 s."""
        try:
            return self.sock.recvfrom(65535)
        except socket.timeout:
            return None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TlsTransport:
    """One TLS connection to the server, its certificate checked against *ca_file* for the name
    *server_name*: ssl.SSLCertVerificationError when it does not match.  The agent's receiving
    thread and its senders share the connection: OpenSSL does not allow a read and a write at the
    same time, so both go through one lock (the wait for data happens outside it)."""

    name = 'TLS'
    reliable = True

    def __init__(self, local_ip, server, port, ca_file=None, server_name=None, timeout=5.0):
        context = ssl.create_default_context(cafile=ca_file or None)
        plain = socket.create_connection((server, port), timeout=timeout, source_address=(local_ip, 0))
        try:
            self.sock = context.wrap_socket(plain, server_hostname=server_name or server)
        except Exception:
            plain.close()
            raise
        self.sock.settimeout(0.2)
        self.local = self.sock.getsockname()[:2]
        self.peer = (server, port)
        self.version = self.sock.version()
        self._buffer = b''
        self._lock = threading.Lock()

    def send(self, data, address=None):
        with self._lock:
            try:
                self.sock.sendall(data)
            except OSError:
                pass

    def receive(self):
        """One whole message of the stream (framed by Content-Length), or None."""
        while True:
            self._buffer = self._buffer.lstrip(b'\r\n')
            end = self._buffer.find(b'\r\n\r\n')
            if end >= 0:
                head = self._buffer[:end].decode('utf-8', 'replace')
                length = re.search(r'(?im)^(?:content-length|l)[ \t]*:[ \t]*(\d+)', head)
                total = end + 4 + (int(length.group(1)) if length else 0)
                if len(self._buffer) >= total:
                    message, self._buffer = self._buffer[:total], self._buffer[total:]
                    return message, self.peer
            if not self.sock.pending():
                ready, _, _ = select.select([self.sock], [], [], 0.2)
                if not ready:
                    return None
            with self._lock:
                try:
                    chunk = self.sock.recv(65535)
                except (socket.timeout, ssl.SSLWantReadError):
                    return None  # a record without data (a session ticket): nothing to read yet
            if not chunk:
                raise ConnectionError('connection closed')
            self._buffer += chunk

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# user agent
# ---------------------------------------------------------------------------

class UserAgent:
    """A SIP endpoint on one socket: client transactions (with one digest challenge answered),
    and the requests it receives, given to its calls or to *on_invite*."""

    def __init__(self, local_ip, user, password='', server='', port=5060, sip_port=0, display='',
                 user_agent=USER_AGENT, transport='udp', ca_file=None, server_name=None, on_invite=None):
        self.user, self.password = str(user), password
        self.server, self.port = server, int(port)
        self.display, self.user_agent = display, user_agent
        self.on_invite = on_invite
        if transport == 'tls':
            self.transport = TlsTransport(local_ip, server, self.port, ca_file, server_name)
            self.uri_suffix = ';transport=tls'
        else:
            self.transport = UdpTransport(local_ip, sip_port)
            self.uri_suffix = ''
        self.local_ip, self.local_port = self.transport.local
        self.contact = f'<sip:{self.user}@{self.local_ip}:{self.local_port}{self.uri_suffix}>'
        self.dialogs = {}                           # Call-ID -> Call
        self._waiters = {}                          # (Call-ID, CSeq number, method) -> queue of responses
        self._acks = {}                             # (Call-ID, CSeq number) -> (ACK, address), sent again on a retransmission
        self._served = collections.OrderedDict()    # (branch, method) -> (response, address)
        self._closed = threading.Event()
        self._register_call_id = f'{os.urandom(8).hex()}@{self.local_ip}'
        self._register_tag = new_tag()
        self._register_cseq = 0
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def close(self):
        self._closed.set()
        self.transport.close()

    # -- building and sending

    def new_request(self, method, uri, call_id, cseq, from_value, to_value, headers=(), body='', contact=True,
                    routes=()):
        via = f'SIP/2.0/{self.transport.name} {self.local_ip}:{self.local_port};branch={new_branch()};rport'
        lines = [('Via', via), ('Max-Forwards', '70'), ('From', from_value), ('To', to_value),
                 ('Call-ID', call_id), ('CSeq', f'{cseq} {method}')]
        lines += [('Route', route) for route in routes]
        if contact:
            lines.append(('Contact', self.contact))
        lines += [('User-Agent', self.user_agent), ('Allow', ALLOW)]
        lines += list(headers)
        if body:
            lines.append(('Content-Type', 'application/sdp'))
        return SipMessage(method=method, uri=uri, headers=lines, body=body)

    def send(self, message, address=None):
        self.transport.send(message.encode(), address or (self.server, self.port))

    def transact(self, message, address=None, timeout=4.0, on_provisional=None, stop=None):
        """Send the request *message* and return its final response, None after *timeout* seconds.
        Over UDP the request is sent again (0.5 s, 1 s, 2 s, 4 s...) until an answer comes."""
        number, method = message.cseq()
        key = (message.get('call-id'), number, method)
        waiter = self._waiters[key] = queue.Queue()
        data = message.encode()
        address = address or (self.server, self.port)
        self.transport.send(data, address)
        start = time.monotonic()
        interval = 0.5
        again = start + interval
        retransmit = not self.transport.reliable
        try:
            while time.monotonic() - start < timeout and not (stop is not None and stop.is_set()):
                try:
                    response = waiter.get(timeout=0.05)
                except queue.Empty:
                    if retransmit and time.monotonic() >= again:
                        self.transport.send(data, address)
                        interval = min(interval * 2, 4.0)
                        again = time.monotonic() + interval
                    continue
                if response.status >= 200:
                    return response
                retransmit = retransmit and method != 'INVITE'
                if on_provisional is not None:
                    on_provisional(response)
            return None
        finally:
            self._waiters.pop(key, None)

    def ack_failure(self, request, response):
        """ACK of a final non-2xx answer to the INVITE *request* (same branch, RFC 3261 17.1.1.3)."""
        number, _ = request.cseq()
        ack = SipMessage(method='ACK', uri=request.uri, headers=[
            ('Via', request.get('via')), ('Max-Forwards', '70'), ('From', request.get('from')),
            ('To', response.get('to') or request.get('to')), ('Call-ID', request.get('call-id')),
            ('CSeq', f'{number} ACK'), ('User-Agent', self.user_agent)])
        self._acks[(request.get('call-id'), number)] = (ack.encode(), None)
        self.send(ack)

    def transact_auth(self, build, timeout=4.0, on_provisional=None, stop=None):
        """Send ``build(None)``; when it is challenged (401 / 407), send ``build((header name, value))``
        with the digest.  Returns (final response or None, the challenge or None, the last request)."""
        request = build(None)
        response = self.transact(request, timeout=timeout, on_provisional=on_provisional, stop=stop)
        challenge = None
        if response is not None and response.status in (401, 407):
            if request.method == 'INVITE':
                self.ack_failure(request, response)
            proxy = response.status == 407
            challenge = pick_challenge(response.get_all('proxy-authenticate' if proxy else 'www-authenticate'))
            if challenge is not None:
                value = digest_authorization(challenge, request.method, request.uri, self.user, self.password)
                request = build(('Proxy-Authorization' if proxy else 'Authorization', value))
                response = self.transact(request, timeout=timeout, on_provisional=on_provisional, stop=stop)
        return response, challenge, request

    # -- registration

    def register(self, expires=120, contact=True, timeout=4.0):
        """REGISTER the contact of this agent for *expires* seconds; without *contact* the request
        only queries the bindings (it is authenticated all the same and changes nothing)."""
        uri = f'sip:{self.server}{self.uri_suffix}'
        identity = f'<sip:{self.user}@{self.server}>'

        def build(authorization):
            self._register_cseq += 1
            headers = [('Expires', str(expires))] if contact else []
            if authorization:
                headers.append(authorization)
            return self.new_request('REGISTER', uri, self._register_call_id, self._register_cseq,
                                    f'{identity};tag={self._register_tag}', identity, headers=headers,
                                    contact=contact)

        result = {'status': None, 'challenged': False, 'realm': '', 'algorithm': '', 'qop': '',
                  'expires': None, 'contacts': [], 'server': '', 'error': None}
        response, challenge, _ = self.transact_auth(build, timeout=timeout)
        if challenge is not None:
            result.update(challenged=True, realm=challenge.get('realm', ''), qop=challenge.get('qop', ''),
                          algorithm=challenge.get('algorithm', 'MD5'))
        if response is None:
            result['error'] = 'timeout'
            return result
        result['status'] = response.status
        result['server'] = response.get('server') or response.get('user-agent')
        result['contacts'] = response.get_all('contact')
        if response.status == 200:
            granted = None
            for value in result['contacts']:
                if f'{self.local_ip}:{self.local_port}' in value:
                    match = re.search(r';\s*expires=(\d+)', value)
                    granted = int(match.group(1)) if match else granted
            if granted is None and response.get('expires').isdigit():
                granted = int(response.get('expires'))
            result['expires'] = granted
        return result

    # -- receiving

    def _receive_loop(self):
        while not self._closed.is_set():
            try:
                item = self.transport.receive()
            except (OSError, ConnectionError):
                return
            if item is None:
                continue
            message = parse_message(item[0])
            if message is None:
                continue
            try:
                if message.is_request:
                    self._on_request(message, item[1])
                else:
                    self._on_response(message)
            except Exception as error:  # one bad message must not stop the phone
                sys.stderr.write(f'sip_probe: {type(error).__name__}: {error}\n')

    def _on_response(self, message):
        number, method = message.cseq()
        call_id = message.get('call-id')
        if method == 'INVITE' and message.status >= 200:
            ack = self._acks.get((call_id, number))
            if ack is not None:  # a final answer sent again: its ACK was lost
                self.transport.send(ack[0], ack[1] or (self.server, self.port))
        waiter = self._waiters.get((call_id, number, method))
        if waiter is not None:
            waiter.put(message)

    def respond(self, request, status, reason, source, to_tag=None, headers=(), body=''):
        """Answer *request* (to the address it came from) and keep the answer for a retransmission."""
        to_value = request.get('to')
        if to_tag and ';tag=' not in to_value:
            to_value += f';tag={to_tag}'
        lines = [('Via', via) for via in request.get_all('via')]
        lines += [('From', request.get('from')), ('To', to_value), ('Call-ID', request.get('call-id')),
                  ('CSeq', request.get('cseq')), ('User-Agent', self.user_agent), ('Allow', ALLOW)]
        lines += list(headers)
        if body:
            lines.append(('Content-Type', 'application/sdp'))
        data = SipMessage(status=status, reason=reason, headers=lines, body=body).encode()
        self._served[(request.branch(), request.method)] = (data, source)
        while len(self._served) > 256:
            self._served.popitem(last=False)
        self.transport.send(data, source)

    def resend(self, request):
        """Send again the last answer given to *request* (the 200 of an INVITE awaiting its ACK)."""
        served = self._served.get((request.branch(), request.method))
        if served is not None:
            self.transport.send(*served)

    def _on_request(self, message, source):
        method = message.method
        if method != 'ACK' and (message.branch(), method) in self._served:
            self.resend(message)  # a retransmission
            return
        call = self.dialogs.get(message.get('call-id'))
        if call is not None:
            call.on_request(message, source)
        elif method == 'INVITE':
            if self.on_invite is None:
                self.respond(message, 486, 'Busy Here', source, to_tag=new_tag())
                return
            self.respond(message, 100, 'Trying', source)
            call = Call(self, incoming=message, source=source)
            self.dialogs[call.call_id] = call
            threading.Thread(target=self.on_invite, args=(call,), daemon=True).start()
        elif method in ('OPTIONS', 'NOTIFY', 'INFO', 'MESSAGE', 'UPDATE'):
            self.respond(message, 200, 'OK', source, to_tag=new_tag())
        elif method in ('BYE', 'CANCEL'):
            self.respond(message, 481, 'Call/Transaction Does Not Exist', source)
        elif method != 'ACK':
            self.respond(message, 405, 'Method Not Allowed', source, to_tag=new_tag())


# ---------------------------------------------------------------------------
# one call
# ---------------------------------------------------------------------------

class Call:
    """An INVITE dialog of a UserAgent: placed with invite(), or received (*incoming*, the INVITE)
    and then answered with ring() / answer() or refused with reject()."""

    def __init__(self, agent, incoming=None, source=None):
        self.agent = agent
        self.rtp = None
        self.ended = threading.Event()
        self.acked = threading.Event()
        self.answered = False
        self.cancelled = False
        self.challenged = False
        self.bye = None           # 'sent' | 'received'
        self.provisional = []     # status codes received before the final answer
        self.reinvites = []       # media changes asked by the other side
        self.updates = 0          # UPDATE / re-INVITE without media change
        self.routes = []
        self.local_sdp = ''
        self.remote_sdp = {}
        self.cseq = 0
        self._last_provisional = None
        self.invite_request = incoming
        self.source = source
        if incoming is None:
            self.call_id = f'{os.urandom(8).hex()}@{agent.local_ip}'
            self.local_tag = new_tag()
            self.local_value = self.remote_value = ''
            self.remote_target = ''
            self.remote_address = None
        else:
            self.call_id = incoming.get('call-id')
            self.local_tag = new_tag()
            to_value = incoming.get('to')
            self.local_value = to_value if ';tag=' in to_value else f'{to_value};tag={self.local_tag}'
            self.remote_value = incoming.get('from')
            contact = parse_name_addr(incoming.get('contact'))
            self.remote_target = contact['uri'] or parse_name_addr(self.remote_value)['uri']
            self.remote_address = source
            self.routes = incoming.get_all('record-route')
            self.remote_sdp = parse_sdp(incoming.body)

    # -- caller

    def invite(self, number, sdp, ring_timeout=8.0, display=None, stop=None):
        """Call *number* through the agent's server.  Returns the final response; None when nothing
        final came within *ring_timeout* seconds (the call is then cancelled)."""
        agent = self.agent
        uri = f'sip:{number}@{agent.server}:{agent.port}{agent.uri_suffix}'
        name = f'"{display}" ' if display else ''
        self.local_value = f'{name}<sip:{agent.user}@{agent.server}>;tag={self.local_tag}'
        self.remote_value = f'<sip:{number}@{agent.server}>'
        self.local_sdp = sdp
        agent.dialogs[self.call_id] = self

        def build(authorization):
            self.cseq += 1
            self.invite_request = agent.new_request(
                'INVITE', uri, self.call_id, self.cseq, self.local_value, self.remote_value,
                headers=[authorization] if authorization else [], body=sdp)
            return self.invite_request

        def provisional(response):
            self.provisional.append(response.status)
            self._last_provisional = response

        response, challenge, request = agent.transact_auth(build, timeout=ring_timeout,
                                                           on_provisional=provisional, stop=stop)
        self.challenged = challenge is not None
        if response is None:
            self._cancel(request)
            return None
        if response.status >= 300:
            agent.ack_failure(request, response)
            self.ended.set()
            return response
        self.answered = True
        self.remote_value = response.get('to')
        self.routes = list(reversed(response.get_all('record-route')))
        contact = parse_name_addr(response.get('contact'))
        self.remote_target = contact['uri'] or uri
        if contact['host'] and not agent.transport.reliable:
            self.remote_address = (contact['host'], contact['port'] or 5060)
        self.remote_sdp = parse_sdp(response.body)
        ack = agent.new_request('ACK', self.remote_target, self.call_id, self.cseq, self.local_value,
                                self.remote_value, contact=False, routes=self.routes)
        agent._acks[(self.call_id, self.cseq)] = (ack.encode(), self.remote_address)
        agent.send(ack, self.remote_address)
        return response

    def _cancel(self, request):
        """CANCEL the pending INVITE *request* (only allowed once a provisional answer came)."""
        self.cancelled = True
        self.ended.set()
        if self._last_provisional is None:
            return
        agent = self.agent
        common = [('Via', request.get('via')), ('Max-Forwards', '70'), ('From', request.get('from'))]
        tail = [('Call-ID', self.call_id), ('User-Agent', agent.user_agent)]
        # the ACK of the 487 that will close the INVITE
        ack = SipMessage(method='ACK', uri=request.uri, headers=common + [
            ('To', self._last_provisional.get('to') or request.get('to')), ('CSeq', f'{self.cseq} ACK')] + tail)
        agent._acks[(self.call_id, self.cseq)] = (ack.encode(), None)
        cancel = SipMessage(method='CANCEL', uri=request.uri, headers=common + [
            ('To', request.get('to')), ('CSeq', f'{self.cseq} CANCEL')] + tail)
        agent.transact(cancel, timeout=2.0)

    # -- callee

    def ring(self):
        self.agent.respond(self.invite_request, 180, 'Ringing', self.source, to_tag=self.local_tag,
                           headers=[('Contact', self.agent.contact)])

    def answer(self, sdp):
        """200 with *sdp*, sent again until the ACK arrives."""
        agent = self.agent
        self.local_sdp = sdp
        self.answered = True
        agent.respond(self.invite_request, 200, 'OK', self.source, to_tag=self.local_tag,
                      headers=[('Contact', agent.contact)], body=sdp)
        interval = 0.5
        while not agent.transport.reliable and not self.acked.wait(interval) and not self.ended.is_set():
            if interval > 4:
                break
            agent.resend(self.invite_request)
            interval *= 2

    def reject(self, status=486, reason='Busy Here'):
        self.agent.respond(self.invite_request, status, reason, self.source, to_tag=self.local_tag)
        self.ended.set()

    # -- both sides

    def hangup(self):
        """BYE, unless the call is already over."""
        if self.ended.is_set() or not self.answered:
            return
        self.ended.set()
        self.bye = 'sent'
        self.cseq += 1
        agent = self.agent
        request = agent.new_request('BYE', self.remote_target, self.call_id, self.cseq, self.local_value,
                                    self.remote_value, contact=False, routes=self.routes)
        agent.transact(request, address=self.remote_address, timeout=2.0)

    def on_request(self, message, source):
        """A request of the other side inside the dialog."""
        agent, method = self.agent, message.method
        if method == 'ACK':
            self.acked.set()
        elif method == 'BYE':
            agent.respond(message, 200, 'OK', source)
            self.bye = self.bye or 'received'
            self.ended.set()
        elif method == 'CANCEL':
            agent.respond(message, 200, 'OK', source)
            if not self.answered and not self.ended.is_set():
                self.cancelled = True
                self.ended.set()
                agent.respond(self.invite_request, 487, 'Request Terminated', self.source, to_tag=self.local_tag)
        elif method in ('INVITE', 'UPDATE'):
            sdp = parse_sdp(message.body)
            if sdp.get('address') and sdp.get('port'):
                changed = (sdp['address'], sdp['port']) != (self.remote_sdp.get('address'), self.remote_sdp.get('port'))
                self.remote_sdp = sdp
                if changed:
                    self.reinvites.append({'method': method, 'address': sdp['address'], 'port': sdp['port']})
                    if self.rtp is not None:
                        self.rtp.set_remote((sdp['address'], sdp['port']))
                else:
                    self.updates += 1
            else:
                self.updates += 1
            body = self.local_sdp if (sdp or method == 'INVITE') else ''
            agent.respond(message, 200, 'OK', source, headers=[('Contact', agent.contact)], body=body)
        else:
            agent.respond(message, 200, 'OK', source)

    def close(self):
        self.agent.dialogs.pop(self.call_id, None)


# ---------------------------------------------------------------------------
# placing a call
# ---------------------------------------------------------------------------

def _wait(call, seconds, stop=None):
    """Wait *seconds*; true when the call ended (or *stop* was set) meanwhile."""
    end = time.monotonic() + seconds
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return call.ended.is_set()
        if call.ended.wait(min(left, 0.05)) or (stop is not None and stop.is_set()):
            return True


def _talk(call, rtp, duration, digits, stop=None):
    """Stay *duration* seconds in the call, sending the *digits* ({"at": seconds, "digits"})."""
    start = time.monotonic()
    pending = sorted(digits, key=lambda item: float(item.get('at', 0)))
    while True:
        elapsed = time.monotonic() - start
        while pending and elapsed >= float(pending[0].get('at', 0)):
            rtp.send_digits(str(pending.pop(0).get('digits', '')))
        if elapsed >= duration or _wait(call, 0.05, stop):
            return


def _leave_message(call, rtp, duration, stop=None, skip_at=1.5, pause=0.4, limit=14.0):
    """Leave a message on a voicemail: '#' while the greeting still plays (it skips to the beep),
    then *duration* seconds of tone once the prompts have stopped.  True when '#' was sent."""
    start = time.monotonic()
    if _wait(call, skip_at, stop):
        return False
    idle = rtp.idle()
    pound = idle is not None and idle < 0.3
    if pound:
        rtp.send_digits('#')
    while time.monotonic() - start < limit:
        idle = rtp.idle()
        if idle is not None and idle >= pause:
            break
        if _wait(call, 0.05, stop):
            return pound
    _wait(call, duration, stop)
    return pound


def make_call(agent, listen, scenario, stop=None):
    """Place the call of *scenario* from *agent* and report it (see the header of the file)."""
    result = {'status': None, 'provisional': [], 'answered': False, 'challenged': False, 'cancelled': False,
              'sdp': {}, 'rtp': {}, 'reinvites': [], 'updates': 0, 'bye': None, 'pound': False,
              't_start': time.time(), 't_answer': None, 't_end': None, 'error': None}
    codecs = scenario.get('codecs') or ['PCMA', 'PCMU']
    ptime = int(scenario.get('ptime') or 20)
    secure = bool(scenario.get('srtp'))
    rtp = RtpSession(agent.local_ip, listen=listen)
    call = Call(agent)
    try:
        offer = build_sdp(agent.local_ip, rtp.port, codecs, ptime, srtp_key=os.urandom(30) if secure else None)
        response = call.invite(str(scenario['to']), offer, ring_timeout=float(scenario.get('ring_timeout') or 8),
                               display=scenario.get('display'), stop=stop)
        if response is None:
            result['error'] = 'no answer' if call.provisional else 'timeout'
            return result
        result['status'] = response.status
        if response.status >= 300:
            return result
        result['answered'], result['t_answer'] = True, time.time()
        sdp = call.remote_sdp
        result['sdp'] = {'address': sdp.get('address'), 'port': sdp.get('port'), 'profile': sdp.get('profile'),
                         'payloads': sdp.get('payloads', []), 'ptime': sdp.get('ptime'),
                         'crypto': bool(sdp.get('crypto'))}
        codec = pick_codec(sdp)
        if codec and sdp.get('address') and sdp.get('port'):
            call.rtp = rtp
            # no key exchange is implemented: an encrypted stream is only counted
            rtp.start((sdp['address'], sdp['port']), codec, scenario.get('tone'), ptime,
                      telephone_event=sdp.get('telephone_event'), send=not secure)
        duration = float(scenario.get('duration') or 4)
        if scenario.get('voicemail'):
            result['pound'] = _leave_message(call, rtp, duration, stop)
        else:
            _talk(call, rtp, duration, scenario.get('dtmf') or [], stop)
        return result
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
        return result
    finally:
        try:
            call.hangup()
        except Exception:
            pass
        rtp.stop()
        call.close()
        result.update(provisional=call.provisional, challenged=call.challenged, cancelled=call.cancelled,
                      reinvites=call.reinvites, updates=call.updates, bye=call.bye, rtp=rtp.stats(),
                      t_end=time.time())


# ---------------------------------------------------------------------------
# run: the scenarios of the grader
# ---------------------------------------------------------------------------

def _agent_of(spec, scenario, **more):
    return UserAgent(spec['local_ip'], scenario['user'], scenario.get('password', ''), scenario['server'],
                     scenario.get('port') or 5060, display=scenario.get('display', ''),
                     user_agent=scenario.get('user_agent') or USER_AGENT,
                     transport=scenario.get('transport') or 'udp', ca_file=scenario.get('ca_file'),
                     server_name=scenario.get('server_name'), **more)


def _open_agent(spec, scenario):
    """(agent, tls report): the report says whether the server's certificate was accepted."""
    secure = scenario.get('transport') == 'tls'
    failure = None
    for attempt in range(3):  # a TLS handshake now and then fails on a busy server: tried again
        try:
            agent = _agent_of(spec, scenario)
        except ssl.SSLCertVerificationError as error:
            return None, {'verified': False, 'version': None, 'error': error.verify_message}
        except (OSError, ssl.SSLError) as error:
            failure = {'verified': None, 'version': None, 'error': f'{type(error).__name__}: {error}'}
            time.sleep(0.4)
            continue
        return agent, ({'verified': True, 'version': agent.transport.version, 'error': None} if secure else None)
    return None, failure


def scenario_register(spec, scenario, stop):
    agent, tls = _open_agent(spec, scenario)
    if agent is None:
        return {'status': None, 'tls': tls, 'error': 'connection'}
    try:
        contact = bool(scenario.get('contact'))
        result = agent.register(expires=int(scenario.get('expires') or 60), contact=contact)
        result['tls'] = tls
        if contact and result['status'] == 200 and scenario.get('unregister', True):
            result['unregistered'] = agent.register(expires=0, contact=True)['status']
        return result
    finally:
        agent.close()


def scenario_call(spec, scenario, stop):
    agent, tls = _open_agent(spec, scenario)
    if agent is None:
        return {'status': None, 'answered': False, 'tls': tls, 'error': 'connection'}
    try:
        result = make_call(agent, spec.get('listen') or [], scenario, stop)
        result['tls'] = tls
        return result
    finally:
        agent.close()


def scenario_sleep(spec, scenario, stop):
    stop.wait(float(scenario.get('seconds') or 1))
    return {'error': None}


SCENARIOS = {'register': scenario_register, 'call': scenario_call, 'sleep': scenario_sleep}


def run(spec):
    """The tracks of *spec* in parallel; what is not finished at the deadline is reported as such."""
    results, errors = {}, []
    stop = threading.Event()
    deadline = time.monotonic() + float(spec.get('deadline') or 40)

    def track(scenarios):
        for scenario in scenarios:
            name = str(scenario.get('id'))
            if stop.is_set():
                results[name] = {'error': 'deadline'}
                continue
            started = time.time()
            try:
                result = SCENARIOS[scenario.get('kind')](spec, scenario, stop)
            except Exception as error:
                result = {'error': f'{type(error).__name__}: {error}'}
            result.setdefault('t_start', started)
            result.setdefault('t_end', time.time())
            results[name] = result

    threads = [threading.Thread(target=track, args=(scenarios,), daemon=True)
               for scenarios in spec.get('tracks') or []]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        errors.append('deadline reached')
        stop.set()  # the calls in progress hang up
        for thread in threads:
            thread.join(4)
    for scenarios in spec.get('tracks') or []:
        for scenario in scenarios:
            results.setdefault(str(scenario.get('id')), {'error': 'deadline'})
    return {'errors': errors, 'results': results}


# ---------------------------------------------------------------------------
# daemon: the persistent phones
# ---------------------------------------------------------------------------

DEFAULT_LOG = '/var/log/sre_sip_probe.jsonl'
DEFAULT_PID = '/run/sre_sip_probe.pid'
DEFAULT_STATUS = '/run/sre_sip_probe.status'
ERROR_LOG = '/var/log/sre_sip_probe.err'


class Phone:
    """One account of the daemon: keeps it registered, answers its calls, places its periodic calls."""

    RING = 0.3  # seconds of ringing before an incoming call is answered

    def __init__(self, daemon, account):
        self.daemon = daemon
        self.account = account
        self.user = str(account['user'])
        self.mode = account.get('mode') or 'answer'
        self.codecs = tuple(account.get('codecs') or ('PCMA', 'PCMU'))
        self.kick = threading.Event()
        self.status = {'registered': False, 'status': None, 'error': 'not tried', 't': 0.0}
        self._last_logged = None
        self._last_call = None
        self.agent = UserAgent(daemon.local_ip, self.user, account.get('password', ''), account['server'],
                               account.get('port') or 5060, sip_port=int(account.get('sip_port') or 0),
                               display=account.get('display', ''), user_agent=account.get('user_agent') or USER_AGENT,
                               on_invite=self.incoming if self.mode != 'none' else None)

    def start(self):
        threading.Thread(target=self._register_loop, daemon=True).start()
        if self.account.get('calls'):
            threading.Thread(target=self._calls_loop, daemon=True).start()

    def _register_loop(self):
        expires = int(self.account.get('expires') or 120)
        refresh = self.account.get('refresh')
        retry = float(self.account.get('retry') or 10)
        while not self.daemon.stopped.is_set():
            try:
                result = self.agent.register(expires=expires)
            except Exception as error:
                result = {'status': None, 'error': f'{type(error).__name__}: {error}', 'expires': None}
            registered = result['status'] == 200
            self.status = {'registered': registered, 'status': result['status'], 'error': result.get('error'),
                           'expires': result.get('expires'), 't': time.time()}
            if (registered, result['status']) != self._last_logged:
                self._last_logged = (registered, result['status'])
                self.daemon.log({'event': 'register', 'user': self.user, 'status': result['status'],
                                 'registered': registered, 'error': result.get('error')})
            self.daemon.write_status()
            delay = float(refresh or max(5, (result.get('expires') or expires) / 2)) if registered else retry
            self.kick.wait(delay)
            self.kick.clear()

    def _calls_loop(self):
        calls = self.account['calls']
        scenario = {'to': calls['number'], 'duration': calls.get('duration') or 5, 'tone': self.account.get('tone'),
                    'codecs': [calls.get('codec') or 'PCMA'], 'ptime': calls.get('ptime') or 20,
                    'display': self.account.get('display')}
        self.daemon.stopped.wait(4)
        while not self.daemon.stopped.is_set():
            if self.status['registered']:
                result = make_call(self.agent, self.daemon.listen, scenario, self.daemon.stopped)
                outcome = (result['status'], result['error'])
                if outcome != self._last_call:  # the first call and every change, not the routine
                    self._last_call = outcome
                    self.daemon.log({'event': 'call', 'direction': 'out', 'user': self.user,
                                     'to': str(calls['number']), 'status': result['status'],
                                     'error': result['error'], 'received': result['rtp'].get('received')})
            self.daemon.stopped.wait(float(calls.get('every') or 25))

    def _rtp_session(self):
        base = int(self.account.get('rtp_port') or 0)
        for index in range(16 if base else 1):
            try:
                return RtpSession(self.daemon.local_ip, base + 2 * index if base else 0, self.daemon.listen)
            except OSError:
                continue
        return RtpSession(self.daemon.local_ip, 0, self.daemon.listen)

    def incoming(self, call):
        """An INVITE for this phone (run in its own thread)."""
        started = time.time()
        request = call.invite_request
        caller, callee = parse_name_addr(request.get('from')), parse_name_addr(request.get('to'))
        target = _URI_RE.match(request.uri)
        offer = call.remote_sdp
        entry = {'event': 'call', 'direction': 'in', 'user': self.user, 'action': None,
                 'from_user': caller['user'], 'from_display': caller['display'], 'to_user': callee['user'],
                 'ruri_user': (target.group(2) or '') if target else '', 'source': f'{call.source[0]}:{call.source[1]}',
                 'offer': {'address': offer.get('address'), 'port': offer.get('port'),
                           'profile': offer.get('profile'), 'payloads': offer.get('payloads', [])},
                 'end': None, 'rtp': {}, 'reinvites': [], 'error': None}
        rtp = None
        try:
            codec = pick_codec(offer, self.codecs)
            if self.mode == 'busy':
                call.reject(486, 'Busy Here')
                entry['action'] = 'busy'
                return
            if codec is None or offer.get('profile') != 'RTP/AVP' or not offer.get('port'):
                call.reject(488, 'Not Acceptable Here')
                entry['action'] = 'refused'
                return
            call.ring()
            if call.ended.wait(self.RING):
                entry['action'] = 'cancelled'
                return
            rtp = call.rtp = self._rtp_session()
            ptime = offer.get('ptime') or 20
            call.answer(build_sdp(self.daemon.local_ip, rtp.port, [codec], ptime))
            rtp.start((offer['address'], offer['port']), codec, self.account.get('tone'), ptime,
                      telephone_event=offer.get('telephone_event'))
            entry['action'] = 'answered'
            # like a real phone, hang up when the audio stops coming (or never came)
            limit = time.monotonic() + float(self.account.get('max_call') or 120)
            silence = float(self.account.get('rtp_timeout') or 10)
            answered = time.monotonic()
            while not call.ended.wait(0.5):
                idle = rtp.idle()
                quiet = time.monotonic() - answered if idle is None else idle
                if quiet >= silence or time.monotonic() >= limit:
                    call.hangup()
                    entry['end'] = 'silence' if quiet >= silence else 'timeout'
                    break
            entry['end'] = entry['end'] or call.bye
        except Exception as error:
            entry['error'] = f'{type(error).__name__}: {error}'
        finally:
            if rtp is not None:
                rtp.stop()
                entry['rtp'] = rtp.stats()
            if call.cancelled:
                entry['action'] = 'cancelled'
            entry['reinvites'] = call.reinvites
            entry['duration'] = round(time.time() - started, 2)
            call.close()
            self.daemon.log(entry)


class Daemon:
    def __init__(self, spec):
        self.spec = spec
        self.local_ip = spec['local_ip']
        self.listen = spec.get('listen') or []
        self.log_path = spec.get('log') or DEFAULT_LOG
        self.status_path = spec.get('status') or DEFAULT_STATUS
        self.stopped = threading.Event()
        self._lock = threading.Lock()
        self.phones = []

    def log(self, entry):
        line = json.dumps({'t': round(time.time(), 3), **entry}, sort_keys=True)
        with self._lock:
            with open(self.log_path, 'a') as log:
                log.write(line + '\n')

    def write_status(self):
        status = {'t': time.time(), 'pid': os.getpid(), 'phones': {phone.user: phone.status for phone in self.phones}}
        with self._lock:
            temporary = self.status_path + '.tmp'
            with open(temporary, 'w') as output:
                json.dump(status, output, sort_keys=True)
            os.replace(temporary, self.status_path)

    def run(self):
        signal.signal(signal.SIGUSR1, lambda *_: [phone.kick.set() for phone in self.phones])
        signal.signal(signal.SIGTERM, lambda *_: self.stopped.set())
        open(self.log_path, 'w').close()
        for account in self.spec.get('accounts') or []:
            try:
                self.phones.append(Phone(self, account))
            except OSError as error:
                self.log({'event': 'error', 'user': str(account.get('user')), 'error': f'{type(error).__name__}: {error}'})
        self.write_status()
        self.log({'event': 'start', 'phones': [phone.user for phone in self.phones]})
        for phone in self.phones:
            phone.start()
        while not self.stopped.wait(1):
            pass


def _read_pid(path):
    try:
        with open(path) as pid_file:
            return int(pid_file.read().strip())
    except (OSError, ValueError):
        return None


def _alive(pid):
    """True when *pid* is a running instance of this script."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as cmdline:
            return b'sip_probe' in cmdline.read()
    except OSError:
        return True  # no /proc: the signal test is all there is


def daemonize(pid_path):
    if os.fork() != 0:
        os._exit(0)
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    for fd in (0, 1, 2):
        try:
            os.close(fd)
        except OSError:
            pass
    os.open(os.devnull, os.O_RDONLY)
    errors = os.open(ERROR_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(errors, 1)
    os.dup2(errors, 2)
    with open(pid_path, 'w') as pid_file:
        pid_file.write(str(os.getpid()))


def command_daemon(spec, only_if_dead=False):
    """Start the phones of *spec* in the background, in place of a previous instance (kept, with
    *only_if_dead*, when it is still running)."""
    pid_path = spec.get('pid') or DEFAULT_PID
    previous = _read_pid(pid_path)
    if _alive(previous):
        if only_if_dead:
            return 0
        os.kill(previous, signal.SIGTERM)
        for _ in range(20):
            if not _alive(previous):
                break
            time.sleep(0.1)
        else:
            os.kill(previous, signal.SIGKILL)
            time.sleep(0.2)
    daemonize(pid_path)
    Daemon(spec).run()
    return 0


def command_kick(status_path=DEFAULT_STATUS, pid_path=DEFAULT_PID, timeout=7.0):
    """Make every phone register now and print the status once each of them has answered
    (``alive`` false without a daemon; ``kicked`` = the time of the request, to compare with the
    ``t`` of each phone)."""
    answer = {'alive': False, 'kicked': time.time(), 'phones': {}}
    pid = _read_pid(pid_path)
    for _ in range(20):  # a daemon started just before writes its pid file a moment later
        if _alive(pid):
            break
        time.sleep(0.1)
        pid = _read_pid(pid_path)
    if _alive(pid):
        answer['alive'] = True
        os.kill(pid, signal.SIGUSR1)
        end = time.monotonic() + timeout
        while True:
            try:
                with open(status_path) as status_file:
                    status = json.load(status_file)
            except (OSError, ValueError):
                status = {}
            phones = status.get('phones') or {}
            answer['phones'] = phones
            if phones and all(phone.get('t', 0) >= answer['kicked'] for phone in phones.values()):
                break
            if time.monotonic() >= end:
                break
            time.sleep(0.1)
    print(json.dumps(answer, sort_keys=True))
    return 0


def decode_spec(text):
    return json.loads(base64.urlsafe_b64decode(text))


def main(argv):
    command = argv[1] if len(argv) > 1 else ''
    if command in ('daemon', 'ensure') and len(argv) == 3:
        return command_daemon(decode_spec(argv[2]), only_if_dead=command == 'ensure')
    if command == 'kick':
        return command_kick(*argv[2:4])
    if command == 'run' and len(argv) == 3:
        try:
            answer = run(decode_spec(argv[2]))
        except Exception as error:  # the grader needs a JSON document whatever happens
            answer = {'errors': [f'{type(error).__name__}: {error}'], 'results': {}}
        print(json.dumps(answer, sort_keys=True))
        return 0
    sys.stderr.write(f'usage: {argv[0]} daemon|ensure SPEC | kick [STATUS [PID]] | run SPEC\n')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
