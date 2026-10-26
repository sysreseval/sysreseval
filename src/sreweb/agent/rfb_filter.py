"""The client-to-server side of an RFB (VNC) connection, filtered for a read-only viewer.

A spectator of a presentation sees the virtual desktop of the project through noVNC like the
presenter does, but must not act on it: ``app.display_ws`` passes the frames of such a viewer
through :class:`RfbInputFilter` before writing them to the X server.  The filter follows the
protocol (RFC 6143 and the extensions noVNC uses):

- the handshake passes: the version line (12 bytes), the security type the client picks (one
  byte, ``None`` is the only one the agent's Xvnc offers), the ClientInit shared flag (one byte);
- then every client message is parsed by type and length: the messages the display needs pass
  (SetPixelFormat, SetEncodings, FramebufferUpdateRequest, EnableContinuousUpdates, and the
  ClientFence replies, which TigerVNC uses to measure the round trip: a viewer that never
  answers them is taken for congested and stops getting updates), the input and the desktop
  changes are swallowed (KeyEvent, PointerEvent, ClientCutText, xvp, SetDesktopSize, the QEMU
  extended key event), anything else is a :class:`RfbProtocolError` (the socket is closed).

The filter keeps the bytes of a message split across WebSocket frames, and consumes a dropped
message however long it is without buffering it (the clipboard of a spectator may be large).
"""
import re
import struct

#: A forwarded message longer than this is a protocol error (nothing the display sends is).
MAX_RFB_MESSAGE = 1 << 20
VERSION_RE = re.compile(rb'^RFB (\d{3})\.(\d{3})\n$')
#: The client messages of a fixed size: type -> length in bytes.
FIXED_LENGTH = {0: 20, 3: 10, 4: 8, 5: 6, 150: 10, 250: 4}
#: The client messages a read-only viewer may not send: KeyEvent, PointerEvent, ClientCutText,
#: xvp (power control), SetDesktopSize, QEMU client messages (the extended key event).
DROPPED = frozenset({4, 5, 6, 250, 251, 255})

STATE_VERSION, STATE_SECURITY, STATE_INIT, STATE_MESSAGES = 'version', 'security', 'init', 'messages'


class RfbProtocolError(ValueError):
    """The viewer sent something the protocol (or the filter) does not allow."""


class RfbInputFilter:
    """``feed(bytes) -> bytes``: what may go to the X server out of what the viewer sent."""

    def __init__(self):
        self._buf = bytearray()
        self._state = STATE_VERSION
        self._skip = 0          # bytes of a dropped message still to come

    @property
    def handshake_done(self) -> bool:
        return self._state == STATE_MESSAGES

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        self._buf.extend(data)
        while True:
            if self._skip:
                n = min(self._skip, len(self._buf))
                del self._buf[:n]
                self._skip -= n
                if self._skip:
                    break
                continue
            if not self._buf:
                break
            if self._state == STATE_VERSION:
                if len(self._buf) < 12:
                    break
                head = bytes(self._buf[:12])
                m = VERSION_RE.match(head)
                if not m or m.group(1) != b'003' or int(m.group(2)) not in (3, 7, 8):
                    raise RfbProtocolError("bad protocol version")
                out += head
                del self._buf[:12]
                self._state = STATE_INIT if int(m.group(2)) == 3 else STATE_SECURITY
            elif self._state == STATE_SECURITY:
                if self._buf[0] != 1:
                    raise RfbProtocolError(f"security type {self._buf[0]}")
                out.append(self._buf[0])
                del self._buf[:1]
                self._state = STATE_INIT
            elif self._state == STATE_INIT:
                out.append(self._buf[0])
                del self._buf[:1]
                self._state = STATE_MESSAGES
            else:
                length = self._message_length()
                if length is None:
                    break
                if self._buf[0] in DROPPED:
                    n = min(length, len(self._buf))
                    del self._buf[:n]
                    self._skip = length - n
                    continue
                if length > MAX_RFB_MESSAGE:
                    raise RfbProtocolError("message too long")
                if len(self._buf) < length:
                    break
                out += self._buf[:length]
                del self._buf[:length]
        return bytes(out)

    def _message_length(self) -> int | None:
        """The length of the client message at the head of the buffer, ``None`` when its header
        is not complete yet."""
        buf = self._buf
        kind = buf[0]
        if kind in FIXED_LENGTH:
            return FIXED_LENGTH[kind]
        if kind == 2:        # SetEncodings: padding, u16 count, s32 encodings
            if len(buf) < 4:
                return None
            return 4 + 4 * struct.unpack_from('>H', buf, 2)[0]
        if kind == 6:        # ClientCutText: padding[3], s32 length (negative: extended clipboard)
            if len(buf) < 8:
                return None
            return 8 + abs(struct.unpack_from('>i', buf, 4)[0])
        if kind == 248:      # ClientFence: padding[3], u32 flags, u8 length, payload
            if len(buf) < 9:
                return None
            return 9 + buf[8]
        if kind == 251:      # SetDesktopSize: padding, u16 width, u16 height, u8 screens, padding, 16 bytes each
            if len(buf) < 7:
                return None
            return 8 + 16 * buf[6]
        if kind == 255:      # QEMU client message: u8 subtype, 0 = extended key event
            if len(buf) < 2:
                return None
            if buf[1] == 0:
                return 12
            raise RfbProtocolError(f"QEMU message subtype {buf[1]}")
        raise RfbProtocolError(f"client message type {kind}")
