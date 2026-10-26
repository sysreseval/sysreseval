"""Tests of sreweb.agent.rfb_filter: the client-to-server RFB stream of a read-only viewer (a
spectator of a presentation): the handshake and the display requests pass, the input and the
desktop changes are dropped, anything else is an error."""
import struct

import pytest

from sreweb.agent import rfb_filter as R

VERSION = b'RFB 003.008\n'
SECURITY = b'\x01'                                   # None
INIT = b'\x01'                                       # ClientInit: shared
SET_PIXEL_FORMAT = b'\x00' + b'\x00' * 19
FB_UPDATE_REQUEST = b'\x03\x00' + struct.pack('>HHHH', 0, 0, 1280, 800)
KEY_EVENT = b'\x04\x01\x00\x00' + struct.pack('>I', 0x61)
POINTER_EVENT = b'\x05\x01' + struct.pack('>HH', 10, 20)
ENABLE_CONTINUOUS = b'\x96\x01' + struct.pack('>HHHH', 0, 0, 100, 100)
XVP = b'\xfa\x00\x01\x02'
QEMU_KEY = b'\xff\x00' + struct.pack('>HII', 1, 0x61, 0x1e)


def set_encodings(*encodings) -> bytes:
    return b'\x02\x00' + struct.pack('>H', len(encodings)) + b''.join(struct.pack('>i', e) for e in encodings)


def cut_text(text: bytes, extended: bool = False) -> bytes:
    return b'\x06' + b'\x00' * 3 + struct.pack('>i', -len(text) if extended else len(text)) + text


def fence(payload: bytes) -> bytes:
    return b'\xf8' + b'\x00' * 3 + struct.pack('>I', 1) + bytes([len(payload)]) + payload


def set_desktop_size(screens: int) -> bytes:
    return b'\xfb\x00' + struct.pack('>HH', 800, 600) + bytes([screens, 0]) + b'\x00' * 16 * screens


def after_handshake() -> R.RfbInputFilter:
    f = R.RfbInputFilter()
    assert f.feed(VERSION) == VERSION and not f.handshake_done
    assert f.feed(SECURITY) == SECURITY
    assert f.feed(INIT) == INIT and f.handshake_done
    return f


class TestHandshake:
    def test_version_3_8(self):
        after_handshake()

    def test_version_3_3_has_no_security_byte(self):
        f = R.RfbInputFilter()
        assert f.feed(b'RFB 003.003\n') == b'RFB 003.003\n'
        assert f.feed(INIT) == INIT and f.handshake_done

    def test_split_version_line(self):
        f = R.RfbInputFilter()
        assert f.feed(VERSION[:5]) == b''
        assert f.feed(VERSION[5:] + SECURITY) == VERSION + SECURITY

    @pytest.mark.parametrize('bad', [b'RFB 004.000\n', b'RFB 003.009\n', b'HTTP/1.1 200\n'])
    def test_bad_version(self, bad):
        with pytest.raises(R.RfbProtocolError):
            R.RfbInputFilter().feed(bad)

    def test_security_type_other_than_none(self):
        f = R.RfbInputFilter()
        f.feed(VERSION)
        with pytest.raises(R.RfbProtocolError):
            f.feed(b'\x02')          # VNC authentication


class TestMessages:
    @pytest.mark.parametrize('message', [SET_PIXEL_FORMAT, FB_UPDATE_REQUEST, set_encodings(0, 7, -239, -223),
                                         set_encodings(), fence(b''), fence(b'abc'), ENABLE_CONTINUOUS])
    def test_display_messages_pass(self, message):
        f = after_handshake()
        assert f.feed(message) == message
        assert f.feed(FB_UPDATE_REQUEST) == FB_UPDATE_REQUEST     # the stream stays in step

    @pytest.mark.parametrize('message', [KEY_EVENT, POINTER_EVENT, cut_text(b'hello'), cut_text(b''),
                                         cut_text(b'xyz', extended=True), set_desktop_size(0), set_desktop_size(2),
                                         XVP, QEMU_KEY])
    def test_input_and_desktop_changes_are_dropped(self, message):
        f = after_handshake()
        assert f.feed(message) == b''
        assert f.feed(FB_UPDATE_REQUEST) == FB_UPDATE_REQUEST

    def test_mixed_frame(self):
        f = after_handshake()
        assert f.feed(KEY_EVENT + FB_UPDATE_REQUEST + POINTER_EVENT + SET_PIXEL_FORMAT) == FB_UPDATE_REQUEST + SET_PIXEL_FORMAT

    def test_messages_split_across_frames(self):
        f = after_handshake()
        assert f.feed(KEY_EVENT[:3]) == b''
        assert f.feed(KEY_EVENT[3:] + FB_UPDATE_REQUEST[:4]) == b''
        assert f.feed(FB_UPDATE_REQUEST[4:]) == FB_UPDATE_REQUEST
        encodings = set_encodings(1, 2, 3)
        assert f.feed(encodings[:1]) == b''                      # the count is not there yet
        assert f.feed(encodings[1:7]) == b''
        assert f.feed(encodings[7:]) == encodings

    def test_long_dropped_message_is_consumed_without_buffering(self):
        f = after_handshake()
        total = 5 << 20                                          # a 5 MiB clipboard
        header = b'\x06' + b'\x00' * 3 + struct.pack('>i', total)
        assert f.feed(header + b'x' * 1000) == b''
        fed = 1000
        while total - fed > 100000:
            assert f.feed(b'x' * 100000) == b''
            fed += 100000
            assert len(f._buf) == 0                              # nothing of it is kept
        assert f.feed(b'x' * (total - fed) + FB_UPDATE_REQUEST) == FB_UPDATE_REQUEST

    def test_qemu_other_subtype_and_unknown_type_are_errors(self):
        f = after_handshake()
        with pytest.raises(R.RfbProtocolError):
            f.feed(b'\xff\x01' + b'\x00' * 10)
        f = after_handshake()
        with pytest.raises(R.RfbProtocolError):
            f.feed(b'\x07')

    def test_oversize_forwarded_message(self, monkeypatch):
        monkeypatch.setattr(R, 'MAX_RFB_MESSAGE', 100)
        f = after_handshake()
        with pytest.raises(R.RfbProtocolError):
            f.feed(set_encodings(*range(30)))
