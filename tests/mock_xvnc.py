#!/usr/bin/env python3
"""A stand-in for TigerVNC's Xvnc in the tests of ``sreweb.agent.display`` (no X at all).

Takes the command line the agent builds (``:N`` and the ``-option value`` pairs), checks the X
authority file of ``-auth`` (one MIT-MAGIC-COOKIE-1 record of 16 bytes for the display), creates
the RFB Unix socket of ``-rfbunixpath`` with the mode of ``-rfbunixmode`` and serves it: every
viewer gets the RFB version line, then an echo of what it sends until it hangs up.  Ends on
SIGTERM, the socket removed.

Environment: ``MOCK_XVNC_LOG`` appends one JSON line ``{"argv": [...], "env": {...}, "pid": N}``
per run; ``MOCK_XVNC_FAIL=early`` exits 1 before creating the socket (a server whose port is
taken), ``late`` exits 0 right after creating it (a server that dies).
"""
import contextlib
import json
import os
import signal
import socket
import struct
import sys
import threading

RFB_VERSION = b'RFB 003.008\n'
AUTH_NAME = b'MIT-MAGIC-COOKIE-1'
FLAGS = ('-AlwaysShared', '-AcceptSetDesktopSize')   # the options without a value


def parse_args(argv: list) -> tuple:
    number, options, i = None, {}, 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith(':'):
            number = int(arg[1:])
            i += 1
        elif arg in FLAGS or i + 1 >= len(argv):
            options[arg] = True
            i += 1
        else:
            options[arg] = argv[i + 1]
            i += 2
    return number, options


def cookie_of(path: str, number: int) -> bytes:
    """The data of the MIT-MAGIC-COOKIE-1 record of the display in an X authority file."""
    blob = open(path, 'rb').read()
    i = 0
    while i < len(blob):
        i += 2
        fields = []
        for _ in range(4):
            (n,) = struct.unpack_from('>H', blob, i)
            fields.append(blob[i + 2:i + 2 + n])
            i += 2 + n
        if fields[1] == str(number).encode() and fields[2] == AUTH_NAME:
            return fields[3]
    return b''


def serve(client: socket.socket):
    with client:
        with contextlib.suppress(OSError):
            client.sendall(RFB_VERSION)
            while True:
                data = client.recv(65536)
                if not data:
                    break
                client.sendall(data)


def main(argv: list, env: dict) -> int:
    number, options = parse_args(argv)
    if env.get('MOCK_XVNC_LOG'):
        with open(env['MOCK_XVNC_LOG'], 'a') as f:
            f.write(json.dumps({'argv': list(argv), 'env': dict(env), 'pid': os.getpid()}) + '\n')
    if number is None or '-rfbunixpath' not in options or '-auth' not in options:
        print("usage: Xvnc :N -rfbunixpath PATH -auth FILE ...", file=sys.stderr)
        return 2
    if env.get('MOCK_XVNC_FAIL') == 'early':
        print("Fatal server error: Cannot establish any listening sockets", file=sys.stderr)
        return 1
    if len(cookie_of(options['-auth'], number)) != 16:
        print(f"no 16-byte cookie for display :{number} in {options['-auth']}", file=sys.stderr)
        return 2
    path = options['-rfbunixpath']
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, int(options.get('-rfbunixmode', '0600'), 8))
    server.listen(8)

    def on_term(signum, frame):
        with contextlib.suppress(OSError):
            os.unlink(path)
        os._exit(0)

    signal.signal(signal.SIGTERM, on_term)
    print(f"mock Xvnc :{number} listening on {path}", file=sys.stderr, flush=True)
    if env.get('MOCK_XVNC_FAIL') == 'late':
        return 0
    while True:
        client, _ = server.accept()
        threading.Thread(target=serve, args=(client,), daemon=True).start()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], os.environ))
