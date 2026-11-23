#!/usr/bin/env python3
"""The asset inventory service of the scanning and hardening lab (stdlib only), copied into a
container: the service the students write an NSE script for.

``asset_service.py --port 7070 --asset ID --serial S --owner NAME [--bind ADDR] [--lifetime SECONDS]
[--pidfile FILE]``

A line protocol over TCP.  On connection the server sends its greeting::

    SRE-ASSET 1.2 ready

then reads one command per line (``\\r\\n`` or ``\\n``; the case of the command does not matter):

- ``INVENTORY``: ``asset=<ID>;serial=<S>;owner=<NAME>``, then the connection is closed;
- ``HELP``: ``commands: INVENTORY HELP QUIT``;
- ``QUIT``: ``bye``, then the connection is closed;
- anything else: ``ERR unknown command``.

A client that sends nothing for 10 seconds is disconnected.  With ``--lifetime`` the server exits
after that many seconds (the grader starts a fresh instance with a new serial at every evaluation
and lets it end by itself).  The process detaches itself (double fork, standard streams on
``/dev/null``): a state or a test may start it with a plain command.
"""
import argparse
import os
import socket
import sys
import threading
import time

GREETING = "SRE-ASSET 1.2 ready"
IDLE_TIMEOUT = 10


def answer(command: str, asset: str, serial: str, owner: str):
    """``(reply, close)`` for one command line."""
    word = command.strip().upper()
    if word == "INVENTORY":
        return f"asset={asset};serial={serial};owner={owner}", True
    if word == "HELP":
        return "commands: INVENTORY HELP QUIT", False
    if word == "QUIT":
        return "bye", True
    return "ERR unknown command", False


def serve_client(conn: socket.socket, asset: str, serial: str, owner: str) -> None:
    conn.settimeout(IDLE_TIMEOUT)
    try:
        conn.sendall((GREETING + "\r\n").encode())
        buffer = b""
        while True:
            data = conn.recv(1024)
            if not data:
                return
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                reply, close = answer(line.decode(errors="replace"), asset, serial, owner)
                conn.sendall((reply + "\r\n").encode())
                if close:
                    return
            if len(buffer) > 4096:
                return
    except OSError:
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


def detach() -> None:
    if os.fork() != 0:
        os._exit(0)
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="asset inventory service")
    parser.add_argument("--port", type=int, default=7070)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--asset", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--lifetime", type=float, default=0)
    parser.add_argument("--pidfile", default="")
    parser.add_argument("--foreground", action="store_true")
    args = parser.parse_args(argv)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.bind, args.port))
    server.listen(16)
    if not args.foreground:
        detach()
    if args.pidfile:
        with open(args.pidfile, "w") as f:
            f.write(f"{os.getpid()}\n")
    if args.lifetime > 0:
        threading.Timer(args.lifetime, lambda: os._exit(0)).start()
    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            time.sleep(0.1)
            continue
        threading.Thread(target=serve_client, args=(conn, args.asset, args.serial, args.owner),
                         daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
