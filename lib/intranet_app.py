#!/usr/bin/env python3
"""A small intranet web application with a login form (stdlib only), copied into a container by the
fail2ban part of the Suricata / fail2ban lab.

``intranet_app.py [--port 80] [--users /etc/intranet/users.json] [--log /var/log/intranet/auth.log]``

- ``GET /``: the login form; ``GET /health``: ``OK`` (the supervision of the network polls it);
- ``POST /login`` (form fields ``user`` and ``password``): ``200`` and ``Bienvenue <user>`` when the
  pair is in the users file (a JSON object ``{"user": "password"}``), ``401`` otherwise.

Every login attempt appends one line to the log file, in local time::

    2026-11-23 15:30:12 FAILED login user=alice from=203.0.113.9
    2026-11-23 15:30:14 OK login user=bob from=203.0.113.10

and every health check ``... INFO health check from=<address>``.  The user name is written as the
client typed it (the classic mistake that makes a log injectable: ``user=x from=10.0.0.1``), except
for control characters, replaced by ``?``, and a length cut at 64 characters, so that a request can
never forge a whole line.  The client address is the peer address of the TCP connection.
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

FORM = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Intranet</title></head>
<body><h1>Intranet</h1>
<form method="post" action="/login">
<p><label>Utilisateur <input name="user"></label></p>
<p><label>Mot de passe <input name="password" type="password"></label></p>
<p><button type="submit">Connexion</button></p>
</form></body></html>
"""

_lock = threading.Lock()


def clean_user(user: str) -> str:
    """The user name as logged: control characters replaced by ``?``, at most 64 characters."""
    return "".join(c if c.isprintable() else "?" for c in user)[:64]


def log_line(event: str, user, address: str) -> str:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if event == "health":
        return f"{stamp} INFO health check from={address}\n"
    return f"{stamp} {event} login user={clean_user(user)} from={address}\n"


def make_handler(users: dict, log_path: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        server_version = "intranet/1.0"

        def log_message(self, *args):
            pass

        def _write_log(self, line: str) -> None:
            with _lock, open(log_path, "a", encoding="utf-8") as f:
                f.write(line)

        def _send(self, code: int, body: str, ctype: str = "text/plain; charset=utf-8") -> None:
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.split("?")[0] == "/health":
                self._write_log(log_line("health", None, self.client_address[0]))
                self._send(200, "OK\n")
            else:
                self._send(200, FORM, "text/html; charset=utf-8")

        def do_POST(self):
            if self.path.split("?")[0] != "/login":
                self._send(404, "Not found\n")
                return
            length = min(int(self.headers.get("Content-Length") or 0), 65536)
            fields = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            user = (fields.get("user") or [""])[0]
            password = (fields.get("password") or [""])[0]
            ok = user in users and users[user] == password
            self._write_log(log_line("OK" if ok else "FAILED", user, self.client_address[0]))
            if ok:
                self._send(200, f"Bienvenue {clean_user(user)}\n")
            else:
                self._send(401, "Identifiants incorrects\n")

    return Handler


def main(argv) -> int:
    port, users_path, log_path = 80, "/etc/intranet/users.json", "/var/log/intranet/auth.log"
    i = 0
    while i < len(argv):
        if argv[i] == "--port":
            port = int(argv[i + 1])
        elif argv[i] == "--users":
            users_path = argv[i + 1]
        elif argv[i] == "--log":
            log_path = argv[i + 1]
        else:
            print(f"unknown option {argv[i]}", file=sys.stderr)
            return 2
        i += 2
    with open(users_path, encoding="utf-8") as f:
        users = json.load(f)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(users, log_path)).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
