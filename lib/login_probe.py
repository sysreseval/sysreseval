#!/usr/bin/env python3
"""Interactive password login tester (stdlib only), copied into a container by the labs.

``login_probe.py su USER PASSWORD`` runs ``su - USER`` as the unprivileged user ``student`` in a
pseudo-terminal (``su`` run by root asks no password: ``pam_rootok``), answers the password prompt
and reports what the session printed; ``login_probe.py ssh HOST USER PASSWORD`` does the same with
an ``ssh`` password login (keyboard-interactive / password only, no host key check).  The session
runs :data:`SESSION_SCRIPT`: a marker line, the login name, the home directory and whether it
exists (``pam_mkhomedir``).  One JSON document on stdout: ``{"ok", "login", "home",
"home_exists", "prompted", "exit", "timeout", "output"}``.

Options: ``--timeout S`` (default 20), ``--as USER`` (the user running ``su``, default
``student``), ``--port N`` (ssh).
"""
import json
import os
import pty
import select
import signal
import sys
import time

MARK = "SRE_LOGIN_OK"
SESSION_SCRIPT = (f'echo {MARK}; echo LOGIN=$(id -un); echo HOME=$HOME; '
                  f'if [ -d "$HOME" ]; then echo HOME_EXISTS=1; else echo HOME_EXISTS=0; fi')
PROMPT = b"assword"


def run(argv, password, timeout=20.0):
    """Run *argv* in a pty, answer the first password prompt, return the decoded output, the exit
    status (None when killed on timeout) and whether a prompt was seen."""
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - child
        os.execvp(argv[0], argv)
    out = b""
    prompted = False
    timed_out = False
    status = None
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if fd in ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                if not prompted and PROMPT in out:
                    prompted = True
                    os.write(fd, password.encode() + b"\n")
            else:
                wpid, wstatus = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    status = wstatus
                    # drain what is left
                    while True:
                        ready, _, _ = select.select([fd], [], [], 0.2)
                        if fd not in ready:
                            break
                        try:
                            chunk = os.read(fd, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        out += chunk
                    break
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                _, status = os.waitpid(pid, 0)
            except ChildProcessError:
                status = None
        os.close(fd)
    code = None
    if status is not None and not timed_out:
        code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status >> 8
    return out.decode("utf-8", errors="replace"), code, prompted, timed_out


def parse_session(text):
    """The fields printed by :data:`SESSION_SCRIPT` (``''`` / None when absent)."""
    login = home = ""
    home_exists = None
    seen = False
    for line in text.replace("\r", "").splitlines():
        line = line.strip()
        if line == MARK:
            seen = True
        elif line.startswith("LOGIN="):
            login = line[6:]
        elif line.startswith("HOME="):
            home = line[5:]
        elif line.startswith("HOME_EXISTS="):
            home_exists = line.endswith("1")
    return seen, login, home, home_exists


def main(argv):
    timeout = 20.0
    as_user = "student"
    port = 22
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--timeout":
            timeout = float(argv[i + 1])
            i += 2
        elif a == "--as":
            as_user = argv[i + 1]
            i += 2
        elif a == "--port":
            port = int(argv[i + 1])
            i += 2
        else:
            args.append(a)
            i += 1
    if not args:
        print("usage: login_probe.py su USER PASSWORD | ssh HOST USER PASSWORD", file=sys.stderr)
        return 2
    mode = args[0]
    if mode == "su" and len(args) == 3:
        user, password = args[1], args[2]
        cmd = ["runuser", "-u", as_user, "--", "su", "-", user, "-c", SESSION_SCRIPT]
    elif mode == "ssh" and len(args) == 4:
        host, user, password = args[1], args[2], args[3]
        cmd = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "LogLevel=ERROR", "-o", "PreferredAuthentications=password,keyboard-interactive",
               "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5",
               f"{user}@{host}", SESSION_SCRIPT]
    else:
        print("usage: login_probe.py su USER PASSWORD | ssh HOST USER PASSWORD", file=sys.stderr)
        return 2
    output, code, prompted, timed_out = run(cmd, password, timeout)
    seen, login, home, home_exists = parse_session(output)
    result = {
        "ok": seen and code == 0,
        "login": login,
        "home": home,
        "home_exists": home_exists,
        "prompted": prompted,
        "exit": code,
        "timeout": timed_out,
        "output": output[-4000:],
    }
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
