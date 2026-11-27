"""The management console of a ``vde_switch``: the text protocol of its management socket.

A managed switch of the Podman engine is a ``vde_switch`` started with ``-M <socket>``.  A command
is one line of text (``vlan/create 10``); the switch answers with an optional block of text and a
status line made of a code (1000 on success, 1000 + an errno otherwise) and a message, then its
prompt.  This is the protocol Kathara's own client speaks to the switches of its network plugin:
the outputs, and so what ``lib/switch.py`` parses, are the same with both engines.
"""
import errno
import os
import re
import socket
import stat

from .base import EngineError, SwitchCommandError

SUCCESS_CODE = 1000
# What an engine plugs is described "kathara <machine>:eth<N>", as the Kathara network plugin does.
ENDPOINT_PREFIX = "kathara "
# Never passed to a switch: they would stop it, make it read a file of the host, or end the session.
FORBIDDEN_COMMANDS = ("shutdown", "load", "logout")

_PROMPT = b"\nvde$ "
_DATA_BEGIN = "0000 DATA END WITH"
_DATA_END = "."
_TIMEOUT = 5.0   # seconds
_STATUS = re.compile(r"^(1\d{3})(?: (.*))?$")
_PORT = re.compile(r"^Port (\d+) untagged_vlan=(\d+) (IN)?ACTIVE")
_ENDPOINT = re.compile(r"^\s*-- endpoint ID \d+ module [^:]*: (.*?)(?: user=\S+ pid=\d+.*)?$")
_VLAN = re.compile(r"^VLAN (\d+)")
_VLAN_PORT = re.compile(r"^\s*-- Port (\d+) tagged=(\d)")


def parse_reply(reply: str) -> tuple[int, str, str]:
    """``(code, message, printed text)`` of the answer to one command."""
    code, message, lines, in_data = None, "", [], False
    for line in reply.splitlines():
        if in_data:
            if line == _DATA_END:
                in_data = False
            else:
                lines.append(line)
        elif line.startswith(_DATA_BEGIN):
            in_data = True
        else:
            status = _STATUS.match(line)
            if status:
                code, message = int(status.group(1)), status.group(2) or ""
    if code is None:
        raise EngineError(f"the switch gave no status in its answer: {reply.strip()[:200]!r}")
    return code, message, "\n".join(lines)


def parse_ports(ports_output: str, vlans_output: str = "") -> dict:
    """The ports of a switch from what ``port/allprint`` and ``vlan/allprint`` print:
    ``{port number: {'vlan': untagged VLAN, 'tagged_vlans': [...], 'active': bool, 'endpoints':
    ['<machine>:eth<N>', ...]}}`` (the endpoints without their ``kathara`` prefix)."""
    ports: dict = {}
    port = None
    for line in ports_output.splitlines():
        found = _PORT.match(line)
        if found:
            port = ports[int(found.group(1))] = {'vlan': int(found.group(2)), 'tagged_vlans': [],
                                                 'active': not found.group(3), 'endpoints': []}
            continue
        found = _ENDPOINT.match(line)
        if found and port is not None:
            description = found.group(1).strip()
            if description.startswith(ENDPOINT_PREFIX):
                description = description[len(ENDPOINT_PREFIX):]
            port['endpoints'].append(description)
    vlan = None
    for line in vlans_output.splitlines():
        found = _VLAN.match(line)
        if found:
            vlan = int(found.group(1))
            continue
        found = _VLAN_PORT.match(line)
        if found and vlan is not None and int(found.group(1)) in ports and found.group(2) == "1":
            ports[int(found.group(1))]['tagged_vlans'].append(vlan)
    return ports


class Console:
    """One connection to the management socket *path* of a switch (a context manager).  The socket
    must be a socket owned by *owner_uid*: the process may be root, and the path is in a directory
    of an unprivileged account."""

    def __init__(self, path: str, owner_uid: int | None = None, timeout: float = _TIMEOUT):
        self.path = path
        self._socket = None
        try:
            status = os.lstat(path)
            if not stat.S_ISSOCK(status.st_mode) or (owner_uid is not None and status.st_uid != owner_uid):
                raise EngineError(f"{path} is not the management socket of a switch")
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.settimeout(timeout)
            self._socket.connect(path)
            self._read()    # the banner of the switch
        except OSError as e:
            self.close()
            raise EngineError(f"the console of the switch cannot be reached ({path}): {e.strerror or e}") from None
        except EngineError:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def _read(self) -> str:
        """What the switch sends up to its next prompt."""
        data = b""
        while not data.endswith(_PROMPT):
            chunk = self._socket.recv(4096)
            if not chunk:
                raise EngineError(f"the switch closed its console ({self.path})")
            data += chunk
        return data[:-len(_PROMPT)].decode('utf-8', errors='replace')

    def exec(self, command: str) -> str:
        """Run one command and return what it printed.  A command the switch refuses, and one
        that is never passed to it, raise :class:`SwitchCommandError` (code 1000 + errno)."""
        command = command.strip()
        if not command or '\n' in command or '\r' in command:
            raise SwitchCommandError(SUCCESS_CODE + errno.EINVAL, "A command is a single line of text.")
        if command.split()[0] in FORBIDDEN_COMMANDS:
            raise SwitchCommandError(SUCCESS_CODE + errno.EPERM, "Operation not permitted")
        try:
            self._socket.sendall(f"{command}\n".encode('utf-8'))
            reply = self._read()
        except OSError as e:
            raise EngineError(f"the console of the switch does not answer ({self.path}): {e.strerror or e}") from None
        code, message, output = parse_reply(reply)
        if code != SUCCESS_CODE:
            raise SwitchCommandError(code, message)
        return output
