"""
The console of a managed switch of the Podman engine (`src/SRE/engine/vde_console.py`): the text
protocol of the management socket of a `vde_switch`, spoken here to a small stand-in that answers
as the switch does (the answers were taken from a real one, and from the fixtures of the Kathara
fork in `tests/mock_data/switch/`).
"""
import os
import shutil
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from SRE.engine import vde_console
from SRE.engine.base import EngineError, SwitchCommandError
from SRE.engine.vde_console import Console, parse_ports, parse_reply

MOCK = Path(__file__).parent / 'mock_data' / 'switch'
BANNER = ("VDE switch V.2.3.3\n(C) Virtual Square Team (coord. R. Davoli) 2005,2006,2007 - GPLv2\n\n"
          "vde$ ")
PORTS = (
    "0000 DATA END WITH '.'\n"
    "Port 0001 untagged_vlan=0010 ACTIVE - NOT Unnamed Allocatable\n"
    " Current User: root Access Control: (User: NONE - Group: NONE)\n"
    "  -- endpoint ID 0003 module unix prog   : kathara pc1:eth0 user=root pid=592759\n"
    "Port 0002 untagged_vlan=0020 INACTIVE - NOT Unnamed Allocatable\n"
    " Current User: NONE Access Control: (User: NONE - Group: NONE)\n"
    ".\n"
    "1000 Success\n")


class FakeSwitch:
    """A management socket answering from `replies` (`{command: text sent before the prompt}`),
    `1038 Function not implemented` otherwise; `received` keeps the commands."""

    def __init__(self, replies=None, banner=BANNER):
        # a short path: the path of a unix socket is limited to about a hundred bytes
        self.directory = tempfile.mkdtemp(prefix='sre-vde-', dir='/tmp')
        self.path = os.path.join(self.directory, 'mgmt')
        self.replies = replies or {}
        self.banner = banner
        self.received = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        self._server.listen(4)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                connection, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(connection,), daemon=True).start()

    def _session(self, connection):
        with connection:
            connection.sendall(self.banner.encode())
            buffer = b""
            while True:
                try:
                    chunk = connection.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    command = line.decode()
                    self.received.append(command)
                    reply = self.replies.get(command, "1038 Function not implemented\n")
                    if reply is None:       # the switch goes away
                        return
                    connection.sendall(reply.encode() + b"\nvde$ ")

    def close(self):
        self._server.close()
        shutil.rmtree(self.directory, ignore_errors=True)


@pytest.fixture
def switch():
    fake = FakeSwitch({
        'vlan/create 10': "1000 Success\n",
        'vlan/create 20': "1017 File exists\n",
        'port/allprint': PORTS,
        'showinfo': "0000 DATA END WITH '.'\nVDE switch V.2.3.3\n\npid 1 MAC 00:ff:9d:30:70:1f uptime 11\n.\n1000 Success\n",
        'gone': None,
        'silent': "no status at all\n",
    })
    yield fake
    fake.close()


class TestParseReply:
    def test_success_without_text(self):
        assert parse_reply("1000 Success\n") == (1000, 'Success', '')

    def test_an_error_code_and_its_message(self):
        assert parse_reply("1017 File exists\n") == (1017, 'File exists', '')

    def test_text_then_status(self):
        assert parse_reply("0000 DATA END WITH '.'\nVLAN 0010\n -- Port 0001 tagged=0\n.\n1000 Success\n") == (
            1000, 'Success', "VLAN 0010\n -- Port 0001 tagged=0")

    def test_a_status_like_line_inside_the_text_is_text(self):
        assert parse_reply("0000 DATA END WITH '.'\n1017 looks like a status\n.\n1000 Success\n") == (
            1000, 'Success', '1017 looks like a status')

    def test_no_status(self):
        with pytest.raises(EngineError, match="no status"):
            parse_reply("garbage\n")


class TestParsePorts:
    def test_the_ports_of_a_real_switch(self):
        """What a switch of the Podman engine prints: the plug runs as root of its user namespace."""
        ports = parse_ports(parse_reply(PORTS)[2])
        assert ports == {1: {'vlan': 10, 'tagged_vlans': [], 'active': True, 'endpoints': ['pc1:eth0']},
                         2: {'vlan': 20, 'tagged_vlans': [], 'active': False, 'endpoints': []}}

    def test_the_fixtures_of_the_kathara_fork(self):
        """The same parser reads what the switches of the Docker plugin print (`user=0`, an
        endpoint without label, an external interface)."""
        ports = parse_ports((MOCK / 'port_allprint.txt').read_text(), (MOCK / 'vlan_allprint.txt').read_text())
        assert ports[1]['endpoints'] == ['r1:eth0'] and ports[2] == {
            'vlan': 10, 'tagged_vlans': ports[2]['tagged_vlans'], 'active': True, 'endpoints': ['pc2:eth0']}
        assert ports[3]['active'] is False and ports[3]['endpoints'] == []
        assert ports[5]['endpoints'] == ['kathara', 'vde_ext: eth1']
        assert all(isinstance(p['tagged_vlans'], list) for p in ports.values())

    def test_tagged_vlans(self):
        vlans = "VLAN 0010\n -- Port 0001 tagged=0 active=1\n -- Port 0002 tagged=1 active=1\nVLAN 0020\n -- Port 0002 tagged=1\n"
        ports = parse_ports("Port 0001 untagged_vlan=0010 ACTIVE\nPort 0002 untagged_vlan=0000 ACTIVE\n", vlans)
        assert ports[1]['tagged_vlans'] == [] and ports[2]['tagged_vlans'] == [10, 20]


class TestConsole:
    def test_a_command_and_its_text(self, switch):
        with Console(switch.path) as console:
            assert console.exec('vlan/create 10') == ''
            assert console.exec('showinfo').splitlines()[0] == 'VDE switch V.2.3.3'
            assert parse_ports(console.exec('port/allprint'))[1]['endpoints'] == ['pc1:eth0']
        assert switch.received == ['vlan/create 10', 'showinfo', 'port/allprint']     # one connection

    def test_a_refused_command_has_its_code_and_message(self, switch):
        with Console(switch.path) as console:
            with pytest.raises(SwitchCommandError) as error:
                console.exec('vlan/create 20')
        assert (error.value.code, error.value.message) == (1017, 'File exists')
        assert str(error.value) == '1017 File exists' and isinstance(error.value, EngineError)

    def test_an_unknown_command(self, switch):
        with Console(switch.path) as console:
            with pytest.raises(SwitchCommandError) as error:
                console.exec('nonsense')
        assert error.value.code == 1038

    @pytest.mark.parametrize('command', ['shutdown', 'load /etc/passwd', 'logout', '  shutdown now'])
    def test_commands_never_passed_to_a_switch(self, switch, command):
        """They would stop the switch, make it read a file of the host, or end the session."""
        with Console(switch.path) as console:
            with pytest.raises(SwitchCommandError) as error:
                console.exec(command)
        assert (error.value.code, error.value.message) == (1001, 'Operation not permitted')
        assert switch.received == []

    @pytest.mark.parametrize('command', ['', '   ', 'vlan/print\nshutdown', 'a\rb'])
    def test_a_command_is_one_line(self, switch, command):
        with Console(switch.path) as console:
            with pytest.raises(SwitchCommandError) as error:
                console.exec(command)
        assert error.value.code == 1022 and switch.received == []

    def test_a_switch_that_goes_away(self, switch):
        with Console(switch.path) as console:
            with pytest.raises(EngineError, match="closed its console"):
                console.exec('gone')

    def test_an_answer_without_status(self, switch):
        with Console(switch.path) as console:
            with pytest.raises(EngineError, match="no status"):
                console.exec('silent')

    def test_no_socket(self, tmp_path):
        with pytest.raises(EngineError, match="cannot be reached .*No such file"):
            Console(str(tmp_path / 'mgmt'))

    def test_a_file_that_is_not_a_socket(self, tmp_path):
        (tmp_path / 'mgmt').write_text('x')
        with pytest.raises(EngineError, match="is not the management socket of a switch"):
            Console(str(tmp_path / 'mgmt'))

    def test_a_socket_of_somebody_else(self, switch):
        """The process may be root, and the path is in a directory of the account."""
        with pytest.raises(EngineError, match="is not the management socket of a switch"):
            Console(switch.path, owner_uid=os.getuid() + 1)
        with Console(switch.path, owner_uid=os.getuid()) as console:
            assert console.exec('vlan/create 10') == ''

    def test_a_socket_nobody_listens_on(self):
        directory = tempfile.mkdtemp(prefix='sre-vde-', dir='/tmp')
        try:
            path = os.path.join(directory, 'mgmt')
            dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            dead.bind(path)
            dead.close()
            with pytest.raises(EngineError, match="cannot be reached"):
                Console(path)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_the_names_the_engine_uses(self):
        assert vde_console.ENDPOINT_PREFIX == 'kathara ' and vde_console.SUCCESS_CODE == 1000
