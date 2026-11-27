"""
Podman integration tests of the lab lifecycle with REAL containers: the counterpart of
`test_docker_lifecycle.py` on a host whose engine is the Podman one.

Each test drives the CLI of the tree that provides the SRE package (`src/sre.py`, run with the
current interpreter as root, and as a student for the user-mode commands), then asks Podman and
the user manager of the sre account what is left: containers, units (the hubs and the plugs of
the interfaces), the directory of the networks.

Requirements — the module is skipped otherwise: run as root, on a host whose engine is Podman
(`container_engine` or `container_engine_by_host` of `params.py`) and that
`scripts/podman-setup.sh` prepared, with the switch program (`make vde-switch`), pasta, the
address `params.sre_host_ip` on the host (Docker's bridge has it), the images of the labs (pulled
by the first start) and a writable directory listed in `params.authorized_src_dir` (the temporary
labs are written there).  Excluded from `make tests`; run with `make podman-tests`.
"""
import json
import os
import pty
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from SRE import params
from net_config import REMOUNT_PROC_SYS_CMD

# Skipped as a whole (one line of the `-ra` summary), like the Docker lifecycle tests.  The
# engine of the host is read here, when the module is collected: the fixture of conftest.py
# gives every test the Kathara engine.
if os.geteuid() != 0:
    pytest.skip("Podman lifecycle tests must run as root", allow_module_level=True)
try:
    _HOST_ENGINE = params.host_container_engine()
except ValueError as e:
    pytest.skip(str(e), allow_module_level=True)
if _HOST_ENGINE != params.container_engine_podman:
    pytest.skip("the container engine of this host is not Podman (container_engine / container_engine_by_host)",
                allow_module_level=True)

from SRE.engine.podman_engine import PodmanEngine, lab_hash_of  # noqa: E402
from test_docker_lifecycle import (  # noqa: E402, F401  (no_exam: a fixture)
    DMZ_PC1, DMZ_R1, DMZ_SRV, FAILING_PRIVILEGED_LAB, HUB_LAB, INSTRUCTOR_LAB, IPV6_LAB, NON_PRIVILEGED_LAB,
    OLD_PC3, OLD_SRV, PC1, PC2, PC3, PRIVILEGED_INSTRUCTOR_LAB, PRIVILEGED_LAB, PROJECTS, R1_VLAN10,
    ROOT_OWNED_DIRS_CMD, SHARED_LAB, SRE_PY, SWITCH_LAB, _info, _lab_hash, _project_dirs, _sre, _sre_user,
    _user_public_dir, no_exam)

ENGINE = PodmanEngine()     # asked as root: its commands run as the sre account, like those of the CLI
START_TIMEOUT = 1800        # seconds: the first start pulls the image and copies it for the uid range

# fails in its initial state, once the machines run
FAILING_LAB = NON_PRIVILEGED_LAB.replace(
    "        self.cmd('router', 'echo from-initial > /root/from_initial')",
    "        raise RuntimeError('deliberate failure after deploy')")
# its image does not exist: the deployment itself fails, after the hub is started
MISSING_IMAGE_LAB = NON_PRIVILEGED_LAB.replace(
    "_machine_specs = {'router': {}, 'client': {}}",
    "_machine_specs = {'router': {}, 'client': {'image': 'sysreseval/no-such-image-for-the-tests:0'}}")
# what a machine may be given: a start-up command, sysctls (one of an interface), variables, a limit
OPTIONS_LAB = NON_PRIVILEGED_LAB.replace(
    "_machine_specs = {'router': {}, 'client': {}}",
    """_machine_specs = {
        'router': {'exec_commands': ["echo 'started by the lab' > /root/exec_command"],
                   'sysctls': ('net.ipv4.ip_forward=0', 'net.ipv4.conf.eth0.rp_filter=2'),
                   'envs': {'LAB_VARIABLE=a value': True}, 'ulimits': {'nofile=1234:1234': True}},
        'client': {},
    }""")
assert 'deliberate failure' in FAILING_LAB and 'no-such-image' in MISSING_IMAGE_LAB and 'exec_commands' in OPTIONS_LAB

# gw has one lab interface (eth0), so its outside interface is eth1, and a port published in a
# range of a hundred; pc1 reaches the outside through the NAT of gw
OUTSIDE_LAB = '''
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state

title = "podman lifecycle test (outside interface)"


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        return cls()


class NetScheme(NetScheme0):
    _machine_specs = {'gw': {'bridged': True, 'ports': ['184XX:80/tcp']}, 'pc1': {}}
    _topology = {'lan': ['gw', 'pc1']}

    @sre_state()
    def initial(self):
        self.cmd('gw', 'ip addr add 10.97.0.1/24 dev eth0')
        self.cmd('gw', 'iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE')
        self.cmd('pc1', 'ip addr add 10.97.0.2/24 dev eth0')
        self.cmd('pc1', 'ip route add default via 10.97.0.1')


class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='dummy', grade=0, max_grade=1)
'''


# ---------------------------------------------------------------------------
# What Podman and the user manager have
# ---------------------------------------------------------------------------

def _containers(lab_hash=None):
    """`{machine: its row of podman ps}` for one project, or every container of the engine."""
    return {c['Labels'].get('name') if lab_hash else c['Names'][0]: c for c in ENGINE._containers(lab_hash)}


def _units(lab_hash=''):
    """The units of the engine (of one project) the user manager still knows, whatever their state."""
    result = ENGINE.run(['systemctl', '--user', 'list-units', '--all', '--plain', '--no-legend',
                         f'srelab-{lab_hash}*'])
    return sorted(line.split()[0] for line in result.stdout.decode().splitlines() if line.strip())


def _leftovers(lab_hash):
    """Everything that still belongs to a project."""
    directory = Path(ENGINE._network_dir(lab_hash))
    return sorted(c['Names'][0] for c in _containers(lab_hash).values()) + _units(lab_hash + '-') \
        + ([str(directory)] if directory.exists() else [])


def _everything():
    directory = Path(ENGINE._network_dir())
    return (sorted(_containers()), _units(), sorted(p.name for p in directory.iterdir()) if directory.is_dir() else [])


def _run(running_lab_name, machine, command):
    """`sre exec` of a shell command: ``(exit status, stdout)``."""
    r = _sre('exec', running_lab_name, machine, 'sh', '-c', command)
    return r.returncode, r.stdout


def _host_uid(lab_hash, machine):
    """The uid, on the host, of the first process of a machine (root inside it)."""
    result = ENGINE.podman(['top', ENGINE._container_name(lab_hash, machine), 'huser'])
    assert result.returncode == 0, result.stderr
    return int(result.stdout.split()[1])


def _wait_started(running_lab_name, machine):
    """The start-up work of a machine is done (it runs detached, as with Kathara)."""
    for _ in range(60):
        if _run(running_lab_name, machine, 'test -e /tmp/EOS')[0] == 0:
            return
        time.sleep(0.5)
    pytest.fail(f"{machine} never finished its start-up work")


@pytest.fixture(scope='module')
def labs_dir():
    base = next((d for d in params.authorized_src_dir if os.path.isdir(d) and os.access(d, os.W_OK)), None)
    if base is None:
        pytest.skip(f"no writable directory in params.authorized_src_dir {params.authorized_src_dir}")
    d = Path(tempfile.mkdtemp(prefix='sre-podman-tests-', dir=base))
    d.chmod(0o755)
    for name, text in (('non_privileged.py', NON_PRIVILEGED_LAB), ('privileged.py', PRIVILEGED_LAB),
                       ('shared.py', SHARED_LAB), ('ipv6.py', IPV6_LAB), ('hubs.py', HUB_LAB),
                       ('instructor.py', INSTRUCTOR_LAB), ('failing.py', FAILING_LAB),
                       ('missing_image.py', MISSING_IMAGE_LAB), ('options.py', OPTIONS_LAB),
                       ('outside.py', OUTSIDE_LAB), ('failing_privileged.py', FAILING_PRIVILEGED_LAB),
                       ('instructor_privileged.py', PRIVILEGED_INSTRUCTOR_LAB)):
        (d / name).write_text(text)
    shutil.copy(SWITCH_LAB, d / 'switch_modes.py')
    for f in d.iterdir():
        f.chmod(0o644)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def projects():
    """Registry of the projects a test creates; whatever is left is stopped and removed, so a
    failing test leaks nothing."""
    created = []
    yield created
    for running_lab_name, lab_hash in created:
        project_dir = PROJECTS / running_lab_name
        if project_dir.exists():
            user_public_dir = _user_public_dir(running_lab_name)
            _sre('stop', running_lab_name)
            shutil.rmtree(project_dir, ignore_errors=True)
            if user_public_dir is not None:
                shutil.rmtree(user_public_dir, ignore_errors=True)
        ENGINE.remove_leftovers(lab_hash, [])


def _start(projects, lab_path, *options):
    before = _project_dirs()
    r = _sre('start', *options, '-p', str(lab_path), timeout=START_TIMEOUT)
    assert r.returncode == 0, f"sre start failed:\n{r.stderr[-3000:]}"
    new = _project_dirs() - before
    assert len(new) == 1, f"expected exactly one new project, got {new}"
    running_lab_name = new.pop()
    lab_hash = _lab_hash(running_lab_name)
    projects.append((running_lab_name, lab_hash))
    return running_lab_name, lab_hash


def _stop(running_lab_name, lab_hash):
    r = _sre('stop', running_lab_name)
    assert r.returncode == 0, r.stderr
    assert _leftovers(lab_hash) == [], "left after sre stop"
    assert not (PROJECTS / running_lab_name).exists()


# ---------------------------------------------------------------------------
# sre start / sre stop
# ---------------------------------------------------------------------------

class TestStartStop:

    def test_start_then_stop_leaves_nothing(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        assert lab_hash == lab_hash_of(running_lab_name), "info.json holds the hash Kathara would give"

        containers = _containers(lab_hash)
        assert set(containers) == {'router', 'client'}
        assert all(c['State'] == 'running' for c in containers.values())
        # one hub, one plug per interface, all running; the directory of the network
        assert _units(lab_hash + '-') == [f'srelab-{lab_hash}-p-client-0.service', f'srelab-{lab_hash}-p-router-0.service',
                                          f'srelab-{lab_hash}-sw-0.service']
        assert Path(ENGINE._network_dir(lab_hash, 0), 'ctl').exists()
        # the `initial` state ran in the machine
        assert _run(running_lab_name, 'router', 'cat /root/from_initial') == (0, 'from-initial\n')

        _stop(running_lab_name, lab_hash)

    def test_the_progress_of_a_start(self, labs_dir, projects):
        """What the GUI and the web agent read on stderr."""
        r = _sre('start', '-p', str(labs_dir / 'non_privileged.py'), timeout=START_TIMEOUT)
        assert r.returncode == 0, r.stderr
        events = [json.loads(line) for line in r.stderr.splitlines() if line.startswith('{')]
        created = [e for e in events if e.get('phase') == 'project']
        assert len(created) == 1
        running_lab_name = created[0]['running_lab_name']
        projects.append((running_lab_name, _lab_hash(running_lab_name)))
        deploy = [e for e in events if e.get('phase') == 'deploy']
        assert deploy[0] == {'phase': 'deploy', 'status': 'start', 'total': 2}
        assert sorted(e['machine'] for e in deploy[1:-1]) == ['client', 'router']
        assert [e['current'] for e in deploy[1:-1]] == [1, 2] and deploy[-1]['status'] == 'end'

    def test_the_root_of_a_machine_is_nobody_on_the_host(self, labs_dir, projects):
        """Neither root nor the sre account: an id of the subordinate range of the account."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        assert _run(running_lab_name, 'router', 'id -u') == (0, '0\n')
        host_uid = _host_uid(lab_hash, 'router')
        assert host_uid not in (0, params.sre_uid) and host_uid > 65535, host_uid
        assert _host_uid(lab_hash, 'client') == host_uid, "one range for the machines of a project"

    def test_two_projects_have_two_uid_ranges(self, labs_dir, projects):
        first, first_hash = _start(projects, labs_dir / 'non_privileged.py')
        time.sleep(1)       # a running lab name holds the second of its start
        second, second_hash = _start(projects, labs_dir / 'non_privileged.py')
        ranges = {h: {c['Labels']['uid_range'] for c in _containers(h).values()} for h in (first_hash, second_hash)}
        assert all(len(r) == 1 for r in ranges.values()) and ranges[first_hash] != ranges[second_hash], ranges
        assert abs(_host_uid(first_hash, 'router') - _host_uid(second_hash, 'router')) >= 65536
        _stop(first, first_hash)
        # the second project is untouched by the stop of the first
        assert _run(second, 'router', 'cat /root/from_initial') == (0, 'from-initial\n')
        assert len(_units(second_hash + '-')) == 3


class TestUserNamespace:
    def test_the_first_start_after_a_boot_makes_it_again(self, labs_dir, projects):
        """The user namespace of Podman does not survive a boot, and the `sre` command cannot
        make it by itself when `docker_gid` is not the primary group of the account (`newuidmap`
        refuses): the engine has the user manager make it.  A boot is played by ending the
        pause process that holds the namespace, when no container of the engine uses it."""
        if _containers():
            pytest.skip("containers of the engine are running in the user namespace")
        assert ENGINE.podman(['info']).returncode == 0
        pid_file = Path(ENGINE._runtime_dir, 'libpod', 'tmp', 'pause.pid')
        pid = int(pid_file.read_text())
        os.kill(pid, signal.SIGKILL)
        for _ in range(50):
            if not os.path.exists(f'/proc/{pid}'):
                break
            time.sleep(0.1)
        assert not ENGINE._namespace_alive()

        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        assert ENGINE._namespace_alive() and int(pid_file.read_text()) != pid
        assert _run(running_lab_name, 'router', 'cat /root/from_initial') == (0, 'from-initial\n')
        _stop(running_lab_name, lab_hash)


class TestMachine:
    """A machine is what Kathara makes on Docker."""

    def test_as_kathara_starts_it(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        _wait_started(running_lab_name, 'router')
        rc, out = _run(running_lab_name, 'router', '; '.join([
            'hostname', 'cat /etc/hosts', 'echo "resolv.conf: $(wc -c < /etc/resolv.conf) bytes"',
            'echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"',
            'echo "rp_filter=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)$(cat /proc/sys/net/ipv4/conf/eth0/rp_filter)"',
            'echo "icmp_ratelimit=$(cat /proc/sys/net/ipv4/icmp_ratelimit)"',
            'echo "disable_ipv6=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)$(cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6)"',
            'echo "pids.max=$(cat /sys/fs/cgroup/pids.max)"',
            f'echo "lab=${params.sre_name_env_variable}"',
            'echo "eth0: $(cat /sys/class/net/eth0/operstate) $(cat /sys/class/net/eth0/mtu)"',
            'test -c /dev/net/tun && echo tun', 'test -d /shared && test -d /hosthome && echo image-volumes',
            'test -w /proc/sys/net/ipv4/ip_forward || echo "proc/sys read-only"',
        ]))
        assert rc == 0, out
        lines = out.splitlines()
        assert lines[0] == 'router'
        assert lines[1:4] == ['127.0.0.1 localhost', '::1 localhost', '127.0.1.1 router']
        assert lines[4:] == [
            'resolv.conf: 0 bytes', 'ip_forward=1', 'rp_filter=00', 'icmp_ratelimit=0', 'disable_ipv6=11',
            'pids.max=max', f'lab={params.get_abbreviated_lab_name_from_running_lab_name(running_lab_name)}',
            'eth0: up 1500', 'tun', 'image-volumes',
            'proc/sys read-only',       # as under Docker: the states remount it (REMOUNT_PROC_SYS_CMD)
        ], out

    def test_an_ordinary_user_pings_and_binds_port_80(self, labs_dir, projects):
        """Docker sets both sysctls by itself; the engine does it."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        rc, out = _run(running_lab_name, 'router', "setpriv --reuid 65534 --regid 65534 --clear-groups sh -c '"
                                                   "ping -c 1 -W 1 -q 127.0.0.1 >/dev/null && echo ping; "
                                                   "python3 -c \"import socket; socket.socket().bind((str(), 80))\" && echo bind'")
        assert (rc, out) == (0, 'ping\nbind\n')

    def test_the_options_of_a_machine(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'options.py')
        _wait_started(running_lab_name, 'router')
        rc, out = _run(running_lab_name, 'router', '; '.join([
            'cat /root/exec_command', 'cat /var/log/startup.log', 'cat /proc/sys/net/ipv4/ip_forward',
            'cat /proc/sys/net/ipv4/conf/eth0/rp_filter', 'echo "$LAB_VARIABLE"', 'ulimit -n']))
        assert (rc, out.splitlines()) == (0, ['started by the lab', "++ echo 'started by the lab' > /root/exec_command",
                                              '0', '2', 'a value', '1234']), out
        # the other machine keeps the defaults
        assert _run(running_lab_name, 'client', 'cat /proc/sys/net/ipv4/ip_forward') == (0, '1\n')

    def test_sysctls_are_writable_after_the_remount_of_the_states(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        rc, out = _run(running_lab_name, 'router', f'{REMOUNT_PROC_SYS_CMD} && sysctl -w net.ipv4.ip_forward=1 '
                                                   '&& sysctl -w net.ipv4.ip_forward=0 && cat /proc/sys/net/ipv4/ip_forward')
        assert rc == 0 and out.strip().endswith('0'), out

    def test_ipv6_follows_the_lab(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'ipv6.py')
        flag = 'cat /proc/sys/net/ipv6/conf/all/disable_ipv6 /proc/sys/net/ipv6/conf/eth0/disable_ipv6'
        assert _run(running_lab_name, 'r', flag) == (0, '0\n0\n')
        assert _run(running_lab_name, 'h4', flag) == (0, '1\n1\n')
        assert _run(running_lab_name, 'r', 'cat /proc/sys/net/ipv6/conf/all/forwarding')[1] == '1\n'
        for _ in range(10):     # duplicate address detection
            rc, out = _run(running_lab_name, 'h', 'ping -6 -c 1 -W 1 fd00:1::1')
            if rc == 0:
                break
            time.sleep(1)
        assert rc == 0, out


# ---------------------------------------------------------------------------
# Networks
# ---------------------------------------------------------------------------

def _sees_traffic(running_lab_name, sniffer, interface, source, source_ip, dest_ip):
    """True when *sniffer* captures on *interface* an echo request *source* sends to *dest_ip*
    (tcpdump ends with status 0 at the first one, `timeout` with 124 when none came)."""
    assert _run(running_lab_name, source, f'ping -c 1 -W 2 {dest_ip}')[0] == 0, f"{source_ip} does not reach {dest_ip}"
    capture = subprocess.Popen(
        [sys.executable, '-W', 'ignore', str(SRE_PY), 'exec', running_lab_name, sniffer, 'sh', '-c',
         f"timeout 10 tcpdump -n -i {interface} -c 1 "
         f"'icmp[icmptype] == icmp-echo and src host {source_ip} and dst host {dest_ip}' >/dev/null 2>&1"],
        env=dict(os.environ, LOGNAME='root'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)   # tcpdump is listening
    _run(running_lab_name, source, f'ping -c 8 -i 0.5 -w 5 {dest_ip}')
    code = capture.wait(timeout=60)
    assert code in (0, 124), f"capture on {interface} failed: status {code}"
    return code == 0


class TestHub:
    def test_a_third_machine_sees_the_traffic_of_two_others(self, labs_dir, projects):
        """Every network is a hub: two networks, two switches, the frames of each on its own."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'hubs.py')
        assert [u for u in _units(lab_hash + '-') if '-sw-' in u] == [f'srelab-{lab_hash}-sw-0.service',
                                                                      f'srelab-{lab_hash}-sw-1.service']
        assert _sees_traffic(running_lab_name, 'c', 'eth0', 'a', '10.98.1.1', '10.98.1.2')
        assert _sees_traffic(running_lab_name, 'c', 'eth1', 'a', '10.98.2.1', '10.98.2.2')
        # the two networks are apart: nothing of net2 on the interface of net1
        assert not _sees_traffic(running_lab_name, 'c', 'eth0', 'a', '10.98.2.1', '10.98.2.2')

    def test_a_hub_carries_large_frames(self, labs_dir, projects):
        """A lab may raise the MTU of its links (VXLAN, MPLS): frames of 9000 bytes cross a hub
        (`vde_switch` of Debian loses everything above 1500, which is why the hub is not one)."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'hubs.py')
        for machine in ('a', 'b'):
            assert _run(running_lab_name, machine, 'ip link set dev eth0 mtu 9000')[0] == 0
        for payload in (1472, 1473, 4000, 8972):    # 8972 + 28 = an IP packet of 9000 bytes
            rc, out = _run(running_lab_name, 'a', f'ping -c 2 -i 0.2 -W 2 -M do -s {payload} 10.98.1.2')
            assert rc == 0, f"payload {payload}:\n{out}"

    def test_the_mac_address_of_the_lab(self, labs_dir, projects):
        lab = labs_dir / 'mac.py'
        lab.write_text(NON_PRIVILEGED_LAB.replace(
            "    _topology = {'lan': ['router', 'client']}",
            "    _topology = {'lan': ['router', 'client']}\n\n"
            "    def __init__(self, data, running_lab_name):\n"
            "        super().__init__(data=data, running_lab_name=running_lab_name)\n"
            "        self.get_machine('router').net_adapters[self.get_network('lan')].mac = '02-00-5E-00-53-01'\n"))
        lab.chmod(0o644)
        running_lab_name, lab_hash = _start(projects, lab)
        assert _run(running_lab_name, 'router', 'cat /sys/class/net/eth0/address') == (0, '02:00:5e:00:53:01\n')


# ---------------------------------------------------------------------------
# Commands on a running project
# ---------------------------------------------------------------------------

class TestCommands:

    def test_exec_gives_the_outputs_and_the_status(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        r = _sre('exec', running_lab_name, 'router', 'sh', '-c', 'echo out; echo err >&2; exit 3')
        assert (r.returncode, r.stdout, r.stderr) == (3, 'out\n', 'err\n')
        r = _sre('exec', running_lab_name, 'nobody', 'true')
        assert r.returncode == 1 and 'device nobody is unknown' in r.stderr

    def test_a_terminal(self, labs_dir, projects):
        """`sre connect` in a pseudo-terminal: the shell of the machine, with a terminal type."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        master, slave = pty.openpty()
        process = subprocess.Popen([sys.executable, '-W', 'ignore', str(SRE_PY), 'connect', running_lab_name, 'router'],
                                   stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                                   env=dict(os.environ, LOGNAME='root', TERM='vt100'))
        os.close(slave)
        output, sent, deadline = b'', False, time.monotonic() + 90
        try:
            while time.monotonic() < deadline:
                if not sent and (b'# ' in output or b'$ ' in output):
                    os.write(master, b'echo "tty=$(tty) term=$TERM host=$(hostname) sum=$((6*7))"; exit\r')
                    sent = True
                if select.select([master], [], [], 0.5)[0]:
                    try:
                        data = os.read(master, 4096)
                    except OSError:     # the terminal is closed: the session ended
                        break
                    if not data:
                        break
                    output += data
                elif process.poll() is not None:
                    break
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            os.close(master)
        text = output.decode(errors='replace')
        assert sent, f"no prompt:\n{text}"
        assert 'tty=/dev/pts/' in text and 'term=xterm host=router sum=42' in text, text
        assert process.returncode == 0, text

    def test_a_state_and_an_evaluation(self, labs_dir, projects, no_exam):
        """Commands, a file written by a state and the tests of an evaluation, as root and as a
        student (`sre --user`: the path of sre-wrapper)."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'instructor.py')
        r = _sre('state', running_lab_name, 'final')
        assert r.returncode == 0, r.stderr
        assert _run(running_lab_name, 'router', 'cat /root/state; cat /root/solution; stat -c "%U:%G %a" /root/solution') == (
            0, 'final\nthe solution\nroot:root 644\n')
        r = _sre('eval', running_lab_name)
        assert r.returncode == 0, r.stderr
        assert [e['max_grade'] for e in json.loads(r.stdout)['grades']] == [1]
        assert 'Traceback' not in r.stderr and 'ERROR' not in r.stderr.upper().replace('STDERR', ''), r.stderr

        r = _sre_user('state', running_lab_name, 'broken')
        assert r.returncode == 0, r.stderr
        assert _run(running_lab_name, 'router', 'cat /root/state') == (0, 'broken\n')
        r = _sre_user('eval', running_lab_name)
        assert r.returncode == 0, r.stderr

    def test_the_result_of_a_test_reaches_the_grade(self, labs_dir, projects):
        """A lab whose grade reads a file of the machine: the output and the status of the test."""
        lab = labs_dir / 'graded.py'
        lab.write_text(NON_PRIVILEGED_LAB.replace(
            "        self.add_grade_element(title='dummy', grade=0, max_grade=1)",
            "        out, code = self.test('router', 'cat /root/from_initial; exit 7', default_value='', default_code=0)\n"
            "        self.add_grade_element(title='file', grade=2 if (out.strip(), code) == ('from-initial', 7) else 0,\n"
            "                               max_grade=2)"))
        lab.chmod(0o644)
        running_lab_name, lab_hash = _start(projects, lab)
        r = _sre('eval', running_lab_name)
        assert r.returncode == 0, r.stderr
        assert [(e['grade'], e['max_grade']) for e in json.loads(r.stdout)['grades']] == [(2, 2)], r.stderr[-2000:]

    def test_eval_all(self, labs_dir, projects):
        """`sre eval-all` calls the engine with the effective uid lowered only."""
        if _project_dirs():
            pytest.skip("sre eval-all would evaluate projects that are not the test's")
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        r = _sre('eval-all', '--no-display-grades')
        assert r.returncode == 0, r.stderr
        assert 'Traceback' not in r.stderr, r.stderr
        archives = [p for d in params.archive_dirs if os.path.isdir(d) for p in Path(d).rglob(f'*{running_lab_name}*')]
        assert archives, f"no archive of the evaluation in {params.archive_dirs}:\n{r.stderr[-2000:]}"


# ---------------------------------------------------------------------------
# shared/ and volumes
# ---------------------------------------------------------------------------

class TestSharedDirectories:
    def test_files_of_a_machine_belong_to_nobody_and_stop_removes_them(self, labs_dir, projects):
        """Under Docker these files are root's.  Here a setuid file left in shared/ belongs to a
        subordinate uid: running it on the host gives neither root nor the sre account."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'shared.py')
        rc, out = _run(running_lab_name, 'router', ROOT_OWNED_DIRS_CMD + ' && cp /bin/true /shared/suid && chmod 4755 /shared/suid')
        assert rc == 0, out
        user_public_dir = _user_public_dir(running_lab_name)
        shared = user_public_dir / params.shared_dir_name
        volume = Path(params.private_mount_dir(running_lab_name)) / 'data'
        host_uid = _host_uid(lab_hash, 'router')
        for path in (shared / 'rep_root' / 'f', volume / 'rep_root' / 'f', shared / 'suid'):
            assert path.stat().st_uid == host_uid, path
        assert host_uid not in (0, params.sre_uid)
        # the other way: a file of the host in shared/ is readable in the machine
        (shared / 'from_host').write_text('hello\n')
        assert _run(running_lab_name, 'client', 'cat /shared/from_host') == (0, 'hello\n')

        _stop(running_lab_name, lab_hash)
        assert not user_public_dir.exists(), "user public dir left after sre stop"

    def test_wipe(self, labs_dir, projects):
        """`sre wipe` removes every project of the host: the test only runs when there is none."""
        others = _project_dirs() | set(_containers())
        if others:
            pytest.skip(f"sre wipe would remove projects that are not the test's: {sorted(others)}")
        running_lab_name, lab_hash = _start(projects, labs_dir / 'shared.py')
        assert _run(running_lab_name, 'router', ROOT_OWNED_DIRS_CMD)[0] == 0
        user_public_dir = _user_public_dir(running_lab_name)
        r = _sre('wipe')
        assert r.returncode == 0, r.stderr
        assert _everything() == ([], [], [])
        assert not (PROJECTS / running_lab_name).exists() and not user_public_dir.exists()


# ---------------------------------------------------------------------------
# Switches and managed switches
# ---------------------------------------------------------------------------

def _ping(running_lab_name, machine, address):
    return _run(running_lab_name, machine, f'ping -c 2 -w 4 {address}')[0] == 0


def _switches(lab_hash):
    """The networks of a project that are not hubs, with their mode, as the engine left them."""
    path = Path(ENGINE._network_dir(lab_hash), 'networks.json')
    return {name: entry['mode'] for name, entry in json.loads(path.read_text()).items()} if path.exists() else {}


class TestSwitchModes:
    """The Podman counterpart of `TestSwitchModes` of the Docker tests, on the same lab
    (`tests/labs/switch_test_lab.py`); save / restore is not available yet."""

    def test_only_a_hub_shows_the_traffic_to_a_third_machine(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'switch_modes.py')
        # hub: pc2 sees what srv sends to pc3
        assert _sees_traffic(running_lab_name, 'pc2', 'eth1', 'srv', OLD_SRV, OLD_PC3), "a hub floods every frame"
        # plain switch: pc1 captures what r1 sends to it (the capture works there), not what r1 sends to srv
        assert _sees_traffic(running_lab_name, 'pc1', 'eth1', 'r1', DMZ_R1, DMZ_PC1)
        assert not _sees_traffic(running_lab_name, 'pc1', 'eth1', 'r1', DMZ_R1, DMZ_SRV), \
            "a switch sends a frame to its destination only"
        # managed switch, the three PCs in VLAN 10: the same inside a VLAN
        r = _sre('state', running_lab_name, 'move')
        assert r.returncode == 0, r.stderr
        assert _sees_traffic(running_lab_name, 'pc3', 'eth0', 'pc1', PC1, PC3)
        assert not _sees_traffic(running_lab_name, 'pc3', 'eth0', 'pc1', PC1, PC2), \
            "a managed switch is a switch inside a VLAN"
        _stop(running_lab_name, lab_hash)

    def test_modes_vlans_console_and_states(self, labs_dir, projects, no_exam):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'switch_modes.py')
        assert _switches(lab_hash) == {'lan': 'managed', 'dmz': 'switch', 'closed': 'managed', 'hid': 'managed'}
        assert _info(running_lab_name)['switches'] == [
            {'name': 'lan', 'mode': 'managed', 'allow_connection': True},
            {'name': 'dmz', 'mode': 'switch', 'allow_connection': True},
            {'name': 'closed', 'mode': 'managed', 'allow_connection': False},
            {'name': 'old', 'mode': 'hub', 'allow_connection': True},
        ]
        # one IP subnet: only the VLANs separate pc2 (VLAN 20) from pc1 and pc3 (VLAN 10)
        assert _ping(running_lab_name, 'pc1', PC3), "pc1 and pc3 are both in VLAN 10"
        assert not _ping(running_lab_name, 'pc1', PC2), "pc2 is in VLAN 20"
        if _run(running_lab_name, 'r1', 'ip link show eth0.10')[0] == 0:    # the 8021q module of the host
            assert _ping(running_lab_name, 'pc1', R1_VLAN10), "r1 reaches VLAN 10 tagged on its trunk port"

        # the console, for a privileged user; the ports read as the grading code reads them
        r = _sre('exec', running_lab_name, 'lan', 'vlan/print')
        assert r.returncode == 0 and 'VLAN 0010' in r.stdout and 'VLAN 0020' in r.stdout, (r.stdout, r.stderr)
        r = _sre('exec', running_lab_name, 'lan', 'vlan/create', '10')
        assert r.returncode == 17 and 'error:' in r.stderr, (r.returncode, r.stderr)
        r = _sre('exec', running_lab_name, 'dmz', 'vlan/print')
        assert r.returncode == 1 and 'device dmz is a switch: it has no console' in r.stderr, r.stderr
        r = _sre('exec', running_lab_name, 'lan', 'port/allprint')
        assert r.returncode == 0 and 'kathara pc1:eth0' in r.stdout and 'kathara r1:eth0' in r.stdout, r.stdout
        ports = ENGINE.switch_ports(lab_hash, 'lan')
        by_endpoint = {port['endpoints'][0]: (number, port['vlan'], port['tagged_vlans'])
                       for number, port in ports.items() if port['endpoints']}
        assert by_endpoint == {'pc1:eth0': (1, 10, []), 'pc2:eth0': (2, 20, []), 'pc3:eth0': (3, 10, []),
                               'r1:eth0': (4, 0, [10, 20])}, ports

        # the console, for a student: the commands of the allow-list only
        r = _sre_user('connect', running_lab_name, 'lan', input='vlan/print\nport/remove 1\nshutdown\nexit\n')
        assert r.returncode == 0, r.stderr
        assert 'VLAN 0010' in r.stdout, r.stdout
        assert "command 'port/remove' is not allowed" in r.stderr, r.stderr
        assert "command 'shutdown' is not allowed" in r.stderr, r.stderr
        r = _sre('exec', running_lab_name, 'lan', 'port/print')
        assert r.returncode == 0 and 'pc1:eth0' in r.stdout, "the refused commands did not reach the switch"
        r = _sre_user('connect', running_lab_name, 'closed', input='vlan/print\n')
        assert r.returncode == 1 and 'connection to device closed is not allowed' in r.stderr, r.stderr
        r = _sre_user('connect', running_lab_name, 'hid', input='vlan/print\n')
        assert r.returncode == 1 and 'device hid is unknown' in r.stderr, r.stderr
        # what no user may send, whoever asks
        r = _sre('exec', running_lab_name, 'lan', 'shutdown')
        assert r.returncode == 1 and 'Operation not permitted' in r.stderr, (r.returncode, r.stderr)

        # a state runs a switch command: pc2 joins VLAN 10; the grade reads the switch
        def grades():
            r = _sre('eval', running_lab_name)
            assert r.returncode == 0, r.stderr
            return {g['title']: g['grade'] for g in json.loads(r.stdout)['grades']}

        assert grades() == {'pc2 in the VLAN of pc1': 0, 'pc1 reaches pc2': 0}
        r = _sre_user('state', running_lab_name, 'move')
        assert r.returncode == 0, r.stderr
        assert _ping(running_lab_name, 'pc1', PC2), "the state moved the port of pc2 to VLAN 10"
        assert grades() == {'pc2 in the VLAN of pc1': 1, 'pc1 reaches pc2': 1}
        r = _sre('state', running_lab_name, 'back')
        assert r.returncode == 0, r.stderr
        assert not _ping(running_lab_name, 'pc1', PC2)
        _stop(running_lab_name, lab_hash)

    def test_switches_carry_large_frames(self, labs_dir, projects):
        """The switch program of SRE has the frame buffer of the Kathara network plugin: an MTU
        of 9000 crosses a plain switch and, inside a VLAN, a managed one."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'switch_modes.py')
        for machine, interface in (('r1', 'eth1'), ('srv', 'eth0'), ('pc1', 'eth0'), ('pc3', 'eth0')):
            assert _run(running_lab_name, machine, f'ip link set dev {interface} mtu 9000')[0] == 0
        for payload in (1472, 4000, 8972):
            rc, out = _run(running_lab_name, 'r1', f'ping -c 2 -i 0.2 -W 2 -M do -s {payload} {DMZ_SRV}')
            assert rc == 0, f"plain switch, payload {payload}:\n{out}"
            rc, out = _run(running_lab_name, 'pc1', f'ping -c 2 -i 0.2 -W 2 -M do -s {payload} {PC3}')
            assert rc == 0, f"managed switch, payload {payload}:\n{out}"


# ---------------------------------------------------------------------------
# The outside interface
# ---------------------------------------------------------------------------

class _Listener:
    """A TCP service of the host answering `hello`, on *address* and a port the system gives."""

    def __init__(self, address):
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((address, 0))
        self._socket.listen(8)
        self.port = self._socket.getsockname()[1]
        self.peers = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                connection, peer = self._socket.accept()
            except OSError:
                return
            self.peers.append(peer[0])
            with connection:
                connection.sendall(b'hello\n')

    def close(self):
        self._socket.close()


def _greeting(running_lab_name, machine, address, port):
    """What *machine* reads from *address*:*port* (`hello` from a listener above, '' when closed)."""
    return _run(running_lab_name, machine,
                f"timeout 4 bash -c 'exec 3<>/dev/tcp/{address}/{port} && head -c 5 <&3' 2>/dev/null")[1]


class TestOutsideInterface:
    @pytest.fixture
    def listeners(self):
        everywhere, loopback = _Listener('0.0.0.0'), _Listener('127.0.0.1')
        yield everywhere, loopback
        everywhere.close()
        loopback.close()

    def test_as_the_bridge_of_docker_from_inside(self, labs_dir, projects):
        """The interface after the lab interfaces, with the address and the default route a
        container gets on Docker's bridge; no IPv6, the MTU of a bridge; the files Kathara
        leaves plain are plain files."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'outside.py')
        _wait_started(running_lab_name, 'gw')
        host = params.sre_host_ip
        rc, out = _run(running_lab_name, 'gw', '; '.join([
            'ip -4 -o addr show dev eth1 | tr -s " " | cut -d" " -f2-4', 'ip route show default',
            'cat /sys/class/net/eth1/mtu', 'cat /proc/sys/net/ipv6/conf/eth1/disable_ipv6',
            # (a host whose kernel has the gre or bonding modules shows their own devices in every machine)
            'ls -d /sys/class/net/eth* | tr "\\n" " "; echo', 'echo "resolv.conf: $(wc -c < /etc/resolv.conf)"',
            'grep -c " /etc/resolv.conf \\| /etc/hosts " /proc/self/mountinfo', 'tail -1 /etc/hosts']))
        assert out.splitlines() == [
            'eth1 inet 172.17.0.2/16', f'default via {host} dev eth1 ', '1500', '1', '/sys/class/net/eth0 /sys/class/net/eth1 ',
            'resolv.conf: 0', '0', '127.0.1.1 gw'], out
        # what the labs do on a gateway: the route exists already, as under Docker
        rc, out = _run(running_lab_name, 'gw', f'ip route add 0.0.0.0/0 via {host} 2>&1')
        assert rc != 0 and 'File exists' in out
        _stop(running_lab_name, lab_hash)

    def test_the_host_and_beyond(self, labs_dir, projects, listeners):
        """The host answers at `sre_host_ip` (the X11 displays, a capture sent to the host), its
        services bound to its loopback only do not; a machine behind the gateway reaches the
        same through the gateway's NAT."""
        everywhere, loopback = listeners
        running_lab_name, lab_hash = _start(projects, labs_dir / 'outside.py')
        host = params.sre_host_ip
        assert _greeting(running_lab_name, 'gw', host, everywhere.port) == 'hello'
        assert _greeting(running_lab_name, 'gw', host, loopback.port) == '', "a loopback-only service of the host is open"
        assert _run(running_lab_name, 'gw', f'ping -c 1 -W 2 {host}')[0] == 0
        assert _ping(running_lab_name, 'pc1', '10.97.0.1')
        assert _greeting(running_lab_name, 'pc1', host, everywhere.port) == 'hello', "through the NAT of the gateway"
        assert _greeting(running_lab_name, 'pc1', host, loopback.port) == ''
        assert len(everywhere.peers) == 2 and loopback.peers == []
        _stop(running_lab_name, lab_hash)
        assert ENGINE.run(['pgrep', '-u', str(params.sre_uid), '-c', 'pasta']).stdout.strip() == b'0'

    def test_a_published_port(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'outside.py')
        (published,) = next(m for m in _info(running_lab_name)['machines'] if m['name'] == 'gw')['ports']
        port = int(published.split(':')[0])
        assert 18400 <= port <= 18499 and published.endswith(':80/tcp'), published
        assert _run(running_lab_name, 'gw', 'cd /tmp && (nohup python3 -m http.server 80 >/dev/null 2>&1 &) ; sleep 1')[0] == 0
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=5) as answer:
            assert answer.status == 200
        _stop(running_lab_name, lab_hash)
        with pytest.raises(OSError):
            urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2)


# ---------------------------------------------------------------------------
# Privileged machines (systemd)
# ---------------------------------------------------------------------------

def _left_running():
    """The processes of the uids of the machines (the subordinate ids of the account)."""
    first = int(ENGINE.podman(['unshare', 'awk', '$1 == 1 {print $2}', '/proc/self/uid_map']).stdout.split()[0])
    listing = subprocess.run(['ps', '-eo', 'uid=,args='], capture_output=True, text=True).stdout
    return [line.strip()[:80] for line in listing.splitlines() if int(line.split()[0]) >= first]


class TestPrivilegedMachines:
    def test_a_systemd_machine(self, labs_dir, projects):
        """`privileged` is a rootless container too: systemd runs, its services answer as soon
        as `sre start` returns, and nothing of the host is given."""
        if not params.allow_privileged_machines:
            pytest.skip("params.allow_privileged_machines is False")
        running_lab_name, lab_hash = _start(projects, labs_dir / 'privileged.py')
        assert {name: c['State'] for name, c in _containers(lab_hash).items()} == {'srv': 'running', 'client': 'running'}
        # no wait here: the deployment returned once systemd was up
        rc, out = _run(running_lab_name, 'srv', 'systemctl is-system-running; cat /proc/1/comm; ls /tmp/EOS')
        assert out.splitlines()[0] in ('running', 'degraded') and out.splitlines()[1:] == ['systemd', '/tmp/EOS'], out
        rc, out = _run(running_lab_name, 'srv', 'systemctl start ssh && systemctl is-active ssh && journalctl -q --no-pager -u ssh | wc -l')
        assert rc == 0 and out.splitlines()[0] == 'active' and int(out.splitlines()[1]) > 0, out
        # every capability inside, a writable /proc/sys without the remount of the plain machines...
        rc, out = _run(running_lab_name, 'srv', 'grep CapEff /proc/1/status | cut -f2; sysctl -w net.ipv4.ip_forward=0 && '
                                                'sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null && cat /proc/sys/net/ipv4/ip_forward')
        assert rc == 0 and out.splitlines()[0].endswith('ffffffffff') and out.splitlines()[-1] == '0', out
        # ... and nothing of the host: its root is an ordinary uid, the kernel's own settings are out of reach
        host_uid = _host_uid(lab_hash, 'srv')
        assert host_uid not in (0, params.sre_uid) and host_uid > 65535
        assert _run(running_lab_name, 'srv', 'sysctl -w kernel.sysrq=1')[0] != 0
        assert _run(running_lab_name, 'srv', 'dmesg')[0] != 0
        _stop(running_lab_name, lab_hash)
        assert _left_running() == []

    def test_a_failed_start_leaves_nothing(self, labs_dir):
        """The lab fails in its `initial` state: the machines run, the command has dropped root."""
        if not params.allow_privileged_machines:
            pytest.skip("params.allow_privileged_machines is False")
        before, projects_before = _everything(), _project_dirs()
        r = _sre('start', '-p', str(labs_dir / 'failing_privileged.py'), timeout=START_TIMEOUT)
        assert r.returncode != 0 and 'deliberate failure after deploy' in r.stderr, r.stderr[-3000:]
        assert _everything() == before and _project_dirs() == projects_before
        assert _left_running() == []

    def test_states_and_evaluations_as_a_student(self, labs_dir, projects, no_exam):
        """The instructor lab with a systemd router: the commands keep root for such a lab and
        call the engine as root; a state and an evaluation from the student path."""
        if not params.allow_privileged_machines:
            pytest.skip("params.allow_privileged_machines is False")
        running_lab_name, lab_hash = _start(projects, labs_dir / 'instructor_privileged.py')
        assert _run(running_lab_name, 'router', 'cat /root/from_initial') == (0, 'from-initial\n')
        r = _sre_user('state', running_lab_name, 'broken')
        assert r.returncode == 0, r.stderr
        assert _run(running_lab_name, 'router', 'cat /root/state') == (0, 'broken\n')
        r = _sre('state', running_lab_name, 'final')
        assert r.returncode == 0, r.stderr
        assert _run(running_lab_name, 'router', 'cat /root/state; cat /root/solution') == (0, 'final\nthe solution\n')
        for evaluate in (_sre, _sre_user):
            r = evaluate('eval', running_lab_name)
            assert r.returncode == 0 and 'Traceback' not in r.stderr, r.stderr

    def test_eval_all_with_two_privileged_projects(self, labs_dir, projects):
        """The evaluations of several projects run in threads, each raising and lowering the
        effective uid of the process around its engine calls."""
        if not params.allow_privileged_machines:
            pytest.skip("params.allow_privileged_machines is False")
        if _project_dirs():
            pytest.skip("sre eval-all would evaluate projects that are not the test's")
        first, _ = _start(projects, labs_dir / 'privileged.py')
        time.sleep(1)
        second, _ = _start(projects, labs_dir / 'privileged.py')
        for _ in range(3):
            r = _sre('eval-all', '--no-display-grades')
            assert r.returncode == 0 and 'Traceback' not in r.stderr and 'cannot run' not in r.stderr, r.stderr[-3000:]
            time.sleep(1.1)     # an archive is named after the second of its evaluation
        for running_lab_name in (first, second):
            archives = [p for d in params.archive_dirs if os.path.isdir(d) for p in Path(d).rglob(f'*{running_lab_name}*')]
            assert len(archives) >= 3, (running_lab_name, archives)


# ---------------------------------------------------------------------------
# Failures and refusals
# ---------------------------------------------------------------------------

class TestFailures:
    """Nothing is left of a project that could not be created, and the error is one line."""

    @pytest.mark.parametrize('lab_file, said', [
        ('missing_image.py', 'sre: podman pull: '),
        ('failing.py', 'deliberate failure after deploy'),
    ])
    def test_a_failed_start_leaves_nothing(self, labs_dir, lab_file, said):
        before, projects_before = _everything(), _project_dirs()
        r = _sre('start', '-p', str(labs_dir / lab_file), timeout=START_TIMEOUT)
        assert r.returncode != 0 and said in r.stderr, r.stderr[-3000:]
        if lab_file == 'missing_image.py':
            assert 'Traceback' not in r.stderr, r.stderr[-3000:]
        assert _everything() == before
        assert _project_dirs() == projects_before

    def test_save_is_refused_and_the_project_goes_on(self, labs_dir, projects, tmp_path):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        r = _sre('save', '-o', str(tmp_path / 'p.sre'), running_lab_name)
        assert r.returncode == 1 and 'Traceback' not in r.stderr
        assert r.stderr.strip().endswith("sre: save / restore is not available with the Podman engine yet"), r.stderr
        assert not (tmp_path / 'p.sre').exists()
        assert _run(running_lab_name, 'router', 'cat /root/from_initial') == (0, 'from-initial\n')
        assert _run(running_lab_name, 'router', 'test -e /root/save_hook')[0] == 1, "the save state was applied"

    def test_a_stopped_machine_is_not_running(self, labs_dir, projects):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        assert ENGINE.podman(['stop', '--time', '0', ENGINE._container_name(lab_hash, 'client')]).returncode == 0
        r = _sre('exec', running_lab_name, 'client', 'true')
        assert r.returncode == 1 and 'Machine not running' in r.stderr
        _stop(running_lab_name, lab_hash)
