"""
Podman integration tests of the lab lifecycle with REAL containers: the counterpart of
`test_docker_lifecycle.py` on a host whose engine is the Podman one.

Each test drives the CLI of the tree that provides the SRE package (`src/sre.py`, run with the
current interpreter as root, and as a student for the user-mode commands), then asks Podman and
the user manager of the sre account what is left: containers, units (the hubs and the plugs of
the interfaces), the directory of the networks.

Requirements — the module is skipped otherwise: run as root, on a host whose engine is Podman
(`container_engine` or `container_engine_by_host` of `params.py`) and that
`scripts/podman-setup.sh` prepared, with the base image of the labs (pulled by the first start)
and a writable directory listed in `params.authorized_src_dir` (the temporary labs are written
there).  Excluded from `make tests`; run with `make podman-tests`.
"""
import json
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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
    HUB_LAB, INSTRUCTOR_LAB, IPV6_LAB, NON_PRIVILEGED_LAB, PRIVILEGED_LAB, PROJECTS, ROOT_OWNED_DIRS_CMD,
    SHARED_LAB, SRE_PY, SWITCH_LAB, _lab_hash, _project_dirs, _sre, _sre_user, _user_public_dir, no_exam)

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
                       ('missing_image.py', MISSING_IMAGE_LAB), ('options.py', OPTIONS_LAB)):
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

    @pytest.mark.parametrize('lab_file, said', [
        ('privileged.py', "sre: machine 'srv': a privileged machine is not available with the Podman engine yet"),
        ('switch_modes.py', "is not available with the Podman engine yet (hubs only)"),
    ])
    def test_a_lab_the_engine_cannot_run_yet(self, labs_dir, lab_file, said):
        before, projects_before = _everything(), _project_dirs()
        r = _sre('start', '-p', str(labs_dir / lab_file))
        assert r.returncode == 1 and said in r.stderr and 'Traceback' not in r.stderr, r.stderr[-3000:]
        assert _everything() == before and _project_dirs() == projects_before

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
