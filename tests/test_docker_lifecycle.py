"""
Docker integration tests of the lab lifecycle with REAL containers:
`sre start` / `sre stop`, `sre save` / `sre restore`, and the instructor mode
(`--instructor-mode`, `sre set-instructor-mode` / `sre remove-instructor-mode`).

Why: `sre stop` once removed the project directory while leaving the containers running,
because Kathara only undeploys the containers whose `user` label matches the caller and
the label differs between the two kinds of labs (non-privileged labs are deployed as sre,
privileged ones as their owner).  The unit tests (test_stop_privileges.py) check the
SUDO_UID alignment with Kathara mocked; these tests check the outcome on Docker itself.

Each test drives the CLI of the tree that provides the SRE package (`src/sre.py`, run with
the current interpreter as root) and then asks the Docker API whether any container or
network still carries the lab hash.

Requirements — the tests are skipped otherwise: run as root, a reachable Docker daemon
(python `docker` package), the SRE images, and a writable directory listed in
`params.authorized_src_dir` (the temporary labs are written there).  Excluded from
`make tests`; run with `make docker-tests`.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from SRE import params

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="Docker lifecycle tests must run as root")

SRE_PY = Path(params.__file__).resolve().parents[2] / 'src' / 'sre.py'
PROJECTS = Path(params.sre_projects_dir)

NON_PRIVILEGED_LAB = '''
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state

title = "docker lifecycle test (non-privileged)"
allow_save_restore = True


@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=1)


class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _topology = {'lan': ['router', 'client']}

    @sre_state()
    def initial(self):
        self.cmd('router', 'echo from-initial > /root/from_initial')

    @sre_state()
    def save(self):
        # runs in the running instance just before its filesystem is captured
        self.cmd('router', 'echo saved > /root/save_hook')

    @sre_state()
    def restore(self):
        # runs in the restored instance right after its containers are redeployed
        self.cmd('router', 'echo restored > /root/restore_hook')


class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='dummy', grade=0, max_grade=1)
'''

KEYED_LAB = NON_PRIVILEGED_LAB.replace(
    'allow_save_restore = True', 'allow_save_restore = True\nsave_key = "docker-tests-key"')

# shared/ (bind-mounted as /shared) plus a private volume (.private/mnt/data, mounted as /data):
# the containers run as host root and leave root-owned files in both
SHARED_LAB = NON_PRIVILEGED_LAB.replace(
    'allow_save_restore = True', 'allow_save_restore = True\nshared_path = True').replace(
    "_machine_specs = {'router': {}, 'client': {}}",
    "_machine_specs = {'router': {'volumes': [['data', '/data', 'rw', 'private']]}, 'client': {}}")
assert 'shared_path = True' in SHARED_LAB and "'volumes'" in SHARED_LAB

ROOT_OWNED_DIRS_CMD = 'mkdir -p /shared/rep_root /data/rep_root && echo x > /shared/rep_root/f && echo x > /data/rep_root/f'

PRIVILEGED_LAB = '''
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0
from SRE.params import sre_docker_image

title = "docker lifecycle test (privileged)"


@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=1)


class NetScheme(NetScheme0):
    # one systemd machine (privileged) next to a plain one: the whole lab is deployed as root
    _machine_specs = {
        'srv': {"privileged": True, "entrypoint": "/sbin/init", "image": sre_docker_image("init")},
        'client': {},
    }
    _topology = {'lan': ['srv', 'client']}


class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='dummy', grade=0, max_grade=1)
'''

# fails in its initial state, i.e. once the containers are up and (single-project mode) the
# privileges permanently dropped: Kathara's undeploy then no longer sees the owner-labelled containers
FAILING_PRIVILEGED_LAB = PRIVILEGED_LAB.replace(
    'from SRE.lib_sre import Data0, NetScheme0, Grade0\n',
    'from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state\n').replace(
    'class Grade(Grade0):',
    """    @sre_state()
    def initial(self):
        raise RuntimeError("deliberate failure after deploy")


class Grade(Grade0):""")
assert 'sre_state' in FAILING_PRIVILEGED_LAB and 'deliberate failure' in FAILING_PRIVILEGED_LAB


# IPv6: the module-level `ipv6 = True` enables IPv6 in every container, `'ipv6': False` on a
# machine opts it out; `r` and `h` get static addresses in the initial state.
IPV6_LAB = '''
from dataclasses import dataclass
from ipaddress import IPv6Interface
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state

title = "docker lifecycle test (ipv6)"
ipv6 = True


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        d = cls()
        d.ips6.r = IPv6Interface('fd00:1::1/64')
        d.ips6.h = IPv6Interface('fd00:1::2/64')
        return d


class NetScheme(NetScheme0):
    _machine_specs = {'r': {}, 'h': {}, 'h4': {'ipv6': False}}
    _topology = {'lan': ['r', 'h', 'h4']}

    @sre_state()
    def initial(self):
        self.cmd('r', f'ip addr add {self.data.ips6.r} dev eth0')
        self.cmd('h', f'ip addr add {self.data.ips6.h} dev eth0')


class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='dummy', grade=0, max_grade=1)
'''


# Instructor mode: an instructor() text in the informations and in a question title, a state the
# students may apply (`broken`) and one reserved to privileged users (`final`).
INSTRUCTOR_LAB = '''
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0, instructor, sre_state

title = "docker lifecycle test (instructor mode)"
allow_save_restore = True
allow_user_states = True


@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=1)


class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = instructor("INSTRUCTOR-NOTE apply the final state.\\n\\n") + "Public text."

    @sre_state()
    def initial(self):
        self.cmd('router', 'echo from-initial > /root/from_initial')

    @sre_state(user_allowed=True, description='Break it')
    def broken(self):
        self.cmd('router', 'echo broken > /root/state')

    @sre_state(description='Fix it')
    def final(self):
        self.cmd('router', 'echo final > /root/state')
        self.file('router', '/root/solution', 'the solution\\n')


class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='dummy', grade=0, max_grade=1)
        self.question_text(title="Question" + instructor(" INSTRUCTOR-ANSWER"), description="Describe.")
        self.test('router', 'cat /root/from_initial')
'''

# the same lab deployed as root: its router is a systemd machine
PRIVILEGED_INSTRUCTOR_LAB = INSTRUCTOR_LAB.replace(
    "import Data0, NetScheme0, Grade0, instructor, sre_state\n",
    "import Data0, NetScheme0, Grade0, instructor, sre_state\nfrom SRE.params import sre_docker_image\n").replace(
    "_machine_specs = {'router': {}, 'client': {}}",
    """_machine_specs = {
        'router': {"privileged": True, "entrypoint": "/sbin/init", "image": sre_docker_image("init")},
        'client': {},
    }""").replace('allow_save_restore = True\n', '')
assert 'sre_docker_image("init")' in PRIVILEGED_INSTRUCTOR_LAB and '"privileged": True' in PRIVILEGED_INSTRUCTOR_LAB


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def docker_client():
    docker = pytest.importorskip('docker')
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:  # noqa: BLE001 - any failure means "no usable daemon"
        pytest.skip(f"Docker daemon not reachable: {e}")
    return client


@pytest.fixture(scope='module')
def labs_dir():
    """Temporary lab files in an authorized source dir, readable by the sre user
    (sre.py drops its privileges before importing the lab module)."""
    base = next((d for d in params.authorized_src_dir if os.path.isdir(d) and os.access(d, os.W_OK)), None)
    if base is None:
        pytest.skip(f"no writable directory in params.authorized_src_dir {params.authorized_src_dir}")
    d = Path(tempfile.mkdtemp(prefix='sre-docker-tests-', dir=base))
    d.chmod(0o755)
    (d / 'non_privileged.py').write_text(NON_PRIVILEGED_LAB)
    (d / 'privileged.py').write_text(PRIVILEGED_LAB)
    (d / 'keyed.py').write_text(KEYED_LAB)
    (d / 'shared.py').write_text(SHARED_LAB)
    (d / 'failing_privileged.py').write_text(FAILING_PRIVILEGED_LAB)
    (d / 'ipv6.py').write_text(IPV6_LAB)
    (d / 'instructor.py').write_text(INSTRUCTOR_LAB)
    (d / 'instructor_privileged.py').write_text(PRIVILEGED_INSTRUCTOR_LAB)
    for f in d.iterdir():
        f.chmod(0o644)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _sre(*args, timeout=600):
    env = dict(os.environ, LOGNAME='root')
    return subprocess.run([sys.executable, '-W', 'ignore', str(SRE_PY), *args],
                          capture_output=True, text=True, timeout=timeout, env=env)


def _project_dirs():
    if not PROJECTS.exists():
        return set()
    return {p.name for p in PROJECTS.iterdir() if '@@@' in p.name}


def _lab_hash(running_lab_name):
    info = json.loads((PROJECTS / running_lab_name / params.info_json_name).read_text())
    return info['lab_hash']


def _user_public_dir(running_lab_name):
    """Target of the project's `.private/user_public_dir` symlink (under /home/sre), or None."""
    link = PROJECTS / running_lab_name / params.private_dir_name / params.user_public_dir_name
    if not link.is_symlink():
        return None
    target = link.resolve()
    return target if str(target).startswith(params.sre_user_public_dir + '/') else None


def _leave_root_owned_dirs(running_lab_name):
    """Make the router leave a non-empty root-owned directory in /shared and in its private
    volume, and return the two host-side directories (checked to be root-owned)."""
    r = _sre('exec', running_lab_name, 'router', 'sh', '-c', ROOT_OWNED_DIRS_CMD)
    assert r.returncode == 0, r.stderr
    user_public_dir = _user_public_dir(running_lab_name)
    assert user_public_dir is not None
    dirs = (user_public_dir / params.shared_dir_name / 'rep_root',
            Path(params.private_mount_dir(running_lab_name)) / 'data' / 'rep_root')
    for d in dirs:
        assert (d / 'f').is_file(), d
        assert d.stat().st_uid == 0, f"precondition: {d} should have been created by root"
    return dirs


def _containers(client, lab_hash):
    return client.containers.list(all=True, filters={'label': [f'lab_hash={lab_hash}']})


def _networks(client, lab_hash):
    return [n for n in client.networks.list() if (n.attrs.get('Labels') or {}).get('lab_hash') == lab_hash]


@pytest.fixture
def projects(docker_client):
    """Registry of the projects a test creates; whatever is left is stopped, and any container,
    network or saved image still carrying their hash is removed, so a failing test leaks nothing."""
    created = []
    yield created
    for running_lab_name, lab_hash in created:
        project_dir = PROJECTS / running_lab_name
        if project_dir.exists():
            user_public_dir = _user_public_dir(running_lab_name)
            _sre('stop', running_lab_name)
            # whatever a failing stop left behind (we are root)
            shutil.rmtree(project_dir, ignore_errors=True)
            if user_public_dir is not None:
                shutil.rmtree(user_public_dir, ignore_errors=True)
        for c in _containers(docker_client, lab_hash):
            c.remove(force=True)
        for n in _networks(docker_client, lab_hash):
            try:
                n.remove()
            except Exception:  # noqa: BLE001
                pass
        safe_hash = re.sub(r'[^a-z0-9]', '', lab_hash.lower())
        for image in docker_client.images.list(name=f'kathara_save_{safe_hash}'):
            docker_client.images.remove(image.id, force=True)


def _start(projects, lab_path, *options):
    before = _project_dirs()
    r = _sre('start', *options, '-p', str(lab_path))
    assert r.returncode == 0, f"sre start failed:\n{r.stderr[-3000:]}"
    new = _project_dirs() - before
    assert len(new) == 1, f"expected exactly one new project, got {new}"
    running_lab_name = new.pop()
    lab_hash = _lab_hash(running_lab_name)
    projects.append((running_lab_name, lab_hash))
    return running_lab_name, lab_hash


# ---------------------------------------------------------------------------
# sre stop
# ---------------------------------------------------------------------------

class TestStop:

    @pytest.mark.parametrize('lab_file, machines, label_owner', [
        ('non_privileged.py', {'router', 'client'}, params.sre_user),
        ('privileged.py', {'srv', 'client'}, 'owner'),
    ])
    def test_stop_removes_containers_and_networks(self, docker_client, labs_dir, projects,
                                                  lab_file, machines, label_owner):
        if lab_file == 'privileged.py' and not params.allow_privileged_machines:
            pytest.skip("params.allow_privileged_machines is False")

        running_lab_name, lab_hash = _start(projects, labs_dir / lab_file)

        containers = _containers(docker_client, lab_hash)
        assert {c.labels['name'] for c in containers} == machines
        assert all(c.status == 'running' for c in containers)
        # The label convention `stop` has to match: sre for non-privileged labs, the owner
        # (here the caller, root) for privileged ones.
        owner = params.get_username_from_running_lab_name(running_lab_name) if label_owner == 'owner' else label_owner
        assert all(c.labels['user'].startswith(f'{owner}-') for c in containers), \
            [c.labels['user'] for c in containers]
        assert _networks(docker_client, lab_hash), "the lab network should exist while the lab runs"

        r = _sre('stop', running_lab_name)
        assert r.returncode == 0, r.stderr

        assert _containers(docker_client, lab_hash) == [], "containers left running after sre stop"
        assert _networks(docker_client, lab_hash) == [], "networks left after sre stop"
        assert not (PROJECTS / running_lab_name).exists()

    def test_stop_removes_root_owned_dirs_in_shared_and_volume(self, docker_client, labs_dir, projects):
        """The containers run as host root: a non-empty directory they leave in /shared or in a
        volume used to make `sre stop` die with PermissionError (the privileges were dropped
        before the removal) and leave the project dir behind."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'shared.py')
        _leave_root_owned_dirs(running_lab_name)
        user_public_dir = _user_public_dir(running_lab_name)

        r = _sre('stop', running_lab_name)
        assert r.returncode == 0, r.stderr

        assert _containers(docker_client, lab_hash) == []
        assert _networks(docker_client, lab_hash) == []
        assert not (PROJECTS / running_lab_name).exists()
        assert not user_public_dir.exists(), "user public dir left after sre stop"


# ---------------------------------------------------------------------------
# failed sre start
# ---------------------------------------------------------------------------

def _kathara_containers(client):
    return {c.id: c for c in client.containers.list(all=True, filters={'label': ['app=kathara']})}


def _kathara_networks(client):
    return {n.id: n for n in client.networks.list() if (n.attrs.get('Labels') or {}).get('app') == 'kathara'}


def _user_public_entries():
    home = Path(params.sre_user_public_dir)
    return {p.name for p in home.iterdir()} if home.exists() else set()


class TestStartFailure:

    def test_failed_privileged_start_leaves_nothing(self, docker_client, labs_dir):
        """A privileged lab failing in its initial state, after finalize_project's permanent drop:
        Kathara's undeploy no longer sees its containers (labelled with the owner, filtered on sre),
        the rollback must force-remove whatever still carries the lab hash.  The lab hash is derived
        from the timestamped running lab name, unknown from outside: compare before/after."""
        if not params.allow_privileged_machines:
            pytest.skip("params.allow_privileged_machines is False")
        before_containers = _kathara_containers(docker_client)
        before_networks = _kathara_networks(docker_client)
        before_projects, before_home = _project_dirs(), _user_public_entries()
        try:
            r = _sre('start', '-p', str(labs_dir / 'failing_privileged.py'))
            assert r.returncode != 0, "the lab is meant to fail once deployed"
            assert 'deliberate failure after deploy' in r.stderr, r.stderr[-2000:]
            assert _project_dirs() == before_projects
            assert _user_public_entries() == before_home
            assert set(_kathara_containers(docker_client)) == set(before_containers), \
                "containers left after a failed start"
            assert set(_kathara_networks(docker_client)) == set(before_networks), \
                "networks left after a failed start"
        finally:
            # leak of a failing test only: remove what this lab created (never anything older)
            for cid, c in _kathara_containers(docker_client).items():
                if cid not in before_containers and c.labels.get('name') in ('srv', 'client'):
                    c.remove(force=True)
            for nid, n in _kathara_networks(docker_client).items():
                if nid not in before_networks and (n.attrs.get('Labels') or {}).get('name') == 'lan':
                    try:
                        n.remove()
                    except Exception:  # noqa: BLE001
                        pass


# ---------------------------------------------------------------------------
# sre save / sre restore
# ---------------------------------------------------------------------------

class TestSaveRestore:

    def test_restore_then_stop_both_instances(self, docker_client, labs_dir, projects, tmp_path):
        running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py')
        r = _sre('exec', running_lab_name, 'router', 'sh', '-c', 'echo marker > /root/marker')
        assert r.returncode == 0, r.stderr

        save_file = tmp_path / 'project.sre'
        r = _sre('save', running_lab_name, '-o', str(save_file))
        assert r.returncode == 0, r.stderr
        assert save_file.read_bytes().startswith(params.save_file_magic)
        # the lab's save() hook ran in the original instance before the capture
        r = _sre('exec', running_lab_name, 'router', 'sh', '-c', 'cat /root/save_hook; ls /root')
        assert r.returncode == 0 and 'saved' in r.stdout, (r.stdout, r.stderr)
        assert 'restore_hook' not in r.stdout, "restore() must not run in the saved instance"

        before = _project_dirs()
        r = _sre('restore', str(save_file))
        assert r.returncode == 0, r.stderr[-3000:]
        new = _project_dirs() - before
        assert len(new) == 1, new
        restored = new.pop()
        restored_hash = _lab_hash(restored)
        projects.append((restored, restored_hash))
        assert restored != running_lab_name and restored_hash != lab_hash

        containers = _containers(docker_client, restored_hash)
        assert {c.labels['name'] for c in containers} == {'router', 'client'}
        assert all(c.attrs['Config']['Image'].startswith('kathara_save_') for c in containers), \
            [c.attrs['Config']['Image'] for c in containers]
        r = _sre('exec', restored, 'router', 'sh', '-c',
                 'cat /root/marker /root/from_initial /root/save_hook /root/restore_hook')
        assert r.returncode == 0, (r.stdout, r.stderr)
        assert 'marker' in r.stdout and 'from-initial' in r.stdout, r.stdout
        assert 'saved' in r.stdout, "the file written by save() must travel with the saved filesystem"
        assert 'restored' in r.stdout, "the lab's restore() hook must run in the restored instance"

        for name, h in ((restored, restored_hash), (running_lab_name, lab_hash)):
            r = _sre('stop', name)
            assert r.returncode == 0, r.stderr
            assert _containers(docker_client, h) == [], f"containers of {name} left after sre stop"
            assert _networks(docker_client, h) == []
            assert not (PROJECTS / name).exists()

    def test_encrypted_round_trip(self, docker_client, labs_dir, projects, tmp_path):
        pytest.importorskip('cryptography')
        lab_file = labs_dir / 'keyed.py'
        running_lab_name, lab_hash = _start(projects, lab_file)

        save_file = tmp_path / 'keyed.sre'
        r = _sre('save', running_lab_name, '-o', str(save_file))
        assert r.returncode == 0, r.stderr
        magic, header, payload = save_file.read_bytes().split(b'\n', 2)
        assert magic + b'\n' == params.save_file_magic
        assert json.loads(header)[params.save_meta_encrypted] is True
        assert b'data.json' not in payload, "encrypted payload must not expose tar member names"

        before = _project_dirs()
        r = _sre('restore', str(save_file))
        assert r.returncode == 0, r.stderr[-3000:]
        restored = (_project_dirs() - before).pop()
        restored_hash = _lab_hash(restored)
        projects.append((restored, restored_hash))
        assert {c.labels['name'] for c in _containers(docker_client, restored_hash)} == {'router', 'client'}
        r = _sre('exec', restored, 'router', 'sh', '-c', 'cat /root/from_initial /root/save_hook /root/restore_hook')
        assert r.returncode == 0 and 'from-initial' in r.stdout and 'saved' in r.stdout and 'restored' in r.stdout, \
            (r.stdout, r.stderr)

        # a lab whose key changed cannot restore the file any more
        lab_file.write_text(KEYED_LAB.replace('docker-tests-key', 'another-key'))
        try:
            before = _project_dirs()
            r = _sre('restore', str(save_file))
            assert r.returncode != 0 and 'cannot decrypt' in r.stderr, (r.returncode, r.stderr[-500:])
            assert _project_dirs() == before
        finally:
            lab_file.write_text(KEYED_LAB)

        for name, h in ((restored, restored_hash), (running_lab_name, lab_hash)):
            r = _sre('stop', name)
            assert r.returncode == 0, r.stderr
            assert _containers(docker_client, h) == []
            assert not (PROJECTS / name).exists()


# ---------------------------------------------------------------------------
# sre wipe
# ---------------------------------------------------------------------------

class TestWipe:
    """`sre wipe` removes every project of the host: the test only runs when there is none."""

    def test_wipe_removes_root_owned_dirs(self, docker_client, labs_dir, projects):
        others = _project_dirs() | {c.name for c in docker_client.containers.list(all=True, filters={'name': 'kathara_'})}
        if others:
            pytest.skip(f"sre wipe would remove projects that are not the test's: {sorted(others)}")
        running_lab_name, lab_hash = _start(projects, labs_dir / 'shared.py')
        _leave_root_owned_dirs(running_lab_name)
        user_public_dir = _user_public_dir(running_lab_name)

        r = _sre('wipe')
        assert r.returncode == 0, r.stderr

        assert _containers(docker_client, lab_hash) == []
        assert _networks(docker_client, lab_hash) == []
        assert not (PROJECTS / running_lab_name).exists()
        assert not user_public_dir.exists(), "user public dir left after sre wipe"


# ---------------------------------------------------------------------------
# IPv6 option
# ---------------------------------------------------------------------------

def _exec(container, command):
    rc, out = container.exec_run(['sh', '-c', command])
    return rc, out.decode(errors='replace')


class TestIpv6:

    def test_ipv6_option_per_machine(self, docker_client, labs_dir, projects):
        """`ipv6 = True` reaches Kathara (IPv6 enabled, addresses usable), `'ipv6': False`
        keeps a machine IPv4-only, and `sre export` writes both in lab.conf."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'ipv6.py')
        by_name = {c.labels['name']: c for c in _containers(docker_client, lab_hash)}
        assert set(by_name) == {'r', 'h', 'h4'}

        for name, expected in (('r', '0'), ('h', '0'), ('h4', '1')):
            rc, out = _exec(by_name[name], 'cat /proc/sys/net/ipv6/conf/all/disable_ipv6')
            assert rc == 0 and out.strip() == expected, (name, rc, out)

        rc, out = _exec(by_name['r'], 'ip -6 addr show dev eth0')
        assert rc == 0 and 'fd00:1::1/64' in out, out
        rc, out = _exec(by_name['h4'], 'ip -6 addr show dev eth0')
        assert 'inet6' not in out, out
        rc, out = _exec(by_name['h'], 'ping -c 1 -w 3 fd00:1::1')
        assert rc == 0 and 'bytes from' in out, out

        r = _sre('export', running_lab_name)
        assert r.returncode == 0, r.stderr
        import base64
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(r.stdout))) as z:
            lab_conf = next(z.read(n).decode() for n in z.namelist() if n.endswith('lab.conf'))
        assert 'r[ipv6]="true"' in lab_conf and 'h[ipv6]="true"' in lab_conf and 'h4[ipv6]="false"' in lab_conf, lab_conf


# ---------------------------------------------------------------------------
# Instructor mode
# ---------------------------------------------------------------------------

STUDENT = 'student'


def _sre_user(*args, stdin=None, timeout=600):
    """The student path: what sre-wrapper runs through sudo (`sre --user ...`), without sudo.
    The process is the same one, with the user-mode checks of the actions."""
    env = dict(os.environ, LOGNAME='root', SUDO_USER=STUDENT, USER_USERNAME=STUDENT)
    env.pop('SUDO_COMMAND', None)
    return subprocess.run([sys.executable, '-W', 'ignore', str(SRE_PY), '--user', *args],
                          capture_output=True, text=True, timeout=timeout, env=env, stdin=stdin)


def _info(running_lab_name):
    return json.loads((PROJECTS / running_lab_name / params.info_json_name).read_text())


def _instructor_marker(running_lab_name):
    return Path(params.instructor_mode_marker_filename(running_lab_name))


def _operations_log(running_lab_name):
    return Path(params.operations_log_filename(running_lab_name))


def _machine(client, lab_hash, name):
    return next(c for c in _containers(client, lab_hash) if c.labels['name'] == name)


def _assert_owned_by_sre(path, mode):
    st = path.stat()
    assert st.st_uid == params.sre_uid, f"{path} is owned by uid {st.st_uid}"
    assert st.st_mode & 0o777 == mode, f"{path} has mode {st.st_mode & 0o777:o}"


def _assert_instructor_project(running_lab_name):
    """Marker and info.json of a project in instructor mode: the instructor() texts are kept
    and every state is listed, the one a student could not apply being flagged."""
    from SRE.instructor_text import has_instructor, strip_instructor, unwrap_instructor
    _assert_owned_by_sre(_instructor_marker(running_lab_name), 0o600)
    _assert_owned_by_sre(PROJECTS / running_lab_name / params.info_json_name, 0o644)
    info = _info(running_lab_name)
    assert info['instructor_mode'] is True and info['debug_project'] is False
    assert has_instructor(info['informations'])
    assert 'INSTRUCTOR-NOTE' in unwrap_instructor(info['informations'])['en']
    assert strip_instructor(info['informations'])['en'] == 'Public text.'
    assert unwrap_instructor(info['questions'][0]['title'])['en'].endswith('Question INSTRUCTOR-ANSWER')
    assert set(info['user_allowed_states']) == {'broken', 'final'}
    assert info['admin_only_states'] == ['final']
    return info


def _assert_normal_project(running_lab_name):
    """What students can read of a project that is not in instructor mode: no instructor text,
    only the user-allowed state."""
    assert not _instructor_marker(running_lab_name).exists()
    _assert_owned_by_sre(PROJECTS / running_lab_name / params.info_json_name, 0o644)
    raw = (PROJECTS / running_lab_name / params.info_json_name).read_text()
    info = json.loads(raw)
    assert info['instructor_mode'] is False
    assert 'INSTRUCTOR' not in raw
    for mark in (params.instructor_begin_mark, params.instructor_args_end_mark, params.instructor_end_mark):
        assert mark not in raw and json.dumps(mark).strip('"') not in raw
    assert info['informations']['en'] == 'Public text.'
    assert info['questions'][0]['title']['en'].endswith('Question')
    assert set(info['user_allowed_states']) == {'broken'} and info['admin_only_states'] == []
    return info


def _machines(info):
    return sorted((m['name'], m['status']) for m in info['machines'])


RUNNING_MACHINES = [('client', 'running'), ('router', 'running')]


@pytest.fixture
def no_exam():
    if (Path(params.sre_pub_dir) / params.exam_json_name).exists():
        pytest.skip("an exam is configured on this host: the user-mode commands are refused")


INSTRUCTOR_LABS = ['instructor.py', 'instructor_privileged.py']


def _skip_unless_allowed(lab_file):
    if lab_file == 'instructor_privileged.py' and not params.allow_privileged_machines:
        pytest.skip("params.allow_privileged_machines is False")


class TestInstructorMode:

    @pytest.mark.parametrize('lab_file', INSTRUCTOR_LABS)
    def test_start_in_instructor_mode(self, docker_client, labs_dir, projects, lab_file):
        """`sre start --instructor-mode`: marker, instructor texts and all the states in
        info.json, and the journal of the initial state, readable by the GUI."""
        _skip_unless_allowed(lab_file)
        running_lab_name, lab_hash = _start(projects, labs_dir / lab_file, '--instructor-mode')
        info = _assert_instructor_project(running_lab_name)
        assert [name for name, _ in _machines(info)] == ['client', 'router']

        log = _operations_log(running_lab_name)
        _assert_owned_by_sre(log, 0o644)
        text = log.read_text()
        assert re.search(r'^=== .*  state initial$', text, re.MULTILINE), text
        assert 'step1 - on router : echo from-initial > /root/from_initial\n    exit code 0\n' in text, text
        rc, out = _exec(_machine(docker_client, lab_hash, 'router'), 'cat /root/from_initial')
        assert rc == 0 and out.strip() == 'from-initial'

        r = _sre('stop', running_lab_name)
        assert r.returncode == 0, r.stderr
        assert _containers(docker_client, lab_hash) == [] and _networks(docker_client, lab_hash) == []
        assert not (PROJECTS / running_lab_name).exists()

    @pytest.mark.parametrize('lab_file', INSTRUCTOR_LABS)
    def test_switch_on_a_running_project(self, docker_client, labs_dir, projects, no_exam, lab_file):
        """`sre set-instructor-mode` / `sre remove-instructor-mode` on a running project, for a
        lab deployed as sre and for one deployed as root: info.json is written again without
        touching the containers, the reserved state becomes applicable from the student path
        (what the GUI runs) and is logged, an evaluation is not logged, and everything is
        undone when the mode is removed."""
        _skip_unless_allowed(lab_file)
        running_lab_name, lab_hash = _start(projects, labs_dir / lab_file)
        started = _assert_normal_project(running_lab_name)
        container_ids = {c.id for c in _containers(docker_client, lab_hash)}
        router = _machine(docker_client, lab_hash, 'router')
        log = _operations_log(running_lab_name)
        assert not log.exists()

        # a normal project: the reserved state is refused, and so are the two commands
        r = _sre_user('state', running_lab_name, 'final')
        assert r.returncode == 1 and "state 'final' is not allowed in user mode" in r.stderr, r.stderr
        for command in ('set-instructor-mode', 'remove-instructor-mode'):
            r = _sre_user(command, running_lab_name)
            assert r.returncode == 1 and "you're not allowed to run this command" in r.stderr, r.stderr
        _assert_normal_project(running_lab_name)

        r = _sre('set-instructor-mode', running_lab_name)
        assert r.returncode == 0, r.stderr
        info = _assert_instructor_project(running_lab_name)
        # the command asked Kathara as the owner of the containers (sre, or root for the
        # privileged lab): it found them
        assert _machines(info) == RUNNING_MACHINES
        assert [q['question_hash'] for q in info['questions']] == [q['question_hash'] for q in started['questions']]
        assert not log.exists(), "nothing was applied yet"

        r = _sre_user('state', running_lab_name, 'final')
        assert r.returncode == 0, r.stderr
        rc, out = _exec(router, 'cat /root/state /root/solution')
        assert rc == 0 and out.split('\n')[:2] == ['final', 'the solution'], out
        _assert_owned_by_sre(log, 0o644)
        text = log.read_text()
        assert re.search(r'^=== .*  state final$', text, re.MULTILINE), text
        assert 'step1 - on router : echo final > /root/state\n    exit code 0\n' in text, text
        assert 'step1 - on router : file /root/solution (0o644 root:root, 13 B)\n    the solution\n' in text, text

        r = _sre('eval', running_lab_name)
        assert r.returncode == 0, r.stderr
        assert 'evaluation' not in log.read_text(), "an instructor-mode project logs its states only"

        r = _sre('remove-instructor-mode', running_lab_name)
        assert r.returncode == 0, r.stderr
        info = _assert_normal_project(running_lab_name)
        assert _machines(info) == RUNNING_MACHINES
        assert not log.exists(), "the journal of the states is not for the students"

        r = _sre_user('state', running_lab_name, 'final')
        assert r.returncode == 1 and "state 'final' is not allowed in user mode" in r.stderr, r.stderr
        r = _sre_user('state', running_lab_name, 'broken')
        assert r.returncode == 0, r.stderr
        rc, out = _exec(router, 'cat /root/state')
        assert rc == 0 and out.strip() == 'broken'
        assert not log.exists()

        assert {c.id for c in _containers(docker_client, lab_hash)} == container_ids, \
            "switching the mode must not redeploy the containers"
        r = _sre('stop', running_lab_name)
        assert r.returncode == 0, r.stderr
        assert _containers(docker_client, lab_hash) == [] and _networks(docker_client, lab_hash) == []
        assert not (PROJECTS / running_lab_name).exists()

    def test_restore_in_instructor_mode(self, docker_client, labs_dir, projects, tmp_path):
        """A save file does not carry the mode: `sre restore` gives a normal project, whatever
        the saved one was, and `sre restore --instructor-mode` one in instructor mode."""
        running_lab_name, lab_hash = _start(projects, labs_dir / 'instructor.py', '--instructor-mode')
        save_file = tmp_path / 'project.sre'
        r = _sre('save', running_lab_name, '-o', str(save_file))
        assert r.returncode == 0, r.stderr
        assert 'instructor_mode' not in json.loads(save_file.read_bytes().split(b'\n', 2)[1])

        def restore(*options):
            before = _project_dirs()
            r = _sre('restore', *options, str(save_file))
            assert r.returncode == 0, r.stderr[-3000:]
            (restored,) = _project_dirs() - before
            projects.append((restored, _lab_hash(restored)))
            return restored

        plain = restore()
        _assert_normal_project(plain)
        assert not _operations_log(plain).exists()

        restored = restore('--instructor-mode')
        _assert_instructor_project(restored)
        _assert_owned_by_sre(_operations_log(restored), 0o644)
        assert re.search(r'^=== .*  state restore$', _operations_log(restored).read_text(), re.MULTILINE)
        rc, out = _exec(_machine(docker_client, _lab_hash(restored), 'router'), 'cat /root/from_initial')
        assert rc == 0 and out.strip() == 'from-initial'

        # the student path cannot ask for the mode
        before = _project_dirs()
        with open(save_file, 'rb') as f:
            r = _sre_user('restore', '--instructor-mode', params.save_stdio_arg, stdin=f)
        assert r.returncode == 1 and '--instructor-mode is not available in user mode' in r.stderr, r.stderr
        assert _project_dirs() == before

        for name in (restored, plain, running_lab_name):
            h = _lab_hash(name)
            r = _sre('stop', name)
            assert r.returncode == 0, r.stderr
            assert _containers(docker_client, h) == [], f"containers of {name} left after sre stop"
            assert not (PROJECTS / name).exists()

    def test_student_path_cannot_start_in_instructor_mode(self, docker_client, labs_dir):
        before = _project_dirs()
        r = _sre_user('start', '--instructor-mode', 'no/such/lab')
        assert r.returncode == 1 and '--instructor-mode is not available in user mode' in r.stderr, r.stderr
        assert _project_dirs() == before
