"""
Docker integration tests of the lab lifecycle with REAL containers:
`sre start` / `sre stop`, and `sre save` / `sre restore`.

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
        if (PROJECTS / running_lab_name).exists():
            _sre('stop', running_lab_name)
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


def _start(projects, lab_path):
    before = _project_dirs()
    r = _sre('start', '-p', str(lab_path))
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
