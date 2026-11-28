"""
Integration tests of a host that allows BOTH container engines, with REAL containers: a
project run by Kathara (Docker) and a project run by Podman at the same time, each command
going to the engine of its project.

What the unit tests (test_project_engine.py) check with two stand-in engines is checked here on
the engines themselves: the engine chosen at the start (the default one of the host, the one a
privileged caller names, the one the lab accepts), its record in the project, `sre status`,
the evaluations of both kinds of projects in one `sre eval-all`, a save made with one engine
restored with the other, and nothing left by a stop.

Requirements — the file is skipped otherwise: run as root, both engines among
`params.container_engines_allowed` of the host (after `make podman-setup`), a reachable Docker
daemon, the SRE images in both stores, and a writable directory of `params.authorized_src_dir`.
Excluded from `make tests`; run by `make docker-tests` and `make podman-tests`.

No test here runs `sre wipe`: with Kathara it removes the containers of every user of the host.
"""
import json
import os
import time
from pathlib import Path

import pytest

from SRE import params

# Skipped as a whole (one line of the `-ra` summary), like the two lifecycle files.
if os.geteuid() != 0:
    pytest.skip("the tests of a host with both engines must run as root", allow_module_level=True)
try:
    _ALLOWED = params.host_allowed_engines()
except ValueError as e:
    pytest.skip(str(e), allow_module_level=True)
if set(_ALLOWED) != set(params.container_engines):
    pytest.skip("this host does not allow both container engines (container_engines_allowed / "
                "container_engines_allowed_by_host)", allow_module_level=True)

from SRE.archive_summary import read_archive  # noqa: E402
from SRE.engine.podman_engine import PodmanEngine  # noqa: E402
from test_docker_lifecycle import (  # noqa: E402, F401  (docker_client, labs_dir, no_exam: fixtures)
    NON_PRIVILEGED_LAB, PROJECTS, STUDENT, _containers, _lab_hash, _networks, _project_dirs, _sre, _sre_user,
    _user_public_dir, docker_client, labs_dir, no_exam)

KATHARA, PODMAN = params.container_engine_kathara, params.container_engine_podman
DEFAULT, OTHER = _ALLOWED[0], _ALLOWED[1]
PODMAN_ENGINE = PodmanEngine()      # asked as root: its commands run as the sre account, like those of the CLI
START_TIMEOUT = 1800                # seconds: a first start pulls the image, and Podman copies it for a uid range


def _lab(labs_dir, name: str, text: str) -> Path:
    path = labs_dir / name
    path.write_text(text)
    path.chmod(0o644)
    return path


def _of_docker(docker_client, lab_hash) -> list:
    return sorted(c.name for c in _containers(docker_client, lab_hash))


def _of_podman(lab_hash) -> list:
    return sorted(c['Names'][0] for c in PODMAN_ENGINE._containers(lab_hash))


def _recorded(running_lab_name) -> str:
    record = PROJECTS / running_lab_name / params.private_dir_name / params.origin_json_name
    return json.loads(record.read_text()).get(params.origin_engine_keyword)


def _machines_of(docker_client, lab_hash) -> dict:
    """`{engine: the containers it runs for the project}`: one of the two lists is empty."""
    return {KATHARA: _of_docker(docker_client, lab_hash), PODMAN: _of_podman(lab_hash)}


@pytest.fixture
def projects(docker_client):
    """The projects a test creates; whatever is left is stopped, and what either engine still
    runs for them is removed: a failing test leaks nothing."""
    created = []
    yield created
    import shutil
    for running_lab_name, lab_hash in created:
        project_dir = PROJECTS / running_lab_name
        if project_dir.exists():
            user_public_dir = _user_public_dir(running_lab_name)
            _sre('stop', running_lab_name)
            shutil.rmtree(project_dir, ignore_errors=True)
            if user_public_dir is not None:
                shutil.rmtree(user_public_dir, ignore_errors=True)
        for container in _containers(docker_client, lab_hash):
            container.remove(force=True)
        for network in _networks(docker_client, lab_hash):
            try:
                network.remove()
            except Exception:  # noqa: BLE001
                pass
        PODMAN_ENGINE.remove_leftovers(lab_hash, [])


def _start(projects, lab_path, *options):
    before = _project_dirs()
    r = _sre('start', *options, '-p', str(lab_path), timeout=START_TIMEOUT)
    assert r.returncode == 0, f"sre start failed:\n{r.stderr[-3000:]}"
    (running_lab_name,) = _project_dirs() - before
    lab_hash = _lab_hash(running_lab_name)
    projects.append((running_lab_name, lab_hash))
    return running_lab_name, lab_hash


def _archives_of(running_lab_name) -> list:
    """The evaluation archives of a project, the newest last."""
    found = []
    for directory in params.archive_dirs:
        if os.path.isdir(directory):
            found += [path for path in Path(directory).iterdir() if path.name.endswith(f'_{running_lab_name}.zst')]
    return sorted(found, key=lambda path: path.stat().st_mtime)


def test_one_project_per_engine_at_the_same_time(projects, labs_dir, docker_client, no_exam):
    lab = labs_dir / 'non_privileged.py'
    with_kathara, kathara_hash = _start(projects, lab, '--engine', KATHARA)
    with_podman, podman_hash = _start(projects, lab, '--engine', PODMAN)
    # each engine runs the machines of its project, and of that one only
    assert _machines_of(docker_client, kathara_hash)[PODMAN] == [] and len(_of_docker(docker_client, kathara_hash)) == 2
    assert _machines_of(docker_client, podman_hash)[KATHARA] == [] and len(_of_podman(podman_hash)) == 2
    assert (_recorded(with_kathara), _recorded(with_podman)) == (KATHARA, PODMAN)
    # `sre status` names the engine of each
    status = json.loads(_sre('status', '--json').stdout)
    engines = {row['running_lab_name']: row['engine'] for row in status['projects']}
    assert engines[with_kathara] == KATHARA and engines[with_podman] == PODMAN
    # every command goes to the engine of its project
    for running_lab_name in (with_kathara, with_podman):
        r = _sre('exec', running_lab_name, 'router', 'cat', '/root/from_initial')
        assert r.returncode == 0 and r.stdout.strip() == 'from-initial', r.stderr[-1000:]
        r = _sre('eval', running_lab_name)
        assert r.returncode == 0, r.stderr[-2000:]
    assert read_archive(str(_archives_of(with_kathara)[-1]))[params.archive_engine_keyword] == KATHARA
    assert read_archive(str(_archives_of(with_podman)[-1]))[params.archive_engine_keyword] == PODMAN
    # a stop removes the machines of its project and leaves the other project alone
    assert _sre('stop', with_kathara).returncode == 0
    assert _of_docker(docker_client, kathara_hash) == [] and _networks(docker_client, kathara_hash) == []
    assert len(_of_podman(podman_hash)) == 2 and (PROJECTS / with_podman).is_dir()
    assert _sre('stop', with_podman).returncode == 0
    assert _of_podman(podman_hash) == [] and not (PROJECTS / with_podman).exists()


def test_the_engine_nobody_chose(projects, labs_dir, docker_client, no_exam):
    """Without `--engine`: the default engine of the host; for a lab that does not accept it,
    the other one.  The project says nothing of it to the interface of a student."""
    plain = labs_dir / 'non_privileged.py'
    restricted = _lab(labs_dir, 'other_engine.py', NON_PRIVILEGED_LAB + f"\ncontainer_engines = ({OTHER!r},)\n")
    by_default, default_hash = _start(projects, plain)
    by_the_lab, lab_hash = _start(projects, restricted)
    assert (_recorded(by_default), _recorded(by_the_lab)) == (DEFAULT, OTHER)
    assert _machines_of(docker_client, default_hash)[OTHER] == [] and _machines_of(docker_client, lab_hash)[DEFAULT] == []
    assert len(_machines_of(docker_client, lab_hash)[OTHER]) == 2
    # info.json, what the interface of a student reads, does not name the engine
    info = json.loads((PROJECTS / by_the_lab / params.info_json_name).read_text())
    assert info['container_engine'] == ''


def test_what_is_refused(projects, labs_dir, no_exam):
    lab = labs_dir / 'non_privileged.py'
    restricted = _lab(labs_dir, 'one_engine.py', NON_PRIVILEGED_LAB + f"\ncontainer_engines = ({KATHARA!r},)\n")
    before = _project_dirs()
    r = _sre('start', '--engine', PODMAN, '-p', str(restricted))
    assert r.returncode != 0 and f"this lab does not accept the engine {PODMAN} (it accepts: {KATHARA})" in r.stderr
    r = _sre_user('start', '--engine', KATHARA, str(lab))
    assert r.returncode != 0 and "--engine is not available in user mode" in r.stderr
    r = _sre('start', '--engine', 'lxc', '-p', str(lab))
    assert r.returncode == 2 and "invalid choice" in r.stderr
    assert _project_dirs() == before


def test_a_debug_project_says_its_engine(projects, labs_dir, no_exam):
    running_lab_name, _hash = _start(projects, labs_dir / 'non_privileged.py', '--debug-project', '--engine', OTHER)
    info = json.loads((PROJECTS / running_lab_name / params.info_json_name).read_text())
    assert info['debug_project'] is True and info['container_engine'] == OTHER
    log = (PROJECTS / running_lab_name / params.operations_log_name).read_text().splitlines()
    assert log[1] == f"container engine: {OTHER}"


def test_eval_all_evaluates_the_projects_of_both_engines(projects, labs_dir, no_exam):
    lab = labs_dir / 'non_privileged.py'
    with_kathara, _ = _start(projects, lab, '--engine', KATHARA)
    with_podman, _ = _start(projects, lab, '--engine', PODMAN)
    before = {name: len(_archives_of(name)) for name in (with_kathara, with_podman)}
    time.sleep(1.1)     # an archive is named to the second
    r = _sre('eval-all', '--no-display-grades')
    assert r.returncode == 0, r.stderr[-2000:]
    for name, engine in ((with_kathara, KATHARA), (with_podman, PODMAN)):
        archives = _archives_of(name)
        assert len(archives) == before[name] + 1, name
        assert read_archive(str(archives[-1]))[params.archive_engine_keyword] == engine


@pytest.mark.parametrize('saved_with, restored_with', [(PODMAN, KATHARA), (KATHARA, PODMAN)])
def test_a_save_made_with_one_engine_restored_with_the_other(projects, labs_dir, docker_client, tmp_path, no_exam,
                                                             saved_with, restored_with):
    running_lab_name, _ = _start(projects, labs_dir / 'non_privileged.py', '--engine', saved_with)
    r = _sre('exec', running_lab_name, 'router', 'sh', '-c', 'echo kept > /root/kept')
    assert r.returncode == 0, r.stderr[-1000:]
    save_file = tmp_path / 'project.sre'
    r = _sre('save', '-o', str(save_file), running_lab_name)
    assert r.returncode == 0, r.stderr[-2000:]
    before = _project_dirs()
    r = _sre('restore', '--engine', restored_with, str(save_file), timeout=START_TIMEOUT)
    assert r.returncode == 0, r.stderr[-3000:]
    (restored,) = _project_dirs() - before
    restored_hash = _lab_hash(restored)
    projects.append((restored, restored_hash))
    assert _recorded(restored) == restored_with
    assert len(_machines_of(docker_client, restored_hash)[restored_with]) == 2
    assert _machines_of(docker_client, restored_hash)[saved_with] == []
    r = _sre('exec', restored, 'router', 'cat', '/root/kept')
    assert r.returncode == 0 and r.stdout.strip() == 'kept', r.stderr[-1000:]


def test_stop_all_stops_the_projects_of_both_engines(projects, labs_dir, docker_client, no_exam):
    lab = labs_dir / 'non_privileged.py'
    with_kathara, kathara_hash = _start(projects, lab, '--engine', KATHARA)
    with_podman, podman_hash = _start(projects, lab, '--engine', PODMAN)
    r = _sre('stop-all')
    assert r.returncode == 0, r.stderr[-2000:]
    assert _of_docker(docker_client, kathara_hash) == [] and _of_podman(podman_hash) == []
    assert not (PROJECTS / with_kathara).exists() and not (PROJECTS / with_podman).exists()


def test_a_project_is_stopped_by_its_engine_whatever_the_host_says_now(projects, labs_dir, docker_client, no_exam):
    """The record of the project decides, not the parameters: here the record is the only thing
    that names the engine (a project of the engine that is not the default one)."""
    running_lab_name, lab_hash = _start(projects, labs_dir / 'non_privileged.py', '--engine', OTHER)
    assert len(_machines_of(docker_client, lab_hash)[OTHER]) == 2
    assert _sre('stop', running_lab_name).returncode == 0
    assert _machines_of(docker_client, lab_hash) == {KATHARA: [], PODMAN: []}
