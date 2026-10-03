"""
Functional tests for the full SRE lab lifecycle:
  do_action_start → verify files → do_eval (various outcomes) → action_stop → verify cleanup

The test lab (tests/labs/functional_test_lab.py) has:
  - 2 machines: router, client
  - 2 steps of tests: step 1 on both machines, step 2 on router only
  - Various outcomes: pass (code 0), fail (code 1), timeout (code -1)

Kathara and Docker are not needed: Grade0.run_tests_on_machine is patched to
return predetermined exetests-format output, and the Kathara manager is the
MagicMock stub already installed by conftest.py.
"""
import io
import json
import os
import shutil
import stat
import tarfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import msgpack
import pytest
import zstandard as zstd

from SRE import params
from SRE.lib_sre import Grade0
from SRE.command.start import do_action_start
from SRE.command.eval import do_eval
from SRE.command.stop import action_stop
from SRE.command.save import do_action_save, action_save
from SRE.command.restore import do_action_restore, action_restore
from SRE import save_archive


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LAB_PATH = Path(__file__).parent / 'labs' / 'functional_test_lab.py'


def _build_exetests_output(*commands):
    """Build fake exetests output bytes in the format produced by exetests.py.

    Each element of *commands* is a (timeout, cmd, result, exit_code) tuple.
    The separator is a fixed fake UUID string.
    """
    sep = "FAKE-EXETESTS-UUID-SEPARATOR"
    parts = []
    for timeout, cmd, result, code in commands:
        parts.append(f"{timeout}:{cmd}\n2024-01-01T00:00:00\n{result}")
        parts.append(f"2024-01-01T00:00:01\n{code}")
    return (sep + "\n" + ("\n" + sep + "\n").join(parts)).encode()


def _fake_run_tests_on_machine(machine_name, machine, exetests):
    """Fake exetests runner: returns predetermined results per machine/step."""
    if machine_name == 'router' and '10:ip route' in exetests:
        # Step 1 – router: ip route passes, cat /etc/hostname passes
        output = _build_exetests_output(
            (10, 'ip route', '192.168.1.0/24 dev eth0 proto kernel scope link\n', 0),
            (5, 'cat /etc/hostname', 'router\n', 0),
        )
        return machine_name, 0, output
    elif machine_name == 'client' and '15:ping' in exetests:
        # Step 1 – client: ping fails (code 1), sleep times out (code -1)
        output = _build_exetests_output(
            (15, 'ping -c1 192.168.1.1', '', 1),
            (2, 'sleep 100', '', -1),
        )
        return machine_name, 0, output
    elif machine_name == 'router' and '10:ip addr' in exetests:
        # Step 2 – router: ip addr passes
        output = _build_exetests_output(
            (10, 'ip addr', '1: lo: <LOOPBACK,UP,LOWER_UP>\n2: eth0: <BROADCAST,UP>\n', 0),
        )
        return machine_name, 0, output
    else:
        return machine_name, 0, b'UNKNOWN-MACHINE-STEP\n'


def _read_archive(path):
    """Decompress and unpack a zstd+msgpack SRE archive."""
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            raw = reader.read()
    return msgpack.unpackb(raw, raw=False, use_list=False, strict_map_key=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def functional_env(tmp_path, monkeypatch):
    """Patch all paths and mocks needed for start/eval/stop in isolation."""
    # Redirect public lab storage
    pub = tmp_path / 'pub'
    pub.mkdir()
    monkeypatch.setattr(params, 'sre_pub_dir', str(pub))
    monkeypatch.setattr(params, 'sre_projects_dir', str(pub / 'projects'))
    monkeypatch.setattr(params, 'self_grade_timestamp_dir', str(pub / 'last_self_grades'))
    monkeypatch.setattr(params, 'archive_dirs', [str(pub / 'archives')])

    # Redirect /home/sre so user-public-dir creation doesn't touch real filesystem
    home_sre = tmp_path / 'home_sre'
    home_sre.mkdir()
    monkeypatch.setattr(params, 'sre_user_public_dir', str(home_sre))

    # Allow lab files from the test fixture labs directory
    monkeypatch.setattr(params, 'authorized_src_dir', [str(_LAB_PATH.parent), '/home/etudiant'])

    # Set a non-empty username so the running_lab_name regex '^(.+)@@@(.+)@@@(.+)$'
    # matches (empty username causes resolve_running_lab_name to filter it out)
    monkeypatch.setattr(params.SRE, 'username', 'testuser')

    # Neutralise privilege-dropping functions.  When run as root on the
    # production machine, os.setuid() would permanently drop to sre_uid for
    # the rest of the pytest process, causing cleanup to fail.  Patching at
    # the command-module level is sufficient because the functions are imported
    # by name there (e.g. `from ..utils_privileges import drop_privileges_permanently`).
    noop    = lambda: None
    noop_ns = lambda net_scheme: None
    noop_u  = lambda username: None
    import SRE.command.start as _start_cmd
    import SRE.command.eval  as _eval_cmd
    import SRE.command.stop  as _stop_cmd
    monkeypatch.setattr(_start_cmd, 'drop_privileges_permanently',            noop)
    monkeypatch.setattr(_start_cmd, 'drop_privileges_permanently_if_not_needed', noop_ns)
    monkeypatch.setattr(_start_cmd, 'gain_privileges_if_needed',              noop_ns)
    monkeypatch.setattr(_start_cmd, 'set_sudo_uid_for_username',              noop_u)
    monkeypatch.setattr(_start_cmd, 'gain_privileges',                        noop)
    monkeypatch.setattr(_start_cmd, 'drop_privileges_temporarily',            noop)
    monkeypatch.setattr(_eval_cmd,  'drop_privileges_permanently',            noop)
    monkeypatch.setattr(_eval_cmd,  'drop_privileges_permanently_if_not_needed', noop_ns)
    monkeypatch.setattr(_eval_cmd,  'drop_privileges_temporarily',            noop)
    monkeypatch.setattr(_eval_cmd,  'gain_privileges_if_needed',              noop_ns)
    monkeypatch.setattr(_eval_cmd,  'set_sudo_uid_for_username',              noop_u)
    monkeypatch.setattr(_stop_cmd,  'drop_privileges_permanently',            noop)
    monkeypatch.setattr(_stop_cmd,  'gain_privileges',                        noop)
    monkeypatch.setattr(_stop_cmd,  'set_sudo_uid_for_username',              noop_u)
    monkeypatch.setattr(_stop_cmd,  'drop_privileges_temporarily',            noop)
    import SRE.command.save    as _save_cmd
    import SRE.command.restore as _restore_cmd
    import SRE.wipe            as _wipe_mod
    monkeypatch.setattr(_save_cmd,    'gain_privileges',                          noop)
    monkeypatch.setattr(_save_cmd,    'drop_privileges_temporarily',              noop)
    monkeypatch.setattr(_save_cmd,    'set_sudo_uid_for_username',                noop_u)
    monkeypatch.setattr(_restore_cmd, 'drop_privileges_permanently_if_not_needed', noop_ns)
    monkeypatch.setattr(_restore_cmd, 'drop_privileges_temporarily',              noop)
    monkeypatch.setattr(_restore_cmd, 'gain_privileges',                          noop)
    monkeypatch.setattr(_restore_cmd, 'gain_privileges_if_needed',                noop_ns)
    monkeypatch.setattr(_restore_cmd, 'set_sudo_uid_for_username',                noop_u)
    monkeypatch.setattr(params, 'save_tmp_dir', str(pub / 'tmp'))

    # Set SRE.args attributes that do_action_start reads (MagicMock auto-attributes
    # are truthy, so we must explicitly set optional ones to None/False)
    args = params.SRE.args
    args.set_flavor_name = None
    args.data_version = None
    args.data = None
    args.flavor_json = None
    args.flavor = None
    args.output = None
    args.full_images = False

    # Import Lab and Kathara from lib_sre's own namespace so we patch the
    # exact mock objects that lib_sre uses — independent of test ordering.
    # (test_net_config.py replaces sys.modules stubs, creating new mocks;
    # lib_sre keeps its original imports, so sys.modules may diverge.)
    from SRE import lib_sre as _lib_sre
    _lib_sre.Lab.return_value.hash = "fake-lab-hash-1234"

    kathara_instance = _lib_sre.Kathara.get_instance()
    # save.py / restore.py / start.py import Kathara themselves; make them use the same mock
    monkeypatch.setattr(_save_cmd,    'Kathara', _lib_sre.Kathara)
    monkeypatch.setattr(_restore_cmd, 'Kathara', _lib_sre.Kathara)
    monkeypatch.setattr(_start_cmd,   'Kathara', _lib_sre.Kathara)
    monkeypatch.setattr(_wipe_mod,    'Kathara', _lib_sre.Kathara)
    kathara_instance.save_lab.reset_mock(side_effect=True)
    kathara_instance.restore_lab.reset_mock(side_effect=True)
    kathara_instance.undeploy_lab.reset_mock()
    # the leftover sweep of rollback_project / stop sees nothing unless a test says so
    kathara_instance.get_machines_api_objects.reset_mock(return_value=True, side_effect=True)
    kathara_instance.get_links_api_objects.reset_mock(return_value=True, side_effect=True)
    kathara_instance.get_machines_api_objects.return_value = []
    kathara_instance.get_links_api_objects.return_value = []

    # get_machine_stats returns an iterator; returning an empty one means
    # next(..., None) yields None, so machine status is set to "" in info.json
    kathara_instance.get_machine_stats.side_effect = lambda **kwargs: iter([])

    fake_lab = MagicMock()
    fake_lab.machines = {
        'router': MagicMock(),
        'client': MagicMock(),
    }
    kathara_instance.get_lab_from_api.return_value = fake_lab

    return {'pub': pub, 'home_sre': home_sre}


@pytest.fixture
def started_lab(functional_env):
    """Call do_action_start and return the running lab name."""
    do_action_start(lab_cli_arg=str(_LAB_PATH), lab_cli_arg_is_path=True)
    projects_dir = Path(params.sre_projects_dir)
    running_labs = list(projects_dir.iterdir())
    assert len(running_labs) == 1, "Exactly one project should exist after start"
    return running_labs[0].name


@pytest.fixture
def evaled_lab(started_lab):
    """Run do_eval on the started lab, return the unpacked archive dict."""
    with patch.object(Grade0, 'run_tests_on_machine',
                      side_effect=_fake_run_tests_on_machine):
        do_eval(running_lab_name=started_lab, print_result=False)

    archives_dir = Path(params.archive_dirs[0])
    archives = list(archives_dir.iterdir())
    assert len(archives) == 1, "Exactly one archive should be written after eval"
    return _read_archive(archives[0])


# ---------------------------------------------------------------------------
# Tests: project structure after start
# ---------------------------------------------------------------------------

class TestProjectStructure:

    def test_project_directory_created(self, started_lab):
        proj_dir = Path(params.sre_projects_dir) / started_lab
        assert proj_dir.is_dir()

    def test_info_json_exists(self, started_lab):
        info_path = Path(params.sre_projects_dir) / started_lab / 'info.json'
        assert info_path.exists()

    def test_info_json_machines(self, started_lab):
        info_path = Path(params.sre_projects_dir) / started_lab / 'info.json'
        info = json.loads(info_path.read_text())
        machine_names = {m['name'] for m in info['machines']}
        assert machine_names == {'router', 'client'}

    def test_private_dir_exists(self, started_lab):
        private_dir = Path(params.sre_projects_dir) / started_lab / '.private'
        assert private_dir.is_dir()

    def test_data_json_exists(self, started_lab):
        data_path = Path(params.sre_projects_dir) / started_lab / '.private' / 'data.json'
        assert data_path.exists()

    def test_data_json_value(self, started_lab):
        data_path = Path(params.sre_projects_dir) / started_lab / '.private' / 'data.json'
        outer = json.loads(data_path.read_text())
        # Data0.to_json() wraps as {"__type__": "...", "data": {...}}
        assert outer['data']['value'] == 42

    def test_srelab_symlink_exists(self, started_lab):
        symlink = Path(params.sre_projects_dir) / started_lab / '.private' / 'srelab'
        assert symlink.is_symlink()
        assert symlink.resolve() == _LAB_PATH.resolve()

    def test_files_dir_exists(self, started_lab):
        files_dir = Path(params.sre_projects_dir) / started_lab / '.private' / 'files'
        assert files_dir.is_dir()

    def test_answers_dir_exists(self, started_lab):
        answers_dir = Path(params.sre_projects_dir) / started_lab / 'answers'
        assert answers_dir.is_dir()

    def test_user_public_dir_created(self, started_lab, functional_env):
        # A user-public directory named after the abbreviated lab name should exist
        home_sre = functional_env['home_sre']
        subdirs = list(home_sre.iterdir())
        assert len(subdirs) == 1
        assert subdirs[0].is_dir()


# ---------------------------------------------------------------------------
# Tests: eval grades and errors
# ---------------------------------------------------------------------------

class TestEval:

    def test_archive_written(self, evaled_lab):
        # Fixture assertion already checks this; just ensure archive is non-empty
        assert evaled_lab is not None

    def test_routing_grade(self, evaled_lab):
        """ip route returned '192.168...', code 0 → full routing grade."""
        grades = {g['title']: g for g in evaled_lab['grade_list']}
        assert grades['routing']['grade'] == 2
        assert grades['routing']['max_grade'] == 2

    def test_connectivity_grade_partial(self, evaled_lab):
        """ping returned code 1 → partial connectivity grade."""
        grades = {g['title']: g for g in evaled_lab['grade_list']}
        assert grades['connectivity']['grade'] == 1
        assert grades['connectivity']['max_grade'] == 3

    def test_slow_test_grade(self, evaled_lab):
        """sleep 100 timed out (code -1) → slow_test grade awarded."""
        grades = {g['title']: g for g in evaled_lab['grade_list']}
        assert grades['slow_test']['grade'] == 1
        assert grades['slow_test']['max_grade'] == 1

    def test_step2_grade(self, evaled_lab):
        """ip addr on step 2 returned code 0 → step2_check grade awarded."""
        grades = {g['title']: g for g in evaled_lab['grade_list']}
        assert grades['step2_check']['grade'] == 1
        assert grades['step2_check']['max_grade'] == 1

    def test_total_grade(self, evaled_lab):
        assert evaled_lab['total_grade_exo_eval'] == 5   # 2 + 1 + 1 + 1
        assert evaled_lab['total_max_exo_eval'] == 7     # 2 + 3 + 1 + 1

    def test_ping_failure_recorded_as_error(self, evaled_lab):
        """Non-zero exit from ping (no allow_error) must be in errors list."""
        errors = evaled_lab['errors']
        assert any('ping' in (e[1] if isinstance(e, (list, tuple)) else e)
                   for e in errors), f"Expected ping error, got: {errors}"

    def test_sleep_timeout_not_an_error(self, evaled_lab):
        """Timed-out sleep (allow_error=True) must NOT appear in errors list."""
        errors = evaled_lab['errors']
        assert not any('sleep' in e for e in errors), f"Unexpected sleep error: {errors}"

    def test_archive_contains_data_json(self, evaled_lab):
        outer = json.loads(evaled_lab['data_json'])
        assert outer['data']['value'] == 42

    def test_archive_running_lab_name_matches(self, started_lab, evaled_lab):
        assert evaled_lab['running_lab_name'] == started_lab


# ---------------------------------------------------------------------------
# Tests: stop removes project
# ---------------------------------------------------------------------------

class TestArchiveDirCreation:
    def test_dir_created_meanwhile_by_another_evaluation(self, started_lab, monkeypatch):
        """Evaluations running at once (`sre eval-all`) may all find the archive directory
        missing: the ones that lose the race to create it must still save their archive."""
        archives_dir = Path(params.archive_dirs[0]).resolve()
        assert not archives_dir.exists()
        real_exists = Path.exists

        def exists(self, *args, **kwargs):
            if self == archives_dir and not real_exists(self):
                os.mkdir(self, 0o700)  # another evaluation creates it right after our check
                return False
            return real_exists(self, *args, **kwargs)
        monkeypatch.setattr(Path, 'exists', exists)

        with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
            do_eval(running_lab_name=started_lab, print_result=False)
        assert len(list(archives_dir.iterdir())) == 1

    def test_dir_is_created_private(self, evaled_lab):
        archives_dir = Path(params.archive_dirs[0])
        assert stat.S_IMODE(archives_dir.stat().st_mode) == 0o700

    def test_missing_parent_is_an_error(self, started_lab, tmp_path, monkeypatch, capsys):
        """Only the archive directory itself is created: a wrong or unmounted path is reported,
        not silently created (its parents would get a mode that depends on the umask)."""
        monkeypatch.setattr(params, 'archive_dirs', [str(tmp_path / 'missing' / 'archives')])
        with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
            do_eval(running_lab_name=started_lab, print_result=False)
        assert not (tmp_path / 'missing').exists()
        assert "can't save archive" in capsys.readouterr().err


class TestStop:

    def test_stop_removes_project_directory(self, started_lab, mock_sre_args):
        params.SRE.args.running_lab = started_lab
        action_stop()

        proj_dir = Path(params.sre_projects_dir) / started_lab
        assert not proj_dir.exists(), "Project directory must be removed after stop"

    def test_stop_removes_user_public_dir(self, started_lab, mock_sre_args, functional_env):
        params.SRE.args.running_lab = started_lab
        home_sre = functional_env['home_sre']
        action_stop()

        assert list(home_sre.iterdir()) == [], "User public dir must be removed after stop"

    def test_no_projects_remain_after_stop(self, started_lab, mock_sre_args):
        params.SRE.args.running_lab = started_lab
        action_stop()

        projects_dir = Path(params.sre_projects_dir)
        # directory itself may not exist yet if it was never created — check it's empty or gone
        if projects_dir.exists():
            assert list(projects_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Tests: start failure leaves no project behind
# ---------------------------------------------------------------------------

class TestStartFailure:

    def test_missing_grade_class_exits(self, functional_env, tmp_path):
        """do_action_start exits cleanly when Grade class is missing."""
        bad_lab = tmp_path / 'bad_lab.py'
        bad_lab.write_text("""\
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0

@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        return cls()

class NetScheme(NetScheme0):
    _machine_specs = {}
    _network_specs = {}
    _topology = {}
    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
""")
        old_auth = params.authorized_src_dir
        params.authorized_src_dir = [str(tmp_path)] + old_auth
        try:
            with pytest.raises(SystemExit):
                do_action_start(lab_cli_arg=str(bad_lab), lab_cli_arg_is_path=True)
        finally:
            params.authorized_src_dir = old_auth

        projects_dir = Path(params.sre_projects_dir)
        remaining = list(projects_dir.iterdir()) if projects_dir.exists() else []
        assert remaining == [], "No project directory should remain after failed start"

    def test_missing_grade_method_exits(self, functional_env, tmp_path):
        """do_action_start exits cleanly when grade() method is missing.

        A Grade class that does NOT inherit from Grade0 and has no grade()
        triggers the check: hasattr(module_rvlab.Grade, 'grade') is False.
        """
        bad_lab = tmp_path / 'bad_lab2.py'
        bad_lab.write_text("""\
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0

@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        return cls()

class NetScheme(NetScheme0):
    _machine_specs = {}
    _network_specs = {}
    _topology = {}
    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

class Grade:
    pass  # does not inherit Grade0, has no grade() method
""")
        old_auth = params.authorized_src_dir
        params.authorized_src_dir = [str(tmp_path)] + old_auth
        try:
            with pytest.raises(SystemExit):
                do_action_start(lab_cli_arg=str(bad_lab), lab_cli_arg_is_path=True)
        finally:
            params.authorized_src_dir = old_auth

        projects_dir = Path(params.sre_projects_dir)
        remaining = list(projects_dir.iterdir()) if projects_dir.exists() else []
        assert remaining == [], "No project directory should remain after failed start"


# ---------------------------------------------------------------------------
# Tests: save / restore
# ---------------------------------------------------------------------------

    def test_failure_after_deploy_removes_leftover_containers(self, functional_env, monkeypatch):
        """A failure once the containers are up (here in the initial state) must undo the deploy:
        Kathara's undeploy, which cannot see a privileged lab's containers after the permanent
        drop, plus the force-removal of whatever still carries the lab hash."""
        import SRE.command.start as _start_cmd
        from SRE import lib_sre as _lib_sre
        kathara_instance = _lib_sre.Kathara.get_instance()
        container, network = MagicMock(), MagicMock()
        kathara_instance.get_machines_api_objects.return_value = [container]
        kathara_instance.get_links_api_objects.return_value = [network]

        def failing_state(**kwargs):
            raise RuntimeError('boom after deploy')

        monkeypatch.setattr(_start_cmd, 'do_action_state', failing_state)
        with pytest.raises(RuntimeError, match='boom after deploy'):
            do_action_start(lab_cli_arg=str(_LAB_PATH), lab_cli_arg_is_path=True)

        kathara_instance.undeploy_lab.assert_called_once_with('fake-lab-hash-1234')
        kathara_instance.get_machines_api_objects.assert_called_once_with(lab_hash='fake-lab-hash-1234', all_users=True)
        kathara_instance.get_links_api_objects.assert_called_once_with(lab_hash='fake-lab-hash-1234', all_users=True)
        container.remove.assert_called_once_with(v=True, force=True)
        network.remove.assert_called_once_with()
        projects_dir = Path(params.sre_projects_dir)
        assert not projects_dir.exists() or list(projects_dir.iterdir()) == []
        assert list(functional_env['home_sre'].iterdir()) == []


def _write_fake_kathara_tar(archive_path, **_kwargs):
    """Stand-in for Kathara.save_lab(): write a minimal save archive with a manifest."""
    manifest = {"save_mode": "diff", "machines": [
        {"name": "router", "meta": {"image": "kathara_save_h:router"}},
        {"name": "client", "meta": {"image": "kathara_save_h:client"}},
    ]}
    with tarfile.open(archive_path, 'w') as tar:
        payload = json.dumps(manifest).encode()
        info = tarfile.TarInfo('manifest.json')
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))


@pytest.fixture
def save_restore_env(functional_env):
    from SRE import lib_sre as _lib_sre
    kathara_instance = _lib_sre.Kathara.get_instance()
    kathara_instance.save_lab.side_effect = _write_fake_kathara_tar
    kathara_instance.restore_lab.side_effect = lambda archive_path, lab=None, **kw: lab
    return functional_env


def _project_dirs():
    return sorted(p.name for p in Path(params.sre_projects_dir).iterdir() if '@@@' in p.name)


def _data_value(running_lab_name):
    return json.loads((Path(params.sre_projects_dir) / running_lab_name / '.private' / 'data.json').read_text())


def _lab_copy(tmp_path, name, transform):
    """Copy the fixture lab under tmp_path (which functional_env must authorize) after transforming its text."""
    text = transform(_LAB_PATH.read_text())
    dst = tmp_path / 'labs' / name
    dst.parent.mkdir(exist_ok=True)
    dst.write_text(text)
    return dst
class TestSaveRestore:

    def test_save_to_file_layout(self, save_restore_env, started_lab, tmp_path):
        proj = Path(params.sre_projects_dir) / started_lab
        (proj / 'answers' / 'answers.json').write_text('{"q1": "42"}')
        user_public = (proj / '.private' / 'user_public_dir').resolve()
        (user_public / 'hello.txt').write_text('shared file')
        (proj / '.private' / 'files' / 'host.txt').write_text('host file')

        out = tmp_path / 'p.sre'
        do_action_save(started_lab, output=str(out))

        with open(out, 'rb') as f:
            meta, _ = save_archive.read_header(f)
            dest = tmp_path / 'extracted'
            dest.mkdir()
            save_archive.extract_payload(f, str(dest))
        assert meta.lab_name == params.get_lab_name_from_running_lab_name(started_lab)
        assert meta.running_lab_name == started_lab
        assert meta.username == 'testuser'
        assert meta.encrypted is False and meta.full_images is False
        assert meta.srelab_file == str(_LAB_PATH.resolve())
        assert json.loads((dest / 'data.json').read_text())['data']['value'] == 42
        assert tarfile.is_tarfile(dest / 'kathara.tar')
        assert (dest / 'answers' / 'answers.json').read_text() == '{"q1": "42"}'
        assert (dest / 'user_public' / 'hello.txt').read_text() == 'shared file'
        assert (dest / 'files' / 'host.txt').read_text() == 'host file'
        assert not (dest / 'mnt').exists()

    def test_save_lab_called_with_hash_and_diff_mode(self, save_restore_env, started_lab, tmp_path):
        from SRE import lib_sre as _lib_sre
        do_action_save(started_lab, out_fileobj=io.BytesIO())
        kwargs = _lib_sre.Kathara.get_instance().save_lab.call_args.kwargs
        assert kwargs['lab_hash'] == 'fake-lab-hash-1234'
        assert kwargs['filesystem_diff'] is True

    def test_save_to_stream_and_save_state_applied(self, save_restore_env, started_lab, monkeypatch):
        import SRE.command.save as _save_cmd
        states = []
        monkeypatch.setattr(_save_cmd, 'do_action_state',
                            lambda lab, state, net_scheme, project_has_directory: states.append(state))
        buf = io.BytesIO()
        do_action_save(started_lab, out_fileobj=buf)
        assert buf.getvalue().startswith(params.save_file_magic)
        assert states == [params.save_state_name]

    def test_save_refused_without_flag(self, save_restore_env, tmp_path, monkeypatch):
        lab = _lab_copy(tmp_path, 'noflag.py', lambda t: t.replace('allow_save_restore = True', ''))
        monkeypatch.setattr(params, 'authorized_src_dir', params.authorized_src_dir + [str(tmp_path)])
        do_action_start(lab_cli_arg=str(lab), lab_cli_arg_is_path=True)
        (rln,) = _project_dirs()
        with pytest.raises(SystemExit):
            do_action_save(rln, out_fileobj=io.BytesIO())

    def test_user_mode_refusals(self, save_restore_env, started_lab, mock_sre_args, monkeypatch):
        mock_sre_args.user = True
        mock_sre_args.running_lab = started_lab
        mock_sre_args.output = '/tmp/x.sre'
        with pytest.raises(SystemExit):
            action_save()
        mock_sre_args.output = None
        mock_sre_args.full_images = True
        with pytest.raises(SystemExit):
            action_save()
        mock_sre_args.full_images = False
        mock_sre_args.save_file = '/tmp/x.sre'
        with pytest.raises(SystemExit):        # restore must read stdin in user mode
            action_restore()

    def test_user_can_save_a_project_started_by_someone_else(self, save_restore_env, started_lab,
                                                             mock_sre_args, monkeypatch, capsysbinary):
        """A project started by root (`sre start -p ...`) must be savable from the GUI, which
        runs `sre-wrapper save` as the logged-in user: no ownership check in user mode."""
        mock_sre_args.user = True
        mock_sre_args.running_lab = started_lab          # owner is 'testuser'
        monkeypatch.setattr(params.SRE, 'username', 'someone_else')
        action_save()
        assert capsysbinary.readouterr().out.startswith(params.save_file_magic)

    def test_restore_of_path_lab_inside_lab_dir_allowed_in_user_mode(self, save_restore_env, tmp_lab_dir,
                                                                     tmp_path, mock_sre_args, monkeypatch):
        """`sre start -p /opt/sre/lab/x/lab.py` names the lab by its absolute path; a save of
        such a project is restored like the lab `x/lab.py`, so students can restore it too."""
        lab = tmp_lab_dir / 'x' / 'lab.py'
        lab.parent.mkdir()
        lab.write_text(_LAB_PATH.read_text())
        monkeypatch.setattr(params, 'authorized_src_dir', params.authorized_src_dir + [str(tmp_lab_dir)])
        do_action_start(lab_cli_arg=str(lab), lab_cli_arg_is_path=True)
        (rln,) = _project_dirs()
        assert params.get_lab_name_from_running_lab_name(rln).startswith('@')
        out = tmp_path / 'p.sre'
        do_action_save(rln, output=str(out))

        mock_sre_args.user = True
        with open(out, 'rb') as f:
            new_rln = do_action_restore(f)
        assert _project_dirs() == sorted([rln, new_rln])
        assert params.get_lab_name_from_running_lab_name(new_rln) == 'x@lab.py'
        assert (Path(params.sre_projects_dir) / new_rln / '.private' / 'srelab').resolve() == lab.resolve()

    def test_restore_creates_new_project(self, save_restore_env, started_lab, tmp_path, monkeypatch):
        from SRE import lib_sre as _lib_sre
        import SRE.command.start as _start_cmd
        proj = Path(params.sre_projects_dir) / started_lab
        (proj / 'answers' / 'answers.json').write_text('{"q1": "42"}')
        out = tmp_path / 'p.sre'
        do_action_save(started_lab, output=str(out))

        states = []
        real = _start_cmd.do_action_state
        monkeypatch.setattr(_start_cmd, 'do_action_state',
                            lambda **kw: (states.append(kw['state']), real(**kw)))
        with open(out, 'rb') as f:
            new_rln = do_action_restore(f)

        assert new_rln != started_lab
        assert _project_dirs() == sorted([started_lab, new_rln])
        assert params.get_username_from_running_lab_name(new_rln) == 'testuser'
        assert _data_value(new_rln) == _data_value(started_lab)
        new_proj = Path(params.sre_projects_dir) / new_rln
        answers = new_proj / 'answers' / 'answers.json'
        assert answers.read_text() == '{"q1": "42"}'
        assert stat.S_IMODE(answers.stat().st_mode) == 0o666
        assert stat.S_IMODE((new_proj / 'answers').stat().st_mode) == 0o777
        info = json.loads((new_proj / 'info.json').read_text())
        assert info['allow_save_restore'] is True
        assert (new_proj / '.private' / 'srelab').resolve() == _LAB_PATH.resolve()
        assert (new_proj / '.private' / 'user_public_dir').resolve().is_dir()
        call = _lib_sre.Kathara.get_instance().restore_lab.call_args
        assert call.args[0].endswith(params.save_kathara_name)
        assert call.kwargs['lab'] is not None
        assert states == [params.restore_state_name]

    def test_restore_rollback_on_failure(self, save_restore_env, started_lab, tmp_path):
        from SRE import lib_sre as _lib_sre
        out = tmp_path / 'p.sre'
        do_action_save(started_lab, output=str(out))
        kathara_instance = _lib_sre.Kathara.get_instance()
        kathara_instance.restore_lab.side_effect = RuntimeError('boom')
        home_before = sorted(p.name for p in Path(params.sre_user_public_dir).iterdir())
        with open(out, 'rb') as f, pytest.raises(RuntimeError):
            do_action_restore(f)
        assert _project_dirs() == [started_lab]
        assert sorted(p.name for p in Path(params.sre_user_public_dir).iterdir()) == home_before
        kathara_instance.undeploy_lab.assert_called_once()

    def test_restore_absolute_path_lab_refused_in_user_mode(self, save_restore_env, started_lab,
                                                            tmp_path, mock_sre_args):
        out = tmp_path / 'p.sre'
        do_action_save(started_lab, output=str(out))
        mock_sre_args.user = True
        with open(out, 'rb') as f, pytest.raises(SystemExit):
            do_action_restore(f)
        assert _project_dirs() == [started_lab]

    def test_encrypted_roundtrip(self, save_restore_env, tmp_path, monkeypatch):
        pytest.importorskip('cryptography')
        monkeypatch.setattr(params, 'save_kdf_iterations', 1000)
        lab = _lab_copy(tmp_path, 'keyed.py', lambda t: t + '\nsave_key = "s3cret"\n')
        monkeypatch.setattr(params, 'authorized_src_dir', params.authorized_src_dir + [str(tmp_path)])
        do_action_start(lab_cli_arg=str(lab), lab_cli_arg_is_path=True)
        (rln,) = _project_dirs()
        out = tmp_path / 'p.sre'
        do_action_save(rln, output=str(out))

        blob = out.read_bytes()
        with open(out, 'rb') as f:
            meta, _ = save_archive.read_header(f)
        assert meta.encrypted is True and meta.kdf_salt
        assert b'data.json' not in blob.split(b'\n', 2)[2]

        with open(out, 'rb') as f:
            new_rln = do_action_restore(f)
        assert _project_dirs() == sorted([rln, new_rln])
        assert _data_value(new_rln) == _data_value(rln)

        # the lab's key changed → the file cannot be restored any more
        lab.write_text(lab.read_text().replace('"s3cret"', '"other"'))
        with open(out, 'rb') as f, pytest.raises(SystemExit):
            do_action_restore(f)
        assert _project_dirs() == sorted([rln, new_rln])

    def _keyed_lab_in_lab_dir(self, tmp_lab_dir, monkeypatch, key):
        """A lab inside params.lab_dir (so that user-mode restore reaches the key checks)."""
        lab = tmp_lab_dir / 'keyed' / 'lab.py'
        lab.parent.mkdir()
        lab.write_text(_LAB_PATH.read_text() + (f'\nsave_key = "{key}"\n' if key else ''))
        monkeypatch.setattr(params, 'authorized_src_dir', params.authorized_src_dir + [str(tmp_lab_dir)])
        do_action_start(lab_cli_arg=str(lab), lab_cli_arg_is_path=True)
        (rln,) = _project_dirs()
        return lab, rln

    def test_cleartext_file_for_keyed_lab_accepted_by_privileged_with_warning(self, save_restore_env, tmp_lab_dir,
                                                                             tmp_path, monkeypatch, capsys):
        lab, rln = self._keyed_lab_in_lab_dir(tmp_lab_dir, monkeypatch, key=None)
        out = tmp_path / 'p.sre'
        do_action_save(rln, output=str(out))            # cleartext (no key yet)
        lab.write_text(lab.read_text() + '\nsave_key = "s3cret"\n')
        with open(out, 'rb') as f:
            do_action_restore(f)
        assert len(_project_dirs()) == 2
        assert 'warning: restoring a cleartext save file' in capsys.readouterr().err

    def test_cleartext_file_for_keyed_lab_refused_in_user_mode(self, save_restore_env, tmp_lab_dir, tmp_path,
                                                               monkeypatch, mock_sre_args, capsys):
        lab, rln = self._keyed_lab_in_lab_dir(tmp_lab_dir, monkeypatch, key=None)
        out = tmp_path / 'p.sre'
        do_action_save(rln, output=str(out))            # cleartext (no key yet)
        lab.write_text(lab.read_text() + '\nsave_key = "s3cret"\n')
        mock_sre_args.user = True
        with open(out, 'rb') as f, pytest.raises(SystemExit):
            do_action_restore(f)
        assert 'only accepts encrypted save files' in capsys.readouterr().err
        assert _project_dirs() == [rln]

    def test_encrypted_file_refused_when_lab_has_no_key(self, save_restore_env, tmp_lab_dir, tmp_path,
                                                         monkeypatch, capsys):
        pytest.importorskip('cryptography')
        monkeypatch.setattr(params, 'save_kdf_iterations', 1000)
        lab, rln = self._keyed_lab_in_lab_dir(tmp_lab_dir, monkeypatch, key='s3cret')
        out = tmp_path / 'p.sre'
        do_action_save(rln, output=str(out))            # encrypted
        lab.write_text(lab.read_text().replace('save_key = "s3cret"', ''))
        with open(out, 'rb') as f, pytest.raises(SystemExit):
            do_action_restore(f)
        assert 'encrypted but the lab defines no save_key' in capsys.readouterr().err
        assert _project_dirs() == [rln]

    def test_lifecycle_states_not_listed_in_debug_info(self, started_lab):
        info = json.loads((Path(params.sre_projects_dir) / started_lab / 'info.json').read_text())
        assert not set(params.lifecycle_state_names) & set(info['admin_only_states'])
        assert not set(params.lifecycle_state_names) & set(info['user_allowed_states'])


# ---------------------------------------------------------------------------
# Tests: instructor mode
# ---------------------------------------------------------------------------

_INSTRUCTOR_LAB_PATH = Path(__file__).parent / 'labs' / 'instructor_test_lab.py'


@pytest.fixture
def instructor_env(functional_env, mock_sre_args, monkeypatch):
    """functional_env for the instructor-mode commands.  The projects are not debug projects
    (an unset flag of the MagicMock args is truthy)."""
    import SRE.command.instructor_mode as _instructor_cmd
    import SRE.command.state as _state_cmd
    monkeypatch.setattr(_instructor_cmd, 'drop_privileges_permanently_if_not_needed', lambda net_scheme: None)
    monkeypatch.setattr(_instructor_cmd, 'set_sudo_uid_for_username', lambda username: None)
    monkeypatch.setattr(_state_cmd, 'drop_privileges_permanently_if_not_needed', lambda net_scheme: None)
    monkeypatch.setattr(_state_cmd, 'gain_privileges_if_needed', lambda net_scheme: None)
    monkeypatch.setattr(_state_cmd, 'set_sudo_uid_for_username', lambda username: None)
    monkeypatch.setattr(_state_cmd, 'drop_privileges_temporarily', lambda: None)
    mock_sre_args.debug_project = False
    return functional_env


def _start_instructor_lab(instructor_mode: bool, lab: Path = _INSTRUCTOR_LAB_PATH) -> str:
    before = set(_project_dirs()) if Path(params.sre_projects_dir).is_dir() else set()
    do_action_start(lab_cli_arg=str(lab), lab_cli_arg_is_path=True, instructor_mode=instructor_mode)
    (running_lab_name,) = set(_project_dirs()) - before
    return running_lab_name


def _instructor_lab_copy(tmp_path, monkeypatch, name: str, transform=lambda text: text) -> Path:
    """A copy of the instructor fixture lab under tmp_path (a lab of its own: another project
    name, a file the test may edit), its text passed through *transform*."""
    if str(tmp_path) not in params.authorized_src_dir:
        monkeypatch.setattr(params, 'authorized_src_dir', params.authorized_src_dir + [str(tmp_path)])
    lab = tmp_path / 'labs' / name
    lab.parent.mkdir(exist_ok=True)
    lab.write_text(transform(_INSTRUCTOR_LAB_PATH.read_text()))
    return lab


def _replace_once(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, old
    return text.replace(old, new)


_LAB_IMPORT = "from SRE.lib_sre import Data0, NetScheme0, Grade0, instructor, make_tr\n"
_LAB_GRADE = "class Grade(Grade0):\n    def grade(self):\n        super().grade()\n"
# texts built while the lab module is imported: a title, and the description of a state
_MODULE_LEVEL_TEXTS = ("title = instructor('SECRET title ') + 'Lab'\n"
                       "allow_user_states = True\n")
_STATE_WITH_INSTRUCTOR_TEXT = ("    @sre_state(user_allowed=True, description=instructor('SECRET state ') + 'Apply')\n"
                               "    def fix(self):\n"
                               "        pass\n\n\n")


def _with_module_level_instructor_texts(text: str) -> str:
    text = _replace_once(text, _LAB_IMPORT,
                         _LAB_IMPORT.replace("make_tr", "make_tr, sre_state") + _MODULE_LEVEL_TEXTS)
    return _replace_once(text, _LAB_GRADE, _STATE_WITH_INSTRUCTOR_TEXT + _LAB_GRADE)


def _forcing_the_instructor_flag(text: str) -> str:
    """The lab made to produce instructor fragments whatever the mode of its project: it turns
    the flag on itself when it is imported, in NetScheme.__init__ and in grade()."""
    force = "set_instructor_context(True)\n"
    text = _replace_once(text, _LAB_IMPORT,
                         _LAB_IMPORT.replace("make_tr", "make_tr, sre_state")
                         + "from SRE.instructor_text import set_instructor_context\n" + force
                         + _MODULE_LEVEL_TEXTS)
    init = "        super().__init__(data=data, running_lab_name=running_lab_name)\n"
    text = _replace_once(text, init, init + "        " + force)
    return _replace_once(text, _LAB_GRADE, _STATE_WITH_INSTRUCTOR_TEXT + _LAB_GRADE + "        " + force)


_LAB_STATES = ("    @sre_state(user_allowed=True, description='Break the route')\n"
               "    def broken(self):\n"
               "        pass\n\n"
               "    @sre_state(description='Apply the solution')\n"
               "    def final(self):\n"
               "        pass\n\n\n")


def _with_states(allow_user_states: bool):
    """The lab with a user-allowed state (`broken`) and one reserved to privileged users (`final`)."""
    def transform(text: str) -> str:
        text = _replace_once(text, _LAB_IMPORT,
                             _LAB_IMPORT.replace("make_tr", "make_tr, sre_state")
                             + ("allow_user_states = True\n" if allow_user_states else ""))
        return _replace_once(text, _LAB_GRADE, _LAB_STATES + _LAB_GRADE)
    return transform


def _apply_state(running_lab_name: str, state: str):
    from SRE.command.state import action_state
    params.SRE.args.running_lab = running_lab_name
    params.SRE.args.state = state
    action_state()


def _raw_info(running_lab_name: str) -> str:
    return (Path(params.sre_projects_dir) / running_lab_name / 'info.json').read_text()


def _info(running_lab_name: str) -> dict:
    return json.loads((Path(params.sre_projects_dir) / running_lab_name / 'info.json').read_text())


def _info_texts(info: dict) -> list:
    """Every lab text of info.json a student can read."""
    texts = [info['title'], info['informations']]
    for question in info['questions']:
        texts += [question['title'], question['description']]
    return texts


def _instructor_marker(running_lab_name: str) -> Path:
    return Path(params.instructor_mode_marker_filename(running_lab_name))


class TestInstructorMode:

    def test_normal_project_holds_no_instructor_text(self, instructor_env):
        from SRE.instructor_text import has_instructor
        rln = _start_instructor_lab(False)
        info = _info(rln)
        assert info['instructor_mode'] is False
        assert not _instructor_marker(rln).exists()
        assert not any(has_instructor(text) for text in _info_texts(info))
        raw = (Path(params.sre_projects_dir) / rln / 'info.json').read_text()
        for secret in ('Solution', 'expected', 'attendu', 'Any notation', 'The mask is 24'):
            assert secret not in raw
        assert 'Configure the default route' in info['informations']['en']
        assert info['questions'][0]['title'] == {'en': 'Gateway', 'fr': 'Passerelle'}
        assert not Path(params.operations_log_filename(rln)).exists()

    def test_instructor_project_keeps_the_instructor_text(self, instructor_env):
        from SRE.instructor_text import has_instructor, strip_instructor, unwrap_instructor
        rln = _start_instructor_lab(True)
        info = _info(rln)
        assert info['instructor_mode'] is True and info['debug_project'] is False
        marker = _instructor_marker(rln)
        assert marker.exists() and stat.S_IMODE(marker.stat().st_mode) == 0o600
        assert has_instructor(info['informations'])
        assert '## Solution' in unwrap_instructor(info['informations']['en'])
        assert 'Solution' not in strip_instructor(info['informations']['en'])
        question = info['questions'][0]
        assert unwrap_instructor(question['title']) == {'en': 'Gateway (expected: 10.0.0.1)',
                                                        'fr': 'Passerelle (attendu : 10.0.0.1)'}
        assert strip_instructor(question['title']) == {'en': 'Gateway', 'fr': 'Passerelle'}
        assert has_instructor(info['questions'][1]['description'])

    def test_instructor_project_logs_the_states_only(self, instructor_env):
        rln = _start_instructor_lab(True)
        log_path = Path(params.operations_log_filename(rln))
        assert log_path.read_text().rstrip('\n').endswith('  state initial')
        with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
            do_eval(running_lab_name=rln, print_result=False)
        assert 'evaluation' not in log_path.read_text()
        # a project that is also a debug project logs its evaluations
        Path(params.debug_project_marker_filename(rln)).touch()
        with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
            do_eval(running_lab_name=rln, print_result=False)
        assert '  evaluation\n' in log_path.read_text()

    def test_set_and_remove_on_a_running_project(self, instructor_env, mock_sre_args):
        from SRE.command.instructor_mode import action_remove_instructor_mode, action_set_instructor_mode
        from SRE.instructor_text import has_instructor
        rln = _start_instructor_lab(False)
        hashes = [q['question_hash'] for q in _info(rln)['questions']]
        mock_sre_args.running_lab = rln

        action_set_instructor_mode()
        info = _info(rln)
        assert _instructor_marker(rln).exists() and info['instructor_mode'] is True
        assert has_instructor(info['informations']) and has_instructor(info['questions'][0]['title'])
        # the answers stay attached: same hashes in both modes
        assert [q['question_hash'] for q in info['questions']] == hashes
        action_set_instructor_mode()   # idempotent
        assert _info(rln)['instructor_mode'] is True

        log_path = Path(params.operations_log_filename(rln))
        log_path.write_text('=== t  state final\n')
        action_remove_instructor_mode()
        info = _info(rln)
        assert not _instructor_marker(rln).exists() and info['instructor_mode'] is False
        assert not any(has_instructor(text) for text in _info_texts(info))
        assert [q['question_hash'] for q in info['questions']] == hashes
        assert not log_path.exists()
        action_remove_instructor_mode()   # idempotent
        assert _info(rln)['instructor_mode'] is False

    def test_remove_keeps_the_log_of_a_debug_project(self, instructor_env, mock_sre_args):
        from SRE.command.instructor_mode import action_remove_instructor_mode
        rln = _start_instructor_lab(True)
        Path(params.debug_project_marker_filename(rln)).touch()
        mock_sre_args.running_lab = rln
        action_remove_instructor_mode()
        assert Path(params.operations_log_filename(rln)).exists()
        assert _info(rln)['instructor_mode'] is False and _info(rln)['debug_project'] is True

    def test_restore_takes_the_mode_from_its_flag_only(self, instructor_env, save_restore_env, tmp_path):
        from SRE.instructor_text import has_instructor
        rln = _start_instructor_lab(True)
        out = tmp_path / 'p.sre'
        do_action_save(rln, output=str(out))
        with open(out, 'rb') as f:
            plain = do_action_restore(f)
        assert not _instructor_marker(plain).exists()
        assert _info(plain)['instructor_mode'] is False
        assert not any(has_instructor(text) for text in _info_texts(_info(plain)))
        with open(out, 'rb') as f:
            restored = do_action_restore(f, instructor_mode=True)
        assert restored not in (rln, plain)
        assert _instructor_marker(restored).exists()
        assert _info(restored)['instructor_mode'] is True and has_instructor(_info(restored)['informations'])

    def test_user_mode_refusals(self, instructor_env, mock_sre_args, capsys):
        from SRE.command.instructor_mode import action_remove_instructor_mode, action_set_instructor_mode
        from SRE.command.start import action_start
        rln = _start_instructor_lab(False)
        mock_sre_args.user = True
        mock_sre_args.running_lab = rln
        for action in (action_set_instructor_mode, action_remove_instructor_mode):
            with pytest.raises(SystemExit):
                action()
        assert not _instructor_marker(rln).exists()

        mock_sre_args.instructor_mode = True
        mock_sre_args.lab = str(_INSTRUCTOR_LAB_PATH)
        mock_sre_args.xauth_file = None
        with pytest.raises(SystemExit):
            action_start()
        assert '--instructor-mode is not available in user mode' in capsys.readouterr().err
        mock_sre_args.save_file = params.save_stdio_arg
        with pytest.raises(SystemExit):
            action_restore()
        assert '--instructor-mode is not available in user mode' in capsys.readouterr().err
        assert _project_dirs() == [rln]

    def test_info_json_is_stripped_whatever_instructor_returned(self, instructor_env, tmp_path, monkeypatch):
        """Safety net of save_lab_info(): the project of a lab that produces instructor fragments
        outside the instructor mode still gets none in its info.json (students read that file)."""
        from SRE.instructor_text import has_instructor
        # the lab does produce fragments everywhere, title and state description included:
        # seen in a project in instructor mode, where nothing is stripped
        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'forced_shown.py', _forcing_the_instructor_flag)
        info = _info(_start_instructor_lab(True, lab))
        assert has_instructor(info['title']) and has_instructor(info['user_allowed_states']['fix'])
        assert has_instructor(info['informations'])
        assert has_instructor(info['questions'][0]['title']) and has_instructor(info['questions'][0]['description'])
        assert has_instructor(info['questions'][1]['description'])

        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'forced_hidden.py', _forcing_the_instructor_flag)
        rln = _start_instructor_lab(False, lab)
        info = _info(rln)
        assert info['instructor_mode'] is False
        assert not any(has_instructor(text) for text in _info_texts(info))
        assert info['title'] == {'en': 'Lab'}
        assert info['user_allowed_states'] == {'fix': {'en': 'Apply'}}
        assert info['questions'][0]['title'] == {'en': 'Gateway', 'fr': 'Passerelle'}
        assert 'Configure the default route' in info['informations']['en']
        raw = _raw_info(rln)
        for secret in ('SECRET', 'Solution', 'expected', 'attendu', 'Any notation', 'The mask is 24'):
            assert secret not in raw
        assert not has_instructor(json.loads(raw))

    def test_module_level_instructor_calls_are_dropped(self, instructor_env, tmp_path, monkeypatch):
        """The mode of a project is not known while its lab module is imported: instructor() then
        gives nothing, even in a project in instructor mode and with the flag left on by a
        project the thread handled before."""
        from SRE.instructor_text import has_instructor, set_instructor_context
        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'module_level.py', _with_module_level_instructor_texts)
        set_instructor_context(True)
        rln = _start_instructor_lab(True, lab)
        info = _info(rln)
        assert info['instructor_mode'] is True
        assert info['title'] == {'en': 'Lab'}
        assert info['user_allowed_states'] == {'fix': {'en': 'Apply'}}
        assert 'SECRET' not in _raw_info(rln)
        # the texts built in NetScheme.__init__ and in grade() are kept
        assert has_instructor(info['informations']) and has_instructor(info['questions'][0]['title'])

    def test_eval_rewrites_info_json_of_an_edited_lab(self, instructor_env, tmp_path, monkeypatch):
        """`sre eval` writes info.json again when the lab file is newer: the instructor texts of
        the edited lab reach the project in instructor mode, and only that one."""
        from SRE.instructor_text import has_instructor, strip_instructor, unwrap_instructor
        projects = {}
        for instructor_mode, name in ((True, 'edited_instructor.py'), (False, 'edited_normal.py')):
            lab = _instructor_lab_copy(tmp_path, monkeypatch, name)
            projects[instructor_mode] = _start_instructor_lab(instructor_mode, lab)
            lab.write_text(lab.read_text().replace('## Solution', '## New solution')
                           .replace('Configure the default route', 'Set the default route'))
            newer = time.time() + 60
            os.utime(lab, (newer, newer))
        assert 'New solution' not in _raw_info(projects[True]) + _raw_info(projects[False])

        with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
            for rln in projects.values():
                do_eval(running_lab_name=rln, print_result=False)

        info = _info(projects[True])
        assert info['instructor_mode'] is True and has_instructor(info['informations'])
        assert '## New solution' in unwrap_instructor(info['informations']['en'])
        assert 'Set the default route' in strip_instructor(info['informations']['en'])
        info = _info(projects[False])
        assert info['instructor_mode'] is False
        assert not any(has_instructor(text) for text in _info_texts(info))
        assert 'Set the default route' in info['informations']['en']
        assert 'solution' not in _raw_info(projects[False]).lower()

    def test_eval_leaves_info_json_alone_when_the_lab_is_not_newer(self, instructor_env):
        rln = _start_instructor_lab(True)
        info_path = Path(params.sre_projects_dir) / rln / 'info.json'
        newer = time.time() + 60
        os.utime(info_path, (newer, newer))
        with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
            do_eval(running_lab_name=rln, print_result=False)
        assert info_path.stat().st_mtime == newer

    def test_eval_all_with_mixed_projects(self, instructor_env, mock_sre_args, tmp_path, monkeypatch):
        """`sre eval-all` evaluates the projects in one process, one thread each: an instructor
        project and a normal one evaluated at the same time each keep their own mode.  Both
        info.json files are older than their lab file, so both are written again."""
        import SRE.command.eval as _eval_cmd
        from SRE.command.eval_all import action_eval_all
        from SRE.instructor_text import has_instructor
        instructor_project = _start_instructor_lab(True)
        normal_project = _start_instructor_lab(False, _instructor_lab_copy(tmp_path, monkeypatch, 'other.py'))
        info_paths = {rln: Path(params.sre_projects_dir) / rln / 'info.json'
                      for rln in (instructor_project, normal_project)}
        for info_path in info_paths.values():
            os.utime(info_path, (1, 1))
        # Both evaluations have built their NetScheme (which sets the instructor flag of its
        # thread) before either goes on to Grade / save_lab_info(): they really overlap.
        both_started = threading.Barrier(2, timeout=20)
        threads = set()

        def wait_for_the_other_evaluation(username):
            threads.add(threading.get_ident())
            both_started.wait()
        monkeypatch.setattr(_eval_cmd, 'set_sudo_uid_for_username', wait_for_the_other_evaluation)
        mock_sre_args.display_grades = False

        with patch.object(Grade0, 'run_tests_on_machine', side_effect=_fake_run_tests_on_machine):
            action_eval_all()

        assert len(threads) == 2 and not both_started.broken
        assert all(info_path.stat().st_mtime != 1 for info_path in info_paths.values())
        assert len(list(Path(params.archive_dirs[0]).iterdir())) == 2
        info = _info(instructor_project)
        assert info['instructor_mode'] is True
        assert has_instructor(info['informations']) and has_instructor(info['questions'][0]['title'])
        info = _info(normal_project)
        assert info['instructor_mode'] is False
        assert not any(has_instructor(text) for text in _info_texts(info))
        for secret in ('Solution', 'expected', 'Any notation', 'The mask is 24'):
            assert secret not in _raw_info(normal_project)

    # -- states: every state can be applied to a project in instructor mode, as to a debug project

    BROKEN = {'broken': {'en': 'Break the route'}}
    FINAL = {'final': {'en': 'Apply the solution'}}

    def test_instructor_project_lists_every_state(self, instructor_env, tmp_path, monkeypatch):
        """info.json lists every state but the lifecycle ones; those a student could not apply
        are in admin_only_states (the GUI shows them only while the button is on)."""
        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'states_normal.py', _with_states(True))
        info = _info(_start_instructor_lab(False, lab))
        assert info['user_allowed_states'] == self.BROKEN and info['admin_only_states'] == []

        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'states_instructor.py', _with_states(True))
        info = _info(_start_instructor_lab(True, lab))
        assert info['user_allowed_states'] == {**self.BROKEN, **self.FINAL}
        assert info['admin_only_states'] == ['final']
        assert not set(params.lifecycle_state_names) & set(info['user_allowed_states'])

    def test_instructor_project_of_a_lab_without_user_states(self, instructor_env, tmp_path, monkeypatch):
        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'no_user_states_normal.py', _with_states(False))
        info = _info(_start_instructor_lab(False, lab))
        assert info['user_allowed_states'] == {} and info['admin_only_states'] == []

        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'no_user_states_instructor.py', _with_states(False))
        info = _info(_start_instructor_lab(True, lab))
        assert info['user_allowed_states'] == {**self.BROKEN, **self.FINAL}
        assert info['admin_only_states'] == ['broken', 'final']

    def test_set_and_remove_switch_the_listed_states(self, instructor_env, mock_sre_args, tmp_path, monkeypatch):
        from SRE.command.instructor_mode import action_remove_instructor_mode, action_set_instructor_mode
        rln = _start_instructor_lab(False, _instructor_lab_copy(tmp_path, monkeypatch, 'states.py', _with_states(True)))
        mock_sre_args.running_lab = rln
        action_set_instructor_mode()
        assert _info(rln)['user_allowed_states'] == {**self.BROKEN, **self.FINAL}
        assert _info(rln)['admin_only_states'] == ['final']
        action_remove_instructor_mode()
        assert _info(rln)['user_allowed_states'] == self.BROKEN and _info(rln)['admin_only_states'] == []

    def test_user_mode_applies_any_state_of_an_instructor_project(self, instructor_env, mock_sre_args,
                                                                  tmp_path, monkeypatch, capsys):
        """`sre --user state` (what the GUI runs): a state reserved to privileged users is refused
        on a normal project and applied on a project in instructor mode."""
        normal = _start_instructor_lab(False, _instructor_lab_copy(tmp_path, monkeypatch, 'a.py', _with_states(True)))
        instructor_project = _start_instructor_lab(
            True, _instructor_lab_copy(tmp_path, monkeypatch, 'b.py', _with_states(True)))
        mock_sre_args.user = True

        _apply_state(normal, 'broken')
        with pytest.raises(SystemExit):
            _apply_state(normal, 'final')
        assert "state 'final' is not allowed in user mode" in capsys.readouterr().err

        _apply_state(instructor_project, 'broken')
        _apply_state(instructor_project, 'final')
        log = Path(params.operations_log_filename(instructor_project)).read_text()
        assert '  state broken\n' in log and '  state final\n' in log
        with pytest.raises(SystemExit):
            _apply_state(instructor_project, 'nosuchstate')
        assert "unknown state 'nosuchstate'" in capsys.readouterr().err

    def test_user_mode_and_a_lab_without_user_states(self, instructor_env, mock_sre_args, tmp_path,
                                                     monkeypatch, capsys):
        from SRE.command.instructor_mode import action_remove_instructor_mode
        rln = _start_instructor_lab(True, _instructor_lab_copy(tmp_path, monkeypatch, 'c.py', _with_states(False)))
        mock_sre_args.user = True
        _apply_state(rln, 'final')
        _apply_state(rln, 'broken')

        mock_sre_args.user = False
        mock_sre_args.running_lab = rln
        action_remove_instructor_mode()
        mock_sre_args.user = True
        for state in ('broken', 'final'):
            with pytest.raises(SystemExit):
                _apply_state(rln, state)
            assert 'state changes are not allowed in user mode for this lab' in capsys.readouterr().err

    def test_info_json_written_as_root_is_given_to_sre(self, instructor_env, mock_sre_args, monkeypatch):
        """For a lab with privileged machines root is only dropped temporarily, and the Kathara
        calls of save_lab_info() leave the effective uid at 0: `sre set-instructor-mode` then
        wrote an info.json owned by root (seen with real containers, test_docker_lifecycle.py)."""
        from SRE.command.instructor_mode import action_set_instructor_mode
        rln = _start_instructor_lab(False)
        mock_sre_args.running_lab = rln
        chowned = []
        monkeypatch.setattr(os, 'geteuid', lambda: 0)
        monkeypatch.setattr(os, 'fchown', lambda fd, uid, gid: chowned.append((uid, gid)))
        action_set_instructor_mode()
        assert chowned == [(params.sre_uid, -1)]
        assert _info(rln)['instructor_mode'] is True

    # -- sbin/strip-instructor

    def test_stripped_lab_is_the_normal_project(self, instructor_env, tmp_path, monkeypatch):
        """sbin/strip-instructor: the lab file without its instructor() calls gives the info.json
        of the original lab started as a normal project, same texts and same question hashes."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))
        from strip_instructor import strip_source

        def stripped(text: str) -> str:
            result = strip_source(text.encode())
            assert result.calls == 4 and result.import_removed and not result.warnings
            return result.data.decode()

        original = _info(_start_instructor_lab(False))
        lab = _instructor_lab_copy(tmp_path, monkeypatch, 'stripped.py', stripped)
        # (the docstring of the fixture lab still names the function: comments are not touched)
        assert ' instructor, ' not in lab.read_text() and 'Solution' not in lab.read_text()
        info = _info(_start_instructor_lab(False, lab))
        for key in ('informations', 'questions', 'user_allowed_states', 'admin_only_states', 'instructor_mode'):
            assert info[key] == original[key], key

        # and it stays a normal project in instructor mode: there is nothing left to show
        from SRE.instructor_text import has_instructor
        in_mode = _info(_start_instructor_lab(True, _instructor_lab_copy(tmp_path, monkeypatch, 'stripped2.py', stripped)))
        assert in_mode['instructor_mode'] is True
        assert not any(has_instructor(text) for text in _info_texts(in_mode))
        assert in_mode['questions'] == original['questions']
