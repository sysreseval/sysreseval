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
import shutil
import stat
import tarfile
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
    monkeypatch.setattr(_eval_cmd,  'drop_privileges_permanently',            noop)
    monkeypatch.setattr(_eval_cmd,  'drop_privileges_permanently_if_not_needed', noop_ns)
    monkeypatch.setattr(_eval_cmd,  'drop_privileges_temporarily',            noop)
    monkeypatch.setattr(_eval_cmd,  'gain_privileges_if_needed',              noop_ns)
    monkeypatch.setattr(_eval_cmd,  'set_sudo_uid_for_username',              noop_u)
    monkeypatch.setattr(_stop_cmd,  'drop_privileges_permanently',            noop)
    monkeypatch.setattr(_stop_cmd,  'gain_privileges',                        noop)
    monkeypatch.setattr(_stop_cmd,  'set_sudo_uid_for_username',              noop_u)
    import SRE.command.save    as _save_cmd
    import SRE.command.restore as _restore_cmd
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
    kathara_instance.save_lab.reset_mock(side_effect=True)
    kathara_instance.restore_lab.reset_mock(side_effect=True)
    kathara_instance.undeploy_lab.reset_mock()

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
        monkeypatch.setattr(params.SRE, 'username', 'someone_else')
        with pytest.raises(SystemExit):        # another student's project
            action_save()
        mock_sre_args.save_file = '/tmp/x.sre'
        with pytest.raises(SystemExit):        # restore must read stdin in user mode
            action_restore()

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

    def test_cleartext_file_refused_in_user_mode_when_lab_has_key(self, save_restore_env, tmp_path,
                                                                  monkeypatch, mock_sre_args):
        lab = _lab_copy(tmp_path, 'keyed2.py', lambda t: t)
        monkeypatch.setattr(params, 'authorized_src_dir', params.authorized_src_dir + [str(tmp_path)])
        do_action_start(lab_cli_arg=str(lab), lab_cli_arg_is_path=True)
        (rln,) = _project_dirs()
        out = tmp_path / 'p.sre'
        do_action_save(rln, output=str(out))            # cleartext (no key yet)
        lab.write_text(lab.read_text() + '\nsave_key = "s3cret"\n')
        # privileged: accepted with a warning
        with open(out, 'rb') as f:
            do_action_restore(f)
        assert len(_project_dirs()) == 2

    def test_lifecycle_states_not_listed_in_debug_info(self, started_lab):
        info = json.loads((Path(params.sre_projects_dir) / started_lab / 'info.json').read_text())
        assert not set(params.lifecycle_state_names) & set(info['admin_only_states'])
        assert not set(params.lifecycle_state_names) & set(info['user_allowed_states'])
