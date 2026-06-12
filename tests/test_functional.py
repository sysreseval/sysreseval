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
import json
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

    # Set SRE.args attributes that do_action_start reads (MagicMock auto-attributes
    # are truthy, so we must explicitly set optional ones to None/False)
    args = params.SRE.args
    args.set_flavor_name = None
    args.data_version = None
    args.data = None
    args.flavor_json = None
    args.flavor = None

    # Import Lab and Kathara from lib_sre's own namespace so we patch the
    # exact mock objects that lib_sre uses — independent of test ordering.
    # (test_net_config.py replaces sys.modules stubs, creating new mocks;
    # lib_sre keeps its original imports, so sys.modules may diverge.)
    from SRE import lib_sre as _lib_sre
    _lib_sre.Lab.return_value.hash = "fake-lab-hash-1234"

    kathara_instance = _lib_sre.Kathara.get_instance()

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
