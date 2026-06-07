"""
Tests that `sre state` reproduces the right uid / euid / SUDO_UID context
based on whether the lab has privileged machines.

Background — this mirrors the bug fixed for `eval` in commit 7bc2bb2 ("bug priv").
Kathara labels containers with `user=<owner>-{hostname}` and filters by that
label.  The label's <owner> is computed differently depending on the (uid, euid,
SUDO_UID) state at `deploy_lab` time:
  - privileged lab:  euid is raised to 0, Kathara uses SUDO_UID → label = lab-owner
  - non-privileged:  fully dropped to sre_uid,                  → label = sre

`sre state` must reproduce the matching state at `get_lab_from_kathara()` time,
otherwise the returned `lab.machines` is empty and every `self.file()` / `self.cmd()`
op is silently dropped.

The tests below simulate the (uid, euid, SUDO_UID) state machine — we can't
actually setuid in a pytest process — and assert on the snapshot at each
stage of `action_state()`.
"""
from unittest.mock import MagicMock

import pytest

from SRE import params
from SRE.command import state as state_cmd


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeNetScheme:
    """Minimal NetScheme stand-in: just enough surface for action_state()."""

    def __init__(self, privileged, on_kathara_query):
        self._privileged = privileged
        self._on_kathara_query = on_kathara_query
        self.running_lab_name = '20260101000000@@@test_lab@@@em'

    def has_privileged_machines(self):
        return self._privileged

    def get_lab_from_kathara(self):
        self._on_kathara_query()
        return MagicMock(machines={'m1': MagicMock()})

    @staticmethod
    def get_state_methods():
        return ['initial', 'final']

    @staticmethod
    def is_state_user_allowed(state):
        return True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def privilege_simulator(monkeypatch):
    """Replace the four privilege helpers in state_cmd with fakes that maintain
    a (uid, euid, sudo_uid) state machine and snapshot it on every call.

    Initial state simulates the process at the entry of `action_state()`
    after sre.py's `drop_privileges_temporarily()` (with 'state' now in the
    temp-drop list): ruid=0, euid=sre_uid, SUDO_UID=invoking-user's uid.
    """
    SRE_UID = 1100
    state = {'uid': 0, 'euid': SRE_UID, 'sudo_uid': '1000', 'log': []}

    def snapshot(stage):
        state['log'].append((stage, {
            'uid': state['uid'],
            'euid': state['euid'],
            'sudo_uid': state['sudo_uid'],
        }))

    def fake_drop_perm_if_not_needed(net_scheme):
        # mirrors utils_privileges._drop_permanently when no priv machines
        if not net_scheme.has_privileged_machines():
            state['uid'] = SRE_UID
            state['euid'] = SRE_UID
        snapshot('drop_perm_if_not_needed')

    def fake_set_sudo_uid(username):
        # mirrors set_sudo_uid_for_username: no-op unless real uid is 0
        if state['uid'] == 0 and username:
            state['sudo_uid'] = f'uid_of({username})'
        snapshot('set_sudo_uid')

    def fake_gain_priv_if_needed(net_scheme):
        if net_scheme.has_privileged_machines() and state['uid'] == 0:
            state['euid'] = 0
        snapshot('gain_priv_if_needed')

    def fake_drop_temp():
        if state['uid'] == 0:
            state['euid'] = SRE_UID
        snapshot('drop_temp')

    monkeypatch.setattr(state_cmd, 'drop_privileges_permanently_if_not_needed',
                        fake_drop_perm_if_not_needed)
    monkeypatch.setattr(state_cmd, 'set_sudo_uid_for_username', fake_set_sudo_uid)
    monkeypatch.setattr(state_cmd, 'gain_privileges_if_needed', fake_gain_priv_if_needed)
    monkeypatch.setattr(state_cmd, 'drop_privileges_temporarily', fake_drop_temp)

    return state, snapshot


def _run_action_state(privileged, monkeypatch, snapshot, tmp_path):
    """Stub out everything action_state() touches except the privilege helpers,
    then invoke it.  Records two extra snapshots at the Kathara/Docker boundary
    (get_lab_from_kathara, do_action_state) so tests can check the privilege
    state at those critical points."""

    def on_kathara_query():
        snapshot('get_lab_from_kathara')

    net_scheme = _FakeNetScheme(privileged=privileged,
                                on_kathara_query=on_kathara_query)

    module_rvlab = MagicMock()
    module_rvlab.Grade.return_value.get_cheat_answers.return_value = None

    running_lab_name = '20260101000000@@@test_lab@@@em'
    monkeypatch.setattr(state_cmd, 'resolve_running_lab_name',
                        lambda partial: running_lab_name)
    monkeypatch.setattr(state_cmd, 'set_all_variables_for_action',
                        lambda running_lab_name: (module_rvlab, net_scheme))
    monkeypatch.setattr(state_cmd, 'user_not_allowed_in_exam_mode', lambda: None)
    monkeypatch.setattr(state_cmd, 'in_user_mode', lambda: False)

    def fake_do_action_state(lab, state, net_scheme, project_has_directory):
        snapshot('do_action_state')

    monkeypatch.setattr(state_cmd, 'do_action_state', fake_do_action_state)

    # Cheat file lands under params.cheat_filename(running_lab_name); redirect
    # the project tree into tmp_path so we don't write to /var/lib/sre.
    monkeypatch.setattr(params, 'sre_projects_dir', str(tmp_path))

    params.SRE.args.running_lab = running_lab_name
    params.SRE.args.state = 'final'

    state_cmd.action_state()


# ---------------------------------------------------------------------------
# Privileged-lab path
# ---------------------------------------------------------------------------


class TestStateWithPrivilegedMachines:

    def test_uid_never_drops(self, privilege_simulator, monkeypatch, tmp_path):
        """Real uid must stay 0 throughout — a permanent drop would lose SUDO_UID
        and prevent gain_privileges_if_needed from raising euid back to 0."""
        state, snap = privilege_simulator
        _run_action_state(True, monkeypatch, snap, tmp_path)
        for stage, snapshot in state['log']:
            assert snapshot['uid'] == 0, \
                f"uid dropped to {snapshot['uid']} at {stage} (expected 0)"

    def test_sudo_uid_aligned_with_lab_owner(self, privilege_simulator, monkeypatch, tmp_path):
        """SUDO_UID must be set to the lab owner (third @@@ segment) so Kathara
        labels its container queries with the same user as `start` did."""
        state, snap = privilege_simulator
        _run_action_state(True, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['set_sudo_uid']['sudo_uid'] == 'uid_of(em)'

    def test_euid_raised_before_kathara_query(self, privilege_simulator, monkeypatch, tmp_path):
        """At get_lab_from_kathara() time euid must be 0 so Kathara's
        @privileged decorator + the SUDO_UID lookup actually take effect."""
        state, snap = privilege_simulator
        _run_action_state(True, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['get_lab_from_kathara']['euid'] == 0
        assert log['get_lab_from_kathara']['sudo_uid'] == 'uid_of(em)'

    def test_euid_raised_during_do_action_state(self, privilege_simulator, monkeypatch, tmp_path):
        """The actual `put_archive` / `exec_run` calls happen inside
        do_action_state — euid must still be 0 there (containers were created
        privileged; Kathara's @privileged decorator requires root)."""
        state, snap = privilege_simulator
        _run_action_state(True, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['do_action_state']['euid'] == 0

    def test_euid_dropped_after_do_action_state(self, privilege_simulator, monkeypatch, tmp_path):
        """Cheat-file write happens after do_action_state and must be done as
        sre, not root."""
        state, snap = privilege_simulator
        _run_action_state(True, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['drop_temp']['euid'] == 1100


# ---------------------------------------------------------------------------
# Non-privileged-lab path
# ---------------------------------------------------------------------------


class TestStateWithoutPrivilegedMachines:

    def test_fully_drops_early(self, privilege_simulator, monkeypatch, tmp_path):
        """For a non-privileged lab, ruid and euid must drop to sre_uid right
        away — there is no reason to keep root."""
        state, snap = privilege_simulator
        _run_action_state(False, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['drop_perm_if_not_needed']['uid'] == 1100
        assert log['drop_perm_if_not_needed']['euid'] == 1100

    def test_set_sudo_uid_is_noop_after_full_drop(self, privilege_simulator, monkeypatch, tmp_path):
        """Once uid != 0, set_sudo_uid_for_username refuses to touch SUDO_UID."""
        state, snap = privilege_simulator
        _run_action_state(False, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['set_sudo_uid']['sudo_uid'] == '1000'

    def test_gain_privileges_is_noop(self, privilege_simulator, monkeypatch, tmp_path):
        """No privileged machines → gain_privileges_if_needed must not raise euid."""
        state, snap = privilege_simulator
        _run_action_state(False, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['gain_priv_if_needed']['euid'] == 1100

    def test_kathara_query_runs_as_sre(self, privilege_simulator, monkeypatch, tmp_path):
        """For non-privileged labs, Kathara was queried as sre at start time
        so containers carry `user=sre-{hostname}` — state must match by
        querying with the same uid."""
        state, snap = privilege_simulator
        _run_action_state(False, monkeypatch, snap, tmp_path)
        log = dict(state['log'])
        assert log['get_lab_from_kathara']['euid'] == 1100
        assert log['get_lab_from_kathara']['uid'] == 1100


# ---------------------------------------------------------------------------
# Call ordering (privileged and non-privileged share the same skeleton)
# ---------------------------------------------------------------------------


class TestStateCallOrder:

    @pytest.mark.parametrize('privileged', [True, False])
    def test_helpers_run_before_kathara_query(self, privilege_simulator, monkeypatch,
                                              tmp_path, privileged):
        """The privilege helpers must all run before get_lab_from_kathara so
        the container query uses the right uid."""
        state, snap = privilege_simulator
        _run_action_state(privileged, monkeypatch, snap, tmp_path)
        stages = [name for name, _ in state['log']]
        assert stages.index('drop_perm_if_not_needed') < stages.index('get_lab_from_kathara')
        assert stages.index('set_sudo_uid') < stages.index('get_lab_from_kathara')
        assert stages.index('gain_priv_if_needed') < stages.index('get_lab_from_kathara')

    @pytest.mark.parametrize('privileged', [True, False])
    def test_drop_temp_runs_after_do_action_state(self, privilege_simulator, monkeypatch,
                                                  tmp_path, privileged):
        state, snap = privilege_simulator
        _run_action_state(privileged, monkeypatch, snap, tmp_path)
        stages = [name for name, _ in state['log']]
        assert stages.index('do_action_state') < stages.index('drop_temp')
