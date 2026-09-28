"""
`sre stop` must undeploy with the (uid, euid, SUDO_UID) context that matches the `user`
label Kathara put on the containers at deploy time (see tests/test_state_privileges.py):
  - non-privileged lab: deployed after a permanent drop to sre   → label = sre
  - privileged lab:     deployed as root with SUDO_UID = owner    → label = owner
Kathara's undeploy filters on that label, so a mismatch silently leaves the containers
running (the project directory is removed anyway).  These tests simulate the privilege
state machine and assert on the SUDO_UID in effect at every `undeploy_lab` call.
"""
from unittest.mock import MagicMock

import pytest

from SRE import params
from SRE.command import stop as stop_cmd

RLN = '20260101000000@@@test_lab@@@em'


class _FakeNetScheme:
    def __init__(self, privileged):
        self._privileged = privileged

    def has_privileged_machines(self):
        return self._privileged

    def get_lab_hash(self):
        return 'hash'


@pytest.fixture
def privilege_simulator(monkeypatch, tmp_path):
    """Fake privilege helpers keeping a (uid, euid, sudo_uid) state machine; every
    `undeploy_lab` call records the state in effect.  Initial state: after sre.py's
    temporary drop (ruid=0, euid=sre_uid, SUDO_UID=invoking user)."""
    SRE_UID = 1100
    state = {'uid': 0, 'euid': SRE_UID, 'sudo_uid': '1000', 'undeploys': [], 'drops': []}

    def fake_set_sudo_uid(username):
        if state['uid'] == 0 and username:
            state['sudo_uid'] = f'uid_of({username})'

    def fake_gain_privileges():
        if state['uid'] == 0:
            state['euid'] = 0

    def fake_drop_perm():
        state['uid'] = state['euid'] = SRE_UID
        state['drops'].append('permanent')

    def fake_drop_temp():
        if state['uid'] == 0:
            state['euid'] = SRE_UID
        state['drops'].append('temporary')

    kathara = MagicMock()
    kathara.get_instance.return_value.undeploy_lab.side_effect = \
        lambda lab_hash: state['undeploys'].append((lab_hash, state['euid'], state['sudo_uid']))

    monkeypatch.setattr(stop_cmd, 'set_sudo_uid_for_username', fake_set_sudo_uid)
    monkeypatch.setattr(stop_cmd, 'gain_privileges', fake_gain_privileges)
    monkeypatch.setattr(stop_cmd, 'drop_privileges_permanently', fake_drop_perm)
    monkeypatch.setattr(stop_cmd, 'drop_privileges_temporarily', fake_drop_temp)
    monkeypatch.setattr(stop_cmd, 'Kathara', kathara)
    monkeypatch.setattr(params, 'sre_projects_dir', str(tmp_path / 'projects'))
    monkeypatch.setattr(params, 'sre_user_public_dir', str(tmp_path / 'home_sre'))
    return state


class TestUndeployUsers:
    def test_non_privileged_uses_sre(self):
        assert stop_cmd.undeploy_users(RLN, privileged=False) == [params.sre_user]

    def test_privileged_uses_owner(self):
        assert stop_cmd.undeploy_users(RLN, privileged=True) == ['em']

    def test_unknown_tries_both_without_duplicates(self):
        assert stop_cmd.undeploy_users(RLN, privileged=None) == [params.sre_user, 'em']
        assert stop_cmd.undeploy_users(f'20260101000000@@@lab@@@{params.sre_user}', None) == [params.sre_user]


class TestStopRunningLab:
    def test_non_privileged_lab_undeploys_as_sre(self, privilege_simulator, monkeypatch):
        monkeypatch.setattr(stop_cmd, 'set_all_variables_for_action',
                            lambda running_lab_name: (MagicMock(), _FakeNetScheme(privileged=False)))
        stop_cmd.stop_running_lab(RLN)
        assert privilege_simulator['undeploys'] == [('hash', 0, f'uid_of({params.sre_user})')]
        assert privilege_simulator['drops'] == ['permanent']

    def test_privileged_lab_undeploys_as_owner(self, privilege_simulator, monkeypatch):
        monkeypatch.setattr(stop_cmd, 'set_all_variables_for_action',
                            lambda running_lab_name: (MagicMock(), _FakeNetScheme(privileged=True)))
        stop_cmd.stop_running_lab(RLN)
        assert privilege_simulator['undeploys'] == [('hash', 0, 'uid_of(em)')]

    def test_lab_hash_only_tries_both_labels_and_keeps_privileges(self, privilege_simulator, monkeypatch):
        """pre-start-exam passes lab_hash without loading the lab: both labels are tried,
        and multi_project keeps the real uid for the next project."""
        monkeypatch.setattr(stop_cmd, 'set_all_variables_for_action',
                            lambda running_lab_name: pytest.fail("must not load the lab module"))
        stop_cmd.stop_running_lab(RLN, lab_hash='given', multi_project=True)
        assert privilege_simulator['undeploys'] == [('given', 0, f'uid_of({params.sre_user})'),
                                                    ('given', 0, 'uid_of(em)')]
        assert privilege_simulator['drops'] == ['temporary']
        assert privilege_simulator['uid'] == 0

    def test_project_directory_removed(self, privilege_simulator, monkeypatch, tmp_path):
        monkeypatch.setattr(stop_cmd, 'set_all_variables_for_action',
                            lambda running_lab_name: (MagicMock(), _FakeNetScheme(privileged=False)))
        proj = tmp_path / 'projects' / RLN
        proj.mkdir(parents=True)
        stop_cmd.stop_running_lab(RLN)
        assert not proj.exists()
