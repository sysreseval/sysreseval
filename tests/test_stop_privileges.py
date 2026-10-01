"""
`sre stop` must undeploy with the (uid, euid, SUDO_UID) context that matches the `user`
label Kathara put on the containers at deploy time (see tests/test_state_privileges.py):
  - non-privileged lab: deployed after a permanent drop to sre   → label = sre
  - privileged lab:     deployed as root with SUDO_UID = owner    → label = owner
Kathara's undeploy filters on that label, so a mismatch silently leaves the containers
running (the project directory is removed anyway).  These tests simulate the privilege
state machine and assert on the SUDO_UID in effect at every `undeploy_lab` call.

The directories must then be removed while still root: the containers run as host root and
leave root-owned files in shared/ and in the volume dirs that the sre user cannot delete
(`sre stop` used to drop its privileges first, die with PermissionError and leave the project
dir behind).  Every `shutil.rmtree` call records the simulated euid in effect.
"""
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from SRE import params
from SRE.command import stop as stop_cmd

RLN = '20260101000000@@@test_lab@@@em'
SRE_UID = 1100

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
    temporary drop (ruid=0, euid=sre_uid, SUDO_UID=invoking user).  `events` keeps the
    order of the `shutil.rmtree` calls (with the euid in effect) and of the drops."""
    base = tmp_path.resolve()
    state = {'uid': 0, 'euid': SRE_UID, 'sudo_uid': '1000', 'undeploys': [], 'drops': [], 'events': [],
             'projects': base / 'projects', 'home_sre': base / 'home_sre'}

    def fake_set_sudo_uid(username):
        if state['uid'] == 0 and username:
            state['sudo_uid'] = f'uid_of({username})'

    def fake_gain_privileges():
        if state['uid'] == 0:
            state['euid'] = 0

    def fake_drop_perm():
        state['uid'] = state['euid'] = SRE_UID
        state['drops'].append('permanent')
        state['events'].append(('drop', 'permanent'))

    def fake_drop_temp():
        if state['uid'] == 0:
            state['euid'] = SRE_UID
        state['drops'].append('temporary')
        state['events'].append(('drop', 'temporary'))

    real_rmtree = shutil.rmtree

    def recording_rmtree(path, *args, **kwargs):
        state['events'].append(('rmtree', Path(path), state['euid']))
        return real_rmtree(path, *args, **kwargs)

    kathara = MagicMock()
    kathara.get_instance.return_value.undeploy_lab.side_effect = \
        lambda lab_hash: state['undeploys'].append((lab_hash, state['euid'], state['sudo_uid']))

    monkeypatch.setattr(stop_cmd, 'set_sudo_uid_for_username', fake_set_sudo_uid)
    monkeypatch.setattr(stop_cmd, 'gain_privileges', fake_gain_privileges)
    monkeypatch.setattr(stop_cmd, 'drop_privileges_permanently', fake_drop_perm)
    monkeypatch.setattr(stop_cmd, 'drop_privileges_temporarily', fake_drop_temp)
    monkeypatch.setattr(stop_cmd, 'Kathara', kathara)
    monkeypatch.setattr(shutil, 'rmtree', recording_rmtree)
    monkeypatch.setattr(params, 'sre_projects_dir', str(state['projects']))
    monkeypatch.setattr(params, 'sre_user_public_dir', str(state['home_sre']))
    return state


@pytest.fixture
def non_privileged_lab(monkeypatch):
    monkeypatch.setattr(stop_cmd, 'set_all_variables_for_action',
                        lambda running_lab_name: (MagicMock(), _FakeNetScheme(privileged=False)))


def _make_project(state, rln=RLN):
    """Project dir whose `.private/user_public_dir` symlink points to a user public dir holding
    `shared/rep_root/f`, what a container leaves behind.  Returns (project dir, user public dir)."""
    proj = state['projects'] / rln
    private = proj / params.private_dir_name
    private.mkdir(parents=True)
    (proj / params.info_json_name).write_text('{}')
    user_public_dir = state['home_sre'] / 'test_lab'
    rep_root = user_public_dir / params.shared_dir_name / 'rep_root'
    rep_root.mkdir(parents=True)
    (rep_root / 'f').write_text('x')
    (private / params.user_public_dir_name).symlink_to(user_public_dir)
    return proj, user_public_dir


class TestUndeployUsers:
    def test_non_privileged_uses_sre(self):
        assert stop_cmd.undeploy_users(RLN, privileged=False) == [params.sre_user]

    def test_privileged_uses_owner(self):
        assert stop_cmd.undeploy_users(RLN, privileged=True) == ['em']

    def test_unknown_tries_both_without_duplicates(self):
        assert stop_cmd.undeploy_users(RLN, privileged=None) == [params.sre_user, 'em']
        assert stop_cmd.undeploy_users(f'20260101000000@@@lab@@@{params.sre_user}', None) == [params.sre_user]


class TestStopRunningLab:
    def test_non_privileged_lab_undeploys_as_sre(self, privilege_simulator, non_privileged_lab):
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

    def test_project_directory_removed(self, privilege_simulator, non_privileged_lab):
        proj = privilege_simulator['projects'] / RLN
        proj.mkdir(parents=True)
        assert stop_cmd.stop_running_lab(RLN) == []
        assert not proj.exists()

    def test_directories_removed_as_root_before_drop(self, privilege_simulator, non_privileged_lab):
        proj, user_public_dir = _make_project(privilege_simulator)
        assert stop_cmd.stop_running_lab(RLN) == []
        assert not proj.exists() and not user_public_dir.exists()
        assert privilege_simulator['events'] == [('rmtree', user_public_dir, 0),
                                                 ('rmtree', proj, 0),
                                                 ('drop', 'permanent')]

    def test_user_public_dir_outside_home_sre_is_kept(self, privilege_simulator, non_privileged_lab, tmp_path):
        proj, user_public_dir = _make_project(privilege_simulator)
        elsewhere = tmp_path.resolve() / 'elsewhere'
        elsewhere.mkdir()
        link = proj / params.private_dir_name / params.user_public_dir_name
        link.unlink()
        link.symlink_to(elsewhere)
        assert stop_cmd.stop_running_lab(RLN) == []
        assert not proj.exists()
        assert elsewhere.is_dir() and user_public_dir.is_dir()

    def test_removal_errors_reported_after_drop(self, privilege_simulator, non_privileged_lab, unremovable):
        proj, user_public_dir = _make_project(privilege_simulator)
        rep_root = user_public_dir / params.shared_dir_name / 'rep_root'
        unremovable.add('f')
        errors = stop_cmd.stop_running_lab(RLN)
        assert any(str(rep_root / 'f') in e for e in errors), errors
        assert (rep_root / 'f').exists()
        assert not proj.exists(), "the project dir is removed even when the user public dir cannot be"
        assert privilege_simulator['events'][-1] == ('drop', 'permanent')
        assert privilege_simulator['uid'] == SRE_UID

    def test_multi_project_keeps_root_after_error(self, privilege_simulator, monkeypatch, unremovable):
        monkeypatch.setattr(stop_cmd, 'set_all_variables_for_action',
                            lambda running_lab_name: pytest.fail("must not load the lab module"))
        proj, user_public_dir = _make_project(privilege_simulator)
        unremovable.add('f')
        errors = stop_cmd.stop_running_lab(RLN, lab_hash='given', multi_project=True)
        assert errors
        assert not proj.exists()
        assert privilege_simulator['drops'] == ['temporary']
        assert privilege_simulator['uid'] == 0


class TestActionStop:
    @pytest.fixture(autouse=True)
    def _plain_stop(self, monkeypatch):
        monkeypatch.setattr(stop_cmd, 'user_not_allowed_in_exam_mode', lambda: None)
        monkeypatch.setattr(stop_cmd, 'resolve_running_lab_name', lambda partial: RLN)

    def test_exit_status_on_removal_error(self, monkeypatch, capsys):
        monkeypatch.setattr(stop_cmd, 'stop_running_lab',
                            lambda running_lab_name: ['/home/sre/x/shared/rep_root/f: Permission denied'])
        with pytest.raises(SystemExit) as e:
            stop_cmd.action_stop()
        assert e.value.code == 1
        assert 'rep_root/f: Permission denied' in capsys.readouterr().err

    def test_silent_on_success(self, monkeypatch, capsys):
        monkeypatch.setattr(stop_cmd, 'stop_running_lab', lambda running_lab_name: [])
        stop_cmd.action_stop()
        assert capsys.readouterr().err == ''
