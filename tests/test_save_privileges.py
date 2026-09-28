"""
Tests that `sre save` reproduces the right uid / euid / SUDO_UID context — the
counterpart of tests/test_state_privileges.py for the save command.

`sre save` keeps the real uid at 0 for the whole capture (root must be able to read
the root-owned files the containers wrote into shared/ and mnt/) and relies on
SUDO_UID for Kathara's owner label instead of a permanent drop:
  - privileged lab:     SUDO_UID = lab owner  (containers labelled with the owner)
  - non-privileged lab: SUDO_UID = sre        (containers labelled with sre)
The effective uid is raised to 0 before the Kathara query and lowered back to sre
once the save file has been written.
"""
from unittest.mock import MagicMock

import pytest

from SRE import params
from SRE.command import save as save_cmd


class _FakeNetScheme:
    def __init__(self, privileged, on_kathara_query):
        self._privileged = privileged
        self._on_kathara_query = on_kathara_query
        self.running_lab_name = '20260101000000@@@test_lab@@@em'

    def has_privileged_machines(self):
        return self._privileged

    def get_lab_from_kathara(self):
        self._on_kathara_query()
        return MagicMock(machines={'m1': MagicMock()})

    def get_lab_hash(self):
        return 'hash'


@pytest.fixture
def privilege_simulator(monkeypatch):
    """Fakes of the privilege helpers used by save.py, keeping a (uid, euid, sudo_uid)
    state machine and a snapshot log.  Initial state: after sre.py's temporary drop
    (ruid=0, euid=sre_uid, SUDO_UID=invoking user)."""
    SRE_UID = 1100
    state = {'uid': 0, 'euid': SRE_UID, 'sudo_uid': '1000', 'log': []}

    def snapshot(stage):
        state['log'].append((stage, dict(uid=state['uid'], euid=state['euid'], sudo_uid=state['sudo_uid'])))

    def fake_set_sudo_uid(username):
        if state['uid'] == 0 and username:
            state['sudo_uid'] = f'uid_of({username})'
        snapshot('set_sudo_uid')

    def fake_gain_privileges():
        if state['uid'] == 0:
            state['euid'] = 0
        snapshot('gain_privileges')

    def fake_drop_temp():
        if state['uid'] == 0:
            state['euid'] = SRE_UID
        snapshot('drop_temp')

    monkeypatch.setattr(save_cmd, 'set_sudo_uid_for_username', fake_set_sudo_uid)
    monkeypatch.setattr(save_cmd, 'gain_privileges', fake_gain_privileges)
    monkeypatch.setattr(save_cmd, 'drop_privileges_temporarily', fake_drop_temp)
    return state, snapshot


def _run_save(privileged, monkeypatch, snapshot, tmp_pub_dir):
    net_scheme = _FakeNetScheme(privileged, lambda: snapshot('get_lab_from_kathara'))
    module_rvlab = MagicMock()
    module_rvlab.allow_save_restore = True
    module_rvlab.save_key = None
    module_rvlab.shared_path = False
    monkeypatch.setattr(save_cmd, 'set_all_variables_for_action',
                        lambda running_lab_name: (module_rvlab, net_scheme))
    monkeypatch.setattr(save_cmd, 'do_action_state',
                        lambda lab, state, net_scheme, project_has_directory: snapshot('do_action_state'))
    kathara = MagicMock()
    kathara.get_instance.return_value.save_lab.side_effect = \
        lambda archive_path, **kw: (snapshot('save_lab'), open(archive_path, 'wb').close())
    monkeypatch.setattr(save_cmd, 'Kathara', kathara)
    monkeypatch.setattr(save_cmd, 'write_header', lambda out, meta: (snapshot('write_header'), 'hdr')[1])
    monkeypatch.setattr(save_cmd, 'write_payload', lambda *a, **kw: snapshot('write_payload'))

    import io
    save_cmd.do_action_save(net_scheme.running_lab_name, out_fileobj=io.BytesIO())


@pytest.mark.parametrize('privileged', [True, False])
class TestSavePrivileges:

    def test_uid_never_drops(self, privilege_simulator, monkeypatch, tmp_pub_dir, privileged):
        state, snap = privilege_simulator
        _run_save(privileged, monkeypatch, snap, tmp_pub_dir)
        for stage, s in state['log']:
            assert s['uid'] == 0, f"uid dropped to {s['uid']} at {stage}"

    def test_sudo_uid_matches_container_owner(self, privilege_simulator, monkeypatch, tmp_pub_dir, privileged):
        state, snap = privilege_simulator
        _run_save(privileged, monkeypatch, snap, tmp_pub_dir)
        log = dict(state['log'])
        expected = 'uid_of(em)' if privileged else f'uid_of({params.sre_user})'
        assert log['get_lab_from_kathara']['sudo_uid'] == expected
        assert log['save_lab']['sudo_uid'] == expected

    def test_euid_root_during_capture(self, privilege_simulator, monkeypatch, tmp_pub_dir, privileged):
        state, snap = privilege_simulator
        _run_save(privileged, monkeypatch, snap, tmp_pub_dir)
        log = dict(state['log'])
        for stage in ('get_lab_from_kathara', 'do_action_state', 'save_lab', 'write_payload'):
            assert log[stage]['euid'] == 0, f"euid is {log[stage]['euid']} at {stage}"

    def test_euid_dropped_at_the_end(self, privilege_simulator, monkeypatch, tmp_pub_dir, privileged):
        state, snap = privilege_simulator
        _run_save(privileged, monkeypatch, snap, tmp_pub_dir)
        stages = [name for name, _ in state['log']]
        assert stages[-1] == 'drop_temp'
        assert state['log'][-1][1]['euid'] == 1100
        assert stages.index('set_sudo_uid') < stages.index('gain_privileges') < stages.index('get_lab_from_kathara')
        assert stages.index('write_payload') < stages.index('drop_temp')
