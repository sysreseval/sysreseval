"""
`sre wipe` (and `sre del-exam` through it) must remove every project dir and every user public
dir while still root: the containers run as host root and leave root-owned files in shared/
and in the volume dirs that the sre user cannot delete (`wipe` used to drop its privileges
first, die on the first PermissionError and skip the remaining projects).  The privilege
helpers and the forked Kathara wipe are simulated; every `shutil.rmtree` call records the
simulated euid in effect.
"""
import os
import shutil
from pathlib import Path

import pytest

from SRE import params
from SRE import wipe as wipe_mod

SRE_UID = 1100

class _FakeProcess:
    """Stands in for the forked Kathara wipe: `alive` simulates a hang, `exitcode` a failure."""
    alive = False
    exitcode = 0

    def __init__(self, target=None):
        self.killed = False

    def start(self):
        pass

    def join(self, timeout=None):
        pass

    def is_alive(self):
        return self.alive and not self.killed

    def kill(self):
        self.killed = True


@pytest.fixture
def wipe_env(monkeypatch, tmp_path):
    """Initial state: after sre.py's temporary drop (ruid=0, euid=sre_uid).  `events` keeps the
    order of the gain, of the `shutil.rmtree` calls (with the euid in effect), of the docker
    fallback and of the drop."""
    base = tmp_path.resolve()
    state = {'uid': 0, 'euid': SRE_UID, 'events': [],
             'projects': base / 'projects', 'home_sre': base / 'home_sre'}
    state['projects'].mkdir()
    state['home_sre'].mkdir()

    def fake_gain_privileges():
        if state['uid'] == 0:
            state['euid'] = 0
        state['events'].append(('gain',))

    def fake_drop_perm():
        state['uid'] = state['euid'] = SRE_UID
        state['events'].append(('drop', 'permanent'))

    real_rmtree = shutil.rmtree

    def recording_rmtree(path, *args, **kwargs):
        state['events'].append(('rmtree', Path(path), state['euid']))
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(wipe_mod, 'gain_privileges', fake_gain_privileges)
    monkeypatch.setattr(wipe_mod, 'drop_privileges_permanently', fake_drop_perm)
    monkeypatch.setattr(wipe_mod, '_docker_wipe', lambda: state['events'].append(('docker_wipe',)))
    monkeypatch.setattr(wipe_mod.multiprocessing, 'Process', _FakeProcess)
    monkeypatch.setattr(shutil, 'rmtree', recording_rmtree)
    monkeypatch.setattr(params, 'sre_projects_dir', str(state['projects']))
    monkeypatch.setattr(params, 'sre_user_public_dir', str(state['home_sre']))
    return state


def _populate(state):
    """Two projects (one with a private volume holding `rep_root/volume_f`), a stray file in the
    projects dir, two user public dirs (one with `shared/rep_root/shared_f`) and a symlink in
    /home/sre."""
    rln_a = '20260101000000@@@lab_a@@@em'
    rln_b = '20260101000001@@@lab_b@@@em'
    volume = state['projects'] / rln_a / params.private_dir_name / params.private_mount_dir_name / 'data' / 'rep_root'
    volume.mkdir(parents=True)
    (volume / 'volume_f').write_text('x')
    (state['projects'] / rln_a / params.info_json_name).write_text('{}')
    (state['projects'] / rln_b).mkdir()
    (state['projects'] / rln_b / params.info_json_name).write_text('{}')
    (state['projects'] / 'stray').write_text('')
    shared = state['home_sre'] / 'lab_a' / params.shared_dir_name / 'rep_root'
    shared.mkdir(parents=True)
    (shared / 'shared_f').write_text('x')
    (state['home_sre'] / 'lab_b').mkdir()
    (state['home_sre'] / 'link').symlink_to(state['home_sre'] / 'lab_b')
    return {'rln_a': rln_a, 'rln_b': rln_b, 'volume': volume, 'shared': shared}


class TestWipe:
    def test_removes_everything_as_root_then_drops(self, wipe_env):
        _populate(wipe_env)
        wipe_mod.wipe()
        assert list(wipe_env['projects'].iterdir()) == []
        assert list(wipe_env['home_sre'].iterdir()) == []
        rmtrees = [e for e in wipe_env['events'] if e[0] == 'rmtree']
        assert len(rmtrees) == 4 and all(e[2] == 0 for e in rmtrees), wipe_env['events']
        assert wipe_env['events'][0] == ('gain',)
        assert wipe_env['events'][-1] == ('drop', 'permanent')
        assert ('docker_wipe',) not in wipe_env['events']

    def test_keeps_lost_and_found_and_mount_points(self, wipe_env, monkeypatch):
        _populate(wipe_env)
        (wipe_env['home_sre'] / 'lost+found' / 'x').mkdir(parents=True)
        mounted = wipe_env['home_sre'] / 'mounted'
        (mounted / 'x').mkdir(parents=True)
        monkeypatch.setattr(os.path, 'ismount', lambda p: Path(p) == mounted)
        wipe_mod.wipe()
        assert {p.name for p in wipe_env['home_sre'].iterdir()} == {'lost+found', 'mounted'}
        assert (mounted / 'x').is_dir()
        assert list(wipe_env['projects'].iterdir()) == []

    def test_missing_directories_are_fine(self, wipe_env):
        wipe_env['projects'].rmdir()
        wipe_env['home_sre'].rmdir()
        wipe_mod.wipe()
        assert wipe_env['events'] == [('gain',), ('drop', 'permanent')]

    def test_failure_does_not_stop_the_removal(self, wipe_env, unremovable, capsys):
        layout = _populate(wipe_env)
        unremovable.add('volume_f')
        with pytest.raises(SystemExit) as e:
            wipe_mod.wipe()
        assert e.value.code == 1
        err = capsys.readouterr().err
        assert str(layout['volume'] / 'volume_f') in err, err
        # everything else is gone, the privileges were dropped before the report
        assert {p.name for p in wipe_env['projects'].iterdir()} == {layout['rln_a']}
        assert (layout['volume'] / 'volume_f').exists()
        assert list(wipe_env['home_sre'].iterdir()) == []
        assert wipe_env['events'][-1] == ('drop', 'permanent')
        assert wipe_env['uid'] == SRE_UID

    def test_hung_kathara_wipe_falls_back_to_docker(self, wipe_env, monkeypatch):
        _populate(wipe_env)
        monkeypatch.setattr(_FakeProcess, 'alive', True)
        wipe_mod.wipe()
        assert ('docker_wipe',) in wipe_env['events']
        assert wipe_env['events'].index(('docker_wipe',)) < wipe_env['events'].index(('drop', 'permanent'))
        assert list(wipe_env['projects'].iterdir()) == []

    def test_failed_kathara_wipe_falls_back_to_docker(self, wipe_env, monkeypatch):
        monkeypatch.setattr(_FakeProcess, 'exitcode', 1)
        wipe_mod.wipe()
        assert wipe_env['events'] == [('gain',), ('docker_wipe',), ('drop', 'permanent')]
