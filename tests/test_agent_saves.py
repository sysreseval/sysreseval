"""Tests of the saved projects on the agent (``sreweb/agent/saves.py`` and its routes): a real
agent on the fake ``sre``, with a directory of saved projects of its own, reached through the
helper program exactly as on a pool host (minus the change of account: the tests do not run as
root)."""
import asyncio
import json
import os
import platform
import pwd
import re
import time

import pytest

from SRE import params
from sreweb import savestore as store
from sreweb.agent import saves as S
from sreweb.agent.saves import SaveStore, sweep_tmp_dir
from sreweb.config import ConfigError, SavesConfig, agent_config_from_dict

from test_agent_api import Harness, headers, ALICE, BOB, PROF, TOKEN, run
from test_agent_exam import EXAM_LAB, exam_body

LAB = 'sre/dhcp.py'


def store_user() -> str:
    """The ``[saves] user`` of an agent of the tests: the account running them, so that the
    helper changes nothing (as root too, which the agent refuses without a user); ``''`` for an
    account whose name the configuration would not take."""
    name = pwd.getpwuid(os.getuid()).pw_name
    return name if re.match(r'^[a-z_][a-z0-9_-]*$', name) else ''


def saves_dir(tmp_path, marker: bool = True):
    directory = tmp_path / 'saves'
    directory.mkdir(exist_ok=True)
    if marker:
        (directory / store.MARKER).touch()
    return directory


def harness(tmp_path, mock_env=None, marker: bool = True, **saves):
    """An agent whose ``[saves]`` names a directory of the test, the helper running as the
    account of the tests."""
    directory = saves_dir(tmp_path, marker)
    return Harness(tmp_path, mock_env=mock_env,
                   saves={'dir': str(directory), 'user': store_user(), 'min_free_mb': 0, **saves})


async def save(h, rln, identity=ALICE, **body):
    resp = await h.client.post(f'/v1/projects/{rln}/save', json=body, headers=headers(identity))
    return resp.status, await resp.json()


async def saved(h, rln, identity=ALICE, **body) -> dict:
    status, answer = await save(h, rln, identity, **body)
    assert status == 200, answer
    return answer['save']


async def catalog(h) -> list:
    resp = await h.client.get('/v1/saves', headers=headers(None))
    assert resp.status == 200, await resp.text()
    return (await resp.json())['saves']


async def restore(h, entry, identity=ALICE, **body):
    resp = await h.client.post(f"/v1/saves/{entry['owner']}/{entry['id']}/restore", json=body, headers=headers(identity))
    if resp.status != 200:
        return resp.status, await resp.json()
    lines = [json.loads(line) for line in (await resp.text()).splitlines()]
    return 200, lines[-1]


def files_of(tmp_path) -> list:
    return sorted(str(p.relative_to(tmp_path / 'saves')) for p in (tmp_path / 'saves').rglob('*') if p.is_file())


class TestConfig:
    def test_defaults_are_off(self):
        cfg = agent_config_from_dict({'token': TOKEN})
        assert cfg.saves == SavesConfig() and cfg.saves.dir == '' and cfg.saves.user == 'sre'
        assert cfg.timeouts['save'] == 900 and cfg.timeouts['restore'] == 900

    def test_section(self):
        cfg = agent_config_from_dict({'token': TOKEN, 'saves': {'dir': '/srv/saves', 'max_size_mb': 100, 'timeout': '45s'},
                                      'timeouts': {'save': '20m', 'restore': 600}})
        assert cfg.saves.dir == '/srv/saves' and cfg.saves.max_size_mb == 100 and cfg.saves.timeout == 45
        assert cfg.timeouts['save'] == 1200 and cfg.timeouts['restore'] == 600

    @pytest.mark.parametrize('section', [
        {'dir': 'relative'}, {'dir': 3}, {'user': 'Bad User'}, {'max_size_mb': 0}, {'max_size_mb': True},
        {'min_free_mb': -1}, {'max_concurrent': 0}, {'timeout': 0}, {'unknown': 1},
    ])
    def test_refused(self, section):
        with pytest.raises(ConfigError):
            agent_config_from_dict({'token': TOKEN, 'saves': section})


class TestStatus:
    def test_off_without_a_directory(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                status = await (await h.client.get('/v1/status', headers=headers(None))).json()
                assert status[store.STATUS_SAVES] is False and status[store.STATUS_SAVES_ERROR] == 'not configured'
                # no directory: the host is not meant to save, nothing to tell an administrator
                assert status[store.STATUS_SAVES_CONFIGURED] is False
                rln = await h.started()
                project = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert project['can_save'] is False
                assert (await save(h, rln))[0] == 404
                assert (await h.client.get('/v1/saves', headers=headers(None))).status == 404
        run(go())

    def test_usable_then_the_volume_goes_away(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                status = await (await h.client.get('/v1/status', headers=headers(None))).json()
                assert status[store.STATUS_SAVES] is True and status[store.STATUS_SAVES_ERROR] == ''
                assert status[store.STATUS_SAVES_CONFIGURED] is True
                rln = await h.started()
                project = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert project['can_save'] is True
                # the marker is the volume: gone, the next check turns the saves off, and every
                # call answers at once without asking the directory
                os.unlink(tmp_path / 'saves' / store.MARKER)
                assert await h.agent.saves.refresh() is False
                status = await (await h.client.get('/v1/status', headers=headers(None))).json()
                assert status[store.STATUS_SAVES] is False and 'not found' in status[store.STATUS_SAVES_ERROR]
                # still configured: meant to save and unable to, what the Pool page flags
                assert status[store.STATUS_SAVES_CONFIGURED] is True
                assert status[store.STATUS_SAVES_ERROR].startswith(str(tmp_path / 'saves' / store.MARKER))
                code, answer = await save(h, rln)
                assert code == 503 and answer['code'] == store.CODE_UNAVAILABLE
                assert (await h.client.get('/v1/saves', headers=headers(None))).status == 503
                project = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert project['can_save'] is False
                # back
                (tmp_path / 'saves' / store.MARKER).touch()
                assert await h.agent.saves.refresh() is True
                assert (await save(h, rln))[0] == 200
        run(go())

    def test_no_marker_at_start(self, tmp_path):
        async def go():
            async with harness(tmp_path, marker=False) as h:
                assert h.agent.saves.available is False
                # the volume mounted and its marker never created: told from the first status
                status = await (await h.client.get('/v1/status', headers=headers(None))).json()
                assert (status[store.STATUS_SAVES], status[store.STATUS_SAVES_CONFIGURED]) == (False, True)
                assert 'never created' in status[store.STATUS_SAVES_ERROR]
                rln = await h.started()
                assert (await save(h, rln))[0] == 503
                assert files_of(tmp_path) == []
        run(go())

    def test_an_account_is_required_as_root(self, tmp_path, monkeypatch):
        s = SaveStore(SavesConfig(dir=str(saves_dir(tmp_path)), user=''))
        monkeypatch.setattr(S.os, 'geteuid', lambda: 0)
        run(s.start())
        assert s.available is False and 'saves.user is required' in s.error
        s = SaveStore(SavesConfig(dir=str(saves_dir(tmp_path)), user='no-such-user-xyz'))
        run(s.start())
        assert s.available is False and 'does not exist' in s.error
        # a store that never started is configured and unusable, with its reason
        assert s.status() == {store.STATUS_SAVES: False, store.STATUS_SAVES_CONFIGURED: True,
                              store.STATUS_SAVES_ERROR: s.error}

    def test_the_helper_runs_as_the_account_of_the_store(self, tmp_path, monkeypatch):
        """As root the helper is spawned under ``saves.user``, with no group of the agent."""
        import pwd
        me = pwd.getpwuid(os.getuid())
        seen = {}

        async def spawn(*argv, **kwargs):
            seen.update(argv=argv, **kwargs)
            raise FileNotFoundError('stop here')

        s = SaveStore(SavesConfig(dir=str(saves_dir(tmp_path)), user=me.pw_name), spawn=spawn)
        monkeypatch.setattr(S.os, 'geteuid', lambda: 0)
        s._resolve_user()
        with pytest.raises(FileNotFoundError):
            run(s.spawn('check', {'root': s.cfg.dir}, stdin=asyncio.subprocess.DEVNULL))
        assert seen['user'] == me.pw_uid and seen['group'] == me.pw_gid and seen['extra_groups'] == []
        assert seen['umask'] == 0o077 and seen['cwd'] == '/' and seen['start_new_session'] is True
        assert seen['argv'][1:4] == ('-I', '-B', store.__file__) and seen['argv'][4] == 'check'
        assert 'PYTHONPATH' not in seen['env']


class TestSave:
    def test_save_list_restore_delete(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                entry = await saved(h, rln, comment='  after part 2 ')
                assert entry['owner'] == 'alice' and store.valid_id(entry['id'])
                assert entry['lab'] == LAB and entry['project'] == rln and entry['project_owner'] == 'alice'
                assert entry['comment'] == 'after part 2' and entry['fullname'] == 'Alice A' and entry['group'] == 'INFO1'
                assert entry['host'] == 'pool1' and entry['arch'] == platform.machine()
                assert entry['sre_version'] == params.sre_version and entry['shared_with'] == []
                assert entry['exam'] is False and entry['instructor_mode'] is False and entry['debug_project'] is False
                assert entry['size'] > 1024 and len(entry['sha256']) == 64
                assert files_of(tmp_path) == [store.MARKER, f"alice/{entry['id']}.json", f"alice/{entry['id']}.sre"]
                # the student path: sre --user save, for the owner
                call = [e for e in h.entries() if 'save' in e['argv']][-1]
                assert call['argv'] == ['--user', 'save', '--', rln] and call['env']['SUDO_USER'] == 'alice'

                # the catalog: asked by the portal, no user behind the call
                assert await catalog(h) == [entry]
                assert (await h.client.get('/v1/saves', headers={'Authorization': 'Bearer wrong-token-000000'})).status == 401

                # restored as a NEW project of the caller, the saved one untouched
                code, result = await restore(h, entry)
                assert code == 200 and result['status'] == 'created', result
                assert result['running_lab_name'] != rln and result['running_lab_name'].endswith('@@@alice')
                call = [e for e in h.entries() if 'restore' in e['argv']][-1]
                assert call['argv'] == ['--user', 'restore', '--', '-'] and call['env']['SUDO_USER'] == 'alice'
                projects = await (await h.client.get('/v1/projects', headers=headers())).json()
                assert {p['running_lab_name'] for p in projects} == {rln, result['running_lab_name']}
                assert all(p['managed'] for p in projects)

                resp = await h.client.delete(f"/v1/saves/alice/{entry['id']}", headers=headers())
                assert resp.status == 200 and (await resp.json())['save'] == entry
                assert await catalog(h) == [] and files_of(tmp_path) == [store.MARKER]
                assert (await restore(h, entry))[0] == 404
        run(go())

    def test_the_lab_must_allow_it(self, tmp_path):
        async def go():
            async with harness(tmp_path, mock_env={'MOCK_NO_SAVE_RESTORE': '1'}) as h:
                rln = await h.started()
                project = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert project['can_save'] is False
                code, answer = await save(h, rln)
                assert code == 403 and answer['error'] == 'this lab cannot be saved'
                assert not [e for e in h.entries() if 'save' in e['argv']], "refused before sre is run"
        run(go())

    def test_another_student_cannot_save_it(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                assert (await save(h, rln, BOB))[0] == 403
                assert await catalog(h) == []
        run(go())

    def test_quota(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                first = await saved(h, rln, quota=2)
                await saved(h, rln, quota=2)
                code, answer = await save(h, rln, quota=2)
                assert code == 409 and answer['code'] == store.CODE_QUOTA
                assert answer['quota'] == 2 and answer['count'] == 2
                assert len(await catalog(h)) == 2
                # an old one deleted: there is room again
                await h.client.delete(f"/v1/saves/alice/{first['id']}", headers=headers())
                await saved(h, rln, quota=2)
                # 0 = no limit; the saves of the others do not count
                await saved(h, rln, quota=0)
                bob = await h.started(BOB)
                await saved(h, bob, BOB, quota=1)
                assert (await save(h, rln, quota=-1))[0] == 400 and (await save(h, rln, quota='2'))[0] == 400
        run(go())

    def test_too_large_leaves_nothing(self, tmp_path):
        async def go():
            async with harness(tmp_path, mock_env={'MOCK_SAVE_SIZE': str(3 << 20)}, max_size_mb=1) as h:
                rln = await h.started()
                code, answer = await save(h, rln)
                assert code == 413 and answer['code'] == store.CODE_TOO_LARGE, answer
                assert files_of(tmp_path) == [store.MARKER] and await catalog(h) == []
        run(go())

    def test_a_save_that_dies_while_streaming_leaves_nothing(self, tmp_path):
        """``sre save`` wrote a valid beginning, then failed: what the helper received is a file
        that starts like a save, and must never be listed."""
        async def go():
            async with harness(tmp_path, mock_env={'MOCK_SAVE_BREAK': '1'}) as h:
                rln = await h.started()
                code, answer = await save(h, rln)
                assert code == 502 and answer['error'] == 'sre: mock failure', answer
                assert files_of(tmp_path) == [store.MARKER] and await catalog(h) == []
        run(go())

    def test_sre_failing_at_once(self, tmp_path):
        async def go():
            async with harness(tmp_path, mock_env={'MOCK_FAIL': 'save'}) as h:
                rln = await h.started()
                code, answer = await save(h, rln)
                assert code == 502 and answer['error'] == 'sre: mock failure'
                assert files_of(tmp_path) == [store.MARKER]
        run(go())

    def test_host_in_exam_mode(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                entry = await saved(h, rln)
                (h.pub / params.exam_json_name).write_text('{}')
                assert (await save(h, rln))[0] == 409
                assert (await restore(h, entry))[0] == 409
                project = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).json())['project']
                assert project['can_save'] is False
        run(go())

    def test_an_exam_project_is_saved_by_an_instructor_only(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started(ALICE, lab=EXAM_LAB, exam=exam_body(), flavor='hard')
                project = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert project['can_save'] is False
                code, answer = await save(h, rln)
                assert code == 409 and answer['error'] == 'exam in progress'
                # the instructor's save: marked, never shared, never restored by a student
                entry = await saved(h, rln, PROF)
                assert entry['owner'] == 'prof' and entry['exam'] is True and entry['lab'] == EXAM_LAB
                resp = await h.client.put(f"/v1/saves/prof/{entry['id']}", json={'shared_with': ['department:INFO1']},
                                          headers=headers(PROF))
                assert resp.status == 409
                assert (await restore(h, entry, PROF))[1]['status'] == 'created'
        run(go())

    def test_a_project_of_the_qt_gui_is_not_saved_from_the_web(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                h.agent.registry.projects[rln].managed = False
                code, answer = await save(h, rln)
                assert code == 403 and 'not started from the web site' in answer['error']
        run(go())

    def test_a_busy_project(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                async with h.agent.registry.projects[rln].lock:
                    code, answer = await save(h, rln)
                assert code == 409 and answer['error'] == 'the project is busy'
                assert files_of(tmp_path) == [store.MARKER]
        run(go())

    def test_not_enough_room(self, tmp_path):
        async def go():
            async with harness(tmp_path, min_free_mb=1 << 40) as h:
                rln = await h.started()
                code, answer = await save(h, rln)
                assert code == 507, answer
        run(go())

    def test_anonymous(self, tmp_path):
        from sreweb.identity import Identity
        guest = Identity(login='guest-1a2b3c4d', anonymous=True)

        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started(guest)
                assert (await save(h, rln, guest))[0] == 403
        run(go())


class TestInstructor:
    def test_an_instructor_saves_a_student_project_as_their_own(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                entry = await saved(h, rln, PROF, comment='for the class')
                assert entry['owner'] == 'prof' and entry['project_owner'] == 'alice' and entry['project'] == rln
                # a privileged sre save, in the name of the instructor
                call = [e for e in h.entries() if 'save' in e['argv']][-1]
                assert call['argv'] == ['save', '--', rln] and call['env']['LOGNAME'] == 'prof'
                # the student does not manage it
                assert (await h.client.delete(f"/v1/saves/prof/{entry['id']}", headers=headers())).status == 403
                assert (await h.client.put(f"/v1/saves/prof/{entry['id']}", json={'comment': 'x'},
                                           headers=headers())).status == 403
                assert (await restore(h, entry))[0] == 403
        run(go())

    def test_restore_in_instructor_mode(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                entry = await saved(h, await h.started())
                assert (await restore(h, entry, ALICE, instructor_mode=True))[0] == 403
                code, result = await restore(h, entry, PROF, instructor_mode=True)
                assert code == 200 and result['status'] == 'created' and result['running_lab_name'].endswith('@@@prof')
                call = [e for e in h.entries() if 'restore' in e['argv']][-1]
                assert call['argv'] == ['restore', '--instructor-mode', '--', '-'] and call['env']['LOGNAME'] == 'prof'
                project = (await (await h.client.get(f"/v1/projects/{result['running_lab_name']}",
                                                     headers=headers(PROF))).json())['project']
                assert project['instructor_mode'] is True
                # an instructor manages the saves of everybody
                resp = await h.client.put(f"/v1/saves/alice/{entry['id']}", json={'comment': 'seen'}, headers=headers(PROF))
                assert resp.status == 200 and (await resp.json())['save']['comment'] == 'seen'
                assert (await h.client.delete(f"/v1/saves/alice/{entry['id']}", headers=headers(PROF))).status == 200
        run(go())


class TestSharing:
    def test_update(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                entry = await saved(h, await h.started())
                url = f"/v1/saves/alice/{entry['id']}"
                resp = await h.client.put(url, json={'shared_with': ['department:INFO1', 'custom:TP 2'], 'comment': 'v2'},
                                          headers=headers())
                changed = (await resp.json())['save']
                assert resp.status == 200 and changed['shared_with'] == ['department:INFO1', 'custom:TP 2']
                assert changed == {**entry, 'shared_with': changed['shared_with'], 'comment': 'v2'}
                assert await catalog(h) == [changed]
                for body in ({}, {'shared_with': 'custom:TP 2'}, {'shared_with': [1]}, {'comment': 3},
                             {'shared_with': ['g'] * (store.MAX_SHARED_WITH + 1)}, {'owner': 'bob'}):
                    assert (await h.client.put(url, json=body, headers=headers())).status == 400, body
                assert (await h.client.put(url, json={'comment': 'x'}, headers=headers(BOB))).status == 403
                assert (await h.client.put(f"/v1/saves/alice/{store.new_id()}", json={'comment': 'x'},
                                           headers=headers())).status == 404
        run(go())

    def test_a_member_restores_through_the_group_the_portal_names(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                entry = await saved(h, await h.started())
                # not shared: nobody else
                assert (await restore(h, entry, BOB))[0] == 403
                assert (await restore(h, entry, BOB, via='custom:TP 2'))[0] == 403
                await h.client.put(f"/v1/saves/alice/{entry['id']}", json={'shared_with': ['custom:TP 2']}, headers=headers())
                # shared: only through a group the save is shared with now
                assert (await restore(h, entry, BOB))[0] == 403
                assert (await restore(h, entry, BOB, via='custom:TP 1'))[0] == 403
                code, result = await restore(h, entry, BOB, via='custom:TP 2')
                assert code == 200 and result['status'] == 'created' and result['running_lab_name'].endswith('@@@bob')
                # sharing is not managing
                assert (await h.client.delete(f"/v1/saves/alice/{entry['id']}", headers=headers(BOB))).status == 403
                # unshared: the group stops at once
                await h.client.put(f"/v1/saves/alice/{entry['id']}", json={'shared_with': []}, headers=headers())
                assert (await restore(h, entry, BOB, via='custom:TP 2'))[0] == 403
        run(go())


class TestRestore:
    def test_names_are_checked(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await saved(h, await h.started())
                for owner, save_id in (('..', store.new_id()), ('alice', 'nope'), ('alice', store.new_id()),
                                       ('al%2Fice', store.new_id()), ('alice', '..%2F..%2Fx')):
                    for method, body in (('POST', {}), ('PUT', {'comment': 'x'}), ('DELETE', None)):
                        suffix = '/restore' if method == 'POST' else ''
                        resp = await h.client.request(method, f'/v1/saves/{owner}/{save_id}{suffix}', json=body,
                                                      headers=headers(PROF))
                        assert resp.status == 404, (method, owner, save_id)
        run(go())

    def test_an_exam_only_lab_never_comes_back_to_a_student(self, tmp_path):
        """``sre restore`` accepts the exam-only labs in user mode: the agent checks the lab of
        the save against the labs the caller may start."""
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started(PROF, lab=EXAM_LAB, debug_project=True)
                entry = await saved(h, rln, PROF)
                assert entry['lab'] == EXAM_LAB and entry['debug_project'] is True
                await h.client.put(f"/v1/saves/prof/{entry['id']}", json={'shared_with': ['custom:TP 2']},
                                   headers=headers(PROF))
                code, answer = await restore(h, entry, ALICE, via='custom:TP 2')
                assert code == 404 and 'not available' in answer['error']
                assert not [e for e in h.entries() if 'restore' in e['argv']]
                # an instructor may
                assert (await restore(h, entry, PROF))[1]['status'] == 'created'
        run(go())

    def test_another_architecture(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                entry = await saved(h, await h.started())
                sidecar = tmp_path / 'saves' / 'alice' / f"{entry['id']}.json"
                sidecar.write_text(json.dumps({**entry, 'arch': 'riscv128'}))
                code, answer = await restore(h, entry)
                assert code == 409 and 'riscv128' in answer['error']
        run(go())

    def test_a_damaged_save_says_so(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await h.started()
                entry = await saved(h, rln)
                data = tmp_path / 'saves' / 'alice' / f"{entry['id']}.sre"
                os.truncate(data, entry['size'] - 100)
                code, result = await restore(h, entry)
                assert code == 200 and result == {'phase': 'result', 'status': 'error',
                                                  'message': 'the saved project is damaged'}
                projects = await (await h.client.get('/v1/projects', headers=headers())).json()
                assert [p['running_lab_name'] for p in projects] == [rln]
        run(go())

    def test_sre_refusing(self, tmp_path):
        async def go():
            async with harness(tmp_path, mock_env={'MOCK_FAIL': 'restore'}) as h:
                # MOCK_FAIL names one command: the save itself goes through
                entry = await saved(h, await h.started())
                code, result = await restore(h, entry)
                assert code == 200 and result['status'] == 'error' and result['message'] == 'sre: mock failure'
        run(go())

    def test_a_restore_shares_the_start_limits(self, tmp_path):
        """Two restores of one user run one after the other (the start lock per user), and the
        helper of the second is not started while it waits."""
        async def go():
            async with harness(tmp_path, mock_env={'MOCK_START_DELAY': '0.1'}) as h:
                entry = await saved(h, await h.started())
                started = []
                reader = h.agent.saves.reader

                def counting(owner, save_id):
                    source = reader(owner, save_id)
                    opening = source.open

                    async def open_():
                        started.append(time.monotonic())
                        return await opening()

                    source.open = open_
                    return source

                h.agent.saves.reader = counting
                first, second = await asyncio.gather(restore(h, entry), restore(h, entry))
                assert first[1]['status'] == second[1]['status'] == 'created'
                # 7 steps of 0.1 s per restore: the second helper started once the first restore ended
                assert len(started) == 2 and started[1] - started[0] > 0.5
        run(go())

    def test_agent_restarting(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                entry = await saved(h, await h.started())
                h.agent.restarting = time.monotonic()
                assert (await restore(h, entry))[0] == 503
        run(go())


class TestShutdown:
    def test_a_running_save_is_stopped_and_leaves_nothing(self, tmp_path):
        async def go():
            async with harness(tmp_path, mock_env={'MOCK_SAVE_SIZE': str(1 << 20)}) as h:
                rln = await h.started()
                project = h.agent.registry.projects[rln]
                # the save waits behind the lock of the owner: cancelled there, as at a stop
                async with h.agent.saves.owner_lock('alice'):
                    request = asyncio.ensure_future(save(h, rln))
                    for _ in range(100):
                        if h.agent._save_tasks:
                            break
                        await asyncio.sleep(0.01)
                    assert h.agent._save_tasks
                    for task in list(h.agent._save_tasks):
                        task.cancel()
                    await asyncio.gather(*h.agent._save_tasks, return_exceptions=True)
                request.cancel()
                await asyncio.gather(request, return_exceptions=True)
                assert files_of(tmp_path) == [store.MARKER] and not project.lock.locked()
        run(go())


class TestSweep:
    def test_stale_temporary_directories(self, tmp_path):
        old, fresh, other = tmp_path / 'save-old', tmp_path / 'restore-fresh', tmp_path / 'kept'
        for directory in (old, fresh, other, tmp_path / 'restore-old'):
            directory.mkdir()
            (directory / 'kathara.tar').write_bytes(b'x')
        (tmp_path / 'save-file').write_text('not a directory')
        now = time.time()
        for directory in (old, tmp_path / 'restore-old', other):
            os.utime(directory, (now - 4000,) * 2)
        assert sorted(sweep_tmp_dir(str(tmp_path), older_than=1800)) == ['restore-old', 'save-old']
        assert sorted(p.name for p in tmp_path.iterdir()) == ['kept', 'restore-fresh', 'save-file']
        assert sweep_tmp_dir(str(tmp_path / 'nowhere'), older_than=1) == []
