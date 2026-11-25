"""Tests of the saved projects on the portal (``sreweb/portal/saves.py``): the rules about who
sees, restores and shares a save, the list kept from the agents, and the routes in front of a
real agent whose directory of saved projects is a directory of the test."""
import json

import pytest

from sreweb import savestore as store
from sreweb.config import ConfigError, web_config_from_dict
from sreweb.identity import Identity
from sreweb.portal import saves as W
from sreweb.portal.groups import Memberships
from sreweb.portal.pool import PoolError

import test_web_portal as P
from test_agent_saves import store_user
from test_web_portal import run

LAB = 'sre/dhcp.py'
ALICE = P.who('alice', 'Alice A', group='1A')
BOB = P.who('bob', 'Bob B', group='1A')
CAROL = P.who('carol', group='2B')
PROF = P.who('prof', 'Prof P', groups=P.TEACHERS)


def entry(owner='alice', save_id='20261123101500-0a1b2c3d', **over) -> dict:
    return store.clean_entry({'lab': LAB, 'saved_at': '2026-11-23T10:15:00+00:00', 'size': 10, **over}, owner, save_id)


class FakeMemberships:
    def __init__(self, groups):
        self.groups = groups

    def groups_of_identity(self, identity):
        return list(self.groups.get(identity.login, []))


class TestConfig:
    BASE = {'secret': P.SECRET, **P.PROXY_OVER}

    def test_off_by_default(self):
        cfg = web_config_from_dict(self.BASE)
        assert cfg.saves.enabled is False and cfg.saves.max_per_user == 5 and cfg.saves.max_per_instructor == 0
        assert cfg.saves.cache_ttl == 30 and cfg.limits.save_interval == 60

    def test_section(self):
        cfg = web_config_from_dict({**self.BASE, 'saves': {'enabled': True, 'max_per_user': 3, 'max_per_instructor': 20,
                                                           'cache_ttl': '2m'}, 'limits': {'save_interval': '5m'}})
        assert cfg.saves.enabled and cfg.saves.max_per_user == 3 and cfg.saves.max_per_instructor == 20
        assert cfg.saves.cache_ttl == 120 and cfg.limits.save_interval == 300

    @pytest.mark.parametrize('section', [{'enabled': 'yes'}, {'max_per_user': -1}, {'max_per_user': True},
                                         {'max_per_instructor': 1.5}, {'cache_ttl': -1}, {'dir': '/srv'}])
    def test_refused(self, section):
        with pytest.raises(ConfigError):
            web_config_from_dict({**self.BASE, 'saves': section})

    def test_needs_users_who_log_in(self):
        """A pseudonym lasts as long as its cookie: its saves would be nobody's."""
        with pytest.raises(ConfigError, match='log in'):
            web_config_from_dict({'secret': P.SECRET, 'auth': {'mode': 'anonymous'}, 'saves': {'enabled': True}})
        web_config_from_dict({'secret': P.SECRET, 'auth': {'mode': 'anonymous'}, 'saves': {'enabled': False}})


class TestRules:
    alice = Identity(login='alice', group='1A')
    bob = Identity(login='bob', group='1A')
    prof = Identity(login='prof', role='instructor')

    def test_keys_of_an_identity(self):
        # without any directory: the department the identity carries
        assert W.keys_of(self.alice, Memberships()) == ['department:1A']
        assert W.keys_of(Identity(login='x'), Memberships()) == []
        m = FakeMemberships({'alice': ['department:1A', 'directory:sre', 'custom:TP lundi', 'department:1A']})
        assert W.keys_of(self.alice, m) == ['department:1A', 'directory:sre', 'custom:TP lundi']

    def test_canonical(self):
        assert W.canonical('1A') == 'department:1A' and W.canonical('custom:TP 2') == 'custom:TP 2'
        assert W.canonical('a:b') == 'department:a:b'

    def test_who_sees_what(self):
        mine = entry()
        shared = entry('carol', '20261123101500-00000002', shared_with=['custom:TP 2', '1A'])
        other = entry('carol', '20261123101500-00000003', shared_with=['department:2B'])
        exam = entry('prof', '20261123101500-00000004', shared_with=['department:1A'], exam=True)
        saves = [mine, shared, other, exam]
        own = ['department:1A']
        assert W.visible(saves, self.alice, own) == [mine, shared]
        assert W.via_group(shared, own) == '1A' and W.via_group(other, own) is None
        assert W.visible(saves, self.prof, []) == [exam]
        assert W.visible(saves, self.prof, [], everything=True) == saves
        # "everything" is the instructors'
        assert W.visible(saves, self.alice, own, everything=True) == [mine, shared]

    def test_who_restores_and_changes(self):
        mine = entry()
        shared = entry('carol', shared_with=['department:1A'])
        other = entry('carol')
        exam = entry('prof', shared_with=['department:1A'], exam=True)
        own = ['department:1A']
        assert W.may_restore(mine, self.alice, own) and W.may_change(mine, self.alice)
        assert W.may_restore(shared, self.alice, own) and not W.may_change(shared, self.alice)
        assert not W.may_restore(other, self.alice, own)
        assert W.may_restore(other, self.prof, []) and W.may_change(other, self.prof)
        # the save of an exam project: instructors only, whatever it is shared with
        assert not W.may_restore(exam, self.alice, own) and W.may_restore(exam, self.prof, [])
        assert not W.may_restore(entry(exam=True), self.alice, own)

    def test_quota(self):
        cfg = web_config_from_dict({**TestConfig.BASE, 'saves': {'max_per_user': 3, 'max_per_instructor': 0}}).saves
        assert W.quota_of(self.alice, cfg) == 3 and W.quota_of(self.prof, cfg) == 0

    def test_shares_of_a_student(self):
        own = ['department:1A', 'custom:TP 2']
        mine = entry()
        assert W.checked_shares(mine, self.alice, ['1A', 'custom:TP 2', 'department:1A'], own) == \
            ['department:1A', 'custom:TP 2']
        assert W.checked_shares(mine, self.alice, [], own) == []
        with pytest.raises(W.SaveRule) as e:
            W.checked_shares(mine, self.alice, ['department:2B'], own)
        assert e.value.status == 403 and '2B' in e.value.message
        # a group already there stays (an instructor shared it, or the student left the group)
        kept = entry(shared_with=['department:2B'])
        assert W.checked_shares(kept, self.alice, ['department:2B', '1A'], own) == ['department:2B', 'department:1A']

    def test_shares_of_an_instructor(self):
        assert W.checked_shares(entry(), self.prof, ['department:2B', 'directory:sre'], []) == \
            ['department:2B', 'directory:sre']

    @pytest.mark.parametrize('wanted', ['department:1A', [1], [''], ['custom:'], ['custom:a\x00b'], ['x' * 80],
                                        [f'custom:g{i}' for i in range(store.MAX_SHARED_WITH + 1)]])
    def test_bad_shares(self, wanted):
        with pytest.raises(W.SaveRule) as e:
            W.checked_shares(entry(), self.prof, wanted, [])
        assert e.value.status == 400

    def test_an_exam_save_is_never_shared(self):
        with pytest.raises(W.SaveRule) as e:
            W.checked_shares(entry(exam=True), self.prof, ['department:1A'], [])
        assert e.value.status == 409
        assert W.checked_shares(entry(exam=True), self.prof, [], []) == []

    def test_what_an_agent_lists_is_coerced(self):
        assert W.coerced(entry()) == entry()
        for bad in (None, [], {}, {'owner': '..', 'id': '20261123101500-0a1b2c3d'}, {'owner': 'alice', 'id': 'x'}):
            assert W.coerced(bad) is None
        hostile = W.coerced({'owner': 'alice', 'id': '20261123101500-0a1b2c3d', 'size': 'huge', 'shared_with': 'all',
                             'exam': 1, 'lab': 3})
        assert hostile['size'] == 0 and hostile['shared_with'] == [] and hostile['exam'] is False and hostile['lab'] == ''


class FakePool:
    def __init__(self):
        self.hosts = []

    def save_hosts(self, identity=None):
        return list(self.hosts)


class TestCatalog:
    def catalog(self, answers, ttl=30.0):
        """A catalog whose agent answers the next item of *answers* at each fetch (``None``: no
        host answers), on a clock the test moves."""
        clock = {'now': 1000.0}
        catalog = W.SaveCatalog(FakePool(), ttl=ttl, clock=lambda: clock['now'])
        fetched = []

        async def fetch():
            fetched.append(clock['now'])
            answer = answers.pop(0)
            return None if answer is None else (list(answer), {'free_mb': 10, 'total_mb': 20})

        catalog._fetch = fetch
        return catalog, clock, fetched

    def test_kept_for_the_ttl(self):
        a, b = entry(), entry('bob', '20261123111500-00000002', saved_at='2026-11-23T11:15:00+00:00')
        catalog, clock, fetched = self.catalog([[a], [a, b]])

        async def go():
            first = await catalog.load()
            assert first == {'saves': [a], 'free_mb': 10, 'total_mb': 20, 'stale': False}
            clock['now'] += 29
            assert (await catalog.load())['saves'] == [a] and len(fetched) == 1
            clock['now'] += 2
            assert (await catalog.load())['saves'] == [b, a] and len(fetched) == 2      # the newest first
            assert await catalog.find('bob', b['id']) == b
            with pytest.raises(PoolError) as e:
                await catalog.find('bob', a['id'])
            assert e.value.status == 404
        run(go())

    def test_what_this_portal_changed_stays_on_top(self):
        """Another host lists the shared directory through its own cache: a save just made is
        missing from its list, a save just deleted still in it."""
        old, new = entry(), entry('alice', '20261123121500-00000009', saved_at='2026-11-23T12:15:00+00:00')
        catalog, clock, fetched = self.catalog([[old], [old], [old], [old, new]], ttl=0)

        async def go():
            assert (await catalog.load())['saves'] == [old]
            catalog.applied(new)
            catalog.removed('alice', old['id'])
            assert (await catalog.load())['saves'] == [new]
            # a change of a save: the entry replaces the listed one
            shared = {**new, 'shared_with': ['department:1A']}
            catalog.applied(shared)
            assert (await catalog.load())['saves'] == [shared]
            # two minutes later the agents are believed again
            clock['now'] += W.OVERLAY_TTL + 1
            assert (await catalog.load())['saves'] == [new, old]
        run(go())

    def test_no_host(self):
        a = entry()
        catalog, clock, fetched = self.catalog([None, [a], None])

        async def go():
            with pytest.raises(PoolError) as e:
                await catalog.load()
            assert e.value.status == 503 and e.value.retry_after == 30
            assert (await catalog.load())['stale'] is False
            clock['now'] += 31
            # the last list, flagged: an empty page would read as lost saves
            assert await catalog.load() == {'saves': [a], 'free_mb': 10, 'total_mb': 20, 'stale': True}
        run(go())

    def test_invalidate_and_refresh(self):
        a = entry()
        catalog, clock, fetched = self.catalog([[a], [], [a]])

        async def go():
            await catalog.load()
            catalog.invalidate()
            assert (await catalog.load())['saves'] == [] and len(fetched) == 2
            assert (await catalog.load(refresh=True))['saves'] == [a] and len(fetched) == 3
        run(go())


# ---------------------------------------------------------------------------------------------
# through the portal
# ---------------------------------------------------------------------------------------------

def harness(tmp_path, *, web_saves=None, agent_saves=None, enabled=True, web_extra=None, **kw):
    directory = tmp_path / 'saves'
    directory.mkdir()
    (directory / store.MARKER).touch()
    web_over = {**P.PROXY_OVER, 'limits': {'save_interval': 0, 'start_interval': 0},
                'saves': {'enabled': enabled, 'cache_ttl': 0, **(web_saves or {})}, **(web_extra or {})}
    return P.Harness(tmp_path, auth_mode='proxy', web_over=web_over, host_over={'max_projects': 9},
                     agent_over={'saves': {'dir': str(directory), 'user': store_user(), 'min_free_mb': 0,
                                           **(agent_saves or {})}},
                     mock_env={'MOCK_SRE_LOG': str(tmp_path / 'mock.log')}, **kw)


def sre_calls(tmp_path, command: str) -> list:
    log = tmp_path / 'mock.log'
    if not log.exists():
        return []
    return [json.loads(line)['argv'] for line in log.read_text().splitlines() if command in json.loads(line)['argv']]


async def ready(h):
    """The portal has polled the agent: it knows the host has the saved projects."""
    await h.portal.pool.refresh()
    assert h.portal.pool.status['a01'].saves is True


async def start(h, user, lab=LAB, **body) -> str:
    resp = await h.client.post('/api/projects', json={'lab': lab, **body}, headers={**user, **P.CSRF})
    assert resp.status == 200, await resp.text()
    result = json.loads((await resp.text()).splitlines()[-1])
    assert result['status'] == 'created', result
    return result['running_lab_name']


async def save(h, user, rln, **body):
    resp = await h.client.post(f'/api/projects/a01/{rln}/save', json=body, headers={**user, **P.CSRF})
    return resp.status, await resp.json()


async def saved(h, user, rln, **body) -> dict:
    status, answer = await save(h, user, rln, **body)
    assert status == 200, answer
    return answer['save']


async def listing(h, user, query='') -> dict:
    resp = await h.client.get('/api/saves' + query, headers=user)
    assert resp.status == 200, await resp.text()
    return await resp.json()


async def restore(h, user, entry_, **body):
    resp = await h.client.post(f"/api/saves/{entry_['owner']}/{entry_['id']}/restore", json=body,
                               headers={**user, **P.CSRF})
    if resp.status != 200:
        return resp.status, await resp.json()
    return 200, json.loads((await resp.text()).splitlines()[-1])


async def share(h, user, entry_, groups):
    resp = await h.client.put(f"/api/saves/{entry_['owner']}/{entry_['id']}", json={'shared_with': groups},
                              headers={**user, **P.CSRF})
    return resp.status, await resp.json()


class TestGuards:
    def test_off(self, tmp_path):
        async def go():
            async with harness(tmp_path, enabled=False) as h:
                await h.portal.pool.refresh()
                rln = await start(h, ALICE)
                assert (await h.client.get('/saves', headers=ALICE)).status == 404
                assert (await h.client.get('/api/saves', headers=ALICE)).status == 404
                assert (await save(h, ALICE, rln))[0] == 404
                for method in ('PUT', 'DELETE'):
                    resp = await h.client.request(method, '/api/saves/alice/20261123101500-0a1b2c3d', json={},
                                                  headers={**ALICE, **P.CSRF})
                    assert resp.status == 404
                assert sre_calls(tmp_path, 'save') == []
        run(go())

    def test_page_and_roles(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                resp = await h.client.get('/saves', headers=ALICE)
                assert resp.status == 200 and 'alice False saves=True' in await resp.text()
                assert 'prof True saves=True' in await (await h.client.get('/saves', headers=PROF)).text()
                # not logged in (no proxy header): nothing
                assert (await h.client.get('/api/saves')).status == 401
                # every save of the pool: instructors
                assert (await h.client.get('/api/saves?all=1', headers=ALICE)).status == 403
                assert (await h.client.get('/api/saves?all=1', headers=PROF)).status == 200
                # a write without the CSRF header
                rln = await start(h, ALICE)
                resp = await h.client.post(f'/api/projects/a01/{rln}/save', json={}, headers=ALICE)
                assert resp.status == 403
        run(go())

    def test_a_student_in_an_exam(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                rln = await start(h, ALICE)
                kept = await saved(h, ALICE, rln)
                h.portal.routes._exam_binding = lambda identity: ('exam',) if identity.login == 'alice' else None
                assert (await h.client.get('/api/saves', headers=ALICE)).status == 403
                assert (await save(h, ALICE, rln))[0] == 403
                assert (await restore(h, ALICE, kept))[0] == 403
                assert (await share(h, ALICE, kept, []))[0] == 403
                resp = await h.client.get('/saves', headers=ALICE, allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == '/projects'
                # the others are not concerned
                assert (await h.client.get('/api/saves', headers=BOB)).status == 200
        run(go())


class TestSaveAndRestore:
    def test_a_save_from_the_project_to_its_deletion(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                rln = await start(h, ALICE)
                project = (await (await h.client.get(f'/api/projects/a01/{rln}', headers=ALICE)).json())['project']
                assert project['can_save'] is True
                kept = await saved(h, ALICE, rln, comment='after part 2')
                assert kept['owner'] == 'alice' and kept['lab'] == LAB and kept['comment'] == 'after part 2'
                assert kept['fullname'] == 'Alice A' and kept['group'] == '1A'

                mine = await listing(h, ALICE)
                assert mine['quota'] == {'max': 5, 'used': 1} and mine['stale'] is False
                assert mine['my_groups'] == [{'key': 'department:1A', 'kind': 'department', 'name': '1A'}]
                assert isinstance(mine['free_mb'], int) and mine['total_mb'] >= mine['free_mb']
                row = mine['saves'][0]
                assert {k: row[k] for k in kept} == kept
                assert row['mine'] is True and row['shared_with_me'] is False and row['lab_known'] is True
                assert row['lab_title'] is not None
                # nobody else sees it; an instructor does, in the list of every save
                assert (await listing(h, BOB))['saves'] == []
                assert (await listing(h, PROF))['saves'] == []
                everything = (await listing(h, PROF, '?all=1'))['saves']
                assert [r['id'] for r in everything] == [kept['id']] and everything[0]['mine'] is False

                # restored as a new project of the user, on the host that has the saves
                code, result = await restore(h, ALICE, kept)
                assert code == 200 and result['status'] == 'created' and result['host'] == 'a01'
                assert result['running_lab_name'] != rln and result['running_lab_name'].endswith('@@@alice')
                projects = await (await h.client.get('/api/projects', headers=ALICE)).json()
                assert len(projects['projects'] if isinstance(projects, dict) else projects) == 2

                resp = await h.client.delete(f"/api/saves/alice/{kept['id']}", headers={**ALICE, **P.CSRF})
                assert resp.status == 200
                assert (await listing(h, ALICE))['saves'] == []
                assert (await restore(h, ALICE, kept))[0] == 404
                # deleted twice: already what was asked
                resp = await h.client.delete(f"/api/saves/alice/{kept['id']}", headers={**ALICE, **P.CSRF})
                assert resp.status == 404
        run(go())

    def test_the_quota_is_told_before_anything_is_saved(self, tmp_path):
        async def go():
            async with harness(tmp_path, web_saves={'max_per_user': 1, 'max_per_instructor': 2}) as h:
                await ready(h)
                rln = await start(h, ALICE)
                first = await saved(h, ALICE, rln, comment='one')
                code, answer = await save(h, ALICE, rln)
                assert code == 409 and answer['code'] == store.CODE_QUOTA and answer['quota'] == 1
                # the page lists what may be deleted
                assert [(r['id'], r['comment'], r['mine']) for r in answer['saves']] == [(first['id'], 'one', True)]
                assert len(sre_calls(tmp_path, 'save')) == 1, "refused before the agent runs sre"
                # one deleted: saved
                await h.client.delete(f"/api/saves/alice/{first['id']}", headers={**ALICE, **P.CSRF})
                await saved(h, ALICE, rln)
                # an instructor has their own limit, and their saves of a student's project are theirs
                for _ in range(2):
                    assert (await saved(h, PROF, rln))['owner'] == 'prof'
                assert (await save(h, PROF, rln))[0] == 409
                assert (await listing(h, ALICE))['quota'] == {'max': 1, 'used': 1}
                assert (await listing(h, PROF))['quota'] == {'max': 2, 'used': 2}
        run(go())

    def test_the_agent_has_the_last_word_on_the_quota(self, tmp_path):
        """The list the portal keeps may miss a save made a moment ago through another portal or
        host: the agent counts in the directory, and its refusal reads like the portal's."""
        async def go():
            async with harness(tmp_path, web_saves={'max_per_user': 1, 'cache_ttl': 3600}) as h:
                await ready(h)
                rln = await start(h, ALICE)
                await listing(h, ALICE)             # the list is kept, empty
                first = await saved(h, ALICE, rln)
                # forget it, as a portal that did not make it
                h.portal.routes.saves.catalog._overlay.clear()
                code, answer = await save(h, ALICE, rln)
                assert code == 409 and answer['code'] == store.CODE_QUOTA
                assert [r['id'] for r in answer['saves']] == [first['id']]
        run(go())

    def test_another_student_cannot_save_the_project(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                rln = await start(h, ALICE)
                assert (await save(h, BOB, rln))[0] == 403
                assert (await save(h, ALICE, rln, comment=3))[0] == 400
        run(go())

    def test_one_save_at_a_time_and_an_interval(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                rln = await start(h, ALICE)
                h.portal.routes.saves._saving.add('alice')
                code, answer = await save(h, ALICE, rln)
                assert code == 409 and 'already running' in answer['error']
                h.portal.routes.saves._saving.clear()
                h.portal.cfg.limits.save_interval = 3600
                await saved(h, ALICE, rln)
                resp = await h.client.post(f'/api/projects/a01/{rln}/save', json={}, headers={**ALICE, **P.CSRF})
                assert resp.status == 429 and (await resp.json())['retry_after'] > 0
        run(go())

    def test_a_save_that_fails_costs_nothing(self, tmp_path):
        async def go():
            async with harness(tmp_path, agent_saves={'max_size_mb': 1}, web_saves={'max_per_user': 1}) as h:
                h.agent.runner.extra_env['MOCK_SAVE_SIZE'] = str(3 << 20)
                await ready(h)
                rln = await start(h, ALICE)
                h.portal.cfg.limits.save_interval = 3600
                code, answer = await save(h, ALICE, rln)
                assert code == 413 and answer['code'] == store.CODE_TOO_LARGE
                assert (await listing(h, ALICE))['saves'] == []
                # the slot of the user was given back: the next save is not made to wait
                h.agent.runner.extra_env['MOCK_SAVE_SIZE'] = '1000'
                await saved(h, ALICE, rln)
        run(go())


class TestSharing:
    def test_a_group_restores_what_a_member_shared(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                kept = await saved(h, ALICE, await start(h, ALICE))
                # only a group of the student
                code, answer = await share(h, ALICE, kept, ['department:2B'])
                assert code == 403 and '2B' in answer['error']
                code, answer = await share(h, ALICE, kept, ['1A'])
                assert code == 200 and answer['save']['shared_with'] == ['department:1A']

                seen = (await listing(h, BOB))['saves']
                assert [(r['id'], r['mine'], r['shared_with_me']) for r in seen] == [(kept['id'], False, True)]
                assert (await listing(h, BOB))['quota']['used'] == 0, "a shared save is not the member's"
                assert (await listing(h, CAROL))['saves'] == []

                code, result = await restore(h, BOB, kept)
                assert code == 200 and result['status'] == 'created' and result['running_lab_name'].endswith('@@@bob')
                assert (await restore(h, CAROL, kept))[0] == 403
                # a member neither changes nor deletes it
                assert (await share(h, BOB, kept, []))[0] == 403
                resp = await h.client.delete(f"/api/saves/alice/{kept['id']}", headers={**BOB, **P.CSRF})
                assert resp.status == 403

                # an instructor shares with any group
                code, answer = await share(h, PROF, kept, ['department:1A', 'department:2B'])
                assert code == 200 and (await listing(h, CAROL))['saves'][0]['shared_with_me'] is True
                # the owner keeps a group they are not in, and takes everything back
                assert (await share(h, ALICE, kept, ['department:2B']))[0] == 200
                assert (await listing(h, BOB))['saves'] == []
                assert (await share(h, ALICE, kept, []))[0] == 200
                assert (await listing(h, CAROL))['saves'] == [] and (await restore(h, CAROL, kept))[0] == 403
        run(go())

    def test_the_comment(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                kept = await saved(h, ALICE, await start(h, ALICE))
                url = f"/api/saves/alice/{kept['id']}"
                resp = await h.client.put(url, json={'comment': 'renamed'}, headers={**ALICE, **P.CSRF})
                assert resp.status == 200 and (await resp.json())['save']['comment'] == 'renamed'
                assert (await listing(h, ALICE))['saves'][0]['comment'] == 'renamed'
                for body in ({}, {'comment': 3}, {'shared_with': 'x'}, [1]):
                    assert (await h.client.put(url, json=body, headers={**ALICE, **P.CSRF})).status == 400
        run(go())


class TestHostsAndLabs:
    def test_only_a_host_that_has_the_saves(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                kept = await saved(h, ALICE, await start(h, ALICE))
                await listing(h, ALICE)
                # its volume went away: the agent says so in its status
                (tmp_path / 'saves' / store.MARKER).unlink()
                await h.agent.saves.refresh()
                await h.portal.pool.refresh()
                assert h.portal.pool.status['a01'].saves is False
                assert h.portal.pool.save_hosts() == []
                # the last list, flagged; no restore, no change
                again = await listing(h, ALICE)
                assert again['stale'] is True and [r['id'] for r in again['saves']] == [kept['id']]
                code, answer = await restore(h, ALICE, kept)
                assert code == 503
                assert (await share(h, ALICE, kept, []))[0] == 503
                # a project still starts there
                await start(h, ALICE)
        run(go())

    def test_a_host_meant_to_save_and_unable_to_is_told(self, tmp_path):
        """The rows of ``GET /api/pool`` (the Pool page, `sre-web-tool list`) say that the host
        has a directory of the saved projects, whether it is usable, and the agent's reason."""
        from sreweb.portal.pool import MAX_STATUS_TEXT
        from sreweb.portal.poolctl import saves_unusable, _cell

        async def row(h) -> dict:
            await h.agent.saves.refresh()
            await h.portal.pool.refresh()
            resp = await h.client.get('/api/pool', headers=PROF)
            assert resp.status == 200, await resp.text()
            (found,) = [r for r in await resp.json() if r['name'] == 'a01']
            return found

        async def go():
            async with harness(tmp_path) as h:
                usable = await row(h)
                assert (usable['saves'], usable['saves_configured'], usable['saves_error']) == (True, True, '')
                assert not saves_unusable(usable) and _cell(usable, 'state') == 'up' and _cell(usable, 'error') == ''
                # the marker is gone (the volume not mounted, or a marker nobody created)
                marker = tmp_path / 'saves' / store.MARKER
                marker.unlink()
                told = await row(h)
                assert (told['saves'], told['saves_configured'], told['reachable']) == (False, True, True)
                # the agent's text, cut by the portal like every text of a status (the path of a
                # test directory is long): the file and what is wrong with it come first
                reason = h.agent.saves.error
                assert reason.startswith(f"{marker}: not found (") and 'never created' in reason
                assert told['saves_error'] == reason[:MAX_STATUS_TEXT]
                assert saves_unusable(told) and _cell(told, 'state') == 'up (saves unusable)'
                assert _cell(told, 'error').startswith(f"saves: {marker}"[:40])
                # a student is told nothing of the pool
                assert (await h.client.get('/api/pool', headers=ALICE)).status == 403
                # created: the host is back at its next check
                marker.touch()
                back = await row(h)
                assert (back['saves'], back['saves_configured'], back['saves_error']) == (True, True, '')
        run(go())

    def test_a_host_without_a_directory_is_not_told(self, tmp_path):
        """No ``[saves] dir`` on the agent: the host is not meant to save, nothing is flagged."""
        from sreweb.portal.poolctl import saves_unusable

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy',
                                 web_over={**P.PROXY_OVER, 'saves': {'enabled': True}}) as h:
                await h.portal.pool.refresh()
                (found,) = await (await h.client.get('/api/pool', headers=PROF)).json()
                assert (found['saves'], found['saves_configured'], found['saves_error']) == (False, False, 'not configured')
                assert found['reachable'] and not saves_unusable(found)
        run(go())

    def test_a_named_host_without_the_saves(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                kept = await saved(h, ALICE, await start(h, ALICE))
                assert (await restore(h, ALICE, kept, host='a01'))[0] == 403       # instructors name a host
                assert (await restore(h, ALICE, kept, instructor_mode=True))[0] == 403
                code, result = await restore(h, PROF, kept, host='a01', instructor_mode=True)
                assert code == 200 and result['status'] == 'created'
                assert sre_calls(tmp_path, 'restore')[-1] == ['restore', '--instructor-mode', '--', '-']
                h.portal.pool.status['a01'].saves = False
                code, answer = await restore(h, PROF, kept, host='a01')
                assert code == 503 and 'saved projects' in answer['error']
        run(go())

    def test_a_lab_that_is_gone(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                kept = await saved(h, ALICE, await start(h, ALICE))
                sidecar = tmp_path / 'saves' / 'alice' / f"{kept['id']}.json"
                sidecar.write_text(json.dumps({**kept, 'lab': 'old/removed.py'}))
                # the portal keeps what it saved on top of what the agents list: not for this
                # change, made behind its back
                h.portal.routes.saves.catalog._overlay.clear()
                row = (await listing(h, ALICE))['saves'][0]
                assert row['lab'] == 'old/removed.py' and row['lab_known'] is False and row['lab_title'] is None
                code, result = await restore(h, ALICE, kept)
                assert code == 404 and 'not available' in result['error']
        run(go())

    def test_restores_are_counted_like_starts(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                kept = await saved(h, ALICE, await start(h, ALICE))
                await share(h, ALICE, kept, ['department:1A'])
                h.portal.cfg.limits.start_interval = 3600
                # alice started a project a moment ago: her restore waits as a start would
                code, answer = await restore(h, ALICE, kept)
                assert code == 429 and answer['retry_after'] > 0
                # bob started nothing: his restore passes, and is his start of the hour
                assert (await restore(h, BOB, kept))[1]['status'] == 'created'
                assert (await restore(h, BOB, kept))[0] == 429
                resp = await h.client.post('/api/projects', json={'lab': LAB}, headers={**BOB, **P.CSRF})
                assert resp.status == 429
                # a restore that is refused costs nothing
                assert (await restore(h, CAROL, kept))[0] == 403
                resp = await h.client.post('/api/projects', json={'lab': LAB}, headers={**CAROL, **P.CSRF})
                assert resp.status == 200
        run(go())

    def test_names_are_checked(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                await ready(h)
                for owner, save_id in (('..', '20261123101500-0a1b2c3d'), ('alice', 'x'), ('a%2Fb', '20261123101500-0a1b2c3d')):
                    for method, suffix in (('POST', '/restore'), ('PUT', ''), ('DELETE', '')):
                        resp = await h.client.request(method, f'/api/saves/{owner}/{save_id}{suffix}', json={},
                                                      headers={**PROF, **P.CSRF})
                        assert resp.status == 404, (method, owner, save_id)
        run(go())


class TestAccessLog:
    def test_events(self):
        from sreweb.portal import accesslog as A
        assert A.EVENTS[('POST', '/api/projects/{host}/{rln}/save')] == 'save' and 'save' in A.PROJECT_EVENTS
        # a restore is a start: the statistics count it with the others
        assert A.EVENTS[('POST', '/api/saves/{owner}/{id}/restore')] == 'start'
        assert A.EVENTS[('PUT', '/api/saves/{owner}/{id}')] == 'save_share'
        assert A.EVENTS[('DELETE', '/api/saves/{owner}/{id}')] == 'save_delete'
        assert {'save', 'save_share', 'save_delete'} <= set(A.ALL_EVENTS)

    def test_lines(self, tmp_path):
        from sreweb.portal import accesslog as A
        log = tmp_path / 'access.log'

        async def go():
            async with harness(tmp_path, web_extra={'access_log': {'file': str(log), 'journal': False}}) as h:
                await ready(h)
                rln = await start(h, ALICE)
                kept = await saved(h, ALICE, rln)
                await share(h, ALICE, kept, ['department:1A'])
                await restore(h, BOB, kept)
                await h.client.delete(f"/api/saves/alice/{kept['id']}", headers={**ALICE, **P.CSRF})
                return rln, kept
        rln, kept = run(go())
        lines = [A.parse_line(line) for line in log.read_text().splitlines()]
        by_event = {}
        for line in lines:
            by_event.setdefault(line['event'], []).append(line)
        name = f"alice/{kept['id']}"
        save_line = by_event['save'][0]
        assert save_line['login'] == 'alice' and save_line['rln'] == rln and save_line['host'] == 'a01'
        assert save_line['save'] == name and save_line['result'] == 'saved' and save_line['lab'] == LAB
        assert by_event['save_share'][0]['save'] == name and 'department:1A' in str(by_event['save_share'][0]['groups'])
        restored = [line for line in by_event['start'] if line.get('restore')]
        assert len(restored) == 1 and restored[0]['login'] == 'bob' and restored[0]['restore'] == name
        assert restored[0]['result'] == 'created' and restored[0]['rln'].endswith('@@@bob') and restored[0]['lab'] == LAB
        assert by_event['save_delete'][0]['save'] == name and by_event['save_delete'][0]['login'] == 'alice'
