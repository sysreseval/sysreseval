"""The state file of the pool (``[admin] state_file``): what is changed by hand (the hosts added
and removed, the ``enabled`` flags differing from the configuration, the drains) and the clocks
of the wakes, power offs and restarts are back when the portal restarts; an edit of the
configuration wins over an older change made by hand; a file that cannot be written is told."""
import json
import logging
import os
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip('aiohttp')

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_pool_manager as M   # noqa: E402  (FakeSession: the agents of a pool, up(): a status)

from sreweb.config import HostConfig, PoolConfig   # noqa: E402
from sreweb.portal.manager import PoolManager   # noqa: E402
from sreweb.portal.pool import (Pool, STATE_VERSION, MAX_HOLD, MAX_WAKE_FAILURES, UNREADABLE_SUFFIX,   # noqa: E402
                                STATE_UP, STATE_OFF, STATE_WAKING, STATE_DRAINING, STATE_DISABLED)

TOKEN = M.TOKEN
run = M.run
up = M.up


def hosts(**enabled) -> list:
    """``hosts(s01=True, z01=False)``: the ``[[hosts]]`` of a configuration, with their ``enabled``."""
    return [HostConfig(name, f'http://{name}', TOKEN, 10, enabled=flag) for name, flag in enabled.items()]


def saved(path) -> dict:
    return json.loads(path.read_text())


def flags(pool) -> dict:
    return {name: rt.enabled for name, rt in pool.runtime.items()}


class TestEnabledFlags:
    def test_enabled_by_hand_is_kept(self, tmp_path):
        """The bug of 2026-11-10: a host the configuration disables, enabled by hand, came back
        disabled at every restart (the file only had a ``disabled`` list)."""
        state = tmp_path / 'pool.json'
        config = dict(s01=True, z01=False, z02=False)
        pool = Pool(hosts(**config), None, state_file=str(state))
        assert not state.exists() and pool.state_error == ''
        pool.set_enabled('z01', True)
        file = saved(state)
        assert file['version'] == STATE_VERSION and file['enabled'] == ['z01'] and file['disabled'] == []
        assert file['removed'] == [] and file['added'] == [] and file['drain'] == {} and file['clocks'] == {}
        assert oct(state.stat().st_mode & 0o777) == '0o600'
        again = Pool(hosts(**config), None, state_file=str(state))
        assert flags(again) == {'s01': True, 'z01': True, 'z02': False}
        assert again.state_of('z01') == STATE_OFF and again.state_of('z02') == STATE_DISABLED
        assert saved(state) == file                       # nothing to normalise: not written again
        # disabled again by hand: as the configuration says, nothing left in the file
        again.set_enabled('z01', False)
        assert saved(state)['enabled'] == [] and saved(state)['disabled'] == []
        assert flags(Pool(hosts(**config), None, state_file=str(state)))['z01'] is False

    def test_disabled_by_hand_is_kept(self, tmp_path):
        state = tmp_path / 'pool.json'
        config = dict(s01=True, s02=True, z01=False)
        Pool(hosts(**config), None, state_file=str(state)).set_enabled('s02', False)
        assert saved(state)['disabled'] == ['s02'] and saved(state)['enabled'] == []   # not z01: the configuration's
        again = Pool(hosts(**config), None, state_file=str(state))
        assert flags(again) == {'s01': True, 's02': False, 'z01': False}

    def test_an_edit_of_the_configuration_wins(self, tmp_path, caplog):
        """A flag set by hand holds while the configuration says what it said then; once the
        configuration says the same, the entry is gone (the file written again at the start), so
        a second edit of the configuration is followed too."""
        state = tmp_path / 'pool.json'
        pool = Pool(hosts(s01=True, z01=False), None, state_file=str(state))
        pool.set_enabled('z01', True)
        pool.set_enabled('s01', False)
        assert saved(state)['enabled'] == ['z01'] and saved(state)['disabled'] == ['s01']
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            edited = Pool(hosts(s01=False, z01=True), None, state_file=str(state))
        assert flags(edited) == {'s01': False, 'z01': True}
        assert saved(state)['enabled'] == [] and saved(state)['disabled'] == []
        assert 'z01 was enabled by hand and the configuration says so now' in caplog.text
        assert 's01 was disabled by hand and the configuration says so now' in caplog.text
        back = Pool(hosts(s01=True, z01=False), None, state_file=str(state))
        assert flags(back) == {'s01': True, 'z01': False}

    def test_version_1_file(self, tmp_path):
        """The former file listed every disabled host, the ones the configuration disables too:
        it loads as it is, and only what differs from the configuration stays.  A host enabled
        in the configuration afterwards is no longer held by the old list."""
        state = tmp_path / 'pool.json'
        state.write_text(json.dumps({'removed': [], 'added': [], 'disabled': ['s02', 'z01', 'z02']}))
        pool = Pool(hosts(s01=True, s02=True, z01=False, z02=False), None, state_file=str(state))
        assert flags(pool) == {'s01': True, 's02': False, 'z01': False, 'z02': False}
        file = saved(state)
        assert file['version'] == STATE_VERSION and file['disabled'] == ['s02'] and file['enabled'] == []
        edited = Pool(hosts(s01=True, s02=True, z01=True, z02=False), None, state_file=str(state))
        assert flags(edited) == {'s01': True, 's02': False, 'z01': True, 'z02': False}

    def test_disabled_wins_and_hosts_gone_are_forgotten(self, tmp_path, caplog):
        state = tmp_path / 'pool.json'
        state.write_text(json.dumps({'version': STATE_VERSION, 'removed': ['gone'], 'added': [],
                                     'enabled': ['z01', 'z02', 'left'], 'disabled': ['z02', 's01'],
                                     'drain': {'left': 5.0}, 'clocks': {'left': {'woken_at': time.time()}}}))
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            pool = Pool(hosts(s01=True, z01=False, z02=False), None, state_file=str(state))
        assert flags(pool) == {'s01': False, 'z01': True, 'z02': False}
        assert 'left (enabled by hand) is not in the pool any more' in caplog.text
        file = saved(state)
        assert file['enabled'] == ['z01'] and file['disabled'] == ['s01'] and file['removed'] == []
        assert file['drain'] == {} and file['clocks'] == {}

    def test_removed_and_added_hosts(self, tmp_path, caplog):
        state = tmp_path / 'pool.json'
        config = dict(s01=True, z01=False)
        pool = Pool(hosts(**config), None, state_file=str(state))
        pool.remove_host('z01')
        pool.add_host(HostConfig('b02', 'http://b02', TOKEN, 2))
        pool.set_enabled('b02', False)
        file = saved(state)
        assert file['removed'] == ['z01'] and [h['name'] for h in file['added']] == ['b02']
        assert file['disabled'] == ['b02'] and file['enabled'] == []
        again = Pool(hosts(**config), None, state_file=str(state))
        assert flags(again) == {'s01': True, 'b02': False} and again.runtime['b02'].source == 'added'
        assert saved(state) == file
        # `enable` of a host removed by hand brings it back enabled, whatever the configuration says
        again.set_enabled('z01', True)
        assert again.runtime['z01'].enabled is True and again.runtime['z01'].source == 'config'
        assert saved(state)['removed'] == [] and saved(state)['enabled'] == ['z01']
        assert flags(Pool(hosts(**config), None, state_file=str(state))) == {'s01': True, 'z01': True, 'b02': False}
        # the added host is now in the configuration: its entry there is used, the flag set by hand kept
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            moved = Pool(hosts(b02=True, **config), None, state_file=str(state))
        assert moved.runtime['b02'].source == 'config' and moved.hosts['b02'].max_projects == 10
        assert flags(moved)['b02'] is False and 'b02, added by hand, is in the configuration now' in caplog.text
        assert saved(state)['added'] == [] and saved(state)['disabled'] == ['b02']

    @pytest.mark.parametrize('content, readable', [
        ('{"removed": [[1]], "added": "x", "enabled": [5, ["a"], null], "disabled": "s01", "drain": 3, '
         '"clocks": ["x"]}', True),
        ('[1, 2]', False), ('not json', False), ('', False)])
    def test_odd_files_never_break_the_start(self, tmp_path, content, readable):
        """Whatever a hand edit left in the file, the pool starts from the configuration; a file
        that is not a state at all is kept under another name, not written over."""
        state = tmp_path / 'pool.json'
        state.write_text(content)
        pool = Pool(hosts(s01=True, z01=False), None, state_file=str(state))
        assert flags(pool) == {'s01': True, 'z01': False} and pool.state_error == ''
        kept = tmp_path / ('pool.json' + UNREADABLE_SUFFIX)
        assert kept.exists() is not readable and state.exists() is readable
        pool.set_enabled('z01', True)
        assert saved(state)['enabled'] == ['z01']
        if not readable:
            assert kept.read_text() == content

    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
    def test_file_of_another_user_is_not_written_over(self, tmp_path, caplog):
        """The file edited as root came back unreadable for the portal: its content is kept
        (the portal stopping would otherwise write the state of the configuration over it)."""
        state = tmp_path / 'pool.json'
        state.write_text(json.dumps({'version': STATE_VERSION, 'enabled': ['z01']}))
        state.chmod(0)
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            pool = Pool(hosts(s01=True, z01=False), None, state_file=str(state))
        assert flags(pool) == {'s01': True, 'z01': False}
        assert 'cannot read' in caplog.text and 'is kept as' in caplog.text
        pool.save_state()                                         # what the portal does when it stops
        kept = tmp_path / ('pool.json' + UNREADABLE_SUFFIX)
        kept.chmod(0o600)
        assert json.loads(kept.read_text())['enabled'] == ['z01'] and saved(state)['enabled'] == []


class TestDrain:
    def test_kept_cancelled_and_over(self, tmp_path):
        state = tmp_path / 'pool.json'
        config = dict(s01=True, s02=True)
        session = M.FakeSession()
        session.answers = {'http://s01': up(projects=1, uptime=100000), 'http://s02': up()}
        pool = Pool(hosts(**config), session, state_file=str(state))

        async def go():
            await pool.refresh()
            before = time.time()
            pool.set_drain('s01')
            asked_at = saved(state)['drain']['s01']
            assert before - 1 <= asked_at <= time.time() + 1       # rounded to the millisecond
            assert pool.state_of('s01') == STATE_DRAINING
            pool.set_drain('s01')                                  # again: nothing changes
            assert saved(state)['drain'] == {'s01': asked_at}
            # a new portal: still draining, no project placed there
            again = Pool(hosts(**config), session, state_file=str(state))
            await again.refresh()
            assert again.state_of('s01') == STATE_DRAINING and again.runtime['s01'].drain_at == asked_at
            assert again.pick()[0].name == 's02'
            # the host goes down then comes back: the drain is over, in the file too
            session.answers['http://s01'] = None
            await again.refresh()
            assert again.runtime['s01'].drain is True and saved(state)['drain'] == {'s01': asked_at}
            session.answers['http://s01'] = up()
            await again.refresh()
            assert again.state_of('s01') == STATE_UP and saved(state)['drain'] == {}
            # `enable` cancels a drain
            again.set_drain('s02')
            assert list(saved(state)['drain']) == ['s02']
            again.set_enabled('s02', True)
            assert saved(state)['drain'] == {} and again.runtime['s02'].drain_at == 0.0
        run(go())

    @pytest.mark.parametrize('asked_ago, uptime, kept', [
        (3600, 100, False),        # booted 100 s ago, the drain is one hour old: it went down and came back
        (3600, 7200, True),        # up since before the drain
        (3600, None, True),        # an agent without uptime: nothing known, kept
        (None, 100, True),         # a drain written by hand in the file, without its time
    ])
    def test_host_rebooted_while_the_portal_was_stopped(self, tmp_path, caplog, asked_ago, uptime, kept):
        """A drain read from the state file is over when its host booted after it was asked:
        without the test, the host would be powered off again as soon as it is empty."""
        state = tmp_path / 'pool.json'
        drain = ['s01'] if asked_ago is None else {'s01': time.time() - asked_ago}
        state.write_text(json.dumps({'version': STATE_VERSION, 'drain': drain}))
        session = M.FakeSession()
        session.answers = {'http://s01': up(uptime=uptime)}
        pool = Pool(hosts(s01=True), session, state_file=str(state))
        assert pool.runtime['s01'].drain is True

        async def go():
            with caplog.at_level(logging.INFO, logger='sreweb.portal'):
                await pool.refresh()
            assert pool.runtime['s01'].drain is kept
            assert pool.state_of('s01') == (STATE_DRAINING if kept else STATE_UP)
            assert ('booted since its drain was asked' in caplog.text) is not kept
            assert list(saved(state)['drain']) == (['s01'] if kept else [])
        run(go())

    def test_power_off_sent_then_the_portal_restarts(self, tmp_path):
        """The power off of a host is in the file at once: a portal restarted while the host
        goes down places nothing there, and sees the drain end when the host is gone."""
        state = tmp_path / 'pool.json'
        config = [HostConfig('s01', 'http://s01', TOKEN, 10, power=True), HostConfig('s02', 'http://s02', TOKEN, 10)]
        session = M.FakeSession()
        session.answers = {'http://s01': up(uptime=100000), 'http://s02': up(projects=3)}
        cfg = PoolConfig(spare_projects=0, min_hosts_up=0, active_hours='')
        pool = Pool(config, session, state_file=str(state), wake_timeout=100.0)

        async def go():
            await pool.refresh()
            await PoolManager(pool, cfg, wol=lambda mac, broadcast: None).power_off('s01')
            file = saved(state)
            assert list(file['drain']) == ['s01'] and set(file['clocks']['s01']) == {'power_off_sent', 'next_wake_at'}
            again = Pool(config, session, state_file=str(state), wake_timeout=100.0)
            mgr = PoolManager(again, cfg, wol=lambda mac, broadcast: None)
            await again.refresh()
            rt = again.runtime['s01']
            assert again.state_of('s01') == STATE_DRAINING and rt.power_off_sent is not None
            assert rt.next_wake_at > time.monotonic() + 500         # the hold after a power off
            assert again.pick()[0].name == 's02'                    # the least loaded host is going down
            await mgr.tick()
            assert session.posts == ['http://s01/v1/power/off']     # not sent a second time
            session.answers['http://s01'] = None
            await again.refresh()
            assert again.state_of('s01') == STATE_OFF and rt.drain is False and rt.power_off_sent is None
            assert saved(state)['drain'] == {} and set(saved(state)['clocks']['s01']) == {'next_wake_at'}
        run(go())


class TestClocks:
    def test_round_trip(self, tmp_path):
        state = tmp_path / 'pool.json'
        config = dict(a=True, b=True, c=True, d=True, e=True)
        pool = Pool(hosts(**config), None, state_file=str(state), wake_timeout=100.0, restart_hold=50.0)
        now = time.monotonic()
        pool.runtime['a'].woken_at = now - 10
        pool.runtime['b'].next_wake_at, pool.runtime['b'].wake_failures = now + 300, 2
        pool.runtime['c'].power_off_sent = now - 5
        pool.runtime['d'].restart_sent = now - 3
        pool.runtime['e'].wake_failures, pool.runtime['e'].next_wake_at = 4, now - 1   # a hold that is over
        pool.runtime['e'].idle_since = now - 1000                                     # never kept
        pool.save_state()
        clocks = saved(state)['clocks']
        assert set(clocks) == {'a', 'b', 'c', 'd'} and clocks['b']['wake_failures'] == 2
        assert abs(clocks['a']['woken_at'] - (time.time() - 10)) < 2
        again = Pool(hosts(**config), None, state_file=str(state), wake_timeout=100.0, restart_hold=50.0)
        now = time.monotonic()
        rt = again.runtime
        assert abs(rt['a'].woken_at - (now - 10)) < 2 and again.state_of('a') == STATE_WAKING
        assert abs(rt['b'].next_wake_at - (now + 300)) < 2 and rt['b'].wake_failures == 2
        assert abs(rt['c'].power_off_sent - (now - 5)) < 2
        assert abs(rt['d'].restart_sent - (now - 3)) < 2
        assert (rt['e'].next_wake_at, rt['e'].wake_failures, rt['e'].idle_since) == (0.0, 0, None)

    def test_stale_clocks_are_dropped(self, tmp_path):
        """The portal may have been stopped for long: a wake or a power off older than the wake
        timeout, a restart older than its hold and a hold that is over mean nothing any more;
        a hold absurdly far (the clock was set back) is capped."""
        state = tmp_path / 'pool.json'
        wall = time.time()
        state.write_text(json.dumps({'version': STATE_VERSION, 'clocks': {
            'a': {'woken_at': wall - 200, 'next_wake_at': wall - 1, 'wake_failures': 3,
                  'power_off_sent': wall - 200, 'restart_sent': wall - 60},
            'b': {'woken_at': wall + 500, 'next_wake_at': wall + 1e7, 'wake_failures': 10 ** 9,
                  'power_off_sent': 'x', 'restart_sent': None},
            'c': 'x', 'gone': {'woken_at': wall}}}))
        pool = Pool(hosts(a=True, b=True, c=True), None, state_file=str(state), wake_timeout=100.0, restart_hold=50.0)
        a, b = pool.runtime['a'], pool.runtime['b']
        assert (a.woken_at, a.next_wake_at, a.wake_failures, a.power_off_sent, a.restart_sent) == (None, 0.0, 0, None, None)
        assert b.woken_at is None and b.power_off_sent is None and b.restart_sent is None
        assert abs(b.next_wake_at - (time.monotonic() + MAX_HOLD)) < 2 and b.wake_failures == MAX_WAKE_FAILURES
        assert pool.state_of('a') == STATE_OFF

    def test_a_wake_is_saved_by_the_next_refresh(self, tmp_path):
        state = tmp_path / 'pool.json'
        config = [HostConfig('a', 'http://a', TOKEN, 10, mac='aa:bb:cc:dd:ee:ff')]
        session = M.FakeSession()
        pool = Pool(config, session, state_file=str(state), wake_timeout=100.0)
        mgr = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0, active_hours=''),
                          wol=lambda mac, broadcast: None)

        async def go():
            await pool.refresh()
            assert not state.exists()                               # nothing changed: nothing written
            await mgr.wake('a')
            await pool.refresh()
            assert set(saved(state)['clocks']['a']) == {'woken_at'}
            again = Pool(config, session, state_file=str(state), wake_timeout=100.0)
            assert again.state_of('a') == STATE_WAKING              # "a host is starting", not "no host"
            written = state.stat().st_mtime_ns
            await pool.refresh()
            await pool.refresh()
            assert state.stat().st_mtime_ns == written              # written when something changes only
            session.answers['http://a'] = up()                      # up: the wake is over
            await pool.refresh()
            assert saved(state)['clocks'] == {}
        run(go())


class TestNotSaved:
    def test_a_file_that_cannot_be_written_is_told(self, tmp_path, caplog):
        """The directory of the state file cannot be made (a file is in the way: true for root
        too): said at the start, in the status of the pool, and gone once the file is written."""
        blocker = tmp_path / 'state'
        blocker.write_text('')
        state = blocker / 'pool.json'
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            pool = Pool(hosts(s01=True, z01=False), None, state_file=str(state))
        assert pool.state_error and 'pool state NOT saved' in caplog.text
        mgr = PoolManager(pool, PoolConfig(), wol=lambda mac, broadcast: None)
        info = mgr.status()
        assert info['state_file'] == str(state) and info['state_error'] == pool.state_error
        pool.set_enabled('z01', True)                               # applied all the same
        assert pool.runtime['z01'].enabled is True and pool.state_error
        blocker.unlink()
        caplog.clear()
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            pool.set_enabled('s01', False)
        assert pool.state_error == '' and 'pool state saved again' in caplog.text
        assert saved(state)['enabled'] == ['z01'] and saved(state)['disabled'] == ['s01']
        assert mgr.status()['state_error'] == ''

    def test_no_state_file(self):
        pool = Pool(hosts(s01=True), None)
        pool.set_enabled('s01', False)
        pool.set_drain('s01')
        assert pool.state_info() == {'state_file': '', 'state_error': ''}
