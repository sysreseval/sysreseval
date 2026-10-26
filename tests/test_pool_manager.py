"""The elastic pool of the portal: the host states, the wake / power-off policy (pure plans), the
manager on a pool with fake agents, the Wake-on-LAN packet."""
import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip('aiohttp')
import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from sreweb.config import HostConfig, PoolConfig
from sreweb.identity import Identity, ROLE_INSTRUCTOR
from sreweb.portal.manager import (HostView, PoolManager, magic_packet, poweroff_plan, spare_capacity,
                                   wake_plan, BACKOFF_MIN)
from sreweb.portal.pool import (Pool, HostStatus, PoolError, STATE_OFF, STATE_UP, STATE_WAKING,
                                STATE_OCCUPIED, STATE_DRAINING, STATE_DISABLED, STATE_EXAM,
                                PLACEMENT_LOAD, PLACEMENT_SESSION, PLACEMENT_NAMED)

TOKEN = 't' * 32


def view(name, state, projects=0, max_projects=10, can_wake=True, enabled=True, power=False,
         power_off_allowed=False, next_wake_at=0.0, idle_for=None, drain=False, power_off_pending=False,
         instructors_only=False):
    return HostView(name=name, state=state, projects=projects, max_projects=max_projects, can_wake=can_wake,
                    enabled=enabled, power=power, power_off_allowed=power_off_allowed, next_wake_at=next_wake_at,
                    idle_for=idle_for, drain=drain, power_off_pending=power_off_pending,
                    instructors_only=instructors_only)


class TestWakePlan:
    def test_spare_capacity_deficit(self):
        hosts = [view('a', STATE_UP, projects=8), view('b', STATE_OFF), view('c', STATE_OFF)]
        cfg = PoolConfig(spare_projects=5, min_hosts_up=0)
        assert spare_capacity(hosts) == 2
        assert wake_plan(hosts, cfg, now=1000.0, active=False, last_wake_at=0.0) == ['b']   # one at a time
        hosts[0].projects = 3   # spare 7: enough
        assert wake_plan(hosts, cfg, now=1000.0, active=False, last_wake_at=0.0) == []
        # a host waking counts as capacity to come
        hosts = [view('a', STATE_UP, projects=8), view('b', STATE_WAKING), view('c', STATE_OFF)]
        assert wake_plan(hosts, cfg, now=1000.0, active=False, last_wake_at=0.0) == []
        # one wake per wake_interval
        hosts = [view('a', STATE_UP, projects=8), view('b', STATE_OFF)]
        assert wake_plan(hosts, PoolConfig(spare_projects=5, wake_interval=30), 1000.0, False, 990.0) == []
        assert wake_plan(hosts, PoolConfig(spare_projects=5, wake_interval=30), 1000.0, False, 960.0) == ['b']

    def test_backoff_wakeability_and_disabled(self):
        cfg = PoolConfig(spare_projects=5, min_hosts_up=0)
        hosts = [view('b', STATE_OFF, next_wake_at=1100.0), view('c', STATE_OFF, can_wake=False),
                 view('d', STATE_DISABLED), view('e', STATE_OFF)]
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['e']
        hosts[0].next_wake_at = 999.0
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['b']

    def test_floor_during_active_hours(self):
        cfg = PoolConfig(spare_projects=0, min_hosts_up=1)
        hosts = [view('a', STATE_OFF), view('b', STATE_OFF)]
        assert wake_plan(hosts, cfg, 1000.0, active=True, last_wake_at=0.0) == ['a']
        assert wake_plan(hosts, cfg, 1000.0, active=False, last_wake_at=0.0) == []
        # an occupied host is awake for the floor, but has no spare capacity
        hosts = [view('a', STATE_OCCUPIED), view('b', STATE_OFF)]
        assert wake_plan(hosts, cfg, 1000.0, True, 0.0) == []
        assert wake_plan(hosts, PoolConfig(spare_projects=5, min_hosts_up=1), 1000.0, True, 0.0) == ['b']
        # exam and draining hosts are awake too
        hosts = [view('a', STATE_EXAM), view('b', STATE_DRAINING, projects=1), view('c', STATE_OFF)]
        assert wake_plan(hosts, cfg, 1000.0, True, 0.0) == []

    def test_reserved_hosts(self):
        """A host reserved for instructors is no spare capacity, no floor, and is never woken."""
        cfg = PoolConfig(spare_projects=5, min_hosts_up=0)
        hosts = [view('a', STATE_UP, projects=8), view('r', STATE_UP, instructors_only=True), view('b', STATE_OFF)]
        assert spare_capacity(hosts) == 2                   # r's ten slots do not count
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['b']
        hosts = [view('r', STATE_OFF, instructors_only=True), view('b', STATE_OFF)]
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['b']
        assert wake_plan([view('r', STATE_OFF, instructors_only=True)], cfg, 1000.0, False, 0.0) == []
        assert spare_capacity([view('r', STATE_WAKING, instructors_only=True)]) == 0
        floor = PoolConfig(spare_projects=0, min_hosts_up=1)
        hosts = [view('r', STATE_UP, instructors_only=True), view('b', STATE_OFF)]
        assert wake_plan(hosts, floor, 1000.0, active=True, last_wake_at=0.0) == ['b']   # r is not the floor


class TestPowerOffPlan:
    def test_drained_host_first(self):
        cfg = PoolConfig(idle_host_timeout=0)   # never for idleness
        hosts = [view('a', STATE_DRAINING, projects=0, power=True, power_off_allowed=True, drain=True),
                 view('b', STATE_DRAINING, projects=2, power=True, power_off_allowed=True, drain=True)]
        assert poweroff_plan(hosts, cfg, active=True) == ['a']
        hosts[0].power_off_pending = True   # already sent
        assert poweroff_plan(hosts, cfg, active=True) == []
        hosts[0].power_off_pending, hosts[0].power_off_allowed = False, False   # the agent does not allow it
        assert poweroff_plan(hosts, cfg, active=True) == []

    def test_idle_hosts_above_the_floor(self):
        cfg = PoolConfig(idle_host_timeout=600, spare_projects=5, min_hosts_up=1)
        hosts = [view('a', STATE_UP, power=True, power_off_allowed=True, idle_for=700),
                 view('b', STATE_UP, power=True, power_off_allowed=True, idle_for=100)]
        assert poweroff_plan(hosts, cfg, active=True) == ['a']          # the most idle, b keeps 10 spare
        assert poweroff_plan(hosts, PoolConfig(idle_host_timeout=600, spare_projects=15), True) == []
        assert poweroff_plan([hosts[0]], cfg, active=True) == []        # the floor
        assert poweroff_plan([hosts[0]], PoolConfig(idle_host_timeout=600, spare_projects=0), active=False) == ['a']
        hosts[0].idle_for = 500
        assert poweroff_plan(hosts, cfg, active=True) == []             # not idle long enough
        hosts[0].idle_for, hosts[0].power = 700, False
        assert poweroff_plan(hosts, cfg, active=True) == []             # power = false in the configuration

    def test_reserved_hosts(self):
        """An idle reserved host is powered off whatever the floor and the spare; it never
        counts as the floor keeping a shared host up."""
        cfg = PoolConfig(idle_host_timeout=600, spare_projects=5, min_hosts_up=1)
        a = view('a', STATE_UP, power=True, power_off_allowed=True, idle_for=700)
        r = view('r', STATE_UP, power=True, power_off_allowed=True, idle_for=800, instructors_only=True)
        assert poweroff_plan([a, r], cfg, active=True) == ['r']        # the most idle; a is the floor
        r.idle_for = 100
        assert poweroff_plan([a, r], cfg, active=True) == []           # r not idle enough, a is the floor
        r.idle_for, a.projects = 800, 9
        assert poweroff_plan([a, r], cfg, active=True) == ['r']        # a short shared spare does not hold r
        a.projects, a.idle_for, r.idle_for = 0, 700, 100
        assert poweroff_plan([a, r], cfg, active=False) == []          # r is no spare for the students: a stays
        assert poweroff_plan([a, r], PoolConfig(idle_host_timeout=600, spare_projects=0), active=False) == ['a']
        drained = view('r', STATE_DRAINING, projects=0, power=True, power_off_allowed=True, drain=True,
                       instructors_only=True)
        assert poweroff_plan([drained], cfg, active=True) == ['r']


class TestMagicPacket:
    def test_bytes(self):
        packet = magic_packet('aa:bb:cc:dd:ee:ff')
        assert len(packet) == 102 and packet[:6] == b'\xff' * 6
        assert packet[6:] == bytes.fromhex('aabbccddeeff') * 16


# -- the manager on a pool of fake agents ------------------------------------------------------------

class FakeResponse:
    content_type = 'application/json'

    def __init__(self, status, data):
        self.status, self.data = status, data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):
        return self.data

    async def text(self):
        return json.dumps(self.data)


class FakeSession:
    """``answers[url]``: the status of the agent at that URL, None when the host is down."""

    def __init__(self):
        self.answers = {}
        self.posts = []
        self.post_status, self.post_data = 200, {'ok': True}

    def get(self, url, headers=None, timeout=None):
        base = url.rsplit('/v1/', 1)[0]
        data = self.answers.get(base)
        if data is None:
            raise aiohttp.ClientConnectionError('down')
        return FakeResponse(200, data)

    def post(self, url, headers=None, timeout=None):
        self.posts.append(url)
        return FakeResponse(self.post_status, self.post_data)


def up(projects=0, **over):
    return {'projects': projects, 'managed_projects': projects, 'terminals': 0, 'load1': 0.5, 'exam_mode': False,
            'occupied': False, 'occupied_by': [], 'uptime': 100, 'power_off_allowed': True, 'hostname': 'h',
            'sre_version': '1', **over}


def run(coro):
    return asyncio.run(coro)


class TestStates:
    def test_state_of_and_pick(self):
        hosts = [HostConfig(n, f'http://{n}', TOKEN, 10) for n in 'abcdefg']
        pool = Pool(hosts, session=None, wake_timeout=100.0)
        pool.status['a'] = HostStatus(reachable=True)
        pool.status['b'] = HostStatus(reachable=True, occupied=True, occupied_by=['session:bob'])
        pool.status['c'] = HostStatus(reachable=True, exam_mode=True)
        pool.status['d'] = HostStatus(reachable=True)
        pool.runtime['d'].drain = True
        pool.status['e'] = HostStatus(reachable=True)
        pool.runtime['e'].enabled = False
        now = time.monotonic()
        pool.runtime['f'].woken_at = now
        assert [pool.state_of(n, now=now + 50) for n in 'abcdefg'] == [
            STATE_UP, STATE_OCCUPIED, STATE_EXAM, STATE_DRAINING, STATE_DISABLED, STATE_WAKING, STATE_OFF]
        assert pool.state_of('f', now=now + 100) == STATE_OFF    # wake_timeout over
        assert pool.pick()[0].name == 'a'
        pool.status['a'] = HostStatus(reachable=True, projects=10)
        with pytest.raises(PoolError) as e:
            pool.pick()
        assert e.value.status == 503 and e.value.retry_after == 30 and 'starting' in e.value.message   # f is waking
        pool.runtime['f'].woken_at = None
        with pytest.raises(PoolError) as e:
            pool.pick()
        assert e.value.retry_after == 60 and 'no host' in e.value.message
        rows = {r['name']: r for r in pool.summary(now=now + 50)}
        assert rows['b']['state'] == STATE_OCCUPIED and rows['b']['occupied_by'] == ['session:bob']
        assert rows['d']['drain'] is True and rows['e']['enabled'] is False and 'token' not in rows['a']

    def test_pick_reserved_host(self):
        """A host reserved for instructors: never a student's, an instructor's by the automatic
        rule or by name; a shared host may be named too."""
        hosts = [HostConfig('a', 'http://a', TOKEN, 10), HostConfig('r', 'http://r', TOKEN, 10, instructors_only=True)]
        pool = Pool(hosts, session=None, wake_timeout=100.0)
        pool.status['a'] = HostStatus(reachable=True, projects=5)
        pool.status['r'] = HostStatus(reachable=True, projects=1)
        student, prof = Identity(login='bob'), Identity(login='prof', role=ROLE_INSTRUCTOR)
        assert pool.pick(student)[0].name == 'a' and pool.pick()[0].name == 'a'   # r is emptier, but reserved
        assert pool.pick(prof)[0].name == 'r'                                     # the least loaded usable host
        pool.status['r'].projects = 10
        assert pool.pick(prof)[0].name == 'a'
        with pytest.raises(PoolError) as e:
            pool.pick(prof, host='nope')
        assert e.value.status == 404
        with pytest.raises(PoolError) as e:
            pool.pick(student, host='r')
        assert e.value.status == 403 and 'instructors only' in e.value.message
        with pytest.raises(PoolError) as e:
            pool.pick(prof, host='r')
        assert e.value.status == 503 and 'full' in e.value.message and e.value.retry_after == 60
        pool.status['r'] = HostStatus()
        with pytest.raises(PoolError) as e:
            pool.pick(prof, host='r')
        assert e.value.status == 503 and 'not available' in e.value.message
        pool.status['r'] = HostStatus(reachable=True, projects=2)
        host, reservation = pool.pick(prof, host='r')
        assert host.name == 'r' and pool.status['r'].projects == 3 and reservation in pool._reservations['r']
        assert pool.pick(prof, host='a')[0].name == 'a'
        # a waking reserved host never tells a student to retry
        pool.status['a'] = HostStatus(reachable=True, projects=10)
        pool.status['r'] = HostStatus()
        pool.runtime['r'].woken_at = time.monotonic()
        with pytest.raises(PoolError) as e:
            pool.pick(student)
        assert e.value.retry_after == 60 and 'no host' in e.value.message
        with pytest.raises(PoolError) as e:
            pool.pick(prof)
        assert e.value.retry_after == 30 and 'starting' in e.value.message
        assert {row['name']: row['instructors_only'] for row in pool.summary()} == {'a': False, 'r': True}

    def test_pick_local_session(self):
        """follow_local_sessions: the host occupied by a local login session of the user takes
        their new projects whatever its load; every other rule stands."""
        hosts = [HostConfig('a', 'http://a', TOKEN, 10), HostConfig('b', 'http://b', TOKEN, 10),
                 HostConfig('r', 'http://r', TOKEN, 10, instructors_only=True)]
        pool = Pool(hosts, session=None, wake_timeout=100.0)
        bob, alice = Identity(login='bob'), Identity(login='alice')
        prof = Identity(login='prof', role=ROLE_INSTRUCTOR)

        def reset():
            pool.status['a'] = HostStatus(reachable=True, projects=1, load1=0.5)
            pool.status['b'] = HostStatus(reachable=True, projects=8, load1=4.0, occupied=True,
                                          occupied_by=['session:bob', 'projects:1'])
            pool.status['r'] = HostStatus(reachable=True, projects=0)
            pool.runtime['b'].drain = False
            pool.runtime['b'].enabled = True
        reset()
        host, reservation = pool.pick(bob)
        assert host.name == 'b' and reservation.placement == PLACEMENT_SESSION and pool.status['b'].projects == 9
        host, reservation = pool.pick(alice)
        assert host.name == 'a' and reservation.placement == PLACEMENT_LOAD     # occupied by somebody else
        assert pool.pick()[0].name == 'a'                                       # no identity
        assert pool.pick(bob)[0].name == 'b'                                    # the last slot of b
        host, reservation = pool.pick(bob)
        assert host.name == 'a' and reservation.placement == PLACEMENT_LOAD     # b full: the normal placement
        reset()
        pool.runtime['b'].drain = True
        assert pool.pick(bob)[0].name == 'a'
        reset()
        pool.status['b'].exam_mode = True
        assert pool.pick(bob)[0].name == 'a'
        reset()
        pool.runtime['b'].enabled = False
        assert pool.pick(bob)[0].name == 'a'
        # two hosts with a session of bob: the least loaded of them
        reset()
        pool.status['a'] = HostStatus(reachable=True, projects=3, occupied=True, occupied_by=['session:bob'])
        assert pool.pick(bob)[0].name == 'a'
        # a reserved host: a student's session there changes nothing, an instructor's counts
        reset()
        pool.status['r'] = HostStatus(reachable=True, projects=9, occupied=True,
                                      occupied_by=['session:bob', 'session:prof'])
        assert pool.pick(bob)[0].name == 'b'
        host, reservation = pool.pick(prof)
        assert host.name == 'r' and reservation.placement == PLACEMENT_SESSION
        # a named host wins; the host of one's own session may be named, another's may not
        reset()
        pool.status['r'] = HostStatus(reachable=True, projects=2, occupied=True, occupied_by=['session:prof'])
        host, reservation = pool.pick(prof, host='a')
        assert host.name == 'a' and reservation.placement == PLACEMENT_NAMED
        assert pool.pick(prof, host='r')[0].name == 'r'
        with pytest.raises(PoolError) as e:
            pool.pick(prof, host='b')
        assert e.value.status == 503 and 'not available' in e.value.message
        # the option off: nothing on an occupied host
        strict = Pool(hosts, session=None, follow_local_sessions=False)
        strict.status['a'] = HostStatus(reachable=True, projects=1)
        strict.status['b'] = HostStatus(reachable=True, projects=8, occupied=True, occupied_by=['session:bob'])
        host, reservation = strict.pick(bob)
        assert host.name == 'a' and reservation.placement == PLACEMENT_LOAD
        strict.status['a'].projects = 10
        with pytest.raises(PoolError) as e:
            strict.pick(bob)
        assert e.value.status == 503
        with pytest.raises(PoolError) as e:
            strict.pick(prof, host='b')
        assert e.value.status == 503 and 'not available' in e.value.message


class TestManager:
    def test_wake_command_wol_and_backoff(self, tmp_path):
        wakes = tmp_path / 'wakes'
        hosts = [HostConfig('a', 'http://a', TOKEN, 10, mac='aa:bb:cc:dd:ee:ff',
                            wake_command=f'sh -c "echo wake {{name}} {{mac}} >> {wakes}"'),
                 HostConfig('b', 'http://b', TOKEN, 10, mac='01:02:03:04:05:06'),
                 HostConfig('c', 'http://c', TOKEN, 10, wake_command='false')]
        session = FakeSession()
        pool = Pool(hosts, session, wake_timeout=100.0)
        sent = []
        mgr = PoolManager(pool, PoolConfig(spare_projects=5, min_hosts_up=1, active_hours='', wake_interval=0),
                          wol=lambda mac, broadcast: sent.append((mac, broadcast)))

        async def go():
            await pool.refresh()
            assert all(not st.reachable for st in pool.status.values())
            await mgr.tick()                                  # everything off: a, the first one
            assert wakes.read_text() == 'wake a aa:bb:cc:dd:ee:ff\n'
            assert pool.state_of('a') == STATE_WAKING and pool.state_of('b') == STATE_OFF and sent == []
            assert mgr.status()['waking'] == ['a'] and mgr.status()['spare_projects'] == 10
            await mgr.tick()                                  # a waking: capacity to come, floor met
            assert wakes.read_text().count('\n') == 1
            session.answers['http://a'] = up()                # a is up
            await pool.refresh()
            assert pool.state_of('a') == STATE_UP and pool.runtime['a'].woken_at is None
            assert pool.pick()[0].name == 'a'
            # a goes down for good: the wake expires, backoff, b is woken by Wake-on-LAN instead
            session.answers['http://a'] = None
            await pool.refresh()
            await mgr.tick()
            assert pool.state_of('a') == STATE_WAKING and wakes.read_text().count('\n') == 2
            pool.runtime['a'].woken_at -= 200
            await mgr.tick()
            rt = pool.runtime['a']
            assert pool.state_of('a') == STATE_OFF and rt.wake_failures == 1 and rt.next_wake_at > 0
            assert sent == [('01:02:03:04:05:06', '255.255.255.255')] and pool.state_of('b') == STATE_WAKING
            # the failing wake command: 502, counted as a failure with a backoff
            with pytest.raises(PoolError) as e:
                await mgr.wake('c')
            assert e.value.status == 502 and pool.runtime['c'].wake_failures == 1
            assert pool.state_of('c') == STATE_OFF
            # the backoff doubles up to the cap
            for _ in range(10):
                mgr._wake_failed('c', pool.runtime['c'], 1000.0, 'x')
            assert pool.runtime['c'].next_wake_at - 1000.0 == 1800.0 and BACKOFF_MIN == 60.0
            with pytest.raises(PoolError) as e:
                await mgr.wake('d')
            assert e.value.status == 404
        run(go())

    def test_power_off_idle_drain_and_recovery(self):
        hosts = [HostConfig('a', 'http://a', TOKEN, 10, power=True), HostConfig('b', 'http://b', TOKEN, 10, power=True)]
        session = FakeSession()
        session.answers = {'http://a': up(), 'http://b': up()}
        pool = Pool(hosts, session, wake_timeout=100.0)
        mgr = PoolManager(pool, PoolConfig(spare_projects=5, min_hosts_up=1, active_hours='', idle_host_timeout=50),
                          wol=lambda mac, broadcast: None)

        async def go():
            await pool.refresh()
            await mgr.tick()
            assert session.posts == []                        # idle for 0 s
            pool.runtime['a'].idle_since -= 100
            pool.runtime['b'].idle_since -= 60
            await mgr.tick()                                  # the most idle one, the floor keeps the other
            assert session.posts == ['http://a/v1/power/off']
            assert pool.state_of('a') == STATE_DRAINING and pool.runtime['a'].power_off_sent is not None
            await mgr.tick()
            assert len(session.posts) == 1                    # not repeated while it goes down
            host, reservation = pool.pick()
            assert host.name == 'b'
            pool.release(reservation)
            # not woken again by the policy for a while
            assert pool.runtime['a'].next_wake_at > time.monotonic() + 500
            # a is gone (the drain is over), then back after the night: usable again
            session.answers['http://a'] = None
            await pool.refresh()
            assert pool.state_of('a') == STATE_OFF and pool.runtime['a'].drain is False
            session.answers['http://a'] = up()
            await pool.refresh()
            assert pool.state_of('a') == STATE_UP and pool.runtime['a'].next_wake_at == 0.0
            # a drain by hand: no new project, powered off as soon as it is empty
            session.answers['http://b'] = up(projects=1)
            await pool.refresh()
            pool.runtime['b'].drain = True
            assert pool.state_of('b') == STATE_DRAINING
            await mgr.tick()
            assert len(session.posts) == 1                    # b still has a project
            session.answers['http://b'] = up()
            await pool.refresh()
            pool.runtime['b'].idle_since = None
            await mgr.tick()
            assert session.posts[-1] == 'http://b/v1/power/off'
            # the agent refuses (occupied meanwhile): a warning, no state change
            session.post_status, session.post_data = 409, {'error': 'occupied'}
            with pytest.raises(PoolError) as e:
                await mgr.power_off('a')
            assert e.value.status == 409 and 'occupied' in e.value.message
            assert pool.state_of('a') == STATE_UP
            session.answers['http://a'] = None
            await pool.refresh()
            with pytest.raises(PoolError) as e:
                await mgr.power_off('a')
            assert e.value.status == 409 and 'not reachable' in e.value.message
        run(go())

    def test_active_hours_clock(self):
        import datetime
        pool = Pool([], session=None)
        mgr = PoolManager(pool, PoolConfig(active_hours='07:00-20:00'),
                          clock=lambda: datetime.datetime(2026, 10, 22, 8, 30))
        assert mgr.active() is True
        mgr.clock = lambda: datetime.datetime(2026, 10, 22, 22, 0)
        assert mgr.active() is False and mgr.status()['active_now'] is False
