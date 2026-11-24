"""The elastic pool of the portal: the host states, the wake / power-off policy (pure plans), the
manager on a pool with fake agents, the Wake-on-LAN packet."""
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip('aiohttp')
import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from sreweb.config import HostConfig, PoolConfig, check_priority
from sreweb.identity import Identity, ROLE_INSTRUCTOR
from sreweb.portal.manager import (HostView, PoolManager, free_slots, magic_packet, poweroff_plan, preload_plan,
                                   spare_capacity, wake_plan, BACKOFF_MIN, PRELOAD_REFUSED_HOLD)
from sreweb.portal.pool import (Pool, HostStatus, PoolError, STATE_OFF, STATE_UP, STATE_WAKING,
                                STATE_OCCUPIED, STATE_DRAINING, STATE_DISABLED, STATE_EXAM,
                                PLACEMENT_LOAD, PLACEMENT_SESSION, PLACEMENT_NAMED)

TOKEN = 't' * 32


def prio(value):
    """A priority as the configuration writes it: ``"group:order"``, or one integer, that
    order in group 0."""
    return check_priority(value, 'priority')


def view(name, state, projects=0, max_projects=10, can_wake=True, enabled=True, power=False,
         power_off_allowed=False, next_wake_at=0.0, idle_for=None, drain=False, power_off_pending=False,
         instructors_only=False, restart_pending=False, **more):
    """*more*: the preload fields (``preload``, ``preload_since``, ``preload_granted``,
    ``preload_hold``, ``exam_projects``), ``held``, ``priority`` (as ``prio`` takes it),
    ``memory_room``."""
    if 'priority' in more:
        more['priority'] = prio(more['priority'])
    return HostView(name=name, state=state, projects=projects, max_projects=max_projects, can_wake=can_wake,
                    enabled=enabled, power=power, power_off_allowed=power_off_allowed, next_wake_at=next_wake_at,
                    idle_for=idle_for, drain=drain, power_off_pending=power_off_pending,
                    instructors_only=instructors_only, restart_pending=restart_pending, **more)


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

    def test_memory_room_in_the_spare_capacity(self):
        """A host up gives no more free slots than its memory holds (``memory_room``), so a host
        short of memory makes the policy wake the next one; None = the memory is not checked."""
        assert free_slots(view('a', STATE_UP, projects=2)) == 8
        assert free_slots(view('a', STATE_UP, projects=2, memory_room=3)) == 3
        assert free_slots(view('a', STATE_UP, projects=8, memory_room=5)) == 2      # max_projects first
        assert free_slots(view('a', STATE_UP, projects=2, memory_room=0)) == 0
        cfg = PoolConfig(spare_projects=5, min_hosts_up=0)
        hosts = [view('a', STATE_UP, projects=2, memory_room=9), view('b', STATE_OFF)]
        assert spare_capacity(hosts) == 8 and wake_plan(hosts, cfg, 1000.0, False, 0.0) == []
        hosts[0].memory_room = 4                       # 8 slots by the count, 4 by the memory: b is woken
        assert spare_capacity(hosts) == 4 and wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['b']
        # an idle host is not powered off while the others' memory leaves less than the spare
        hosts = [view('a', STATE_UP, projects=3, memory_room=1), view('b', STATE_UP, power=True,
                                                                       power_off_allowed=True, idle_for=999.0)]
        assert poweroff_plan(hosts, PoolConfig(spare_projects=5, min_hosts_up=0, idle_host_timeout=60), False) == []
        hosts[0].memory_room = None
        assert poweroff_plan(hosts, PoolConfig(spare_projects=5, min_hosts_up=0, idle_host_timeout=60), False) == ['b']

    def test_backoff_wakeability_and_disabled(self):
        cfg = PoolConfig(spare_projects=5, min_hosts_up=0)
        hosts = [view('b', STATE_OFF, next_wake_at=1100.0), view('c', STATE_OFF, can_wake=False),
                 view('d', STATE_DISABLED), view('e', STATE_OFF)]
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['e']
        hosts[0].next_wake_at = 999.0
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['b']
        hosts[0].restart_pending = True      # its agent is restarting: not a host to wake
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['e']

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


    def test_lowest_priority_first(self):
        """The sleeping host with the lowest priority is woken first; equal priorities keep the
        order of the configuration, and the priority changes nothing to who may be woken."""
        cfg = PoolConfig(spare_projects=5, min_hosts_up=0)
        hosts = [view('a', STATE_OFF), view('b', STATE_OFF, priority=-2), view('c', STATE_OFF, priority=3),
                 view('d', STATE_OFF, priority=-2)]
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['b']       # b and d are equal: b comes first
        hosts[1].state = STATE_WAKING                                   # 10 slots to come: enough
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == []
        hosts[1].state = STATE_UP
        hosts[1].projects = 8
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['d']
        hosts[3].next_wake_at = 2000.0                                  # d is held after a failed wake
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['a']       # 0, the default, before 3
        hosts[0].enabled = False
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['c']
        # the floor of the active hours too
        hosts = [view('a', STATE_OFF, priority=1), view('b', STATE_OFF)]
        assert wake_plan(hosts, PoolConfig(spare_projects=0, min_hosts_up=1), 1000.0, True, 0.0) == ['b']
        # a pool without priorities: the order of the configuration, as before
        assert wake_plan([view('b', STATE_OFF), view('a', STATE_OFF)], cfg, 1000.0, False, 0.0) == ['b']
        # the group before the order
        hosts = [view('a', STATE_OFF, priority='1:-9'), view('b', STATE_OFF, priority='0:5'),
                 view('c', STATE_OFF, priority='-1:7')]
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['c']
        hosts[2].can_wake = False
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['b']
        hosts[1].state = STATE_UP
        hosts[1].projects = 9                                           # one slot left: the next group
        assert wake_plan(hosts, cfg, 1000.0, False, 0.0) == ['a']


class TestPowerOffPlan:
    def test_highest_priority_first(self):
        """Among the hosts idle long enough the one with the highest priority goes first, then
        the most idle: the hosts left awake are those the placement prefers."""
        cfg = PoolConfig(idle_host_timeout=600, spare_projects=5, min_hosts_up=1)

        def idle(name, seconds, **more):
            return view(name, STATE_UP, power=True, power_off_allowed=True, idle_for=seconds, **more)
        hosts = [idle('a', 900), idle('b', 700, priority=5), idle('c', 800, priority=5), idle('d', 5000, priority=-1)]
        assert poweroff_plan(hosts, cfg, active=True) == ['c']          # 5 before 0 and -1; c idle longer than b
        hosts[2].idle_for = 100                                         # c not idle long enough: the next one
        assert poweroff_plan(hosts, cfg, active=True) == ['b']
        hosts[1].idle_for = 100
        assert poweroff_plan(hosts, cfg, active=True) == ['a']          # then the default, d (-1) last
        hosts[0].idle_for = 100
        assert poweroff_plan(hosts, cfg, active=True) == ['d']
        # a drained host still goes first, whatever its priority
        hosts = [idle('a', 900, priority=5), view('z', STATE_DRAINING, power=True, power_off_allowed=True, drain=True,
                                                  priority=-5)]
        assert poweroff_plan(hosts, cfg, active=True) == ['z']
        # a pool without priorities: the most idle, as before
        assert poweroff_plan([idle('a', 700), idle('b', 900)], cfg, active=True) == ['b']
        # the group before the order: the highest group goes first, whatever the orders and the idle times
        hosts = [idle('a', 5000, priority='0:9'), idle('b', 700, priority='2:-5'), idle('c', 900, priority='1:50'),
                 idle('d', 800, priority='2:-4')]
        assert poweroff_plan(hosts, cfg, active=True) == ['d']          # group 2: d (-4) before b (-5)
        hosts[3].idle_for = 100
        assert poweroff_plan(hosts, cfg, active=True) == ['b']
        hosts[1].idle_for = 100
        assert poweroff_plan(hosts, cfg, active=True) == ['c']          # then group 1, group 0 last
        hosts[2].idle_for = 100
        assert poweroff_plan(hosts, cfg, active=True) == ['a']

    def test_drained_host_first(self):
        cfg = PoolConfig(idle_host_timeout=0)   # never for idleness
        hosts = [view('a', STATE_DRAINING, projects=0, power=True, power_off_allowed=True, drain=True),
                 view('b', STATE_DRAINING, projects=2, power=True, power_off_allowed=True, drain=True)]
        assert poweroff_plan(hosts, cfg, active=True) == ['a']
        hosts[0].power_off_pending = True   # already sent
        assert poweroff_plan(hosts, cfg, active=True) == []
        hosts[0].power_off_pending, hosts[0].power_off_allowed = False, False   # the agent does not allow it
        assert poweroff_plan(hosts, cfg, active=True) == []
        hosts[0].power_off_allowed, hosts[0].restart_pending = True, True       # its agent is restarting
        assert poweroff_plan(hosts, cfg, active=True) == []

    def test_drained_disabled_host(self):
        """A disabled host is never powered off, drained or not, unless its agent says a drain
        powers it off all the same (``allow_power_off_when_disabled`` of agent.toml): it is then
        judged on the state it would have were it enabled."""
        cfg = PoolConfig(idle_host_timeout=0)

        def disabled(name='a', **more):
            return view(name, STATE_DISABLED, enabled=False,
                        **{'power': True, 'power_off_allowed': True, 'drain': True, 'live_state': STATE_DRAINING, **more})
        assert poweroff_plan([disabled()], cfg, active=True) == []                  # the agent does not say so
        assert poweroff_plan([disabled(power_off_when_disabled=True)], cfg, active=True) == ['a']
        for over in ({'live_state': STATE_OCCUPIED}, {'live_state': STATE_EXAM}, {'live_state': STATE_OFF},
                     {'live_state': STATE_WAKING}, {'live_state': ''}, {'drain': False, 'live_state': STATE_UP},
                     {'projects': 1}, {'power': False}, {'power_off_allowed': False}, {'power_off_pending': True},
                     {'restart_pending': True}):
            assert poweroff_plan([disabled(power_off_when_disabled=True, **over)], cfg, active=True) == [], over
        # one host per poll, in the order of the pool, enabled or not
        both = [disabled(power_off_when_disabled=True),
                view('b', STATE_DRAINING, power=True, power_off_allowed=True, drain=True)]
        assert poweroff_plan(both, cfg, active=True) == ['a']
        assert poweroff_plan(both[::-1], cfg, active=True) == ['b']
        # never for idleness: only a drain powers a disabled host off
        cfg = PoolConfig(idle_host_timeout=600, spare_projects=0, min_hosts_up=0)
        idle = disabled(power_off_when_disabled=True, drain=False, live_state=STATE_UP, idle_for=5000)
        assert poweroff_plan([idle], cfg, active=False) == []
        assert poweroff_plan([idle, view('b', STATE_UP, power=True, power_off_allowed=True, idle_for=700)],
                             cfg, active=False) == ['b']

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

    def test_a_host_waiting_for_its_preload_is_not_idle(self):
        """Powered off for idleness while it waits for its turn to pull the Docker images (or
        pulls them), a host would never have them; a drain does not wait."""
        cfg = PoolConfig(idle_host_timeout=600, spare_projects=0, min_hosts_up=0)
        a = view('a', STATE_UP, power=True, power_off_allowed=True, idle_for=700, preload='pending')
        assert poweroff_plan([a], cfg, active=False) == []
        a.preload = 'running'
        assert poweroff_plan([a], cfg, active=False) == []
        a.preload, a.preload_granted = 'idle', True        # its turn was just given
        assert poweroff_plan([a], cfg, active=False) == []
        a.preload_granted = False
        for over in ('idle', 'done', 'failed', ''):
            a.preload = over
            assert poweroff_plan([a], cfg, active=False) == ['a'], over
        a.preload = 'pending'                               # the portal gives no turn: nothing to wait for
        assert poweroff_plan([a], PoolConfig(idle_host_timeout=600, spare_projects=0, min_hosts_up=0, max_preloads=0),
                             active=False) == ['a']
        d = view('d', STATE_DRAINING, power=True, power_off_allowed=True, drain=True, preload='running')
        assert poweroff_plan([d], cfg, active=False) == ['d']


class TestPreloadPlan:
    """The preloads of the Docker images: a few hosts at a time (``max_preloads``)."""

    def test_cap_and_order(self):
        cfg = PoolConfig(max_preloads=2)
        hosts = [view('a', STATE_UP, preload='pending', preload_since=10),
                 view('b', STATE_UP, preload='pending', preload_since=50),
                 view('c', STATE_UP, preload='pending', preload_since=50),
                 view('d', STATE_UP, preload='idle'), view('e', STATE_UP, preload='done'),
                 view('f', STATE_UP, preload='failed'), view('g', STATE_OFF), view('h', STATE_UP)]
        assert preload_plan(hosts, cfg) == ['b', 'c']      # the longest wait first, the name breaks a tie
        hosts[1].preload = 'running'
        assert preload_plan(hosts, cfg) == ['c']
        hosts[2].preload_granted = True                    # its turn was given, its status still says pending
        assert preload_plan(hosts, cfg) == []
        assert preload_plan(hosts, PoolConfig(max_preloads=3)) == ['a']
        assert preload_plan(hosts, PoolConfig(max_preloads=10)) == ['a']   # nobody else asks
        assert preload_plan(hosts, PoolConfig(max_preloads=1)) == []       # more running than the cap allows now
        assert preload_plan(hosts, PoolConfig(max_preloads=0)) == []       # the portal gives no turn

    def test_hosts_left_out(self):
        cfg = PoolConfig(max_preloads=5)
        for over in ({'exam_projects': 1}, {'drain': True}, {'restart_pending': True}, {'power_off_pending': True},
                     {'preload_hold': True}, {'preload_granted': True}):
            hosts = [view('a', STATE_UP, preload='pending', **over), view('b', STATE_UP, preload='pending')]
            assert preload_plan(hosts, cfg) == ['b'], over

    def test_disabled_occupied_and_exam_mode_hosts_are_served(self):
        """The local users of a host start labs too: only the agent says whether it wants the
        images (``exam.json`` of the Qt GUI is there long before its exam)."""
        hosts = [view('a', STATE_DISABLED, enabled=False, preload='pending'), view('b', STATE_OCCUPIED, preload='pending'),
                 view('c', STATE_EXAM, preload='pending'), view('d', STATE_UP, instructors_only=True, preload='pending'),
                 view('e', STATE_UP, projects=9, preload='pending')]
        assert preload_plan(hosts, PoolConfig(max_preloads=5)) == ['a', 'b', 'c', 'd', 'e']


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
        self.labs = {}          # base URL -> the answer of GET /v1/labs: a list, (status, data), None = down
        self.gets = []
        self.posts = []
        self.post_status, self.post_data = 200, {'ok': True}
        self.post_answers = {}  # URL -> (status, data) of a POST there, None = no answer; else the two above

    def get(self, url, headers=None, timeout=None, params=None):
        self.gets.append(url)
        base, _, path = url.rpartition('/v1/')
        if path == 'labs' and base in self.labs:
            answer = self.labs[base]
            if answer is None:
                raise aiohttp.ClientConnectionError('down')
            status, data = answer if isinstance(answer, tuple) else (200, answer)
            return FakeResponse(status, data)
        data = self.answers.get(base)
        if data is None:
            raise aiohttp.ClientConnectionError('down')
        return FakeResponse(200, data)

    def post(self, url, headers=None, timeout=None):
        self.posts.append(url)
        if url in self.post_answers:
            if self.post_answers[url] is None:
                raise aiohttp.ClientConnectionError('down')
            return FakeResponse(*self.post_answers[url])
        return FakeResponse(self.post_status, self.post_data)


def up(projects=0, **over):
    return {'projects': projects, 'managed_projects': projects, 'terminals': 0, 'load1': 0.5, 'exam_mode': False,
            'occupied': False, 'occupied_by': [], 'uptime': 100, 'power_off_allowed': True, 'hostname': 'h',
            'sre_version': '1', 'agent_uptime': 500, 'restart_allowed': True, 'restarting': False, **over}


def preloading(state, since=0, **over):
    """The ``preload`` object of the status of an agent that knows the preload of the images
    (``up()`` alone is an older agent): ``up(preload=preloading('pending', 30))``."""
    return {'state': state, 'since': since, 'total': 0, 'current': 0, 'image': '', 'error': '', **over}


def asking(asked=False, allowed=True, default=True, since=None):
    """The ``local_drain`` object of the status of an agent that knows the drains asked on the
    host itself (``up()`` alone is an older agent): ``up(local_drain=asking(True))``."""
    return {'asked': asked, 'since': (ASKED if asked else None) if since is None else since,
            'allowed': allowed, 'default': default}


ASKED = 1795104130.5


def run(coro):
    return asyncio.run(coro)


class TestLocalDrain:
    """The drain a host asks for itself (`sre set-drain` there), told by the status of its agent."""

    @staticmethod
    def fields(st) -> tuple:
        return st.local_drain, st.local_drain_since, st.local_drain_allowed, st.local_drain_default

    def test_status_is_coerced(self):
        from sreweb.portal.pool import status_from_json
        assert self.fields(status_from_json(up(local_drain=asking(True, default=False)))) == (True, ASKED, True, False)
        assert self.fields(status_from_json(up(local_drain=asking()))) == (False, None, True, True)
        # an agent older than the local drains: nothing asked, nothing known
        assert self.fields(status_from_json(up())) == (False, None, None, None)
        for odd in ('yes', [], 3, None):
            assert self.fields(status_from_json(up(local_drain=odd))) == (False, None, None, None), odd
        # never a drain where the agent forbids them, nor from anything but true
        assert self.fields(status_from_json(up(local_drain=asking(True, allowed=False)))) == (False, None, False, True)
        odd = status_from_json(up(local_drain={'asked': 'yes', 'since': 'now', 'allowed': True, 'default': 'no'}))
        assert self.fields(odd) == (False, None, True, False)
        odd = status_from_json(up(local_drain={'asked': True, 'since': 'now', 'allowed': 1}))
        assert self.fields(odd) == (False, None, False, False)
        assert self.fields(HostStatus()) == (False, None, None, None)      # unreachable

    def test_state_and_placement(self):
        hosts = [HostConfig(n, f'http://{n}', TOKEN, 10) for n in 'abcd']
        pool = Pool(hosts, session=None)
        pool.status['a'] = HostStatus(reachable=True, local_drain=True, local_drain_allowed=True)
        pool.status['b'] = HostStatus(reachable=True, occupied=True, occupied_by=['session:bob'],
                                      local_drain=True, local_drain_allowed=True)
        pool.status['c'] = HostStatus(reachable=True, projects=5, local_drain_allowed=True)
        pool.status['d'] = HostStatus(local_drain=True)             # not reachable: its last word is not a drain
        assert [pool.state_of(n) for n in 'abcd'] == [STATE_DRAINING, STATE_OCCUPIED, STATE_UP, STATE_OFF]
        assert [pool.draining(n) for n in 'abcd'] == [True, True, False, False]
        assert pool.runtime['a'].drain is False                     # the drain of the portal is another one
        assert pool.pick()[0].name == 'c'                           # not the empty host that drains
        host, reservation = pool.pick(Identity(login='bob'))        # nor the workstation bob is leaving
        assert host.name == 'c' and reservation.placement == PLACEMENT_LOAD
        rows = {r['name']: r for r in pool.summary()}
        assert rows['a']['drain'] is True and rows['a']['local_drain'] is True and rows['a']['state'] == STATE_DRAINING
        assert rows['b']['drain'] is True and rows['b']['state'] == STATE_OCCUPIED
        assert rows['c']['drain'] is False and rows['c']['local_drain'] is False
        assert rows['c']['local_drain_allowed'] is True and rows['d']['local_drain_allowed'] is None
        # both drains at once: still one drain
        pool.runtime['a'].drain = True
        assert pool.state_of('a') == STATE_DRAINING and pool.draining('a')

    def test_powered_off_when_empty_and_cancelled(self, caplog):
        hosts = [HostConfig('a', 'http://a', TOKEN, 10, power=True), HostConfig('b', 'http://b', TOKEN, 10, power=True)]
        session = FakeSession()
        session.answers = {'http://a': up(projects=1, local_drain=asking(True)), 'http://b': up(local_drain=asking())}
        pool = Pool(hosts, session, wake_timeout=100.0)
        mgr = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0, active_hours='', idle_host_timeout=0),
                          wol=lambda mac, broadcast: None)
        cancel = 'http://a/v1/local-drain/cancel'

        async def go():
            with caplog.at_level(logging.INFO, logger='sreweb.portal'):
                await pool.refresh()
            assert 'host a asked for its own drain' in caplog.text
            assert pool.state_of('a') == STATE_DRAINING and pool.state_of('b') == STATE_UP
            assert pool.status['a'].local_drain_since == ASKED
            await mgr.tick()
            assert session.posts == []                                  # a project still runs there
            # the instructor cancels it (Enable): on the agent, shown at once
            session.post_answers[cancel] = (200, {'ok': True, 'local_drain': asking()})
            assert await mgr.cancel_local_drain('a') is True
            assert session.posts == [cancel] and pool.state_of('a') == STATE_UP
            # a status asked before the cancel and answered after it does not bring the drain back
            pool.runtime['a'].local_drain_told = time.monotonic() + 60
            session.answers['http://a'] = up(local_drain=asking(True))  # empty now: it would be powered off
            await pool.refresh()
            assert pool.state_of('a') == STATE_UP and pool.status['a'].local_drain is False
            await mgr.tick()
            assert session.posts == [cancel]
            # a status asked after the answer tells
            pool.runtime['a'].local_drain_told = time.monotonic() - 1
            session.answers['http://a'] = up(local_drain=asking())
            await pool.refresh()
            assert pool.runtime['a'].local_drain_told is None and pool.runtime['a'].local_drain_view is None
            assert pool.state_of('a') == STATE_UP
            assert await mgr.cancel_local_drain('a') is False           # nothing asked: nothing sent
            assert await mgr.cancel_local_drain('b') is False
            assert session.posts == [cancel]
            # asked again on an empty host: powered off, as a drain of the portal
            session.answers['http://a'] = up(local_drain=asking(True))
            caplog.clear()
            with caplog.at_level(logging.INFO, logger='sreweb.portal'):
                await pool.refresh()
                await mgr.tick()
            assert session.posts[-1] == 'http://a/v1/power/off' and 'powering off host a (draining)' in caplog.text
            assert pool.runtime['a'].power_off_sent is not None
            await mgr.tick()
            assert session.posts.count('http://a/v1/power/off') == 1    # not repeated while it goes down
            # gone, then back after its boot: nothing is asked any more
            session.answers['http://a'] = None
            await pool.refresh()
            assert pool.runtime['a'].drain is False and not pool.draining('a')
            session.answers['http://a'] = up(local_drain=asking())
            await pool.refresh()
            assert pool.state_of('a') == STATE_UP
            # the agent does not answer the cancel: an error, the drain stays
            session.answers['http://a'] = up(projects=1, local_drain=asking(True))
            await pool.refresh()
            session.post_answers[cancel] = None
            with pytest.raises(PoolError) as e:
                await mgr.cancel_local_drain('a')
            assert e.value.status == 502 and pool.state_of('a') == STATE_DRAINING
            with pytest.raises(PoolError) as e:
                await mgr.cancel_local_drain('nope')
            assert e.value.status == 404
        run(go())

    def test_allowed_and_forbidden_by_the_portal(self):
        hosts = [HostConfig(n, f'http://{n}', TOKEN, 10) for n in 'abc']
        session = FakeSession()
        session.answers = {'http://a': up(local_drain=asking(True)), 'http://b': up(), 'http://c': None}
        pool = Pool(hosts, session)
        mgr = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0, active_hours=''),
                          wol=lambda mac, broadcast: None)
        allow, forbid = 'http://a/v1/local-drain/allow', 'http://a/v1/local-drain/forbid'

        async def go():
            await pool.refresh()
            assert pool.state_of('a') == STATE_DRAINING
            # forbidding also cancels the drain the host asked for
            session.post_answers[forbid] = (200, {'ok': True, 'local_drain': asking(allowed=False)})
            await mgr.set_local_drain_allowed('a', False)
            st = pool.status['a']
            assert (st.local_drain, st.local_drain_allowed, st.local_drain_default) == (False, False, True)
            assert pool.state_of('a') == STATE_UP and session.posts == [forbid]
            session.post_answers[allow] = (200, {'ok': True, 'local_drain': asking()})
            await mgr.set_local_drain_allowed('a', True)
            assert pool.status['a'].local_drain_allowed is True and session.posts == [forbid, allow]
            # an agent older than the local drains, a host that is down, an unknown one
            for name, status, text in (('b', 409, 'older version'), ('c', 409, 'not reachable'), ('nope', 404, 'unknown')):
                with pytest.raises(PoolError) as e:
                    await mgr.set_local_drain_allowed(name, True)
                assert e.value.status == status and text in e.value.message, name
            # the agent does not answer, or refuses: nothing changes
            session.post_answers[forbid] = None
            with pytest.raises(PoolError) as e:
                await mgr.set_local_drain_allowed('a', False)
            assert e.value.status == 502 and pool.status['a'].local_drain_allowed is True
            session.post_answers[forbid] = (500, {'error': 'internal error'})
            with pytest.raises(PoolError) as e:
                await mgr.set_local_drain_allowed('a', False)
            assert e.value.status == 500 and 'refused' in e.value.message
            assert pool.status['a'].local_drain_allowed is True and len(session.posts) == 2 + 2
        run(go())

    def test_disabled_host(self, caplog):
        """A disabled host that drains (the drain it asked for, or the portal's) is powered off
        only when its agent says a drain powers it off all the same
        (``allow_power_off_when_disabled``), and then as an enabled one: once it is empty and
        nobody is at its keyboard.  It is never powered off for idleness, nor woken again."""
        hosts = [HostConfig(n, f'http://{n}', TOKEN, 10, mac='aa:bb:cc:dd:ee:0' + str(i), power=True, enabled=False)
                 for i, n in enumerate('abcd')]
        session = FakeSession()
        says = {'power_off_when_disabled_allowed': True}
        session.answers = {'http://a': up(local_drain=asking(True)),                        # asks; its agent does not say so
                           'http://b': up(projects=1, local_drain=asking(True), **says),    # asks, a project left
                           'http://c': up(occupied=True, occupied_by=['session:bob'], **says),  # drained here, bob at the keyboard
                           'http://d': up(**says)}                                          # no drain
        pool = Pool(hosts, session, wake_timeout=100.0)
        woken = []
        mgr = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0, active_hours='', idle_host_timeout=50),
                          wol=lambda mac, broadcast: woken.append(mac))
        off = 'http://{}/v1/power/off'.format

        async def go():
            await pool.refresh()
            pool.set_drain('c')
            assert [pool.state_of(n) for n in 'abcd'] == [STATE_DISABLED] * 4
            assert [pool.live_state(n) for n in 'abcd'] == [STATE_DRAINING, STATE_DRAINING, STATE_OCCUPIED, STATE_UP]
            assert [pool.draining(n) for n in 'abcd'] == [True, True, True, False]
            views = {v.name: v for v in mgr.views()}
            assert [views[n].power_off_when_disabled for n in 'abcd'] == [False, True, True, True]
            assert [views[n].live_state for n in 'abcd'] == [STATE_DRAINING, STATE_DRAINING, STATE_OCCUPIED, STATE_UP]
            await mgr.tick()
            for name in 'abcd':
                pool.runtime[name].idle_since = time.monotonic() - 5000     # idle for long, where there is no project
            await mgr.tick()
            assert session.posts == []
            # the project of b is closed, bob logs out of c: one host per poll, in the order of the pool
            session.answers['http://b'] = up(local_drain=asking(True), **says)
            session.answers['http://c'] = up(**says)
            await pool.refresh()
            with caplog.at_level(logging.INFO, logger='sreweb.portal'):
                await mgr.tick()
            assert session.posts == [off('b')] and 'powering off host b (draining)' in caplog.text
            await mgr.tick()
            assert session.posts == [off('b'), off('c')]
            await mgr.tick()
            assert len(session.posts) == 2      # not sent again; a (no setting) and d (no drain) stay on
            rows = {r['name']: r for r in pool.summary()}
            assert [rows[n]['state'] for n in 'abcd'] == [STATE_DISABLED] * 4
            assert [rows[n]['power_off_when_disabled_allowed'] for n in 'abcd'] == [False, True, True, True]
            assert [rows[n]['power_off_sent'] for n in 'abcd'] == [False, True, True, False]
            # b and c are gone: their drain is over, they stay disabled and are not woken again
            session.answers['http://b'] = session.answers['http://c'] = None
            await pool.refresh()
            assert [pool.runtime[n].drain for n in 'bc'] == [False, False]
            assert [pool.runtime[n].power_off_sent for n in 'bc'] == [None, None]
            pool.runtime['b'].next_wake_at = pool.runtime['c'].next_wake_at = 0.0
            await mgr.tick()
            assert woken == [] and len(session.posts) == 2
            assert [pool.state_of(n) for n in 'abcd'] == [STATE_DISABLED] * 4
        run(go())


class TestStatusCoercion:
    def test_status_json_is_coerced(self):
        """A broken or hostile agent cannot plant a string where pick() sorts by a number, nor
        stay reachable with a body that is not an object (security review, seventh Low finding)."""
        from sreweb.portal.pool import status_from_json, MAX_STATUS_TEXT
        st = status_from_json(up(projects=3, load1=1.5, occupied_by=['session:bob']), extra_projects=2)
        assert (st.reachable, st.projects, st.managed_projects, st.load1, st.occupied_by, st.uptime, st.agent_uptime,
                st.hostname, st.sre_version, st.power_off_allowed, st.restart_allowed, st.error) == \
            (True, 5, 3, 1.5, ['session:bob'], 100, 500, 'h', '1', True, True, '')
        odd = status_from_json({'projects': '3', 'managed_projects': -2, 'terminals': 2.9, 'load1': 'high',
                                'exam_mode': 1, 'occupied': 'yes', 'occupied_by': 'bob', 'uptime': 'x',
                                'power_off_allowed': None, 'agent_uptime': float('nan'), 'restart_allowed': True,
                                'restarting': 0, 'hostname': 5, 'sre_version': ['1']})
        assert odd.reachable and odd.error == ''
        assert (odd.projects, odd.managed_projects, odd.terminals, odd.load1, odd.exam_mode, odd.occupied,
                odd.occupied_by, odd.uptime, odd.power_off_allowed, odd.agent_uptime, odd.restart_allowed,
                odd.restarting, odd.hostname, odd.sre_version) == \
            (0, 0, 2, None, False, False, [], None, False, None, True, False, '', '')
        assert status_from_json({'load1': float('inf')}).load1 is None
        assert status_from_json({'load1': True}).load1 is None and status_from_json({'load1': 2}).load1 == 2.0
        # a drain powers the host off while it is disabled: only when its agent says true (an
        # older agent says nothing, an unreachable host neither)
        assert st.power_off_when_disabled_allowed is False and HostStatus().power_off_when_disabled_allowed is False
        assert status_from_json(up(power_off_when_disabled_allowed=True)).power_off_when_disabled_allowed is True
        for odd_value in ('true', 1, [True], None, False):
            assert status_from_json(
                up(power_off_when_disabled_allowed=odd_value)).power_off_when_disabled_allowed is False, odd_value
        # the available memory of the host, in MiB: a whole number, 0 or more, or None
        for value, expected in ((2048, 2048), (2048.9, 2048), (-5, 0), ('2048', None), (True, None),
                                (float('nan'), None), (None, None)):
            assert status_from_json({'mem_available_mb': value}).mem_available_mb == expected, value
        assert status_from_json({}).mem_available_mb is None        # an agent older than the key
        assert status_from_json({'occupied_by': ['a', 3, None, 'b']}).occupied_by == ['a', 'b']
        assert status_from_json({'hostname': 'x' * 500}).hostname == 'x' * MAX_STATUS_TEXT
        for body in ([1, 2], 'up', None, 3):
            st = status_from_json(body)
            assert not st.reachable and 'object' in st.error, body

    def test_preload_object(self):
        """The ``preload`` object of the status, flat in the ``HostStatus``; an agent older than
        the preload sends none (``''``: never given a turn), a hostile one plants nothing."""
        from sreweb.portal.pool import status_from_json, MAX_STATUS_TEXT

        def fields(st):
            return (st.preload, st.preload_since, st.preload_current, st.preload_total, st.preload_image,
                    st.preload_error, st.exam_projects)
        assert fields(status_from_json(up())) == ('', None, 0, 0, '', '', 0)
        assert fields(HostStatus(error='down')) == ('', None, 0, 0, '', '', 0)
        st = status_from_json(up(exam_projects=2, preload=preloading('running', 12, total=5, current=2, image='debian:12')))
        assert fields(st) == ('running', 12, 2, 5, 'debian:12', '', 2)
        assert status_from_json(up(preload=preloading('pending', 40))).preload_since == 40
        for odd in ('running', ['running'], {'state': 'exploding'}, {'state': 5}, {'state': ['running']}, None, 7):
            assert status_from_json(up(preload=odd)).preload == '', odd
        st = status_from_json(up(exam_projects='many', preload={'state': 'failed', 'since': 'x', 'total': -3,
                                                                'current': 2.7, 'image': 7, 'error': 'e' * 500}))
        assert fields(st) == ('failed', None, 2, 0, '', 'e' * MAX_STATUS_TEXT, 0)

    def test_gui_users(self):
        """The users in the Qt GUI of a host (the Clients view of the Watch page): one valid
        login each, a capped name, a number or nothing as the start; an agent older than the key
        sends none, a hostile one plants nothing."""
        from sreweb.portal.pool import status_from_json, MAX_STATUS_TEXT, MAX_GUI_USERS
        assert status_from_json(up()).gui_users == [] and HostStatus(error='down').gui_users == []
        st = status_from_json(up(gui_users=[{'login': 'alice', 'fullname': 'Alice', 'since': 1700000000.5},
                                            {'login': 'bob', 'fullname': '', 'since': None}]))
        assert st.gui_users == [{'login': 'alice', 'fullname': 'Alice', 'since': 1700000000.5},
                                {'login': 'bob', 'fullname': '', 'since': None}]
        odd = status_from_json(up(gui_users=[
            'alice', None, 7, ['bob'], {}, {'login': 5}, {'login': ''}, {'login': 'a b'}, {'login': '<script>'},
            {'login': 'x' * 200}, {'login': 'carol', 'fullname': ['x'], 'since': 'yesterday', 'extra': 1},
            {'login': 'dave', 'fullname': 'd' * 500, 'since': True}, {'login': 'carol', 'fullname': 'again'},
            {'login': 'erin', 'since': float('inf')}]))
        assert odd.gui_users == [{'login': 'carol', 'fullname': '', 'since': None},
                                 {'login': 'dave', 'fullname': 'd' * MAX_STATUS_TEXT, 'since': None},
                                 {'login': 'erin', 'fullname': '', 'since': None}]
        for value in ('alice', {'login': 'alice'}, None, 3):
            assert status_from_json(up(gui_users=value)).gui_users == [], value
        many = status_from_json(up(gui_users=[{'login': f'user{i}'} for i in range(MAX_GUI_USERS + 10)]))
        assert len(many.gui_users) == MAX_GUI_USERS

    def test_gui_users_of_the_pool(self):
        """``Pool.gui_users()``: the reachable hosts with somebody in the GUI; the rows of the
        Pool page and of ``sre-web-tool list --json`` do not carry them."""
        hosts = [HostConfig('a', 'http://a', TOKEN, 10), HostConfig('b', 'http://b', TOKEN, 10),
                 HostConfig('c', 'http://c', TOKEN, 10)]
        session = FakeSession()
        session.answers['http://a'] = up(gui_users=[{'login': 'alice', 'fullname': 'Alice', 'since': 5.0}])
        session.answers['http://b'] = up()
        session.answers['http://c'] = up(gui_users=[{'login': 'carol'}])
        pool = Pool(hosts, session)

        async def go():
            assert pool.gui_users() == {}                                  # nothing polled yet
            await pool.refresh()
            assert pool.gui_users() == {'a': [{'login': 'alice', 'fullname': 'Alice', 'since': 5.0}],
                                        'c': [{'login': 'carol', 'fullname': '', 'since': None}]}
            pool.gui_users()['a'][0]['login'] = 'changed'                  # a copy: the status is untouched
            assert pool.gui_users()['a'][0]['login'] == 'alice'
            assert all('gui_users' not in row for row in pool.summary())
            session.answers['http://a'] = None                             # the host does not answer any more
            await pool.refresh()
            assert not pool.status['a'].reachable and set(pool.gui_users()) == {'c'}
        run(go())

    def test_one_odd_agent_does_not_break_the_placement(self):
        hosts = [HostConfig('a', 'http://a', TOKEN, 10), HostConfig('b', 'http://b', TOKEN, 10)]
        session = FakeSession()
        session.answers['http://a'] = up(load1='high', projects='2')
        session.answers['http://b'] = up(load1=0.3, projects=1)
        pool = Pool(hosts, session)

        async def go():
            await pool.refresh()
            a = pool.status['a']
            assert a.reachable and a.load1 is None and a.projects == 0
            assert pool.pick()[0].name == 'a'              # no project, load unknown (0): the least loaded
            session.answers['http://a'] = [1, 2]            # not an object: unreachable, not kept up forever
            await pool.refresh()
            assert not pool.status['a'].reachable and 'object' in pool.status['a'].error
            assert pool.pick()[0].name == 'b'
        run(go())


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
        now = float(int(time.monotonic()))   # integer-valued: now + 100 - now is exactly wake_timeout (float rounding made it 99.99… once in ~400 runs)
        pool.runtime['f'].woken_at = now
        assert [pool.state_of(n, now=now + 50) for n in 'abcdefg'] == [
            STATE_UP, STATE_OCCUPIED, STATE_EXAM, STATE_DRAINING, STATE_DISABLED, STATE_WAKING, STATE_OFF]
        # the state whatever `enabled`: the same for an enabled host, what a disabled one hides
        assert [pool.live_state(n, now=now + 50) for n in 'abcdefg'] == [
            STATE_UP, STATE_OCCUPIED, STATE_EXAM, STATE_DRAINING, STATE_UP, STATE_WAKING, STATE_OFF]
        for name in 'bcdfg':
            pool.runtime[name].enabled = False
        assert [pool.state_of(n, now=now + 50) for n in 'bcdfg'] == [STATE_DISABLED] * 5
        assert [pool.live_state(n, now=now + 50) for n in 'bcdfg'] == [
            STATE_OCCUPIED, STATE_EXAM, STATE_DRAINING, STATE_WAKING, STATE_OFF]
        for name in 'bcdfg':
            pool.runtime[name].enabled = True
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

    def test_pick_priority_among_the_hosts_without_project(self):
        """In a group (here group 0, the default) the lowest order decides between the hosts
        without project; a loaded host is still chosen on its load alone, and the user's own
        session comes before everything."""
        hosts = [HostConfig(n, f'http://{n}', TOKEN, 10) for n in 'abc'] \
            + [HostConfig('d', 'http://d', TOKEN, 10, priority=prio(-1))]
        pool = Pool(hosts, session=None)
        assert [pool.runtime[n].priority for n in 'abcd'] == [(0, 0), (0, 0), (0, 0), (0, -1)]   # those of the configuration
        for name in 'abcd':
            pool.status[name] = HostStatus(reachable=True, load1=1.0)
        pool.status['d'].load1 = 9.0                 # the priority comes before the load
        assert pool.pick()[0].name == 'd'
        assert pool.pick()[0].name == 'a'            # d has a start in flight: the others, by name
        pool.set_priority('c', prio(-5))
        pool.set_priority('b', prio(7))
        assert pool.pick()[0].name == 'c' and pool.pick()[0].name == 'b'      # b, the last one without project
        assert {row['name']: row['priority'] for row in pool.summary()} == {'a': '0:0', 'b': '0:7', 'c': '0:-5',
                                                                            'd': '0:-1'}
        assert {row['name']: (row['group'], row['order']) for row in pool.summary()} == {
            'a': (0, 0), 'b': (0, 7), 'c': (0, -5), 'd': (0, -1)}
        # every host has one project: the load and the name, the priorities play no part
        pool.status['b'].load1 = 0.5
        assert pool.pick()[0].name == 'b'
        assert [pool.pick()[0].name for _ in range(3)] == ['a', 'c', 'd']
        # an empty host that cannot be used is not waited for: the least loaded of the others
        pool.status['c'].projects = 0
        pool.runtime['c'].drain = True
        assert pool.pick()[0].name == 'b'
        # the host of a local session of the user first, whatever its priority and its load
        pool.runtime['c'].drain = False
        pool.status['a'] = HostStatus(reachable=True, projects=6, occupied=True, occupied_by=['session:bob'])
        pool.set_priority('a', prio(50))
        host, reservation = pool.pick(Identity(login='bob'))
        assert host.name == 'a' and reservation.placement == PLACEMENT_SESSION
        host, reservation = pool.pick(Identity(login='alice'))
        assert host.name == 'c' and reservation.placement == PLACEMENT_LOAD
        with pytest.raises(PoolError) as e:
            pool.set_priority('nope', prio(1))
        assert e.value.status == 404

    def test_pick_the_lowest_group_first(self):
        """The group of the priorities is strict: a new project goes to the lowest group that
        has a host able to take it, whatever the load of its hosts; a higher group is used
        when the hosts below are full, down or draining, and left as soon as one of them has
        room again; the user's own session still comes before everything."""
        hosts = [HostConfig('a', 'http://a', TOKEN, 3), HostConfig('b', 'http://b', TOKEN, 3),
                 HostConfig('c', 'http://c', TOKEN, 3, priority=prio('1:0')),
                 HostConfig('d', 'http://d', TOKEN, 3, priority=prio('1:-4')),
                 HostConfig('e', 'http://e', TOKEN, 3, priority=prio('-1:9'))]
        pool = Pool(hosts, session=None)
        for name in 'abcde':
            pool.status[name] = HostStatus(reachable=True, load1=1.0)
        pool.status['e'].load1 = 9.0
        # group -1: e until it is full, though the hosts of the other groups are empty and less loaded
        assert [pool.pick()[0].name for _ in range(3)] == ['e'] * 3
        # then group 0, by the rule of a group: the least loaded host, then the name
        assert [pool.pick()[0].name for _ in range(6)] == ['a', 'b', 'a', 'b', 'a', 'b']
        # then group 1: d (order -4) before c while both are empty, then the least loaded
        assert [pool.pick()[0].name for _ in range(6)] == ['d', 'c', 'c', 'd', 'c', 'd']
        with pytest.raises(PoolError) as e:
            pool.pick()
        assert e.value.status == 503 and 'no host' in e.value.message
        # a host of a lower group that cannot take the project is not waited for
        pool.status['c'].projects = 0
        pool.status['e'].projects = 0
        pool.runtime['e'].drain = True                       # group -1: draining
        pool.status['a'] = HostStatus(reachable=False)       # group 0: a down, b full
        assert pool.pick()[0].name == 'c'
        # a host of a lower group has room again: it takes the project, loaded as it is
        pool.status['b'].projects = 2
        pool.status['b'].load1 = 30.0
        assert [pool.pick()[0].name for _ in range(2)] == ['b', 'c']      # b full again: back to group 1
        # a priority set by hand counts at once
        pool.runtime['e'].drain = False
        pool.set_priority('c', prio('-5:0'))
        assert [pool.pick()[0].name for _ in range(2)] == ['c', 'e']      # c (2 of 3) in group -5, then e, empty
        # the host of a local session of the user first, whatever its group
        pool.set_priority('d', prio('9:9'))
        pool.status['d'] = HostStatus(reachable=True, projects=1, occupied=True, occupied_by=['session:bob'])
        host, reservation = pool.pick(Identity(login='bob'))
        assert host.name == 'd' and reservation.placement == PLACEMENT_SESSION
        host, reservation = pool.pick(Identity(login='alice'))
        assert host.name == 'e' and reservation.placement == PLACEMENT_LOAD

    def test_pick_one_host_per_group_fills_them_in_turn(self):
        """One host per group, what ``placement = "pack"`` was for: the lowest group until it is
        full, though the other hosts are emptier and less loaded, so that the projects gather
        on the fewest hosts; the pool has no placement mode any more."""
        hosts = [HostConfig(f'vm{n}', f'http://vm{n}', TOKEN, 4, priority=prio(f'{n}:0')) for n in (1, 2, 3)]
        pool = Pool(hosts, session=None)
        for host in hosts:
            pool.status[host.name] = HostStatus(reachable=True, load1=1.0)
        pool.status['vm1'].load1 = 8.0
        pool.status['vm3'].projects = 1
        assert [pool.pick()[0].name for _ in range(9)] == ['vm1'] * 4 + ['vm2'] * 4 + ['vm3']
        # a project of vm1 ended: it is filled again before vm3 goes on
        pool.status['vm1'].projects = 3
        assert [pool.pick()[0].name for _ in range(2)] == ['vm1', 'vm3']
        # the fill is a ratio inside a group: 3 of 10 is emptier than 2 of 4
        pool = Pool([HostConfig('big', 'http://big', TOKEN, 10), HostConfig('small', 'http://small', TOKEN, 4)],
                    session=None)
        pool.status['big'] = HostStatus(reachable=True, projects=3)
        pool.status['small'] = HostStatus(reachable=True, projects=2)
        assert pool.pick()[0].name == 'big'
        assert not hasattr(pool, 'placement')
        with pytest.raises(TypeError):
            Pool(hosts, session=None, placement='pack')

    def test_pick_memory_room(self):
        """``project_memory_mb``: a host takes no more new projects than its available memory
        holds of them, each start in flight counting as one until a status asked after its end;
        a host named by an instructor too; nothing checked at 0 or without the agent's figure."""
        hosts = [HostConfig('a', 'http://a', TOKEN, 10), HostConfig('b', 'http://b', TOKEN, 10)]
        pool = Pool(hosts, session=None, project_memory_mb=1000)
        pool.status['a'] = HostStatus(reachable=True, mem_available_mb=2500)    # two projects of 1000
        pool.status['b'] = HostStatus(reachable=True, projects=5)               # no figure: not checked
        assert (pool.memory_room('a'), pool.memory_room('b')) == (2, None)
        picked = [pool.pick() for _ in range(2)]
        assert [host.name for host, _ in picked] == ['a', 'a'] and pool.memory_room('a') == 0
        assert pool.pick()[0].name == 'b'            # a is the least loaded but its memory is full
        rows = {row['name']: row for row in pool.summary()}
        assert rows['a']['memory_room'] == 0 and rows['a']['mem_available_mb'] == 2500
        assert rows['b']['memory_room'] is None
        # the elastic pool reads the same room
        mgr = PoolManager(pool, PoolConfig(project_memory_mb=1000))
        assert {v.name: v.memory_room for v in mgr.views()} == {'a': 0, 'b': None}
        status = mgr.status()
        assert (status['project_memory_mb'], status['memory_full']) == (1000, ['a']) and 'placement' not in status
        # a host named by an instructor whose memory is full: 503
        prof = Identity(login='prof', role=ROLE_INSTRUCTOR)
        with pytest.raises(PoolError) as e:
            pool.pick(prof, host='a')
        assert e.value.status == 503 and 'memory' in e.value.message
        # the starts are over and a status asked afterwards tells the memory they took: the
        # reservations are consumed, the room follows the new reading alone
        for _, reservation in picked:
            Pool.release(reservation)
        assert pool._consume('a', time.monotonic()) == 0
        pool.status['a'] = HostStatus(reachable=True, projects=2, mem_available_mb=1200)
        assert pool.memory_room('a') == 1 and pool.pick(prof, host='a')[0].name == 'a'
        assert pool.memory_room('a') == 0            # that start in flight takes the last one
        # no host with room: refused
        pool.status['b'] = HostStatus(reachable=True, mem_available_mb=900)
        with pytest.raises(PoolError) as e:
            pool.pick()
        assert e.value.status == 503 and 'no host' in e.value.message
        # an unreachable host, or the memory not checked: no room computed
        pool.status['b'] = HostStatus(reachable=False, mem_available_mb=900)
        assert pool.memory_room('b') is None
        unchecked = Pool(hosts, session=None)
        unchecked.status['a'] = HostStatus(reachable=True, mem_available_mb=10)
        assert unchecked.memory_room('a') is None and unchecked.pick()[0].name == 'a'

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
    def test_the_lowest_priority_is_woken_first(self):
        """The policy reads the priorities of the pool, those set by hand included: the group,
        then the order."""
        hosts = [HostConfig('a', 'http://a', TOKEN, 10, mac='0a:00:00:00:00:01'),
                 HostConfig('b', 'http://b', TOKEN, 10, mac='0a:00:00:00:00:02', priority=prio(-1)),
                 HostConfig('c', 'http://c', TOKEN, 10, mac='0a:00:00:00:00:03')]
        session = FakeSession()
        pool = Pool(hosts, session, wake_timeout=100.0)
        sent = []
        mgr = PoolManager(pool, PoolConfig(spare_projects=15, min_hosts_up=0, active_hours='', wake_interval=0),
                          wol=lambda mac, broadcast: sent.append(mac))

        async def go():
            await pool.refresh()
            pool.set_priority('c', prio('-1:7'))
            assert {v.name: v.priority for v in mgr.views(time.monotonic())} == {'a': (0, 0), 'b': (0, -1),
                                                                                 'c': (-1, 7)}
            await mgr.tick()
            assert sent == ['0a:00:00:00:00:03'] and pool.state_of('c') == STATE_WAKING       # c, group -1
            await mgr.tick()                                    # 10 slots to come, 15 wanted: b, 0:-1, before a
            assert sent[1:] == ['0a:00:00:00:00:02'] and pool.state_of('a') == STATE_OFF
        run(go())

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

    def test_restart_and_recovery(self, caplog):
        """``restart``: the POST, then the host takes no project, is neither woken nor powered
        off and keeps its drain until the portal sees the agent's uptime reset (even without an
        unreachable poll in between); given up after the hold unless the agent still says it is
        about to restart."""
        hosts = [HostConfig('a', 'http://a', TOKEN, 10, mac='aa:bb:cc:dd:ee:ff'), HostConfig('b', 'http://b', TOKEN, 10)]
        session = FakeSession()
        session.answers = {'http://a': up(), 'http://b': up()}
        pool = Pool(hosts, session, wake_timeout=100.0, restart_hold=1.0)
        sent = []
        mgr = PoolManager(pool, PoolConfig(spare_projects=5, min_hosts_up=2, active_hours=''),
                          wol=lambda mac, broadcast: sent.append(mac))
        prof = Identity(login='prof', role=ROLE_INSTRUCTOR)

        async def go():
            await pool.refresh()
            rt = pool.runtime['a']
            rt.drain = True
            await mgr.restart('a')
            assert session.posts == ['http://a/v1/restart'] and rt.restart_sent is not None and rt.drain is True
            rows = {r['name']: r for r in pool.summary()}
            assert rows['a']['restart_sent'] is True and rows['a']['restart_allowed'] is True
            assert rows['a']['agent_uptime'] == 500 and rows['b']['restart_sent'] is False
            assert [v.restart_pending for v in mgr.views()] == [True, False]
            # no placement there, by load or by name; the other host full: "a host is starting"
            assert pool.pick()[0].name == 'b'
            with pytest.raises(PoolError) as e:
                pool.pick(prof, host='a')
            assert e.value.status == 503 and 'not available' in e.value.message
            session.answers['http://b'] = up(projects=10)
            await pool.refresh()
            with pytest.raises(PoolError) as e:
                pool.pick()
            assert e.value.status == 503 and 'starting' in e.value.message
            with pytest.raises(PoolError) as e:                   # a second restart meanwhile
                await mgr.restart('a')
            assert e.value.status == 409 and 'sent' in e.value.message and len(session.posts) == 1
            # down while it restarts: off, not woken by the policy although the floor wants two hosts
            session.answers['http://a'] = None
            await pool.refresh()
            assert pool.state_of('a') == STATE_OFF and rt.restart_sent is not None and rt.drain is True
            await mgr.tick()
            assert sent == []
            # back with a fresh uptime: the restart is over, the drain kept
            session.answers['http://a'] = up(agent_uptime=0)
            rt.restart_sent -= 2.0                              # the request is two seconds old
            await pool.refresh()
            assert rt.restart_sent is None and rt.drain is True and pool.state_of('a') == STATE_DRAINING
            # a fast restart between two polls: the uptime alone tells
            rt.drain = False
            session.answers['http://a'] = up()
            await pool.refresh()
            await mgr.restart('a')
            await pool.refresh()
            assert rt.restart_sent is not None                   # the agent's uptime is older than the request
            session.answers['http://a'] = up(agent_uptime=0)
            await pool.refresh()
            assert rt.restart_sent is not None                   # too soon: the uptime is rounded to the second
            rt.restart_sent -= 2.0
            await pool.refresh()
            assert rt.restart_sent is None and pool.state_of('a') == STATE_UP
            # nothing restarts (the command failed on the agent): given up after the hold, with a warning
            session.answers['http://a'] = up()
            await pool.refresh()
            await mgr.restart('a')
            rt.restart_sent -= 2.0
            with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
                await pool.refresh()
            assert rt.restart_sent is None and 'no restart seen' in caplog.text
            # ... unless the agent still says it is about to (a sre command in flight delays it)
            await mgr.restart('a')
            rt.restart_sent -= 2.0
            session.answers['http://a'] = up(restarting=True)
            await pool.refresh()
            assert rt.restart_sent is not None
            rt.restart_sent = None
            # the agent refuses, or is unreachable: nothing marked
            session.post_status, session.post_data = 409, {'error': 'not a systemd service'}
            with pytest.raises(PoolError) as e:
                await mgr.restart('a')
            assert e.value.status == 409 and 'systemd' in e.value.message and rt.restart_sent is None
            session.answers['http://a'] = None
            await pool.refresh()
            with pytest.raises(PoolError) as e:
                await mgr.restart('a')
            assert e.value.status == 409 and 'not reachable' in e.value.message
        run(go())

    @staticmethod
    def _preload_pool(states: dict, **cfg):
        """A pool whose agents say *states* about their preload (None: an agent older than it)."""
        hosts = [HostConfig(n, f'http://{n}', TOKEN, 10) for n in states]
        session = FakeSession()
        session.answers = {f'http://{n}': up() if p is None else up(preload=p) for n, p in states.items()}
        pool = Pool(hosts, session)
        mgr = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0, active_hours='', **cfg),
                          wol=lambda mac, broadcast: None)
        return session, pool, mgr

    def test_preloads_a_few_hosts_at_a_time(self, caplog):
        """The hosts asking for a preload of the Docker images get their turn ``max_preloads`` at
        a time, the one that waited longest first; a turn given counts until a status asked after
        it tells, whatever the statuses asked before say (the polls and the policy are two loops)."""
        session, pool, mgr = self._preload_pool({'a': preloading('pending', 30), 'b': preloading('pending', 20),
                                                 'c': preloading('pending', 10), 'd': None}, max_preloads=2)
        START = '/v1/preload/start'

        async def go():
            await pool.refresh()
            await mgr.tick()
            assert session.posts == [f'http://a{START}', f'http://b{START}']
            status = mgr.status()
            assert (status['max_preloads'], status['preloading'], status['preload_queued'], status['preload_failed']) \
                == (2, ['a', 'b'], 1, 0)
            await mgr.tick()                                    # the statuses held are older than the turns
            assert len(session.posts) == 2
            # a status asked before the turn was given and arriving after it does not free the turn
            for name in 'ab':
                pool.runtime[name].preload_granted = time.monotonic() + 60
            await pool.refresh()
            assert pool.status['a'].preload == 'pending' and pool.runtime['a'].preload_granted is not None
            await mgr.tick()
            assert len(session.posts) == 2
            # the next one tells: both run, c still waits
            for name in 'ab':
                pool.runtime[name].preload_granted = time.monotonic() - 1
                session.answers[f'http://{name}'] = up(preload=preloading('running', 2, total=4, current=1, image='debian:12'))
            await pool.refresh()
            assert pool.runtime['a'].preload_granted is None and pool.runtime['b'].preload_granted is None
            await mgr.tick()
            assert len(session.posts) == 2 and mgr.status()['preloading'] == ['a', 'b']
            row = {r['name']: r for r in pool.summary()}['a']
            assert (row['preload'], row['preload_current'], row['preload_total'], row['preload_image']) == \
                ('running', 1, 4, 'debian:12')
            # a is done: its turn goes to c
            session.answers['http://a'] = up(preload=preloading('done', 0, total=4, current=4))
            with caplog.at_level(logging.INFO, logger='sreweb.portal'):
                await pool.refresh()
            assert 'host a: 4 image(s) preloaded' in caplog.text
            await mgr.tick()
            assert session.posts[2:] == [f'http://c{START}']
            # the turn never reached c (its status, asked after it, still says pending): given again
            pool.runtime['c'].preload_granted = time.monotonic() - 1
            await pool.refresh()
            await mgr.tick()
            assert session.posts[3:] == [f'http://c{START}']
            # b fails: told once, not tried again by the portal
            pool.runtime['c'].preload_granted = time.monotonic() - 1
            session.answers['http://c'] = up(preload=preloading('running', 1))
            session.answers['http://b'] = up(preload=preloading('failed', 0, error='1 of 4 image(s) failed to pull: x:1'))
            with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
                await pool.refresh()
            assert 'host b: preload of the images failed: 1 of 4 image(s) failed to pull: x:1' in caplog.text
            await mgr.tick()
            assert len(session.posts) == 4 and mgr.status()['preload_failed'] == 1
        run(go())

    def test_preload_turn_refused_or_unanswered(self, caplog):
        session, pool, mgr = self._preload_pool({'a': preloading('pending', 30), 'b': preloading('pending', 20),
                                                 'c': preloading('pending', 10)}, max_preloads=1)
        START = '/v1/preload/start'

        async def go():
            await pool.refresh()
            # a refuses its turn (an exam started there): held back for a while, b is served
            session.post_answers[f'http://a{START}'] = (409, {'error': '1 exam project(s) running'})
            with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
                await mgr.tick()
            assert session.posts == [f'http://a{START}'] and 'preload of a: a refused: 1 exam project(s) running' in caplog.text
            rt = pool.runtime['a']
            assert rt.preload_granted is None and rt.next_preload_at > time.monotonic() + PRELOAD_REFUSED_HOLD - 5
            # b does not answer: it may have started, so it holds the turn until its next status
            session.post_answers[f'http://b{START}'] = None
            await mgr.tick()
            assert session.posts[1:] == [f'http://b{START}'] and pool.runtime['b'].preload_granted is not None
            await mgr.tick()
            assert len(session.posts) == 2
            # its status says it did not: c is next in line, b comes again after it
            pool.runtime['b'].preload_granted = time.monotonic() - 1
            del session.post_answers[f'http://b{START}']
            await pool.refresh()
            await mgr.tick()
            assert session.posts[2:] == [f'http://b{START}']    # b waited longer than c
            # the hold of a is over
            pool.runtime['b'].preload_granted = time.monotonic() - 1
            session.answers['http://b'] = up(preload=preloading('done'))
            del session.post_answers[f'http://a{START}']
            rt.next_preload_at = time.monotonic() - 1
            await pool.refresh()
            await mgr.tick()
            assert session.posts[3:] == [f'http://a{START}']
        run(go())

    def test_no_preload_while_an_exam_runs_or_the_host_goes_down(self):
        session, pool, mgr = self._preload_pool({'a': preloading('pending', 30), 'b': preloading('pending', 20),
                                                 'c': preloading('pending', 10)}, max_preloads=3)

        async def go():
            session.answers['http://a']['exam_projects'] = 1
            await pool.refresh()
            pool.runtime['b'].drain = True
            await mgr.tick()
            assert session.posts == ['http://c/v1/preload/start']
            # nothing is given with max_preloads = 0, and a request by hand is refused
            mgr.cfg.max_preloads = 0
            pool.runtime['b'].drain = False
            await mgr.tick()
            assert len(session.posts) == 1
            with pytest.raises(PoolError) as e:
                await mgr.request_preload('b')
            assert e.value.status == 409 and 'max_preloads' in e.value.message
        run(go())

    def test_preload_asked_by_hand(self):
        """``sre-web-tool preload``: the agent is asked, and waits for its turn like the others;
        its answer shows at once in the row."""
        session, pool, mgr = self._preload_pool({'a': preloading('idle'), 'old': None, 'down': preloading('idle')},
                                                max_preloads=1)
        REQUEST = 'http://a/v1/preload/request'

        async def go():
            session.answers['http://down'] = None
            await pool.refresh()
            session.post_answers[REQUEST] = (200, {'ok': True, 'preload': preloading('pending')})
            await mgr.request_preload('a')
            assert session.posts == [REQUEST]
            assert pool.status['a'].preload == 'pending' and pool.runtime['a'].preload_granted is None
            assert {r['name']: r['preload'] for r in pool.summary()} == {'a': 'pending', 'old': '', 'down': ''}
            session.post_answers['http://a/v1/preload/start'] = (200, {'ok': True, 'preload': preloading('running')})
            await mgr.tick()                                    # the policy gives the turn
            assert session.posts[1:] == ['http://a/v1/preload/start'] and pool.status['a'].preload == 'running'
            for name, fragment in (('old', 'older version'), ('down', 'not reachable')):
                with pytest.raises(PoolError) as e:
                    await mgr.request_preload(name)
                assert e.value.status == 409 and fragment in e.value.message
            with pytest.raises(PoolError) as e:
                await mgr.request_preload('nope')
            assert e.value.status == 404
            session.post_answers[REQUEST] = (500, {'error': 'internal error'})
            with pytest.raises(PoolError) as e:
                await mgr.request_preload('a')
            assert e.value.status == 500 and 'internal error' in e.value.message
            assert len(session.posts) == 3
        run(go())

    def test_active_hours_clock(self):
        import datetime
        pool = Pool([], session=None)
        mgr = PoolManager(pool, PoolConfig(active_hours='07:00-20:00'),
                          clock=lambda: datetime.datetime(2026, 10, 22, 8, 30))
        assert mgr.active() is True
        mgr.clock = lambda: datetime.datetime(2026, 10, 22, 22, 0)
        assert mgr.active() is False and mgr.status()['active_now'] is False


# -- the lab list of the Open page --------------------------------------------------------------------

#: what an agent answers: the display order of the CLI (dhcp before s4 here, not the name order),
#: an unknown sort mode, an entry without title / with an unknown kind, a bare name, a duplicate
LABS = [{'name': 'sre/dhcp.py', 'title': {'en': 'DHCP'}, 'kind': 'lab', 'sort': 'title'},
        {'name': 's4', 'title': None, 'kind': 'dir', 'sort': 'bogus'},
        {'name': 's4/tp_ssh', 'kind': 'nope'},
        's4/arp.py', 'sre/dhcp.py']
LABS_OUT = [{'name': 'sre/dhcp.py', 'title': {'en': 'DHCP'}, 'kind': 'lab', 'sort': 'title'},
            {'name': 's4', 'title': None, 'kind': 'dir', 'sort': 'name'},
            {'name': 's4/tp_ssh', 'title': None, 'kind': 'lab', 'sort': 'name'},
            {'name': 's4/arp.py', 'title': None, 'kind': 'lab', 'sort': 'name'}]


class TestLabs:
    """``Pool.labs()``: one host, the likely placement of a new project, the next one when it
    fails; the list kept ``labs_cache_ttl`` seconds per role."""

    def test_order_and_keys_kept(self):
        """The order of the host is the display order (the browser sorts the ``title`` mode
        alone): never sorted again; the entries normalised to {name, title, kind, sort}."""
        pool, session = self._pool()
        labs = run(pool.labs(Identity(login='bob')))
        assert labs == LABS_OUT
        assert [lab['name'] for lab in labs] != sorted(lab['name'] for lab in labs)

    def test_readmes_of_the_directories(self):
        """The README an agent renders for a directory (`readme_html`: html by language) is kept
        on its entry, its texts that are non-empty strings only; the entry without name, the top
        of the lab directory, is kept for its README alone; never a README on a lab."""
        pool, session = self._pool()
        session.labs['http://a'] = [
            {'name': '', 'title': None, 'kind': 'dir', 'sort': 'name', 'readme_html': {'': '<h1>Welcome</h1>'}},
            {'name': 's4', 'kind': 'dir', 'sort': 'name', 'readme_html': {'fr': '<p>S4</p>', 'en': '', 'de': 3, 5: 'x'}},
            {'name': 's4/x.py', 'kind': 'lab', 'sort': 'name', 'readme_html': {'': '<p>on a lab</p>'}},
            {'name': 's5', 'kind': 'dir', 'sort': 'name', 'readme_html': 'not a dict'},
            {'name': 's6', 'kind': 'dir', 'sort': 'name', 'readme_html': {'': ''}},
            {'name': 's7', 'kind': 'dir', 'sort': 'name', 'readme': {'': 'raw markdown'}},
            {'name': 8, 'kind': 'lab'}]
        pool.status['a'] = HostStatus(reachable=True, load1=0.0)
        assert run(pool.labs(Identity(login='bob'))) == [
            {'name': '', 'title': None, 'kind': 'dir', 'sort': 'name', 'readme_html': {'': '<h1>Welcome</h1>'}},
            {'name': 's4', 'title': None, 'kind': 'dir', 'sort': 'name', 'readme_html': {'fr': '<p>S4</p>'}},
            {'name': 's4/x.py', 'title': None, 'kind': 'lab', 'sort': 'name'},
            {'name': 's5', 'title': None, 'kind': 'dir', 'sort': 'name'},
            {'name': 's6', 'title': None, 'kind': 'dir', 'sort': 'name'},
            {'name': 's7', 'title': None, 'kind': 'dir', 'sort': 'name'}]
        # the titles of the labs the exams read are those of the labs only
        assert pool.lab_titles() == {}

    def test_subtitles_of_the_manual_order(self):
        """The subtitle an agent gives with the first entry of a group (`subtitle`: a text, or
        texts by language) is kept on the entries of the manual mode, directories and labs, its
        texts that are strings only; anything else is dropped, and so is the subtitle of an
        entry of another mode."""
        pool, session = self._pool()
        session.labs['http://a'] = [
            {'name': 's4', 'kind': 'dir', 'sort': 'manual', 'subtitle': {'fr': 'Deuxième année', 'en': '', 'de': 3}},
            {'name': 's4/a.py', 'kind': 'lab', 'sort': 'manual', 'subtitle': 'Addressing', 'weight': 5},
            {'name': 's4/b.py', 'kind': 'lab', 'sort': 'manual', 'subtitle': '   '},
            {'name': 's4/c.py', 'kind': 'lab', 'sort': 'manual', 'subtitle': {'en': ''}},
            {'name': 's4/d.py', 'kind': 'lab', 'sort': 'manual', 'subtitle': ['Routing']},
            {'name': 's4/e.py', 'kind': 'lab', 'sort': 'manual', 'subtitle': 7},
            {'name': 's5', 'kind': 'dir', 'sort': 'title', 'subtitle': 'Not manual'},
            {'name': 's6.py', 'kind': 'lab', 'sort': 'bogus', 'subtitle': 'Not manual'},
            {'name': 's7.py', 'kind': 'lab', 'subtitle': 'No mode'}]
        pool.status['a'] = HostStatus(reachable=True, load1=0.0)
        assert run(pool.labs(Identity(login='bob'))) == [
            {'name': 's4', 'title': None, 'kind': 'dir', 'sort': 'manual', 'subtitle': {'fr': 'Deuxième année'}},
            {'name': 's4/a.py', 'title': None, 'kind': 'lab', 'sort': 'manual', 'subtitle': 'Addressing', 'weight': 5},
            {'name': 's4/b.py', 'title': None, 'kind': 'lab', 'sort': 'manual'},
            {'name': 's4/c.py', 'title': None, 'kind': 'lab', 'sort': 'manual'},
            {'name': 's4/d.py', 'title': None, 'kind': 'lab', 'sort': 'manual'},
            {'name': 's4/e.py', 'title': None, 'kind': 'lab', 'sort': 'manual'},
            {'name': 's5', 'title': None, 'kind': 'dir', 'sort': 'title'},
            {'name': 's6.py', 'title': None, 'kind': 'lab', 'sort': 'name'},
            {'name': 's7.py', 'title': None, 'kind': 'lab', 'sort': 'name'}]

    def test_top_entry_without_readme_dropped(self):
        """An entry without name is nothing but the README of the top directory."""
        pool, session = self._pool()
        session.labs['http://a'] = [{'name': '', 'kind': 'dir'}, {'name': '', 'kind': 'lab', 'readme_html': {'': 'x'}},
                                    {'name': 'a.py', 'kind': 'lab'}]
        pool.status['a'] = HostStatus(reachable=True, load1=0.0)
        assert run(pool.labs(Identity(login='bob'))) == [{'name': 'a.py', 'title': None, 'kind': 'lab', 'sort': 'name'}]

    @staticmethod
    def _pool(ttl=60.0):
        hosts = [HostConfig(n, f'http://{n}', TOKEN, 10) for n in 'abc']
        hosts.append(HostConfig('r', 'http://r', TOKEN, 10, instructors_only=True))
        session = FakeSession()
        pool = Pool(hosts, session, labs_cache_ttl=ttl)
        for n in 'abcr':
            pool.status[n] = HostStatus(reachable=True, load1=0.5)
            session.labs[f'http://{n}'] = LABS
        return pool, session

    @staticmethod
    def asked(session):
        return [u.rsplit('/v1/', 1)[0].removeprefix('http://') for u in session.gets if u.endswith('/v1/labs')]

    def test_one_host_the_likely_placement(self):
        pool, session = self._pool()
        pool.status['a'] = HostStatus(reachable=True, projects=0, load1=0.2)
        pool.status['b'] = HostStatus(reachable=True, projects=2, load1=0.1)    # the most loaded by projects
        pool.status['c'] = HostStatus(reachable=True, projects=0, load1=0.9)
        bob, prof = Identity(login='bob'), Identity(login='prof', role=ROLE_INSTRUCTOR)
        assert run(pool.labs(bob)) == LABS_OUT
        assert self.asked(session) == ['a']                   # one host: the least loaded a student may use
        # the reserved host r (0 projects, load 0.5) comes after a for an instructor too
        assert run(pool.labs(prof)) == LABS_OUT and self.asked(session) == ['a', 'a']
        # a disabled host is never asked, an occupied one after the hosts up, an unreachable one never
        pool.runtime['a'].enabled = False
        pool.status['c'] = HostStatus(reachable=True, occupied=True, occupied_by=['x'])
        pool._labs_cache.clear()
        assert run(pool.labs(bob)) == LABS_OUT and self.asked(session)[-1] == 'b'
        pool.status['b'] = HostStatus()                       # off
        pool._labs_cache.clear()
        assert run(pool.labs(bob)) == LABS_OUT and self.asked(session)[-1] == 'c'    # occupied, still serving
        pool.status['c'] = HostStatus()
        pool._labs_cache.clear()
        assert run(pool.labs(bob)) == [] and len(self.asked(session)) == 4             # nobody left to ask
        assert run(pool.labs(prof)) == LABS_OUT and self.asked(session)[-1] == 'r'    # the instructor: r

    def test_fallback_and_no_cache_of_a_failure(self):
        pool, session = self._pool()
        pool.status['a'] = HostStatus(reachable=True, load1=0.1)
        pool.status['b'] = HostStatus(reachable=True, load1=0.2)
        session.labs['http://a'] = None                       # down since the last poll
        session.labs['http://b'] = (500, {'error': 'x'})
        bob = Identity(login='bob')
        assert run(pool.labs(bob)) == LABS_OUT and self.asked(session) == ['a', 'b', 'c']
        session.labs['http://c'] = {'not': 'a list'}
        pool._labs_cache.clear()
        assert run(pool.labs(bob)) == [] and self.asked(session) == ['a', 'b', 'c'] * 2
        assert run(pool.labs(bob)) == [] and len(self.asked(session)) == 9              # a failure is not cached
        session.labs['http://c'] = LABS
        assert run(pool.labs(bob)) == LABS_OUT and len(self.asked(session)) == 12
        assert run(pool.labs(bob)) == LABS_OUT and len(self.asked(session)) == 12       # the success is

    def test_cache_per_role(self):
        pool, session = self._pool(ttl=60.0)
        bob, alice, prof = Identity(login='bob'), Identity(login='alice'), Identity(login='prof', role=ROLE_INSTRUCTOR)
        assert run(pool.labs(bob)) == LABS_OUT and len(self.asked(session)) == 1
        assert run(pool.labs(alice)) == LABS_OUT and len(self.asked(session)) == 1      # same role: cached
        assert run(pool.labs(prof)) == LABS_OUT and len(self.asked(session)) == 2       # the other role: fetched
        assert run(pool.labs(prof)) == LABS_OUT and len(self.asked(session)) == 2
        pool._labs_cache[(False, False)] = (time.monotonic() - 61, LABS_OUT)            # expired
        assert run(pool.labs(bob)) == LABS_OUT and len(self.asked(session)) == 3
        pool, session = self._pool(ttl=0)
        for _ in range(3):
            assert run(pool.labs(bob)) == LABS_OUT
        assert len(self.asked(session)) == 3                                            # 0 = no cache

    def test_concurrent_requests_share_one_fetch(self):
        pool, session = self._pool()
        bob = Identity(login='bob')

        async def go():
            return await asyncio.gather(*(pool.labs(bob) for _ in range(5)))
        assert run(go()) == [LABS_OUT] * 5 and len(self.asked(session)) == 1
