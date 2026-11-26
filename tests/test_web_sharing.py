"""The shared projects of the web front-end: the owner of a running project lets other students
work in it (``src/sreweb/portal/sharing.py``, the ``…/sharing`` routes, the Watch page's policy
and bulk actions).  The registry alone with fake sockets, a fake clock and fake host statuses,
then through the portal with a real agent on the fake ``sre``."""
import asyncio
import json
import os
from dataclasses import dataclass, field

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_presentation as T                             # noqa: E402  (the fakes and the identities)
from sreweb.identity import Identity                          # noqa: E402
from sreweb.portal import presentation as PR                  # noqa: E402
from sreweb.portal import sharing as SH                       # noqa: E402
from sreweb.portal.accesslog import iso_time                  # noqa: E402
from sreweb.portal.focus import project_page_url              # noqa: E402

RLN = '20261126100000@@@sre@dhcp.py@@@alice'                   # the @ form of the real names
RLN_BOB = '20261126100100@@@sre@dhcp.py@@@bob'
ALICE, BOB, CAROL, DAVE, PROF = T.ALICE, T.BOB, T.CAROL, T.DAVE, T.PROF
ERIN = Identity(login='erin', fullname='Erin E', group='INFO1')
INFO1, INFO2, TP_A = 'department:INFO1', 'department:INFO2', 'custom:TP A'
ROW = {'lab_name': 'sre@dhcp.py', 'title': 'DHCP', 'started_at': '2026-11-26T10:00:00'}
run = T.run
FakeWatcher = T.FakeWatcher


@dataclass
class Status:
    """What the registry reads of the status of a host (``pool.HostStatus``)."""
    reachable: bool = True
    project_names: list | None = field(default_factory=list)
    polled_at: float = 0.0


class World:
    """A registry with its presence, its clocks, one host ``a01`` and the students bound by an
    exam (``bound``)."""

    def __init__(self, default='yes-by-default', state_file='', names=(RLN, RLN_BOB), **over):
        self.clock = T.Clock(1000.0)
        self.mono = T.Clock(50.0)
        self.presence = PR.Presence(clock=self.clock)
        self.status = {'a01': Status(project_names=list(names), polled_at=self.mono.now)}
        self.bound: set = set()
        self.reg = SH.Sharing(self.presence, default=default, bound=lambda login, group: login in self.bound,
                              statuses=lambda: self.status, state_file=state_file, clock=self.clock,
                              monotonic=self.mono, **over)

    def page(self, identity: Identity, page: str = '/projects') -> FakeWatcher:
        watcher = FakeWatcher()
        self.presence.add(identity, page, watcher)
        return watcher

    def poll(self, seconds: float, host: str = 'a01', **changes):
        """A status of *host* asked *seconds* later."""
        self.mono.now += seconds
        self.clock.now += seconds
        status = self.status[host]
        for key, value in changes.items():
            setattr(status, key, value)
        status.polled_at = self.mono.now

    async def shared(self, audience=SH.AUDIENCE_ALL, keys=(INFO1,)) -> SH.Share:
        return await self.reg.start(ALICE, 'a01', RLN, audience, own_keys=keys, row=ROW)

    async def joined(self, identity: Identity = BOB, keys=(INFO1,)) -> SH.Share:
        """*identity* asked and alice accepted (alice needs a page to be asked)."""
        if self.presence.identity_of('alice') is None:
            self.page(ALICE)
        request = await self.reg.request(identity, 'a01', RLN, keys)
        share, _ = await self.reg.accept(request.id, ALICE)
        return share


def asked(share: SH.Share, request: SH.JoinRequest) -> dict:
    return {'t': 'share-request', 'id': request.id, 'host': share.host, 'rln': share.rln, 'lab': 'sre@dhcp.py',
            'title': 'DHCP', 'from': {'login': request.identity.login, 'fullname': request.identity.fullname},
            'to': {'login': 'alice', 'fullname': 'Alice A'}}


def answered(share, request, reason: str) -> dict:
    message = {**asked(share, request), 'ended': True, 'reason': reason}
    if reason == 'accepted':
        message['url'] = project_page_url(share.host, share.rln)
    return message


def out(share: SH.Share, reason: str) -> dict:
    return {'t': 'share', 'id': share.id, 'host': share.host, 'rln': share.rln,
            'owner': {'login': 'alice', 'fullname': 'Alice A'}, 'title': 'DHCP', 'ended': True, 'reason': reason}


def refusal(coro) -> SH.SharingRefused:
    with pytest.raises(SH.SharingRefused) as refused:
        run(coro) if asyncio.iscoroutine(coro) else coro()
    return refused.value


async def refused_by(coro) -> SH.SharingRefused:
    with pytest.raises(SH.SharingRefused) as refused:
        await coro
    return refused.value


# ---------------------------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------------------------

class TestPolicy:
    def test_the_two_defaults_and_what_an_instructor_decides(self):
        async def go():
            for default, by_default in (('no-by-default', False), ('yes-by-default', True)):
                w = World(default)
                reg = w.reg
                assert reg.allowed('a01', RLN) is by_default and reg.policy_of('a01', RLN) == 'default'
                assert reg.row('a01', RLN) == {'available': True, 'allowed': by_default, 'policy': 'default',
                                               'shared': False, 'audience': '', 'participants': 0, 'connected': 0}
                assert await reg.set_policy([('a01', RLN), ('a01', RLN)], 'allowed') == 1
                assert reg.allowed('a01', RLN) and reg.policy_of('a01', RLN) == 'allowed'
                assert reg.allowed('a01', RLN_BOB) is by_default                 # the others follow the default
                assert await reg.set_policy([('a01', RLN)], 'allowed') == 0      # nothing changed
                assert await reg.set_policy([('a01', RLN), ('a01', RLN_BOB)], 'forbidden') == 2
                assert not reg.allowed('a01', RLN) and reg.policy_of('a01', RLN_BOB) == 'forbidden'
                assert await reg.set_policy([('a01', RLN)], 'default') == 1
                assert reg.allowed('a01', RLN) is by_default and reg.policy_of('a01', RLN) == 'default'
                with pytest.raises(ValueError):
                    await reg.set_policy([('a01', RLN)], 'maybe')
        run(go())

    def test_no_by_default_refuses_until_allowed(self):
        async def go():
            w = World('no-by-default')
            error = await refused_by(w.shared())
            assert (error.status, error.extra) == (403, {'code': 'not_allowed'})
            await w.reg.set_policy([('a01', RLN)], 'allowed')
            share = await w.shared()
            assert w.reg.get('a01', RLN) is share and w.reg.row('a01', RLN)['shared']
        run(go())

    def test_forbidding_ends_the_share(self):
        async def go():
            w = World()
            share = await w.shared()
            await w.joined(BOB)
            wb = w.page(BOB, project_page_url('a01', RLN))
            grant = w.reg.grant(BOB, 'a01', RLN)
            assert grant.hold()
            assert await w.reg.set_policy([('a01', RLN)], 'forbidden') == 1
            assert w.reg.get('a01', RLN) is None and share.ended
            assert grant.revoked.is_set() and grant.reason == 'forbidden'
            assert wb.sent == [out(share, 'forbidden')]
            assert w.reg.grant(BOB, 'a01', RLN) is None
            # back to the default: the owner starts again, nobody is in it
            await w.reg.set_policy([('a01', RLN)], 'default')
            again = await w.shared()
            assert again is not share and again.participants == {}
        run(go())

    def test_a_host_that_cannot_share(self):
        async def go():
            w = World()
            w.status['a01'].project_names = None                 # an agent older than the participants
            assert not w.reg.available('a01') and not w.reg.row('a01', RLN)['available']
            assert (await refused_by(w.shared())).status == 409
            w.status['a01'] = Status(reachable=False)
            assert not w.reg.available('a01') and not w.reg.available('nope')
            # the registry alone (no pool behind): every host shares
            alone = SH.Sharing(PR.Presence(), default='yes-by-default')
            assert alone.available('anything')
            assert (await alone.start(ALICE, 'x', RLN, 'all')).host == 'x'
            await alone.tick()
            assert alone.get('x', RLN) is not None
        run(go())


class TestShare:
    def test_start_audience_and_stop(self):
        async def go():
            w = World()
            reg = w.reg
            assert (await refused_by(reg.start(BOB, 'a01', RLN, 'all'))).status == 403      # not the owner
            assert (await refused_by(w.shared(audience=INFO2))).status == 403               # not a group of alice
            for bad in ('', None, 3, ['all'], 'x' * 300):
                assert (await refused_by(w.shared(audience=bad))).status == 400, bad
            share = await w.shared(audience=INFO1)
            assert (share.host, share.rln, share.owner, share.owner_fullname, share.audience, share.started_at) == \
                ('a01', RLN, 'alice', 'Alice A', INFO1, 1000.0)
            assert (share.lab_name, share.title, share.project_started_at) == ('sre@dhcp.py', 'DHCP', '2026-11-26T10:00:00')
            assert reg.listing() == [share] and reg.get('a01', RLN_BOB) is None
            # a second start changes the audience and keeps the share
            assert await w.shared(audience='all') is share and share.audience == 'all'
            assert reg.describe(share) == {
                'id': share.id, 'host': 'a01', 'rln': RLN, 'audience': 'all',
                'owner': {'login': 'alice', 'fullname': 'Alice A', 'connected': False},
                'started_at': iso_time(1000.0), 'lab_name': 'sre@dhcp.py', 'title': 'DHCP',
                'project_started_at': '2026-11-26T10:00:00', 'max_participants': 4, 'participants': []}
            assert reg.describe(share, requests=True)['requests'] == []
            assert await reg.stop('a01', RLN) is share and reg.get('a01', RLN) is None and share.ended
            assert await reg.stop('a01', RLN) is None
        run(go())

    def test_who_sees_what(self):
        async def go():
            w = World()
            share = await w.shared(audience=INFO1)
            mine = await w.reg.start(BOB, 'a01', RLN_BOB, 'all', row=ROW)
            empty = {'joined': [], 'requested': [], 'joinable': []}
            # the owner never sees their own; a student outside the audience nothing of it
            assert [s['rln'] for s in w.reg.listing_for(ALICE, [INFO1])['joinable']] == [RLN_BOB]
            assert [s['rln'] for s in w.reg.listing_for(CAROL, [INFO2])['joinable']] == [RLN_BOB]
            assert w.reg.listing_for(PROF, [INFO1]) == empty               # an instructor opens any project already
            seen = w.reg.listing_for(DAVE, [INFO1, TP_A])
            assert {s['rln'] for s in seen['joinable']} == {RLN, RLN_BOB} and seen['joined'] == seen['requested'] == []
            assert next(s for s in seen['joinable'] if s['rln'] == RLN) == {
                'id': share.id, 'host': 'a01', 'rln': RLN, 'url': project_page_url('a01', RLN),
                'owner': {'login': 'alice', 'fullname': 'Alice A'}, 'audience': INFO1, 'lab_name': 'sre@dhcp.py',
                'title': 'DHCP', 'project_started_at': '2026-11-26T10:00:00', 'started_at': iso_time(1000.0),
                'participants': 0, 'full': False, 'request': None}
            w.page(ALICE)
            request = await w.reg.request(DAVE, 'a01', RLN, [INFO1])
            seen = w.reg.listing_for(DAVE, [INFO1])
            assert [s['rln'] for s in seen['joinable']] == [RLN_BOB]
            assert [(s['rln'], s['request']) for s in seen['requested']] == [(RLN, request.id)]
            await w.reg.accept(request.id, ALICE)
            seen = w.reg.listing_for(DAVE, [INFO1])
            assert seen['requested'] == [] and [s['participants'] for s in seen['joined']] == [1]
            # a participant stays one when the audience no longer includes them
            await w.shared(audience='all', keys=())
            await w.shared(audience=TP_A, keys=(TP_A,))
            assert [s['rln'] for s in w.reg.listing_for(DAVE, [INFO1])['joined']] == [RLN]
            assert [s['rln'] for s in w.reg.listing_for(ERIN, [INFO1])['joinable']] == [RLN_BOB]
            # nothing of a host that does not answer
            w.status['a01'].reachable = False
            assert w.reg.listing_for(DAVE, [INFO1]) == empty
            assert mine.owner == 'bob'
        run(go())

    def test_who_is_on_the_project(self):
        async def go():
            w = World()
            share = await w.shared()
            await w.joined(BOB)
            await w.joined(DAVE)
            page = project_page_url('a01', RLN)
            assert w.reg.connected(share) == set() and w.reg.row('a01', RLN)['connected'] == 0
            w.page(ALICE, page)
            bob = w.presence.add(BOB, page, FakeWatcher())
            w.page(DAVE, '/projects')                             # elsewhere on the site
            w.page(CAROL, page)                                   # a stranger naming the page
            w.page(PROF, page)                                    # an instructor helping: never counted
            assert w.reg.connected(share) == {'alice', 'bob'}
            assert w.reg.row('a01', RLN) == {'available': True, 'allowed': True, 'policy': 'default', 'shared': True,
                                             'audience': 'all', 'participants': 2, 'connected': 1}
            view = w.reg.describe(share)
            assert view['owner']['connected'] is True
            assert [(p['login'], p['fullname'], p['connected']) for p in view['participants']] == \
                [('bob', 'Bob B', True), ('dave', '', False)]
            bob.away = True                                       # the page is being left
            assert w.reg.connected(share) == {'alice'}
        run(go())


class TestJoining:
    def test_ask_accept_and_the_pushes(self):
        async def go():
            w = World()
            share = await w.shared(audience=INFO1)
            wa, wb = w.page(ALICE, '/open'), w.page(BOB, '/open')
            request = await w.reg.request(BOB, 'a01', RLN, [INFO1])
            assert wa.sent == [asked(share, request)] and wb.sent == []
            assert w.reg.request_share(request.id) is share
            assert w.reg.describe(share, requests=True)['requests'] == [
                {'id': request.id, 'login': 'bob', 'fullname': 'Bob B', 'since': iso_time(1000.0)}]
            # asking again while it waits is the same request, the owner is not told twice
            assert await w.reg.request(BOB, 'a01', RLN, [INFO1]) is request and len(wa.sent) == 1
            # a page of the owner opened meanwhile is told what waits; bob's new page nothing
            wa2, wb2 = FakeWatcher(), FakeWatcher()
            await w.reg.tell(ALICE, wa2)
            await w.reg.tell(BOB, wb2)
            assert wa2.sent == [asked(share, request)] and wb2.sent == []
            assert w.reg.grant(BOB, 'a01', RLN) is None                     # asking is not being in
            with pytest.raises(PermissionError):
                await w.reg.accept(request.id, BOB)                         # only the owner answers
            w.clock.now += 5
            got, _ = await w.reg.accept(request.id, ALICE)
            assert got is share and share.participants['bob'].since == 1005.0
            assert share.participants['bob'].fullname == 'Bob B'
            assert wa.sent[-1] == wb.sent[-1] == answered(share, request, 'accepted')
            assert wb.sent[-1]['url'] == project_page_url('a01', RLN)
            assert share.requests == {} and w.reg.request_share(request.id) is None
            with pytest.raises(SH.RequestGone):
                await w.reg.accept(request.id, ALICE)                       # a second answer
            assert isinstance(w.reg.grant(BOB, 'a01', RLN), SH.Grant)
            error = await refused_by(w.reg.request(BOB, 'a01', RLN, [INFO1]))
            assert (error.status, error.extra) == (409, {'code': 'joined'})
        run(go())

    def test_who_may_ask(self):
        async def go():
            w = World()
            await w.shared(audience=INFO1)
            # not shared, not in the audience, the owner, an instructor: the same answer
            for identity, rln, keys in ((BOB, RLN_BOB, [INFO1]), (CAROL, RLN, [INFO2]), (ALICE, RLN, [INFO1]),
                                        (PROF, RLN, [INFO1])):
                error = await refused_by(w.reg.request(identity, 'a01', rln, keys))
                assert (error.status, error.message) == (404, "no such shared project"), identity.login
            # the owner must be there to be asked
            error = await refused_by(w.reg.request(BOB, 'a01', RLN, [INFO1]))
            assert (error.status, error.extra) == (409, {'code': 'owner_away'})
            w.page(ALICE)
            w.bound.add('bob')
            assert (await refused_by(w.reg.request(BOB, 'a01', RLN, [INFO1]))).message == "no sharing during an exam"
            w.bound.clear()
            assert (await w.reg.request(BOB, 'a01', RLN, [INFO1])).identity is BOB
        run(go())

    def test_decline_cancel_expire(self):
        async def go():
            w = World(request_timeout=60.0)
            share = await w.shared()
            wa, wb, wd = w.page(ALICE), w.page(BOB), w.page(DAVE)
            first = await w.reg.request(BOB, 'a01', RLN, [])
            with pytest.raises(PermissionError):
                await w.reg.decline(first.id, DAVE)
            await w.reg.decline(first.id, ALICE)
            assert wa.sent[-1] == wb.sent[-1] == answered(share, first, 'declined')
            assert share.participants == {} and share.requests == {}
            # refused: a pause before asking the same project again
            error = await refused_by(w.reg.request(BOB, 'a01', RLN, []))
            assert (error.status, error.extra) == (429, {'retry_after': 30})
            w.clock.now += SH.REFUSAL_PAUSE
            second = await w.reg.request(BOB, 'a01', RLN, [])
            with pytest.raises(PermissionError):
                await w.reg.cancel(second.id, DAVE)                         # not their request
            await w.reg.cancel(second.id, BOB)
            assert wa.sent[-1] == wb.sent[-1] == answered(share, second, 'cancelled')
            # taken back, not refused: no pause
            third = await w.reg.request(DAVE, 'a01', RLN, [])
            await w.reg.cancel(third.id, PROF)                              # an instructor may too
            fourth = await w.reg.request(DAVE, 'a01', RLN, [])
            w.clock.now += 59
            await w.reg.tick()
            assert share.requests == {fourth.id: fourth}
            w.clock.now += 1
            await w.reg.tick()
            assert share.requests == {} and wd.sent[-1] == answered(share, fourth, 'expired')
            with pytest.raises(SH.RequestGone):
                await w.reg.decline(fourth.id, ALICE)
            # the sharing stopped with a request waiting
            fifth = await w.reg.request(DAVE, 'a01', RLN, [])
            await w.reg.stop('a01', RLN)
            assert wd.sent[-1] == wa.sent[-1] == answered(share, fifth, 'stopped')
        run(go())

    def test_the_cap(self):
        async def go():
            w = World(max_participants=2)
            share = await w.shared()
            await w.joined(BOB)
            waiting = await w.reg.request(DAVE, 'a01', RLN, [])
            late = await w.reg.request(ERIN, 'a01', RLN, [])
            await w.reg.accept(waiting.id, ALICE)
            assert w.reg.listing_for(CAROL, [])['joinable'][0]['full'] is True
            # full: the request already there stays for the owner to answer later
            error = await refused_by(w.reg.accept(late.id, ALICE))
            assert (error.status, error.extra) == (409, {'code': 'full'}) and late.id in share.requests
            assert (await refused_by(w.reg.request(CAROL, 'a01', RLN, []))).extra == {'code': 'full'}
            await w.reg.remove('a01', RLN, 'bob')
            await w.reg.accept(late.id, ALICE)
            assert set(share.participants) == {'dave', 'erin'}
        run(go())

    def test_too_many_waiting(self):
        async def go():
            w = World(max_participants=50)
            share = await w.shared()
            w.page(ALICE)
            for n in range(SH.MAX_PENDING):
                await w.reg.request(Identity(login=f'student{n}'), 'a01', RLN, [])
            assert (await refused_by(w.reg.request(BOB, 'a01', RLN, []))).status == 409
            assert len(share.requests) == SH.MAX_PENDING
        run(go())


class TestLeaving:
    def test_removed_left_and_stopped(self):
        async def go():
            w = World()
            share = await w.shared()
            await w.joined(BOB)
            await w.joined(DAVE)
            wb, wd = w.page(BOB), w.page(DAVE)
            assert await w.reg.remove('a01', RLN, 'carol') is False
            assert await w.reg.remove('a01', RLN_BOB, 'bob') is False
            assert await w.reg.remove('a01', RLN, 'bob') is True
            assert wb.sent == [out(share, 'removed')] and wd.sent == []
            assert set(share.participants) == {'dave'} and w.reg.grant(BOB, 'a01', RLN) is None
            assert await w.reg.remove('a01', RLN, 'dave', 'left') is True
            assert wd.sent == [out(share, 'left')]
            assert w.reg.get('a01', RLN) is share and share.participants == {}        # still shared, with nobody
            await w.joined(BOB)
            await w.reg.stop('a01', RLN)
            assert wb.sent[-1] == out(share, 'stopped') and w.reg.get('a01', RLN) is None
        run(go())

    def test_grants_and_their_sockets(self):
        async def go():
            w = World()
            share = await w.shared()
            assert w.reg.grant(BOB, 'a01', RLN) is None
            await w.joined(BOB)
            assert w.reg.grant(PROF, 'a01', RLN) is None and w.reg.grant(ALICE, 'a01', RLN) is None
            assert w.reg.grant(BOB, 'a01', RLN_BOB) is None
            first, second = w.reg.grant(BOB, 'a01', RLN), w.reg.grant(BOB, 'a01', RLN)
            assert first.hold() and second.hold() and share.grants == {'bob': {first, second}}
            first.release()
            first.release()                                                   # twice is nothing
            assert share.grants == {'bob': {second}} and not first.revoked.is_set()
            # a request checked, then the participant removed before its socket is registered:
            # the socket is refused; the sockets already open are cut
            late = w.reg.grant(BOB, 'a01', RLN)
            await w.reg.remove('a01', RLN, 'bob')
            assert second.revoked.is_set() and second.reason == 'removed' and share.grants == {}
            assert late.hold() is False and late.revoked.is_set() and share.grants == {}
            second.release()
            # accepted again: a new access, the old grants stay dead
            await w.joined(BOB)
            assert w.reg.grant(BOB, 'a01', RLN).hold() and second.revoked.is_set()
            held = w.reg.grant(BOB, 'a01', RLN)
            held.hold()
            await w.reg.stop('a01', RLN)
            assert held.revoked.is_set() and held.reason == 'stopped'
            assert w.reg.grant(BOB, 'a01', RLN) is None
        run(go())

    def test_an_exam_ends_it(self):
        async def go():
            w = World()
            share = await w.shared()
            await w.joined(BOB)
            await w.joined(DAVE)
            wb, wd = w.page(BOB), w.page(DAVE)
            held = w.reg.grant(BOB, 'a01', RLN)
            held.hold()
            # a participant bound by an exam: no access at once, out at the next tick
            w.bound.add('bob')
            assert w.reg.grant(BOB, 'a01', RLN) is None and w.reg.grant(DAVE, 'a01', RLN) is not None
            await w.reg.tick()
            assert held.revoked.is_set() and held.reason == 'exam' and wb.sent == [out(share, 'exam')]
            assert set(share.participants) == {'dave'}
            # the owner bound: nobody gets in, the share ends
            w.bound = {'alice'}
            assert w.reg.grant(DAVE, 'a01', RLN) is None
            assert (await refused_by(w.shared())).message == "no sharing during an exam"
            await w.reg.tick()
            assert w.reg.get('a01', RLN) is None and wd.sent == [out(share, 'exam')]
        run(go())

    def test_accepting_when_it_can_no_longer_be(self):
        async def go():
            w = World()
            share = await w.shared()
            wb = w.page(BOB)
            w.page(ALICE)
            request = await w.reg.request(BOB, 'a01', RLN, [])
            w.bound.add('bob')                                # an exam bound bob while alice was thinking
            assert (await refused_by(w.reg.accept(request.id, ALICE))).status == 409
            assert share.participants == {} and wb.sent[-1] == answered(share, request, 'cancelled')
        run(go())


class TestProjectsGone:
    def test_a_project_no_longer_on_its_host(self):
        async def go():
            w = World()
            share = await w.shared()
            await w.joined(BOB)
            wb = w.page(BOB)
            await w.reg.set_policy([('a01', RLN_BOB)], 'forbidden')
            await w.reg.reconcile()                                # the status is the one of before the entries
            w.poll(5)
            await w.reg.reconcile()
            assert w.reg.get('a01', RLN) is share                  # listed: there
            # gone from the status: not believed at once (two polls, twenty seconds apart)
            w.poll(5, project_names=[RLN_BOB])
            await w.reg.reconcile()
            await w.reg.reconcile()                                # the same status twice counts once
            w.poll(10)
            await w.reg.reconcile()
            assert w.reg.get('a01', RLN) is share
            w.poll(10)
            await w.reg.reconcile()
            assert w.reg.get('a01', RLN) is None and wb.sent == [out(share, 'closed')]
            assert w.reg.policy_of('a01', RLN_BOB) == 'forbidden'  # that project still runs
            # back in a status before the delay: the count starts again
            again = await w.shared()
            w.poll(5, project_names=[RLN_BOB])
            await w.reg.reconcile()
            w.poll(10, project_names=[RLN, RLN_BOB])
            await w.reg.reconcile()
            w.poll(5, project_names=[RLN_BOB])
            await w.reg.reconcile()
            w.poll(15)
            await w.reg.reconcile()
            assert w.reg.get('a01', RLN) is again
            w.poll(5)
            await w.reg.reconcile()
            assert w.reg.get('a01', RLN) is None
            # the decision of an instructor goes with its project
            w.poll(5, project_names=[])
            await w.reg.reconcile()
            w.poll(25)
            await w.reg.reconcile()
            assert w.reg.policy_of('a01', RLN_BOB) == 'default'
        run(go())

    def test_what_tells_nothing(self):
        async def go():
            w = World()
            share = await w.shared()
            # an unreachable host, an agent that names nothing: the share is kept
            for changes in ({'reachable': False, 'project_names': []}, {'reachable': True, 'project_names': None}):
                for _ in range(4):
                    w.poll(30, **changes)
                    await w.reg.reconcile()
                assert w.reg.get('a01', RLN) is share
            # the host left the pool: nothing will ever say more
            del w.status['a01']
            await w.reg.tick()
            assert w.reg.get('a01', RLN) is None
        run(go())

    def test_closed_through_the_portal(self):
        async def go():
            w = World()
            share = await w.shared()
            await w.joined(BOB)
            await w.reg.set_policy([('a01', RLN)], 'allowed')
            wb = w.page(BOB)
            await w.reg.project_closed('a01', RLN)
            assert w.reg.get('a01', RLN) is None and w.reg.policy_of('a01', RLN) == 'default'
            assert wb.sent == [out(share, 'closed')]
            await w.reg.project_closed('a01', RLN)                 # twice is nothing
        run(go())


class TestStateFile:
    def test_kept_across_a_restart(self, tmp_path):
        async def go():
            path = str(tmp_path / 'sharing.json')
            w = World(state_file=path)
            assert not os.path.exists(path)                        # nothing to keep yet
            share = await w.shared(audience=INFO1)
            await w.joined(BOB)
            await w.reg.set_policy([('a01', RLN_BOB)], 'forbidden')
            w.page(ALICE)
            waiting = await w.reg.request(DAVE, 'a01', RLN, [INFO1])
            assert os.stat(path).st_mode & 0o777 == 0o600
            kept = json.loads(open(path, encoding='utf-8').read())
            assert kept == {'version': 1, 'policies': [{'host': 'a01', 'rln': RLN_BOB, 'allowed': False}],
                            'shares': [{'id': share.id, 'host': 'a01', 'rln': RLN, 'owner': 'alice',
                                        'owner_fullname': 'Alice A', 'audience': INFO1, 'started_at': 1000.0,
                                        'lab_name': 'sre@dhcp.py', 'title': 'DHCP',
                                        'project_started_at': '2026-11-26T10:00:00',
                                        'participants': [{'login': 'bob', 'fullname': 'Bob B', 'since': 1000.0}]}]}
            # a second portal on the file: the policies, the share and its participant; no request
            again = World(state_file=path)
            back = again.reg.get('a01', RLN)
            assert (back.id, back.owner, back.owner_fullname, back.audience, back.title) == \
                (share.id, 'alice', 'Alice A', INFO1, 'DHCP')
            assert set(back.participants) == {'bob'} and back.requests == {} and back.grants == {}
            assert again.reg.policy_of('a01', RLN_BOB) == 'forbidden'
            assert again.reg.grant(BOB, 'a01', RLN) is not None and again.reg.grant(DAVE, 'a01', RLN) is None
            with pytest.raises(SH.RequestGone):
                await again.reg.accept(waiting.id, ALICE)
            # the statuses asked before the restart say nothing of what it read
            again.status['a01'].project_names = []
            await again.reg.reconcile()
            assert again.reg.get('a01', RLN) is back
            # what ends is written too
            await again.reg.stop('a01', RLN)
            await again.reg.set_policy([('a01', RLN_BOB)], 'default')
            assert json.loads(open(path, encoding='utf-8').read()) == {'version': 1, 'policies': [], 'shares': []}
        run(go())

    def test_a_share_the_default_no_longer_allows(self, tmp_path):
        """web.toml went back to no-by-default between two runs: the shares nobody allowed are
        not read back."""
        async def go():
            path = str(tmp_path / 'sharing.json')
            w = World(state_file=path)
            await w.shared()
            await w.reg.start(BOB, 'a01', RLN_BOB, 'all', row=ROW)
            await w.reg.set_policy([('a01', RLN_BOB)], 'allowed')
            again = World('no-by-default', state_file=path)
            assert again.reg.get('a01', RLN) is None and again.reg.get('a01', RLN_BOB) is not None
        run(go())

    def test_a_file_that_cannot_be_read(self, tmp_path, caplog):
        path = tmp_path / 'sharing.json'
        for text in ('{not json', '[]', '{"version": 7}'):
            path.write_text(text)
            reg = World(state_file=str(path)).reg
            assert reg.listing() == [] and not path.exists()
            assert (tmp_path / 'sharing.json.unreadable').read_text() == text      # set aside, never written over
        # entries that are not entries are skipped, the others read
        path.write_text(json.dumps({'version': 1, 'policies': [
            {'host': 'a01', 'rln': RLN, 'allowed': True}, {'host': 'a01', 'rln': 'nope', 'allowed': True},
            {'host': '', 'rln': RLN, 'allowed': True}, {'host': 'a01', 'rln': RLN_BOB, 'allowed': 'yes'}, 'x'],
            'shares': [{'host': 'a01', 'rln': RLN, 'owner': 'bob', 'audience': 'all'},          # not the owner of the name
                       {'host': 'a01', 'rln': RLN, 'owner': 'alice', 'audience': ''}, 5,
                       {'host': 'a01', 'rln': RLN, 'owner': 'alice', 'audience': 'all', 'started_at': 'x',
                        'participants': [{'login': 'bob'}, {'login': 'alice'}, {'login': '../x'}, {'login': 'bob'}, 7]}]}))
        reg = World(state_file=str(path)).reg
        share = reg.get('a01', RLN)
        assert reg.policy_of('a01', RLN) == 'allowed' and reg.policy_of('a01', RLN_BOB) == 'default'
        assert share is not None and set(share.participants) == {'bob'} and share.started_at == 0.0 and share.id

    def test_a_directory_that_cannot_be_written(self, tmp_path, caplog):
        async def go():
            w = World(state_file=str(tmp_path / 'missing' / 'sharing.json'))
            await w.shared()
            assert w.reg.state_error and w.reg.get('a01', RLN) is not None       # said, and the site goes on
            (tmp_path / 'missing').mkdir()
            await w.reg.set_policy([('a01', RLN_BOB)], 'allowed')
            assert w.reg.state_error == '' and (tmp_path / 'missing' / 'sharing.json').exists()
        run(go())

    def test_where_the_file_goes(self):
        assert SH.state_file_beside('') == ''
        assert SH.state_file_beside('/var/lib/sre-web/pool.json') == '/var/lib/sre-web/sharing.json'


# ---------------------------------------------------------------------------------------------
# through the portal: a real agent on the fake sre behind it
# ---------------------------------------------------------------------------------------------

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from sreweb.portal import routes as RT                        # noqa: E402
from sreweb.portal.accesslog import parse_line                # noqa: E402

A_ALICE = P.who('alice', 'Alice A', group='INFO1')
A_BOB = P.who('bob', 'Bob B', group='INFO1')
A_CAROL = P.who('carol', 'Carol C', group='INFO2')
A_DAVE = P.who('dave', group='INFO1')
A_PROF = P.who('prof', 'Pr. Of', groups=P.TEACHERS)
TERM = RT.TERMINAL_SUBPROTOCOL


def harness(tmp_path, allowed='yes-by-default', **over):
    web_over = {**P.PROXY_OVER, 'sharing': {'allowed': allowed}, 'limits': {'start_interval': 0, 'eval_interval': 0},
                'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False},
                'admin': {'state_file': str(tmp_path / 'pool.json')}, **over}
    return P.Harness(tmp_path, auth_mode='proxy', web_over=web_over, host_over={'max_projects': 9},
                     mock_env={'MOCK_SRE_LOG': str(tmp_path / 'mock.log')})


def calls(tmp_path) -> list:
    log = tmp_path / 'mock.log'
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def base_of(rln: str) -> str:
    return f'/api/projects/a01/{rln}'


async def call(h, method: str, path: str, user: dict, **kwargs) -> tuple:
    resp = await h.client.request(method, path, headers={**user, **P.CSRF}, **kwargs)
    if resp.content_type == 'application/json':
        return resp.status, await resp.json()
    return resp.status, await resp.read()


async def polled(h):
    """The portal has a status of the agent asked now: it knows the projects it runs."""
    await h.portal.pool.refresh()


async def share(h, rln: str, user=A_ALICE, audience='all') -> dict:
    await polled(h)
    status, view = await call(h, 'PUT', base_of(rln) + '/sharing', user, json={'audience': audience})
    assert status == 200, view
    return view


async def presence(h, user: dict, page='/projects'):
    return await h.client.ws_connect('/api/presence/ws', params={'page': page}, headers=user)


async def join(h, rln: str, user: dict, owner=A_ALICE, owner_ws=None) -> dict:
    """*user* asks, the owner accepts: the view the owner gets back."""
    ws = owner_ws if owner_ws is not None else await presence(h, owner)
    status, asked = await call(h, 'POST', base_of(rln) + '/sharing/requests', user)
    assert status == 201, asked
    pushed = await asyncio.wait_for(ws.receive_json(), 5)
    assert (pushed['t'], pushed['id']) == ('share-request', asked['id'])
    status, view = await call(h, 'POST', f"{base_of(rln)}/sharing/requests/{asked['id']}/accept", owner)
    assert status == 200, view
    ended = await asyncio.wait_for(ws.receive_json(), 5)
    assert (ended['ended'], ended['reason']) == (True, 'accepted')
    if owner_ws is None:
        await ws.close()
    return view


async def refused_socket(h, path: str, user: dict, **kwargs) -> int:
    with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
        await h.client.ws_connect(path, headers=user, **kwargs)
    return refused.value.status


async def pushed(ws, kind: str, timeout=5.0) -> dict:
    async with asyncio.timeout(timeout):
        while True:
            message = await ws.receive_json()
            if message.get('t') == kind:
                return message


class TestThroughThePortal:
    def test_the_whole_flow(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await polled(h)
                # before anything: nobody but the owner, nothing to join
                assert (await call(h, 'GET', base, A_BOB))[0] == 403
                assert (await call(h, 'GET', '/api/shares', A_BOB))[1] == {'joined': [], 'requested': [], 'joinable': []}
                assert (await call(h, 'GET', base + '/sharing', A_BOB))[0] == 404
                assert (await call(h, 'POST', base + '/sharing/requests', A_BOB))[0] == 404
                status, view = await call(h, 'GET', base + '/sharing', A_ALICE)
                assert status == 200 and view == {
                    'available': True, 'allowed': True, 'policy': 'default', 'shared': False, 'me': 'owner',
                    'max_participants': 4,
                    'audiences': [{'key': 'all', 'kind': 'all', 'name': ''},
                                  {'key': 'department:INFO1', 'kind': 'department', 'name': 'INFO1'}]}
                # only the owner shares, and only with a group of theirs
                assert (await call(h, 'PUT', base + '/sharing', A_BOB, json={'audience': 'all'}))[0] == 403
                assert (await call(h, 'PUT', base + '/sharing', A_ALICE, json={'audience': 'department:INFO2'}))[0] == 403
                assert (await call(h, 'PUT', base + '/sharing', A_ALICE, json={}))[0] == 400
                view = await share(h, rln, audience='department:INFO1')
                assert view['shared'] and view['audience'] == {'key': 'department:INFO1', 'kind': 'department', 'name': 'INFO1'}
                assert (view['lab_name'], view['owner'], view['participants'], view['requests']) == \
                    ('sre@dhcp.py', {'login': 'alice', 'fullname': 'Alice A', 'connected': False}, [], [])
                # who may ask: the students of the audience
                assert (await call(h, 'GET', '/api/shares', A_CAROL))[1]['joinable'] == []
                assert (await call(h, 'POST', base + '/sharing/requests', A_CAROL))[0] == 404
                assert (await call(h, 'GET', '/api/shares', A_PROF))[1]['joinable'] == []
                joinable = (await call(h, 'GET', '/api/shares', A_BOB))[1]['joinable']
                assert [(s['rln'], s['owner'], s['participants'], s['request'], s['audience']['name']) for s in joinable] == \
                    [(rln, {'login': 'alice', 'fullname': 'Alice A'}, 0, None, 'INFO1')]
                # the owner is not there: nobody to ask
                status, answer = await call(h, 'POST', base + '/sharing/requests', A_BOB)
                assert (status, answer['code']) == (409, 'owner_away')
                alice_ws, bob_ws = await presence(h, A_ALICE), await presence(h, A_BOB, '/open')
                status, asked = await call(h, 'POST', base + '/sharing/requests', A_BOB)
                assert status == 201 and asked['rln'] == rln
                request = await asyncio.wait_for(alice_ws.receive_json(), 5)
                assert (request['t'], request['id'], request['from'], request['rln'], request['lab']) == \
                    ('share-request', asked['id'], {'login': 'bob', 'fullname': 'Bob B'}, rln, 'sre@dhcp.py')
                assert (await call(h, 'GET', '/api/shares', A_BOB))[1]['requested'][0]['request'] == asked['id']
                assert (await call(h, 'GET', base + '/sharing', A_ALICE))[1]['requests'][0]['login'] == 'bob'
                assert (await call(h, 'GET', base, A_BOB))[0] == 403                    # asking is not being in
                # only the owner answers, and only once
                accept = f"{base}/sharing/requests/{asked['id']}/accept"
                assert (await call(h, 'POST', accept, A_BOB))[0] == 403
                assert (await call(h, 'POST', accept.replace(rln, rln.replace('alice', 'bob')), A_ALICE))[0] in (404, 410)
                status, view = await call(h, 'POST', accept, A_ALICE)
                assert status == 200 and [(p['login'], p['fullname']) for p in view['participants']] == [('bob', 'Bob B')]
                assert (await call(h, 'POST', accept, A_ALICE))[0] == 410
                for ws in (alice_ws, bob_ws):
                    ended = await asyncio.wait_for(ws.receive_json(), 5)
                    assert (ended['id'], ended['ended'], ended['reason']) == (asked['id'], True, 'accepted')
                    assert ended['url'] == project_page_url('a01', rln)
                # the participant is in: the page, the project as the owner sees it
                assert (await h.client.get(f'/projects/a01/{rln}', headers=A_BOB)).status == 200
                status, project = await call(h, 'GET', base, A_BOB)
                assert status == 200 and project['participant'] is True and project['owner'] == 'alice'
                assert (await call(h, 'GET', base, A_ALICE))[1]['participant'] is False
                status, view = await call(h, 'GET', base + '/sharing', A_BOB)
                assert status == 200 and view['me'] == 'participant' and 'requests' not in view and 'audiences' not in view
                assert (await call(h, 'GET', '/api/shares', A_BOB))[1]['joined'][0]['rln'] == rln
                # answers and evaluation: the owner's file, the owner's sre
                assert (await call(h, 'PUT', base + '/answers', A_BOB, json={'answers': {P.TEXT_HASH: 'bob was here'}}))[0] == 200
                on_disk = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert (on_disk['login'], on_disk['fullname'], on_disk[P.TEXT_HASH]) == ('alice', 'Alice A', 'bob was here')
                assert (await call(h, 'POST', base + '/eval', A_BOB))[0] == 200
                last = calls(tmp_path)[-1]
                assert last['argv'] == ['--user', 'eval', '--auto-eval', '--', rln] and last['username'] == 'alice'
                assert (await call(h, 'POST', base + '/states/final', A_BOB))[0] == 200
                # what stays the owner's
                assert (await call(h, 'DELETE', base, A_BOB))[0] == 403
                assert (await call(h, 'GET', base + '/evaluation', A_BOB))[0] == 403
                assert (await call(h, 'GET', base + '/log', A_BOB))[0] == 403
                assert (await call(h, 'PUT', base + '/sharing', A_BOB, json={'audience': 'all'}))[0] == 403
                assert (await call(h, 'DELETE', base + '/sharing', A_BOB))[0] == 403
                assert h.agent.registry.get(rln) is not None
                # the Watch page counts them; the participant's page on the project is seen
                bob_page = await presence(h, A_BOB, project_page_url('a01', rln))
                row = next(r for r in (await call(h, 'GET', '/api/watch', A_PROF))[1] if r['running_lab_name'] == rln)
                assert row['sharing'] == {'available': True, 'allowed': True, 'policy': 'default', 'shared': True,
                                          'audience': 'department:INFO1', 'participants': 1, 'connected': 1}
                assert row['closing'] is False
                assert (await call(h, 'GET', base + '/sharing', A_PROF))[1]['me'] == 'instructor'
                view = (await call(h, 'GET', base + '/sharing', A_ALICE))[1]
                assert [(p['login'], p['connected']) for p in view['participants']] == [('bob', True)]
                # the state is kept beside the state file of the pool
                kept = json.loads((tmp_path / 'sharing.json').read_text())
                assert [(s['rln'], [p['login'] for p in s['participants']]) for s in kept['shares']] == [(rln, ['bob'])]
                for ws in (alice_ws, bob_ws, bob_page):
                    await ws.close()
        run(go())

    def test_a_participant_removed_is_cut_at_once(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await share(h, rln)
                await join(h, rln, A_BOB)
                await join(h, rln, A_DAVE)
                events = await h.client.ws_connect(base + '/events', headers=A_BOB)
                term = await h.client.ws_connect(base + '/terminals/m1', headers=A_BOB, protocols=(TERM,))
                assert (await T.receive_text(term, 'ready'))['joined'] is False
                await term.send_bytes(b'echo HELLO\n')
                dave_events = await h.client.ws_connect(base + '/events', headers=A_DAVE)
                bob_ws = await presence(h, A_BOB, project_page_url('a01', rln))
                share_id = h.portal.sharing.get('a01', rln).id
                # a participant does not take another one out; the owner does
                assert (await call(h, 'DELETE', base + '/sharing/participants/dave', A_BOB))[0] == 403
                assert (await call(h, 'DELETE', base + '/sharing/participants/carol', A_ALICE))[0] == 404
                status, view = await call(h, 'DELETE', base + '/sharing/participants/bob', A_ALICE)
                assert status == 200 and [p['login'] for p in view['participants']] == ['dave']
                # closed from another task than their handler: the code is the CLOSE frame's
                assert (await T.receive_close(events)).data == SH.WS_SHARE_ENDED
                async with asyncio.timeout(5):
                    while True:
                        msg = await term.receive()
                        if msg.type == aiohttp.WSMsgType.CLOSE:
                            break
                assert msg.data == SH.WS_SHARE_ENDED
                told = await pushed(bob_ws, 'share')
                assert told == {'t': 'share', 'id': share_id, 'host': 'a01', 'rln': rln,
                                'owner': {'login': 'alice', 'fullname': 'Alice A'}, 'title': told['title'],
                                'ended': True, 'reason': 'removed'}
                # ... and out for good: every call, every socket; the page sends them home
                assert (await call(h, 'GET', base, A_BOB))[0] == 403
                assert (await call(h, 'PUT', base + '/answers', A_BOB, json={'answers': {}}))[0] == 403
                assert await refused_socket(h, base + '/events', A_BOB) == 403
                assert await refused_socket(h, base + '/terminals/m1', A_BOB, protocols=(TERM,)) == 403
                page = await h.client.get(f'/projects/a01/{rln}', headers=A_BOB, allow_redirects=False)
                assert page.status == 302 and page.headers['Location'] == '/projects'
                assert (await h.client.get(f'/projects/a01/{rln}', headers=A_CAROL, allow_redirects=False)).status == 403
                # the other participant is untouched; the terminal bob opened stays for the others
                assert (await call(h, 'GET', base, A_DAVE))[0] == 200 and not dave_events.closed
                assert [t['created_by'] for t in (await call(h, 'GET', base, A_ALICE))[1]['terminals']] == ['bob']
                # dave leaves by himself, an instructor stops what is left
                assert (await call(h, 'DELETE', base + '/sharing/participants/dave', A_DAVE)) == (200, {'ok': True})
                assert (await T.receive_close(dave_events)).data == SH.WS_SHARE_ENDED
                await join(h, rln, A_DAVE)
                status, view = await call(h, 'DELETE', base + '/sharing', A_PROF)
                assert status == 200 and view['shared'] is False and view['me'] == 'instructor'
                # the log says who stopped whose sharing, and how many were sent out
                stop = [line for line in map(parse_line, (tmp_path / 'access.log').read_text().splitlines())
                        if line['event'] == 'share_stop'][-1]
                assert (stop['login'], stop['owner'], stop['count']) == ('prof', 'alice', '1')
                assert (await call(h, 'GET', base, A_DAVE))[0] == 403
                assert (await call(h, 'GET', '/api/shares', A_DAVE))[1]['joined'] == []
                await bob_ws.close()
        run(go())

    def test_a_socket_being_opened_while_the_participant_is_removed(self, tmp_path):
        """The request is checked, then the socket to the agent is opened (awaits), then the
        browser's is accepted: a removal in between must not leave a live socket behind."""
        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await share(h, rln)
                await join(h, rln, A_BOB)
                session = h.portal.relay.session
                entered, release, real = asyncio.Event(), asyncio.Event(), session.ws_connect

                async def held(*args, **kwargs):
                    entered.set()
                    await release.wait()
                    return await real(*args, **kwargs)

                session.ws_connect = held
                try:
                    opening = asyncio.ensure_future(h.client.ws_connect(base + '/events', headers=A_BOB))
                    await asyncio.wait_for(entered.wait(), 5)
                    assert (await call(h, 'DELETE', base + '/sharing/participants/bob', A_ALICE))[0] == 200
                    release.set()
                    ws = await asyncio.wait_for(opening, 5)
                finally:
                    session.ws_connect = real
                closing = await asyncio.wait_for(ws.receive(), 5)
                assert closing.type == aiohttp.WSMsgType.CLOSE and closing.data == SH.WS_SHARE_ENDED
                assert h.portal.sharing.get('a01', rln).grants == {}
        run(go())

    def test_no_by_default_and_the_policy_of_the_watch_page(self, tmp_path):
        async def go():
            async with harness(tmp_path, allowed='no-by-default') as h:
                rln = await T.start_project(h, A_ALICE)
                other = await T.start_project(h, A_BOB)
                base = base_of(rln)
                await polled(h)
                view = (await call(h, 'GET', base + '/sharing', A_ALICE))[1]
                assert (view['allowed'], view['policy'], view['shared']) == (False, 'default', False)
                status, answer = await call(h, 'PUT', base + '/sharing', A_ALICE, json={'audience': 'all'})
                assert (status, answer['code']) == (403, 'not_allowed')
                # the Watch page: instructors only, a well-formed selection
                both = [{'host': 'a01', 'rln': rln}, {'host': 'a01', 'rln': other}]
                body = {'projects': both, 'policy': 'allowed'}
                assert (await call(h, 'POST', '/api/watch/sharing', A_ALICE, json=body))[0] == 403
                for bad in ({}, {'projects': [], 'policy': 'allowed'}, {'projects': 'all', 'policy': 'allowed'},
                            {'projects': [{'host': 'a01', 'rln': 'nope'}], 'policy': 'allowed'},
                            {'projects': both, 'policy': 'maybe'}, {'projects': both}):
                    assert (await call(h, 'POST', '/api/watch/sharing', A_PROF, json=bad))[0] == 400, bad
                unknown = {'projects': [{'host': 'nope', 'rln': rln}], 'policy': 'allowed'}
                assert (await call(h, 'POST', '/api/watch/sharing', A_PROF, json=unknown))[0] == 404
                assert await call(h, 'POST', '/api/watch/sharing', A_PROF, json=body) == (200, {'changed': 2, 'skipped': 0})
                assert await call(h, 'POST', '/api/watch/sharing', A_PROF, json=body) == (200, {'changed': 0, 'skipped': 0})
                rows = {r['running_lab_name']: r['sharing'] for r in (await call(h, 'GET', '/api/watch', A_PROF))[1]}
                assert {(v['allowed'], v['policy'], v['shared']) for v in rows.values()} == {(True, 'allowed', False)}
                await share(h, rln)
                await join(h, rln, A_BOB)
                events = await h.client.ws_connect(base + '/events', headers=A_BOB)
                # forbidden: the share ends, the participant is cut, the owner cannot start again
                one = {'projects': [{'host': 'a01', 'rln': rln}], 'policy': 'forbidden'}
                assert await call(h, 'POST', '/api/watch/sharing', A_PROF, json=one) == (200, {'changed': 1, 'skipped': 0})
                assert (await T.receive_close(events)).data == SH.WS_SHARE_ENDED
                assert (await call(h, 'GET', base, A_BOB))[0] == 403
                assert (await call(h, 'PUT', base + '/sharing', A_ALICE, json={'audience': 'all'}))[0] == 403
                row = next(r for r in (await call(h, 'GET', '/api/watch', A_PROF))[1] if r['running_lab_name'] == rln)
                assert (row['sharing']['policy'], row['sharing']['shared'], row['sharing']['participants']) == \
                    ('forbidden', False, 0)
                # back to the default of the site: not allowed here
                back = {'projects': both, 'policy': 'default'}
                assert await call(h, 'POST', '/api/watch/sharing', A_PROF, json=back) == (200, {'changed': 2, 'skipped': 0})
                assert (await call(h, 'GET', base + '/sharing', A_ALICE))[1]['allowed'] is False
        run(go())

    def test_what_is_never_shared(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                debug = await T.start_project(h, A_PROF, debug_project=True)
                teaching = await T.start_project(h, A_PROF, lab='s4/tp_ssh', instructor_mode=True)
                plain = await T.start_project(h, A_PROF)
                await polled(h)
                for rln in (debug, teaching):
                    status, answer = await call(h, 'PUT', base_of(rln) + '/sharing', A_PROF, json={'audience': 'all'})
                    assert (status, answer['code']) == (409, 'not_shareable'), rln
                rows = {r['running_lab_name']: r['sharing']['available'] for r in (await call(h, 'GET', '/api/watch', A_PROF))[1]}
                assert rows == {debug: False, teaching: False, plain: True}
                # a standard project of an instructor is a project like another
                assert (await share(h, plain, A_PROF))['shared'] is True
                # a project that does not run
                gone = '2020' + plain[4:]
                assert (await call(h, 'PUT', base_of(gone) + '/sharing', A_PROF, json={'audience': 'all'}))[0] == 404
        run(go())

    def test_an_exam_binds_one_of_them(self, tmp_path, monkeypatch):
        monkeypatch.setattr(SH, 'TICK', 0.05)

        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await share(h, rln)
                await join(h, rln, A_BOB)
                events = await h.client.ws_connect(base + '/events', headers=A_BOB)
                bound = set()
                h.portal.sharing.bound = lambda login, group: login in bound
                bound.add('bob')
                # no access from the first request on, cut by the next tick
                assert (await call(h, 'GET', base, A_BOB))[0] == 403
                assert (await T.receive_close(events)).data == SH.WS_SHARE_ENDED
                assert h.portal.sharing.get('a01', rln).participants == {}
                # the routes of the sharing themselves: nothing for a student in an exam
                h.portal.routes._exam_binding = lambda identity: object() if identity.login in bound else None
                assert (await call(h, 'GET', '/api/shares', A_BOB))[1] == {'joined': [], 'requested': [], 'joinable': []}
                assert (await call(h, 'POST', base + '/sharing/requests', A_BOB))[0] == 403
                assert (await call(h, 'GET', base + '/sharing', A_BOB))[0] == 403
        run(go())

    def test_the_project_closes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(SH, 'TICK', 0.05)
        monkeypatch.setattr(SH, 'GONE_AFTER', 0.3)

        async def go():
            async with harness(tmp_path) as h:
                # closed through the portal: the share ends with the answer
                rln = await T.start_project(h, A_ALICE)
                await share(h, rln)
                await join(h, rln, A_BOB)
                bob_ws = await presence(h, A_BOB)
                assert (await call(h, 'DELETE', base_of(rln), A_ALICE))[0] == 200
                assert (await pushed(bob_ws, 'share'))['reason'] == 'closed'
                assert h.portal.sharing.get('a01', rln) is None
                assert (await call(h, 'GET', '/api/shares', A_BOB))[1]['joined'] == []
                # closed behind the portal (the idle reaper of the agent, an exam): the statuses
                # of the host no longer name it, the share goes after the delay
                rln = await T.start_project(h, A_ALICE)
                await share(h, rln)
                await join(h, rln, A_BOB)
                await h.portal.sharing.set_policy([('a01', rln)], 'allowed')
                await h.agent.schedulers.close_project(h.agent.registry.get(rln))
                await h.agent.registry.tick()
                assert (await pushed(bob_ws, 'share', timeout=10))['reason'] == 'closed'
                assert h.portal.sharing.get('a01', rln) is None and h.portal.sharing.policy_of('a01', rln) == 'default'
                await bob_ws.close()
        run(go())

    def test_the_evaluation_is_shown_to_the_others(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await share(h, rln)
                await join(h, rln, A_BOB)
                alice = await h.client.ws_connect(base + '/events', headers=A_ALICE)
                status, answer = await call(h, 'POST', base + '/eval', A_BOB)
                assert status == 200 and answer['rows']
                event = await pushed(alice, 'self_evaluation')
                assert event['by'] == {'login': 'bob', 'fullname': 'Bob B'} and event['result'] == answer['result']
                await alice.close()
        run(go())

    def test_the_owners_budget_of_evaluations(self, tmp_path):
        """The portal's own pause between two evaluations is the project's: a participant
        evaluates on the owner's."""
        async def go():
            async with harness(tmp_path, limits={'start_interval': 0, 'eval_interval': 60}) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await share(h, rln)
                await join(h, rln, A_BOB)
                assert (await call(h, 'POST', base + '/eval', A_BOB))[0] == 200
                assert (await call(h, 'POST', base + '/eval', A_ALICE))[0] == 429
                assert (await call(h, 'POST', base + '/eval', A_BOB))[0] == 429
                # bob's own projects keep bob's own budget
                mine = await T.start_project(h, A_BOB)
                assert (await call(h, 'POST', base_of(mine) + '/eval', A_BOB))[0] == 200
        run(go())

    def test_a_participant_in_the_audience_of_a_presentation(self, tmp_path):
        """The page of a presentation says so on its calls: there the participant is a spectator
        (the presenter's read-only view), on their own page a participant."""
        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await share(h, rln)
                await join(h, rln, A_BOB)
                # no presentation: the marked call is nobody's
                assert (await call(h, 'GET', base + '?presentation=x', A_BOB))[0] == 403
                shown = await T.present(h, A_PROF, rln, {'logins': ['bob'], 'groups': []})
                status, project = await call(h, 'GET', base + f"?presentation={shown['id']}", A_BOB)
                assert status == 200 and project['participant'] is False          # the presenter's view
                assert (await call(h, 'PUT', base + f"/answers?presentation={shown['id']}", A_BOB,
                                   json={'answers': {}}))[0] == 403
                status, project = await call(h, 'GET', base, A_BOB)
                assert status == 200 and project['participant'] is True
                assert (await call(h, 'PUT', base + '/answers', A_BOB, json={'answers': {}}))[0] == 200
        run(go())


class TestRouteMatrix:
    #: what stays the owner's and the instructors' (403 for a participant)
    OWNERS = {('DELETE', '/api/projects/{host}/{rln}'), ('POST', '/api/projects/{host}/{rln}/save'),
              ('GET', '/api/projects/{host}/{rln}/log'), ('GET', '/api/projects/{host}/{rln}/evaluation')}
    #: the routes of the sharing itself, each with its own gate
    SHARING = {('GET', '/api/projects/{host}/{rln}/sharing'), ('PUT', '/api/projects/{host}/{rln}/sharing'),
               ('DELETE', '/api/projects/{host}/{rln}/sharing'),
               ('DELETE', '/api/projects/{host}/{rln}/sharing/participants/{login}'),
               ('POST', '/api/projects/{host}/{rln}/sharing/requests'),
               ('POST', '/api/projects/{host}/{rln}/sharing/requests/{id}/accept'),
               ('POST', '/api/projects/{host}/{rln}/sharing/requests/{id}/decline'),
               ('DELETE', '/api/projects/{host}/{rln}/sharing/requests/{id}')}
    SOCKETS = ('/events', '/display/ws', '/terminals/{device}')

    @staticmethod
    def path_of(canonical: str, rln: str) -> str:
        return (canonical.replace('{host}', 'a01').replace('{rln}', rln).replace('{state}', 'final')
                .replace('{device}', 'm1').replace('{login}', 'bob').replace('{id}', 'x'))

    def test_every_route_of_a_project_has_a_decision(self, tmp_path):
        """A route added to a project without a decision for the participants fails here."""
        async def go():
            async with harness(tmp_path) as h:
                routes = {(route.method, route.resource.canonical) for route in h.client.app.router.routes()
                          if route.resource is not None and route.method != 'HEAD'
                          and route.resource.canonical.startswith(('/api/projects/{host}/{rln}', '/projects/{host}/{rln}'))}
                decided = RT.PARTICIPANT_ROUTES | self.OWNERS | self.SHARING
                assert routes == decided, sorted(routes ^ decided)
                assert not RT.PARTICIPANT_ROUTES & self.OWNERS
                # a spectator never does more than a participant, but for the log of a debug project
                assert RT.SPECTATOR_ROUTES - RT.PARTICIPANT_ROUTES == {('GET', '/api/projects/{host}/{rln}/log')}
        run(go())

    def test_by_role(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                await share(h, rln)
                await join(h, rln, A_BOB)
                await join(h, rln, A_DAVE)
                assert (await call(h, 'DELETE', base_of(rln) + '/sharing/participants/dave', A_ALICE))[0] == 200

                async def status(user, method, canonical):
                    path = self.path_of(canonical, rln)
                    if canonical.endswith(self.SOCKETS):
                        try:
                            ws = await h.client.ws_connect(path, headers=user, protocols=(TERM, RT.DISPLAY_SUBPROTOCOL))
                        except aiohttp.WSServerHandshakeError as e:
                            return e.status
                        await ws.close()
                        return 101
                    return (await call(h, method, path, user, json={'answers': {}}, allow_redirects=False))[0]

                # the display of a lab without one answers 404 to its owner too: not a refusal
                for method, canonical in sorted(RT.PARTICIPANT_ROUTES):
                    for user in (A_CAROL, A_DAVE):                        # a stranger, a participant removed
                        got = await status(user, method, canonical)
                        assert got in (302, 403), (user['X-Remote-User'], method, canonical, got)
                    got = await status(A_BOB, method, canonical)
                    assert got not in (401, 403), (method, canonical, got)
                for method, canonical in sorted(self.OWNERS):
                    for user in (A_BOB, A_CAROL, A_DAVE):
                        got = await status(user, method, canonical)
                        # the saved projects are off on this site: 404 for everybody, before anything
                        assert got == (404 if canonical.endswith('/save') else 403), (user['X-Remote-User'], canonical, got)
                assert h.agent.registry.get(rln) is not None
        run(go())


class TestBulkClose:
    def test_projects_closed_in_one_go(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                first = await T.start_project(h, A_ALICE)
                second = await T.start_project(h, A_BOB)
                kept = await T.start_project(h, A_CAROL)
                await share(h, first)
                await join(h, first, A_DAVE)
                body = {'projects': [{'host': 'a01', 'rln': first}, {'host': 'a01', 'rln': second},
                                     {'host': 'a01', 'rln': first}]}
                assert (await call(h, 'POST', '/api/watch/close', A_ALICE, json=body))[0] == 403
                assert (await call(h, 'GET', '/api/watch/close', A_ALICE))[0] == 403
                assert (await call(h, 'POST', '/api/watch/close', A_PROF, json={'projects': []}))[0] == 400
                assert await call(h, 'GET', '/api/watch/close', A_PROF) == (200, {'job': None})
                status, answer = await call(h, 'POST', '/api/watch/close', A_PROF, json=body)
                assert status == 202 and (answer['job']['total'], answer['job']['running']) == (2, True)
                # meanwhile: the rows are told, a second job of the same instructor waits
                rows = {r['running_lab_name']: r['closing'] for r in (await call(h, 'GET', '/api/watch', A_PROF))[1]}
                assert rows.get(kept) is False and all(rows[r] for r in (first, second) if r in rows)
                assert (await call(h, 'POST', '/api/watch/close', A_PROF, json=body))[0] == 409
                async with asyncio.timeout(20):
                    while True:
                        job = (await call(h, 'GET', '/api/watch/close', A_PROF))[1]['job']
                        if not job['running']:
                            break
                        await asyncio.sleep(0.05)
                assert (job['total'], job['done'], job['closed'], job['failed'], job['errors']) == (2, 2, 2, 0, [])
                await h.agent.registry.tick()
                assert set(h.agent.registry.projects) == {kept}
                # the sharing of a project closed this way ended with it
                assert h.portal.sharing.get('a01', first) is None
                # a project already gone counts as closed
                status, answer = await call(h, 'POST', '/api/watch/close', A_PROF,
                                            json={'projects': [{'host': 'a01', 'rln': first}]})
                assert status == 202
                async with asyncio.timeout(10):
                    while (await call(h, 'GET', '/api/watch/close', A_PROF))[1]['job']['running']:
                        await asyncio.sleep(0.05)
                job = (await call(h, 'GET', '/api/watch/close', A_PROF))[1]['job']
                assert (job['closed'], job['failed']) == (1, 0)
        run(go())

    def test_a_project_that_does_not_close(self, tmp_path):
        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over={**P.PROXY_OVER, 'limits': {'start_interval': 0}},
                                 mock_env={'MOCK_FAIL': 'stop'}) as h:
                rln = await T.start_project(h, A_ALICE)
                status, answer = await call(h, 'POST', '/api/watch/close', A_PROF,
                                            json={'projects': [{'host': 'a01', 'rln': rln}]})
                assert status == 202
                async with asyncio.timeout(20):
                    while (await call(h, 'GET', '/api/watch/close', A_PROF))[1]['job']['running']:
                        await asyncio.sleep(0.05)
                job = (await call(h, 'GET', '/api/watch/close', A_PROF))[1]['job']
                assert (job['closed'], job['failed']) == (0, 1)
                assert [(e['host'], e['rln']) for e in job['errors']] == [('a01', rln)] and job['errors'][0]['error']
                rows = (await call(h, 'GET', '/api/watch', A_PROF))[1]
                assert [r['closing'] for r in rows if r['running_lab_name'] == rln] in ([False], [])
        run(go())


class TestSiteWithoutSharing:
    def test_anonymous_mode(self, tmp_path):
        """The pseudonyms of the anonymous mode name nobody an owner could accept: no sharing."""
        async def go():
            async with P.Harness(tmp_path) as h:
                await h.login()
                result = await h.start()
                rln = result['running_lab_name']
                for method, path in (('GET', '/api/shares'), ('GET', base_of(rln) + '/sharing'),
                                     ('PUT', base_of(rln) + '/sharing'), ('POST', base_of(rln) + '/sharing/requests')):
                    resp = await h.client.request(method, path, headers=P.CSRF, json={'audience': 'all'})
                    assert resp.status == 404, (method, path)
        run(go())


class TestAccessLog:
    def test_lines(self, tmp_path):
        async def go():
            async with harness(tmp_path) as h:
                rln = await T.start_project(h, A_ALICE)
                base = base_of(rln)
                await share(h, rln, audience='department:INFO1')
                alice_ws = await presence(h, A_ALICE)
                status, asked = await call(h, 'POST', base + '/sharing/requests', A_DAVE)
                await call(h, 'POST', f"{base}/sharing/requests/{asked['id']}/decline", A_ALICE)
                status, asked = await call(h, 'POST', base + '/sharing/requests', A_BOB)
                await call(h, 'POST', f"{base}/sharing/requests/{asked['id']}/accept", A_ALICE)
                assert (await call(h, 'GET', base, A_BOB))[0] == 200
                events = await h.client.ws_connect(base + '/events', headers=A_BOB)
                await call(h, 'DELETE', base + '/sharing/participants/bob', A_ALICE)
                await T.receive_close(events)
                await call(h, 'DELETE', base + '/sharing', A_ALICE)
                await call(h, 'POST', '/api/watch/sharing', A_PROF,
                           json={'projects': [{'host': 'a01', 'rln': rln}], 'policy': 'forbidden'})
                await call(h, 'POST', '/api/watch/close', A_PROF, json={'projects': [{'host': 'a01', 'rln': rln}]})
                async with asyncio.timeout(20):
                    while (await call(h, 'GET', '/api/watch/close', A_PROF))[1]['job']['running']:
                        await asyncio.sleep(0.05)
                await alice_ws.close()
                return rln

        rln = run(go())
        lines = [parse_line(line) for line in (tmp_path / 'access.log').read_text().splitlines()]
        by_event = {}
        for line in lines:
            by_event.setdefault(line['event'], []).append(line)
        start = by_event['share_start'][0]
        assert (start['login'], start['host'], start['rln'], start['audience'], start['status']) == \
            ('alice', 'a01', rln, 'department:INFO1', '200')
        assert [(l['login'], l['owner'], l['status']) for l in by_event['share_request']] == \
            [('dave', 'alice', '201'), ('bob', 'alice', '201')]
        assert [(l['login'], l['member']) for l in by_event['share_decline']] == [('alice', 'dave')]
        assert [(l['login'], l['member']) for l in by_event['share_accept']] == [('alice', 'bob')]
        assert [(l['login'], l['member'], l['reason']) for l in by_event['share_remove']] == [('alice', 'bob', 'removed')]
        assert [(l['login'], l['rln'], l['count']) for l in by_event['share_stop']] == [('alice', rln, '0')]
        assert [(l['login'], l['policy'], l['count'], l['selected']) for l in by_event['share_policy']] == \
            [('prof', 'forbidden', '1', '1')]
        assert [(l['login'], l['count']) for l in by_event['bulk_close']] == [('prof', '1')]
        # the calls of a participant on the project are marked
        # the calls of a participant on the project are marked (on the close line of a socket,
        # as for a spectator); the code of that line is the one the browser answered the close
        # with (a browser echoes the 4413 it got, the test client says 1000)
        closed = [l for l in by_event['project_close'] if l['login'] == 'bob']
        assert [l['participant'] for l in closed] == ['1']
        assert not [l for l in by_event['project_close'] if l['login'] == 'alice' and 'participant' in l]
        # the polls are not counted as requests of the session; nothing denied was logged as such
        assert not [l for l in lines if l['event'] == 'denied' and '/sharing' in l.get('path', '')]
