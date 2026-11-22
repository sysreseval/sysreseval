"""The costs of the labs (sreweb.portal.costs): what a project of each lab is counted for on a
host, learned from what the agents measure and from the weights the labs declare; the load of a
host in the same units; and the pool feeding and keeping them."""
import asyncio
import json
import logging
import time

import pytest

pytest.importorskip('aiohttp')

from dataclasses import replace  # noqa: E402

from test_pool_manager import FakeSession, up, view, TOKEN  # noqa: E402 (it puts src/ on the path)
from sreweb.config import HostConfig, PoolConfig, check_priority  # noqa: E402
from sreweb.identity import Identity, ROLE_INSTRUCTOR  # noqa: E402
from sreweb.portal.manager import PoolManager, free_slots, spare_capacity, wake_plan  # noqa: E402
from sreweb.portal import costs as C  # noqa: E402
from sreweb.portal.costs import (Cost, CostBook, HostLoad, Usage, host_load, quantile, lab_key, figure,  # noqa: E402
                                 SOURCE_MEASURED, SOURCE_DECLARED, SOURCE_DEFAULT, MIN_SAMPLES, MAX_SAMPLES)
from sreweb.portal.pool import (Pool, HostStatus, PoolError, usage_fields, status_from_json, MAX_USAGE,  # noqa: E402
                                PLACEMENT_NAMED, STATE_UP, STATE_OFF)

LAB = 'sre/dhcp.py'


def usage(name, lab=LAB, mem=100.0, cpu=0.1, containers=5, settled=True):
    return Usage(name=name, lab=lab, containers=containers, mem_mb=mem, cpu=cpu, settled=settled)


def book(**more):
    return CostBook(default=Cost(512.0, 0.2), unit=Cost(16.0, 0.01), **more)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------------------------
# the book
# ---------------------------------------------------------------------------------------------

class TestHelpers:
    def test_quantile(self):
        assert quantile([7], 0.8) == 7
        assert quantile([10, 20], 0.5) == 15
        assert quantile([3, 1, 2], 0.8) == pytest.approx(2.6)        # between the two largest
        assert quantile(range(1, 11), 0.8) == pytest.approx(8.2)
        assert quantile([5, 5, 5, 900], 0.8) == pytest.approx(363.0)
        assert quantile([4, 8], 0) == 4 and quantile([4, 8], 1) == 8

    def test_lab_key(self):
        assert lab_key('sre@dhcp.py') == lab_key('sre/dhcp.py') == 'sre/dhcp.py'
        assert lab_key('s3@r306@tp') == 's3/r306/tp'

    @pytest.mark.parametrize('value, expected', [(3, 3.0), (2.5, 2.5), (0, 0.0), (-1, None), (True, None),
                                                 ('3', None), (None, None), (float('nan'), None),
                                                 (float('inf'), None), (1e9, None)])
    def test_figure(self, value, expected):
        assert figure(value) == expected


class TestCostOfALab:
    def test_default_for_a_lab_never_heard_of(self):
        b = book()
        assert b.resolve('never/seen.py') == (Cost(512.0, 0.2), SOURCE_DEFAULT)
        assert b.resolve(None) == (Cost(512.0, 0.2), SOURCE_DEFAULT) and b.cost('') == Cost(512.0, 0.2)
        assert b.labs == {}                                         # asking creates nothing

    def test_declared_weight(self):
        b = book()
        b.declare([{'name': LAB, 'kind': 'lab', 'weight': 15}, {'name': 'sre', 'kind': 'dir'},
                   {'name': 'sre/big.py', 'kind': 'lab', 'weight': 105.5}, {'name': 'sre/none.py', 'kind': 'lab'}])
        assert b.resolve(LAB) == (Cost(240.0, 0.15), SOURCE_DECLARED)
        assert b.cost('sre@dhcp.py') == Cost(240.0, 0.15)           # the name as a project carries it
        assert b.cost('sre/big.py') == Cost(1688.0, 1.055)
        assert b.resolve('sre/none.py')[1] == SOURCE_DEFAULT and 'sre/none.py' not in b.labs

    def test_a_list_without_weights_erases_nothing(self):
        """An older host, or a lab tree whose titles.json was not made again."""
        b = book()
        b.declare([{'name': LAB, 'kind': 'lab', 'weight': 15}])
        b.declare([{'name': LAB, 'kind': 'lab'}, {'name': LAB, 'kind': 'lab', 'weight': 'heavy'},
                   {'name': LAB, 'kind': 'lab', 'weight': -3}, 'junk', {'kind': 'lab', 'weight': 4},
                   {'name': '', 'weight': 4}, {'name': 7, 'weight': 4}])
        assert b.labs[LAB].weight == 15 and list(b.labs) == [LAB]
        b.declare([{'name': LAB, 'kind': 'lab', 'weight': 20}])     # a new weight replaces the old one
        assert b.cost(LAB) == Cost(320.0, 0.2)

    def test_measured_from_three_projects(self):
        b = book()
        b.declare([{'name': LAB, 'weight': 15}])                    # 240 MiB, 0.15 core declared
        b.observe([usage('p1', mem=100, cpu=0.05)], 10)
        # one project, then two: too few to trust alone, never below what they used
        assert b.resolve(LAB) == (Cost(240.0, 0.15), SOURCE_DECLARED)
        b.observe([usage('p2', mem=400, cpu=0.30)], 11)
        assert b.resolve(LAB) == (Cost(400.0, 0.30), SOURCE_DECLARED)
        b.observe([usage('p3', mem=200, cpu=0.10)], 12)
        assert len(b.labs[LAB].samples) == MIN_SAMPLES
        cost, source = b.resolve(LAB)
        assert source == SOURCE_MEASURED                            # the weight no longer counts
        assert cost == (pytest.approx(320.0), pytest.approx(0.22))  # the 80th percentile of each

    def test_measured_without_any_weight(self):
        b = book()
        b.observe([usage('p1', lab='x.py', mem=900, cpu=0.01)], 10)
        assert b.resolve('x.py') == (Cost(900.0, 0.2), SOURCE_DEFAULT)      # the default, raised
        b.observe([usage('p2', lab='x.py', mem=50, cpu=0.01), usage('p3', lab='x.py', mem=50, cpu=0.01)], 11)
        assert b.resolve('x.py')[1] == SOURCE_MEASURED

    def test_one_runaway_project_does_not_make_the_cost(self):
        b = book()
        rows = [usage(f'p{i}', mem=100, cpu=0.1) for i in range(9)] + [usage('mad', mem=9000, cpu=7.5)]
        b.observe(rows, 10)
        assert b.cost(LAB) == (pytest.approx(100.0), pytest.approx(0.1))

    def test_never_less_than_the_floor(self):
        b = book()
        b.declare([{'name': 'tiny.py', 'weight': 0}])
        assert b.cost('tiny.py') == C.MIN_COST
        b.observe([usage(f'p{i}', lab='idle.py', mem=0.5, cpu=0.0) for i in range(3)], 10)
        assert b.cost('idle.py') == C.MIN_COST
        assert CostBook(default=Cost(0, 0)).default == C.MIN_COST

    def test_only_settled_projects_with_figures_are_learned(self):
        b = book()
        b.observe([usage('starting', settled=False), usage('nomem', mem=None), usage('nocpu', cpu=None)], 10)
        assert b.labs == {} and not b.dirty

    def test_a_running_project_is_one_sample(self):
        """Seen at every poll: its memory the most it used, its processors the mean it tells now."""
        b = book()
        b.observe([usage('p1', mem=100, cpu=0.5, containers=4)], 10)
        b.observe([usage('p1', mem=300, cpu=0.2, containers=5)], 20)
        b.observe([usage('p1', mem=150, cpu=0.1, containers=5)], 30)
        assert b.labs[LAB].samples == {'p1': C.Sample(mem_mb=300, cpu=0.1, containers=5, at=30)}

    def test_the_last_projects_are_kept(self):
        b = book()
        for i in range(MAX_SAMPLES + 5):
            b.observe([usage(f'p{i}', mem=float(i))], 100 + i)
        samples = b.labs[LAB].samples
        assert len(samples) == MAX_SAMPLES and list(samples)[0] == 'p5' and list(samples)[-1] == f'p{MAX_SAMPLES + 4}'
        b.observe([usage('p5', mem=1.0)], 999)                      # measured again: the newest
        assert list(b.labs[LAB].samples)[-1] == 'p5'

    def test_the_labs_seen_last_are_kept(self, monkeypatch):
        monkeypatch.setattr(C, 'MAX_LABS', 3)
        b = book()
        for i, lab in enumerate(['a.py', 'b.py', 'c.py']):
            b.declare([{'name': lab, 'weight': 1}], at=10 + i)
        b.observe([usage('p', lab='a.py')], 50)                     # a.py seen again
        b.declare([{'name': 'd.py', 'weight': 1}], at=60)
        assert sorted(b.labs) == ['a.py', 'c.py', 'd.py']           # b.py, the one seen longest ago, went

    def test_dirty_only_when_something_changed(self):
        b = book()
        b.declare([{'name': LAB, 'weight': 15}])
        b.observe([usage('p1')], 10)
        assert b.dirty
        b.to_json(0)
        assert not b.dirty
        b.declare([{'name': LAB, 'weight': 15}])
        b.observe([usage('p1')], 20)                                # the same figures, a later poll
        assert not b.dirty
        b.observe([usage('p1', cpu=0.11)], 30)
        assert b.dirty

    def test_the_cost_follows_the_book(self):
        b = book()
        b.declare([{'name': LAB, 'weight': 10}])
        assert b.cost(LAB) == Cost(160.0, 0.1)
        b.declare([{'name': LAB, 'weight': 20}])
        assert b.cost(LAB) == Cost(320.0, 0.2)
        b.observe([usage(f'p{i}', mem=50, cpu=0.02) for i in range(3)], 10)
        assert b.cost(LAB) == (pytest.approx(50.0), pytest.approx(0.02))

    def test_measured_unit(self):
        b = book()
        assert b.measured_unit() is None
        b.declare([{'name': 'a.py', 'weight': 10}, {'name': 'b.py', 'weight': 30}, {'name': 'c.py', 'weight': 99}])
        b.observe([usage('a1', lab='a.py', mem=100, cpu=0.1), usage('a2', lab='a.py', mem=300, cpu=0.3),
                   usage('b1', lab='b.py', mem=1000, cpu=0.6), usage('x1', lab='noweight.py', mem=5000, cpu=5)], 10)
        # (200 + 1000) MiB and (0.2 + 0.6) core for 40 units of weight: the labs with both
        assert b.measured_unit() == (pytest.approx(30.0), pytest.approx(0.02))

    def test_rows(self):
        b = book()
        b.declare([{'name': 'b.py', 'weight': 4}, {'name': 'a.py', 'weight': 2.5}])
        b.observe([usage(f'p{i}', lab='b.py', mem=80, cpu=0.04, containers=4 + i) for i in range(3)], 10)
        b.observe([usage('q', lab='c.py', mem=20, cpu=0.01, containers=2)], 10)
        assert b.rows({'a.py': 'Lab A'}) == [
            {'lab': 'a.py', 'title': 'Lab A', 'weight': 2.5, 'containers': None, 'mem_mb': 40.0, 'cpu': 0.025,
             'samples': 0, 'source': 'declared'},
            {'lab': 'b.py', 'title': None, 'weight': 4, 'containers': 6, 'mem_mb': 80.0, 'cpu': 0.04,
             'samples': 3, 'source': 'measured'},
            {'lab': 'c.py', 'title': None, 'weight': None, 'containers': 2, 'mem_mb': 512.0, 'cpu': 0.2,
             'samples': 1, 'source': 'default'}]


class TestCostsFile:
    def filled(self):
        b = book()
        b.declare([{'name': LAB, 'weight': 15}, {'name': 'w.py', 'weight': 3}], at=1000)
        b.observe([usage('p1', mem=100.26, cpu=0.12345, containers=15), usage('p2', mem=120, cpu=0.2, containers=15),
                   usage('p3', mem=90, cpu=0.1, containers=15), usage('q1', lab='x@y.py', mem=7, cpu=0.5)], 2000)
        return b

    def test_round_trip(self):
        b = self.filled()
        data = json.loads(json.dumps(b.to_json(3000.4)))
        assert data['version'] == 1 and data['saved_at'] == 3000 and sorted(data['labs']) == [LAB, 'w.py', 'x@y.py']
        assert data['labs'][LAB] == {'weight': 15, 'seen': 2000, 'samples': [
            {'project': 'p1', 'mem_mb': 100.3, 'cpu': 0.1235, 'containers': 15, 'at': 2000},
            {'project': 'p2', 'mem_mb': 120.0, 'cpu': 0.2, 'containers': 15, 'at': 2000},
            {'project': 'p3', 'mem_mb': 90.0, 'cpu': 0.1, 'containers': 15, 'at': 2000}]}
        again = book()
        assert again.load(data) and not again.dirty
        assert again.resolve(LAB)[1] == SOURCE_MEASURED
        assert again.cost(LAB) == (pytest.approx(b.cost(LAB).mem_mb, abs=0.1), pytest.approx(b.cost(LAB).cpu, abs=1e-3))
        assert again.cost('w.py') == Cost(48.0, 0.03)
        assert list(again.labs[LAB].samples) == ['p1', 'p2', 'p3']  # their order: the one measured last at the end
        assert 'x/y.py' in again.labs                               # the key of a lab is its list name

    @pytest.mark.parametrize('data', [None, [], 'x', {}, {'version': 2, 'labs': {}}, {'version': 1},
                                      {'version': 1, 'labs': []}])
    def test_not_a_costs_file(self, data):
        b = book()
        assert b.load(data) is False and b.labs == {}

    def test_a_damaged_file_gives_what_it_can(self):
        b = book()
        assert b.load({'version': 1, 'labs': {
            'ok.py': {'weight': 4, 'samples': [{'project': 'p', 'mem_mb': 10, 'cpu': 0.1, 'containers': 2, 'at': 5},
                                              {'project': 'bad', 'mem_mb': 'x', 'cpu': 0.1},
                                              {'project': '', 'mem_mb': 1, 'cpu': 0.1}, 'junk',
                                              {'project': 'neg', 'mem_mb': -1, 'cpu': 0.1},
                                              {'project': 'nocount', 'mem_mb': 5, 'cpu': 0.2}]},
            'weightonly.py': {'weight': 9, 'samples': 'none'},
            'badweight.py': {'weight': True, 'samples': []},        # nothing left of it
            'notadict.py': 3, '': {'weight': 1}, 7: {'weight': 1}}})
        assert sorted(b.labs) == ['ok.py', 'weightonly.py']
        assert b.labs['ok.py'].samples == {'p': C.Sample(10.0, 0.1, 2, 5.0), 'nocount': C.Sample(5.0, 0.2, 0, 0.0)}
        assert b.cost('weightonly.py') == Cost(144.0, 0.09)


# ---------------------------------------------------------------------------------------------
# the load of a host
# ---------------------------------------------------------------------------------------------

class TestHostLoad:
    def load(self, **over):
        values = dict(cpus=8, mem_total_mb=16000, mem_available_mb=12000, cpu_busy=0.5, committed_cpu=2.0,
                      in_flight=[], reserve_mb=1000, cpu_target=0.75)
        values.update(over)
        return host_load(**values)

    def test_figures(self):
        load = self.load()
        assert load == HostLoad(mem_free_mb=11000.0, mem_capacity_mb=15000.0, cpu_used=2.0, cpu_capacity=6.0)
        assert load.fill == pytest.approx(1 / 3)                    # the processors: 2 of 6; the memory 4000 of 15000
        assert self.load(mem_available_mb=3000).fill == pytest.approx(1 - 2000 / 15000)

    def test_the_starts_in_flight_count(self):
        load = self.load(in_flight=[Cost(2000, 1.0), Cost(500, 0.5)])
        assert (load.mem_free_mb, load.cpu_used) == (8500.0, 3.5)

    def test_the_processors_the_host_really_burns(self):
        """What its projects are counted for, or what the host burns when that is more."""
        assert self.load(cpu_busy=5.0).cpu_used == 5.0
        assert self.load(cpu_busy=None).cpu_used == 2.0
        assert self.load(cpu_busy=5.0, in_flight=[Cost(1, 0.5)]).cpu_used == 5.5

    def test_fits(self):
        load = self.load()                                          # 11000 MiB free, 4 cores left
        assert load.fits(Cost(11000, 4.0)) and not load.fits(Cost(11001, 0.1)) and not load.fits(Cost(10, 4.01))

    def test_rooms(self):
        load = self.load()
        assert load.rooms(Cost(2000, 0.5)) == (5, 8)
        assert load.rooms(Cost(100, 3.0)) == (110, 1)
        assert self.load(committed_cpu=9.0).rooms(Cost(100, 1.0)) == (110, 0)       # over its processors: none, never less
        assert self.load(mem_available_mb=500).rooms(Cost(100, 1.0)) == (0, 4)      # below the reserve

    def test_over_its_capacity(self):
        assert self.load(committed_cpu=9.0).fill == pytest.approx(1.5)
        assert self.load(mem_available_mb=0).fill == pytest.approx(1.0)
        assert self.load(mem_available_mb=99999).fill == pytest.approx(1 / 3)       # more free than there is: no memory in use

    @pytest.mark.parametrize('over', [{'cpus': None}, {'cpus': 0}, {'mem_total_mb': None},
                                      {'mem_available_mb': None}])
    def test_none_without_the_size_of_the_host(self, over):
        assert self.load(**over) is None

    def test_a_reserve_larger_than_the_host(self):
        load = self.load(reserve_mb=99999)
        assert load.mem_free_mb == 0 and load.mem_capacity_mb == 1.0 and load.fill == 1.0

    def test_a_share_of_the_host(self):
        """``share`` (``[[hosts]] total_usable_capacity``): the host counts as a machine that
        share of its size, and what is in use there counts against it, whoever uses it."""
        assert self.load(share=1.0) == self.load()                  # the whole host: the figures of before
        load = self.load(share=0.5)                                 # 7500 of its 15000 MiB, 3 of its 6 cores
        assert load == HostLoad(mem_free_mb=3500.0, mem_capacity_mb=7500.0, cpu_used=2.0, cpu_capacity=3.0)
        assert load.fill == pytest.approx(2 / 3)                    # the processors: 2 of 3; the memory 4000 of 7500
        assert load.fits(Cost(3500, 1.0)) and not load.fits(Cost(3501, 0.1)) and not load.fits(Cost(10, 1.01))
        assert load.rooms(Cost(1000, 0.5)) == (3, 2)
        assert self.load(share=0.5, in_flight=[Cost(2000, 0.5)]).mem_free_mb == 1500.0
        # more in use than the share holds: full, and over it
        load = self.load(share=0.25)                                # 3750 MiB (4000 in use), 1.5 cores (2 counted)
        assert (load.mem_free_mb, load.mem_capacity_mb, load.cpu_capacity) == (0.0, 3750.0, 1.5)
        assert load.fill == pytest.approx(2.0 / 1.5) and load.rooms(Cost(100, 0.1)) == (0, 0)
        assert self.load(share=0.25, committed_cpu=0.0, cpu_busy=0.0).fill == pytest.approx(1.0)
        # a reserve larger than the host: nothing, at any share
        load = self.load(share=0.5, reserve_mb=99999)
        assert load.mem_free_mb == 0 and load.mem_capacity_mb == 1.0 and load.fill == 1.0


# ---------------------------------------------------------------------------------------------
# the pool feeds the book
# ---------------------------------------------------------------------------------------------

def measured(*rows, **over):
    """The status of an agent that tells its size and the usage of its projects."""
    return up(projects=len(rows), cpus=8, mem_total_mb=16000, mem_available_mb=12000, cpu_busy=0.5,
              usage=list(rows), **over)


def project(name, lab='sre@dhcp.py', mem=100.0, cpu=0.1, containers=5, settled=True):
    return {'name': name, 'lab': lab, 'containers': containers, 'mem_mb': mem, 'cpu': cpu, 'settled': settled}


class TestUsageCoercion:
    def test_rows(self):
        rows = usage_fields([project('p1'), project('p2', lab='s4@tp', mem=None, cpu=None, containers=None,
                                                    settled=False)], 8, 16000)
        assert rows == [Usage('p1', 'sre/dhcp.py', 5, 100.0, 0.1, True), Usage('p2', 's4/tp', None, None, None, False)]

    def test_a_hostile_agent(self):
        """No figure says more than the host has, nothing that is no number is one."""
        rows = usage_fields([project('big', mem=9e6, cpu=500), project('odd', mem='1', cpu=True, containers='x'),
                             project('neg', mem=-5, cpu=-1), project('nan', mem=float('nan'), cpu=float('inf')),
                             project('truthy', settled=1), project('big'),          # twice: the first
                             {'name': 'nolab'}, {'lab': 'x'}, {'name': '', 'lab': 'x'}, {'name': 5, 'lab': 'x'},
                             {'name': 'x' * 400, 'lab': 'x'}, {'name': 'y', 'lab': 'l' * 400}, 'junk', None],
                            8, 16000)
        assert [r.name for r in rows] == ['big', 'odd', 'neg', 'nan', 'truthy']
        assert (rows[0].mem_mb, rows[0].cpu) == (16000.0, 8.0)
        for row in rows[1:4]:
            assert (row.mem_mb, row.cpu) == (None, None)
        assert rows[1].containers is None and rows[4].settled is False
        assert usage_fields('x', 8, 16000) == [] and usage_fields(None, 8, 16000) == []
        assert len(usage_fields([project(f'p{i}') for i in range(MAX_USAGE + 20)], 8, 16000)) == MAX_USAGE

    def test_without_the_size_of_the_host(self):
        row = usage_fields([project('p', mem=50000, cpu=64)], None, None)[0]
        assert (row.mem_mb, row.cpu) == (50000.0, 64.0)

    def test_status(self):
        st = status_from_json(measured(project('p1')))
        assert (st.cpus, st.mem_total_mb, st.cpu_busy) == (8, 16000, 0.5) and len(st.usage) == 1
        odd = status_from_json(up(cpus='8', mem_total_mb=-4, cpu_busy='busy', usage={'p': 1}))
        assert (odd.cpus, odd.mem_total_mb, odd.cpu_busy, odd.usage) == (None, None, None, [])
        assert status_from_json(up(cpus=4, cpu_busy=99)).cpu_busy == 4.0
        old = status_from_json(up())                                # an agent older than these figures
        assert (old.cpus, old.mem_total_mb, old.cpu_busy, old.usage) == (None, None, None, [])


class TestPoolLearns:
    def pool(self, tmp_path=None, **more):
        session = FakeSession()
        hosts = [HostConfig('a', 'http://a', TOKEN, 10), HostConfig('b', 'http://b', TOKEN, 10)]
        pool = Pool(hosts, session, weight_memory_mb=16.0, weight_cpu=0.01,
                    costs_file=str(tmp_path / 'pool-costs.json') if tmp_path else '', **more)
        return pool, session

    def test_the_statuses_feed_the_costs(self):
        pool, session = self.pool()
        session.answers = {'http://a': measured(project('p1', mem=100), project('p2', mem=200)),
                           'http://b': measured(project('p3', mem=300), project('q', lab='s4@tp', settled=False))}
        run(pool.refresh())
        assert pool.costs.resolve('sre/dhcp.py') == ((pytest.approx(260.0), pytest.approx(0.1)), SOURCE_MEASURED)
        assert 's4/tp' not in pool.costs.labs
        # the usage of the projects stays out of the rows of the Pool page
        rows = {row['name']: row for row in pool.summary()}
        assert 'usage' not in rows['a'] and (rows['a']['cpus'], rows['a']['mem_total_mb']) == (8, 16000)
        json.dumps(pool.summary())

    def test_the_lab_lists_declare_the_weights(self):
        from sreweb.identity import Identity
        pool, session = self.pool()
        session.answers = {'http://a': up(), 'http://b': up()}
        session.labs = {'http://a': [{'name': 'sre', 'kind': 'dir', 'weight': 99},
                                     {'name': 'sre/dhcp.py', 'kind': 'lab', 'weight': 15},
                                     {'name': 'sre/x.py', 'kind': 'lab', 'weight': 'heavy'},
                                     {'name': 'sre/y.py', 'kind': 'lab', 'weight': -1},
                                     {'name': 'sre/z.py', 'kind': 'lab'}, 'bare.py']}
        session.labs['http://b'] = session.labs['http://a']
        run(pool.refresh())
        labs = run(pool.labs(Identity(login='bob')))
        assert {lab['name']: lab.get('weight', '-') for lab in labs} == {
            'sre': '-', 'sre/dhcp.py': 15.0, 'sre/x.py': '-', 'sre/y.py': '-', 'sre/z.py': '-', 'bare.py': '-'}
        assert pool.costs.resolve('sre/dhcp.py') == (Cost(240.0, 0.15), SOURCE_DECLARED)
        assert list(pool.costs.labs) == ['sre/dhcp.py']

    def test_load_of_a_host(self):
        pool, session = self.pool(memory_reserve_mb=1000, cpu_target=0.5)
        pool.costs.declare([{'name': 'sre/dhcp.py', 'weight': 50}])            # 800 MiB, 0.5 core
        session.answers = {'http://a': measured(project('p1', settled=False), project('p2', settled=False)),
                           'http://b': up(projects=2)}                          # b: an older agent
        run(pool.refresh())
        assert pool.load_of('a') == HostLoad(mem_free_mb=11000.0, mem_capacity_mb=15000.0, cpu_used=1.0,
                                             cpu_capacity=4.0)
        assert pool.load_of('b') is None
        rows = {row['name']: row for row in pool.summary()}
        assert (rows['a']['cpu_used'], rows['a']['cpu_capacity'], rows['a']['fill']) == (1.0, 4.0, 0.267)
        assert (rows['b']['cpu_used'], rows['b']['cpu_capacity'], rows['b']['fill']) == (None, None, None)
        # a start in flight counts for the cost of its lab until a status asked after its end
        host, reservation = pool.pick(lab='sre/dhcp.py')
        assert host.name == 'a' and reservation.cost == Cost(800.0, 0.5)
        load = pool.load_of('a')
        assert (load.mem_free_mb, load.cpu_used) == (10200.0, 1.5)
        Pool.release(reservation)
        # a lab the pool knows nothing of: the default; no lab given (an older caller): the default too
        assert pool.pick(lab='never/seen.py')[1].cost == pool.costs.default == pool.pick()[1].cost
        session.answers['http://a'] = None
        run(pool.refresh())
        assert pool.load_of('a') is None                                        # unreachable

    def test_the_default_cost_follows_project_memory_mb(self):
        assert self.pool()[0].costs.default == Cost(512.0, 0.2)
        assert self.pool(project_memory_mb=2048)[0].costs.default == Cost(2048.0, 0.2)

    def test_costs_view(self):
        pool, session = self.pool()
        pool.costs.declare([{'name': 'sre/dhcp.py', 'weight': 10}])
        pool.costs.observe([usage('p1', mem=300, cpu=0.2)], 5)
        view = pool.costs_view()
        assert view['default'] == {'mem_mb': 512.0, 'cpu': 0.2} and view['weight_unit'] == {'mem_mb': 16.0, 'cpu': 0.01}
        assert view['measured_unit'] == {'mem_mb': 30.0, 'cpu': 0.02}
        assert (view['memory_reserve_mb'], view['cpu_target'], view['file'], view['error']) == (1024, 0.7, '', '')
        assert [row['lab'] for row in view['labs']] == ['sre/dhcp.py'] and view['labs'][0]['samples'] == 1
        json.dumps(view)
        assert self.pool()[0].costs_view()['measured_unit'] is None

    def test_the_costs_file(self, tmp_path, monkeypatch, caplog):
        pool, session = self.pool(tmp_path)
        path = tmp_path / 'pool-costs.json'
        session.answers = {'http://a': measured(*(project(f'p{i}', mem=100 + i) for i in range(3))),
                           'http://b': up()}
        run(pool.refresh())
        assert json.loads(path.read_text())['labs']['sre/dhcp.py']['samples'][0]['project'] == 'p0'
        # at most one write per minute, whatever changes
        session.answers['http://a'] = measured(*(project(f'p{i}', mem=500 + i) for i in range(3)))
        before = path.read_text()
        run(pool.refresh())
        assert pool.costs.dirty and path.read_text() == before
        pool.save_costs(force=True)                                             # the stop of the portal
        assert not pool.costs.dirty and path.read_text() != before
        assert not (tmp_path / 'pool-costs.json.tmp').exists()
        # a restart finds them again
        again, _ = self.pool(tmp_path)
        assert again.costs.resolve('sre/dhcp.py') == ((pytest.approx(501.6), pytest.approx(0.1)), SOURCE_MEASURED)
        assert not again.costs.dirty
        # nothing changed: nothing written
        stamp = path.stat().st_mtime_ns
        again.save_costs(force=True)
        assert path.stat().st_mtime_ns == stamp

    def test_a_costs_file_that_cannot_be_read_or_written(self, tmp_path, caplog):
        path = tmp_path / 'pool-costs.json'
        for content in ('{not json', '[1, 2]', '{"version": 9, "labs": {}}'):
            path.write_text(content)
            with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
                pool, _ = self.pool(tmp_path)
            assert pool.costs.labs == {} and 'learned again' in caplog.text      # a cache: started empty
            caplog.clear()
        # a write that fails is said once, kept in the view, and tried again
        pool.costs.observe([usage('p1')], 5)
        pool.costs_file = str(tmp_path / 'pool-costs.json' / 'below-a-file' / 'x.json')
        with caplog.at_level(logging.WARNING, logger='sreweb.portal'):
            pool.save_costs(force=True)
            pool.save_costs(force=True)
        assert caplog.text.count('NOT saved') == 1 and pool.costs_error and pool.costs.dirty
        assert pool.costs_view()['error'] == pool.costs_error
        pool.costs_file = str(tmp_path / 'elsewhere.json')
        with caplog.at_level(logging.INFO, logger='sreweb.portal'):
            pool.save_costs(force=True)
        assert pool.costs_error == '' and 'saved again' in caplog.text
        assert json.loads((tmp_path / 'elsewhere.json').read_text())['labs']

    def test_no_file_without_a_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pool, session = self.pool()
        pool.costs.observe([usage('p1')], 5)
        pool.save_costs(force=True)
        assert list(tmp_path.iterdir()) == [] and pool.costs.dirty

    def test_the_file_beside_the_state_file(self):
        from sreweb.portal.defaults import costs_file_beside
        assert costs_file_beside('/var/lib/sre-web/pool.json') == '/var/lib/sre-web/pool-costs.json'
        assert costs_file_beside('') == ''


# ---------------------------------------------------------------------------------------------
# [pool] capacity = "resources": the placement and the elastic pool on memory and processors
# ---------------------------------------------------------------------------------------------

HEAVY, LIGHT = 'sre/heavy.py', 'sre/light.py'      # declared 100 and 5: 1600 MiB + 1 core, 80 MiB + 0.05 core


def host(projects=(), *, available=12000, busy=0.0, cpus=8, total=16000, **more):
    """The status of a host of 8 processors and 16 GiB that runs *projects* (lab names): with the
    pool of ``resources()`` it has 4 cores for its projects and 15000 MiB less the reserve."""
    rows = [Usage(name=f'p{i}-{lab}', lab=lab, containers=3, mem_mb=None, cpu=None, settled=False)
            for i, lab in enumerate(projects)]
    return HostStatus(reachable=True, projects=len(rows), cpus=cpus, mem_total_mb=total, mem_available_mb=available,
                      cpu_busy=busy, usage=rows, **more)


def resources(names=('a', 'b'), *, capacity='resources', max_projects=25, **more):
    """A pool of hosts judged by their memory and processors (1000 MiB kept free, half of the
    processors for the projects), that knows a heavy and a light lab."""
    from sreweb.config import HostConfig as Host
    pool = Pool([Host(name, f'http://{name}', TOKEN, max_projects) for name in names], session=None,
                capacity=capacity, memory_reserve_mb=1000, cpu_target=0.5, weight_memory_mb=16.0, weight_cpu=0.01,
                **more)
    pool.costs.declare([{'name': HEAVY, 'weight': 100}, {'name': LIGHT, 'weight': 5}])
    return pool


class TestResourcesPlacement:
    def test_a_heavy_lab_fills_a_host_sooner(self):
        """Three heavy projects load a host more than ten light ones: the count says the reverse."""
        statuses = {'a': host([HEAVY] * 3, available=7200), 'b': host([LIGHT] * 10, available=11200)}
        pool = resources()
        pool.status.update(statuses)
        assert pool._fill(pool.hosts['a']) == pytest.approx(0.75)           # its processors: 3 of 4 cores
        assert pool._fill(pool.hosts['b']) == pytest.approx(0.32)           # its memory: 4800 of 15000 MiB
        assert pool.pick(lab=HEAVY)[0].name == 'b'
        counted = resources(capacity='projects')
        counted.status.update({'a': host([HEAVY] * 3, available=7200), 'b': host([LIGHT] * 10, available=11200)})
        assert counted._fill(counted.hosts['a']) == 3 / 25 and counted.pick(lab=HEAVY)[0].name == 'a'

    def test_room_for_the_cost_of_the_lab(self):
        pool = resources(['a'])
        pool.status['a'] = host([HEAVY] * 3 + [LIGHT] * 10)                 # 3.5 of its 4 cores counted
        with pytest.raises(PoolError) as e:
            pool.pick(lab=HEAVY)
        assert e.value.status == 503 and 'no host' in e.value.message
        assert pool.pick(lab=LIGHT)[0].name == 'a'                          # a light one still fits
        pool = resources(['a'])
        pool.status['a'] = host([LIGHT], available=1500)                    # 500 MiB above the reserve
        with pytest.raises(PoolError):
            pool.pick(lab=HEAVY)
        assert pool.pick(lab=LIGHT)[0].name == 'a'

    def test_the_starts_in_flight_hold_their_cost(self):
        """A burst: every start counts for the cost of its lab at once, before any container shows."""
        pool = resources(['a'])
        pool.status['a'] = host()
        picked = [pool.pick(lab=HEAVY) for _ in range(4)]                   # four cores for the projects
        assert pool.load_of('a').cpu_used == 4.0 and pool.load_of('a').mem_free_mb == 11000 - 4 * 1600
        for lab in (HEAVY, LIGHT):
            with pytest.raises(PoolError):
                pool.pick(lab=lab)
        # the starts are over, a status asked afterwards tells the four projects: still no room
        for _, reservation in picked:
            Pool.release(reservation)
        assert pool._consume('a', time.monotonic()) == 0
        pool.status['a'] = host([HEAVY] * 4, available=5600)
        with pytest.raises(PoolError):
            pool.pick(lab=LIGHT)
        pool.status['a'] = host([HEAVY] * 3, available=7200)                # one of them closed
        assert pool.pick(lab=HEAVY)[0].name == 'a'

    def test_a_host_without_project_always_takes_one(self):
        """A lab larger than every host still starts, and an empty host is not loaded by the
        memory its system uses: the order of the priorities tells the empty hosts apart."""
        pool = resources()
        pool.costs.declare([{'name': 'sre/huge.py', 'weight': 100000}])    # 1600 GiB, 1000 cores
        pool.status.update({'a': host(available=3000), 'b': host(available=14000)})
        assert pool._fill(pool.hosts['a']) == pool._fill(pool.hosts['b']) == 0.0
        pool.set_priority('b', check_priority('0:-1', 'priority'))
        assert pool.pick(lab='sre/huge.py')[0].name == 'b'
        assert pool.pick(lab='sre/huge.py')[0].name == 'a'                  # b has a start in flight: no longer empty
        with pytest.raises(PoolError):
            pool.pick(lab='sre/huge.py')

    def test_the_usable_share_of_a_host(self):
        """``total_usable_capacity``: a host counts as a machine that share of its size.  At the
        same load it is the fuller one, it refuses what the whole host takes, and it still takes
        a project when it has none."""
        pool = resources()
        pool.set_total_usable_capacity('a', 50)
        pool.status.update({'a': host([HEAVY]), 'b': host([HEAVY])})        # the same load on both
        assert pool.load_of('a') == HostLoad(mem_free_mb=3500.0, mem_capacity_mb=7500.0, cpu_used=1.0,
                                             cpu_capacity=2.0)
        assert pool.load_of('b') == HostLoad(mem_free_mb=11000.0, mem_capacity_mb=15000.0, cpu_used=1.0,
                                             cpu_capacity=4.0)
        assert pool._fill(pool.hosts['a']) == pytest.approx(4000 / 7500)    # its memory: 4000 of 7500 MiB
        assert pool._fill(pool.hosts['b']) == pytest.approx(4000 / 15000)
        assert pool.pick(lab=HEAVY)[0].name == 'b'
        rows = {row['name']: row for row in pool.summary()}
        assert (rows['a']['total_usable_capacity'], rows['a']['cpu_capacity']) == (50, 2.0)
        assert (rows['b']['total_usable_capacity'], rows['b']['cpu_capacity']) == (100, 4.0)
        # its processors: two heavy projects are the two cores of half the host
        whole, half = resources(['a']), resources(['a'])
        half.set_total_usable_capacity('a', 50)
        for one in (whole, half):
            one.status['a'] = host([HEAVY] * 2, available=8800)
        assert whole.pick(lab=HEAVY)[0].name == 'a'
        for lab in (HEAVY, LIGHT):
            with pytest.raises(PoolError) as e:
                half.pick(lab=lab)
            assert e.value.status == 503
        # its memory: 500 MiB of its 7500 left, where the whole host has 8000
        whole, half = resources(['a']), resources(['a'])
        half.set_total_usable_capacity('a', 50)
        for one in (whole, half):
            one.status['a'] = host([LIGHT], available=9000)
        assert whole.pick(lab=HEAVY)[0].name == 'a'
        with pytest.raises(PoolError):
            half.pick(lab=HEAVY)
        assert half.pick(lab=LIGHT)[0].name == 'a'                          # a light one still fits
        # a host without project always takes one, whatever its share
        empty = resources(['a'])
        empty.set_total_usable_capacity('a', 1)
        empty.status['a'] = host(available=3000)
        assert empty._fill(empty.hosts['a']) == 0.0 and empty._rooms('a') == (1, 1)
        assert empty.pick(lab=HEAVY)[0].name == 'a'

    def test_the_usable_share_of_the_configuration(self):
        """The share of ``[[hosts]]`` is the one of the host until it is set by hand."""
        from sreweb.config import HostConfig as Host
        pool = Pool([Host('a', 'http://a', TOKEN, 25, total_usable_capacity=25)], session=None,
                    capacity='resources', memory_reserve_mb=1000, cpu_target=0.5)
        pool.status['a'] = host()
        assert (pool.load_of('a').mem_capacity_mb, pool.load_of('a').cpu_capacity) == (3750.0, 1.0)
        pool.set_total_usable_capacity('a', 100)
        assert (pool.load_of('a').mem_capacity_mb, pool.load_of('a').cpu_capacity) == (15000.0, 4.0)
        assert pool.hosts['a'].total_usable_capacity == 25                  # the configuration is not touched

    def test_the_usable_share_counts_for_nothing_in_projects_mode(self):
        """``capacity = "projects"``: a host holds its ``max_projects``, whatever its share."""
        counted, shared = resources(['a'], capacity='projects'), resources(['a'], capacity='projects')
        shared.set_total_usable_capacity('a', 1)
        for pool in (counted, shared):
            pool.status['a'] = host([HEAVY] * 4, available=5600)
            assert pool._fill(pool.hosts['a']) == 4 / 25 and pool._has_room(pool.hosts['a'])
            assert pool.memory_room('a') is None and pool.cpu_room('a') is None
            assert pool.pick(lab=HEAVY)[0].name == 'a'

    def test_the_processors_the_host_really_burns(self):
        """A runaway container, the Docker daemon: more than its projects are counted for."""
        pool = resources(['a'])
        pool.status['a'] = host([LIGHT], busy=3.99)
        assert pool._fill(pool.hosts['a']) == pytest.approx(3.99 / 4)
        with pytest.raises(PoolError):
            pool.pick(lab=LIGHT)
        pool.status['a'] = host([LIGHT], busy=0.2)
        assert pool.pick(lab=LIGHT)[0].name == 'a'

    def test_max_projects_stays_a_ceiling(self):
        pool = resources(['a'], max_projects=2)
        pool.status['a'] = host([LIGHT] * 2)
        with pytest.raises(PoolError):
            pool.pick(lab=LIGHT)

    def test_an_older_agent_is_judged_by_its_projects(self):
        """A host whose agent does not tell its size: the count rule, project_memory_mb included."""
        pool = resources(project_memory_mb=1000)
        pool.status['a'] = host([HEAVY] * 3, available=7200)
        pool.status['b'] = HostStatus(reachable=True, projects=10, mem_available_mb=2500)
        assert pool._resources('b') is None and pool._fill(pool.hosts['b']) == 10 / 25
        assert pool.memory_room('b') == 2 and pool.cpu_room('b') is None
        assert pool.pick(lab=HEAVY)[0].name == 'b'                          # 0.4 against 0.75
        pool.status['b'] = HostStatus(reachable=True, projects=10, mem_available_mb=900)
        assert pool.memory_room('b') == 0 and pool.pick(lab=HEAVY)[0].name == 'a'

    def test_a_host_named_by_an_instructor(self):
        prof = Identity(login='prof', role=ROLE_INSTRUCTOR)
        pool = resources(['a'])
        pool.status['a'] = host([HEAVY] * 3 + [LIGHT] * 10)
        with pytest.raises(PoolError) as e:
            pool.pick(prof, host='a', lab=HEAVY)
        assert e.value.status == 503 and e.value.message == 'the host a has not enough free processor time'
        assert pool.pick(prof, host='a', lab=LIGHT)[1].placement == PLACEMENT_NAMED
        pool.status['a'] = host([LIGHT], available=1500)
        with pytest.raises(PoolError) as e:
            pool.pick(prof, host='a', lab=HEAVY)
        assert e.value.status == 503 and e.value.message == 'the host a has not enough free memory'
        pool.status['a'] = host(available=1500)                             # empty: it takes it
        assert pool.pick(prof, host='a', lab=HEAVY)[0].name == 'a'

    def test_rooms_in_reference_projects(self):
        """The room of a host is counted in projects like those running: the mean cost of the
        labs of the projects of the hosts the students use (the default without any)."""
        pool = resources(['a', 'b', 'c'])
        assert pool.reference_cost() == pool.costs.default == Cost(512.0, 0.2)
        pool.status.update({'a': host([HEAVY] * 3, available=7200), 'b': host([LIGHT] * 10, available=11200),
                            'c': host()})
        reference = pool.reference_cost()
        assert reference == (pytest.approx((3 * 1600 + 10 * 80) / 13), pytest.approx(3.5 / 13))
        assert (pool.memory_room('a'), pool.cpu_room('a')) == (14, 3)       # 6200 MiB, 1 core left
        assert (pool.memory_room('b'), pool.cpu_room('b')) == (23, 13)      # 10200 MiB, 3.5 cores left
        assert (pool.memory_room('c'), pool.cpu_room('c')) == (25, 14)
        rows = {row['name']: row for row in pool.summary()}
        assert (rows['a']['memory_room'], rows['a']['cpu_room'], rows['a']['fill']) == (14, 3, 0.75)
        # a host without project has room for one, whatever the reference
        pool.status['c'] = host(available=900)
        assert (pool.memory_room('c'), pool.cpu_room('c')) == (1, 14)
        # the projects of a host reserved for the instructors are no part of the reference
        reserved = resources(['a'])
        reserved.hosts['a'] = replace(reserved.hosts['a'], instructors_only=True)
        reserved.status['a'] = host([HEAVY] * 3)
        assert reserved.reference_cost() == reserved.costs.default

    def test_no_room_counted_in_projects_mode(self):
        pool = resources(capacity='projects')
        pool.status.update({'a': host([HEAVY] * 3), 'b': host()})
        assert pool.cpu_room('a') is None and pool.memory_room('a') is None and pool._resources('a') is None
        rows = {row['name']: row for row in pool.summary()}
        assert rows['a']['cpu_room'] is None and rows['a']['cpu_used'] == 3.0   # shown, not used

    def test_the_lab_list_is_asked_from_the_least_filled_host(self):
        pool = resources()
        pool.status.update({'a': host([HEAVY] * 3, available=7200), 'b': host([LIGHT] * 10, available=11200)})
        assert [h.name for h in pool._labs_hosts(Identity(login='bob'))] == ['b', 'a']


class TestResourcesElasticPool:
    def test_free_slots(self):
        assert free_slots(view('a', STATE_UP, projects=2, max_projects=10, memory_room=5, cpu_room=3)) == 3
        assert free_slots(view('a', STATE_UP, projects=2, max_projects=10, memory_room=1, cpu_room=3)) == 1
        assert free_slots(view('a', STATE_UP, projects=9, max_projects=10, memory_room=5, cpu_room=3)) == 1
        assert free_slots(view('a', STATE_UP, projects=2, max_projects=10, cpu_room=0)) == 0
        assert free_slots(view('a', STATE_UP, projects=2, max_projects=10)) == 8           # nothing counted but the projects

    def test_cpu_room_in_the_spare_capacity(self):
        """A host whose processors hold no more project is no spare capacity: the next one is woken."""
        cfg = PoolConfig(spare_projects=3, min_hosts_up=0)
        hosts = [view('a', STATE_UP, projects=4, max_projects=25, memory_room=8, cpu_room=0),
                 view('b', STATE_OFF, max_projects=25)]
        assert spare_capacity(hosts) == 0 and wake_plan(hosts, cfg, 1000.0, True, 0.0) == ['b']
        hosts[0] = view('a', STATE_UP, projects=4, max_projects=25, memory_room=8, cpu_room=3)
        assert spare_capacity(hosts) == 3 and wake_plan(hosts, cfg, 1000.0, True, 0.0) == []

    def test_views_and_status_of_the_manager(self):
        pool = resources(['a', 'b'])
        pool.status.update({'a': host([HEAVY] * 4, available=5600), 'b': host([LIGHT] * 2, available=11840)})
        manager = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0))
        views = {v.name: v for v in manager.views()}
        reference = pool.reference_cost()                                   # (4 × 1600 + 2 × 80) / 6 MiB, 4.1 / 6 core
        assert reference == (pytest.approx(6560 / 6), pytest.approx(4.1 / 6))
        assert (views['a'].memory_room, views['a'].cpu_room) == (4, 0)      # its four cores are counted
        assert (views['b'].memory_room, views['b'].cpu_room) == (9, 5)
        assert free_slots(views['a']) == 0 and free_slots(views['b']) == 5
        status = manager.status()
        assert status['capacity'] == 'resources' and status['cpu_full'] == ['a'] and status['memory_full'] == []
        assert status['reference'] == {'mem_mb': 1093.3, 'cpu': 0.683} and status['spare_projects'] == 5
        json.dumps(status)

    def test_the_usable_share_in_the_spare_capacity(self):
        """A host whose projects may fill half of it has fewer free slots: the elastic pool
        counts the room of the share."""
        pool = resources(['a', 'b'])
        pool.status.update({'a': host([HEAVY], available=10400), 'b': host([HEAVY], available=10400)})
        manager = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0))
        assert pool.reference_cost() == Cost(1600.0, 1.0)
        assert {v.name: (v.memory_room, v.cpu_room) for v in manager.views()} == {'a': (5, 3), 'b': (5, 3)}
        assert manager.status()['spare_projects'] == 6
        pool.set_total_usable_capacity('a', 50)                             # 1900 MiB and one core left there
        views = {v.name: v for v in manager.views()}
        assert (views['a'].memory_room, views['a'].cpu_room) == (1, 1)
        assert (views['b'].memory_room, views['b'].cpu_room) == (5, 3)
        assert free_slots(views['a']) == 1 and manager.status()['spare_projects'] == 4

    def test_projects_mode_tells_no_room(self):
        pool = resources(capacity='projects')
        pool.status.update({'a': host([HEAVY] * 4, available=5600), 'b': host()})
        manager = PoolManager(pool, PoolConfig(spare_projects=0, min_hosts_up=0))
        assert {v.name: (v.memory_room, v.cpu_room) for v in manager.views()} == {'a': (None, None), 'b': (None, None)}
        status = manager.status()
        assert (status['capacity'], status['cpu_full'], status['spare_projects']) == ('projects', [], 21 + 25)
