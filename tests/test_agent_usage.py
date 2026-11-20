"""Tests of the usage sampler of the agent (sreweb.agent.usage): what the running projects use,
read from a fake Docker daemon and a cgroup tree in a temporary directory (tests/fake_docker.py)."""
import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from fake_docker import FakeDocker, MIB, SYSTEMD, CGROUPFS  # noqa: E402
from sreweb.agent import usage  # noqa: E402
from sreweb.agent.usage import (UsageSampler, parse_stat, read_container, containers_by_lab, cpu_usec,  # noqa: E402
                                SETTLE_AFTER, MEAN_AFTER, BUSY_TAU)
from sreweb.config import UsageConfig, agent_config_from_dict, ConfigError  # noqa: E402

CID = 'ab' * 32
RLN = '20261120100000@@@sre@dhcp.py@@@alice'


@pytest.fixture
def short_dir():
    """A short directory: an AF_UNIX socket path is limited to about 100 bytes, and pytest's
    tmp_path is longer than that on macOS."""
    d = Path(tempfile.mkdtemp(prefix='sre-usage-', dir='/tmp'))
    yield d
    shutil.rmtree(d, ignore_errors=True)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def project(rln=RLN, lab_hash='h1', lab_name='sre@dhcp.py'):
    return SimpleNamespace(rln=rln, lab_name=lab_name, info={'lab_hash': lab_hash} if lab_hash else {})


def registry(*projects):
    return SimpleNamespace(projects={p.rln: p for p in projects})


def sampler_of(docker, reg, clock=None, **cfg):
    return UsageSampler(reg, UsageConfig(cgroup_root=str(docker.cgroup_root), **cfg), docker_socket=docker.socket,
                        clock=clock or Clock())


def row(sampler, rln=RLN):
    return next(r for r in sampler.rows() if r['name'] == rln)


# ---------------------------------------------------------------------------------------------
# the readers
# ---------------------------------------------------------------------------------------------

class TestReaders:
    def test_parse_stat(self):
        assert parse_stat("usage_usec 1500\nuser_usec 1000\n\nnot a line\nname x\nlast 7") == {
            'usage_usec': 1500, 'user_usec': 1000, 'last': 7}
        assert parse_stat('') == {}

    @pytest.mark.parametrize('layout', [SYSTEMD, CGROUPFS])
    def test_read_container_in_both_layouts(self, tmp_path, layout):
        docker = FakeDocker(tmp_path)
        cid = docker.add('h', mem=80 * MIB, inactive_file=16 * MIB, cpu_usec=2_500_000, layout=layout)
        # the working set: the pages of files the kernel gives back at once are left out
        assert read_container(str(docker.cgroup_root), cid) == (64 * MIB, 2_500_000)

    def test_read_container_without_cgroup(self, tmp_path):
        docker = FakeDocker(tmp_path)
        assert read_container(str(docker.cgroup_root), docker.add('h', layout=None)) == (None, None)
        assert read_container(str(tmp_path / 'nowhere'), CID) == (None, None)

    def test_read_container_with_files_missing(self, tmp_path):
        docker = FakeDocker(tmp_path)
        cid = docker.add('h', mem=10 * MIB, cpu_usec=7)
        directory = docker._directory(cid)
        (directory / 'memory.stat').unlink()
        assert read_container(str(docker.cgroup_root), cid) == (10 * MIB, 7)     # no stat: nothing left out
        (directory / 'cpu.stat').unlink()
        (directory / 'memory.current').write_text('max\n')
        assert read_container(str(docker.cgroup_root), cid) == (None, None)

    def test_memory_is_never_negative(self, tmp_path):
        docker = FakeDocker(tmp_path)
        cid = docker.add('h', mem=MIB, inactive_file=4 * MIB)
        assert read_container(str(docker.cgroup_root), cid)[0] == 0

    @pytest.mark.parametrize('bad', ['../../etc', 'AB' * 32, 'ab' * 31, 'ab' * 32 + '/x', '', None, 12])
    def test_only_a_container_id_makes_a_path(self, tmp_path, bad):
        """An id is 64 hexadecimal digits: nothing else is ever joined to the cgroup root."""
        (tmp_path / 'docker').mkdir()
        assert read_container(str(tmp_path), bad) == (None, None)

    def test_cpu_of_the_root_cgroup(self, tmp_path):
        docker = FakeDocker(tmp_path)
        assert cpu_usec(str(docker.cgroup_root)) is None
        docker.host_cpu(123456)
        assert cpu_usec(str(docker.cgroup_root)) == 123456

    def test_containers_by_lab(self):
        other = 'cd' * 32
        body = [{'Id': CID, 'Labels': {'app': 'kathara', 'lab_hash': 'h1'}},
                {'Id': other, 'Labels': {'lab_hash': 'h1'}},
                {'Id': 'ef' * 32, 'Labels': {'lab_hash': 'h2'}},
                {'Id': '12' * 32, 'Labels': {}},                    # no project
                {'Id': '34' * 32, 'Labels': {'lab_hash': 7}},
                {'Id': '56' * 32, 'Labels': None},
                {'Id': 'not-an-id', 'Labels': {'lab_hash': 'h1'}},
                {'Id': 12, 'Labels': {'lab_hash': 'h1'}},
                {'Labels': {'lab_hash': 'h1'}}, 'junk', None]
        assert containers_by_lab(body) == {'h1': [CID, other], 'h2': ['ef' * 32]}
        for not_a_list in ({'message': 'error'}, None, 'x', 3):
            assert containers_by_lab(not_a_list) == {}


# ---------------------------------------------------------------------------------------------
# the sampler
# ---------------------------------------------------------------------------------------------

class TestSampler:
    def test_the_figures_of_a_project(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.add('h1', mem=40 * MIB, cpu_usec=100)
                docker.add('h1', mem=24 * MIB, inactive_file=4 * MIB, cpu_usec=100, layout=CGROUPFS)
                docker.add('other', mem=500 * MIB)                 # a project the registry does not have
                sampler = sampler_of(docker, registry(project()))
                assert sampler.rows() == [{'name': RLN, 'lab': 'sre@dhcp.py', 'containers': None, 'mem_mb': None,
                                           'cpu': None, 'settled': False}]
                await sampler.sample()
                assert sampler.rows() == [{'name': RLN, 'lab': 'sre@dhcp.py', 'containers': 2, 'mem_mb': 60.0,
                                           'cpu': None, 'settled': False}]
                # only the containers of Kathara are asked for
                assert docker.requests == [{'filters': '{"label":["app=kathara"]}'}]
        asyncio.run(go())

    def test_settled_then_the_mean_of_the_processors(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                a = docker.add('h1', mem=MIB, cpu_usec=0)
                b = docker.add('h1', mem=MIB, cpu_usec=0)
                clock = Clock()
                sampler = sampler_of(docker, registry(project()), clock)
                await sampler.sample()
                # the boot of the containers: a lot of processor, never counted
                docker.set(a, cpu_usec=90_000_000)
                clock.advance(SETTLE_AFTER - 1)
                await sampler.sample()
                assert row(sampler)['settled'] is False and row(sampler)['cpu'] is None
                clock.advance(1)
                await sampler.sample()                              # settled: the mean starts here
                assert row(sampler)['settled'] is True and row(sampler)['cpu'] is None
                docker.set(a, cpu_usec=90_000_000 + 3_000_000)
                clock.advance(MEAN_AFTER - 1)
                await sampler.sample()
                assert row(sampler)['cpu'] is None                  # too short a time to say
                docker.set(b, cpu_usec=3_000_000)
                clock.advance(1)
                await sampler.sample()
                assert row(sampler)['cpu'] == pytest.approx(6.0 / MEAN_AFTER)      # 6 s of processor in 60 s
                # a burst later: the mean since the project settled, not the last interval
                docker.set(b, cpu_usec=3_000_000 + 54_000_000)
                clock.advance(540)
                await sampler.sample()
                assert row(sampler)['cpu'] == pytest.approx(60.0 / 600)
        asyncio.run(go())

    def test_a_change_of_the_containers_starts_again(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                a = docker.add('h1', mem=MIB)
                clock = Clock()
                sampler = sampler_of(docker, registry(project()), clock)
                await sampler.sample()
                clock.advance(SETTLE_AFTER)
                await sampler.sample()
                assert row(sampler)['settled'] is True
                docker.add('h1', mem=MIB)                           # one more machine comes up
                clock.advance(5)
                await sampler.sample()
                assert row(sampler) == {'name': RLN, 'lab': 'sre@dhcp.py', 'containers': 2, 'mem_mb': 2.0,
                                        'cpu': None, 'settled': False}
                clock.advance(SETTLE_AFTER)
                await sampler.sample()
                assert row(sampler)['settled'] is True
                # a container created again: as many of them, another one
                docker.remove(a)
                docker.add('h1', mem=MIB)
                clock.advance(5)
                await sampler.sample()
                assert row(sampler)['containers'] == 2 and row(sampler)['settled'] is False
        asyncio.run(go())

    def test_a_counter_that_went_back_starts_the_mean_again(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                a = docker.add('h1', mem=MIB, cpu_usec=50_000_000)
                clock = Clock()
                sampler = sampler_of(docker, registry(project()), clock)
                await sampler.sample()
                clock.advance(SETTLE_AFTER)
                await sampler.sample()
                docker.set(a, cpu_usec=1_000_000)
                clock.advance(MEAN_AFTER)
                await sampler.sample()
                assert row(sampler)['cpu'] is None                  # never a negative mean
                docker.set(a, cpu_usec=1_000_000 + 12_000_000)
                clock.advance(MEAN_AFTER)
                await sampler.sample()
                assert row(sampler)['cpu'] == pytest.approx(0.2)
        asyncio.run(go())

    def test_no_figure_when_a_container_cannot_be_read(self, short_dir, caplog):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.add('h1', mem=30 * MIB)
                docker.add('h1', layout=None)
                sampler = sampler_of(docker, registry(project()))
                with caplog.at_level(logging.WARNING, logger='sreweb.agent'):
                    await sampler.sample()
                # a sum over the containers that can be read would be too low
                assert row(sampler)['containers'] == 2 and row(sampler)['mem_mb'] is None
                assert not caplog.records                           # one of them was read: cgroup v2 is there
        asyncio.run(go())

    def test_a_host_without_cgroup_v2(self, short_dir, caplog):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.add('h1', layout=None)
                docker.add('h1', layout=None)
                clock = Clock()
                sampler = sampler_of(docker, registry(project()), clock)
                with caplog.at_level(logging.WARNING, logger='sreweb.agent'):
                    await sampler.sample()
                    clock.advance(SETTLE_AFTER + MEAN_AFTER)
                    await sampler.sample()
                # the containers are counted, nothing is measured
                assert row(sampler) == {'name': RLN, 'lab': 'sre@dhcp.py', 'containers': 2, 'mem_mb': None,
                                        'cpu': None, 'settled': True}
                assert [r.getMessage() for r in caplog.records] == [
                    f"usage of the projects not measured: no cgroup of a container found under "
                    f"{docker.cgroup_root} (cgroup v2 expected)"]           # said once
        asyncio.run(go())

    def test_docker_down(self, short_dir, caplog):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.add('h1', mem=8 * MIB)
                clock = Clock()
                sampler = sampler_of(docker, registry(project()), clock)
                await sampler.sample()
                assert row(sampler)['mem_mb'] == 8.0
                docker.status = 500
                with caplog.at_level(logging.WARNING, logger='sreweb.agent'):
                    clock.advance(SETTLE_AFTER)
                    await sampler.sample()
                    await sampler.sample()
                assert row(sampler) == {'name': RLN, 'lab': 'sre@dhcp.py', 'containers': None, 'mem_mb': None,
                                        'cpu': None, 'settled': False}
                assert len(caplog.records) == 1 and "answered 500" in caplog.records[0].getMessage()
                # back: the project did not change meanwhile, it need not settle again
                docker.status = 200
                await sampler.sample()
                assert row(sampler)['mem_mb'] == 8.0 and row(sampler)['settled'] is True
                # down again: said again
                docker.status = 500
                with caplog.at_level(logging.WARNING, logger='sreweb.agent'):
                    await sampler.sample()
                assert len(caplog.records) == 2
        asyncio.run(go())

    def test_no_docker_socket(self, short_dir, caplog):
        async def go():
            docker = FakeDocker(short_dir)                          # never started: no socket
            sampler = sampler_of(docker, registry(project()))
            with caplog.at_level(logging.WARNING, logger='sreweb.agent'):
                await sampler.sample()
                await sampler.sample()
            assert row(sampler)['containers'] is None
            assert len(caplog.records) == 1 and docker.socket in caplog.records[0].getMessage()
        asyncio.run(go())

    def test_an_answer_that_is_no_list(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.body = {'message': 'what?'}
                sampler = sampler_of(docker, registry(project()))
                await sampler.sample()
                assert row(sampler)['containers'] == 0 and row(sampler)['mem_mb'] is None
        asyncio.run(go())

    def test_projects_without_container_or_hash(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.add('h1', mem=MIB)
                clock = Clock()
                nohash = project(rln='20261120100001@@@x.py@@@bob', lab_hash=None, lab_name='x.py')
                starting = project(rln='20261120100002@@@y.py@@@bob', lab_hash='h9', lab_name='y.py')
                sampler = sampler_of(docker, registry(project(), nohash, starting), clock)
                await sampler.sample()
                clock.advance(SETTLE_AFTER)
                await sampler.sample()
                assert row(sampler)['settled'] is True
                for rln in (nohash.rln, starting.rln):              # nothing running: never settled
                    assert row(sampler, rln) == {'name': rln, 'lab': rln.split('@@@')[1], 'containers': 0,
                                                 'mem_mb': None, 'cpu': None, 'settled': False}
        asyncio.run(go())

    def test_the_projects_of_the_registry_now(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.add('h1', mem=MIB)
                reg = registry(project())
                sampler = sampler_of(docker, reg)
                await sampler.sample()
                # a project created since the last measure is listed at once, without figures
                late = project(rln='20261120100003@@@z.py@@@bob', lab_hash='h3', lab_name='z.py')
                reg.projects[late.rln] = late
                assert [r['name'] for r in sampler.rows()] == [RLN, late.rln]
                assert row(sampler, late.rln)['containers'] is None
                # a project gone is forgotten: the same name later would start from nothing
                del reg.projects[RLN]
                await sampler.sample()
                assert [r['name'] for r in sampler.rows()] == [late.rln] and RLN not in sampler._tracks
        asyncio.run(go())

    def test_without_project_the_daemon_is_not_asked(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.host_cpu(0)
                clock = Clock()
                sampler = sampler_of(docker, registry(), clock)
                await sampler.sample()
                clock.advance(10)
                docker.host_cpu(5_000_000)
                await sampler.sample()
                assert docker.requests == [] and sampler.rows() == []
                assert sampler.cpu_busy == pytest.approx(0.5)       # the host is measured all the same
        asyncio.run(go())

    def test_the_processors_of_the_host_are_smoothed(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                clock = Clock()
                sampler = sampler_of(docker, registry(), clock)
                await sampler.sample()
                assert sampler.cpu_busy is None                     # no root cpu.stat
                docker.host_cpu(1_000_000)
                await sampler.sample()
                assert sampler.cpu_busy is None                     # one reading says nothing
                clock.advance(BUSY_TAU)
                docker.host_cpu(1_000_000 + int(2 * BUSY_TAU * 1e6))
                await sampler.sample()
                assert sampler.cpu_busy == pytest.approx(2.0)       # the first figure as it is
                clock.advance(BUSY_TAU)
                docker.host_cpu(1_000_000 + int(2 * BUSY_TAU * 1e6))        # idle since
                await sampler.sample()
                assert sampler.cpu_busy == pytest.approx(2.0 * 0.36788, rel=1e-3)   # e^-1 of it left
                (docker.cgroup_root / 'cpu.stat').unlink()
                await sampler.sample()
                assert sampler.cpu_busy is None
        asyncio.run(go())

    def test_enabled(self, short_dir):
        docker = FakeDocker(short_dir)
        assert sampler_of(docker, registry()).enabled is True
        assert sampler_of(docker, registry(), interval=0).enabled is False
        assert UsageSampler(registry(), UsageConfig(), docker_socket='').enabled is False

    def test_the_loop(self, short_dir):
        async def go():
            async with FakeDocker(short_dir) as docker:
                docker.add('h1', mem=3 * MIB)
                sampler = sampler_of(docker, registry(project()), interval=0.02)
                sampler.start()
                sampler.start()                                     # one task, whatever is asked
                for _ in range(200):
                    if len(docker.requests) >= 3:
                        break
                    await asyncio.sleep(0.01)
                assert len(docker.requests) >= 3 and row(sampler)['mem_mb'] == 3.0
                await sampler.stop()
                seen = len(docker.requests)
                await asyncio.sleep(0.08)
                assert len(docker.requests) == seen
                await sampler.stop()                                # a second stop is nothing
                # an agent that measures nothing starts no task
                idle = UsageSampler(registry(), UsageConfig(), docker_socket='')
                idle.start()
                assert idle._task is None
        asyncio.run(go())

    def test_a_failing_measure_does_not_end_the_loop(self, short_dir, monkeypatch, caplog):
        async def go():
            async with FakeDocker(short_dir) as docker:
                sampler = sampler_of(docker, registry(project()), interval=0.01)
                calls = []

                async def broken():
                    calls.append(1)
                    raise ZeroDivisionError("a bug")
                monkeypatch.setattr(sampler, 'sample', broken)
                with caplog.at_level(logging.ERROR, logger='sreweb.agent'):
                    sampler.start()
                    for _ in range(200):
                        if len(calls) >= 2:
                            break
                        await asyncio.sleep(0.01)
                    await sampler.stop()
                assert len(calls) >= 2 and "usage sample failed" in caplog.text
        asyncio.run(go())


# ---------------------------------------------------------------------------------------------
# the fake host of the fake pool (tests/fake_docker.py run as a program)
# ---------------------------------------------------------------------------------------------

class TestSimulation:
    """``Simulation``: the projects of an agent on the fake sre get containers that use memory
    and processor time, and the fake host a memory that follows them."""

    def info(self, projects, rln, lab_name, lab_hash):
        (projects / rln).mkdir(parents=True)
        (projects / rln / 'info.json').write_text(json.dumps({'lab_name': lab_name, 'lab_hash': lab_hash}))

    def test_projects_containers_and_memory(self, tmp_path):
        from fake_docker import Simulation, HOST_BASE_MB
        projects = tmp_path / 'projects'
        docker = FakeDocker(tmp_path / 'docker')
        sim = Simulation(docker, projects, {'sre/big.py': [10, 2000, 1.5]}, mem_total_mb=16000)
        meminfo = (tmp_path / 'docker' / 'meminfo').read_text()
        assert f"MemTotal:       {16000 * 1024} kB" in meminfo and f"MemAvailable:   {(16000 - HOST_BASE_MB) * 1024} kB" in meminfo
        self.info(projects, 'r1', 'sre@big.py', 'h1')
        self.info(projects, 'r2', 's4@other', 'h2')                     # not in the table: the default usage
        (projects / 'starting').mkdir()                                 # no info.json yet: no container
        sim.step(10.0)
        by_lab = {}
        for cid, container in docker.containers.items():
            by_lab.setdefault(container['lab_hash'], []).append(cid)
        assert {lab: len(ids) for lab, ids in by_lab.items()} == {'h1': 10, 'h2': 4}
        figures = [read_container(str(docker.cgroup_root), cid) for cid in by_lab['h1']]
        assert sum(m for m, _ in figures) / MIB == pytest.approx(2000, abs=0.01)
        assert sum(u for _, u in figures) == pytest.approx(15e6, rel=1e-6)   # 1.5 cores for 10 s
        assert cpu_usec(str(docker.cgroup_root)) == pytest.approx(15e6 + 0.02 * 10e6, rel=1e-6)
        available = 16000 - HOST_BASE_MB - 2000 - 60
        assert f"MemAvailable:   {available * 1024} kB" in (tmp_path / 'docker' / 'meminfo').read_text()
        # a project closed: its containers go, the memory comes back
        (projects / 'r1' / 'info.json').unlink()
        (projects / 'r1').rmdir()
        sim.step(1.0)
        assert {c['lab_hash'] for c in docker.containers.values()} == {'h2'}
        assert f"MemAvailable:   {(available + 2000) * 1024} kB" in (tmp_path / 'docker' / 'meminfo').read_text()

    def test_the_sampler_measures_a_fake_host(self, short_dir, tmp_path):
        """The agent's sampler on the fake host: what the fake pool gives the portal."""
        from fake_docker import Simulation
        projects = tmp_path / 'projects'
        self.info(projects, RLN, 'sre@dhcp.py', 'h1')

        async def go():
            async with FakeDocker(short_dir) as docker:
                sim = Simulation(docker, projects, {'sre/dhcp.py': [15, 300, 0.1]})
                clock = Clock()
                sampler = sampler_of(docker, registry(project()), clock)
                await sampler.sample()
                for _ in range(2):
                    clock.advance(SETTLE_AFTER)
                    sim.step(SETTLE_AFTER)
                    await sampler.sample()
                assert row(sampler) == {'name': RLN, 'lab': 'sre@dhcp.py', 'containers': 15, 'mem_mb': 300.0,
                                        'cpu': 0.1, 'settled': True}
                assert sampler.cpu_busy == pytest.approx(0.1, rel=1e-3)
        asyncio.run(go())


# ---------------------------------------------------------------------------------------------
# [usage] of agent.toml
# ---------------------------------------------------------------------------------------------

class TestConfig:
    BASE = {'token': 't' * 32}

    def test_defaults(self):
        cfg = agent_config_from_dict(dict(self.BASE))
        assert cfg.usage == UsageConfig(interval=15.0, docker_socket='', cgroup_root='/sys/fs/cgroup',
                                        meminfo='/proc/meminfo')

    def test_values(self):
        cfg = agent_config_from_dict({**self.BASE, 'usage': {'interval': '1m', 'docker_socket': '/run/docker.sock',
                                                             'cgroup_root': '/cg', 'meminfo': '/x/meminfo'}})
        assert cfg.usage == UsageConfig(interval=60.0, docker_socket='/run/docker.sock', cgroup_root='/cg',
                                        meminfo='/x/meminfo')
        assert agent_config_from_dict({**self.BASE, 'usage': {'interval': 0}}).usage.interval == 0

    @pytest.mark.parametrize('table, message', [
        ({'interval': -1}, 'negative'),
        ({'interval': True}, 'duration'),
        ({'docker_socket': 'docker.sock'}, 'docker_socket must be an absolute path'),
        ({'docker_socket': 3}, 'docker_socket must be an absolute path'),
        ({'cgroup_root': ''}, 'cgroup_root must be an absolute path'),
        ({'cgroup_root': 'sys'}, 'cgroup_root must be an absolute path'),
        ({'meminfo': 'meminfo'}, 'meminfo must be an absolute path'),
        ({'meminfo': 7}, 'meminfo must be an absolute path'),
        ({'intervall': 5}, 'unknown key'),
    ])
    def test_refused(self, table, message):
        with pytest.raises(ConfigError, match=message):
            agent_config_from_dict({**self.BASE, 'usage': table})

    def test_not_a_table(self):
        with pytest.raises(ConfigError, match=r"\[usage\] must be a table"):
            agent_config_from_dict({**self.BASE, 'usage': 15})

    def test_the_wire_keys(self):
        """The keys the portal reads (portal/pool.py imports these constants)."""
        assert (usage.STATUS_CPUS, usage.STATUS_MEM_TOTAL, usage.STATUS_CPU_BUSY, usage.STATUS_USAGE) == (
            'cpus', 'mem_total_mb', 'cpu_busy', 'usage')
