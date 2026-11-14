"""The machines of the exams of the web front-end: an exam taken at pool hosts with the Qt GUI,
whose agents write ``exam.json`` for the portal (``src/sreweb/portal/exams.py``: ``ExamHost``,
the lock and release delays, the phase ``local``; ``examhosts.py``: the reconciler;
``examstore.py``; the pool and its policy; the routes).  The model and the registry alone, the
store on the fake database, the reconciler on fake machines behind a real ``Pool``, then the
whole thing through the portal with a real agent on the fake ``sre``."""
import asyncio
import json
import subprocess
import time
from datetime import datetime

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from test_agent_exam import start_by_hand                     # noqa: E402  (a project of the Qt GUI)
import test_pool_manager as M                                 # noqa: E402  (the fake session of the agents)
import test_web_exams as E                                    # noqa: E402  (the fakes of the exams)
import test_web_portal as P                                   # noqa: E402
from SRE import params                                        # noqa: E402
from sreweb.config import HostConfig, PoolConfig              # noqa: E402
from sreweb.portal import exams as X                          # noqa: E402
from sreweb.portal import examhosts as XH                     # noqa: E402
from sreweb.portal.accesslog import parse_line                # noqa: E402
from sreweb.portal.manager import HostView, poweroff_plan, spare_capacity, awake_count   # noqa: E402
from sreweb.portal.pool import Pool, PoolError, host_exam_fields, status_from_json     # noqa: E402

ALICE, BOB, CAROL, PROF = E.ALICE, E.BOB, E.CAROL, E.PROF     # alice, bob: INFO1; carol: INFO2
run = E.run
NOW = E.NOW
CFG = E.CFG
DHCP, SSH, EXAM1 = E.DHCP, E.SSH, E.EXAM1
ORIGIN = 'portal-a'
START, END = NOW + 3600, NOW + 9000        # a window of 90 minutes, in an hour


def spec(**over) -> dict:
    """A parsed definition of an exam for INFO1 on the machines z01 and z02."""
    body = {'title': 'Partiel', 'audience': {'groups': ['department:INFO1']}, 'labs': [DHCP], 'duration': 60,
            'start_after': START, 'end_before': END, 'hosts': ['z01', 'z02']}
    body.update(over)
    return X.parse_exam(body, cfg=CFG, now=NOW)


# ---------------------------------------------------------------------------------------------
# the model
# ---------------------------------------------------------------------------------------------

class TestParse:
    def test_machines_and_delays(self):
        s = spec()
        assert s['hosts'] == ['z01', 'z02'] and (s['host_lead'], s['host_release']) == (600, 600)
        s = spec(hosts=[' z02 ', 'z01'], host_lead=30, host_release=0)
        assert s['hosts'] == ['z02', 'z01'] and (s['host_lead'], s['host_release']) == (1800, 0)
        assert spec(host_lead=None)['host_lead'] == 600
        # web only: no machine, as before
        web = E.spec()
        assert web['hosts'] == [] and (web['host_lead'], web['host_release']) == (600, 600)
        # machines only: no audience
        s = spec(audience={})
        assert s['logins'] == set() and s['groups'] == set() and s['hosts'] == ['z01', 'z02']
        s = X.parse_exam({'title': 't', 'labs': [DHCP], 'end_before': END, 'hosts': ['z01']}, cfg=CFG, now=NOW)
        assert s['hosts'] == ['z01'] and s['duration'] is None

    @pytest.mark.parametrize('over, fragment', [
        ({'hosts': 'z01'}, 'list of machine names'),
        ({'hosts': ['z01', 3]}, 'list of machine names'),
        ({'hosts': ['z01', 'z01']}, 'twice'),
        ({'hosts': [f'h{i}' for i in range(501)]}, 'at most'),
        ({'hosts': ['a\nb']}, 'invalid machine name'),
        ({'end_before': None}, 'end time is required when machines'),
        ({'audience': {}, 'hosts': []}, 'audience is empty'),
        ({'host_lead': -1}, 'host_lead'),
        ({'host_release': 'x'}, 'host_release'),
    ])
    def test_refused(self, over, fragment):
        with pytest.raises(ValueError, match=fragment):
            spec(**over)

    def test_known_machines(self):
        body = {'title': 't', 'labs': [DHCP], 'end_before': END, 'hosts': ['z01', 'z09']}
        with pytest.raises(ValueError, match="unknown machine 'z09'"):
            X.parse_exam(body, cfg=CFG, now=NOW, known_hosts={'z01', 'z02'})
        assert X.parse_exam(body, cfg=CFG, now=NOW, known_hosts={'z01', 'z09'})['hosts'] == ['z01', 'z09']
        # an edit keeps a machine the pool lost meanwhile, and the machines when it does not name them
        clock, presence, reg = E.registry()
        exam = run(reg.create(PROF, spec()))
        edited = X.parse_exam({'hosts': ['z02', 'z01']}, cfg=CFG, now=NOW, current=exam, known_hosts={'z01'})
        assert edited['hosts'] == ['z02', 'z01']
        with pytest.raises(ValueError, match="unknown machine 'z03'"):
            X.parse_exam({'hosts': ['z03']}, cfg=CFG, now=NOW, current=exam, known_hosts={'z01'})
        kept = X.parse_exam({'title': 'New'}, cfg=CFG, now=NOW, current=exam)
        assert kept['hosts'] == ['z01', 'z02'] and kept['host_lead'] == 600 and kept['host_release'] == 600
        with pytest.raises(ValueError, match="end time is required"):
            X.parse_exam({'end_before': None}, cfg=CFG, now=NOW, current=exam)
        # the audience may go once the exam has machines, not both
        assert X.parse_exam({'audience': {}}, cfg=CFG, now=NOW, current=exam)['groups'] == set()
        with pytest.raises(ValueError, match="audience is empty"):
            X.parse_exam({'audience': {}, 'hosts': []}, cfg=CFG, now=NOW, current=exam)


class TestClock:
    def exam(self, **over):
        clock, presence, reg = E.registry()
        return reg, run(reg.create(PROF, spec(**over)))

    def test_lock_hold_and_release(self):
        reg, exam = self.exam(host_lead=20, host_release=15)
        host = exam.hosts['z01']
        assert exam.lock_at() == START - 1200 and exam.hold_at() == START - 1200
        assert exam.host_end_before(host) == END and exam.release_at(host) == END + 900
        assert not exam.host_wanted(host, START - 1201) and exam.host_wanted(host, START - 1200)
        assert exam.host_wanted(host, END + 899) and not exam.host_wanted(host, END + 900)
        assert not exam.host_held(host, START - 1201) and exam.host_held(host, END)
        # the web exam projects start before the lock: no placement on the machines from then
        reg, exam = self.exam(host_lead=2, pre_start=5)
        assert exam.lock_at() == START - 120 and exam.hold_at() == START - 300
        assert exam.host_held(exam.hosts['z01'], START - 200) and not exam.host_wanted(exam.hosts['z01'], START - 200)
        # no start time: locked from the creation
        reg, exam = self.exam(start_after=None)
        assert exam.lock_at() is None and exam.hold_at() is None and exam.host_wanted(exam.hosts['z01'], NOW)
        assert exam.to_dict(NOW)['hosts'] == ['z01', 'z02'] and exam.to_dict(NOW)['lock_at'] is None
        summary = self.exam()[1].to_dict(NOW)
        assert (summary['host_lead'], summary['host_release'], summary['lock_at']) == (10, 10, START - 600)

    def test_minutes_and_end_now_of_a_machine(self):
        reg, exam = self.exam()
        z01, z02 = exam.hosts['z01'], exam.hosts['z02']
        run(reg.adjust(exam.id, None, 5, {'z01'}))
        assert (z01.extra_minutes, z02.extra_minutes) == (5, 0)
        assert exam.host_end_before(z01) == END + 300 and exam.release_at(z01) == END + 900
        assert exam.host_end_before(z02) == END
        run(reg.end_now(exam.id, None, {'z02'}, now=START + 60))
        assert exam.host_end_before(z02) == START + 60 and exam.release_at(z02) == START + 660
        assert exam.ended_at is None and exam.host_end_before(z01) == END + 300
        # minutes lift the End now of the machine
        run(reg.adjust(exam.id, None, -2, {'z02'}))
        assert z02.ended_at is None and exam.host_end_before(z02) == END - 120
        # an End now of everybody caps every machine; minutes for everybody lift it and shift the window
        run(reg.end_now(exam.id, None, now=START + 120))
        assert exam.host_end_before(z01) == START + 120
        run(reg.adjust(exam.id, None, 10))
        assert exam.ended_at is None and exam.end_before == END + 600 and exam.host_end_before(z01) == END + 900
        with pytest.raises(ValueError, match="not a machine of this exam"):
            run(reg.adjust(exam.id, None, 5, {'z09'}))

    def test_phases_of_a_machine(self):
        reg, exam = self.exam()
        host = exam.hosts['z01']
        assert exam.host_phase(host, START - 601) == 'scheduled'
        assert exam.host_phase(host, START - 600) == 'waiting'
        assert exam.host_phase(host, START) == 'starting'
        assert exam.host_phase(host, START + 30, started_at=START + 20) == 'active'
        # its own clock: an hour from its start, before the end of the window
        assert exam.host_end_at(host, START + 20) == START + 3620 and exam.host_end_at(host) == END
        assert exam.host_phase(host, START + 3620, started_at=START + 20) == 'ended'
        assert exam.host_phase(host, END) == 'ended'
        host.extra_minutes = 10
        assert exam.host_end_at(host, START + 20) == START + 4220
        host.closed_at = END
        assert exam.host_phase(host, START) == 'closed' and not exam.host_wanted(host, START)

    def test_status_follows_the_machines(self):
        reg, exam = self.exam(audience={})
        assert exam.status(START - 1) == 'scheduled' and exam.status(END - 1) == 'running'
        assert exam.status(END) == 'past'
        run(reg.adjust(exam.id, None, 5, {'z02'}))
        assert exam.status(END) == 'running' and exam.status(END + 300) == 'past'
        exam.hosts['z02'].closed_at = END
        assert exam.status(END) == 'past'


class TestConflict:
    def test_a_machine_serves_one_exam_at_a_time(self):
        clock, presence, reg = E.registry()
        first = run(reg.create(PROF, spec(title='First')))             # locked START-600 … END+600
        assert X.host_conflict(spec(), reg.listing(), NOW) == "the machine z01 is taken by the exam «First» at that time"
        assert X.host_conflict(spec(hosts=['z03']), reg.listing(), NOW) is None
        assert X.host_conflict(E.spec(), reg.listing(), NOW) is None                      # no machine
        # right after its release, right before its lock
        after = spec(start_after=END + 1200, end_before=END + 5000)
        assert X.host_conflict(after, reg.listing(), NOW) is None
        assert X.host_conflict(spec(start_after=END + 1199, end_before=END + 5000), reg.listing(), NOW) is not None
        before = spec(start_after=NOW + 700, end_before=START - 1200)
        assert X.host_conflict(before, reg.listing(), NOW) is None
        assert X.host_conflict(spec(start_after=NOW + 700, end_before=START - 1199), reg.listing(), NOW) is not None
        # the exam being edited is not its own rival; a machine it is closed on is free again
        assert X.host_conflict(spec(), reg.listing(), NOW, skip=first) is None
        run(reg.close_hosts(first.id, ['z01']))
        assert X.host_conflict(spec(hosts=['z01']), reg.listing(), NOW) is None
        assert X.host_conflict(spec(hosts=['z02']), reg.listing(), NOW) is not None
        # an exam without start time holds its machines from now
        run(reg.delete(first.id))
        run(reg.create(PROF, spec(title='Open', start_after=None, end_before=NOW + 600)))
        assert X.host_conflict(spec(start_after=None, end_before=NOW + 300), reg.listing(), NOW) is not None
        assert X.host_conflict(spec(), reg.listing(), NOW + 1201) is None


class TestRegistry:
    def test_edit_keeps_the_records_of_the_machines(self):
        clock, presence, reg = E.registry()
        exam = run(reg.create(PROF, spec()))
        run(reg.adjust(exam.id, None, 5, {'z01'}))
        z01 = exam.hosts['z01']
        edited = X.parse_exam({'hosts': ['z01', 'z03'], 'host_release': 0}, cfg=CFG, now=NOW, current=exam)
        run(reg.update(exam.id, edited))
        assert list(exam.hosts) == ['z01', 'z03'] and exam.hosts['z01'] is z01 and z01.extra_minutes == 5
        assert exam.hosts['z03'].extra_minutes == 0 and exam.host_release == 0

    def test_close_is_for_good(self):
        clock, presence, reg = E.registry()
        exam = run(reg.create(PROF, spec()))
        assert run(reg.close_hosts(exam.id, ['z01'], now=START)) == ['z01']
        z01 = exam.hosts['z01']
        assert z01.closed_at == START and z01.close_pending is True
        for action in (reg.adjust(exam.id, None, 5, {'z01'}), reg.end_now(exam.id, None, {'z01'}),
                       reg.close_hosts(exam.id, ['z01'])):
            with pytest.raises(ValueError, match="the exam is closed on the machine z01"):
                run(action)
        assert z01.extra_minutes == 0
        # every machine still open; the agent's answer ends the wait
        assert run(reg.close_hosts(exam.id)) == ['z02'] and run(reg.close_hosts(exam.id)) == []
        run(reg.host_closed(exam, 'z01'))
        assert z01.close_pending is False and z01.closed_at == START
        # unselected then selected again: a fresh record
        run(reg.update(exam.id, X.parse_exam({'hosts': ['z02']}, cfg=CFG, now=NOW, current=exam)))
        run(reg.update(exam.id, X.parse_exam({'hosts': ['z02', 'z01']}, cfg=CFG, now=NOW, current=exam)))
        assert exam.hosts['z01'].closed_at is None and exam.hosts['z02'].closed_at is not None

    def test_a_student_at_a_machine_takes_the_exam_there(self):
        clock, presence, reg = E.registry(now=START - 300)          # the lead window
        wa = E.FakeWatcher()
        presence.add(ALICE, '/projects', wa)
        exam = run(reg.create(PROF, spec()))
        assert wa.sent == [E.pushed(1, 'waiting')]
        m = run(reg.set_local(exam, 'alice', 'z01'))
        assert m.local == 'z01' and m.first_seen == START - 300 and wa.sent[-1] == E.pushed(1, 'local')
        assert run(reg.set_local(exam, 'alice', 'z01')) is None      # nothing new
        assert reg.for_login('alice', 'INFO1') == (exam, m, 'local')
        assert reg.start_access('alice', 'INFO1', DHCP) == (False, "you take this exam on the workstation z01")
        assert reg.project_access('alice', 'INFO1', '20261104100000@@@sre@dhcp.py@@@alice')[0] is False
        assert reg.visible_rows('alice', 'INFO1', [E.row(DHCP, 'r1'), E.row(SSH, 'r2')]) == []
        view = reg.student_view(exam, m, 'local', address='10.0.0.5', allowed=True)
        assert view['local_host'] == 'z01' and view['phase'] == 'local' and view['dismissable'] is False
        # no web clock for them, whatever projects their browser had started
        clock.now = START + 10
        assert run(reg.observe(exam, 'alice', [E.row(DHCP, 'r1')])) is True and m.started_at is None
        run(reg.tick())
        assert m.started_at is None and reg.for_login('alice', 'INFO1')[2] == 'local'
        # the phase before the lead: not bound yet, as anybody
        assert exam.phase(m, START - 601) == 'scheduled'
        # bob, on the web: the usual phases, his clock starts
        run(reg.observe(exam, 'bob', [E.row(DHCP, 'r9', owner='bob')]))
        assert exam.members['bob'].started_at == START + 10
        assert run(reg.set_local(exam, 'bob', 'z02')) is None and exam.members['bob'].local == ''
        # the machine closed: the exam is over for her on the web site too, the usual pages are back
        run(reg.close_hosts(exam.id, ['z01']))
        assert reg.for_login('alice', 'INFO1') is None and exam.phase(m, clock.now) == 'past'
        assert wa.sent[-1] == {'t': 'exam', 'id': 1, 'phase': None}
        assert run(reg.set_local(exam, 'carol', 'z01')) is None      # nobody takes it at a closed machine
        assert run(reg.set_local(exam, 'carol', 'z09')) is None

    def test_another_machine_and_a_machine_unselected(self):
        clock, presence, reg = E.registry(now=START)
        exam = run(reg.create(PROF, spec()))
        m = run(reg.set_local(exam, 'alice', 'z01'))
        assert run(reg.set_local(exam, 'alice', 'z02')) is m and m.local == 'z02'     # she moved
        run(reg.update(exam.id, X.parse_exam({'hosts': ['z01']}, cfg=CFG, now=START, current=exam)))
        assert m.local == '' and reg.for_login('alice', 'INFO1')[2] == 'starting'     # back to the web exam

    def test_projects_on_the_machines_are_never_web_exam_projects(self):
        """The project the Qt GUI started at a machine of the exam is listed by the agent of
        that machine as the student's: neither recorded as their web exam project (their clock
        would start) nor shown on their Projects page."""
        clock, presence, reg = E.registry(now=START + 5)
        exam = run(reg.create(PROF, spec()))
        rows = [E.row(DHCP, 'local1', host='z01'), E.row(DHCP, 'web1', host='a01')]
        run(reg.observe(exam, 'alice', rows[:1]))
        m = exam.members['alice']
        assert m.projects == {} and m.started_at is None
        run(reg.observe(exam, 'alice', rows))
        assert m.projects == {DHCP: {'host': 'a01', 'rln': 'web1', 'synced': None}} and m.started_at == START + 5
        assert [r['running_lab_name'] for r in reg.visible_rows('alice', 'INFO1', rows)] == ['web1']


class TestStore:
    def test_round_trip(self):
        server = E.FakeExamsServer()
        store = E.make_store(server)
        clock, presence, reg = E.registry(store=store)
        exam = run(reg.create(PROF, spec(host_lead=20, host_release=0)))
        run(reg.adjust(exam.id, None, 7, {'z01'}))
        run(reg.end_now(exam.id, None, {'z02'}, now=NOW + 50))
        run(reg.close_hosts(exam.id, ['z02'], now=NOW + 60))
        run(reg.set_local(exam, 'alice', 'z01'))
        details = json.loads(server.exams[1][8])
        assert details['host_lead'] == 1200 and details['host_release'] == 0
        assert details['hosts'][0] == {'name': 'z01', 'extra_minutes': 7, 'ended_at': None, 'closed_at': None,
                                       'close_pending': False}
        _, _, reg2 = E.registry(store=E.make_store(server))
        assert run(reg2.load()) == 1
        loaded = reg2.get(1)
        assert loaded.to_dict(NOW, 0) == exam.to_dict(NOW, 0)
        assert {n: h.to_dict() for n, h in loaded.hosts.items()} == {n: h.to_dict() for n, h in exam.hosts.items()}
        assert loaded.hosts['z02'].closed_at == NOW + 60 and loaded.hosts['z02'].close_pending is True
        assert loaded.members['alice'].local == 'z01' and loaded.members['alice'].to_dict()['local'] == 'z01'

    def test_rows_written_before_the_machines(self):
        """An exam stored by an earlier portal: no machine, the delays of the configuration;
        a damaged record is skipped."""
        server = E.FakeExamsServer()
        clock, presence, reg = E.registry(store=E.make_store(server))
        run(reg.create(PROF, E.spec()))
        details = json.loads(server.exams[1][8])
        for key in ('hosts', 'host_lead', 'host_release'):
            del details[key]
        server.exams[1][8] = json.dumps(details)
        _, _, reg2 = E.registry(store=E.make_store(server, host_lead=120.0, host_release=30.0))
        run(reg2.load())
        loaded = reg2.get(1)
        assert loaded.hosts == {} and (loaded.host_lead, loaded.host_release) == (120, 30)
        details['hosts'] = [{'name': 'z01', 'extra_minutes': 'x', 'ended_at': True}, {'name': ''}, 'z02', None]
        details['host_lead'] = 'soon'
        server.exams[1][8] = json.dumps(details)
        _, _, reg3 = E.registry(store=E.make_store(server))
        run(reg3.load())
        loaded = reg3.get(1)
        assert list(loaded.hosts) == ['z01'] and loaded.hosts['z01'].to_dict() == X.ExamHost('z01').to_dict()
        assert loaded.host_lead == 600

    def test_origin(self):
        a, b = E.make_store(E.FakeExamsServer()), E.make_store(E.FakeExamsServer())
        assert a.origin() == b.origin() and len(a.origin()) == 16 and XH.revision({'rev': 'x'}) != a.origin()
        assert E.make_store(E.FakeExamsServer(), table='exams2').origin() != a.origin()


# ---------------------------------------------------------------------------------------------
# what a machine is told
# ---------------------------------------------------------------------------------------------

class TestPayload:
    def exam(self, **over):
        clock, presence, reg = E.registry()
        return reg, run(reg.create(PROF, spec(**over)))

    def test_the_definition_of_a_machine(self):
        reg, exam = self.exam(labs=[{'lab': EXAM1, 'flavor': 'hard'}, DHCP], eval_interval=30)
        payload = XH.host_payload(exam, exam.hosts['z01'], ORIGIN)
        rev = payload.pop('rev')
        assert payload == {'id': '1', 'title': 'Partiel', 'origin': ORIGIN,
                           'labs': [{'lab': EXAM1, 'flavor': 'hard'}, {'lab': DHCP, 'flavor': None}],
                           'start_after': X.iso_utc(START), 'end_before': X.iso_utc(END), 'duration': 60,
                           'eval_interval': 30}
        assert rev == XH.revision(payload) == XH.revision({**payload, 'rev': 'x', 'now': 'y'}) and len(rev) == 16
        assert XH.host_payload(exam, exam.hosts['z02'], ORIGIN)['rev'] == rev        # the same file on every machine
        assert XH.host_payload(exam, exam.hosts['z01'], 'portal-b')['rev'] != rev

    def test_minutes_and_end_now_change_the_revision(self):
        reg, exam = self.exam()
        before = XH.host_payload(exam, exam.hosts['z01'], ORIGIN)
        run(reg.adjust(exam.id, None, 5, {'z01'}))
        after = XH.host_payload(exam, exam.hosts['z01'], ORIGIN)
        assert (after['duration'], after['end_before']) == (65, X.iso_utc(END + 300)) and after['rev'] != before['rev']
        assert XH.host_payload(exam, exam.hosts['z02'], ORIGIN) == before
        run(reg.end_now(exam.id, None, {'z02'}, now=START + 90))
        ended = XH.host_payload(exam, exam.hosts['z02'], ORIGIN)
        assert ended['end_before'] == X.iso_utc(START + 90) and ended['duration'] == 60

    def test_a_window_alone_gives_its_length_as_duration(self):
        """The GUI takes 90 minutes when the file has no duration: the window is sent, which
        the end-before time always beats."""
        reg, exam = self.exam(duration=None, start_after=START, end_before=START + 7230)
        assert XH.host_payload(exam, exam.hosts['z01'], ORIGIN)['duration'] == 121
        reg, exam = self.exam(duration=None, start_after=None, end_before=NOW + 600)
        payload = XH.host_payload(exam, exam.hosts['z01'], ORIGIN)
        assert payload['duration'] == 10 and payload['start_after'] is None
        exam.title = 'Par\x00tiel'
        assert XH.host_payload(exam, exam.hosts['z01'], ORIGIN)['title'] == 'Partiel'

    def test_file_running(self):
        assert not XH.file_running({'started_at': None, 'end_before': END, 'duration': 60}, START)
        started = {'started_at': START, 'end_before': END, 'duration': 60}
        assert XH.file_running(started, START + 3599) and not XH.file_running(started, START + 3600)
        assert not XH.file_running({**started, 'end_before': START + 60}, START + 60)
        assert XH.file_running({'started_at': START, 'end_before': None, 'duration': None}, END * 2)


# ---------------------------------------------------------------------------------------------
# the reconciler on fake machines
# ---------------------------------------------------------------------------------------------

def view_of(payload: dict, previous: dict | None = None) -> dict:
    """The ``exam`` of a status for a machine that took *payload* (what the agent answers)."""
    previous = previous or {}
    return {'id': payload['id'], 'title': payload['title'], 'rev': payload['rev'], 'origin': payload['origin'],
            'labs': [[l['lab'], l['flavor']] for l in payload['labs']], 'start_after': payload['start_after'],
            'end_before': payload['end_before'], 'duration': payload['duration'],
            'eval_interval': payload['eval_interval'], 'pre_started': previous.get('pre_started', False),
            'started_at': previous.get('started_at'), 'ended_at': previous.get('ended_at')}


class Room:
    """The agents of a few machines: the exam file each one holds, the sessions at its
    keyboard; a relay answering ``PUT`` / ``DELETE /v1/exam`` as the agent does, a real ``Pool``
    polling their status (``poll``)."""

    def __init__(self, names=('z01', 'z02')):
        self.session = M.FakeSession()
        self.pool = Pool([HostConfig(name=n, url=f'http://{n}', token=P.TOKEN, max_projects=5) for n in names],
                         self.session)
        self.files = {n: None for n in names}
        self.logged_in = {n: [] for n in names}
        self.off: set = set()
        self.old: set = set()               # agents that know no exam of the host
        self.refusals: dict = {}            # name -> (status, body) answered to a PUT or a DELETE
        self.calls = []

    def answer(self, name):
        if name in self.off:
            return None
        sessions = [f'session:{login}' for login in self.logged_in[name]]
        status = M.up(exam_mode=self.files[name] is not None, occupied=bool(sessions), occupied_by=sessions)
        if name not in self.old:
            status['exam'] = self.files[name]
        return status

    async def poll(self):
        for name in self.files:
            self.session.answers[f'http://{name}'] = self.answer(name)
        await self.pool.refresh()

    async def json(self, host, identity, method, path, *, json=None, params=None, timeout=60.0):
        name = host.name
        assert path == '/exam' and identity.role == 'instructor'
        self.calls.append((name, method, dict(json if json is not None else params or {}), identity.login))
        if name in self.off:
            raise PoolError(502, "the agent does not answer")
        if name in self.old:
            return 404, {'error': 'not found'}
        if name in self.refusals:
            return self.refusals[name]
        current = self.files[name]
        if method == 'PUT':
            if current is not None and (current['id'] != json['id'] or current['origin'] != json['origin']):
                return 409, {'error': "an exam set with sre set-exam is on this host" if current['id'] is None
                             else f"the exam {current['id']} is on this host"}
            self.files[name] = view_of(json, current)
            return 200, {'ok': True, 'exam': self.files[name]}
        if current is not None and current['id'] != params['id']:
            return 409, {'error': f"the exam {current['id']} is on this host"}
        self.files[name] = None
        return 200, {'ok': True, 'exam': None, 'closed': 1 if params.get('close') and current else 0, 'failed': 0}

    def made(self, since=0) -> list:
        return [(name, method) for name, method, _, _ in self.calls[since:]]


class FakeProjects:
    """``ExamProjects`` as the reconciler uses it."""

    def __init__(self):
        self.closed = []

    async def close_member(self, exam, member):
        self.closed.append((exam.id, member.login, sorted(member.projects)))
        member.projects.clear()


def setup(now=START - 700, names=('z01', 'z02'), **over):
    clock, presence, reg = E.registry(now=now)
    room = Room(names)
    projects = FakeProjects()
    hosts = XH.ExamHosts(reg, room.pool, room, origin=ORIGIN, exam_projects=projects, clock=clock)
    run(room.poll())
    exam = run(reg.create(PROF, spec(**over)))
    return clock, presence, reg, room, hosts, exam, projects


async def settle(hosts):
    """The background tasks of the reconciler (the removals with close) run to their end."""
    for _ in range(5):
        tasks = [t for t in list(hosts._closing.values()) + list(hosts._tasks) if not t.done()]
        if not tasks:
            return
        await asyncio.gather(*tasks, return_exceptions=True)


class TestExamHosts:
    def test_the_file_goes_to_the_machines_at_the_lock(self):
        clock, presence, reg, room, hosts, exam, _ = setup()

        async def go():
            await hosts.sync()
            assert room.calls == []                                  # 100 s before the lock
            clock.now = START - 600
            await hosts.sync()
            assert room.made() == [('z01', 'PUT'), ('z02', 'PUT')]
            name, method, body, login = room.calls[0]
            assert login == 'prof' and body['now'] == X.iso_utc(START - 600)
            assert {k: v for k, v in body.items() if k != 'now'} == XH.host_payload(exam, exam.hosts['z01'], ORIGIN)
            assert room.files['z01']['id'] == '1' and room.pool.state_of('z01') == 'exam'
            # nothing more while the machines hold that revision: told by the answer, then by the polls
            await hosts.sync()
            await room.poll()
            await hosts.sync()
            assert len(room.calls) == 2 and hosts.errors == {}
            assert hosts.on_machine(exam, 'z01')['rev'] == body['rev']
        run(go())

    def test_the_tick_hook_is_paced(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)

        async def go():
            await hosts.reconcile()
            assert len(room.calls) == 2
            room.files['z01'] = None                                 # sre del-exam by hand on the machine
            await room.poll()
            clock.now = START + XH.RECONCILE_INTERVAL - 1
            await hosts.reconcile()
            assert len(room.calls) == 2
            clock.now = START + XH.RECONCILE_INTERVAL
            await hosts.reconcile()
            assert room.made(2) == [('z01', 'PUT')]                  # the portal says what a machine holds
        run(go())

    def test_minutes_reach_the_machine_they_are_for(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)

        async def go():
            await hosts.sync()
            await reg.adjust(exam.id, None, 5, {'z02'})
            await hosts.sync()
            assert room.made(2) == [('z02', 'PUT')]
            assert room.calls[2][2]['end_before'] == X.iso_utc(END + 300) and room.calls[2][2]['duration'] == 65
            await reg.adjust(exam.id, None, 10)                      # everybody
            await hosts.sync()
            assert room.made(3) == [('z01', 'PUT'), ('z02', 'PUT')]
            assert room.files['z02']['end_before'] == X.iso_utc(END + 900)
        run(go())

    def test_a_refusal_is_kept_and_tried_again_later(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)
        room.files['z01'] = view_of({**XH.host_payload(exam, exam.hosts['z01'], ORIGIN), 'id': None, 'rev': None,
                                     'origin': None})                # sre set-exam by hand

        async def go():
            await room.poll()
            await hosts.sync()
            assert room.made() == [('z01', 'PUT'), ('z02', 'PUT')]
            assert hosts.errors == {(1, 'z01'): (409, "an exam set with sre set-exam is on this host")}
            rows = {r['name']: r for r in hosts.rows_of(exam, [])}
            assert rows['z01']['phase'] == 'conflict' and rows['z01']['error'].startswith('an exam set')
            assert rows['z01']['locked'] is False and rows['z02']['phase'] == 'starting' and rows['z02']['locked']
            await hosts.sync()
            assert len(room.calls) == 2                              # not before RETRY_DELAY
            clock.now = START + XH.RETRY_DELAY
            await hosts.sync()
            assert room.made(2) == [('z01', 'PUT')] and (1, 'z01') in hosts.errors
            room.files['z01'] = None                                 # del-exam there
            await room.poll()
            clock.now += XH.RETRY_DELAY
            await hosts.sync()
            assert room.files['z01']['id'] == '1' and hosts.errors == {}
        run(go())

    def test_machines_away_or_too_old(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)
        room.off.add('z01')
        room.old.add('z02')

        async def go():
            await room.poll()
            await hosts.sync()
            assert room.calls == []                                  # one does not answer, the other cannot take it
            assert hosts.errors[(1, 'z02')][0] == 404 and 'too old' in hosts.errors[(1, 'z02')][1]
            rows = {r['name']: r for r in hosts.rows_of(exam, [])}
            assert rows['z01']['reachable'] is False and rows['z01']['phase'] == 'pending' and rows['z01']['state'] == 'off'
            assert rows['z02']['phase'] == 'pending' and 'too old' in rows['z02']['error']
            # switched on by a student: the file comes at the next pass
            room.off.clear()
            await room.poll()
            await hosts.sync()
            assert room.made() == [('z01', 'PUT')]
        run(go())

    def test_the_release_closes_the_machines(self):
        """At end-before + ``host_release`` the exam leaves the machines by itself: closed,
        like the ones an instructor closes; until then the file stays (the end screen)."""
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)

        async def go():
            await hosts.sync()
            clock.now = END + 599
            await hosts.sync()
            assert len(room.calls) == 2 and exam.hosts['z01'].closed_at is None
            clock.now = END + 600
            await hosts.sync()
            await settle(hosts)
            assert sorted(room.made(2)) == [('z01', 'DELETE'), ('z02', 'DELETE')]
            assert room.calls[2][2] == {'id': '1', 'origin': ORIGIN, 'close': '1'}
            assert room.files == {'z01': None, 'z02': None}
            z01 = exam.hosts['z01']
            assert z01.closed_at == END + 600 and z01.close_pending is False
            assert exam.host_phase(z01, clock.now) == 'closed' and room.pool.status['z01'].exam is None
            await hosts.sync()
            await settle(hosts)
            assert len(room.calls) == 4                              # for good
        run(go())

    def test_minutes_granted_during_the_delay_resume_the_exam(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)

        async def go():
            await hosts.sync()
            clock.now = END + 300                                    # the end screen, half the delay gone
            await reg.adjust(exam.id, None, 10, {'z01'})
            await hosts.sync()
            assert room.made(2) == [('z01', 'PUT')] and room.files['z01']['end_before'] == X.iso_utc(END + 600)
            clock.now = END + 600                                    # z02 is released, z01 runs again
            await hosts.sync()
            await settle(hosts)
            assert room.made(3) == [('z02', 'DELETE')]
            assert exam.hosts['z01'].closed_at is None and room.files['z01'] is not None
            clock.now = END + 1200
            await hosts.sync()
            await settle(hosts)
            assert room.made(4) == [('z01', 'DELETE')]
        run(go())

    def test_no_delay_releases_at_the_end(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START, host_release=0)

        async def go():
            await hosts.sync()
            clock.now = END - 1
            await hosts.sync()
            assert len(room.calls) == 2
            clock.now = END
            await hosts.sync()
            await settle(hosts)
            assert sorted(room.made(2)) == [('z01', 'DELETE'), ('z02', 'DELETE')]
        run(go())

    def test_close_by_an_instructor_and_a_close_that_fails(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START + 60)

        async def go():
            await hosts.sync()
            room.refusals['z01'] = (502, {'error': "1 project(s) of the exam could not be stopped"})
            await reg.close_hosts(exam.id, ['z01'])
            await hosts.sync()
            await settle(hosts)
            assert room.made(2) == [('z01', 'DELETE')] and room.files['z01'] is not None
            z01 = exam.hosts['z01']
            assert z01.close_pending is True and hosts.errors[(1, 'z01')][0] == 502
            row = hosts.rows_of(exam, [])[0]
            assert row['phase'] == 'closed' and row['closing'] is True and 'could not be stopped' in row['error']
            await hosts.sync()
            await settle(hosts)
            assert len(room.calls) == 3                              # after RETRY_DELAY only
            del room.refusals['z01']
            clock.now += XH.RETRY_DELAY
            await hosts.sync()
            await settle(hosts)
            assert room.files['z01'] is None and z01.close_pending is False and hosts.errors == {}
            assert room.files['z02'] is not None                     # the other machine goes on
        run(go())

    def test_a_close_of_a_machine_that_holds_nothing_is_done(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START - 700)

        async def go():
            await reg.close_hosts(exam.id, ['z01'])                  # before the lock: no file there
            await hosts.sync()
            assert room.calls == [] and exam.hosts['z01'].close_pending is False
            room.off.add('z02')
            await room.poll()
            await reg.close_hosts(exam.id, ['z02'])
            await hosts.sync()
            assert exam.hosts['z02'].close_pending is True           # away: asked when it is back
        run(go())

    def test_a_machine_no_longer_wanted_loses_the_file_without_a_close(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)

        async def go():
            await hosts.sync()
            # unselected: the projects of the GUI there stay, as plain ones
            await reg.update(exam.id, X.parse_exam({'hosts': ['z02']}, cfg=CFG, now=START, current=exam))
            await hosts.sync()
            assert room.made(2) == [('z01', 'DELETE')] and room.calls[2][2] == {'id': '1', 'origin': ORIGIN}
            # the start postponed beyond the lock: the machine is given back until then
            await reg.update(exam.id, X.parse_exam({'start_after': START + 7200, 'end_before': END + 7200},
                                                   cfg=CFG, now=START, current=exam))
            await hosts.sync()
            assert room.made(3) == [('z02', 'DELETE')] and room.files == {'z01': None, 'z02': None}
            clock.now = START + 6600
            await hosts.sync()
            assert room.made(4) == [('z02', 'PUT')]
        run(go())

    def test_files_of_nobody(self):
        """An exam deleted while a machine was away: its file is removed when it does not run
        there, left (with one warning) when students are at work; the file of another portal
        and one set by hand are not the portal's."""
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)
        payload = XH.host_payload(exam, exam.hosts['z01'], ORIGIN)

        async def go():
            await reg.delete(exam.id)
            room.files['z01'] = view_of({**payload, 'id': '7'})
            room.files['z02'] = {**view_of({**payload, 'id': '8'}), 'started_at': X.iso_utc(START - 60)}
            await room.poll()
            await hosts.sync()
            assert room.made() == [('z01', 'DELETE')] and room.calls[0][2] == {'id': '7', 'origin': ORIGIN}
            assert room.calls[0][3] == 'sre-web' and room.files['z02'] is not None
            await hosts.sync()
            assert len(room.calls) == 1
            clock.now = END + 1                                      # over: nobody works there any more
            await hosts.sync()
            assert room.made(1) == [('z02', 'DELETE')]
            room.files['z01'] = view_of({**payload, 'id': '9', 'origin': 'portal-b'})
            room.files['z02'] = view_of({**payload, 'id': None, 'rev': None, 'origin': None})
            await room.poll()
            await hosts.sync()
            assert len(room.calls) == 2
        run(go())

    def test_nothing_before_the_exams_are_loaded(self):
        """A portal starting while its database is down knows no exam: the machines must not
        look like they hold the exams of nobody."""
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)
        payload = XH.host_payload(exam, exam.hosts['z01'], ORIGIN)

        async def go():
            room.files['z01'] = view_of({**payload, 'id': '7'})
            await room.poll()
            reg.loaded = False
            await hosts.sync()
            await hosts.note_request(ALICE)
            assert room.calls == [] and not hosts.ready()
            reg.loaded = True
            unstored = XH.ExamHosts(reg, room.pool, room, origin='', clock=clock)
            await unstored.sync()
            assert room.calls == [] and not unstored.ready()
        run(go())

    def test_the_exam_deleted(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START)

        async def go():
            await hosts.sync()
            room.off.add('z02')
            await room.poll()
            await hosts.release(exam, close=True)
            await reg.delete(exam.id)
            await settle(hosts)
            assert room.made(2) == [('z01', 'DELETE')] and room.calls[2][2]['close'] == '1'
            # the machine that was away is cleaned when it is back (its exam did not start)
            room.off.clear()
            await room.poll()
            await hosts.sync()
            assert room.made(3) == [('z02', 'DELETE')] and 'close' not in room.calls[3][2]
        run(go())

    def test_students_logged_in_at_the_machines(self):
        clock, presence, reg, room, hosts, exam, projects = setup(now=START - 100, audience={
            'logins': ['dave'], 'groups': ['department:INFO1']})
        presence.add(ALICE, '/projects', E.FakeWatcher())
        presence.add(CAROL, '/projects', E.FakeWatcher())
        presence.add(PROF, '/exams', E.FakeWatcher())

        async def go():
            # bob pre-started a web exam project, then sat down at z02
            await reg.observe(exam, 'bob', [E.row(DHCP, 'web1', owner='bob')])
            room.logged_in['z01'] = ['alice', 'carol', 'prof']       # INFO1, INFO2, an instructor
            room.logged_in['z02'] = ['dave', 'bob', 'erin']          # a login of the audience, INFO1 not connected, unknown
            await room.poll()
            await hosts.sync()
            await settle(hosts)
            assert {m.login: m.local for m in exam.members.values()} == {'alice': 'z01', 'dave': 'z02', 'bob': ''}
            assert hosts.sessions('z01') == ['alice', 'carol', 'prof']
            assert hosts.session_host(exam, 'alice') == 'z01' and hosts.session_host(exam, 'zoe') is None
            # bob is seen by his own request (his group comes with his identity)
            await hosts.note_request(BOB)
            await settle(hosts)
            assert exam.members['bob'].local == 'z02' and projects.closed == [(1, 'bob', [DHCP])]
            await hosts.note_request(PROF)
            await hosts.note_request(CAROL)
            assert 'prof' not in exam.members and 'carol' not in exam.members
            rows = {r['name']: r for r in hosts.rows_of(exam, [])}
            assert rows['z02']['sessions'] == ['bob', 'dave', 'erin']
        run(go())

    def test_no_student_is_local_before_the_lock(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START - 700, audience={'logins': ['alice']})

        async def go():
            room.logged_in['z01'] = ['alice']
            await room.poll()
            await hosts.sync()
            await hosts.note_request(ALICE)
            assert exam.members == {}
        run(go())

    def test_rows_of_the_machines_table(self):
        clock, presence, reg, room, hosts, exam, _ = setup(now=START + 30)

        async def go():
            await hosts.sync()
            room.files['z01'] = {**room.files['z01'], 'pre_started': True, 'started_at': X.iso_utc(START + 20)}
            room.logged_in['z01'] = ['alice']
            await room.poll()
            await reg.adjust(exam.id, None, 5, {'z01'})
            listing = [dict(E.row(DHCP, 'local1', host='z01'), managed=False),
                       dict(E.row(DHCP, 'web1', host='z01', owner='bob'), managed=True),
                       dict(E.row(SSH, 'other', host='z01'), managed=False),
                       dict(E.row(DHCP, 'local2', host='a01'), managed=False)]
            rows = hosts.rows_of(exam, listing)
            assert [r['name'] for r in rows] == ['z01', 'z02']
            assert rows[0] == {'name': 'z01', 'state': 'exam', 'reachable': True, 'sessions': ['alice'],
                               'phase': 'active', 'locked': True, 'pre_started': True, 'started_at': START + 20,
                               'end_at': START + 20 + 3900, 'release_at': END + 900, 'extra_minutes': 5,
                               'ended_at': None, 'closed_at': None, 'closing': False, 'error': '',
                               'projects': [{'host': 'z01', 'rln': 'local1', 'lab': DHCP, 'owner': 'alice',
                                             'started_at': '20261104100000'}], 'web_projects': 0}
            assert rows[1]['phase'] == 'starting' and rows[1]['projects'] == [] and rows[1]['end_at'] == END
            # a machine the pool no longer has
            await reg.update(exam.id, X.parse_exam({'hosts': ['z01', 'gone']}, cfg=CFG, now=clock.now, current=exam))
            gone = hosts.rows_of(exam, [])[0]
            assert gone['name'] == 'gone' and gone['state'] is None and gone['phase'] == 'pending'
        run(go())


class TestPool:
    def test_the_exam_file_of_a_status_is_coerced(self):
        assert host_exam_fields(None) is None and host_exam_fields('x') is None
        fields = host_exam_fields({'id': '12', 'title': 'Partiel', 'rev': 'r1', 'origin': 'o',
                                   'start_after': '2023-11-14T23:13:20+00:00', 'end_before': 'x', 'duration': 90,
                                   'pre_started': 1, 'started_at': '2023-11-14T23:13:25+00:00', 'ended_at': None,
                                   'labs': [['a', None]]})
        assert fields == {'id': '12', 'title': 'Partiel', 'rev': 'r1', 'origin': 'o', 'start_after': START,
                          'end_before': None, 'duration': 90, 'pre_started': False, 'started_at': START + 5,
                          'ended_at': None}
        hand_set = host_exam_fields({'id': None, 'start_after': '2023-11-14T23:13:20', 'duration': 'x'})
        assert hand_set['id'] is None and hand_set['start_after'] is None and hand_set['duration'] is None
        assert status_from_json(M.up()).exam is None and status_from_json(M.up()).exam_known is False
        st = status_from_json(M.up(exam=None))
        assert st.exam is None and st.exam_known is True
        assert status_from_json(M.up(exam={'id': 3})).exam['id'] is None

    def test_a_machine_kept_for_an_exam_takes_no_project(self):
        room = Room()

        async def go():
            await room.poll()
            assert room.pool.pick(ALICE)[0].name == 'z01'
            room.pool.exam_hold = lambda name: name == 'z01'
            assert room.pool.pick(ALICE)[0].name == 'z02'
            with pytest.raises(PoolError) as e:
                room.pool.pick(PROF, 'z01')
            assert e.value.status == 503
            rows = {r['name']: r for r in room.pool.summary()}
            assert rows['z01']['exam_hold'] is True and rows['z02']['exam_hold'] is False
            assert 'polled_at' not in rows['z01'] and rows['z01']['exam'] is None
            # the session of a user at that machine does not override it either
            room.logged_in['z01'] = ['alice']
            await room.poll()
            assert room.pool.pick(ALICE)[0].name == 'z02'
            room.pool.exam_hold = lambda name: True
            with pytest.raises(PoolError):
                room.pool.pick(ALICE)
        run(go())

    def test_the_answer_of_the_agent_beats_an_older_status(self):
        room = Room()
        view = view_of(XH.host_payload(run_exam(), X.ExamHost('z01'), ORIGIN))

        async def go():
            await room.poll()
            room.pool.note_exam('z01', view)
            status = room.pool.status['z01']
            assert status.exam['id'] == '1' and status.exam_mode is True and room.pool.state_of('z01') == 'exam'
            # a status asked before the answer (still on its way) says "no exam": not believed
            room.pool.runtime['z01'].exam_told = time.monotonic() + 60
            await room.poll()
            assert room.pool.status['z01'].exam['id'] == '1' and room.pool.state_of('z01') == 'exam'
            # one asked after it tells
            room.pool.runtime['z01'].exam_told = time.monotonic() - 1
            await room.poll()
            assert room.pool.status['z01'].exam is None and room.pool.runtime['z01'].exam_told is None
            room.pool.note_exam('nope', view)                        # a host removed meanwhile
        run(go())

    def test_the_policy_leaves_a_kept_machine_on_and_out_of_the_capacity(self):
        def host(name, **over):
            base = dict(name=name, state='up', projects=0, max_projects=5, can_wake=True, enabled=True, power=True,
                        power_off_allowed=True, next_wake_at=0, idle_for=10_000, drain=False, power_off_pending=False)
            return HostView(**{**base, **over})

        cfg = PoolConfig(idle_host_timeout=600, spare_projects=0, min_hosts_up=0)
        assert poweroff_plan([host('z01'), host('z02', held=True)], cfg, active=False) == ['z01']
        assert poweroff_plan([host('z02', held=True)], cfg, active=False) == []
        assert poweroff_plan([host('z02', held=True, drain=True)], cfg, active=False) == ['z02']   # asked by hand
        hosts = [host('z01'), host('z02', held=True), host('z03', state='waking', held=True)]
        assert spare_capacity(hosts) == 5 and awake_count(hosts) == 1


def run_exam():
    clock, presence, reg = E.registry()
    return run(reg.create(PROF, spec()))


# ---------------------------------------------------------------------------------------------
# through the portal, a real agent behind
# ---------------------------------------------------------------------------------------------

PROF_H = P.who('prof', groups=P.TEACHERS)
ALICE_H = P.who('alice', group='INFO1')
BOB_H = P.who('bob', group='INFO1')


def exam_file(h):
    return h.pub / params.exam_json_name


def stored(h) -> dict:
    return json.loads(exam_file(h).read_text())


def body(**over) -> dict:
    data = {'title': 'Partiel', 'audience': {'groups': ['INFO1']}, 'labs': [DHCP], 'duration': 60,
            'end_before': time.time() + 7200, 'hosts': ['a01']}
    data.update(over)
    return data


async def until(condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        await asyncio.sleep(0.05)


async def machines(h, exam_id) -> dict:
    status, detail = await E.api(h, 'GET', f'/api/exams/{exam_id}', PROF_H)
    assert status == 200, detail
    return {row['name']: row for row in detail['machines']}


def local_session(login):
    """``loginctl`` as the agent runs it: one local session of *login*."""
    return lambda argv, **kw: subprocess.CompletedProcess(
        argv, 0, f"     2 1000 {login} seat0 tty2\n" if argv[1] == 'list-sessions'
        else f"Name={login}\nSeat=seat0\nTTY=tty2\nClass=user\nRemote=no\nUser=1000\n", '')


class TestThroughThePortal:
    def test_an_exam_on_a_machine(self, tmp_path):
        """Created without a start time: the agent writes ``exam.json`` at once, the host
        leaves the pool; minutes, End now and Close per machine change the file, then remove
        it."""
        async def go():
            async with E.harness(tmp_path, E.FakeExamsServer()) as h:
                local = start_by_hand(h, lab=DHCP, login='carol')    # the project of the Qt GUI of a student there
                end = time.time() + 7200
                status, exam = await E.api(h, 'POST', '/api/exams', PROF_H, body(end_before=end))
                assert status == 201 and exam['hosts'] == ['a01'] and exam['host_release'] == 10
                data = stored(h)
                marker = data[params.exam_web]
                assert marker[params.exam_web_id] == str(exam['id']) and marker[params.exam_web_title] == 'Partiel'
                assert marker[params.exam_web_origin] == h.portal.exam_store.origin()
                assert data[params.exam_labs] == [[DHCP, None]] and data[params.exam_duration] == 60
                assert params.exam_start_after not in data and data[params.exam_record_sessions] is True
                await h.portal.pool.refresh()
                assert h.portal.pool.state_of('a01') == 'exam' and h.portal.pool.held_for_exam('a01')
                rows = await machines(h, exam['id'])
                assert rows['a01']['locked'] is True and rows['a01']['phase'] == 'starting'
                assert rows['a01']['state'] == 'exam' and abs(rows['a01']['release_at'] - (end + 600)) < 1
                assert (await E.api(h, 'GET', '/api/exams', PROF_H))[1]['exams'][0]['hosts'] == ['a01']
                # five more minutes for that machine: its file follows
                before = data[params.exam_end_before]
                status, _ = await E.api(h, 'POST', f"/api/exams/{exam['id']}/adjust", PROF_H,
                                        {'hosts': ['a01'], 'extra_minutes': 5})
                assert status == 200
                data = stored(h)
                assert data[params.exam_duration] == 65 and data[params.exam_end_before] > before
                assert (await machines(h, exam['id']))['a01']['extra_minutes'] == 5
                # the GUI started the exam there (sre start-exam stamps the file in place): the
                # machine is active, its clock and its project shown
                started = time.time()
                data[params.exam_started_at] = datetime.fromtimestamp(started).isoformat()
                exam_file(h).write_text(json.dumps(data, indent=4))
                await h.portal.pool.refresh()
                row = (await machines(h, exam['id']))['a01']
                assert row['phase'] == 'active' and abs(row['started_at'] - started) < 2
                assert abs(row['end_at'] - (started + 65 * 60)) < 2
                assert [(p['rln'], p['owner'], p['lab']) for p in row['projects']] == [(local, 'carol', DHCP)]
                # End now for the machine: the end-before time of its file is now, its clock kept
                status, _ = await E.api(h, 'POST', f"/api/exams/{exam['id']}/end", PROF_H, {'hosts': ['a01']})
                assert status == 200
                ended = stored(h)
                assert ended[params.exam_end_before] < before and ended[params.exam_started_at] == data[params.exam_started_at]
                assert (await machines(h, exam['id']))['a01']['phase'] == 'ended'
                assert exam_file(h).exists() and (h.pub / 'projects' / local).is_dir()    # the end screen stays
                # closed: the file goes, for good
                status, answer = await E.api(h, 'POST', f"/api/exams/{exam['id']}/close-projects", PROF_H,
                                             {'hosts': ['a01']})
                assert status == 200 and answer['machines'] == ['a01'] and answer['closing'] is None
                await until(lambda: not exam_file(h).exists())
                await until(lambda: not h.portal.exams.get(exam['id']).hosts['a01'].close_pending)
                assert not (h.pub / 'projects' / local).exists()             # stopped by the agent, then the file
                row = (await machines(h, exam['id']))['a01']
                assert row['phase'] == 'closed' and row['closing'] is False and row['locked'] is False
                status, answer = await E.api(h, 'POST', f"/api/exams/{exam['id']}/adjust", PROF_H,
                                             {'hosts': ['a01'], 'extra_minutes': 5})
                assert status == 400 and 'closed on the machine a01' in answer['error']
                await h.portal.exam_hosts.sync()
                assert not exam_file(h).exists() and not h.portal.pool.held_for_exam('a01')
                lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
                edits = [(l.get('action'), l.get('hosts')) for l in lines if l.get('event') == 'exam_edit']
                assert edits == [('create', '1'), ('adjust', '1'), ('end', '1'), ('close', '1'), ('adjust', None)]
        run(go())

    def test_refusals(self, tmp_path):
        async def go():
            async with E.harness(tmp_path, E.FakeExamsServer()) as h:
                status, answer = await E.api(h, 'POST', '/api/exams', PROF_H, body(hosts=['a09']))
                assert status == 400 and "unknown machine 'a09'" in answer['error']
                status, answer = await E.api(h, 'POST', '/api/exams', PROF_H, body(end_before=None))
                assert status == 400 and 'end time is required when machines' in answer['error']
                start = time.time() + 3600
                status, first = await E.api(h, 'POST', '/api/exams', PROF_H,
                                            body(title='First', start_after=start, end_before=start + 3600))
                assert status == 201 and not exam_file(h).exists()          # an hour before its start
                # the same machine in the same hours
                status, answer = await E.api(h, 'POST', '/api/exams', PROF_H,
                                             body(start_after=start + 600, end_before=start + 1800))
                assert status == 409 and 'the machine a01 is taken by the exam «First»' in answer['error']
                status, second = await E.api(h, 'POST', '/api/exams', PROF_H,
                                             body(title='Second', hosts=[], start_after=start, end_before=start + 3600))
                assert status == 201
                status, answer = await E.api(h, 'PUT', f"/api/exams/{second['id']}", PROF_H, {'hosts': ['a01']})
                assert status == 409
                status, answer = await E.api(h, 'PUT', f"/api/exams/{first['id']}", PROF_H, {'title': 'Renamed'})
                assert status == 200 and answer['hosts'] == ['a01']         # not its own rival
                # the selections
                for selection, fragment in (({'hosts': ['a09']}, 'not a machine of this exam'),
                                            ({'hosts': 'a01'}, 'machine names'), ({}, 'select')):
                    status, answer = await E.api(h, 'POST', f"/api/exams/{first['id']}/end", PROF_H,
                                                 {**selection, 'x': 1})
                    assert status == 400 and fragment in answer['error'], answer
                status, answer = await E.api(h, 'POST', f"/api/exams/{first['id']}/labs", PROF_H,
                                             {'hosts': ['a01'], 'labs': [SSH]})
                assert status == 400 and 'not for a machine' in answer['error']
                assert (await E.api(h, 'POST', f"/api/exams/{first['id']}/end", BOB_H, {'hosts': ['a01']}))[0] == 403
        run(go())

    def test_start_now_edit_and_delete(self, tmp_path):
        async def go():
            async with E.harness(tmp_path, E.FakeExamsServer()) as h:
                start = time.time() + 3600
                status, exam = await E.api(h, 'POST', '/api/exams', PROF_H,
                                           body(start_after=start, end_before=start + 3600, host_lead=5))
                assert status == 201 and exam['lock_at'] == pytest.approx(start - 300) and not exam_file(h).exists()
                assert not h.portal.pool.held_for_exam('a01')       # an hour ahead: still a host of the pool
                # Start now: locked at once
                status, _ = await E.api(h, 'PUT', f"/api/exams/{exam['id']}", PROF_H, {'start_after': time.time()})
                assert status == 200 and params.exam_start_after in stored(h)
                assert h.portal.pool.held_for_exam('a01')
                # a lab added for everybody: the file of the machine too
                status, _ = await E.api(h, 'POST', f"/api/exams/{exam['id']}/labs", PROF_H,
                                        {'all': True, 'labs': [DHCP, SSH]})
                assert status == 200 and stored(h)[params.exam_labs] == [[DHCP, None], [SSH, None]]
                # the machine unselected: given back
                status, _ = await E.api(h, 'PUT', f"/api/exams/{exam['id']}", PROF_H, {'hosts': []})
                assert status == 200
                await until(lambda: not exam_file(h).exists())
                status, _ = await E.api(h, 'PUT', f"/api/exams/{exam['id']}", PROF_H, {'hosts': ['a01']})
                assert status == 200 and exam_file(h).exists()
                # deleted with its projects closed: the file goes with it
                status, answer = await E.api(h, 'DELETE', f"/api/exams/{exam['id']}?close=1", PROF_H)
                assert status == 200
                await until(lambda: not exam_file(h).exists())
                assert not h.portal.pool.held_for_exam('a01')
        run(go())

    def test_the_release_removes_the_file_by_itself(self, tmp_path):
        async def go():
            async with E.harness(tmp_path, E.FakeExamsServer()) as h:
                status, exam = await E.api(h, 'POST', '/api/exams', PROF_H,
                                           body(end_before=time.time() + 2, host_release=0.05, audience={}))
                assert status == 201 and exam_file(h).exists() and exam['members'] == 0
                await asyncio.sleep(2.1)
                await h.portal.exam_hosts.sync()
                assert exam_file(h).exists()                         # over, the end screen: 3 s of delay
                await asyncio.sleep(3.1)
                await h.portal.exam_hosts.sync()
                await until(lambda: not exam_file(h).exists())
                record = h.portal.exams.get(exam['id']).hosts['a01']
                assert record.closed_at is not None
                assert (await E.api(h, 'GET', '/api/exams', PROF_H))[1]['exams'][0]['status'] == 'past'
        run(go())

    def test_a_student_at_the_machine_takes_the_exam_there(self, tmp_path):
        async def go():
            async with E.harness(tmp_path, E.FakeExamsServer(), agent_over={'occupied_check': 'sessions'}) as h:
                h.agent.run_command = local_session('alice')
                h.agent._occupancy = None
                status, exam = await E.api(h, 'POST', '/api/exams', PROF_H, body())
                assert status == 201
                await h.portal.pool.refresh()
                assert h.portal.pool.status['a01'].occupied_by == ['session:alice']
                status, data = await E.api(h, 'GET', '/api/exam', ALICE_H)
                assert status == 200 and data['exam']['phase'] == 'local' and data['exam']['local_host'] == 'a01'
                assert (await E.api(h, 'GET', '/api/projects', ALICE_H))[1] == []
                resp = await h.client.post('/api/projects', json={'lab': DHCP}, headers={**ALICE_H, **P.CSRF})
                assert resp.status == 403
                assert (await resp.json())['error'] == "you take this exam on the workstation a01"
                # bob, elsewhere, takes it on the web site: the usual phase, no project on that machine
                status, data = await E.api(h, 'GET', '/api/exam', BOB_H)
                assert data['exam']['phase'] == 'starting' and data['exam']['local_host'] is None
                resp = await h.client.post('/api/projects', json={'lab': DHCP}, headers={**BOB_H, **P.CSRF})
                assert resp.status == 503                           # the only host is the exam's machine
                status, detail = await E.api(h, 'GET', f"/api/exams/{exam['id']}", PROF_H)
                members = {m['login']: m for m in detail['members']}
                assert members['alice']['phase'] == 'local' and members['alice']['local'] == 'a01'
                assert detail['machines'][0]['sessions'] == [{'login': 'alice', 'fullname': ''}]
                # the machine closed: her usual pages are back
                status, _ = await E.api(h, 'POST', f"/api/exams/{exam['id']}/close-projects", PROF_H, {'hosts': ['a01']})
                assert (await E.api(h, 'GET', '/api/exam', ALICE_H))[1]['exam'] is None
        run(go())
