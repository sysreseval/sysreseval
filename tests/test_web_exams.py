"""The exams of the web front-end (``src/sreweb/portal/exams.py``, ``examstore.py``,
``examprojects.py``, the ``/api/exam`` and ``/api/exams`` routes): the model and the registry
alone with fake sockets and a fixed clock, the store on a fake database, then the whole thing
through the portal of test_web_portal.py (proxy mode, a real agent on the fake ``sre``)."""
import asyncio
import ipaddress
import json
import time
import urllib.parse
from datetime import datetime

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
import test_web_presentation as T                             # noqa: E402  (the fakes and the identities)
from test_web_accessdb import FakeServer, Down, Broken, config as db_config   # noqa: E402
from sreweb.config import ExamsConfig                         # noqa: E402
from sreweb.identity import Identity                          # noqa: E402
from sreweb.portal import exams as X                          # noqa: E402
from sreweb.portal import examstore as XS                     # noqa: E402
from sreweb.portal import examprojects as XP                  # noqa: E402
from sreweb.portal import presentation as PR                  # noqa: E402
from sreweb.portal.accessdb import HistoryError               # noqa: E402
from sreweb.portal.accesslog import parse_line                # noqa: E402

ALICE, BOB, CAROL, PROF = T.ALICE, T.BOB, T.CAROL, T.PROF      # alice, bob: INFO1; carol: INFO2
run = T.run
FakeWatcher = T.FakeWatcher
Clock = T.Clock
NOW = 1_700_000_000.0           # 2023-11-14T22:13:20+00:00
DHCP, SSH, EXAM1 = 'sre/dhcp.py', 's4/tp_ssh', 'sre/_EXAM_/exam1.py'
CFG = ExamsConfig()             # lead 10 min, pre-start 5 min, evaluation 60 s, close after 1 h


class FakeMemberships:
    """``groups.Memberships`` as the registry uses it: custom groups by key."""

    def __init__(self, groups=None, people=None):
        self.groups = groups or {}
        self.people = people or {}
        self.refreshed = 0

    async def refresh(self, *, force=False):
        self.refreshed += 1

    def members_of(self, keys):
        found = set()
        for key in keys:
            found |= set(self.groups.get(key, ()))
        return found

    def is_member(self, login, keys, department=''):
        keys = set(keys)
        if department and f'department:{department}' in keys:
            return True
        return login in self.members_of(keys)

    def person_row(self, login):
        return self.people.get(login, {'login': login, 'fullname': '', 'group': ''})


def spec(**over) -> dict:
    """A parsed definition (``parse_exam``) of an exam on the DHCP lab for INFO1, 90 minutes."""
    body = {'title': 'Partiel', 'audience': {'groups': ['department:INFO1']}, 'labs': [DHCP], 'duration': 90}
    body.update(over)
    return X.parse_exam(body, cfg=CFG, now=NOW)


def registry(now=NOW, memberships=None, store=None):
    clock = Clock(now)
    presence = PR.Presence(clock=clock)
    return clock, presence, X.Exams(presence, store, memberships=memberships, clock=clock, cfg=CFG)


def pushed(exam_id, phase) -> dict:
    return {'t': 'exam', 'id': exam_id, 'phase': phase}


def row(lab, rln, host='a01', owner='alice') -> dict:
    """A project row as ``GET /api/projects`` gives it (the lab in the @ form)."""
    return {'lab_name': lab.replace('/', '@'), 'running_lab_name': rln, 'host': host, 'owner': owner,
            'started_at': '20261104100000'}


# ---------------------------------------------------------------------------------------------
# the model
# ---------------------------------------------------------------------------------------------

class TestNames:
    def test_lab_forms(self):
        assert X.normal_lab('sre@dhcp.py') == DHCP and X.normal_lab(DHCP) == DHCP and X.normal_lab(None) == ''
        assert X.lab_of_rln('20261104100000@@@sre@dhcp.py@@@alice') == DHCP
        assert X.lab_of_rln('bad') is None and X.lab_of_rln('') is None

    def test_exam_lab(self):
        assert X.ExamLab.parse(DHCP) == X.ExamLab(DHCP, None)
        assert X.ExamLab.parse({'lab': EXAM1, 'flavor': ' hard '}) == X.ExamLab(EXAM1, 'hard')
        assert X.ExamLab.parse({'lab': DHCP, 'flavor': ''}).flavor is None
        for bad in ('', 'sre@dhcp.py', '/abs', 'a/../b', {'lab': DHCP, 'flavor': 'h-1'}, 3, {'lab': DHCP, 'flavor': 2}):
            with pytest.raises(ValueError):
                X.ExamLab.parse(bad)


class TestParseExam:
    def test_minimal_and_defaults(self):
        s = spec()
        assert s['title'] == 'Partiel' and s['logins'] == set() and s['groups'] == {'department:INFO1'}
        assert s['labs'] == [X.ExamLab(DHCP)] and s['duration'] == 5400
        assert (s['start_after'], s['end_before'], s['ended_at'] if 'ended_at' in s else None) == (None, None, None)
        assert (s['lead'], s['pre_start'], s['eval_interval'], s['networks']) == (600, 300, 60, [])

    def test_every_field(self):
        s = spec(title='  Partiel   réseau ', audience={'logins': ['alice'], 'groups': ['INFO1', 'custom:tp1']},
                 labs=[{'lab': EXAM1, 'flavor': 'hard'}, SSH], duration=None, start_after=NOW + 3600,
                 end_before=datetime.fromtimestamp(NOW + 7200).astimezone().isoformat(), lead=15, pre_start=2,
                 networks=['10.0.0.0/8', '192.0.2.1'], eval_interval=120)
        assert s['title'] == 'Partiel réseau' and s['logins'] == {'alice'}
        assert s['groups'] == {'department:INFO1', 'custom:tp1'}
        assert s['labs'] == [X.ExamLab(EXAM1, 'hard'), X.ExamLab(SSH)]
        assert (s['duration'], s['start_after'], s['end_before']) == (None, NOW + 3600, NOW + 7200)
        assert (s['lead'], s['pre_start'], s['eval_interval']) == (900, 120, 120)
        assert s['networks'] == [ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('192.0.2.1/32')]

    def test_known_labs(self):
        assert X.parse_exam({'title': 't', 'audience': ['alice'], 'labs': [DHCP], 'duration': 1}, cfg=CFG, now=NOW,
                            known_labs={DHCP, SSH})['labs'] == [X.ExamLab(DHCP)]
        with pytest.raises(ValueError, match="unknown lab 'x.py'"):
            X.parse_exam({'title': 't', 'audience': ['alice'], 'labs': ['x.py'], 'duration': 1}, cfg=CFG, now=NOW,
                         known_labs={DHCP})

    @pytest.mark.parametrize('over, fragment', [
        ({'title': ''}, 'title'),
        ({'title': 'x' * 201}, 'title'),
        ({'audience': {}}, 'audience is empty'),
        ({'audience': {'logins': ['bad login']}}, 'invalid login'),
        ({'labs': []}, 'at least one lab'),
        ({'labs': [DHCP, DHCP]}, 'twice'),
        ({'labs': [f'l{i}.py' for i in range(21)]}, 'at most'),
        ({'duration': None}, 'duration or an end'),
        ({'duration': 0}, 'duration'),
        ({'duration': 'long'}, 'duration'),
        ({'start_after': 'yesterday'}, 'start_after'),
        ({'start_after': NOW + 10, 'end_before': NOW + 5}, 'end must come after'),
        ({'end_before': NOW - 5}, 'in the past'),
        ({'lead': -1}, 'lead'),
        ({'pre_start': 'x'}, 'pre_start'),
        ({'networks': ['10.0.0.300']}, 'networks'),
        ({'networks': 'all'}, 'networks'),
        ({'networks': [f'10.{i}.0.0/16' for i in range(51)]}, 'at most'),
        ({'eval_interval': 0}, 'eval_interval'),
        ({'eval_interval': 'fast'}, 'eval_interval'),
    ])
    def test_refused(self, over, fragment):
        with pytest.raises(ValueError, match=fragment):
            spec(**over)

    def test_edit_keeps_the_rest(self):
        clock, presence, reg = registry()
        exam = run(reg.create(PROF, spec(start_after=NOW + 3600, end_before=NOW + 7200)))
        edited = X.parse_exam({'title': 'New', 'lead': 20}, cfg=CFG, now=NOW, current=exam)
        assert edited['title'] == 'New' and edited['lead'] == 1200 and edited['duration'] == 5400
        assert edited['start_after'] == NOW + 3600 and edited['groups'] == {'department:INFO1'}
        with pytest.raises(ValueError, match="end must come after"):
            X.parse_exam({'end_before': NOW + 60}, cfg=CFG, now=NOW, current=exam)
        with pytest.raises(ValueError, match="in the past"):
            X.parse_exam({'end_before': NOW - 60}, cfg=CFG, now=NOW, current=exam)
        # an edit that leaves end_before alone is not refused because it is past meanwhile
        assert X.parse_exam({'title': 'Late'}, cfg=CFG, now=NOW + 8000, current=exam)['end_before'] == NOW + 7200

    def test_selection_and_minutes(self):
        assert X.parse_selection({'all': True}) == (True, set(), set())
        assert X.parse_selection({'logins': ['alice'], 'groups': ['INFO1']}) == (False, {'alice'}, {'department:INFO1'})
        for bad in ({}, {'all': False}, {'logins': 'alice'}, [], {'logins': ['bad login']}):
            with pytest.raises(ValueError):
                X.parse_selection(bad)
        assert X.parse_extra_minutes(10) == 10 and X.parse_extra_minutes(-5.0) == -5
        for bad in (0, 1.5, 'ten', True, 10 ** 6):
            with pytest.raises(ValueError):
                X.parse_extra_minutes(bad)


class TestPhases:
    """The clock of one student, by the exam alone."""

    def exam(self, **over) -> X.Exam:
        _, _, reg = registry()
        return run(reg.create(PROF, spec(**over)))

    def test_without_start_time(self):
        exam = self.exam()
        assert exam.phase(None, NOW) == X.PHASE_STARTING and exam.status(NOW) == X.STATUS_RUNNING
        m = exam.member('alice', create=True)
        assert exam.phase(m, NOW) == X.PHASE_STARTING and exam.end_at(m) is None and not exam.may_start(m, NOW)
        m.projects[DHCP] = {'host': 'a01', 'rln': 'r1', 'synced': None}
        assert exam.may_start(m, NOW)
        m.started_at = NOW + 30
        assert exam.phase(m, NOW + 30) == X.PHASE_ACTIVE and exam.end_at(m) == NOW + 30 + 5400
        assert exam.phase(m, NOW + 30 + 5399) == X.PHASE_ACTIVE
        assert exam.phase(m, NOW + 30 + 5400) == X.PHASE_ENDED
        m.dismissed_at = NOW + 30 + 5401
        assert exam.phase(m, NOW + 30 + 5401) == X.PHASE_DONE
        assert exam.status(NOW + 9000) == X.STATUS_RUNNING      # no end time, no End now: it runs

    def test_with_a_window(self):
        start = NOW + 3600
        exam = self.exam(start_after=start, end_before=start + 3000, duration=90)    # the window is shorter
        assert exam.hide_at() == start - 600 and exam.prestart_at() == start - 300
        m = exam.member('alice', create=True)
        assert exam.phase(m, start - 601) == X.PHASE_SCHEDULED and exam.status(start - 601) == X.STATUS_SCHEDULED
        assert exam.phase(m, start - 600) == X.PHASE_WAITING
        m.projects[DHCP] = {'host': 'a01', 'rln': 'r1', 'synced': None}
        assert not exam.may_start(m, start - 1) and exam.may_start(m, start)
        m.started_at = start
        assert exam.end_at(m) == start + 3000                    # end_before wins over the duration
        assert exam.phase(m, start + 2999) == X.PHASE_ACTIVE and exam.phase(m, start + 3000) == X.PHASE_ENDED
        # a late starter ends at end_before whatever the duration
        late = exam.member('bob', create=True)
        late.started_at = start + 2000
        assert exam.end_at(late) == start + 3000
        # somebody who never started: past once the window closed
        assert exam.phase(exam.member('carol', create=True), start + 3000) == X.PHASE_PAST
        assert exam.phase(None, start + 3000) == X.PHASE_PAST
        assert exam.status(start + 3000) == X.STATUS_PAST

    def test_extra_minutes_and_end_now(self):
        exam = self.exam()
        m = exam.member('alice', create=True)
        m.started_at = NOW
        m.extra_minutes = 10
        assert exam.end_at(m) == NOW + 5400 + 600
        m.ended_at = NOW + 100
        assert exam.end_at(m) == NOW + 100 and exam.phase(m, NOW + 100) == X.PHASE_ENDED
        m.ended_at = None
        exam.ended_at = NOW + 50
        assert exam.end_at(m) == NOW + 50 and exam.status(NOW + 50) == X.STATUS_PAST
        # minutes taken beyond the time left: the end is the start, never before (the agents refuse it)
        exam.ended_at = None
        m.extra_minutes = -200
        assert exam.end_at(m) == NOW and exam.phase(m, NOW + 1) == X.PHASE_ENDED
        # the extra minutes push past end_before too (an explicit decision of the instructor)
        exam = self.exam(start_after=NOW + 60, end_before=NOW + 1000)
        m = exam.member('alice', create=True)
        m.started_at = NOW + 60
        m.extra_minutes = 5
        assert exam.end_at(m) == NOW + 1000 + 300

    def test_audience(self):
        memberships = FakeMemberships({'custom:tp1': {'carol'}})
        _, _, reg = registry(memberships=memberships)
        exam = run(reg.create(PROF, spec(audience={'logins': ['dave'], 'groups': ['INFO1', 'custom:tp1']})))
        assert exam.includes('dave') and exam.includes('alice', 'INFO1') and exam.includes('carol', 'INFO2')
        assert not exam.includes('bob', 'INFO2') and not exam.includes('bob')
        assert reg.members_of(exam) == {'dave', 'carol'}        # alice connects: she is counted
        presence = reg.presence
        presence.add(ALICE, '/projects', FakeWatcher())
        assert reg.members_of(exam) == {'dave', 'carol', 'alice'}
        assert reg.resolve(exam, {'dave'}, {'department:INFO1'}) == {'dave', 'alice'}
        assert reg.resolve(exam, set(), {'custom:tp1'}) == {'carol'}
        with pytest.raises(ValueError, match="not in the audience"):
            reg.resolve(exam, {'bob'}, set())
        # without memberships only the department string of the identity tells
        _, _, reg2 = registry()
        exam2 = run(reg2.create(PROF, spec(audience={'groups': ['INFO1', 'custom:tp1']})))
        assert exam2.includes('alice', 'INFO1') and not exam2.includes('carol', 'INFO2')

    def test_summary(self):
        exam = self.exam(start_after=NOW + 3600, networks=['10.0.0.0/8'])
        d = exam.to_dict(NOW, 3)
        assert d['id'] == 1 and d['status'] == 'scheduled' and d['members'] == 3
        assert d['audience'] == {'logins': [], 'groups': ['department:INFO1']}
        assert d['labs'] == [{'lab': DHCP, 'flavor': None}] and d['duration'] == 90
        assert (d['lead'], d['pre_start'], d['eval_interval'], d['networks']) == (10, 5, 60, ['10.0.0.0/8'])
        assert (d['start_at'], d['prestart_at'], d['hide_at']) == (NOW + 3600, NOW + 3300, NOW + 3000)


# ---------------------------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------------------------

class TestRegistry:
    def test_create_binds_and_tells_the_connected_students(self):
        clock, presence, reg = registry()
        wa, wb, wp = FakeWatcher(), FakeWatcher(), FakeWatcher()
        presence.add(ALICE, '/projects', wa)
        presence.add(CAROL, '/projects', wb)
        presence.add(PROF, '/exams', wp)
        exam = run(reg.create(PROF, spec()))
        assert exam.id == 1 and reg.get(1) is exam and reg.get('1') is exam and reg.get('x') is None
        assert wa.sent == [pushed(1, 'starting')] and wb.sent == [] and wp.sent == []
        assert set(reg.shown) == {'alice'} and reg.shown['alice'][:2] == (1, 'starting')
        assert reg.for_login('alice', 'INFO1') == (exam, None, 'starting')
        assert reg.for_login('carol', 'INFO2') is None and reg.for_login('prof') is None
        # a second page of alice: nothing new for her login (the browser asks GET /api/exam)
        wa2 = FakeWatcher()
        presence.add(ALICE, '/open', wa2)
        run(reg.resync({'alice'}))
        assert wa2.sent == [] and len(wa.sent) == 1
        # she leaves: forgotten; back: told again
        presence.remove(presence._sockets['alice'][0])
        presence.remove(presence._sockets['alice'][0])
        run(reg.resync({'alice'}))
        assert reg.shown == {}
        wa3 = FakeWatcher()
        presence.add(ALICE, '/projects', wa3)
        run(reg.resync({'alice'}))
        assert wa3.sent == [pushed(1, 'starting')]

    def test_earliest_exam_wins(self):
        clock, presence, reg = registry()
        later = run(reg.create(PROF, spec(title='Later', start_after=NOW + 1200)))
        sooner = run(reg.create(PROF, spec(title='Sooner', start_after=NOW + 900, labs=[SSH])))
        assert [e.title for e in reg.listing()] == ['Sooner', 'Later']
        assert reg.for_login('alice', 'INFO1', NOW) is None                  # both before their lead
        assert reg.for_login('alice', 'INFO1', NOW + 300)[0] is sooner         # Sooner's lead window
        assert reg.for_login('alice', 'INFO1', NOW + 700)[0] is sooner         # both waiting: the earliest
        run(reg.end_now(sooner.id, None, now=NOW + 1000))
        assert reg.for_login('alice', 'INFO1', NOW + 1000)[0] is later         # Sooner past for the never-started

    def test_project_and_start_access(self):
        clock, presence, reg = registry()
        rln_dhcp, rln_ssh = '20261104100000@@@sre@dhcp.py@@@alice', '20261104090000@@@s4@tp_ssh@@@alice'
        assert reg.project_access('alice', 'INFO1', rln_ssh) == (True, '')
        assert reg.start_access('alice', 'INFO1', SSH) == (True, '')
        start = NOW + 3600
        exam = run(reg.create(PROF, spec(start_after=start)))
        assert reg.project_access('alice', 'INFO1', rln_ssh, NOW) == (True, '')          # scheduled: free
        clock.now = start - 600                                                           # waiting
        assert reg.project_access('alice', 'INFO1', rln_ssh) == (False, X.REASON_OTHER_LAB)
        assert reg.project_access('alice', 'INFO1', rln_dhcp) == (False, X.REASON_NOT_STARTED)
        assert reg.start_access('alice', 'INFO1', SSH) == (False, X.REASON_OTHER_LAB)
        assert reg.start_access('alice', 'INFO1', DHCP) == (False, f"the exam projects start at {X.iso_utc(start - 300)}")
        clock.now = start - 300                                                           # the pre-start
        assert reg.start_access('alice', 'INFO1', DHCP) == (True, '')
        assert reg.project_access('alice', 'INFO1', rln_dhcp) == (False, X.REASON_NOT_STARTED)
        assert run(reg.observe(exam, 'alice', [row(DHCP, rln_dhcp)]))                      # recorded, clock not started
        m = exam.members['alice']
        assert m.projects == {DHCP: {'host': 'a01', 'rln': rln_dhcp, 'synced': None}} and m.started_at is None
        assert reg.exam_project('alice', rln_dhcp) == (exam, m) and reg.exam_project('alice', rln_ssh) is None
        clock.now = start                                                                 # the tick starts her clock
        run(reg.tick())
        assert m.started_at == start and exam.phase(m, start) == X.PHASE_ACTIVE
        assert reg.project_access('alice', 'INFO1', rln_dhcp) == (True, '')
        assert reg.project_access('alice', 'INFO1', rln_ssh) == (False, X.REASON_OTHER_LAB)
        assert reg.start_access('alice', 'INFO1', DHCP) == (True, '')                     # another one: the route refuses
        clock.now = start + 5400                                                          # ended
        assert reg.project_access('alice', 'INFO1', rln_dhcp) == (False, X.REASON_OVER)
        assert reg.start_access('alice', 'INFO1', DHCP) == (False, X.REASON_OVER)
        assert run(reg.dismiss(exam.id, 'alice')) == X.PHASE_DONE
        assert reg.for_login('alice', 'INFO1') is None
        assert reg.project_access('alice', 'INFO1', rln_ssh) == (True, '')                # the usual pages
        assert reg.project_access('alice', 'INFO1', rln_dhcp) == (False, X.REASON_OVER)   # the exam project stays closed
        assert reg.start_access('alice', 'INFO1', DHCP) == (True, '')                     # a new project of the lab: fine
        with pytest.raises(ValueError, match="nothing to dismiss"):
            run(reg.dismiss(exam.id, 'alice'))
        # bob never bound: nothing to dismiss either
        with pytest.raises(ValueError):
            run(reg.dismiss(exam.id, 'bob'))

    def test_visible_rows(self):
        clock, presence, reg = registry()
        rln_dhcp, rln_ssh = '20261104100000@@@sre@dhcp.py@@@alice', '20261104090000@@@s4@tp_ssh@@@alice'
        rows = [row(SSH, rln_ssh), row(DHCP, rln_dhcp)]
        assert reg.visible_rows('alice', 'INFO1', rows) == rows
        exam = run(reg.create(PROF, spec()))
        assert reg.visible_rows('alice', 'INFO1', rows) == [dict(rows[1], exam={'id': 1, 'title': 'Partiel'})]
        assert reg.visible_rows('carol', 'INFO2', rows) == rows
        run(reg.observe(exam, 'alice', rows))
        m = exam.members['alice']
        assert m.started_at == NOW and set(m.projects) == {DHCP}
        run(reg.end_now(exam.id, None))
        assert reg.visible_rows('alice', 'INFO1', rows) == []                             # ended: the banner
        run(reg.dismiss(exam.id, 'alice'))
        assert reg.visible_rows('alice', 'INFO1', rows) == [rows[0]]                      # done: the exam project hidden
        later = row(DHCP, '20261105100000@@@sre@dhcp.py@@@alice')
        assert reg.visible_rows('alice', 'INFO1', rows + [later]) == [rows[0], later]      # a new project of the lab shows

    def test_observe_starts_the_clock_once_every_lab_has_a_project(self):
        clock, presence, reg = registry()
        wa = FakeWatcher()
        presence.add(ALICE, '/projects', wa)
        exam = run(reg.create(PROF, spec(labs=[DHCP, SSH])))
        assert wa.sent == [pushed(1, 'starting')]
        assert run(reg.observe(exam, 'alice', [row(DHCP, 'r1')], address='10.0.0.5'))
        m = exam.members['alice']
        assert (m.first_seen, m.started_at, m.address) == (NOW, None, '10.0.0.5')
        assert not run(reg.observe(exam, 'alice', [row(DHCP, 'r1')]))                      # nothing new
        clock.now = NOW + 40
        assert run(reg.observe(exam, 'alice', [row(DHCP, 'r1'), row(SSH, 'r2'), row(DHCP, 'r9', owner='bob')]))
        assert m.started_at == NOW + 40 and set(m.projects) == {DHCP, SSH}
        assert wa.sent == [pushed(1, 'starting'), pushed(1, 'active')]
        # a project replaced (closed by an instructor, started again): the new one recorded
        assert run(reg.observe(exam, 'alice', [row(DHCP, 'r3'), row(SSH, 'r2')]))
        assert m.projects[DHCP]['rln'] == 'r3' and m.projects[DHCP]['synced'] is None

    def test_adjust_end_and_labs(self):
        memberships = FakeMemberships({'custom:tp1': {'alice', 'bob'}})
        clock, presence, reg = registry(memberships=memberships)
        wa, wb = FakeWatcher(), FakeWatcher()
        presence.add(ALICE, '/projects', wa)
        presence.add(BOB, '/projects', wb)
        exam = run(reg.create(PROF, spec(audience={'groups': ['custom:tp1']}, end_before=NOW + 7200)))
        for login, rln in (('alice', 'ra'), ('bob', 'rb')):
            run(reg.observe(exam, login, [row(DHCP, rln, owner=login)]))
        a, b = exam.members['alice'], exam.members['bob']
        assert exam.end_at(a) == exam.end_at(b) == NOW + 5400
        assert wa.sent[-1] == wb.sent[-1] == pushed(1, 'active')
        told = len(wa.sent), len(wb.sent)
        # everybody: the duration and the end time shift together; the pages are told (the phase
        # is the same, the end is not: the countdown follows at once)
        run(reg.adjust(exam.id, None, 10))
        assert (exam.duration, exam.end_before) == (6000, NOW + 7800) and exam.end_at(a) == NOW + 6000
        assert (len(wa.sent), len(wb.sent)) == (told[0] + 1, told[1] + 1) and wa.sent[-1] == pushed(1, 'active')
        run(reg.adjust(exam.id, None, -20))
        assert (exam.duration, exam.end_before) == (4800, NOW + 6600)
        # a selection: their extra minutes, cumulative; only their pages are told
        run(reg.adjust(exam.id, {'alice'}, 5))
        run(reg.adjust(exam.id, {'alice'}, 5))
        assert (a.extra_minutes, exam.end_at(a), exam.end_at(b)) == (10, NOW + 5400, NOW + 4800)
        assert (len(wa.sent), len(wb.sent)) == (told[0] + 4, told[1] + 2)
        run(reg.tick())                                       # nothing changed: nothing pushed
        assert (len(wa.sent), len(wb.sent)) == (told[0] + 4, told[1] + 2)
        # End now for bob, then 5 more minutes for him: ended lifted, the extra counts from the base
        clock.now = NOW + 1000
        run(reg.end_now(exam.id, {'bob'}))
        assert exam.end_at(b) == NOW + 1000 and exam.phase(b, clock.now) == X.PHASE_ENDED
        assert wb.sent[-1] == pushed(1, 'ended') and wa.sent[-1] == pushed(1, 'active')
        run(reg.adjust(exam.id, {'bob'}, 5))
        assert b.ended_at is None and exam.end_at(b) == NOW + 4800 + 300 and wb.sent[-1] == pushed(1, 'active')
        # a dismissed student extended is active again, and ended again at the new end
        run(reg.end_now(exam.id, {'bob'}))
        run(reg.dismiss(exam.id, 'bob'))
        assert wb.sent[-1] == pushed(1, None) and 'bob' not in reg.shown
        run(reg.adjust(exam.id, {'bob'}, 1))
        assert exam.phase(b, clock.now) == X.PHASE_ACTIVE and wb.sent[-1] == pushed(1, 'active')
        clock.now = exam.end_at(b)
        run(reg.tick())
        assert wb.sent[-1] == pushed(1, 'ended')
        # End now for everybody, then +N for everybody: it runs again
        run(reg.end_now(exam.id, None))
        assert exam.ended_at == clock.now and wa.sent[-1] == pushed(1, 'ended')
        run(reg.adjust(exam.id, None, 30))
        assert exam.ended_at is None and wa.sent[-1] == pushed(1, 'active')
        # the labs: of a selection (the DHCP project of alice becomes an orphan; her pages are
        # told, so that they start the new lab at once), of everybody
        told = len(wa.sent)
        run(reg.set_labs(exam.id, {'alice'}, [X.ExamLab(SSH)]))
        assert exam.labs_of('alice') == [X.ExamLab(SSH)] and exam.labs_of('bob') == [X.ExamLab(DHCP)]
        assert len(wa.sent) == told + 1 and wa.sent[-1] == pushed(1, 'active')
        assert a.projects == {} and a.orphans == [{'host': 'a01', 'rln': 'ra'}] and a.started_at is not None
        run(reg.set_labs(exam.id, None, [X.ExamLab(SSH), X.ExamLab(DHCP, 'hard')]))
        assert a.labs is None and b.labs is None and exam.flavor_of('bob', DHCP) == 'hard'
        assert b.projects == {DHCP: {'host': 'a01', 'rln': 'rb', 'synced': None}}

    def test_update_and_delete(self):
        clock, presence, reg = registry()
        wa, wc = FakeWatcher(), FakeWatcher()
        presence.add(ALICE, '/projects', wa)
        presence.add(CAROL, '/projects', wc)
        exam = run(reg.create(PROF, spec(start_after=NOW + 3600)))
        assert wa.sent == [] and reg.for_login('alice', 'INFO1') is None
        edited = X.parse_exam({'audience': {'groups': ['INFO1', 'INFO2']}, 'start_after': NOW + 60}, cfg=CFG, now=NOW,
                              current=exam)
        run(reg.update(exam.id, edited))
        assert exam.groups == {'department:INFO1', 'department:INFO2'} and exam.start_after == NOW + 60
        assert wa.sent == [pushed(1, 'waiting')] and wc.sent == [pushed(1, 'waiting')]
        run(reg.end_now(exam.id, None))
        assert wa.sent[-1] == pushed(1, None)
        run(reg.update(exam.id, X.parse_exam({'title': 'Renamed'}, cfg=CFG, now=NOW, current=exam)))
        assert exam.ended_at is not None                   # a rename does not lift the End now
        run(reg.update(exam.id, X.parse_exam({'duration': 120}, cfg=CFG, now=NOW, current=exam), resume=True))
        assert exam.ended_at is None and wa.sent[-1] == pushed(1, 'waiting')
        gone = run(reg.delete(exam.id))
        assert gone is exam and reg.listing() == [] and reg.shown == {}
        assert wa.sent[-1] == pushed(1, None) and wc.sent[-1] == pushed(1, None)
        with pytest.raises(KeyError):
            run(reg.delete(exam.id))

    def test_tick_runs_the_hooks_and_refreshes(self):
        memberships = FakeMemberships()
        clock, presence, reg = registry(memberships=memberships)
        seen = []

        async def hook(now):
            seen.append(now)

        reg.on_tick.append(hook)
        run(reg.tick())
        assert seen == [NOW] and memberships.refreshed == 1
        clock.now = NOW + 5
        run(reg.tick())
        assert memberships.refreshed == 1                  # at most every MEMBERSHIPS_REFRESH seconds
        clock.now = NOW + 11
        run(reg.tick())
        assert memberships.refreshed == 2 and seen == [NOW, NOW + 5, NOW + 11]

    def test_student_view(self):
        clock, presence, reg = registry()
        exam = run(reg.create(PROF, spec(start_after=NOW + 3600, labs=[{'lab': EXAM1, 'flavor': 'hard'}])))
        view = reg.student_view(exam, None, 'waiting', address='10.0.0.5', allowed=True,
                                titles={EXAM1: {'fr': 'Examen 1'}})
        assert view == {'id': 1, 'title': 'Partiel', 'phase': 'waiting', 'start_at': NOW + 3600,
                        'prestart_at': NOW + 3300, 'hide_at': NOW + 3000, 'started_at': None, 'end_at': None,
                        'lead': 600, 'labs': [{'lab': EXAM1, 'lab_name': 'sre@_EXAM_@exam1.py',
                                               'title': {'fr': 'Examen 1'}, 'flavor': 'hard'}],
                        'address_allowed': True, 'address': '10.0.0.5', 'dismissable': False}
        assert reg.address_allowed(exam, '10.0.0.5')
        exam.networks = [ipaddress.ip_network('10.0.0.0/8')]
        assert reg.address_allowed(exam, '10.1.2.3') and not reg.address_allowed(exam, '192.0.2.1')
        assert not reg.address_allowed(exam, '-')


# ---------------------------------------------------------------------------------------------
# the store on a fake database
# ---------------------------------------------------------------------------------------------

class FakeExamsServer(FakeServer):
    """The two tables of the exams behind the FakeServer: the exams by id, the members by
    (exam id, login); the statements of examstore.py answered from them."""

    def __init__(self, *, tables_exist=True, table='exams'):
        super().__init__(table_exists=True)
        self.table = table
        self.members_table = table + '_members'
        self.tables = {table, self.members_table} if tables_exist else set()
        self.exams = {}         # id -> [title, created_by, created_at, updated_at, start_after, end_before, duration, ended_at, details]
        self.members = {}       # (exam id, login) -> [first_seen, started_at, ended_at, dismissed_at, extra, address, details, updated_at]
        self.next_id = 1

    def dispatch(self, cursor, sql, args) -> bool:
        table = sql.split('`')[1] if '`' in sql else ''
        if table not in (self.table, self.members_table):
            return False
        if sql.startswith('SELECT 1 FROM'):
            if table not in self.tables:
                raise Broken(1146, f"Table 'sre.{table}' doesn't exist")
        elif sql.startswith('CREATE TABLE'):
            self.tables.add(table)
            self.created += 1
        elif sql.startswith('SELECT id, title'):
            cursor._rows = [(eid, *fields) for eid, fields in sorted(self.exams.items())]
        elif sql.startswith('SELECT exam_id, login'):
            cursor._rows = [(eid, login, *fields[:7]) for (eid, login), fields in sorted(self.members.items())]
        elif sql.startswith('INSERT INTO'):
            eid, self.next_id = self.next_id, self.next_id + 1
            self.exams[eid] = list(args)
            cursor.lastrowid, cursor.rowcount = eid, 1
        elif sql.startswith('UPDATE'):
            title, updated, start, end, duration, ended, details, eid = args
            fields = self.exams[eid]
            fields[0], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8] = \
                title, updated, start, end, duration, ended, details
            cursor.rowcount = 1
        elif sql.startswith('REPLACE'):
            eid, login, *rest = args
            self.members[(eid, login)] = list(rest)
            cursor.rowcount = 1
        elif sql.startswith('DELETE FROM') and table == self.members_table:
            gone = [k for k in self.members if k[0] == args[0]]
            for k in gone:
                del self.members[k]
            cursor.rowcount = len(gone)
        elif sql.startswith('DELETE FROM') and 'updated_at <' in sql:
            before = args[0]
            gone = [eid for eid, f in self.exams.items()
                    if f[3] < before and (f[7] is not None or (f[5] is not None and f[5] < before))]
            for eid in gone:
                del self.exams[eid]
            cursor.rowcount = len(gone)
        elif sql.startswith('DELETE FROM'):
            cursor.rowcount = 1 if self.exams.pop(args[0], None) is not None else 0
        elif sql.startswith('DELETE m FROM'):
            orphans = [k for k in self.members if k[0] not in self.exams]
            for k in orphans:
                del self.members[k]
            cursor.rowcount = len(orphans)
        else:
            return False
        return True


def make_store(server, **over) -> XS.ExamStore:
    return XS.ExamStore(db_config(), ExamsConfig(**over), connect=server.connect, clock=lambda: NOW)


class TestStore:
    def test_round_trip(self):
        server = FakeExamsServer(tables_exist=False)
        store = make_store(server)
        clock, presence, reg = registry(store=store)
        exam = run(reg.create(PROF, spec(audience={'logins': ['dave'], 'groups': ['INFO1']}, start_after=NOW + 3600,
                                         end_before=NOW + 9000, labs=[{'lab': EXAM1, 'flavor': 'hard'}, SSH],
                                         networks=['10.0.0.0/8'], lead=12, eval_interval=30)))
        assert exam.id == 1 and server.created == 2 and store.connected
        run(reg.observe(exam, 'alice', [row(EXAM1, 'r1')], address='10.0.0.5'))
        run(reg.adjust(exam.id, {'alice'}, 5))
        run(reg.set_labs(exam.id, {'bob'}, [X.ExamLab(SSH)]))
        run(reg.end_now(exam.id, None, now=NOW + 100))
        assert set(server.members) == {(1, 'alice'), (1, 'bob')}
        # another registry on the same store: the same exam, the same members
        _, _, reg2 = registry(store=make_store(server), memberships=FakeMemberships())
        assert run(reg2.load()) == 1 and reg2.loaded
        loaded = reg2.get(1)
        assert loaded is not exam and loaded.memberships is reg2.memberships
        assert loaded.to_dict(NOW, 0) == exam.to_dict(NOW, 0)
        assert loaded.labs == exam.labs and loaded.networks == exam.networks and loaded.ended_at == NOW + 100
        a, b = loaded.members['alice'], loaded.members['bob']
        assert (a.first_seen, a.started_at, a.extra_minutes, a.address) == (NOW, None, 5, '10.0.0.5')
        assert a.projects == {EXAM1: {'host': 'a01', 'rln': 'r1', 'synced': None}} and a.labs is None
        assert b.labs == [X.ExamLab(SSH)] and b.extra_minutes == 0
        run(reg2.load())                                   # loading again changes nothing
        assert len(reg2.listing()) == 1
        # deletion
        run(reg2.delete(1))
        assert server.exams == {} and server.members == {}

    def test_dirty_writes_and_load_retried(self):
        server = FakeExamsServer()
        store = make_store(server)
        clock, presence, reg = registry(store=store)
        exam = run(reg.create(PROF, spec()))
        server.down = True
        with pytest.raises(HistoryError):
            run(reg.create(PROF, spec(title='Second')))
        assert len(reg.listing()) == 1                     # a refused creation is not kept
        run(reg.observe(exam, 'alice', [row(DHCP, 'r1')]))   # kept in memory, written later
        assert reg._dirty == {(1, 'alice')} and exam.members['alice'].started_at == NOW
        assert (1, 'alice') not in server.members
        clock.now = NOW + X.DIRTY_RETRY
        run(reg.tick())
        assert reg._dirty == {(1, 'alice')}                # still down
        server.down = False
        clock.now = NOW + 2 * X.DIRTY_RETRY
        run(reg.tick())
        assert reg._dirty == set() and (1, 'alice') in server.members
        # a registry started while the database is down loads later
        server.down = True
        _, _, reg2 = registry(store=make_store(server))
        assert run(reg2.load()) == -1 and not reg2.loaded and reg2.listing() == []
        server.down = False
        reg2.clock.now = NOW + X.DIRTY_RETRY
        run(reg2.tick())
        assert reg2.loaded and [e.id for e in reg2.listing()] == [1]

    def test_purge(self):
        server = FakeExamsServer()
        store = make_store(server, keep=30)
        clock, presence, reg = registry(store=store)
        old = run(reg.create(PROF, spec(title='Old')))
        run(reg.end_now(old.id, None))
        run(reg.create(PROF, spec(title='Current')))
        clock.now = NOW + 31 * 86400
        assert store.purge(clock.now - 30 * 86400) == 1
        assert list(server.exams) == [2]
        assert 'tables exams, exams_members' in store.describe()
        assert store.status() == {'connected': True, 'last_error': None}


# ---------------------------------------------------------------------------------------------
# the agents' side
# ---------------------------------------------------------------------------------------------

class FakeRelay:
    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}          # (method, suffix) -> status

    async def json(self, host, identity, method, path, *, json=None, params=None, timeout=60.0):
        self.calls.append((host.name, identity.login, identity.role, method, path, json))
        suffix = path.rsplit('/', 1)[1] if path.endswith('/exam') else ''
        return self.answers.get((method, suffix), 200), {'ok': True}


class SlowRelay(FakeRelay):
    """A relay whose calls take a moment (and wait for ``gate`` when set): the concurrency of a
    close job is observable."""

    def __init__(self, answers=None, delay=0.01):
        super().__init__(answers)
        self.delay = delay
        self.in_flight = 0
        self.max_in_flight = 0
        self.gate: asyncio.Event | None = None

    async def json(self, host, identity, method, path, *, json=None, params=None, timeout=60.0):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.gate is not None:
                await self.gate.wait()
            await asyncio.sleep(self.delay)
            return await super().json(host, identity, method, path, json=json, params=params, timeout=timeout)
        finally:
            self.in_flight -= 1


class FakePool:
    def __init__(self, hosts=('a01',), rows=None):
        self._hosts = {name: P.HostConfig(name=name, url=f'http://{name}', token=P.TOKEN) for name in hosts}
        self.rows = rows or []
        self.listed = 0

    def host(self, name):
        if name not in self._hosts:
            raise P.PoolError(404, "unknown host")
        return self._hosts[name]

    async def projects_of(self, identity, *, all_projects=False):
        self.listed += 1
        return list(self.rows)


class TestExamProjects:
    def test_payload(self):
        clock, presence, reg = registry()
        exam = run(reg.create(PROF, spec()))
        assert XP.exam_payload(exam, None, NOW) == {'id': '1', 'title': 'Partiel', 'started_at': None, 'end_at': None,
                                                     'eval_interval': 60, 'now': '2023-11-14T22:13:20+00:00'}
        m = exam.member('alice', create=True)
        m.started_at = NOW
        assert XP.exam_payload(exam, m, NOW + 1)['started_at'] == '2023-11-14T22:13:20+00:00'
        assert XP.exam_payload(exam, m, NOW + 1)['end_at'] == '2023-11-14T23:43:20+00:00'
        assert XP.instructor_identity(exam) == Identity(login='prof', role='instructor')

    def test_close_job(self):
        """The close runs in the background, CLOSE_CONCURRENCY stops at a time, its progress
        readable on the job; a failed stop keeps the project; a second close meanwhile gets the
        same job; a finished job is forgotten CLOSE_KEEP after its end; shutdown cancels a
        running one (security review: the close ran sequentially inside the request)."""
        clock, presence, reg = registry()
        relay, pool = SlowRelay(), FakePool()
        xp = XP.ExamProjects(reg, pool, relay, clock=clock)
        exam = run(reg.create(PROF, spec(labs=[DHCP, SSH])))

        async def go():
            for i in range(20):
                login = f'user{i:02d}'
                await reg.observe(exam, login, [row(DHCP, f'd{i}', owner=login), row(SSH, f's{i}', owner=login)])
            # nothing to close: a job finished at once, no task
            empty = await xp.close(exam, {'nobody'})
            assert empty.total == 0 and not empty.running and empty.task is None
            # 40 stops, at most CLOSE_CONCURRENCY in flight; a second close meanwhile: the same job
            relay.gate = asyncio.Event()
            job = await xp.close(exam, set(exam.members))
            assert job.total == 40 and job.running and xp.closing_of(exam) is job
            await asyncio.sleep(0.02)
            assert relay.in_flight == XP.CLOSE_CONCURRENCY and job.done == 0
            assert await xp.close(exam, {'user00'}) is job
            relay.gate.set()
            await job.task
            assert (job.done, job.closed, job.failed, job.running) == (40, 40, 0, False)
            assert relay.max_in_flight == XP.CLOSE_CONCURRENCY
            assert all(m.projects == {} for m in exam.members.values())
            assert job.to_dict()['running'] is False and job.to_dict()['finished_at'] is not None
            assert [c[3] for c in relay.calls[-40:]] == ['DELETE'] * 40
            # forgotten CLOSE_KEEP after its end
            assert xp.closing_of(exam) is job
            clock.now += XP.CLOSE_KEEP + 1
            assert xp.closing_of(exam) is None
            # a failed stop keeps the project
            await reg.observe(exam, 'user00', [row(DHCP, 'd0b', owner='user00')])
            relay.answers[('DELETE', '')] = 500
            job = await xp.close(exam, {'user00'})
            await job.task
            assert (job.total, job.closed, job.failed) == (1, 0, 1) and DHCP in exam.members['user00'].projects
            # shutdown cancels a running job
            relay.answers[('DELETE', '')] = 200
            relay.gate = asyncio.Event()
            job = await xp.close(exam, {'user00'})
            assert job.running
            await xp.shutdown()
            assert not job.running and xp.closing_of(exam) is None
        run(go())

    def test_sync_release_and_close(self):
        clock, presence, reg = registry()
        relay, pool = FakeRelay(), FakePool()
        xp = XP.ExamProjects(reg, pool, relay, clock=clock)
        exam = run(reg.create(PROF, spec(labs=[DHCP, SSH])))
        run(reg.observe(exam, 'alice', [row(DHCP, 'r1'), row(SSH, 'r2')]))
        m = exam.members['alice']
        run(xp.reconcile())
        assert [c[3:5] for c in relay.calls] == [('PUT', '/projects/r1/exam'), ('PUT', '/projects/r2/exam')]
        assert relay.calls[0][1:3] == ('prof', 'instructor')
        assert relay.calls[0][5]['started_at'] == X.iso_utc(NOW) and relay.calls[0][5]['end_at'] == X.iso_utc(NOW + 5400)
        wanted = [X.iso_utc(NOW), X.iso_utc(NOW + 5400), 60, 'Partiel']
        assert m.projects[DHCP]['synced'] == wanted and m.projects[SSH]['synced'] == wanted
        run(xp.reconcile())
        assert len(relay.calls) == 2                       # nothing changed: not asked again
        run(reg.adjust(exam.id, {'alice'}, 5))
        clock.now = NOW + XP.RECONCILE_INTERVAL
        run(xp.reconcile())
        assert len(relay.calls) == 4 and relay.calls[-1][5]['end_at'] == X.iso_utc(NOW + 5700)
        # a lab dropped: its project told to drop its exam object (an orphan), then forgotten
        run(reg.set_labs(exam.id, {'alice'}, [X.ExamLab(SSH)]))
        run(xp.sync_member(exam, m))
        assert relay.calls[-1][3:5] == ('DELETE', '/projects/r1/exam') and m.orphans == []
        # an agent down: what it got stays recorded, tried again after RETRY_DELAY only
        relay.answers[('PUT', 'exam')] = 503
        run(reg.adjust(exam.id, {'alice'}, 1))
        run(xp.sync_member(exam, m))
        assert m.projects[SSH]['synced'] == wanted[:1] + [X.iso_utc(NOW + 5700)] + wanted[2:]
        assert relay.calls[-1][3:5] == ('PUT', '/projects/r2/exam')
        run(xp.sync_member(exam, m))
        assert len([c for c in relay.calls if c[4] == '/projects/r2/exam']) == 3
        relay.answers[('PUT', 'exam')] = 200
        clock.now += XP.RETRY_DELAY
        run(xp.sync_member(exam, m))
        assert m.projects[SSH]['synced'][1] == X.iso_utc(NOW + 5760)
        # an older agent (404): told once, the project runs without an exam object
        relay.answers[('PUT', 'exam')] = 404
        run(reg.adjust(exam.id, {'alice'}, 1))
        run(xp.sync_member(exam, m))
        assert m.projects[SSH]['synced'][1] == X.iso_utc(NOW + 5820)
        # close (a background job, awaited here in the same loop) and release
        async def close_alice():
            job = await xp.close(exam, {'alice', 'nobody'})
            await job.task
            return job
        job = run(close_alice())
        assert (job.total, job.closed, job.failed, job.running) == (1, 1, 0, False) and m.projects == {}
        assert relay.calls[-1][3:5] == ('DELETE', '/projects/r2')
        run(reg.observe(exam, 'alice', [row(SSH, 'r5')]))
        run(xp.release(exam))
        assert relay.calls[-1][3:5] == ('DELETE', '/projects/r5/exam')
        # an unknown host: logged, no call
        run(reg.observe(exam, 'alice', [row(SSH, 'r6', host='zz')]))
        before = len(relay.calls)
        run(xp.sync_member(exam, m))
        assert len(relay.calls) == before

    def test_rows_of(self):
        clock, presence, reg = registry()
        rows = [row(DHCP, 'r1'), row(DHCP, 'r2', owner='carol'), row(SSH, 'r3'),
                dict(row(DHCP, 'r4', owner='bob'), exam={'id': '9'})]
        xp = XP.ExamProjects(reg, FakePool(rows=rows), FakeRelay(), clock=clock)
        exam = run(reg.create(PROF, spec()))
        found = run(xp.rows_of(exam, PROF))
        assert set(found) == {'alice', 'carol'}            # bob's row belongs to another exam
        assert found['alice'] == [{'host': 'a01', 'rln': 'r1', 'lab': DHCP, 'started_at': '20261104100000',
                                   'managed': None, 'exam': None}]


# ---------------------------------------------------------------------------------------------
# through the portal
# ---------------------------------------------------------------------------------------------

DB = {'host': 'db.example.org', 'user': 'sre_web', 'name': 'sre'}


def web_over(tmp_path, *, database=True, **more) -> dict:
    access_log = {'file': str(tmp_path / 'access.log'), 'journal': False, **({'database': DB} if database else {})}
    # no start slot: the browsers of the tests start a student's projects seconds apart
    return {**P.PROXY_OVER, 'access_log': access_log, 'archives': {'poll_interval': '1h'},
            'limits': {'start_interval': 0}, **more}


def harness(tmp_path, server=None, **kw):
    return P.Harness(tmp_path, auth_mode='proxy', web_over=web_over(tmp_path, database=server is not None),
                     db_connect=(server.connect, (Down,)) if server is not None else None, **kw)


async def api(h, method, path, headers, json_body=None, **kw):
    resp = await h.client.request(method, path, json=json_body, headers={**headers, **P.CSRF}, **kw)
    text = await resp.text()
    try:
        data = json.loads(text) if text else None
    except ValueError:
        data = text
    return resp.status, data


async def receive(ws, timeout=5.0) -> dict:
    async with asyncio.timeout(timeout):
        msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT, msg
    return json.loads(msg.data)


async def nothing(ws, timeout=0.3) -> bool:
    try:
        async with asyncio.timeout(timeout):
            msg = await ws.receive()
    except TimeoutError:
        return True
    raise AssertionError(f"unexpected frame {msg}")


class Spy:
    """The relay calls of the portal to the agent recorded (the bodies of the starts, the exam
    objects put)."""

    def __init__(self, relay):
        self.relay = relay
        self.starts = []
        self.calls = []
        self._ndjson = relay.forward_ndjson
        self._json = relay.json
        relay.forward_ndjson = self.forward_ndjson
        relay.json = self.json

    async def forward_ndjson(self, request, host, identity, method, path, *, data=None, **kw):
        self.starts.append((identity.login, json.loads(data)))
        return await self._ndjson(request, host, identity, method, path, data=data, **kw)

    async def json(self, host, identity, method, path, *, json=None, **kw):
        status, body = await self._json(host, identity, method, path, json=json, **kw)
        self.calls.append((identity.login, method, path, json, status))
        return status, body


class TestThroughThePortal:
    def test_pages_and_guards(self, tmp_path):
        async def go():
            bob, prof = P.who('bob'), P.who('prof', groups=P.TEACHERS)
            async with harness(tmp_path, FakeExamsServer()) as h:
                assert (await h.client.get('/exams', allow_redirects=False)).status == 302
                assert (await h.client.get('/exams', headers=bob)).status == 403
                page = await h.client.get('/exams', headers=prof)
                assert page.status == 200 and 'prof True True True 10.0 5.0 60.0' in await page.text()
                assert (await h.client.get('/api/exams')).status == 401
                assert (await h.client.get('/api/exams', headers=bob)).status == 403
                assert (await h.client.get('/api/labs?all=1', headers=bob)).status == 403
                assert (await h.client.post('/api/exams', json={}, headers=prof)).status == 403    # no CSRF header
                status, data = await api(h, 'GET', '/api/exams', prof)
                assert status == 200 and data['exams'] == [] and data['database'] == {'connected': True, 'last_error': None}
                status, data = await api(h, 'GET', '/api/exam', bob)
                assert status == 200 and data['exam'] is None and abs(data['now'] - time.time()) < 5
                assert (await api(h, 'GET', '/api/exam', prof))[1]['exam'] is None
                status, data = await api(h, 'POST', '/api/exams', prof, {'title': 'x', 'audience': ['bob'],
                                                                        'labs': ['nope.py'], 'duration': 10})
                assert status == 400 and 'unknown lab' in data['error']
                assert (await api(h, 'GET', '/api/exams/7', prof))[0] == 404
                assert (await api(h, 'POST', '/api/exam/7/dismiss', bob))[0] == 404
            # without a database the page says so and the exams cannot be created
            async with harness(tmp_path / 'nodb') as h:
                page = await h.client.get('/exams', headers=prof)
                assert 'prof True False True' in await page.text()
                status, data = await api(h, 'POST', '/api/exams', prof, {'title': 'x', 'audience': ['bob'],
                                                                        'labs': [DHCP], 'duration': 10})
                assert status == 409 and 'access_log.database' in data['error']
                assert (await api(h, 'GET', '/api/exams', prof))[1]['database'] is None
        run(go())

    def test_lifecycle(self, tmp_path):
        async def go():
            alice, carol, prof = P.who('alice', 'Alice A', group='INFO1'), P.who('carol', group='INFO2'), \
                P.who('prof', groups=P.TEACHERS)
            server = FakeExamsServer()
            async with harness(tmp_path, server) as h:
                clock = Clock(float(int(time.time())))      # whole seconds: the instants of the test are exact
                h.portal.exams.clock = clock
                h.portal.exam_projects.clock = clock
                spy = Spy(h.portal.relay)
                ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=alice)
                assert await nothing(ws)
                # before the exam alice works on tp_ssh
                rln_ssh = await T.start_project(h, alice, lab=SSH)
                # prof programs an exam on the DHCP lab for INFO1, 90 minutes, now
                status, exam = await api(h, 'POST', '/api/exams', prof, {
                    'title': 'Partiel', 'audience': {'groups': ['INFO1']}, 'labs': [DHCP], 'duration': 90,
                    'pre_start': 2, 'eval_interval': 30})
                assert status == 201, exam
                assert exam['status'] == 'running' and exam['start_after'] is None and exam['members'] == 1
                assert exam['labs'] == [{'lab': DHCP, 'flavor': None}] and exam['created_by'] == 'prof'
                xid = exam['id']
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'starting'}
                # alice is bound: the exam alone, her tp_ssh hidden and refused, the Open page gone
                status, data = await api(h, 'GET', '/api/exam', alice)
                assert data['exam']['phase'] == 'starting' and data['exam']['title'] == 'Partiel'
                assert data['exam']['labs'][0]['lab_name'] == 'sre@dhcp.py' and data['exam']['address_allowed']
                assert data['exam']['started_at'] is None and data['exam']['end_at'] is None
                assert (await api(h, 'GET', '/api/projects', alice))[1] == []
                assert [l['name'] for l in (await api(h, 'GET', '/api/labs', alice))[1]] == [DHCP]
                status, data = await api(h, 'GET', f'/api/projects/a01/{rln_ssh}', alice)
                assert status == 403 and data['error'] == X.REASON_OTHER_LAB
                assert (await h.client.get(f'/projects/a01/{rln_ssh}', headers=alice, allow_redirects=False)).status == 302
                assert (await h.client.get('/open', headers=alice, allow_redirects=False)).status == 302
                status, data = await api(h, 'POST', '/api/projects', alice, {'lab': SSH})
                assert status == 403 and data['error'] == X.REASON_OTHER_LAB
                # carol (INFO2) is not concerned
                assert (await api(h, 'GET', '/api/exam', carol))[1]['exam'] is None
                assert (await api(h, 'GET', '/api/projects/a01/' + rln_ssh, carol))[0] == 403    # not hers anyway
                # her browser starts the exam lab: the relayed body carries the exam object
                rln = await T.start_project(h, alice, lab=DHCP)
                body = spy.starts[-1][1]
                assert body['exam']['id'] == str(xid) and body['exam']['started_at'] is None
                assert body['exam']['eval_interval'] == 30 and body['idle_timeout'] == 3600
                await asyncio.sleep(0.2)                           # the creation recorded after the stream
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'active'}
                status, data = await api(h, 'GET', '/api/exam', alice)
                assert data['exam']['phase'] == 'active' and data['exam']['end_at'] == data['exam']['started_at'] + 5400
                m = h.portal.exams.get(xid).members['alice']
                assert m.projects == {DHCP: {'host': 'a01', 'rln': rln, 'synced': m.projects[DHCP]['synced']}}
                put = [c for c in spy.calls if c[1] == 'PUT' and c[2].endswith('/exam')]
                assert put and put[-1][0] == 'prof' and put[-1][3]['started_at'] is not None
                # her projects: the exam one alone, marked; it opens; it cannot be closed; no second one
                rows = (await api(h, 'GET', '/api/projects', alice))[1]
                assert [r['running_lab_name'] for r in rows] == [rln] and rows[0]['exam'] == {'id': xid, 'title': 'Partiel'}
                assert (await api(h, 'GET', f'/api/projects/a01/{rln}', alice))[0] == 200
                assert (await h.client.get(f'/projects/a01/{rln}', headers=alice, allow_redirects=False)).status == 200
                status, data = await api(h, 'DELETE', f'/api/projects/a01/{rln}', alice)
                assert status == 403 and 'cannot be closed' in data['error']
                status, data = await api(h, 'POST', '/api/projects', alice, {'lab': DHCP})
                assert status == 409
                # prof sees her in the detail, with her project
                status, detail = await api(h, 'GET', f'/api/exams/{xid}', prof)
                member = next(mm for mm in detail['members'] if mm['login'] == 'alice')
                assert member['phase'] == 'active' and member['connected'] and member['fullname'] == 'Alice A'
                assert member['projects'][0]['rln'] == rln and member['end_at'] == member['started_at'] + 5400
                # +5 minutes for her: her end moves, the agent is told
                status, data = await api(h, 'POST', f'/api/exams/{xid}/adjust', prof, {'logins': ['alice'],
                                                                                        'extra_minutes': 5})
                assert status == 200, data
                assert (await api(h, 'GET', '/api/exam', alice))[1]['exam']['end_at'] == member['end_at'] + 300
                assert spy.calls[-1][1:3] == ('PUT', f"/projects/{urllib.parse.quote(rln, safe='')}/exam")
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'active'}     # her end moved: told
                assert (await api(h, 'POST', f'/api/exams/{xid}/adjust', prof, {'logins': ['carol'],
                                                                                 'extra_minutes': 5}))[0] == 400
                # the end for everybody: the banner, the project refused, then dismissed
                status, data = await api(h, 'POST', f'/api/exams/{xid}/end', prof, {'all': True})
                assert status == 200 and data['status'] == 'past'
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'ended'}
                status, data = await api(h, 'GET', '/api/exam', alice)
                assert data['exam']['phase'] == 'ended' and data['exam']['dismissable']
                assert (await api(h, 'GET', '/api/projects', alice))[1] == []
                status, data = await api(h, 'GET', f'/api/projects/a01/{rln}', alice)
                assert status == 403 and data['error'] == X.REASON_OVER
                status, data = await api(h, 'POST', f'/api/exam/{xid}/dismiss', alice)
                assert status == 200 and data == {'ok': True, 'phase': 'done'}
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': None}
                assert (await api(h, 'POST', f'/api/exam/{xid}/dismiss', alice))[0] == 409
                assert (await api(h, 'GET', '/api/exam', alice))[1]['exam'] is None
                rows = (await api(h, 'GET', '/api/projects', alice))[1]
                assert [r['running_lab_name'] for r in rows] == [rln_ssh]       # the usual pages, the exam project hidden
                assert (await api(h, 'GET', f'/api/projects/a01/{rln}', alice))[0] == 403
                assert (await api(h, 'GET', f'/api/projects/a01/{rln_ssh}', alice))[0] == 200
                # prof closes her exam project, then deletes the exam
                status, data = await api(h, 'POST', f'/api/exams/{xid}/close-projects', prof, {'all': True})
                assert status == 202 and data['closed'] == 0                 # the stops run in the background
                assert data['closing']['total'] == 1 and data['closing']['running'] is True
                detail = None
                for _ in range(50):
                    await asyncio.sleep(0.1)
                    detail = (await api(h, 'GET', f'/api/exams/{xid}', prof))[1]
                    if detail['closing'] and not detail['closing']['running']:
                        break
                assert detail['closing']['closed'] == 1 and detail['closing']['failed'] == 0
                rows = (await api(h, 'GET', '/api/projects', prof))[1]
                assert rln not in [r['running_lab_name'] for r in rows]
                status, data = await api(h, 'POST', f'/api/exams/{xid}/close-projects', prof, {'all': True})
                assert status == 200 and data['closing']['total'] == 0       # nothing left to close
                status, data = await api(h, 'DELETE', f'/api/exams/{xid}', prof)
                assert status == 200 and data == {'ok': True, 'closed': 0, 'closing': None}
                assert (await api(h, 'GET', '/api/exams', prof))[1]['exams'] == []
                await ws.close()
                # the log: the start of the exam project carries the exam, the edits their action
                lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
                starts = [l for l in lines if l['event'] == 'start' and l.get('login') == 'alice']
                assert [l.get('exam') for l in starts] == [None, str(xid), str(xid), str(xid)]
                assert [l['status'] for l in starts] == ['200', '403', '200', '409']
                edits = [(l['action'], l['status']) for l in lines if l['event'] == 'exam_edit']
                assert edits == [('create', '201'), ('adjust', '200'), ('adjust', '400'), ('end', '200'),
                                 ('close', '202'), ('close', '200'), ('delete', '200')]
                assert [l['status'] for l in lines if l['event'] == 'exam_dismiss'] == ['200', '409']
                denied = [l for l in lines if l['event'] == 'denied' and l['login'] == 'alice']
                assert len(denied) >= 3
        run(go())

    def test_lead_window_and_countdown(self, tmp_path):
        async def go():
            alice, prof = P.who('alice', group='INFO1'), P.who('prof', groups=P.TEACHERS)
            async with harness(tmp_path, FakeExamsServer()) as h:
                clock = Clock(float(int(time.time())))      # whole seconds: the instants of the test are exact
                exams = h.portal.exams
                exams.clock = clock
                h.portal.exam_projects.clock = clock
                start = clock.now + 900
                status, exam = await api(h, 'POST', '/api/exams', prof, {
                    'title': 'Later', 'audience': {'logins': ['alice']}, 'labs': [DHCP], 'duration': 60,
                    'start_after': start, 'end_before': start + 7200})
                assert status == 201, exam
                xid = exam['id']
                assert exam['status'] == 'scheduled' and exam['prestart_at'] == start - 300 and exam['hide_at'] == start - 600
                ws = await h.client.ws_connect('/api/presence/ws?page=/projects', headers=alice)
                assert await nothing(ws) and (await api(h, 'GET', '/api/exam', alice))[1]['exam'] is None
                rln_ssh = await T.start_project(h, alice, lab=SSH)         # free before the lead window
                clock.now = start - 600                                     # the lead window: hidden, countdown
                await exams.tick()
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'waiting'}
                status, data = await api(h, 'GET', '/api/exam', alice)
                assert data['exam']['phase'] == 'waiting' and data['exam']['start_at'] == start
                assert data['exam']['prestart_at'] == start - 300 and abs(data['now'] - clock.now) < 1
                assert (await api(h, 'GET', '/api/projects', alice))[1] == []
                status, data = await api(h, 'POST', '/api/projects', alice, {'lab': DHCP})
                assert status == 403 and data['error'].startswith('the exam projects start at')
                clock.now = start - 300                                     # the pre-start: the browser starts it
                rln = await T.start_project(h, alice, lab=DHCP)
                await asyncio.sleep(0.2)
                rows = (await api(h, 'GET', '/api/projects', alice))[1]
                assert [r['running_lab_name'] for r in rows] == [rln] and rows[0]['exam']['id'] == xid
                status, data = await api(h, 'GET', f'/api/projects/a01/{rln}', alice)
                assert status == 403 and data['error'] == X.REASON_NOT_STARTED
                assert (await api(h, 'GET', '/api/exam', alice))[1]['exam']['started_at'] is None
                assert await nothing(ws)
                clock.now = start                                           # the start: her clock starts
                await exams.tick()
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'active'}
                status, data = await api(h, 'GET', '/api/exam', alice)
                assert data['exam']['started_at'] == start and data['exam']['end_at'] == start + 3600
                assert (await api(h, 'GET', f'/api/projects/a01/{rln}', alice))[0] == 200
                assert (await api(h, 'GET', f'/api/projects/a01/{rln_ssh}', alice))[0] == 403
                # the instructor extends everybody by 30 minutes: the duration and the end time move
                status, data = await api(h, 'POST', f'/api/exams/{xid}/adjust', prof, {'all': True, 'extra_minutes': 30})
                assert status == 200 and data['duration'] == 90 and data['end_before'] == start + 9000
                assert (await api(h, 'GET', '/api/exam', alice))[1]['exam']['end_at'] == start + 5400
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'active'}     # the end moved: told
                # Start now = the start time edited to now, End now by a PUT of end_before
                status, data = await api(h, 'PUT', f'/api/exams/{xid}', prof, {'title': 'Renamed'})
                assert status == 200 and data['title'] == 'Renamed' and data['duration'] == 90
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'active'}     # the title changed: told
                clock.now = start + 5400
                await exams.tick()
                assert await receive(ws) == {'t': 'exam', 'id': xid, 'phase': 'ended'}
                await ws.close()
        run(go())

    def test_networks(self, tmp_path):
        async def go():
            alice, prof = P.who('alice', group='INFO1'), P.who('prof', groups=P.TEACHERS)
            inside = {**alice, 'X-Forwarded-For': '10.0.0.5'}
            async with harness(tmp_path, FakeExamsServer()) as h:
                status, exam = await api(h, 'POST', '/api/exams', prof, {
                    'title': 'Room', 'audience': {'groups': ['INFO1']}, 'labs': [DHCP], 'duration': 60,
                    'networks': ['10.0.0.0/8']})
                assert status == 201 and exam['networks'] == ['10.0.0.0/8']
                xid = exam['id']
                # from the room: everything as usual
                status, data = await api(h, 'GET', '/api/exam', inside)
                assert data['exam']['address_allowed'] and data['exam']['address'] == '10.0.0.5'
                assert [l['name'] for l in (await api(h, 'GET', '/api/labs', inside))[1]] == [DHCP]
                # from elsewhere: a message, no project at all
                status, data = await api(h, 'GET', '/api/exam', alice)
                assert not data['exam']['address_allowed'] and data['exam']['address'] == '127.0.0.1'
                assert (await api(h, 'GET', '/api/projects', alice))[1] == []
                assert (await api(h, 'GET', '/api/labs', alice))[1] == []
                status, data = await api(h, 'POST', '/api/projects', alice, {'lab': DHCP})
                assert status == 403 and data['error'] == X.REASON_ADDRESS.format(address='127.0.0.1')
                rln = await T.start_project(h, inside, lab=DHCP)
                await asyncio.sleep(0.2)
                status, data = await api(h, 'GET', f'/api/projects/a01/{rln}', alice)
                assert status == 403 and 'not allowed' in data['error']
                assert (await api(h, 'GET', f'/api/projects/a01/{rln}', inside))[0] == 200
                member = (await api(h, 'GET', f'/api/exams/{xid}', prof))[1]['members'][0]
                assert member['login'] == 'alice' and member['address'] in ('10.0.0.5', '127.0.0.1')
        run(go())

    def test_restart_of_the_portal_keeps_the_exam(self, tmp_path):
        async def go():
            alice, prof = P.who('alice', group='INFO1'), P.who('prof', groups=P.TEACHERS)
            server = FakeExamsServer()
            async with harness(tmp_path, server) as h:
                status, exam = await api(h, 'POST', '/api/exams', prof, {
                    'title': 'Kept', 'audience': {'groups': ['INFO1']}, 'labs': [DHCP], 'duration': 60})
                assert status == 201
                rln = await T.start_project(h, alice, lab=DHCP)
                await asyncio.sleep(0.2)
                before = (await api(h, 'GET', '/api/exam', alice))[1]['exam']
                assert before['phase'] == 'active'
            async with harness(tmp_path / 'again', server) as h:
                exams = (await api(h, 'GET', '/api/exams', prof))[1]['exams']
                assert [e['title'] for e in exams] == ['Kept']
                after = (await api(h, 'GET', '/api/exam', alice))[1]['exam']
                assert after['phase'] == 'active' and after['started_at'] == before['started_at']
                assert after['end_at'] == before['end_at']
                rows = (await api(h, 'GET', '/api/projects', alice))[1]
                assert rows == []                       # the project lived on the first harness's agent
                assert 'exams' in h.portal.exams.describe()
        run(go())
