"""The exam mode of the web front-end as a student's browser lives it: a headless Chrome
(``web_browser.py``; skipped without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one)
on the real pages of ``web/`` served by the portal of test_web_portal.py (proxy mode behind an
identity proxy, a real agent on the fake ``sre``, the fake database of test_web_exams.py),
the instructor acting through the API: the countdown and the hidden projects before the start,
the automatic start of the exam project and the opening of its page, the page during the exam
(no Close button, no Evaluation tab), time added then taken, the end banner and Continue, time
added after the end (the page of the still running project comes back; a closed project is
started again), a lab added then one removed during the exam.  Real clock: short exams, every
wait bounded."""
import asyncio
import contextlib
import json
import re
import time
from datetime import datetime
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
import test_web_presentation as T                             # noqa: E402  (start_project)
import test_web_exams as X                                    # noqa: E402  (the fake database, api(), the labs)
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402
from sreweb.portal.accesslog import parse_line               # noqa: E402

CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
DHCP, SSH = X.DHCP, X.SSH
ALICE = P.who('alice', 'Alice A', group='INFO1')
PROF = P.who('prof', groups=P.TEACHERS)
api = X.api
run = T.run
# the first automatic start of a page waits up to START_JITTER (5 s) of projects.js, the mock
# start a few tenths of a second, the reconcile loop of the portal runs every 5 s
START_WAIT = 25.0
SYNC_WAIT = 20.0      # one retry of the portal (15 s) after a sync refused by the agent, plus a tick

# -- what the page shows, as JavaScript expressions ---------------------------------------------

BOUND = "document.body.classList.contains('exam-bound')"
PHASE = "([...document.body.classList].find((c) => /^exam-(waiting|starting|active|ended)$/.test(c)) || '').slice(5)"
BAR = "(document.getElementById('exam-bar') && !document.getElementById('exam-bar').hidden) ? document.getElementById('exam-bar').textContent : ''"
COUNTDOWN = "(document.querySelector('#exam-bar .countdown') || {textContent: ''}).textContent"
OVERLAY = "document.getElementById('exam-ended') !== null"
NOTE = "(document.getElementById('exam-note') && !document.getElementById('exam-note').hidden) ? document.getElementById('exam-note').textContent : ''"
# the cards of the Projects page: {rln, exam, open, close, note}
CARDS = """[...document.querySelectorAll('#projects .card')].map((c) => ({
    rln: c.querySelector('h2').title, exam: c.classList.contains('exam'),
    open: Boolean(c.querySelector('a.button.primary')), close: Boolean(c.querySelector('button.danger')),
    note: (c.querySelector('.actions .muted') || {textContent: ''}).textContent}))"""
CARDS_LOADED = "document.querySelector('#projects .card, #no-project:not([hidden])') !== null"
LOGO = "!document.getElementById('no-project').hidden"
OPEN_LINK_HIDDEN = ("(() => { const a = document.querySelector('a[href=\"/open\"]'); "
                    "return a === null || getComputedStyle(a).display === 'none'; })()")
ON_PROJECT_PAGE = "window.location.pathname.startsWith('/projects/a01/')"
ON_PROJECTS_PAGE = "window.location.pathname === '/projects'"
TABS = "[...document.querySelectorAll('#tabbar [role=tab]')].map((b) => b.dataset.tab)"
TABBAR_SHOWN = "!document.getElementById('tabbar').hidden && document.querySelectorAll('#tabbar [role=tab]').length > 0"
CLOSE_HIDDEN = "document.getElementById('close-project').hidden"
RLN = "document.body.dataset.rln || ''"


def seconds(countdown: str) -> int:
    """The seconds of a HH:MM:SS countdown."""
    m = re.fullmatch(r'(\d+):(\d\d):(\d\d)', countdown.strip())
    assert m, f"not a countdown: {countdown!r}"
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))


def epoch(iso: str | None) -> float | None:
    return None if iso is None else datetime.fromisoformat(iso).timestamp()


def same_time(iso: str | None, at: float | None) -> bool:
    """The agent's times are whole seconds, the portal's keep the milliseconds."""
    return (iso is None) == (at is None) and (at is None or abs(epoch(iso) - at) < 1.0)


@contextlib.asynccontextmanager
async def student_browser(tmp_path, identity=ALICE):
    """The harness (proxy mode, the fake database, the real web directory), the identity proxy
    making the browser *identity*, and the browser: ``(h, browser, url)``."""
    server = X.FakeExamsServer()
    h = X.harness(tmp_path, server, host_over={'max_projects': 6})
    h.web_dir = WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', identity)
        await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield h, browser, proxy.url
        finally:
            await proxy.close()


async def exam_state(h, headers=ALICE) -> dict:
    return (await api(h, 'GET', '/api/exam', headers))[1]['exam']


async def agent_exam(h, rln, headers=PROF) -> dict | None:
    """The exam object the agent holds for a project (its view), through the portal."""
    status, data = await api(h, 'GET', f'/api/projects/a01/{rln}', headers)
    assert status == 200, data
    return data['project'].get('exam')


async def until(check, timeout: float, what: str):
    """Poll an async *check* until it returns a true value, and return it."""
    deadline = time.monotonic() + timeout
    while True:
        value = await check()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"timeout waiting for {what}: last value {value!r}")
        await asyncio.sleep(0.25)


async def countdown_follows(page, end_at: float, timeout: float = 8.0, tolerance: float = 3.0) -> int:
    """Wait until the countdown of the bar is within *tolerance* seconds of *end_at*."""
    deadline = time.monotonic() + timeout
    while True:
        text = await page.evaluate(COUNTDOWN)
        left = seconds(text) if text.strip() else None
        if left is not None and abs(left - (end_at - time.time())) <= tolerance:
            return left
        if time.monotonic() >= deadline:
            raise AssertionError(f"the countdown {text!r} does not follow the end {end_at - time.time():.0f} s away")
        await asyncio.sleep(0.25)


async def create_exam(h, **over) -> dict:
    body = {'title': 'Partiel', 'audience': ['alice'], 'labs': [DHCP], 'duration': 2, **over}
    status, exam = await api(h, 'POST', '/api/exams', PROF, body)
    assert status == 201, exam
    return exam


async def act(h, xid, action, body) -> dict:
    status, data = await api(h, 'POST', f'/api/exams/{xid}/{action}', PROF, body)
    assert status in (200, 202), data         # 202: a close running in the background
    return data


def access_lines(tmp_path) -> list:
    return [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]


# ---------------------------------------------------------------------------------------------


class TestStudentFlow:
    def test_scheduled_exam(self, tmp_path):
        """Before the start: the countdown, the other project hidden; at the pre-start the
        project starts by itself (no Open link yet); at the start the page opens it (no Close
        button, no Evaluation tab, the time left); End now: the banner, the page shut down, the
        agent's exam ended; Continue: the usual page, the exam project hidden."""
        async def go():
            async with student_browser(tmp_path) as (h, browser, url):
                rln_ssh = await T.start_project(h, ALICE, lab=SSH)         # alice works on tp_ssh before
                page = await browser.page(url + '/projects')
                await page.wait_for(CARDS_LOADED, what="the cards")
                cards = await page.evaluate(CARDS)
                assert [(c['rln'], c['exam'], c['open'], c['close']) for c in cards] == [(rln_ssh, False, True, True)]
                assert not await page.evaluate(BOUND)
                # the exam: in 16 s, the countdown from 30 s before, the project started 9 s before
                # (the page waits up to 5.5 s before its first start, the mock start takes a second)
                t0 = time.time()
                exam = await create_exam(h, start_after=t0 + 16, lead=0.5, pre_start=0.15)
                xid = exam['id']
                await page.wait_for(f"{PHASE} === 'waiting'", what="the waiting phase")
                bar = await page.evaluate(BAR)
                assert 'Partiel' in bar and 'starts in' in bar and 'your other projects are hidden' in bar
                assert 8 <= seconds(await page.evaluate(COUNTDOWN)) <= 16
                await page.wait_for(f"{CARDS}.length === 0", what="the other project hidden")
                assert 'prepared shortly before' in await page.evaluate(NOTE)
                assert await page.evaluate(OPEN_LINK_HIDDEN)
                # the pre-start: the exam project started by the page, without Open link until the
                # start (the phase and the cards read together: the start may come meanwhile)
                seen = await page.wait_for(f"({CARDS}.length === 1 && {CARDS}[0].exam) ? {{phase: {PHASE}, card: {CARDS}[0]}} : null",
                                           START_WAIT, what="the automatic start")
                card = seen['card']
                assert card['exam'] and not card['close']
                if seen['phase'] in ('waiting', 'starting'):
                    assert not card['open'] and 'Available when the exam starts' in card['note']
                else:
                    assert seen['phase'] == 'active' and card['open']
                rln = card['rln']
                assert rln != rln_ssh and '@@@sre@dhcp.py@@@alice' in rln
                # the start: the project page opens by itself
                await page.wait_for(ON_PROJECT_PAGE, START_WAIT, what="the project page")
                await page.wait_for(f"{PHASE} === 'active' && {TABBAR_SHOWN}", what="the active exam on the project page")
                assert await page.evaluate(RLN) == rln
                bar = await page.evaluate(BAR)
                assert 'time left' in bar and 90 <= seconds(await page.evaluate(COUNTDOWN)) <= 121
                assert await page.evaluate(CLOSE_HIDDEN)
                tabs = await page.evaluate(TABS)
                assert 'schema' in tabs and 'questions' in tabs and 'evaluation' not in tabs and 'apply_config' not in tabs
                state = await exam_state(h)
                assert state['phase'] == 'active' and state['started_at'] is not None
                assert state['end_at'] == state['started_at'] + 120
                view = await until(lambda: agent_exam(h, rln), SYNC_WAIT, "the agent's exam object")
                assert view['id'] == str(xid) and same_time(view['end_at'], state['end_at']) and not view['ended']
                # End now: the banner, the page shut down, the agent ends the exam
                await act(h, xid, 'end', {'all': True})
                await page.wait_for(f"{OVERLAY} && document.getElementById('tabbar').hidden", what="the end banner")
                assert 'is over' in await page.evaluate("document.querySelector('#exam-ended .exam-ended-title').textContent")
                view = await until(lambda: _ended(h, rln), SYNC_WAIT, "the agent's exam ended")
                assert view['ended_at'] is not None
                # Continue: the usual page, the exam project hidden, the exam gone from the page
                await page.click('#exam-ended button')
                await page.wait_for(f"{ON_PROJECTS_PAGE} && !{BOUND} && {CARDS_LOADED}", what="the usual Projects page")
                cards = await page.evaluate(CARDS)
                assert [(c['rln'], c['exam'], c['open']) for c in cards] == [(rln_ssh, False, True)]
                assert not await page.evaluate(OVERLAY) and await page.evaluate(BAR) == ''
                assert (await exam_state(h)) is None
                assert js_errors(page) == [], page.errors
                # the log: the automatic start carries the exam, the dismiss is logged
                lines = access_lines(tmp_path)
                starts = [l for l in lines if l['event'] == 'start' and l.get('login') == 'alice']
                assert [(l.get('lab'), l.get('exam'), l['status']) for l in starts] == [(SSH, None, '200'),
                                                                                       (DHCP, str(xid), '200')]
                assert [l['status'] for l in lines if l['event'] == 'exam_dismiss'] == ['200']
        run(go())


async def _ended(h, rln):
    view = await agent_exam(h, rln)
    return view if view and view['ended'] else None


async def _resumed(h, rln):
    view = await agent_exam(h, rln)
    return view if view and not view['ended'] else None


class TestTimeChanges:
    def test_add_take_end_and_resume(self, tmp_path):
        """During the exam, +2 min then -2 min for everybody: the countdown of the page and the
        agent's end follow within seconds; -3 min for the student: over, the banner; +3 min: the
        exam resumed, the page of the still running project comes back; End now, Continue; the
        project closed, then +5 min: the exam resumed, a new project started by the page."""
        async def go():
            async with student_browser(tmp_path) as (h, browser, url):
                exam = await create_exam(h)                       # 2 minutes, from now
                xid = exam['id']
                page = await browser.page(url + '/projects')
                await page.wait_for(ON_PROJECT_PAGE, START_WAIT, what="the automatic start and the project page")
                await page.wait_for(f"{PHASE} === 'active' && {TABBAR_SHOWN}", what="the active exam")
                rln = await page.evaluate(RLN)
                state = await exam_state(h)
                end0 = state['end_at']
                assert end0 == state['started_at'] + 120
                await countdown_follows(page, end0)
                # +2 minutes for everybody: the page and the agent follow
                await act(h, xid, 'adjust', {'all': True, 'extra_minutes': 2})
                assert (await exam_state(h))['end_at'] == end0 + 120
                await countdown_follows(page, end0 + 120)
                view = await until(lambda: _agent_end(h, rln, end0 + 120), SYNC_WAIT, "the agent's end moved")
                assert not view['ended']
                # -2 minutes: back
                await act(h, xid, 'adjust', {'all': True, 'extra_minutes': -2})
                assert (await exam_state(h))['end_at'] == end0
                await countdown_follows(page, end0)
                await until(lambda: _agent_end(h, rln, end0), SYNC_WAIT, "the agent's end back")
                # -3 minutes for alice: over now
                await act(h, xid, 'adjust', {'logins': ['alice'], 'extra_minutes': -3})
                assert (await exam_state(h))['phase'] == 'ended'
                await page.wait_for(f"{OVERLAY} && document.getElementById('tabbar').hidden", what="the end banner")
                assert await page.evaluate(RLN) == rln
                view = await until(lambda: _ended(h, rln), SYNC_WAIT, "the agent's exam ended")
                assert view['ended_at'] is not None
                # +3 minutes for alice: the exam resumes, the page of the still running project comes back
                await act(h, xid, 'adjust', {'logins': ['alice'], 'extra_minutes': 3})
                state = await exam_state(h)
                assert state['phase'] == 'active' and state['end_at'] == end0
                await page.wait_for(f"{PHASE} === 'active' && !{OVERLAY} && {TABBAR_SHOWN}", what="the page back")
                assert await page.evaluate(RLN) == rln and await page.evaluate(CLOSE_HIDDEN)
                await countdown_follows(page, end0)
                view = await until(lambda: _resumed(h, rln), SYNC_WAIT, "the agent's exam resumed")
                assert view['ended_at'] is None and same_time(view['end_at'], end0)
                assert (await api(h, 'GET', f'/api/projects/a01/{rln}', ALICE))[0] == 200
                # End now for everybody, Continue: the usual page (no project of hers)
                await act(h, xid, 'end', {'all': True})
                await page.wait_for(OVERLAY, what="the end banner")
                await page.click('#exam-ended button')
                await page.wait_for(f"{ON_PROJECTS_PAGE} && !{BOUND} && {LOGO}", what="the usual Projects page")
                # the project closed by the instructor, then +5 minutes for everybody: the exam
                # resumes and the page starts a new project
                closing = (await act(h, xid, 'close-projects', {'all': True}))['closing']    # 202: in the background
                assert closing['total'] == 1 and closing['running'] is True
                await until(lambda: _gone(h, rln), SYNC_WAIT, "the project closed")
                await act(h, xid, 'adjust', {'all': True, 'extra_minutes': 5})
                state = await exam_state(h)
                assert state['phase'] == 'active' and state['end_at'] == end0 + 300
                await page.wait_for(f"{ON_PROJECT_PAGE} && {RLN} !== {json.dumps(rln)}", START_WAIT,
                                    what="a new project started and opened")
                await page.wait_for(f"{PHASE} === 'active' && {TABBAR_SHOWN}", what="the active exam on the new project")
                rln2 = await page.evaluate(RLN)
                assert rln2 != rln and '@@@sre@dhcp.py@@@alice' in rln2
                await countdown_follows(page, end0 + 300)
                view = await until(lambda: agent_exam(h, rln2), SYNC_WAIT, "the new project's exam object")
                assert view['id'] == str(xid) and not view['ended'] and same_time(view['end_at'], end0 + 300)
                assert js_errors(page) == [], page.errors
                lines = access_lines(tmp_path)
                starts = [l for l in lines if l['event'] == 'start' and l.get('login') == 'alice' and l['status'] == '200']
                assert [l.get('exam') for l in starts] == [str(xid), str(xid)]
                edits = [l['action'] for l in lines if l['event'] == 'exam_edit']
                assert edits == ['create', 'adjust', 'adjust', 'adjust', 'adjust', 'end', 'close', 'adjust']
        run(go())


async def _agent_end(h, rln, end_at):
    view = await agent_exam(h, rln)
    return view if view and same_time(view['end_at'], end_at) else None


async def _gone(h, rln):
    rows = (await api(h, 'GET', '/api/projects', PROF))[1]
    return rln not in [r['running_lab_name'] for r in rows]


class TestLabsChange:
    def test_lab_added_then_removed(self, tmp_path):
        """A lab added during the exam: the page of the exam project goes to the Projects page,
        which starts the new project; both cards open.  The first lab removed: its project is
        hidden from the student and refused, the agent is told it is no exam project any more."""
        async def go():
            async with student_browser(tmp_path) as (h, browser, url):
                exam = await create_exam(h, duration=5)
                xid = exam['id']
                page = await browser.page(url + '/projects')
                await page.wait_for(ON_PROJECT_PAGE, START_WAIT, what="the automatic start and the project page")
                await page.wait_for(f"{PHASE} === 'active' && {TABBAR_SHOWN}", what="the active exam")
                rln_dhcp = await page.evaluate(RLN)
                # tp_ssh added: the page goes to the Projects page, which starts it
                await act(h, xid, 'labs', {'all': True, 'labs': [DHCP, SSH]})
                await page.wait_for(ON_PROJECTS_PAGE, what="the Projects page")
                await page.wait_for(f"{CARDS}.length === 2 && {CARDS}.every((c) => c.exam && c.open)", START_WAIT,
                                    what="the two exam projects")
                cards = await page.evaluate(CARDS)
                rln_ssh = next(c['rln'] for c in cards if c['rln'] != rln_dhcp)
                assert '@@@s4@tp_ssh@@@alice' in rln_ssh and not any(c['close'] for c in cards)
                assert (await page.evaluate(PHASE)) == 'active' and 'only its projects are available' in await page.evaluate(NOTE)
                view = await until(lambda: agent_exam(h, rln_ssh), SYNC_WAIT, "the exam object of the new project")
                assert view['id'] == str(xid) and view['started_at'] is not None
                state = await exam_state(h)
                assert [l['lab'] for l in state['labs']] == [DHCP, SSH]
                # the DHCP lab removed: its project hidden and refused, a plain project for the agent
                await act(h, xid, 'labs', {'all': True, 'labs': [SSH]})
                await page.wait_for(f"{CARDS}.length === 1 && {CARDS}[0].rln === {json.dumps(rln_ssh)}", SYNC_WAIT,
                                    what="the tp_ssh card alone")
                assert (await page.evaluate(PHASE)) == 'active'
                status, data = await api(h, 'GET', f'/api/projects/a01/{rln_dhcp}', ALICE)
                assert status == 403 and 'exam' in data['error']
                await until(lambda: _plain(h, rln_dhcp), SYNC_WAIT, "the DHCP project without exam")
                assert (await agent_exam(h, rln_ssh))['id'] == str(xid)
                rows = (await api(h, 'GET', '/api/projects', ALICE))[1]
                assert [r['running_lab_name'] for r in rows] == [rln_ssh]
                assert js_errors(page) == [], page.errors
        run(go())


async def _plain(h, rln):
    return (await agent_exam(h, rln)) is None


def js_errors(page) -> list:
    """The uncaught exceptions of the page but the fetches a navigation of the page itself
    aborted (the polls in flight when the page goes to the project)."""
    return [e for e in page.errors if 'Failed to fetch' not in e and 'NetworkError' not in e and 'AbortError' not in e]
