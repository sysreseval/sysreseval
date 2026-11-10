"""The web conference as a browser lives it: a headless Chrome (``web_browser.py``; skipped
without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/``
served by the portal of test_web_portal.py (proxy mode behind an identity proxy), the fake
BigBlueButton server of ``fake_bbb.py`` as its ``[bbb]`` (its client page is one Leave link).
An instructor opens a room for a student: the client appears in a floating window over the
student's page, is dragged, minimized and restored, comes back at the same place on the project
page, is docked into the Webconf tab (hidden, alive, while another tab is shown), shown full
page and in a window again, left through the client's own link (the pill) and rejoined, restored
after a reload, and removed when the instructor ends the room; a second tab of the student shows
a pill instead of joining twice, and takes the client over."""
import asyncio
import contextlib
import functools
import time
from pathlib import Path
from urllib.parse import quote

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
import test_web_presentation as T                             # noqa: E402  (start_project)
from fake_bbb import FakeBbbServer                            # noqa: E402
from web_browser import Browser, IdentityProxy, find_chrome   # noqa: E402

CHROME = find_chrome()
WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")
ALICE = P.who('alice', 'Alice A', group='INFO1')
PROF = P.who('prof', 'Pr. Of', groups=P.TEACHERS)
run = T.run
CLIENT_WAIT = 15.0     # the push, the iframe, the redirect to the fake client

# -- what the page shows, as JavaScript expressions ---------------------------------------------

FRAME = "document.getElementById('webconf-frame')"
WINDOW = "document.querySelector('#webconf-layer .terminal-window.webconf')"
WINDOW_SHOWN = f"(() => {{ const w = {WINDOW}; return !!w && !w.hidden; }})()"
FRAME_SHOWN = f"(() => {{ const f = {FRAME}; return !!f && getComputedStyle(f).visibility !== 'hidden'; }})()"
FRAME_HIDDEN = f"(() => {{ const f = {FRAME}; return !!f && getComputedStyle(f).visibility === 'hidden'; }})()"
NO_FRAME = f"{FRAME} === null"
FRAME_SRC = f"(() => {{ const f = {FRAME}; return f ? f.getAttribute('src') : null; }})()"
# the rects of the iframe and of the slots it may cover, in page coordinates
RECTS = """(() => { const rect = (e) => { if (!e) { return null; } const r = e.getBoundingClientRect();
    return {x: r.left, y: r.top, w: r.width, h: r.height}; };
  return {frame: rect(document.getElementById('webconf-frame')),
          slot: rect(document.querySelector('#webconf-layer .terminal-window.webconf .webconf-slot')),
          tabSlot: rect(document.querySelector('.pane.webconf .webconf-slot')),
          window: rect(document.querySelector('#webconf-layer .terminal-window.webconf')),
          viewport: {w: window.innerWidth, h: window.innerHeight}}; })()"""
TABBAR_SHOWN = "!document.getElementById('tabbar').hidden && document.querySelectorAll('#tabbar [role=tab]').length > 0"
SELECTED_TAB = "(document.querySelector('#tabbar [role=tab][aria-selected=\"true\"]') || {dataset: {}}).dataset.tab || ''"
WEBCONF_TAB = "document.querySelector('#tabbar [data-tab=\"webconf\"]') !== null"
FULL = "document.body.classList.contains('has-webconf-full')"
PILL = "document.getElementById('webconf-pill')"
PILL_TEXT = f"(() => {{ const p = {PILL}; return p ? p.textContent : ''; }})()"
ELSEWHERE = f"(() => {{ const p = {PILL}; return !!p && p.classList.contains('elsewhere'); }})()"
STORED = "window.localStorage.getItem('sreweb.webconf')"
TOASTS = "[...document.querySelectorAll('#toasts .toast')].map((t) => t.textContent)"
LOGGED_IN = "document.body.dataset.login === 'alice'"


def same_rect(a, b, tolerance=2) -> bool:
    return bool(a and b) and all(abs(a[k] - b[k]) <= tolerance for k in ('x', 'y', 'w', 'h'))


@contextlib.asynccontextmanager
async def browsing(tmp_path, *identities):
    """The fake BBB server, the harness (proxy mode, the real pages, [bbb] on the fake), one
    identity proxy per identity and the browser: (h, fake, browser, {login: url}).  The proxies
    are started first: the URL of the first one is the public_url of the portal, since the
    logoutURL of the meetings must be on the origin of the page holding the client."""
    fake = await FakeBbbServer().start()
    proxies = [IdentityProxy('http://127.0.0.1:1', headers) for headers in identities]
    try:
        urls = {}
        for headers, proxy in zip(identities, proxies):
            urls[headers['X-Remote-User']] = await proxy.start()
        h = P.Harness(tmp_path, auth_mode='proxy', host_over={'max_projects': 6}, web_over={
            **P.PROXY_OVER, 'public_url': urls[identities[0]['X-Remote-User']],
            'bbb': {'url': fake.url, 'secret': fake.secret, 'poll_interval': '0.5s'}})
        h.web_dir = WEB
        async with h:
            for proxy in proxies:
                proxy.target = f'http://127.0.0.1:{h.client.port}'
            async with Browser(CHROME) as browser:
                yield h, fake, browser, urls
    finally:
        for proxy in proxies:
            await proxy.close()
        await fake.close()


async def create_room(h, audience, name='Salle TP') -> dict:
    resp = await h.client.post('/api/webconfs', json={'name': name, 'audience': audience}, headers={**PROF, **P.CSRF})
    assert resp.status == 201, await resp.text()
    return await resp.json()


async def until(check, timeout: float, what: str):
    deadline = time.monotonic() + timeout
    while True:
        value = await check() if asyncio.iscoroutinefunction(check) else check()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"timeout waiting for {what}: last value {value!r}")
        await asyncio.sleep(0.25)


def no_errors(page):
    assert page.errors == [], page.errors


class TestWebconfInTheBrowser:
    def test_window_tab_full_leave_and_end(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, ALICE) as (h, fake, browser, urls):
                rln = await T.start_project(h, ALICE)
                page = await browser.page(f"{urls['alice']}/projects")
                await page.wait_for(LOGGED_IN, what="the Projects page of alice")
                room = await create_room(h, {'logins': ['alice']})
                # the window over the page, the iframe over its body, the client joined on the server
                await page.wait_for(WINDOW_SHOWN, timeout=CLIENT_WAIT, what="the floating window of the conference")
                await page.wait_for(FRAME_SHOWN, timeout=CLIENT_WAIT, what="the iframe of the client")
                assert (await page.evaluate(FRAME_SRC)).startswith('/api/webconfs/')
                rects = await page.evaluate(RECTS)
                assert same_rect(rects['frame'], rects['slot']), rects
                assert rects['window']['x'] >= 0 and rects['window']['x'] + rects['window']['w'] <= rects['viewport']['w'] + 1, rects
                meeting = fake.meetings[room['meeting_id']]
                await until(lambda: any(a['user_id'] == 'alice' for a in meeting.attendees), CLIENT_WAIT,
                            "the join of alice on the fake server")
                # dragged by its title bar: the frame follows
                x0, y0 = rects['window']['x'] + 60, rects['window']['y'] + 10
                await page.drag(x0, y0, x0 - 150, y0 - 90)
                moved = await page.evaluate(RECTS)
                assert abs(moved['window']['x'] - (rects['window']['x'] - 150)) <= 2, (rects, moved)
                assert abs(moved['window']['y'] - (rects['window']['y'] - 90)) <= 2, (rects, moved)
                assert same_rect(moved['frame'], moved['slot']), moved
                # minimized: the title bar alone, the iframe hidden but kept; restored
                await page.click('.terminal-window.webconf button.minimize')
                await page.wait_for(FRAME_HIDDEN, what="the iframe hidden while minimized")
                small = await page.evaluate(RECTS)
                assert small['window']['h'] < 40 and small['frame'] is not None, small
                await page.click('.terminal-window.webconf button.minimize')
                await page.wait_for(FRAME_SHOWN, what="the iframe shown again")
                assert same_rect((await page.evaluate(RECTS))['window'], moved['window'], 3)
                # the project page: the window back at its place (localStorage), the Webconf tab listed
                await page.goto(f"{urls['alice']}/projects/a01/{quote(rln, safe='')}")
                await page.wait_for(TABBAR_SHOWN, what="the tab bar of the project page")
                await page.wait_for(FRAME_SHOWN, timeout=CLIENT_WAIT, what="the window on the project page")
                again = await page.evaluate(RECTS)
                assert same_rect(again['window'], moved['window'], 3), (again, moved)
                await page.wait_for(WEBCONF_TAB, what="the Webconf tab")
                # docked: the Webconf tab selected, the frame over its slot; another tab hides it, alive
                await page.click('.terminal-window.webconf button.dock')
                await page.wait_for(f"{SELECTED_TAB} === 'webconf'", what="the Webconf tab selected")
                await page.wait_for(FRAME_SHOWN, what="the frame in the tab")
                docked = await page.evaluate(RECTS)
                assert same_rect(docked['frame'], docked['tabSlot']), docked
                assert not await page.evaluate(WINDOW_SHOWN)
                await page.click('#tabbar [data-tab="machines"]')
                await page.wait_for(FRAME_HIDDEN, what="the frame hidden under another tab")
                assert not await page.evaluate(NO_FRAME)
                await page.click('#tabbar [data-tab="webconf"]')
                await page.wait_for(FRAME_SHOWN, what="the frame back with its tab")
                # full page, then a window again
                await page.click('.pane.webconf .ctrl-bar button[title="Full screen"]')
                await page.wait_for(FULL, what="the full mode")
                full = await page.evaluate(RECTS)
                assert full['frame']['y'] == 32 and abs(full['frame']['w'] - full['viewport']['w']) <= 1, full
                assert abs(full['frame']['h'] - (full['viewport']['h'] - 32)) <= 1, full
                await page.click('.webconf-fullbar button[title="Back to a window"]')
                await page.wait_for(WINDOW_SHOWN, what="the window again")
                assert not await page.evaluate(FULL)
                # the client's own Leave meeting (the link of the fake client fills the frame): the pill
                rects = await page.evaluate(RECTS)
                await page.click_at(rects['frame']['x'] + rects['frame']['w'] / 2, rects['frame']['y'] + rects['frame']['h'] / 2)
                await page.wait_for(f"{PILL} !== null && {NO_FRAME}", timeout=CLIENT_WAIT, what="the pill after Leave meeting")
                assert 'Salle TP' in await page.evaluate(PILL_TEXT)
                assert '"mode":"left"' in (await page.evaluate(STORED) or '')
                # rejoined from the pill; the window survives a reload
                await page.click('#webconf-pill button')
                await page.wait_for(FRAME_SHOWN, timeout=CLIENT_WAIT, what="the client rejoined")
                await page.goto(f"{urls['alice']}/projects")
                await page.wait_for(FRAME_SHOWN, timeout=CLIENT_WAIT, what="the window after a reload")
                assert await page.evaluate(WINDOW_SHOWN)
                # ended by the instructor: everything gone, the storage cleared, a toast
                resp = await h.client.delete(f"/api/webconfs/{room['id']}", headers={**PROF, **P.CSRF})
                assert resp.status == 200
                await page.wait_for(f"{NO_FRAME} && {WINDOW} === null && {PILL} === null", what="the conference gone")
                assert await page.evaluate(STORED) is None
                assert any('has ended' in t for t in await page.evaluate(TOASTS))
                no_errors(page)
        run(scenario())

    def test_a_second_tab_shows_a_pill_and_takes_the_client_over(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, ALICE) as (h, fake, browser, urls):
                first = await browser.page(f"{urls['alice']}/projects")
                await first.wait_for(LOGGED_IN, what="the first page")
                room = await create_room(h, {'logins': ['alice']})
                await first.wait_for(FRAME_SHOWN, timeout=CLIENT_WAIT, what="the client on the first tab")
                second = await browser.page(f"{urls['alice']}/projects")
                await second.wait_for(ELSEWHERE, timeout=CLIENT_WAIT, what="the pill of the second tab")
                assert await second.evaluate(NO_FRAME) and await first.evaluate(FRAME_SHOWN)
                await second.click('#webconf-pill button')
                await second.wait_for(FRAME_SHOWN, timeout=CLIENT_WAIT, what="the client taken by the second tab")
                await first.wait_for(f"{NO_FRAME} && {ELSEWHERE}", what="the first tab handing the client over")
                resp = await h.client.delete(f"/api/webconfs/{room['id']}", headers={**PROF, **P.CSRF})
                assert resp.status == 200
                await second.wait_for(NO_FRAME, what="the conference gone")
                await first.wait_for(f"{PILL} === null", what="the pill gone")
                no_errors(first)
                no_errors(second)
        run(scenario())


# ---------------------------------------------------------------------------------------------
# the private conversations
# ---------------------------------------------------------------------------------------------

BANNER = "document.getElementById('webconf-invite')"
BANNER_TEXT = f"(() => {{ const b = {BANNER}; return b ? b.querySelector('.text').textContent : ''; }})()"
NO_BANNER = f"{BANNER} === null"
MARKED = "document.title.startsWith('☎ ')"
# the Talk privately button of the helper view: its state once project.js showed it
TALK_STATE = ("(() => { const b = document.getElementById('talk-student'); "
              "return b && !b.hidden && !b.disabled ? b.dataset.state || '' : null; })()")
WINDOW_TITLE = ("(() => { const t = document.querySelector('#webconf-layer .terminal-window.webconf "
                ".terminal-window-title .title'); return t ? t.textContent : ''; })()")
PRIVATE_WINDOW = "document.querySelector('#webconf-layer .terminal-window.webconf.private-room') !== null"


async def invite(h, login: str, tab: str = '') -> dict:
    resp = await h.client.post('/api/webconfs/invitations', json={'login': login, 'tab': tab}, headers={**PROF, **P.CSRF})
    assert resp.status == 201, await resp.text()
    return await resp.json()


async def rooms(h) -> dict:
    """The rooms of the portal by kind (one of each at most in these tests)."""
    listed = await (await h.client.get('/api/webconfs', headers=PROF)).json()
    return {room['kind']: room for room in listed}


def shows(room: dict) -> str:
    """The page shows the client of *room*: its iframe, visible, on the join of that room."""
    return f"{FRAME_SHOWN} && {FRAME_SRC} === '/api/webconfs/{room['id']}/join'"


class TestPrivateConversationInTheBrowser:
    def test_invitation_switch_and_return(self, tmp_path):
        """An instructor on a student's project: Talk privately, the banner of the student
        (taken back, declined, accepted), both conferences windows switched to the private room
        at the place of the class conference, which comes back there when the conversation ends
        (the ✕ of the instructor, then the client's own Leave of the student)."""
        async def scenario():
            async with browsing(tmp_path, ALICE, PROF) as (h, fake, browser, urls):
                rln = await T.start_project(h, ALICE)
                student = await browser.page(f"{urls['alice']}/projects")
                await student.wait_for(LOGGED_IN, what="the Projects page of alice")
                teacher = await browser.page(f"{urls['prof']}/projects/a01/{quote(rln, safe='')}", new_window=True)
                await teacher.wait_for(TABBAR_SHOWN, what="the project of alice on the instructor's page")
                await teacher.wait_for(f"{TALK_STATE} === 'idle'", what="the Talk privately button")
                # the class conference on both pages; the student's window moved somewhere
                room = await create_room(h, {'logins': ['alice']})
                await student.wait_for(shows(room), timeout=CLIENT_WAIT, what="the class conference of alice")
                await teacher.wait_for(shows(room), timeout=CLIENT_WAIT, what="the class conference of the instructor")
                rects = await student.evaluate(RECTS)
                x0, y0 = rects['window']['x'] + 60, rects['window']['y'] + 10
                await student.drag(x0, y0, x0 - 200, y0 - 120)
                place = (await student.evaluate(RECTS))['window']
                assert abs(place['x'] - (rects['window']['x'] - 200)) <= 2, (rects, place)
                # asked, then taken back: the banner comes and goes, the conference untouched
                await teacher.click('#talk-student')
                await teacher.wait_for(f"{TALK_STATE} === 'inviting'", what="the button while calling")
                await student.wait_for(f"{BANNER} !== null", what="the banner of the invitation")
                assert 'Pr. Of' in await student.evaluate(BANNER_TEXT) and await student.evaluate(MARKED)
                assert await student.evaluate(shows(room)) and len(fake.meetings) == 1
                await teacher.click('#talk-student')
                await student.wait_for(NO_BANNER, what="the banner gone after the cancel")
                await teacher.wait_for(f"{TALK_STATE} === 'idle'", what="the button idle again")
                assert not await student.evaluate(MARKED)
                assert any('no longer calling' in t for t in await student.evaluate(TOASTS))
                # asked again, declined
                await teacher.click('#talk-student')
                await student.wait_for(f"{BANNER} !== null", what="the second banner")
                await student.click('#webconf-invite button:not(.primary)')
                await student.wait_for(NO_BANNER, what="the banner gone after Not now")
                await teacher.wait_for(f"{TALK_STATE} === 'idle'", what="the button idle after the refusal")
                assert any('declined' in t for t in await teacher.evaluate(TOASTS))
                assert await student.evaluate(shows(room)) and await teacher.evaluate(shows(room))
                # asked again, accepted: both pages leave the class conference for the private room
                await teacher.click('#talk-student')
                await student.wait_for(f"{BANNER} !== null", what="the third banner")
                await student.click('#webconf-invite button.primary')
                private = await until(functools.partial(_private, h), CLIENT_WAIT, "the private room")
                for page, who, other in ((student, 'alice', 'Pr. Of'), (teacher, 'the instructor', 'Alice A')):
                    await page.wait_for(f"{PRIVATE_WINDOW} && {shows(private)}", timeout=CLIENT_WAIT,
                                        what=f"the private room on the page of {who}")
                    assert await page.evaluate(WINDOW_TITLE) == f'Private — {other}'
                    assert await page.evaluate("document.querySelectorAll('iframe#webconf-frame').length") == 1
                    assert not any('has ended' in t for t in await page.evaluate(TOASTS))
                assert await student.evaluate(NO_BANNER)
                await teacher.wait_for(f"{TALK_STATE} === 'active'", what="the button while talking")
                await until(lambda: {a['user_id'] for a in fake.meetings[private['meeting_id']].attendees} == {'alice', 'prof'},
                            CLIENT_WAIT, "both joined on the fake server")
                assert same_rect((await student.evaluate(RECTS))['window'], place, 3)       # where the class window was
                stored = await student.evaluate(STORED)
                assert '"kind":"private"' in stored and f'"back":{{"id":"{room["id"]}"' in stored
                # ended by the instructor's ✕: the class conference back on both, at its place
                await teacher.click('.terminal-window.webconf button.close')
                for page in (student, teacher):
                    await page.wait_for(f"!({PRIVATE_WINDOW}) && {shows(room)}", timeout=CLIENT_WAIT,
                                        what="the class conference back")
                    assert any('private conversation' in t for t in await page.evaluate(TOASTS))
                assert same_rect((await student.evaluate(RECTS))['window'], place, 3)
                await teacher.wait_for(f"{TALK_STATE} === 'idle'", what="the button idle after the end")
                assert private['meeting_id'] not in fake.meetings and room['meeting_id'] in fake.meetings
                assert '"kind"' not in await student.evaluate(STORED)
                # again, ended by the student through the client's own Leave (the link fills the frame)
                await teacher.click('#talk-student')
                await student.wait_for(f"{BANNER} !== null", what="the fourth banner")
                await student.click('#webconf-invite button.primary')
                await student.wait_for(PRIVATE_WINDOW, timeout=CLIENT_WAIT, what="the second conversation")
                second = await until(functools.partial(_private, h), CLIENT_WAIT, "the second private room")
                await student.wait_for(shows(second), timeout=CLIENT_WAIT, what="the client of the second conversation")
                rects = await student.evaluate(RECTS)
                await student.click_at(rects['frame']['x'] + rects['frame']['w'] / 2, rects['frame']['y'] + rects['frame']['h'] / 2)
                for page in (student, teacher):
                    await page.wait_for(f"!({PRIVATE_WINDOW}) && {shows(room)}", timeout=CLIENT_WAIT,
                                        what="the class conference back after Leave")
                assert await student.evaluate(f"{PILL} === null")             # ended, not "left"
                no_errors(student)
                no_errors(teacher)
        run(scenario())

    def test_two_tabs_of_the_student_hold_one_client(self, tmp_path):
        """Two tabs told of a room at the same moment: one loads the client, the other shows the
        pill.  The tab where Join was clicked shows the private room, whichever held the class
        conference, and keeps the class conference afterwards."""
        async def scenario():
            async with browsing(tmp_path, ALICE) as (h, fake, browser, urls):
                first = await browser.page(f"{urls['alice']}/projects")
                second = await browser.page(f"{urls['alice']}/open")
                for page in (first, second):
                    await page.wait_for(LOGGED_IN, what="a page of alice")
                ws_prof = await h.client.ws_connect('/api/presence/ws?page=/watch', headers=PROF)   # the instructor is on the site
                room = await create_room(h, {'logins': ['alice']})

                async def settled(target: dict):
                    """(the page showing the client of *target*, the other one with the pill)."""
                    states = [(await page.evaluate(shows(target)), await page.evaluate(f"{NO_FRAME} && {ELSEWHERE}"))
                              for page in (first, second)]
                    if states == [(True, False), (False, True)]:
                        return first, second
                    if states == [(False, True), (True, False)]:
                        return second, first
                    return None
                holder, other = await until(functools.partial(settled, room), CLIENT_WAIT, "one tab with the class conference")
                await asyncio.sleep(0.6)                              # past the claim delay: still one client
                assert await settled(room) == (holder, other)
                # invited: the banner on both tabs; Join in the tab that does not hold the conference
                await invite(h, 'alice')
                for page in (first, second):
                    await page.wait_for(f"{BANNER} !== null", what="the banner on each tab")
                await other.click('#webconf-invite button.primary')
                private = await until(functools.partial(_private, h), CLIENT_WAIT, "the private room")
                assert await until(functools.partial(settled, private), CLIENT_WAIT, "the private room in the tab of the click") == (other, holder)
                for page in (first, second):
                    assert await page.evaluate(NO_BANNER)
                assert [a['user_id'] for a in fake.meetings[private['meeting_id']].attendees] == ['alice']    # joined once
                # the conversation ended by the instructor: the class conference in the tab that had the conversation
                resp = await h.client.post(f"/api/webconfs/{private['id']}/leave", json={}, headers={**PROF, **P.CSRF})
                assert resp.status == 200
                assert await until(functools.partial(settled, room), CLIENT_WAIT, "the class conference back in one tab") == (other, holder)
                await asyncio.sleep(0.6)
                assert await settled(room) == (other, holder)
                await ws_prof.close()
                no_errors(first)
                no_errors(second)
        run(scenario())


async def _private(h) -> dict | None:
    return (await rooms(h)).get('private')
