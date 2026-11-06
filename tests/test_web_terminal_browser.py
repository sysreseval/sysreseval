"""The floating terminal windows of the project page as a browser lives them: a headless Chrome
(``web_browser.py``; skipped without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one, and
without the vendored xterm.js of ``make xterm``) on the real pages of ``web/`` served by the
portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``, whose ``connect`` is a /bin/sh on a pty).  The Connect button of the Machines tab opens
a window over the page (the tab kept), what is typed in it reaches the shell, the window is
dragged by its title bar, docked into the Terminals tab and popped out again with the same shell
(the xterm survives its move in the DOM); the windows of a presenter float on the spectator's
page, read-only, at the same relative place, and follow a drag."""
import asyncio
import contextlib
import time
from pathlib import Path
from urllib.parse import quote

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
import test_web_presentation as T                             # noqa: E402  (start_project, present)
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
XTERM = WEB / 'static' / 'vendor' / 'xterm' / 'xterm.js'
pytestmark = [pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)"),
              pytest.mark.skipif(not XTERM.is_file(), reason="xterm.js is not vendored: run `make xterm`")]
ALICE = P.who('alice', 'Alice A', group='INFO1')
PROF = P.who('prof', 'Pr. Of', groups=P.TEACHERS)
run = T.run
SHELL_WAIT = 15.0     # the mock `sre connect`, the pty, the first prompt

# -- what the page shows, as JavaScript expressions ---------------------------------------------

TABBAR_SHOWN = "!document.getElementById('tabbar').hidden && document.querySelectorAll('#tabbar [role=tab]').length > 0"
ON_PROJECT_PAGE = "window.location.pathname.startsWith('/projects/a01/')"
SELECTED_TAB = "(document.querySelector('#tabbar [role=tab][aria-selected=\"true\"]') || {dataset: {}}).dataset.tab || ''"
WINDOWS = "document.querySelectorAll('#panes .terminal-windows .terminal-window').length"
SUBTABS = "document.querySelectorAll('.terminal-tabs [role=tab]').length"
WINDOW_STATUS = "(document.querySelector('.terminal-window .terminal-box .status span') || {textContent: ''}).textContent"
WINDOW_TEXT = "(document.querySelector('.terminal-window .xterm-rows') || {textContent: ''}).textContent"
HOST_TEXT = ("[...document.querySelectorAll('.terminal-host .terminal-box:not([hidden]) .xterm-rows')]"
             ".map((e) => e.textContent).join('\\n')")
# the rect of the (first) window relative to the panes, with the panes' size and the page coordinates
RECT = """(() => { const w = document.querySelector('.terminal-window'); const p = document.getElementById('panes');
  if (!w || !p) { return null; } const r = w.getBoundingClientRect(), a = p.getBoundingClientRect();
  return {x: r.left - a.left, y: r.top - a.top, w: r.width, h: r.height, aw: a.width, ah: a.height,
          left: r.left, top: r.top}; })()"""
def point_in(selector: str) -> str:
    """A point of the element at *selector* where a click reaches it: its centre, else a corner
    (a floating window may cover the centre of the terminal docked under it: it did on the Linux
    font metrics, where the dragged window of the second test hid the sub-tab's shell)."""
    return (f"(() => {{ const e = document.querySelector({selector!r}); if (!e) {{ return null; }} "
            f"const r = e.getBoundingClientRect(), d = 12; "
            f"const points = [[r.left + r.width / 2, r.top + r.height / 2], [r.left + d, r.top + d], "
            f"[r.right - d, r.top + d], [r.left + d, r.bottom - d], [r.right - d, r.bottom - d]]; "
            f"for (const [x, y] of points) {{ const at = document.elementFromPoint(x, y); "
            f"if (at && e.contains(at)) {{ return {{x, y}}; }} }} return null; }})()")
# the first open device of the "New terminal…" select (a sub-tab)
OPEN_SUBTAB = ("(() => { const s = document.querySelector('select.new-terminal:not(.new-window)'); "
               "const o = [...s.options].find((o) => o.value && !o.disabled); s.value = o.value; "
               "s.dispatchEvent(new Event('change')); return true; })()")
# the titles of the windows and of the sub-tabs
TITLES = ("({windows: [...document.querySelectorAll('.terminal-window .terminal-window-title .title')].map((e) => e.textContent), "
          "tabs: [...document.querySelectorAll('.terminal-tabs [role=tab]')].map((b) => b.firstChild.textContent)})")
# a spectator's page is in the iframe of the presentation overlay: the read-only window there
SPECTATOR_WINDOW = """(() => { const f = document.querySelector('#presentation-overlay iframe');
  if (!f || !f.contentDocument) { return null; } const d = f.contentDocument;
  const w = d.querySelector('.terminal-window.readonly'); const p = d.getElementById('panes');
  if (!w || !p) { return null; } const r = w.getBoundingClientRect(), a = p.getBoundingClientRect();
  return {x: (r.left - a.left) / a.width, y: (r.top - a.top) / a.height, w: r.width / a.width, h: r.height / a.height,
          status: (w.querySelector('.status span') || {textContent: ''}).textContent,
          buttons: w.querySelectorAll('.terminal-window-title button').length, windows: d.querySelectorAll('.terminal-window').length,
          subtabs: d.querySelectorAll('.terminal-tabs [role=tab]').length}; })()"""


@contextlib.asynccontextmanager
async def browsing(tmp_path, *identities):
    """The harness (proxy mode, the real web directory), one identity proxy per identity and the
    browser: ``(h, browser, {login: url})``."""
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER, host_over={'max_projects': 6})
    h.web_dir = WEB
    async with h:
        proxies = []
        try:
            urls = {}
            for headers in identities:
                proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', headers)
                await proxy.start()
                proxies.append(proxy)
                urls[headers['X-Remote-User']] = proxy.url
            async with Browser(CHROME) as browser:
                yield h, browser, urls
        finally:
            for proxy in proxies:
                await proxy.close()


async def project_page(browser, url, rln):
    page = await browser.page(f'{url}/projects/a01/{quote(rln, safe="")}')
    await page.wait_for(TABBAR_SHOWN, what="the tab bar of the project page")
    return page


def focused_in(selector: str) -> str:
    """Whether the keyboard focus is in the terminal box holding the element at *selector*."""
    return (f"(() => {{ const e = document.querySelector({selector!r}); const b = e && e.closest('.terminal-box'); "
            f"return !!(b && b.contains(document.activeElement)); }})()")


# every terminal of the page, for the message of a failed wait: where it is, its status, the
# keyboard focus, its rows and the text of its non-empty rows
TERMINALS = """(() => { const a = document.activeElement;
  const boxes = [...document.querySelectorAll('.terminal-box')].map((b) => ({
    where: b.closest('.terminal-window') ? 'window' : (b.closest('.terminal-host') ? 'host' : 'other'),
    hidden: b.hidden, status: (b.querySelector('.status span') || {textContent: ''}).textContent, focused: b.contains(a),
    rows: b.querySelectorAll('.xterm-rows > div').length,
    text: [...b.querySelectorAll('.xterm-rows > div')].map((r) => r.textContent.trimEnd()).filter((t) => t).join('|').slice(-300)}));
  return {active: a ? a.tagName + '.' + a.className : null, boxes}; })()"""


async def type_command(page, screen_selector: str, text_expression: str, command: str, output: str):
    """Click in the xterm at *screen_selector*, type *command* + Enter, wait for *output* in the
    text of the terminal (an output the command line itself does not contain).  The keystrokes go
    to the focused element and a terminal drops them while its socket is not open, so the click
    is checked to have given the focus to that terminal, again once the prompt of its shell has
    come (another terminal connecting meanwhile takes the focus), before anything is typed."""
    at = await page.wait_for(point_in(screen_selector), what=f"a visible point of the terminal {screen_selector}")
    for _ in range(2):
        await page.click_at(at['x'], at['y'])
        await page.wait_for(focused_in(screen_selector), what=f"the keyboard focus in the terminal {screen_selector}")
        await page.wait_for(f"({text_expression}).includes('$')", timeout=SHELL_WAIT, what="the prompt of the shell")
        if await page.evaluate(focused_in(screen_selector)):
            break
    await page.insert_text(command)
    await page.press_enter()
    try:
        await page.wait_for(f"({text_expression}).includes({output!r})", timeout=SHELL_WAIT, what=f"the output {output!r}")
    except AssertionError as e:
        raise AssertionError(f"{e}; the terminals: {await page.evaluate(TERMINALS)}") from None


async def until(check, timeout: float, what: str):
    deadline = time.monotonic() + timeout
    while True:
        value = await check()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"timeout waiting for {what}: last value {value!r}")
        await asyncio.sleep(0.25)


def no_errors(page):
    assert page.errors == [], page.errors


class TestFloatingTerminals:
    def test_connect_opens_a_window_dragged_docked_and_popped_out(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, ALICE) as (h, browser, urls):
                rln = await T.start_project(h, ALICE)
                page = await project_page(browser, urls['alice'], rln)
                await page.click('#tabbar [data-tab="machines"]')
                await page.click('.machines button.connect')
                # a window over the page, the Machines tab kept, no sub-tab
                assert await page.wait_for(f'{WINDOWS} === 1', what="one floating window") is True
                await page.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the terminal connected")
                assert await page.evaluate(SELECTED_TAB) == 'machines'
                assert await page.evaluate(SUBTABS) == 0
                rect = await page.evaluate(RECT)
                assert 0 <= rect['x'] and 0 <= rect['y'] and rect['x'] + rect['w'] <= rect['aw'] + 1 \
                    and rect['y'] + rect['h'] <= rect['ah'] + 1, rect
                # the shell answers what is typed in the window
                await type_command(page, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo flo$((1+1))ating', 'flo2ating')
                # dragged by its title bar
                x0, y0 = rect['left'] + rect['w'] / 2, rect['top'] + 10
                await page.drag(x0, y0, x0 + 150, y0 + 90)
                moved = await page.evaluate(RECT)
                assert abs(moved['x'] - rect['x'] - 150) <= 2 and abs(moved['y'] - rect['y'] - 90) <= 2, (rect, moved)
                assert moved['w'] == rect['w'] and moved['h'] == rect['h']
                # docked: the same shell in a sub-tab of the Terminals tab, shown
                await page.click('.terminal-window button.dock')
                assert await page.evaluate(WINDOWS) == 0
                assert await page.evaluate(SELECTED_TAB) == 'terminals'
                assert await page.evaluate(SUBTABS) == 1
                assert 'flo2ating' in await page.evaluate(HOST_TEXT)           # the screen survived the move
                await type_command(page, '.terminal-host .xterm-screen', HOST_TEXT, 'echo do$((2+2))cked', 'do4cked')
                # popped out again
                await page.click('.terminal-tabs .popout')
                assert await page.evaluate(WINDOWS) == 1
                assert await page.evaluate(SUBTABS) == 0
                await type_command(page, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo po$((3+3))pped', 'po6pped')
                assert 'do4cked' in await page.evaluate(WINDOW_TEXT)
                # closed by its ×: the session ends on the agent
                await page.click('.terminal-window button.close')
                assert await page.evaluate(WINDOWS) == 0
                await until(lambda: terminals_gone(h, rln), 10.0, "the session closed on the agent")
                no_errors(page)
        run(scenario())

    def test_terminals_come_back_after_leaving_the_page(self, tmp_path):
        """The agent keeps the sessions after the page left: back on the project, the window and
        the sub-tab are there, where they were, with their screens (nothing opened on top); the ×
        of each ends its session."""
        async def scenario():
            async with browsing(tmp_path, ALICE) as (h, browser, urls):
                rln = await T.start_project(h, ALICE)
                page = await project_page(browser, urls['alice'], rln)
                await page.click('#tabbar [data-tab="machines"]')
                await page.click('.machines button.connect')
                await page.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the window's terminal")
                await type_command(page, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo win$((1))dow', 'win1dow')
                rect = await page.evaluate(RECT)
                x0, y0 = rect['left'] + rect['w'] / 2, rect['top'] + 10
                await page.drag(x0, y0, x0 + 200, y0 + 120)
                before = await page.evaluate(RECT)
                # a sub-tab from the select of the Terminals tab
                await page.click('#tabbar [data-tab="terminals"]')
                await page.evaluate(OPEN_SUBTAB)
                await page.wait_for(f'{SUBTABS} === 1', what="one sub-tab")
                await type_command(page, '.terminal-host .xterm-screen', HOST_TEXT, 'echo sub$((1))tab', 'sub1tab')
                titles = await page.evaluate(TITLES)
                # away (the page goes to the browser's back/forward cache, its sockets closed by
                # the page itself), and back with the Back button: the same page, its sessions
                # joined again
                await page.goto(f"{urls['alice']}/projects")
                await until(lambda: lingering(h, rln, 2), 10.0, "both sessions kept on the agent")
                await page.evaluate('history.back(); true')
                await page.wait_for(f"{ON_PROJECT_PAGE} && {WINDOWS} === 1 && {SUBTABS} === 1", timeout=SHELL_WAIT,
                                    what="the page back from the cache")
                await page.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the window joined again")
                await until(lambda: attached(h, rln, 2), 10.0, "both sessions attached again")
                await type_command(page, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo ba$((1))ck', 'ba1ck')
                # away again, and back by a fresh load of the page: the terminals resumed from the
                # agent's list, where they were
                await page.goto(f"{urls['alice']}/projects")
                await until(lambda: lingering(h, rln, 2), 10.0, "both sessions kept on the agent again")
                await page.goto(f'{urls["alice"]}/projects/a01/{quote(rln, safe="")}')
                await page.wait_for(TABBAR_SHOWN, what="the tab bar")
                await page.wait_for(f'{WINDOWS} === 1 && {SUBTABS} === 1', timeout=SHELL_WAIT,
                                    what="the window and the sub-tab back")
                await page.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the window joined")
                assert await page.evaluate(TITLES) == titles
                after = await page.evaluate(RECT)
                for key, size in (('x', 'aw'), ('w', 'aw'), ('y', 'ah'), ('h', 'ah')):
                    assert abs(after[key] / after[size] - before[key] / before[size]) <= 0.02, (key, before, after)
                await page.wait_for(f"({WINDOW_TEXT}).includes('ba1ck')", timeout=SHELL_WAIT, what="the replay")
                await page.click('#tabbar [data-tab="terminals"]')
                assert await page.evaluate(SUBTABS) == 1                     # no terminal opened on top
                await page.wait_for(f"({HOST_TEXT}).includes('sub1tab')", timeout=SHELL_WAIT, what="the sub-tab's replay")
                sessions = await terminals_of(h, rln)
                assert len(sessions) == 2 and all(s['clients'] == 1 and not s['lingering'] for s in sessions), sessions
                await type_command(page, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo ba$((2))ck', 'ba2ck')
                # the × of each: the sessions end on the agent
                await page.click('.terminal-window button.close')
                await page.click('.terminal-tabs .close')
                await until(lambda: terminals_gone(h, rln), 10.0, "no session left on the agent")
                no_errors(page)
        run(scenario())

    def test_presenter_windows_float_on_the_spectator_page(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, PROF, ALICE) as (h, browser, urls):
                rln = await T.start_project(h, PROF)
                pres = await T.present(h, PROF, rln, ['alice'])        # before the page loads: resume()
                prof = await project_page(browser, urls['prof'], rln)
                alice = await browser.page(f"{urls['alice']}/projects")
                await alice.wait_for("document.querySelector('#presentation-overlay iframe') !== null", timeout=15.0,
                                     what="the presentation overlay on the student's page")
                await prof.click('#tabbar [data-tab="machines"]')
                await prof.click('.machines button.connect')
                await prof.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the presenter's terminal")
                # the view published carries the geometry of the window
                async def published():
                    resp = await h.client.get(f"/api/presentations/{pres['id']}", headers=PROF)
                    data = await resp.json()
                    open_ = ((data.get('view') or {}).get('terminals') or {}).get('open') or []
                    return open_[0].get('floating') if open_ and open_[0].get('floating') else None
                floating = await until(published, 10.0, "the floating geometry in the presenter's view")
                assert all(0 <= floating[k] <= 1 for k in ('x', 'y', 'w', 'h')) and floating['w'] > 0.2, floating
                rect = await prof.evaluate(RECT)
                assert abs(floating['w'] * rect['aw'] - rect['w']) <= 2 and abs(floating['x'] * rect['aw'] - rect['x']) <= 2
                # the spectator's read-only window at the same relative place, connected, no button
                async def mirrored():
                    seen = await alice.evaluate(SPECTATOR_WINDOW)
                    return seen if seen and seen['status'] == 'Connected.' else None
                seen = await until(mirrored, SHELL_WAIT, "the read-only window on the spectator's page")
                assert seen['buttons'] == 0 and seen['windows'] == 1 and seen['subtabs'] == 0, seen
                for key in ('x', 'y', 'w', 'h'):
                    assert abs(seen[key] - floating[key]) <= 0.02, (key, seen, floating)
                # a drag follows
                x0, y0 = rect['left'] + rect['w'] / 2, rect['top'] + 10
                await prof.drag(x0, y0, x0 + 120, y0 + 60)
                moved = await prof.evaluate(RECT)
                target = {'x': moved['x'] / moved['aw'], 'y': moved['y'] / moved['ah']}
                async def followed():
                    seen = await alice.evaluate(SPECTATOR_WINDOW)
                    return seen if seen and abs(seen['x'] - target['x']) <= 0.02 and abs(seen['y'] - target['y']) <= 0.02 else None
                await until(followed, 10.0, "the spectator's window following the drag")
                no_errors(prof)
                no_errors(alice)
        run(scenario())


async def terminals_of(h, rln) -> list:
    """The live sessions of the project as the agent lists them to the student."""
    resp = await h.client.get(f'/api/projects/a01/{quote(rln, safe="")}', headers=ALICE)
    data = await resp.json()
    return (data.get('terminals') or []) if resp.status == 200 else []


async def terminals_gone(h, rln) -> bool:
    return not await terminals_of(h, rln)


async def lingering(h, rln, n: int) -> bool:
    """Whether the project has exactly *n* sessions, all kept without a browser."""
    sessions = await terminals_of(h, rln)
    return len(sessions) == n and all(s.get('lingering') and s.get('clients') == 0 for s in sessions)


async def attached(h, rln, n: int) -> bool:
    """Whether the project has exactly *n* sessions, each with one browser typing in it."""
    sessions = await terminals_of(h, rln)
    return len(sessions) == n and all(not s.get('lingering') and s.get('clients') == 1 for s in sessions)
