"""The web front-end served under a sub-path (``base_path`` of web.toml) in a headless Chrome
(``web_browser.py``; skipped without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on
the real pages of ``web/``, the portal of test_web_portal.py mounted under ``/my-sre-server``
behind identity proxies that pass the paths as they come: what a student does from the Projects
page to a terminal of a project, the language and the logout, the Watch page of an instructor,
a focus and a presentation pushed to a student's page.  The identity proxy records every path
the browser asked for: nothing is fetched outside the sub-path."""
import asyncio
import contextlib
import json
from pathlib import Path
from urllib.parse import quote

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
XTERM = WEB / 'static' / 'vendor' / 'xterm' / 'xterm.js'
pytestmark = [pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)"),
              pytest.mark.skipif(not XTERM.is_file(), reason="xterm.js is not vendored: run `make xterm`")]

BASE = '/my-sre-server'
ALICE = P.who('alice', 'Alice A', group='INFO1')
BOB = P.who('bob', 'Bob B', group='INFO1')
PROF = P.who('prof', 'Pr. Of', groups=P.TEACHERS)
DHCP = 'sre/dhcp.py'                                          # a lab of the fake sre
SHELL_WAIT = 15.0                                             # the mock `sre connect`, the pty, the first prompt
LOGOUT_URL = '/apache-logout'                                 # a location of the reverse proxy, outside the site

# -- what the page shows, as JavaScript expressions ---------------------------------------------

PATH = "window.location.pathname"
LANG = "document.documentElement.lang"
LOGO_DRAWN = ("(() => { const i = document.querySelector('#no-project img'); "
              "return Boolean(i) && !document.getElementById('no-project').hidden && i.naturalWidth > 0; })()")
STYLED = "getComputedStyle(document.querySelector('header.topbar')).display === 'flex'"
TABBAR_SHOWN = "!document.getElementById('tabbar').hidden && document.querySelectorAll('#tabbar [role=tab]').length > 0"
WINDOW_STATUS = "(document.querySelector('.terminal-window .terminal-box .status span') || {textContent: ''}).textContent"
PDF_LINK = "document.getElementById('schema-pdf-link').getAttribute('href')"
CARD_LINKS = "[...document.querySelectorAll('#projects .card a.button.primary')].map((a) => a.getAttribute('href'))"
WATCH_LINKS = "[...document.querySelectorAll('#watch tbody a.button.primary')].map((a) => a.getAttribute('href'))"
LOGOUT_DIALOG = "document.getElementById('logout-dialog').open"
OVERLAY_SRC = "(document.querySelector('#presentation-overlay iframe') || {getAttribute: () => null}).getAttribute('src')"
# the page shown in the overlay, once it has drawn its tabs: the presentation it says it shows
OVERLAY_PAGE = """(() => { const f = document.querySelector('#presentation-overlay iframe'); const d = f && f.contentDocument;
  const bar = d && d.getElementById('tabbar');
  return bar && !bar.hidden && bar.querySelectorAll('[role=tab]').length > 0 ? d.body.dataset.presentation : null; })()"""


def choose_language(code: str) -> str:
    return (f"(() => {{ const s = document.getElementById('language-select'); s.value = {code!r}; "
            "s.dispatchEvent(new Event('change', {bubbles: true})); })()")


def lab_button(name: str) -> str:
    return f'#labs button.lab[title="{name}"]'


def project_path(rln: str) -> str:
    return f'{BASE}/projects/a01/{quote(rln, safe="")}'


@contextlib.asynccontextmanager
async def browsing(tmp_path, *identities):
    """The harness under ``BASE`` (proxy mode, the real web directory), one identity proxy per
    identity and the browser: ``(h, browser, {login: proxy})``; the site of a login is
    ``proxy.url + BASE``."""
    proxy_auth = {**P.PROXY_OVER['auth']['proxy'], 'logout_url': LOGOUT_URL}
    over = {**P.PROXY_OVER, 'auth': {'mode': 'proxy', 'proxy': proxy_auth}, 'base_path': BASE}
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over, host_over={'max_projects': 6})
    h.web_dir = WEB
    async with h:
        proxies = {}
        try:
            for headers in identities:
                proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', headers)
                await proxy.start()
                proxies[headers['X-Remote-User']] = proxy
            async with Browser(CHROME) as browser:
                yield h, browser, proxies
        finally:
            for proxy in proxies.values():
                await proxy.close()


async def start_project(h, headers) -> str:
    resp = await h.client.post(f'{BASE}/api/projects', json={'lab': DHCP}, headers={**headers, **P.CSRF})
    assert resp.status == 200, await resp.text()
    return [json.loads(line) for line in (await resp.text()).splitlines()][-1]['running_lab_name']


def outside(proxy) -> list:
    """The paths the browser asked for outside the sub-path."""
    return sorted({path for path in proxy.paths if not path.startswith(BASE + '/')})


class TestUnderASubPath:
    def test_a_student_from_the_projects_page_to_a_terminal(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, ALICE) as (h, browser, proxies):
                proxy = proxies['alice']
                site = proxy.url + BASE
                # the root of the site: the Projects page, with its style sheet, its script (the
                # empty page draws the logo once the list of projects came) and its catalog
                page = await browser.page(f'{site}/')
                await page.wait_for(LOGO_DRAWN, what="the logo of the empty Projects page")
                assert await page.evaluate(PATH) == f'{BASE}/projects' and await page.evaluate(STYLED)
                assert await page.evaluate(LANG) == 'en'
                assert f'{BASE}/i18n/en.json' in proxy.paths and f'{BASE}/api/projects' in proxy.paths
                # the Open page by its link, a lab started: the page of the new project
                await page.click('.topbar-nav a')
                await page.wait_for(f"document.querySelector({json.dumps(lab_button(DHCP))}) !== null", what="the lab tree")
                assert await page.evaluate(PATH) == f'{BASE}/open'
                await page.click(lab_button(DHCP))
                await page.click('#start-button')
                await page.wait_for(f"{PATH}.startsWith('{BASE}/projects/a01/')", timeout=20.0, what="the page of the new project")
                await page.wait_for(TABBAR_SHOWN, what="the tab bar of the project page")
                rows = await (await h.client.get(f'{BASE}/api/projects', headers=ALICE)).json()
                rln = rows[0]['running_lab_name']
                assert await page.evaluate(PATH) == project_path(rln)
                assert (await page.evaluate(PDF_LINK)).startswith(f'{BASE}/api/projects/a01/')
                # the page the browser reports is the one of the application
                pages = [socket.page for socket in h.portal.presence.sockets() if not socket.away]
                assert pages == [project_path(rln)[len(BASE):]]
                # a terminal: its WebSocket
                await page.click('#tabbar [data-tab="machines"]')
                await page.click('.machines button.connect')
                await page.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the terminal connected")
                assert any(path.startswith(f'{BASE}/api/projects/a01/') and '/terminals/' in path for path in proxy.paths)
                await page.click('.terminal-window button.close')
                # the language: the cookie of the site read again by the page loaded anew
                await page.evaluate(choose_language('fr'))
                await page.wait_for(f"{LANG} === 'fr'", what="the page in French")
                await page.wait_for(TABBAR_SHOWN, what="the tab bar of the project page again")
                assert f'{BASE}/i18n/fr.json' in proxy.paths
                # back to the projects by the brand: the card of the project links to its page
                await page.click('a.brand')
                await page.wait_for(f"{CARD_LINKS}.length === 1", what="the card of the project")
                assert await page.evaluate(PATH) == f'{BASE}/projects'
                assert await page.evaluate(CARD_LINKS) == [project_path(rln)]
                assert page.errors == [], page.errors
                assert outside(proxy) == []
                # the logout: the form is found (its dialog lists the project), then the browser
                # goes where the reverse proxy logs out, a location that is not of the site
                await page.click('form.inline button[type="submit"]')
                await page.wait_for(LOGOUT_DIALOG, what="the logout dialog")
                await page.click('#logout-keep')
                await page.wait_for(f"{PATH} === '{LOGOUT_URL}'", what="the logout location of the proxy")
                assert f'{BASE}/logout' in proxy.paths
                # that page is not ours: the browser may ask for its icon
                assert LOGOUT_URL in outside(proxy) and set(outside(proxy)) <= {LOGOUT_URL, '/favicon.ico'}
        P.run(scenario())

    def test_watch_focus_and_presentation(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, ALICE, BOB, PROF) as (h, browser, proxies):
                sites = {login: proxy.url + BASE for login, proxy in proxies.items()}
                rln = await start_project(h, ALICE)
                # the Watch page of the instructor: the Open link of the row
                watch = await browser.page(f"{sites['prof']}/watch")
                await watch.wait_for(f"{WATCH_LINKS}.length === 1", what="the row of the project")
                assert await watch.evaluate(WATCH_LINKS) == [project_path(rln)]
                # a focus brings the student's page to the project
                alice = await browser.page(f"{sites['alice']}/projects", new_window=True)
                await alice.wait_for(f"{CARD_LINKS}.length === 1", what="the card of the project")
                await until_connected(h, 'alice')
                resp = await h.client.post(f'{BASE}/api/focus', json={'host': 'a01', 'rln': rln, 'view': {}},
                                           headers={**PROF, **P.CSRF})
                assert resp.status == 201, await resp.text()
                await alice.wait_for(f"{PATH} === {project_path(rln)!r}", what="the student's page on the project")
                await alice.wait_for(TABBAR_SHOWN, what="the tab bar of the project page")
                # a presentation: the project in the overlay of a spectator's page
                bob = await browser.page(f"{sites['bob']}/projects", new_window=True)
                await bob.wait_for(LOGO_DRAWN, what="the empty Projects page of the spectator")
                await until_connected(h, 'bob')
                resp = await h.client.post(f'{BASE}/api/presentations', json={'host': 'a01', 'rln': rln, 'audience': ['bob']},
                                           headers={**PROF, **P.CSRF})
                assert resp.status == 201, await resp.text()
                pid = (await resp.json())['id']
                assert await bob.wait_for(OVERLAY_PAGE, timeout=20.0, what="the presented project in the overlay") == pid
                assert await bob.evaluate(OVERLAY_SRC) == f'{BASE}/present/{pid}'
                assert await bob.evaluate(PATH) == f'{BASE}/projects'
                for login, page in (('prof', watch), ('alice', alice), ('bob', bob)):
                    assert page.errors == [], (login, page.errors)
                    assert outside(proxies[login]) == [], login
        P.run(scenario())


async def until_connected(h, login: str, timeout: float = 10.0):
    """The presence socket of a page of *login* is open: a push reaches it."""
    async with asyncio.timeout(timeout):
        while login not in {socket.identity.login for socket in h.portal.presence.sockets()}:
            await asyncio.sleep(0.05)
