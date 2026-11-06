"""The Open page of the web front-end in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``): the project mode of the instructors (Standard / Instructor mode / Debug mode; the
students have none), the lab tree listing every lab of the host in debug mode and the student
catalog otherwise, the selection kept across the reload while the lab is still listed, and a
debug project started from the page."""
import contextlib
import json
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
ALICE = P.who('alice', 'Alice A', group='INFO1')
PROF = P.who('prof', groups=P.TEACHERS)
DHCP, EXAM_ONLY = 'sre/dhcp.py', 'sre/_EXAM_/exam1.py'       # the catalog of the fake sre, and its exam-only lab

# -- what the page shows, as JavaScript expressions ---------------------------------------------

LABS = "[...document.querySelectorAll('#labs button.lab')].map((b) => b.title)"
MODES = "[...document.querySelectorAll('input[name=\"mode\"]')].map((r) => r.value)"
MODE = "(document.querySelector('input[name=\"mode\"]:checked') || {value: ''}).value"
SELECTED = "document.getElementById('selected-lab').textContent"
HIGHLIGHTED = "[...document.querySelectorAll('#labs button.lab[aria-selected=\"true\"]')].map((b) => b.title)"
START_DISABLED = "document.getElementById('start-button').disabled"
ON_PROJECT_PAGE = "window.location.pathname.startsWith('/projects/a01/')"


def lab_button(name: str) -> str:
    return f'#labs button.lab[title="{name}"]'


def has_lab(name: str) -> str:
    return f"document.querySelector({json.dumps(lab_button(name))}) !== null"


@contextlib.asynccontextmanager
async def browser_of(tmp_path, identity):
    """The harness (proxy mode, the real web directory), the identity proxy making the browser
    *identity*, and the browser: ``(h, browser, url)``."""
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER)
    h.web_dir = WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', identity)
        await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield h, browser, proxy.url
        finally:
            await proxy.close()


class TestOpenPage:
    def test_students_have_no_project_mode(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(MODES) == []
                assert EXAM_ONLY not in await page.evaluate(LABS)
        P.run(go())

    def test_debug_mode_lists_every_lab_and_keeps_the_selection(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, PROF) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(MODES) == ['standard', 'instructor', 'debug']
                assert await page.evaluate(MODE) == 'standard'
                labs = await page.evaluate(LABS)
                assert DHCP in labs and EXAM_ONLY not in labs
                # a lab selected, then the debug mode: the exam-only lab appears, the selection stays
                await page.click(lab_button(DHCP))
                assert await page.evaluate(SELECTED) == DHCP and not await page.evaluate(START_DISABLED)
                await page.click('#mode-debug')
                await page.wait_for(has_lab(EXAM_ONLY), what="the exam-only lab in debug mode")
                assert await page.evaluate(SELECTED) == DHCP and await page.evaluate(HIGHLIGHTED) == [DHCP]
                assert not await page.evaluate(START_DISABLED)
                # the instructor mode: the student catalog again, the lab selected still listed
                await page.click('#mode-instructor')
                await page.wait_for(f"!({has_lab(EXAM_ONLY)})", what="the student catalog in instructor mode")
                assert await page.evaluate(SELECTED) == DHCP and await page.evaluate(HIGHLIGHTED) == [DHCP]
                # an exam-only lab selected in debug mode is dropped by a mode that does not list it
                await page.click('#mode-debug')
                await page.wait_for(has_lab(EXAM_ONLY), what="the exam-only lab again")
                await page.click(lab_button(EXAM_ONLY))
                assert await page.evaluate(SELECTED) == EXAM_ONLY
                await page.click('#mode-standard')
                await page.wait_for(f"!({has_lab(EXAM_ONLY)})", what="the student catalog in standard mode")
                assert await page.evaluate(SELECTED) == '' and await page.evaluate(HIGHLIGHTED) == []
                assert await page.evaluate(START_DISABLED)
                # a debug project of the exam-only lab started from the page: sre start --debug-web-project
                await page.click('#mode-debug')
                await page.wait_for(has_lab(EXAM_ONLY), what="the exam-only lab once more")
                await page.click(lab_button(EXAM_ONLY))
                await page.click('#start-button')
                await page.wait_for(ON_PROJECT_PAGE, timeout=20.0, what="the page of the new project")
                rows = await (await h.client.get('/api/projects', headers=PROF)).json()
                assert [(r['lab_name'], r['debug_project'], r['instructor_mode']) for r in rows] == \
                    [('sre@_EXAM_@exam1.py', True, False)]      # the debug marker, the lab name of the catalog
        P.run(go())
