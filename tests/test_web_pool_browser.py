"""The Pool page of the instructors in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``): a host the configuration disables is enabled with its button and is still enabled on
the page of a portal started again on the same state file; a state file that cannot be written
is said in red in the status line, for as long as it lasts."""
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
PROF = P.who('prof', 'Prof Essor', groups=P.TEACHERS)        # the instructor, the identity of the browser
ADMIN = 'a' * 32
QUIET_POOL = {'poll_interval': 0.1, 'min_hosts_up': 0, 'spare_projects': 0}   # no automatic wake
POLL = 15.0                                                   # the page polls the pool every 5 s

# -- what the page shows, as JavaScript expressions ---------------------------------------------

ROW = "document.querySelector('#pool tbody tr[data-host=\"a01\"]')"
STATE = f"({ROW} ? {ROW}.querySelector('td.state').textContent : '')"
ENABLE = '#pool tbody tr[data-host="a01"] td.actions button.ok'
STATUS = "document.getElementById('pool-status').textContent"
UNSAVED = "document.getElementById('pool-status').classList.contains('unsaved')"
STATUS_COLOR = "getComputedStyle(document.getElementById('pool-status')).color"
MUTED_COLOR = "getComputedStyle(document.getElementById('pool-count')).color"


@contextlib.asynccontextmanager
async def browser_of(tmp_path, state):
    """The harness (proxy mode, the real web directory, its only host disabled by the
    configuration, the state file *state*), the identity proxy making the browser the
    instructor, and the browser: ``(h, browser, url)``."""
    over = {**P.PROXY_OVER, 'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL}
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over, host_over={'enabled': False})
    h.web_dir = WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', PROF)
        await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield h, browser, proxy.url
        finally:
            await proxy.close()


class TestPoolPage:
    def test_enabled_host_kept_and_unsaved_state_told(self, tmp_path):
        state = tmp_path / 'state' / 'pool.json'

        async def go():
            async with browser_of(tmp_path / 'first', state) as (h, browser, url):
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{STATE} === 'disabled'", what="the host disabled by the configuration")
                assert await page.evaluate(UNSAVED) is False and 'NOT saved' not in await page.evaluate(STATUS)
                await page.click(ENABLE)
                await page.wait_for(f"{STATE} === 'up'", what="the host enabled")
                assert json.loads(state.read_text())['enabled'] == ['a01']
                # the state file cannot be written: the status line says it, in red, at the next poll
                h.portal.pool.state_error = 'Read-only file system'
                await page.wait_for(UNSAVED, timeout=POLL, what="the status line of an unsaved state")
                status = await page.evaluate(STATUS)
                assert 'the changes are NOT saved' in status and status.endswith('Read-only file system')
                assert await page.evaluate(STATUS_COLOR) != await page.evaluate(MUTED_COLOR)
                h.portal.pool.state_error = ''
                await page.wait_for(f"!{UNSAVED}", timeout=POLL, what="the status line of a saved state")
                assert 'NOT saved' not in await page.evaluate(STATUS)
            # the portal started again on the same configuration and state file: still enabled
            async with browser_of(tmp_path / 'again', state) as (h, browser, url):
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{ROW} !== null", what="the row of the host")
                assert await page.evaluate(STATE) == 'up'
        P.run(go())
