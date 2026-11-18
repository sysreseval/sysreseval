"""The Pool page of the instructors in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``): a host the configuration disables is enabled with its button and is still enabled on
the page of a portal started again on the same state file; a state file that cannot be written
is said in red in the status line, for as long as it lasts; the Priority column, the dialog that
changes the priority of a host or of the selected hosts, the column sorted, the priorities back
after a restart."""
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
# the priorities: the button of a row's cell, the dialog and its field, the rows in the order shown
DIALOG = "document.querySelector('dialog.pool-priority')"
DIALOG_OPEN = f"Boolean({DIALOG} && {DIALOG}.open)"
DIALOG_TITLE = f"{DIALOG}.querySelector('h2').textContent"
FIELD = f"{DIALOG}.querySelector('input[type=\"number\"]')"
FIELD_FOCUSED = f"document.activeElement === {FIELD}"
ORDER = "Array.from(document.querySelectorAll('#pool tbody tr[data-host]')).map((tr) => tr.dataset.host).join(' ')"
BULK = '#pool-selection button[data-action="priority"]'
BULK_DISABLED = f"document.querySelector('{BULK}').disabled"
RENDER = "document.getElementById('pool-filter').dispatchEvent(new Event('input'))"   # the table drawn again, as a poll does
# per row, [the first cell is tinted, the State cell is tinted, the State cell has a colour]: every
# other row of the table is lightly tinted, the State cell too, over its colour
STRIPES = ("[...document.querySelectorAll('#pool tbody tr[data-host]')].map((tr) => { "
           "const first = getComputedStyle(tr.children[0]), state = getComputedStyle(tr.querySelector('td.state')); "
           "return [first.backgroundImage !== 'none', state.backgroundImage !== 'none', "
           "state.backgroundColor !== 'rgba(0, 0, 0, 0)']; })")


def cell(name: str) -> str:
    """The selector of the button of the Priority cell of host *name*."""
    return f'#pool tbody tr[data-host="{name}"] td.priority button'


def shown(name: str) -> str:
    """The priority the row of host *name* shows, as a JavaScript expression ('' without row)."""
    return f"(document.querySelector('{cell(name)}') || {{textContent: ''}}).textContent"


@contextlib.asynccontextmanager
async def browser_of(tmp_path, state, host_over=None):
    """The harness (proxy mode, the real web directory, its only host disabled by the
    configuration unless *host_over* says otherwise, the state file *state*), the identity proxy
    making the browser the instructor, and the browser: ``(h, browser, url)``."""
    over = {**P.PROXY_OVER, 'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL}
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over,
                  host_over={'enabled': False} if host_over is None else host_over)
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

    def test_priority_of_a_host_and_of_the_selection(self, tmp_path):
        """The Priority cell opens a dialog that survives the table being drawn again; the
        value typed is saved by the portal and shown; the column sorts; Priority… of the bar
        sets one value on every selected host; a portal started again shows them."""
        state = tmp_path / 'state' / 'pool.json'
        token = {'Authorization': f'Bearer {ADMIN}'}

        async def set_in_dialog(page, value: str):
            await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog, its field focused")
            await page.insert_text(value)             # the field is selected: the text replaces what it showed
            await page.press_enter()
            await page.wait_for(f"{DIALOG} === null", what="the dialog closed")

        async def go():
            async with browser_of(tmp_path / 'first', state, host_over={'priority': 1}) as (h, browser, url):
                for name in ('b02', 'b03'):       # two more hosts, down: a priority is set on any host
                    body = {'name': name, 'url': 'http://127.0.0.1:9', 'token': P.TOKEN}
                    assert (await h.client.post('/api/pool/hosts', json=body, headers=token)).status == 201
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{shown('b03')} === '0'", what="the rows of the three hosts")
                assert await page.evaluate(shown('a01')) == '1' and await page.evaluate(shown('b02')) == '0'
                assert await page.evaluate(BULK_DISABLED) is True
                # every other row is lightly tinted, its State cell included, which keeps its colour
                assert await page.evaluate(ORDER) == 'a01 b02 b03'
                assert await page.evaluate(STRIPES) == [[False, False, True], [True, True, True], [False, False, True]]
                # the dialog of a row: the present value, kept open and focused when the table is drawn again
                await page.click(cell('a01'))
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of a01")
                assert 'a01' in await page.evaluate(DIALOG_TITLE) and await page.evaluate(f"{FIELD}.value") == '1'
                await page.evaluate(RENDER)
                assert await page.evaluate(f"{DIALOG_OPEN} && {FIELD_FOCUSED}") is True
                await set_in_dialog(page, '4')
                await page.wait_for(f"{shown('a01')} === '4'", what="the new priority of a01")
                assert json.loads(state.read_text())['priority'] == {'a01': {'value': 4, 'configured': 1}}
                # cancelled: nothing changes; a value out of the range is not taken
                await page.click(cell('b02'))
                await page.wait_for(DIALOG_OPEN, what="the dialog of b02")
                await page.click('dialog.pool-priority .buttons button[type="button"]')
                await page.wait_for(f"{DIALOG} === null", what="the dialog cancelled")
                await page.click(cell('b02'))
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of b02 again")
                await page.insert_text('10000')
                await page.press_enter()
                assert await page.evaluate(DIALOG_OPEN) is True and await page.evaluate(shown('b02')) == '0'
                await page.click('dialog.pool-priority .buttons button[type="button"]')
                await page.wait_for(f"{DIALOG} === null", what="the dialog cancelled again")
                assert h.portal.pool.runtime['b02'].priority == 0
                # a negative priority; the column sorted, the lowest first then the highest first
                await page.click(cell('b03'))
                await set_in_dialog(page, '-2')
                await page.wait_for(f"{shown('b03')} === '-2'", what="the new priority of b03")
                assert await page.evaluate(ORDER) == 'a01 b02 b03'                 # by name
                await page.click('#pool th[data-sort="priority"]')
                assert await page.evaluate(ORDER) == 'b03 b02 a01'
                await page.click('#pool th[data-sort="priority"]')
                assert await page.evaluate(ORDER) == 'a01 b02 b03'
                # the bar: no value shown first when the selected hosts differ, one value for all of them
                await page.click('#pool-select-all')
                assert await page.evaluate(BULK_DISABLED) is False
                await page.click(BULK)
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of the selection")
                assert '3' in await page.evaluate(DIALOG_TITLE) and await page.evaluate(f"{FIELD}.value") == ''
                await set_in_dialog(page, '7')
                await page.wait_for(' && '.join(f"{shown(name)} === '7'" for name in ('a01', 'b02', 'b03')),
                                    what="the priority of the three hosts")
                saved = json.loads(state.read_text())['priority']
                assert saved == {'a01': {'value': 7, 'configured': 1}, 'b02': {'value': 7, 'configured': 0},
                                 'b03': {'value': 7, 'configured': 0}}
                # the selection again: the value they share is shown first
                await page.click(BULK)
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of the selection again")
                assert await page.evaluate(f"{FIELD}.value") == '7'
                await page.click('dialog.pool-priority .buttons button[type="button"]')
                assert page.errors == []
            # the portal started again on the same configuration and state file
            async with browser_of(tmp_path / 'again', state, host_over={'priority': 1}) as (h, browser, url):
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{shown('b03')} === '7'", what="the rows of the three hosts")
                assert await page.evaluate(shown('a01')) == '7' and await page.evaluate(shown('b02')) == '7'
        P.run(go())
