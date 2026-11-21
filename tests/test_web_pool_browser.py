"""The Pool page of the instructors in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``): a host the configuration disables is enabled with its button and is still enabled on
the page of a portal started again on the same state file; a state file that cannot be written
is said in red in the status line, for as long as it lasts; the Priority column (group:order), the
dialog that changes the two numbers of a host, or the group, the order or both of the selected
hosts, the column sorted, the priorities back after a restart; Enable cancelling a drain, from the row (in place of Drain) and from the bar, and
not once the power off of the host is sent; a drain the host asked for itself, its flag, Enable
cancelling it, the local drains forbidden and allowed from the bar; the CPU column (the cores the
projects of a host are counted for / those they may use); the costs of the labs are no longer on
this page (the Costs table… button of the Open page: test_web_open_browser.py)."""
import asyncio
import contextlib
import json
import os
import time
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
# the priorities: the button of a row's cell, the dialog and its two fields (the group, focused
# first, and the order), the rows in the order shown
DIALOG = "document.querySelector('dialog.pool-priority')"
DIALOG_OPEN = f"Boolean({DIALOG} && {DIALOG}.open)"
DIALOG_TITLE = f"{DIALOG}.querySelector('h2').textContent"
GROUP_FIELD = f"{DIALOG}.querySelector('input[name=\"group\"]')"
ORDER_FIELD = f"{DIALOG}.querySelector('input[name=\"order\"]')"
FIELD_FOCUSED = f"document.activeElement === {GROUP_FIELD}"
VALUES = f"[{GROUP_FIELD}.value, {ORDER_FIELD}.value]"
CANCEL = 'dialog.pool-priority .buttons button[type="button"]'
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


# the load of a host: the CPU cell of a01
CPU = f"({ROW} ? {ROW}.querySelector('td.cpu').textContent : null)"


def cell(name: str) -> str:
    """The selector of the button of the Priority cell of host *name*."""
    return f'#pool tbody tr[data-host="{name}"] td.priority button'


def shown(name: str) -> str:
    """The priority the row of host *name* shows, as a JavaScript expression ('' without row)."""
    return f"(document.querySelector('{cell(name)}') || {{textContent: ''}}).textContent"


# the drain: the buttons of the Actions cell of a01 (Enable / Disable, Wake, Drain, Power off), the
# checkbox of its row and the buttons of the bar
CHECKBOX = '#pool tbody tr[data-host="a01"] td.select input'
BAR_ENABLE = '#pool-selection button[data-action="enable"]'
BAR_DRAIN = '#pool-selection button[data-action="drain"]'
BAR_ALLOW = '#pool-selection button[data-action="allow-local-drain"]'
BAR_FORBID = '#pool-selection button[data-action="forbid-local-drain"]'
FLAGS = f"({ROW} ? {ROW}.querySelector('td.flags').textContent : null)"
FLAGS_TITLE = f"{ROW}.querySelector('td.flags').title"


def action(n: int) -> str:
    """The selector of the *n*-th button of the Actions cell of a01."""
    return f'#pool tbody tr[data-host="a01"] td.actions button:nth-child({n})'


def button(selector: str) -> str:
    """``[text, disabled, tooltip]`` of a button, as a JavaScript expression (null without it)."""
    return (f"(() => {{ const b = document.querySelector('{selector}'); "
            f"return b ? [b.textContent, b.disabled, b.title] : null; }})()")


def is_button(selector: str, text: str, *, disabled: bool = False, title: str = '') -> str:
    """Whether the button shows *text*, is *disabled* and has the tooltip *title*: a JavaScript
    expression to wait for."""
    wanted = json.dumps([text, disabled, title], separators=(',', ':'))
    return f"JSON.stringify({button(selector)}) === {json.dumps(wanted)}"


@contextlib.asynccontextmanager
async def browser_of(tmp_path, state, host_over=None, agent_over=None):
    """The harness (proxy mode, the real web directory, its only host disabled by the
    configuration unless *host_over* says otherwise, the state file *state*, *agent_over* in the
    agent.toml of its agent), the identity proxy making the browser the instructor, and the
    browser: ``(h, browser, url)``."""
    over = {**P.PROXY_OVER, 'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL}
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over, agent_over=agent_over,
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
    def test_cpu_of_the_host(self, tmp_path, monkeypatch):
        """The CPU cell of a host: the cores its projects are counted for / those they may use
        (its processors by ``cpu_target``).  The page lists no cost of a lab any more, and never
        asks them: they are the Costs table… button of the Open page."""
        from sreweb.agent import app as agent_app
        monkeypatch.setattr(agent_app, '_mem_available_mb', lambda path=None: 12000)
        monkeypatch.setattr(agent_app, '_mem_total_mb', lambda path=None: 16000)
        monkeypatch.setattr(agent_app.os, 'cpu_count', lambda: 8)
        asked = []

        async def go():
            async with browser_of(tmp_path, tmp_path / 'state' / 'pool.json', host_over={}) as (h, browser, url):
                pool = h.portal.pool
                costs_view = pool.costs_view
                pool.costs_view = lambda: (asked.append(1), costs_view())[1]
                pool.costs.declare([{'name': 'sre/dhcp.py', 'weight': 15}])
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{CPU} === '0.0 / 5.6'", what="the CPU cell of the host")    # 8 cores, 70 %
                assert await page.evaluate("document.querySelectorAll('table').length") == 1
                assert await page.evaluate("document.querySelector('#pool-costs-box, details') === null")
                assert 'sre/dhcp.py' not in await page.evaluate("document.body.textContent")
                assert asked == []                          # the page was polled once: it drew the CPU cell
        P.run(go())

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
        """The Priority cell (group:order) opens a dialog that survives the table being drawn
        again; the two numbers typed are saved by the portal and shown; the column sorts on the
        group, then the order; Priority… of the bar sets the group, the order or both on every
        selected host, each keeping the number left empty; a portal started again shows them."""
        state = tmp_path / 'state' / 'pool.json'
        token = {'Authorization': f'Bearer {ADMIN}'}

        async def fill(page, field: str, value: str):
            """*value* in a field of the dialog in place of what it shows ('' empties it)."""
            await page.evaluate(f"({field}.focus(), {field}.select())")
            if value:
                await page.insert_text(value)         # the field is selected: the text replaces what it showed
            else:
                await page.evaluate(f"({field}.value = '')")

        async def set_in_dialog(page, group, order):
            """The group and the order typed in the open dialog (None: the field as it is), then Enter."""
            await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog, its first field focused")
            if group is not None:
                await fill(page, GROUP_FIELD, group)
            if order is not None:
                await fill(page, ORDER_FIELD, order)
            await page.press_enter()
            await page.wait_for(f"{DIALOG} === null", what="the dialog closed")

        async def go():
            async with browser_of(tmp_path / 'first', state, host_over={'priority': '0:1'}) as (h, browser, url):
                for name in ('b02', 'b03'):       # two more hosts, down: a priority is set on any host
                    body = {'name': name, 'url': 'http://127.0.0.1:9', 'token': P.TOKEN}
                    assert (await h.client.post('/api/pool/hosts', json=body, headers=token)).status == 201
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{shown('b03')} === '0:0'", what="the rows of the three hosts")
                assert await page.evaluate(shown('a01')) == '0:1' and await page.evaluate(shown('b02')) == '0:0'
                assert await page.evaluate(BULK_DISABLED) is True
                # every other row is lightly tinted, its State cell included, which keeps its colour
                assert await page.evaluate(ORDER) == 'a01 b02 b03'
                assert await page.evaluate(STRIPES) == [[False, False, True], [True, True, True], [False, False, True]]
                # the dialog of a row: the two numbers of the host, kept open and focused when the table is drawn again
                await page.click(cell('a01'))
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of a01")
                assert 'a01' in await page.evaluate(DIALOG_TITLE) and await page.evaluate(VALUES) == ['0', '1']
                await page.evaluate(RENDER)
                assert await page.evaluate(f"{DIALOG_OPEN} && {FIELD_FOCUSED}") is True
                await set_in_dialog(page, '2', '4')
                await page.wait_for(f"{shown('a01')} === '2:4'", what="the new priority of a01")
                assert json.loads(state.read_text())['priority'] == {'a01': {'value': '2:4', 'configured': '0:1'}}
                # cancelled: nothing changes; a number out of the range is not taken, nor a field left
                # empty (one host: both numbers are asked)
                await page.click(cell('b02'))
                await page.wait_for(DIALOG_OPEN, what="the dialog of b02")
                await page.click(CANCEL)
                await page.wait_for(f"{DIALOG} === null", what="the dialog cancelled")
                await page.click(cell('b02'))
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of b02 again")
                await page.insert_text('10000')
                await page.press_enter()
                assert await page.evaluate(DIALOG_OPEN) is True and await page.evaluate(shown('b02')) == '0:0'
                await fill(page, GROUP_FIELD, '1')
                await fill(page, ORDER_FIELD, '')
                await page.press_enter()
                assert await page.evaluate(DIALOG_OPEN) is True and await page.evaluate(shown('b02')) == '0:0'
                await page.click(CANCEL)
                await page.wait_for(f"{DIALOG} === null", what="the dialog cancelled again")
                assert h.portal.pool.runtime['b02'].priority == (0, 0)
                # negative numbers; the order alone, the group kept
                await page.click(cell('b03'))
                await set_in_dialog(page, '-1', '9')
                await page.wait_for(f"{shown('b03')} === '-1:9'", what="the new priority of b03")
                await page.click(cell('b02'))
                await set_in_dialog(page, None, '-2')
                await page.wait_for(f"{shown('b02')} === '0:-2'", what="the new priority of b02")
                # the column sorted on the group, then the order: the lowest first, then the highest first
                assert await page.evaluate(ORDER) == 'a01 b02 b03'                 # by name
                await page.click('#pool th[data-sort="priority"]')
                assert await page.evaluate(ORDER) == 'b03 b02 a01'
                await page.click('#pool th[data-sort="priority"]')
                assert await page.evaluate(ORDER) == 'a01 b02 b03'
                # the bar: a number is shown first only when the selected hosts share it, and a field
                # left empty leaves that number of each host: the group alone for all of them
                await page.click('#pool-select-all')
                assert await page.evaluate(BULK_DISABLED) is False
                await page.click(BULK)
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of the selection")
                assert '3' in await page.evaluate(DIALOG_TITLE) and await page.evaluate(VALUES) == ['', '']
                await set_in_dialog(page, '5', None)
                await page.wait_for(' && '.join(f"{shown(name)} === '{value}'" for name, value in
                                                (('a01', '5:4'), ('b02', '5:-2'), ('b03', '5:9'))),
                                    what="the group of the three hosts, their orders kept")
                saved = json.loads(state.read_text())['priority']
                assert saved == {'a01': {'value': '5:4', 'configured': '0:1'},
                                 'b02': {'value': '5:-2', 'configured': '0:0'},
                                 'b03': {'value': '5:9', 'configured': '0:0'}}
                # the selection again: the group they share is shown first, not the order; the order alone
                await page.click(BULK)
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of the selection again")
                assert await page.evaluate(VALUES) == ['5', '']
                await set_in_dialog(page, None, '7')
                await page.wait_for(' && '.join(f"{shown(name)} === '5:7'" for name in ('a01', 'b02', 'b03')),
                                    what="the priority of the three hosts")
                # both numbers are shared now; nothing asked (both fields emptied) changes nothing
                await page.click(BULK)
                await page.wait_for(f"{DIALOG_OPEN} && {FIELD_FOCUSED}", what="the dialog of the selection, third time")
                assert await page.evaluate(VALUES) == ['5', '7']
                await set_in_dialog(page, '', '')
                assert [str(h.portal.pool.runtime[name].priority) for name in ('a01', 'b02', 'b03')] == ['5:7'] * 3
                assert page.errors == []
            # the portal started again on the same configuration and state file
            async with browser_of(tmp_path / 'again', state, host_over={'priority': '0:1'}) as (h, browser, url):
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{shown('b03')} === '5:7'", what="the rows of the three hosts")
                assert await page.evaluate(shown('a01')) == '5:7' and await page.evaluate(shown('b02')) == '5:7'
        P.run(go())

    def test_enable_cancels_a_drain(self, tmp_path):
        """The row of a draining host has Enable in place of Drain, and the Enable of the bar
        applies to it: both cancel the drain; neither does once the power off is sent."""
        state = tmp_path / 'state' / 'pool.json'

        async def go():
            async with browser_of(tmp_path / 'first', state, host_over={}) as (h, browser, url):
                runtime = h.portal.pool.runtime['a01']
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{STATE} === 'up'", what="the host up")
                assert await page.evaluate(button(action(1))) == ['Disable', False, '']
                assert await page.evaluate(button(action(3))) == ['Drain', False, '']
                # the row: Drain, then Enable in its place (green, as the Enable of a disabled host)
                await page.click(action(3))
                await page.wait_for(is_button(action(3), 'Enable', title='cancels the drain'),
                                    what="Enable in place of Drain")
                assert await page.evaluate(STATE) == 'draining'
                assert list(json.loads(state.read_text())['drain']) == ['a01']
                assert await page.evaluate(button(action(1))) == ['Disable', False, '']
                assert await page.evaluate(f"document.querySelector('{action(3)}').className") == 'ok'
                await page.click(action(3))
                await page.wait_for(is_button(action(3), 'Drain'), what="Drain back in the row")
                assert await page.evaluate(STATE) == 'up' and runtime.drain is False
                assert json.loads(state.read_text())['drain'] == {}
                # the bar: its Enable skips an enabled host, unless it drains
                await page.click(CHECKBOX)
                await page.wait_for(f"!document.querySelector('{BAR_DRAIN}').disabled", what="Drain of the bar")
                assert (await page.evaluate(button(BAR_ENABLE)))[1] is True
                await page.click(BAR_DRAIN)
                await page.wait_for(f"{STATE} === 'draining' && !document.querySelector('{BAR_ENABLE}').disabled",
                                    what="Enable of the bar for the draining host")
                assert runtime.drain is True
                await page.click(BAR_ENABLE)
                await page.wait_for(f"{STATE} === 'up'", what="the drain cancelled from the bar")
                assert runtime.drain is False and json.loads(state.read_text())['drain'] == {}
                # the power off is sent: the host is going down, its drain is not cancelled any more
                runtime.drain, runtime.power_off_sent = True, time.monotonic()
                await page.wait_for(is_button(action(3), 'Enable', disabled=True, title='power off sent'),
                                    timeout=POLL, what="Enable disabled once the power off is sent")
                assert (await page.evaluate(button(BAR_ENABLE)))[1] is True
                assert page.errors == []
        P.run(go())

    def test_local_drain(self, tmp_path):
        """A drain the host asked for itself (`sre set-drain` there, here its request file): the
        flag, Enable in place of Drain, which cancels it on the agent, and the two buttons of the
        bar that forbid and allow the local drains of the selected hosts."""
        from SRE import local_drain
        state = tmp_path / 'state' / 'pool.json'

        async def go():
            async with browser_of(tmp_path / 'first', state, host_over={},
                                  agent_over={'allow_local_drain': True}) as (h, browser, url):
                request = local_drain.request_path(str(h.pub))
                page = await browser.page(f'{url}/pool')
                await page.wait_for(f"{FLAGS} === 'local drain allowed'", what="the host allowed to drain itself")
                assert await page.evaluate(STATE) == 'up'
                assert await page.evaluate(button(action(3))) == ['Drain', False, '']
                # the bar: Forbid applies to the selected host, Allow does not (it is allowed already)
                await page.click(CHECKBOX)
                await page.wait_for(f"!document.querySelector('{BAR_FORBID}').disabled", what="Forbid of the bar")
                assert await page.evaluate(button(BAR_ALLOW)) == [
                    'Allow local drain', True, 'applies to none of the selected hosts']
                # the host asks for its drain: seen at a poll of the page
                local_drain.write_request(request, local_drain.boot_id())
                await page.wait_for(f"{FLAGS} === 'local drain'", timeout=POLL, what="the flag of the local drain")
                assert await page.evaluate(STATE) == 'draining'
                assert await page.evaluate(FLAGS_TITLE) == 'drain asked on the host itself (sre set-drain)'
                assert await page.evaluate(button(action(3))) == ['Enable', False, 'cancels the drain']
                # the drain of the host, not one of the portal: nothing of it in the state file
                assert h.portal.pool.runtime['a01'].drain is False
                assert not state.exists() or json.loads(state.read_text())['drain'] == {}
                # Enable of the row cancels it, on the agent
                await page.click(action(3))
                await page.wait_for(is_button(action(3), 'Drain'), what="Drain back in the row")
                assert await page.evaluate(STATE) == 'up' and await page.evaluate(FLAGS) == 'local drain allowed'
                assert not os.path.exists(request)
                # forbidden from the bar (the agent.toml of the host allows it: the flag says so), then allowed
                await page.click(BAR_FORBID)
                await page.wait_for(f"{FLAGS} === 'local drain forbidden'", what="the local drain forbidden")
                assert await page.evaluate(button(BAR_FORBID)) == [
                    'Forbid local drain', True, 'applies to none of the selected hosts']
                assert h.agent.local_drain.allowed is False
                local_drain.write_request(request, local_drain.boot_id())      # refused by the agent
                await page.wait_for(RENDER + f", {FLAGS} === 'local drain forbidden'", what="the page drawn again")
                await asyncio.sleep(0.5)
                assert not os.path.exists(request) and await page.evaluate(STATE) == 'up'
                await page.click(BAR_ALLOW)
                await page.wait_for(f"{FLAGS} === 'local drain allowed'", what="the local drain allowed again")
                assert h.agent.local_drain.allowed is True
                assert page.errors == []
        P.run(go())
