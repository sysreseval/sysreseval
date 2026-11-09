"""The Watch page of the instructors in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``, the fake database of the custom groups as the group source so that the group select is
shown): the group chosen in the select is kept in the URL and remembered by the browser
(localStorage ``sreweb.watch``), so that the page comes back with it through the Watch link of
the header, which carries no query string, until another group or All groups is chosen; a link
with ``?group=`` wins and is remembered; No group (the rows without department) is remembered
too."""
import contextlib
import json
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from test_web_groups import FakeGroupsServer, harness         # noqa: E402  (a group source: the custom groups)
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
PROF = P.who('prof', 'Prof Essor', groups=P.TEACHERS)        # the instructor, the identity of the browser
ALICE = P.who('alice', 'Alice A', group='INFO1')
BOB = P.who('bob', 'Bob B', group='INFO2')
DHCP = 'sre/dhcp.py'                                          # a lab of the fake sre
INFO1, INFO2 = 'department:INFO1', 'department:INFO2'         # the keys of the two departments of the rows
STORAGE_KEY = 'sreweb.watch'

# -- what the page shows, as JavaScript expressions ---------------------------------------------

OWNERS = "[...document.querySelectorAll('#watch tbody tr td:nth-child(2)')].map((td) => td.textContent)"
COUNT = "(document.getElementById('watch-count') || {textContent: ''}).textContent"
RENDERED = f"{COUNT} !== ''"                                  # the table rendered (the count is set by render())
MESSAGE = "(document.querySelector('#watch tbody td.muted') || {textContent: ''}).textContent"
# the option selected: 'all', 'none', or the key of the group
SELECTED = """(() => {
  const option = document.getElementById('watch-group').selectedOptions[0];
  return option ? (option.dataset.kind === 'group' ? option.value : option.dataset.kind) : '';
})()"""
URL_GROUP = "new URL(window.location.href).searchParams.get('group')"     # null without ?group=
STORED = f"window.localStorage.getItem({json.dumps(STORAGE_KEY)})"


def choose(kind: str, value: str = '') -> str:
    """Select the option of *kind* ('all', 'none', or 'group' by *value*) and fire the change
    event, as a user would (a click on an <option> is unreliable headless)."""
    return f"""(() => {{
  const select = document.getElementById('watch-group');
  for (const option of select.options) {{
    option.selected = option.dataset.kind === {json.dumps(kind)}
      && ({json.dumps(kind)} !== 'group' || option.value === {json.dumps(value)});
  }}
  select.dispatchEvent(new Event('change'));
  return select.selectedOptions.length;
}})()"""


@contextlib.asynccontextmanager
async def browser_of(tmp_path):
    """The harness (proxy mode, the real web directory, the fake database of the custom groups as
    the group source), the identity proxy making the browser the instructor, and the browser:
    ``(h, browser, url)``."""
    h = harness(tmp_path, server=FakeGroupsServer())
    h.web_dir = WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', PROF)
        await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield h, browser, proxy.url
        finally:
            await proxy.close()


async def start(h, identity):
    """A project of *identity* started through the API (its group lands in the answers metadata,
    hence in the rows of the Watch page)."""
    resp = await h.client.post('/api/projects', json={'lab': DHCP}, headers={**identity, **P.CSRF})
    result = [json.loads(line) for line in (await resp.text()).splitlines()][-1]
    assert result['status'] == 'created', result


async def back_through_the_nav(page, url):
    """Leave for the Projects page, then come back with the Watch link of the header (which
    carries no query string), and wait for the table."""
    await page.goto(f'{url}/projects')
    await page.wait_for("document.getElementById('projects') !== null", what="the Projects page")
    await page.click('a.watch-link')
    await page.wait_for(RENDERED, what="the Watch page rendered again")


class TestWatchGroupFilter:
    def test_group_remembered_across_the_pages(self, tmp_path):
        async def go():
            async with browser_of(tmp_path) as (h, browser, url):
                await start(h, ALICE)
                await start(h, BOB)
                page = await browser.page(f'{url}/watch')
                await page.wait_for(f"{OWNERS}.length === 2", what="the two projects")
                assert await page.evaluate(SELECTED) == 'all'
                assert await page.evaluate(URL_GROUP) is None and await page.evaluate(STORED) is None
                # one group chosen: its rows, the URL and the storage carry it
                assert await page.evaluate(choose('group', INFO1)) == 1
                await page.wait_for(f"{OWNERS}.length === 1", what="the row of alice")
                assert await page.evaluate(OWNERS) == ['alice']
                assert await page.evaluate(COUNT) == '1 of 2 project(s)'
                assert await page.evaluate(URL_GROUP) == INFO1
                assert json.loads(await page.evaluate(STORED)) == {'group': INFO1}
                # another page, then the Watch link of the header: the group is still chosen
                await back_through_the_nav(page, url)
                assert await page.evaluate(SELECTED) == INFO1
                assert await page.evaluate(OWNERS) == ['alice']
                assert await page.evaluate(URL_GROUP) == INFO1
                # a link with ?group= wins, and is the remembered one from then on
                await page.goto(f'{url}/watch?group={INFO2}')
                await page.wait_for(RENDERED, what="the Watch page of the link")
                assert await page.evaluate(SELECTED) == INFO2 and await page.evaluate(OWNERS) == ['bob']
                assert json.loads(await page.evaluate(STORED)) == {'group': INFO2}
                await back_through_the_nav(page, url)
                assert await page.evaluate(SELECTED) == INFO2 and await page.evaluate(OWNERS) == ['bob']
                # No group (the rows without department: none here) is remembered too
                assert await page.evaluate(choose('none')) == 1
                await page.wait_for(f"{OWNERS}.length === 0", what="no row without department")
                assert await page.evaluate(MESSAGE) == 'No project matches the filter.'
                assert await page.evaluate(URL_GROUP) == '' and json.loads(await page.evaluate(STORED)) == {'group': ''}
                await back_through_the_nav(page, url)
                assert await page.evaluate(SELECTED) == 'none' and await page.evaluate(OWNERS) == []
                assert await page.evaluate(URL_GROUP) == ''
                # All groups: every row, nothing in the URL nor in the storage, and it stays so
                assert await page.evaluate(choose('all')) == 1
                await page.wait_for(f"{OWNERS}.length === 2", what="the two projects again")
                assert await page.evaluate(URL_GROUP) is None and await page.evaluate(STORED) is None
                await back_through_the_nav(page, url)
                assert await page.evaluate(SELECTED) == 'all'
                assert sorted(await page.evaluate(OWNERS)) == ['alice', 'bob']
                assert await page.evaluate(URL_GROUP) is None and await page.evaluate(STORED) is None
        P.run(go())
