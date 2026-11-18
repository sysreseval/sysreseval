"""The Watch page of the instructors in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``, the fake database of the custom groups as the group source so that the group select is
shown): the group chosen in the select is kept in the URL and remembered by the browser
(localStorage ``sreweb.watch``), so that the page comes back with it through the Watch link of
the header, which carries no query string, until another group or All groups is chosen; a link
with ``?group=`` wins and is remembered; No group (the rows without department) is remembered
too.  And the Last action column: the gestures of the student on their project page (a real mouse
press on a tab, a key) reach the row, those of an instructor on that page do not.  And the two
views of the page (Projects, where it lands, and Clients: the browsers connected to the portal
and the users in a local GUI) with the Clients column of the projects."""
import asyncio
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
# per row, whether its first cell carries the tint of a striped table (a layer over the row's colour)
STRIPES = ("[...document.querySelectorAll('#watch tbody tr')]"
           ".map((tr) => getComputedStyle(tr.children[0]).backgroundImage !== 'none')")
ROW_COLOURS = ("[...document.querySelectorAll('#watch tbody tr')]"
               ".map((tr) => getComputedStyle(tr.children[0]).backgroundColor)")
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
async def browser_of(tmp_path, *others, administrators=()):
    """The harness (proxy mode, the real web directory, the fake database of the custom groups as
    the group source), the identity proxy making the browser the instructor, and the browser:
    ``(h, browser, url)``, followed by the address of one more proxy per identity of *others*
    (the pages of a student in the same browser).  The proxies are closed after the browser: a
    proxy closed under an open page waits a minute for its WebSockets.  *administrators*: the
    logins of ``[auth] administrators``."""
    h = harness(tmp_path, server=FakeGroupsServer())
    h.web_dir = WEB
    if administrators:
        h.web_over['auth'] = {**h.web_over['auth'], 'administrators': list(administrators)}
    async with h:
        proxies = [IdentityProxy(f'http://127.0.0.1:{h.client.port}', identity) for identity in (PROF, *others)]
        try:
            for proxy in proxies:
                await proxy.start()
            async with Browser(CHROME) as browser:
                yield (h, browser, *(proxy.url for proxy in proxies))
        finally:
            for proxy in proxies:
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
                # every other row is tinted, over the colour of the row: both are without
                # evaluation, so both keep the same orange under the tint of the second
                assert await page.evaluate(STRIPES) == [False, True]
                colours = await page.evaluate(ROW_COLOURS)
                assert colours[0] == colours[1] != 'rgba(0, 0, 0, 0)'
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


# -- the Last action column ---------------------------------------------------------------------

# the cell of the first row (the 7th column, after Started): its text and its tooltip
LAST_ACTION = """(() => {
  const td = document.querySelector('#watch tbody tr td:nth-child(7)');
  return td ? {text: td.textContent, title: td.title} : null;
})()"""
TABS = "[...document.querySelectorAll('#tabbar [role=tab]')].map((b) => b.dataset.tab)"
SELECTED_TAB = "(document.querySelector('#tabbar [role=tab][aria-selected=true]') || {dataset: {}}).dataset.tab"


def tab_point(tab: str) -> str:
    """The centre of the button of *tab* in the tab bar, for a real mouse press."""
    return (f"(() => {{ const b = document.querySelector('#tabbar [data-tab={json.dumps(tab)}]'); if (!b) {{ return null; }} "
            f"const r = b.getBoundingClientRect(); return {{x: r.left + r.width / 2, y: r.top + r.height / 2}}; }})()")


async def press_tab(page, tab: str):
    """A real mouse press on the button of *tab* (``Page.click`` calls ``element.click()``, which
    fires no pointer event), and the tab shown."""
    at = await page.wait_for(tab_point(tab), what=f"the {tab} tab button")
    await page.click_at(at['x'], at['y'])
    await page.wait_for(f"{SELECTED_TAB} === {json.dumps(tab)}", what=f"the {tab} tab shown")


class TestLastAction:
    def test_gestures_of_the_owner(self, tmp_path):
        """The Last action column: blank while the student has done nothing (the project
        started, its page open), then the age of their last gesture on the page (a click on a
        tab, a key: nothing of that reaches the server by itself); the same gestures of an
        instructor on the student's project page change nothing."""
        async def go():
            async with browser_of(tmp_path, ALICE) as (h, browser, url, student_url):
                await start(h, ALICE)
                rln = (await (await h.client.get('/api/watch', headers=PROF)).json())[0]['running_lab_name']
                project = h.agent.registry.get(rln)

                async def last_action():
                    return (await (await h.client.get('/api/watch', headers=PROF)).json())[0]['last_action']

                async def acted(timeout):
                    async with asyncio.timeout(timeout):
                        while await last_action() is None:
                            await asyncio.sleep(0.05)
                    return await last_action()

                async def subscribed(login):          # the events socket of the page of *login* is open
                    async with asyncio.timeout(10):
                        while not [s for s in project.subscribers if s.identity.login == login]:
                            await asyncio.sleep(0.05)

                watch = await browser.page(f'{url}/watch')
                await watch.wait_for(f"{OWNERS}.length === 1", what="the project of alice")
                assert await watch.evaluate(LAST_ACTION) == {'text': '', 'title': ''}
                # the student's page open, its events socket connected: still no action
                page = await browser.page(f'{student_url}/projects/a01/{rln}', new_window=True)
                await page.wait_for(f"{TABS}.includes('informations')", what="the tabs of the project")
                await subscribed('alice')
                assert await last_action() is None
                # a click on a tab: reported at once
                await press_tab(page, 'informations')
                assert (await acted(10))['age_s'] <= 10
                # the Watch page at its next poll: the age, the time as a tooltip
                cell = await watch.wait_for(f"/ s ago$/.test(({LAST_ACTION} || {{text: ''}}).text) && {LAST_ACTION}",
                                            timeout=15.0, what="the last action of alice on the Watch page")
                assert cell['title']
                # a key pressed right after: reported too, at the end of the interval between two
                # reports (ACTIVITY_INTERVAL of activity.js, 10 s)
                project.last_action_at = None
                await page.press_enter()
                await acted(20)
                # the instructor on the student's project: their gestures are not the student's
                project.last_action_at = None
                helper = await browser.page(f'{url}/projects/a01/{rln}', new_window=True)
                await helper.wait_for(f"{TABS}.includes('informations')", what="the tabs on the instructor's page")
                await subscribed('prof')
                await press_tab(helper, 'informations')
                await helper.press_enter()
                await asyncio.sleep(1.0)
                assert await last_action() is None
        P.run(go())


# -- the Projects / Clients views and the Clients column ----------------------------------------

ADMIN = P.who('admin', 'Ada Min', groups=P.TEACHERS)          # an instructor listed in [auth] administrators
VIEW = "(document.querySelector('.history-views button[aria-pressed=true]') || {dataset: {}}).dataset.view"
URL_VIEW = "new URL(window.location.href).searchParams.get('view')"       # null without ?view=
SECTIONS = ("({projects: !document.getElementById('watch-projects').hidden, "
            "clients: !document.getElementById('watch-clients').hidden})")
TITLE = "document.getElementById('watch-title').textContent"
# the Clients cell of the first project (the 14th column, after Terminals): its text and its tooltip
CLIENTS_CELL = """(() => {
  const td = document.querySelector('#watch tbody tr td:nth-child(14)');
  return td ? {text: td.textContent, title: td.title} : null;
})()"""
ADDRESS_HIDDEN = "document.querySelector('#watch-web th[data-sort=addr]').hidden"
PAGE_LINKS = "[...document.querySelectorAll('#watch-web td.pages a')].map((a) => a.getAttribute('href'))"


def table_rows(table: str) -> str:
    """The texts of the cells of each row of a clients table (a message row has one cell: left out)."""
    return (f"[...document.querySelectorAll('#{table} tbody tr')].filter((tr) => tr.children.length > 1)"
            ".map((tr) => [...tr.children].map((td) => td.textContent))")


LOCAL_ROWS, WEB_ROWS = table_rows('watch-local'), table_rows('watch-web')
LOCAL_MESSAGE = "(document.querySelector('#watch-local tbody td.muted') || {textContent: ''}).textContent"


def view_button(view: str) -> str:
    return f'.history-views button[data-view="{view}"]'


def type_filter(text: str) -> str:
    return (f"(() => {{ const input = document.getElementById('watch-filter'); input.value = {json.dumps(text)}; "
            "input.dispatchEvent(new Event('input')); return true; })()")


class TestClientsView:
    def test_the_two_views_and_the_clients_of_a_project(self, tmp_path, monkeypatch):
        """The page lands on the projects; the Clients button shows who is connected, one row
        per browser (the two pages of the instructor are one browser) and one per user in a
        local GUI, with the addresses for an administrator only; ``?view=clients`` is in the URL
        and never remembered.  The Clients column counts the clients of the owner on the
        project: her browser on its page (not the instructor's, not a page she left, which the
        browser keeps in its back/forward cache) and her local GUI."""
        import os
        from urllib.parse import quote
        from sreweb.agent import localgui
        from sreweb.portal import clients as C
        from test_agent_localgui import GUI, fake_proc, users
        monkeypatch.setattr(localgui, 'SYSTEM_UID_MAX', -1)    # the fake processes belong to whoever runs the tests

        async def go():
            async with browser_of(tmp_path, ALICE, ADMIN, administrators=['admin']) as (
                    h, browser, url, student_url, admin_url):
                await start(h, ALICE)
                rln = (await (await h.client.get('/api/watch', headers=PROF)).json())[0]['running_lab_name']
                project_path = f'/projects/a01/{quote(rln, safe="")}'
                presence = h.portal.presence

                async def clients():
                    return (await (await h.client.get('/api/watch', headers=PROF)).json())[0]['clients']

                async def until(predicate, what, timeout=10.0):
                    async with asyncio.timeout(timeout):
                        while True:
                            result = predicate()
                            if asyncio.iscoroutine(result):
                                result = await result
                            if result:
                                return
                            await asyncio.sleep(0.05)

                def on_project(login):
                    return [s for s in presence.sockets()
                            if s.identity.login == login and C.page_project(s.page) == ('a01', rln)]

                watch = await browser.page(f'{url}/watch')
                await watch.wait_for(f"{OWNERS}.length === 1", what="the project of alice")
                # the page lands on the projects
                assert await watch.evaluate(VIEW) == 'projects' and await watch.evaluate(URL_VIEW) is None
                assert await watch.evaluate(SECTIONS) == {'projects': True, 'clients': False}
                assert await watch.evaluate(TITLE) == 'All running projects'
                assert await watch.evaluate(CLIENTS_CELL) == {'text': '0', 'title': ''}
                # the student opens her project: one client
                page = await browser.page(f'{student_url}{project_path}', new_window=True)
                await page.wait_for(f"{TABS}.includes('informations')", what="the tabs of the project")
                await watch.wait_for(f"({CLIENTS_CELL} || {{}}).text === '1'", timeout=15.0, what="the browser of alice counted")
                # the instructor opens it too: not a client of the project
                helper = await browser.page(f'{url}{project_path}', new_window=True)
                await helper.wait_for(f"{TABS}.includes('informations')", what="the tabs on the instructor's page")
                await until(lambda: on_project('prof'), "the presence socket of the instructor's page")
                assert await clients() == 1

                # the Clients view: alice's browser, and the instructor's with its two pages
                await watch.click(view_button('clients'))
                await watch.wait_for(f"{WEB_ROWS}.length === 2", what="the two browsers")
                assert await watch.evaluate(VIEW) == 'clients' and await watch.evaluate(URL_VIEW) == 'clients'
                assert await watch.evaluate(SECTIONS) == {'projects': False, 'clients': True}
                assert await watch.evaluate(TITLE) == 'Connected clients'
                assert await watch.evaluate(COUNT) == '2 client(s)'
                assert await watch.evaluate(LOCAL_MESSAGE) == 'Nobody is in a local GUI.'
                alice, prof = await watch.evaluate(WEB_ROWS)
                assert alice[:4] == ['alice', 'Alice A', 'INFO1', 'student'] and alice[4].startswith('Chrome')
                assert alice[6] == '' and alice[7] and alice[8] == 'sre/dhcp.py (alice)'
                assert prof[:4] == ['prof', 'Prof Essor', '', 'instructor'] and prof[4].startswith('Chrome')
                assert prof[8] == 'sre/dhcp.py (alice)/watch'                   # one browser, two pages
                assert await watch.evaluate(PAGE_LINKS) == [project_path, project_path]
                assert await watch.evaluate(ADDRESS_HIDDEN) is True               # not an administrator
                # the text filter of the page applies to the clients
                await watch.evaluate(type_filter('student'))
                await watch.wait_for(f"{WEB_ROWS}.length === 1", what="the students only")
                assert await watch.evaluate(COUNT) == '1 of 2 client(s)'
                await watch.evaluate(type_filter(''))
                await watch.wait_for(f"{WEB_ROWS}.length === 2", what="everybody again")

                # alice also sits in the local GUI of the host
                h.agent.proc_dir = fake_proc(tmp_path / 'proc', {4242: {'argv': GUI, 'start': 0}})
                h.agent.user_of = localgui.Users(users({os.getuid(): ('alice', 'alice a')}))
                h.agent._gui_users = None
                await watch.wait_for(f"{LOCAL_ROWS}.length === 1", timeout=20.0, what="the local GUI of alice")
                local, = await watch.evaluate(LOCAL_ROWS)
                assert local[:3] == ['a01', 'alice', 'alice a'] and local[4]
                assert await watch.evaluate(COUNT) == '3 client(s)'

                # an administrator lands on the view named by the link, and sees the addresses
                admin = await browser.page(f'{admin_url}/watch?view=clients', new_window=True)
                await admin.wait_for(f"{WEB_ROWS}.length === 3", what="the three browsers")
                assert await admin.evaluate(VIEW) == 'clients' and await admin.evaluate(ADDRESS_HIDDEN) is False
                assert all(row[6] for row in await admin.evaluate(WEB_ROWS))
                await admin.close()

                # back to the projects: her browser and her local GUI
                await watch.click(view_button('projects'))
                await watch.wait_for(f"({CLIENTS_CELL} || {{}}).text === '2'", timeout=15.0, what="the browser and the GUI")
                assert await watch.evaluate(VIEW) == 'projects' and await watch.evaluate(URL_VIEW) is None
                assert (await watch.evaluate(CLIENTS_CELL))['title'] == 'The local GUI of the owner is one of them'
                # she leaves her project page for another one: the GUI alone, then comes back
                await page.goto(f'{student_url}/projects')
                # (Chrome keeps the page left in its back/forward cache with the presence socket
                # open: the page said `away` in its pagehide handler; a browser that closes the
                # socket instead gives the same count)
                await until(lambda: not [s for s in on_project('alice') if not s.away], "the page of alice left")
                assert await clients() == 1
                await page.evaluate('history.back(); true')
                await page.wait_for(f"{TABS}.includes('informations')", what="the project page again")
                await until(lambda: [s for s in on_project('alice') if not s.away], "the page of alice shown again")
                assert await clients() == 2

                # the view is never remembered: the Watch link of the header lands on the projects
                await watch.click(view_button('clients'))
                await watch.wait_for(f"{WEB_ROWS}.length >= 2", what="the clients again")
                await back_through_the_nav(watch, url)
                assert await watch.evaluate(VIEW) == 'projects' and await watch.evaluate(URL_VIEW) is None
                assert await watch.evaluate(SECTIONS) == {'projects': True, 'clients': False}
                # ... and a link with ?view=clients opens the clients
                await watch.goto(f'{url}/watch?view=clients')
                await watch.wait_for(f"{WEB_ROWS}.length >= 2", what="the clients of the link")
                assert await watch.evaluate(VIEW) == 'clients'
        P.run(go())
