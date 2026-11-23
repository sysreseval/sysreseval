"""The saved projects in a headless Chrome (``web_browser.py``; skipped without Google Chrome /
Chromium, ``SRE_TEST_CHROME`` names one), on the real pages of ``web/`` served by the portal of
test_web_portal.py in front of a real agent whose directory of saved projects is a directory of
the test: the Save Project button of a project page and its dialog, the limit of saved projects
told with what to delete, the Saved projects page of a student (their saves, sharing with a
group of theirs, a restore ending on the page of the new project) and of an instructor (every
save, the filter)."""
import contextlib
import json
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from sreweb import savestore as store                         # noqa: E402
from test_agent_saves import store_user                       # noqa: E402
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
ALICE = P.who('alice', 'Alice A', group='INFO1')
BOB = P.who('bob', 'Bob B', group='INFO1')
PROF = P.who('prof', 'Prof P', groups=P.TEACHERS)
LAB = 'sre/dhcp.py'

# -- what the pages show, as JavaScript expressions ---------------------------------------------

SAVE_BUTTON_SHOWN = "(() => { const b = document.getElementById('save-project'); return b !== null && !b.hidden; })()"
SAVE_DIALOG = "document.querySelector('dialog.save-dialog[open]') !== null"
NO_DIALOG = "document.querySelector('dialog[open]') === null"
SUBMIT_DISABLED = "document.querySelector('dialog.save-dialog button[type=\"submit\"]').disabled"
QUOTA_ITEMS = "[...document.querySelectorAll('dialog.save-dialog ul.save-list li .save-what')].map((e) => e.textContent)"
TOASTS = "[...document.querySelectorAll('#toasts > *')].map((e) => e.textContent)"
ON_PROJECT_PAGE = "window.location.pathname.startsWith('/projects/a01/')"


def rows(table: str) -> str:
    """The cells of the rows of a table of the Saved projects page, the actions as button texts."""
    return f"""[...document.querySelectorAll('#{table} tbody tr')].map((tr) => [...tr.children].map(
      (td) => td.classList.contains('actions')
        ? [...td.querySelectorAll('button')].map((b) => b.textContent + (b.disabled ? ' (off)' : '')).join('|')
        : td.textContent))"""


def button(table: str, text: str) -> str:
    """A click on the button *text* of the first row of *table*."""
    return f"""(() => {{
      const b = [...document.querySelectorAll('#{table} tbody tr:first-child td.actions button')]
        .find((e) => e.textContent === {json.dumps(text)});
      if (!b) throw new Error('no button {text}');
      b.click();
      return true;
    }})()"""


@contextlib.asynccontextmanager
async def browsing(tmp_path, identity, *others, max_per_user=1):
    """The harness with the saved projects on, the browser as *identity*, and one more identity
    proxy per entry of *others*: ``(h, browser, url, [url of each other])``."""
    directory = tmp_path / 'saves'
    directory.mkdir()
    (directory / store.MARKER).touch()
    over = {**P.PROXY_OVER, 'limits': {'save_interval': 0, 'start_interval': 0},
            'saves': {'enabled': True, 'cache_ttl': 0, 'max_per_user': max_per_user}}
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over, host_over={'max_projects': 9},
                  agent_over={'saves': {'dir': str(directory), 'user': store_user(), 'min_free_mb': 0}})
    h.web_dir = WEB
    async with h:
        await h.portal.pool.refresh()
        proxies = [IdentityProxy(f'http://127.0.0.1:{h.client.port}', who) for who in (identity, *others)]
        for proxy in proxies:
            await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield h, browser, proxies[0].url, [proxy.url for proxy in proxies[1:]]
        finally:
            for proxy in proxies:
                await proxy.close()


async def start(h, user) -> str:
    resp = await h.client.post('/api/projects', json={'lab': LAB}, headers={**user, **P.CSRF})
    result = json.loads((await resp.text()).splitlines()[-1])
    assert result['status'] == 'created', result
    return result['running_lab_name']


async def saves_of(h, user) -> list:
    return (await (await h.client.get('/api/saves', headers=user)).json())['saves']


async def save_from_the_dialog(page, comment: str):
    await page.click('#save-project')
    await page.wait_for(SAVE_DIALOG, what="the save dialog")
    await page.click('dialog.save-dialog input[name="comment"]')
    await page.evaluate("document.querySelector('dialog.save-dialog input[name=\"comment\"]').focus()")
    await page.insert_text(comment)
    await page.click('dialog.save-dialog button[type="submit"]')


class TestProjectPage:
    def test_save_then_the_limit(self, tmp_path):
        async def go():
            async with browsing(tmp_path, ALICE) as (h, browser, url, _):
                rln = await start(h, ALICE)
                page = await browser.page(f'{url}/projects/a01/{rln}')
                await page.wait_for(SAVE_BUTTON_SHOWN, what="the Save Project button")
                # the link of every page
                assert await page.evaluate("document.querySelector('a.saves-link').getAttribute('href')") == '/saves'

                await save_from_the_dialog(page, 'after part 2')
                await page.wait_for(NO_DIALOG, what="the dialog closed once saved")
                await page.wait_for(f"{TOASTS}.includes('Project saved.')", what="the toast")
                kept = await saves_of(h, ALICE)
                assert [(s['comment'], s['lab']) for s in kept] == [('after part 2', LAB)]

                # one saved project is all this user may keep: the dialog says which to delete
                await save_from_the_dialog(page, 'part 3')
                await page.wait_for(f"{QUOTA_ITEMS}.length === 1", what="the saves to delete")
                assert 'after part 2' in (await page.evaluate(QUOTA_ITEMS))[0]
                assert await page.evaluate(SUBMIT_DISABLED) is True
                assert len(await saves_of(h, ALICE)) == 1
                await page.click('dialog.save-dialog ul.save-list li button.danger')
                await page.wait_for(f"{QUOTA_ITEMS}.length === 0 && !{SUBMIT_DISABLED}", what="room for the save")
                assert await saves_of(h, ALICE) == []
                await page.click('dialog.save-dialog button[type="submit"]')
                await page.wait_for(NO_DIALOG, what="the dialog closed once saved")
                assert [s['comment'] for s in await saves_of(h, ALICE)] == ['part 3']
        P.run(go())

    def test_no_button_when_the_lab_does_not_allow_it(self, tmp_path):
        async def go():
            async with browsing(tmp_path, ALICE) as (h, browser, url, _):
                h.agent.runner.extra_env['MOCK_NO_SAVE_RESTORE'] = '1'
                rln = await start(h, ALICE)
                page = await browser.page(f'{url}/projects/a01/{rln}')
                await page.wait_for("document.getElementById('project-title').textContent !== ''", what="the project")
                await page.wait_for("document.querySelectorAll('#tabbar > *').length > 0", what="the tabs")
                assert await page.evaluate("document.getElementById('save-project').hidden") is True
        P.run(go())


class TestSavedProjectsPage:
    def test_share_and_restore(self, tmp_path):
        async def go():
            async with browsing(tmp_path, ALICE, BOB, max_per_user=3) as (h, browser, url, (bob_url,)):
                rln = await start(h, ALICE)
                resp = await h.client.post(f'/api/projects/a01/{rln}/save', json={'comment': 'for the group'},
                                           headers={**ALICE, **P.CSRF})
                assert resp.status == 200, await resp.text()

                page = await browser.page(f'{url}/saves')
                await page.wait_for(f"{rows('saves-mine')}.length === 1 && {rows('saves-mine')}[0].length === 6",
                                    what="the saved project")
                row = (await page.evaluate(rows('saves-mine')))[0]
                assert row[1] == 'for the group' and row[4] == '' and row[5] == 'Restore|Share…|Delete'
                assert row[3].endswith(' KB') and row[0] != ''
                assert await page.evaluate("document.getElementById('saves-quota').textContent") == '1 of 3 saved projects'
                assert await page.evaluate("document.getElementById('saves-shared-box').hidden") is True
                # a student has no list of every save
                assert await page.evaluate("document.getElementById('saves-views')") is None

                # shared with the group of the student: the only one the dialog offers
                await page.evaluate(button('saves-mine', 'Share…'))
                await page.wait_for("document.querySelector('dialog.save-share[open] select option') !== null",
                                    what="the groups of the share dialog")
                options = "[...document.querySelectorAll('dialog.save-share select option')].map((o) => o.value)"
                assert await page.evaluate(options) == ['department:INFO1']
                await page.evaluate("document.querySelector('dialog.save-share select option').selected = true")
                await page.click('dialog.save-share button[type="submit"]')
                await page.wait_for(f"{rows('saves-mine')}[0][4] === 'INFO1'", what="the group in the row")

                # the other member of the group sees it under "Shared with me", and may only restore it
                other = await browser.page(f'{bob_url}/saves')
                await other.wait_for(f"{rows('saves-shared')}.length === 1", what="the save shared with bob")
                shared = (await other.evaluate(rows('saves-shared')))[0]
                assert shared[1] == 'for the group' and shared[2] == 'Alice A (alice)' and shared[5] == 'Restore'
                assert await other.evaluate("document.getElementById('saves-shared-box').hidden") is False
                assert (await other.evaluate(rows('saves-mine')))[0] == ['You have no saved project.']
                await other.evaluate(button('saves-shared', 'Restore'))
                await other.wait_for(ON_PROJECT_PAGE, timeout=20, what="the page of the restored project")
                assert (await other.url()).endswith('%40%40%40bob') or (await other.url()).endswith('@@@bob')

                # deleted by its owner (the page asks first)
                await page.evaluate('window.confirm = () => true')
                await page.evaluate(button('saves-mine', 'Delete'))
                await page.wait_for(f"{rows('saves-mine')}[0][0] === 'You have no saved project.'", what="no save left")
                assert await saves_of(h, ALICE) == []
        P.run(go())

    def test_an_instructor_sees_every_save(self, tmp_path):
        async def go():
            async with browsing(tmp_path, PROF, max_per_user=3) as (h, browser, url, _):
                rln = await start(h, ALICE)
                for comment in ('first', 'second'):
                    resp = await h.client.post(f'/api/projects/a01/{rln}/save', json={'comment': comment},
                                               headers={**ALICE, **P.CSRF})
                    assert resp.status == 200, await resp.text()

                page = await browser.page(f'{url}/saves')
                await page.wait_for(f"{rows('saves-mine')}.length === 1", what="the instructor's own saves")
                assert (await page.evaluate(rows('saves-mine')))[0] == ['You have no saved project.']
                await page.click('#saves-views button[data-view="all"]')
                await page.wait_for(f"{rows('saves-all')}.length === 2", what="every saved project")
                listed = await page.evaluate(rows('saves-all'))
                assert [r[0] for r in listed] == ['Alice A (alice)'] * 2 and [r[1] for r in listed] == ['INFO1'] * 2
                assert {r[3] for r in listed} == {'first', 'second'}
                assert all(r[7] == 'Restore|Share…|Delete' for r in listed)
                assert await page.evaluate("document.getElementById('saves-count').textContent") == '(2)'
                assert 'Free space of the saved projects' in await page.evaluate(
                    "document.getElementById('saves-space').textContent")
                assert (await page.url()).endswith('?view=all')
                assert await page.evaluate("document.getElementById('saves-mine-box').hidden") is True

                # the filter
                await page.evaluate("document.getElementById('saves-filter').focus()")
                await page.insert_text('second')
                await page.wait_for(f"{rows('saves-all')}.length === 1", what="the filtered rows")
                assert (await page.evaluate(rows('saves-all')))[0][3] == 'second'
                assert await page.evaluate("document.getElementById('saves-count').textContent") == '(1 of 2)'
                assert 'q=second' in await page.url()

                # restored in instructor mode, as a project of the instructor
                await page.click('#saves-instructor-mode')
                await page.evaluate(button('saves-all', 'Restore'))
                await page.wait_for(ON_PROJECT_PAGE, timeout=20, what="the page of the restored project")
                projects = await (await h.client.get('/api/projects', headers=PROF)).json()
                projects = projects['projects'] if isinstance(projects, dict) else projects
                assert [p['instructor_mode'] for p in projects if p['owner'] == 'prof'] == [True]
        P.run(go())
