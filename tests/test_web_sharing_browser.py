"""The shared projects as the browsers live them: a headless Chrome (``web_browser.py``; skipped
without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one, and without the vendored
xterm.js of ``make xterm``) on the real pages of ``web/`` served by the portal of
test_web_portal.py (proxy mode behind one identity proxy per user, a real agent on the fake
``sre``).  The owner shares a project from its page; another student asks to join from the Open
page; the owner accepts in the banner, on whatever page they are; the project opens for the
student, who works in the owner's terminal, has neither Close nor Save, and is sent out when the
owner removes them.  The cards of the Projects page, the dialog of a project nobody allowed yet,
and the Watch page of the instructors: the Sharing column, its dialog, the selection and its bulk
actions."""
import asyncio
import contextlib
from pathlib import Path
from urllib.parse import quote

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
import test_web_presentation as T                             # noqa: E402  (start_project)
import test_web_sharing as S                                  # noqa: E402  (the harness of the shared projects)
import test_web_terminal_browser as TB                        # noqa: E402  (the terminals of a page)
from sreweb.portal.accesslog import parse_line                # noqa: E402
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
XTERM = WEB / 'static' / 'vendor' / 'xterm' / 'xterm.js'
pytestmark = [pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)"),
              pytest.mark.skipif(not XTERM.is_file(), reason="xterm.js is not vendored: run `make xterm`")]
ALICE, BOB, CAROL, PROF = S.A_ALICE, S.A_BOB, S.A_CAROL, S.A_PROF
run = T.run

# -- what the pages show, as JavaScript expressions ----------------------------------------------

SHARE = "document.getElementById('share-project')"
SHARE_SHOWN = f"!!{SHARE} && !{SHARE}.hidden"
SHARE_TEXT = f"({SHARE} || {{textContent: ''}}).textContent"
DIALOG = "document.querySelector('dialog.share-dialog[open]')"
USERS = ("[...document.querySelectorAll('dialog.share-dialog[open] #share-users li')]"
         ".map((li) => [li.dataset.login, li.classList.contains('connected'), !!li.querySelector('button')])")
BANNER_LINES = ("[...document.querySelectorAll('#share-requests .share-request')]"
                ".map((line) => line.querySelector('.text').textContent)")
TOASTS = "[...document.querySelectorAll('#toasts .toast')].map((t) => t.textContent)"
ENDED = "(() => { const b = document.getElementById('share-ended-banner'); return !!b && !b.hidden; })()"
SHARED_ROWS = ("[...document.querySelectorAll('dialog.shared-labs[open] #shared-labs tbody tr[data-rln]')]"
               ".map((tr) => ({state: tr.dataset.state, cells: [...tr.children].map((td) => td.textContent)}))")
CARDS = ("[...document.querySelectorAll('#projects .card')]"
         ".map((c) => ({shared: c.classList.contains('shared'), title: c.querySelector('h2').textContent, "
         "by: (c.querySelector('.shared-by') || {textContent: ''}).textContent, "
         "buttons: [...c.querySelectorAll('.actions a, .actions button')].map((b) => b.textContent)}))")
# the Watch page: per row, its owner, its Sharing cell and whether it is ticked
WATCH_ROWS = ("[...document.querySelectorAll('#watch tbody tr[data-rln]')].map((tr) => ({"
              "owner: tr.children[2].textContent, sharing: tr.children[15].textContent, "
              "policy: tr.children[15].dataset.policy, ticked: tr.querySelector('td.select input').checked, "
              "closing: tr.classList.contains('row-closing')}))")
SELECTED_TEXT = "document.getElementById('watch-selected').textContent"
BULK = ("Object.fromEntries([...document.querySelectorAll('#watch-selection button[data-action]')]"
        ".map((b) => [b.dataset.action, !b.disabled]))")


def click_in(selector: str, text: str) -> str:
    """Click the first element at *selector* whose text is *text*."""
    return (f"(() => {{ const e = [...document.querySelectorAll({selector!r})].find((x) => x.textContent.trim() === {text!r}); "
            f"if (!e) {{ throw new Error('no ' + {selector!r} + ' saying ' + {text!r}); }} e.click(); return true; }})()")


@contextlib.asynccontextmanager
async def browsing(tmp_path, *identities, allowed='yes-by-default'):
    """The harness of the shared projects on the real web directory, one identity proxy per
    identity and the browser: ``(h, browser, {login: url})``.  Each proxy is an origin of its
    own: the pages of two users never share a storage."""
    h = S.harness(tmp_path, allowed)
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


def project_url(url: str, rln: str) -> str:
    return f'{url}/projects/a01/{quote(rln, safe="")}'


async def project_page(browser, url: str, rln: str):
    page = await browser.page(project_url(url, rln))
    await page.wait_for(TB.TABBAR_SHOWN, what="the tab bar of the project page")
    return page


def bob_lines(tmp_path, event: str) -> int:
    lines = [parse_line(line) for line in (tmp_path / 'access.log').read_text().splitlines()]
    return sum(1 for line in lines if line['event'] == event and line['login'] == 'bob')


class TestSharingAProject:
    def test_share_ask_accept_work_and_remove(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, ALICE, BOB) as (h, browser, urls):
                rln = await T.start_project(h, ALICE)
                await S.polled(h)
                alice = await project_page(browser, urls['alice'], rln)
                # the owner: the Share button, its dialog, whom to share with
                await alice.wait_for(SHARE_SHOWN, what="the Share button of the owner")
                assert await alice.evaluate(SHARE_TEXT) == 'Share'
                await alice.click('#share-project')
                await alice.wait_for(f"!!{DIALOG} && !!document.getElementById('share-start')", what="the Share dialog")
                options = await alice.evaluate("[...document.querySelectorAll('#share-audience option')].map((o) => o.value)")
                assert options == ['all', 'department:INFO1']
                await alice.click('#share-start')
                await alice.wait_for("!!document.getElementById('share-stop')", what="the project shared")
                assert await alice.evaluate(USERS) == [['alice', True, False]]
                await alice.wait_for(f"{SHARE_TEXT} === 'Shared · 1'", what="the button counting the owner")
                await alice.click('#share-close')
                # the owner goes on working in a terminal; they also have another page open elsewhere
                await alice.click('#tabbar [data-tab="terminals"]')
                await alice.wait_for(f"{TB.SUBTABS} === 1", what="the terminal of the owner")
                await TB.type_command(alice, '.terminal-host .xterm-screen', TB.HOST_TEXT, 'echo al$((1+1))ice', 'al2ice')
                elsewhere = await browser.page(f"{urls['alice']}/open", new_window=True)
                await elsewhere.wait_for("document.getElementById('labs') !== null", what="the Open page of the owner")
                # the other student: Open a shared lab, the project listed, Ask to join
                bob = await browser.page(f"{urls['bob']}/open", new_window=True)
                await bob.wait_for("!!document.getElementById('open-shared')", what="the Open a shared lab button")
                await bob.wait_for("document.querySelectorAll('#labs button.lab').length > 0", what="the lab tree")
                await bob.click('#open-shared')
                rows = await bob.wait_for(f"{SHARED_ROWS}.length === 1 && {SHARED_ROWS}", what="the shared project listed")
                assert rows[0]['state'] == 'joinable' and rows[0]['cells'][1] == 'Alice A (alice)'
                assert rows[0]['cells'][2] == 'everybody' and rows[0]['cells'][4] == '0'
                await bob.evaluate(click_in('dialog.shared-labs button', 'Ask to join'))
                await bob.wait_for(f"({SHARED_ROWS}[0] || {{}}).state === 'requested'", what="the request waiting")
                assert 'waiting for Alice A' in (await bob.evaluate(SHARED_ROWS))[0]['cells'][5]
                # the owner is asked on whatever page they are, and accepts
                for page in (elsewhere, alice):
                    lines = await page.wait_for(f"{BANNER_LINES}.length === 1 && {BANNER_LINES}", what="the banner")
                    assert lines[0].startswith('Bob B asks to join ')
                    assert (await page.evaluate('document.title')).startswith('⇄ ')
                await elsewhere.evaluate(click_in('#share-requests button', 'Accept'))
                for page in (elsewhere, alice):
                    await page.wait_for("document.getElementById('share-requests') === null", what="the banner gone")
                    assert not (await page.evaluate('document.title')).startswith('⇄ ')
                # ... and the project opens for the student who asked
                await bob.wait_for(TB.ON_PROJECT_PAGE, what="the project page opened by the acceptance")
                await bob.wait_for(TB.TABBAR_SHOWN, what="the tab bar of the participant's page")
                assert await bob.evaluate("document.body.classList.contains('participating')")
                assert await bob.evaluate("document.getElementById('close-project').hidden") is True
                assert await bob.evaluate("(document.getElementById('save-project') || {hidden: true}).hidden") is True
                assert 'Alice A (alice)' in await bob.evaluate("document.getElementById('project-title').textContent")
                for page in (alice, bob):
                    await page.wait_for(f"{SHARE_TEXT} === 'Shared · 2'", what="both counted on the project")
                # one shell for the two: the participant's page joins the owner's terminal, does
                # not open one of its own, and what they type there the owner sees
                await bob.click('#tabbar [data-tab="terminals"]')
                await bob.wait_for(f"{TB.SUBTABS} === 1", what="the owner's terminal joined")
                await bob.wait_for(f"({TB.HOST_TEXT}).includes('al2ice')", timeout=TB.SHELL_WAIT, what="the replay")
                await TB.type_command(bob, '.terminal-host .xterm-screen', TB.HOST_TEXT, 'echo b$((2+2))ob', 'b4ob')
                await alice.wait_for(f"({TB.HOST_TEXT}).includes('b4ob')", timeout=TB.SHELL_WAIT,
                                     what="what the participant typed, on the owner's page")
                sessions = h.agent.registry.get(rln).terminals
                assert len(sessions) == 1 and next(iter(sessions.values())).writer_count() == 2
                # the participant's dialog: who is there, Leave, nothing to decide
                await bob.click('#share-project')
                await bob.wait_for(f"{USERS}.length === 2", what="the users in the participant's dialog")
                assert await bob.evaluate(USERS) == [['alice', True, False], ['bob', True, False]]
                assert await bob.evaluate("!!document.getElementById('share-leave') && !document.getElementById('share-stop')")
                await bob.click('#share-close')
                # the owner takes them out: their page ends, quietly
                await alice.click('#share-project')
                await alice.wait_for(f"{USERS}.length === 2", what="the users in the owner's dialog")
                assert await alice.evaluate(USERS) == [['alice', True, False], ['bob', True, True]]
                await alice.click('#share-users li[data-login="bob"] button')
                await bob.wait_for(ENDED, what="the participant's page ended")
                assert await bob.evaluate("document.getElementById('panes').hidden && document.getElementById('tabbar').hidden")
                assert await bob.evaluate(f"!{SHARE} || {SHARE}.hidden")
                assert any('taken out of the project of Alice A' in text for text in await bob.evaluate(TOASTS))
                await alice.wait_for(f"{USERS}.length === 1 && {SHARE_TEXT} === 'Shared · 1'", what="the owner alone again")
                # no socket of theirs comes back knocking (each try would log a refused opening)
                before = bob_lines(tmp_path, 'project_open') + bob_lines(tmp_path, 'terminal_open')
                await asyncio.sleep(4)
                assert bob_lines(tmp_path, 'project_open') + bob_lines(tmp_path, 'terminal_open') == before
                # the owner's terminal lives on
                await alice.click('#share-close')
                await TB.type_command(alice, '.terminal-host .xterm-screen', TB.HOST_TEXT, 'echo st$((3+3))ill', 'st6ill')
                for page in (alice, elsewhere):
                    assert page.errors == [], page.errors
        run(scenario())

    def test_cards_of_the_projects_page_and_leave(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, BOB) as (h, browser, urls):
                rln = await T.start_project(h, ALICE)
                mine = await T.start_project(h, BOB)
                await S.share(h, rln)
                page = await browser.page(f"{urls['bob']}/projects")
                await page.wait_for(f"{CARDS}.length === 1", what="bob's own project")
                assert (await page.evaluate(CARDS))[0]['shared'] is False
                # accepted while the page is open: the card comes with the push
                await S.join(h, rln, BOB)
                cards = await page.wait_for(f"{CARDS}.length === 2 && {CARDS}", what="the card of the shared project")
                assert [card['shared'] for card in cards] == [False, True]
                assert cards[1]['by'] == 'Shared by Alice A (alice)' and cards[1]['buttons'] == ['Open', 'Leave']
                assert 'Close Project' in cards[0]['buttons']
                await page.evaluate(click_in('#projects .card.shared button', 'Leave'))
                await page.wait_for(f"{CARDS}.length === 1", what="the card gone")
                assert h.portal.sharing.get('a01', rln).participants == {} and h.agent.registry.get(mine) is not None
                # nothing shared any more: the dialog of the Open page says so
                await S.call(h, 'DELETE', S.base_of(rln) + '/sharing', ALICE)
                await page.goto(f"{urls['bob']}/open")
                await page.wait_for("!!document.getElementById('open-shared')", what="the Open a shared lab button")
                await page.click('#open-shared')
                await page.wait_for("(document.querySelector('dialog.shared-labs[open] td.muted') || {textContent: ''})"
                                    ".textContent === 'Nobody shares a project with you now.'", what="the empty list")
                assert page.errors == [], page.errors
        run(scenario())

    def test_a_project_nobody_allowed_yet(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, ALICE, allowed='no-by-default') as (h, browser, urls):
                rln = await T.start_project(h, ALICE)
                await S.polled(h)
                page = await project_page(browser, urls['alice'], rln)
                await page.wait_for(SHARE_SHOWN, what="the Share button")
                await page.click('#share-project')
                denied = await page.wait_for("(document.getElementById('share-denied') || {textContent: ''}).textContent",
                                             what="why the project cannot be shared")
                assert denied == 'An instructor must allow the sharing of this project first.'
                assert await page.evaluate("!document.getElementById('share-start')")
                # an instructor allows it on the Watch page: the open dialog follows by itself
                status, answer = await S.call(h, 'POST', '/api/watch/sharing', PROF,
                                              json={'projects': [{'host': 'a01', 'rln': rln}], 'policy': 'allowed'})
                assert (status, answer['changed']) == (200, 1)
                await page.wait_for("!!document.getElementById('share-start')", timeout=12, what="the Share control")
                await page.click('#share-start')
                await page.wait_for(f"{SHARE_TEXT} === 'Shared · 1'", what="the project shared")
                # ... then forbids it: the sharing ends under the owner's eyes
                await S.call(h, 'POST', '/api/watch/sharing', PROF,
                             json={'projects': [{'host': 'a01', 'rln': rln}], 'policy': 'forbidden'})
                denied = await page.wait_for("(document.getElementById('share-denied') || {textContent: ''}).textContent",
                                             timeout=12, what="the sharing forbidden")
                assert denied == 'An instructor has forbidden the sharing of this project.'
                await page.wait_for(f"{SHARE_TEXT} === 'Share'", what="the button back to Share")
                assert page.errors == [], page.errors
        run(scenario())


class TestWatchPage:
    def test_sharing_column_dialog_and_bulk_actions(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, PROF) as (h, browser, urls):
                first = await T.start_project(h, ALICE)
                second = await T.start_project(h, CAROL)
                await S.share(h, first)
                await S.join(h, first, BOB)
                page = await browser.page(f"{urls['prof']}/watch")
                rows = await page.wait_for(f"{WATCH_ROWS}.length === 2 && {WATCH_ROWS}", what="the two projects")
                by_owner = {row['owner']: row for row in rows}
                assert by_owner['alice']['sharing'] == 'shared · 1' and by_owner['carol']['sharing'] == 'allowed (default)'
                assert await page.evaluate(BULK) == {'allowed': False, 'forbidden': False, 'default': False, 'close': False}
                # the cell of a row: who is in the project, one of them taken out
                await page.click('#watch tbody tr[data-rln="%s"] td.sharing' % first)
                await page.wait_for(f"{USERS}.length === 2", what="the users of the project")
                assert await page.evaluate(USERS) == [['alice', False, False], ['bob', False, True]]
                assert await page.evaluate("document.querySelector('dialog.watch-detail') === null")   # not the evaluation
                await page.click('#share-users li[data-login="bob"] button')
                await page.wait_for(f"{USERS}.length === 1", what="the participant taken out")
                assert h.portal.sharing.get('a01', first).participants == {}
                # ... the decision of the instructors for it: forbidden ends the sharing
                await page.click('#share-policy input[value="forbidden"]')
                await page.wait_for("(document.getElementById('share-state') || {textContent: ''}).textContent"
                                    " === 'This project is not shared.'", what="the sharing ended")
                assert h.portal.sharing.get('a01', first) is None
                await page.evaluate(click_in('dialog.watch-sharing .buttons button', 'Close'))
                rows = await page.wait_for(f"{WATCH_ROWS}.some((r) => r.policy === 'forbidden') && {WATCH_ROWS}",
                                           what="the row forbidden")
                assert {row['owner']: row['sharing'] for row in rows} == {'alice': 'forbidden', 'carol': 'allowed (default)'}
                # the selection: one row, then the rows shown; it survives the polls of the page
                await page.click('#watch tbody tr[data-rln="%s"] td.select input' % second)
                await page.wait_for(f"{SELECTED_TEXT} === '1 project(s) selected'", what="one project selected")
                assert await page.evaluate("document.querySelector('dialog.watch-detail') === null")
                assert await page.evaluate("document.getElementById('watch-select-all').indeterminate") is True
                await page.click('#watch-select-all')
                await page.wait_for(f"{SELECTED_TEXT} === '2 project(s) selected'", what="both selected")
                await asyncio.sleep(6)                                       # a poll rebuilds the rows
                assert [row['ticked'] for row in await page.evaluate(WATCH_ROWS)] == [True, True]
                assert await page.evaluate(BULK) == {'allowed': True, 'forbidden': True, 'default': True, 'close': True}
                # the sharing of the selection decided at once
                await page.click('#watch-selection button[data-action="allowed"]')
                await page.wait_for(f"{WATCH_ROWS}.every((r) => r.sharing === 'allowed')", what="both allowed")
                assert any(text.startswith('2 project(s) changed') for text in await page.evaluate(TOASTS))
                assert h.portal.sharing.allowed('a01', first) and h.portal.sharing.policy_of('a01', second) == 'allowed'
                await page.click('#watch-selection button[data-action="default"]')
                await page.wait_for(f"{WATCH_ROWS}.every((r) => r.sharing === 'allowed (default)')", what="back to the default")
                # the bulk close: asked first, cancelled, then done
                await page.click('#watch-selection button[data-action="close"]')
                listed = await page.wait_for("[...document.querySelectorAll('dialog.watch-close[open] #watch-close-list li')]"
                                             ".map((li) => li.dataset.rln)", what="the projects to close")
                assert sorted(listed) == sorted([first, second])
                await page.evaluate(click_in('dialog.watch-close .buttons button', 'Cancel'))
                await page.wait_for("document.querySelector('dialog.watch-close') === null", what="the dialog closed")
                assert len(h.agent.registry.projects) == 2
                await page.click('#watch-selection button[data-action="close"]')
                await page.wait_for("!!document.getElementById('watch-close-confirm')", what="the confirmation again")
                await page.click('#watch-close-confirm')
                await page.wait_for(f"{WATCH_ROWS}.length === 0", timeout=30, what="the projects closed")
                await page.wait_for(f"{TOASTS}.some((t) => t.startsWith('2 project(s) closed'))", timeout=15,
                                    what="the outcome of the close")
                await page.wait_for(f"{SELECTED_TEXT} === '0 project(s) selected'", what="the selection emptied")
                await h.agent.registry.tick()
                assert h.agent.registry.projects == {}
                assert page.errors == [], page.errors
        run(scenario())
