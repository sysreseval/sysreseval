"""Select group… of the detail of an exam (the Exams page of an instructor) in a headless Chrome
(``web_browser.py``; skipped without Google Chrome / Chromium): the dialog lists the groups the
members of the exam belong to (their ``groups`` keys in ``GET /api/exams/{id}``: the
departments and the directory groups of the fake directory of test_web_groups.py), the members
of the groups ticked replace the rows checked, and the minutes go to that selection — the page
has no "for all" button any more.  The real pages of ``web/`` served by the portal of
test_web_portal.py, the fake database of test_web_exams.py behind."""
import contextlib

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_exam_browser as B                             # noqa: E402  (the browser, until())
import test_web_exams as X                                    # noqa: E402  (the fake database, api())
import test_web_groups as G                                   # noqa: E402  (the fake directory)
import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from web_browser import Browser, IdentityProxy               # noqa: E402

pytestmark = pytest.mark.skipif(B.CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

PROF = B.PROF
api = X.api
run = B.run
ROWS = "[...document.querySelectorAll('#exam-members tbody tr[data-login]')].map((tr) => tr.dataset.login)"
CHECKED = ("[...document.querySelectorAll('#exam-members tbody tr[data-login]')]"
           ".filter((tr) => tr.querySelector('input[type=checkbox]').checked).map((tr) => tr.dataset.login).sort()")
DIALOG = "document.querySelector('dialog.exam-groups-dialog')"
LISTED = "[...document.querySelectorAll('dialog.exam-groups-dialog .exam-groups > *')].map((n) => n.textContent.trim())"
SELECT = 'dialog.exam-groups-dialog button.primary'
CANCEL = 'dialog.exam-groups-dialog .buttons button:not(.primary)'
BUTTON = "document.getElementById('exam-select-group')"
EXTEND = "document.getElementById('exam-extend-selected')"


@contextlib.asynccontextmanager
async def browsing(tmp_path, identity=PROF):
    """The harness (proxy mode, the fake database, the fake directory, the real web directory)
    and a browser that is *identity*: ``(h, browser, url)``."""
    server = X.FakeExamsServer()
    h = P.Harness(tmp_path, auth_mode='proxy',
                  web_over=X.web_over(tmp_path, auth={**P.PROXY_OVER['auth'], 'ldap': G.LDAP}),
                  db_connect=(server.connect, (X.Down,)), directory_listing=G.FakeListing())
    h.web_dir = B.WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', identity)
        await proxy.start()
        try:
            async with Browser(B.CHROME) as browser:
                yield h, browser, proxy.url
        finally:
            await proxy.close()


async def create_exam(h, logins) -> int:
    status, exam = await api(h, 'POST', '/api/exams', PROF, {
        'title': 'Partiel', 'audience': {'logins': logins}, 'labs': [X.DHCP], 'duration': 30})
    assert status == 201, exam
    return exam['id']


async def pick(page, *keys):
    """Select group…, the groups *keys* ticked, Select."""
    await page.click('#exam-select-group')
    await page.wait_for(f"{DIALOG} !== null", what="the groups dialog")
    for key in keys:
        assert await page.evaluate(f"""(() => {{
            const box = document.querySelector('dialog.exam-groups-dialog input[value="{key}"]');
            box.click();
            return box.checked; }})()"""), key
    await page.click(SELECT)
    await page.wait_for(f"{DIALOG} === null", what="the groups dialog closed")


class TestSelectGroup:
    def test_the_members_of_the_groups_chosen_are_the_selection(self, tmp_path):
        """alice and bob (1A), carol (2B), all three in the directory group etudiants, alice in
        profs too: one group, then another in its place, then two at once; Cancel keeps the
        selection; five minutes for the selection reach its members alone."""
        async def go():
            async with browsing(tmp_path) as (h, browser, url):
                xid = await create_exam(h, ['alice', 'bob', 'carol'])
                status, detail = await api(h, 'GET', f'/api/exams/{xid}', PROF)
                assert status == 200, detail
                assert {m['login']: m['groups'] for m in detail['members']} == {
                    'alice': ['department:1A', 'directory:etudiants', 'directory:profs'],
                    'bob': ['department:1A', 'directory:etudiants'],
                    'carol': ['department:2B', 'directory:etudiants']}
                page = await browser.page(f'{url}/exams?id={xid}')
                await page.wait_for(f"{ROWS}.length === 3", what="the members of the exam")
                # no "for all" button; nothing selected: the minutes are off, the groups offered
                assert await page.evaluate("document.getElementById('exam-extend-all') === null "
                                           "&& document.getElementById('exam-reduce-all') === null")
                assert await page.evaluate(f"{EXTEND}.disabled && !{BUTTON}.disabled")
                assert await page.evaluate(f"{BUTTON}.title") == 'Check the members of one or several groups'
                # the dialog: the groups of the members by kind, with their members in the exam
                await page.click('#exam-select-group')
                await page.wait_for(f"{DIALOG} !== null", what="the groups dialog")
                assert await page.evaluate(LISTED) == ['Departments', '1A (2)', '2B (1)',
                                                       'Directory groups', 'etudiants (3)', 'profs (1)']
                assert await page.evaluate(f"document.querySelector('{SELECT}').disabled")      # nothing ticked
                await page.click(CANCEL)
                await page.wait_for(f"{DIALOG} === null", what="the groups dialog closed")
                assert await page.evaluate(CHECKED) == []
                # one group
                await pick(page, 'department:1A')
                assert await page.evaluate(CHECKED) == ['alice', 'bob']
                assert await page.evaluate(f"!{EXTEND}.disabled")
                assert await page.evaluate("document.getElementById('exam-select-all').indeterminate")
                # another one: in place of the first
                await pick(page, 'department:2B')
                assert await page.evaluate(CHECKED) == ['carol']
                # two at once: their union
                await pick(page, 'department:2B', 'directory:profs')
                assert await page.evaluate(CHECKED) == ['alice', 'carol']
                # cancelled: the selection stays
                await page.click('#exam-select-group')
                await page.wait_for(f"{DIALOG} !== null", what="the groups dialog")
                await page.click(CANCEL)
                await page.wait_for(f"{DIALOG} === null", what="the groups dialog closed")
                assert await page.evaluate(CHECKED) == ['alice', 'carol']
                # the minutes of the selection: its members alone
                await page.click('#exam-extend-selected')
                await B.until(lambda: _extra(h, xid, {'alice': 5, 'bob': 0, 'carol': 5}), 10, "five minutes for the selection")
                assert await page.evaluate(CHECKED) == ['alice', 'carol']
                # everybody: the box of the header
                await pick(page, 'directory:etudiants')
                assert await page.evaluate(CHECKED) == ['alice', 'bob', 'carol']
                assert await page.evaluate("document.getElementById('exam-select-all').checked")
                assert page.errors == []
        run(go())

    def test_no_group_among_the_members(self, tmp_path):
        """A member the directory does not know: no group to offer, the button is off and says why."""
        async def go():
            async with browsing(tmp_path) as (h, browser, url):
                xid = await create_exam(h, ['zoe'])
                page = await browser.page(f'{url}/exams?id={xid}')
                await page.wait_for(f"{ROWS}.length === 1", what="the member of the exam")
                assert await page.evaluate(f"{BUTTON}.disabled")
                assert await page.evaluate(f"{BUTTON}.title") == 'no group among the members'
                assert page.errors == []
        run(go())


async def _extra(h, xid, expected) -> bool:
    members = (await api(h, 'GET', f'/api/exams/{xid}', PROF))[1]['members']
    return {m['login']: m['extra_minutes'] for m in members} == expected
