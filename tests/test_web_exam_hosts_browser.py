"""The machines of an exam in the browsers (a headless Chrome, ``web_browser.py``; skipped
without Google Chrome / Chromium): the Exams page of an instructor — the Machines fieldset of
the form (the checkboxes grouped by room, the two delays), the machines table of the detail,
minutes and Close for a checked machine — and the pages of a student logged in at the keyboard
of a machine of their exam (the bar naming the workstation, no automatic start).  The real
pages of ``web/`` served by the portal of test_web_portal.py, a real agent on the fake ``sre``
behind: ``exam.json`` in its pub directory is what the Qt GUI would read."""
import contextlib

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_exam_browser as B                             # noqa: E402  (the expressions, until())
import test_web_exam_hosts as H                               # noqa: E402  (the local session, the exam file)
import test_web_exams as X                                    # noqa: E402
from SRE import params                                        # noqa: E402
from web_browser import Browser, IdentityProxy               # noqa: E402

pytestmark = pytest.mark.skipif(B.CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

ALICE, PROF = B.ALICE, B.PROF
api = X.api
run = B.run
LOCAL = "document.body.classList.contains('exam-local')"
MACHINE_ROWS = """[...document.querySelectorAll('#exam-machines tbody tr')].map((tr) => ({
    name: tr.dataset.machine, phase: (tr.className.match(/phase-(\\w+)/) || [])[1] || '',
    cells: [...tr.cells].map((td) => td.textContent.trim()),
    checkbox: tr.querySelector('input[type=checkbox]').disabled ? 'disabled' : 'enabled'}))"""
EXAM_ROWS = "[...document.querySelectorAll('#exams tbody tr[data-id]')].map((tr) => [...tr.cells].map((td) => td.textContent.trim()))"


@contextlib.asynccontextmanager
async def browsing(tmp_path, identity, **harness_over):
    """The harness (proxy mode, the fake database, the real web directory) and a browser that
    is *identity*: ``(h, browser, url)``."""
    h = X.harness(tmp_path, X.FakeExamsServer(), **harness_over)
    h.web_dir = B.WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', identity)
        await proxy.start()
        try:
            async with Browser(B.CHROME) as browser:
                yield h, browser, proxy.url
        finally:
            await proxy.close()


class TestInstructor:
    def test_an_exam_on_a_machine_from_the_page(self, tmp_path):
        """New exam with the machine a01 and no audience: the agent writes ``exam.json``, the
        detail lists the machine; five minutes for it, then Close."""
        async def go():
            async with browsing(tmp_path, PROF) as (h, browser, url):
                page = await browser.page(url + '/exams')
                await page.evaluate("window.confirm = () => true")
                await page.click('#exams-new')
                await page.wait_for("document.querySelector('#exam-hosts input[value=\"a01\"]') !== null "
                                    "&& document.querySelector('#exam-labs input[value=\"sre/dhcp.py\"]') !== null",
                                    what="the machines and the labs of the form")
                # the machines by room, the delays of [exams]
                groups = await page.evaluate("[...document.querySelectorAll('#exam-hosts .exam-host-group')]"
                                             ".map((g) => g.textContent.trim())")
                assert groups == ['aa01']                               # the group "a", its machine a01
                assert await page.evaluate("[document.getElementById('exam-host-lead').value, "
                                           "document.getElementById('exam-host-release').value]") == ['10', '10']
                # machines without an end-before time: refused before the request
                await page.evaluate("""(() => {
                    document.getElementById('exam-title').value = 'Partiel en salle';
                    document.getElementById('exam-duration').value = '30';
                    document.querySelector('#exam-hosts .exam-host-all input').click();     // every machine of "a"
                    document.querySelector('#exam-labs input[value="sre/dhcp.py"]').click();
                    return true; })()""")
                assert await page.evaluate("document.querySelector('#exam-hosts input[value=\"a01\"]').checked")
                await page.click('#exam-form-submit')
                await page.wait_for("!document.getElementById('exam-form-error').hidden", what="the error of the form")
                assert 'end-before time is required when machines' in \
                    await page.evaluate("document.getElementById('exam-form-error').textContent")
                assert not H.exam_file(h).exists()
                await page.evaluate("""(() => {
                    const pad = (n) => String(n).padStart(2, '0');
                    const d = new Date(Date.now() + 2 * 3600 * 1000);
                    document.getElementById('exam-end-before').value =
                        `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
                    document.getElementById('exam-host-release').value = '3';
                    return true; })()""")
                await page.click('#exam-form-submit')
                await page.wait_for("!document.getElementById('exam-detail').hidden "
                                    f"&& {MACHINE_ROWS}.length === 1 && {MACHINE_ROWS}[0].phase === 'starting'",
                                    15, what="the machine of the new exam")
                data = H.stored(h)
                assert data[params.exam_web][params.exam_web_title] == 'Partiel en salle'
                assert data[params.exam_duration] == 30 and data[params.exam_labs] == [['sre/dhcp.py', None]]
                row = (await page.evaluate(MACHINE_ROWS))[0]
                assert row['name'] == 'a01' and row['cells'][1] == 'a01' and row['cells'][4].startswith('starting')
                assert row['checkbox'] == 'enabled'
                assert not await page.evaluate("document.getElementById('exam-machines-section').hidden")
                summary = await page.evaluate("document.getElementById('exam-detail-summary').textContent")
                assert '1 machine(s), locked 10 min before, released 3 min after the end' in summary
                listed = await page.evaluate(EXAM_ROWS)
                assert listed[0][0] == 'Partiel en salle' and listed[0][8] == 'a01' and listed[0][7] == '0'
                # nothing selected: the buttons of the selection are off; the machine checked: on
                assert await page.evaluate("document.getElementById('exam-extend-selected').disabled")
                await page.click('#exam-machines tbody input[type=checkbox]')
                await page.wait_for("!document.getElementById('exam-extend-selected').disabled", what="the selection")
                assert await page.evaluate("document.getElementById('exam-labs-selected').disabled")   # no member
                await page.click('#exam-extend-selected')
                await B.until(lambda: _duration(h, 35), 10, "five more minutes in the file of the machine")
                await page.wait_for(f"{MACHINE_ROWS}[0].cells[8] === '+5'", what="the extra minutes of the machine")
                # closed: the file removed by the agent, the row closed for good
                await page.click('#exam-close-projects')
                await B.until(lambda: _gone(h), 15, "the exam file removed")
                await page.wait_for(f"{MACHINE_ROWS}[0].phase === 'closed' && {MACHINE_ROWS}[0].checkbox === 'disabled'",
                                    15, what="the machine closed")
                assert await page.evaluate("document.getElementById('exam-extend-selected').disabled")
                assert page.errors == []
        run(go())


async def _duration(h, minutes) -> bool:
    return H.exam_file(h).exists() and H.stored(h)[params.exam_duration] == minutes


async def _gone(h) -> bool:
    return not H.exam_file(h).exists()


class TestStudent:
    def test_a_student_at_the_machine_is_sent_to_it(self, tmp_path):
        """Alice is logged in at the keyboard of a01, a machine of her exam: her pages say so,
        show no project and start none; the machine closed, her usual pages are back."""
        async def go():
            async with browsing(tmp_path, ALICE, agent_over={'occupied_check': 'sessions'}) as (h, browser, url):
                h.agent.run_command = H.local_session('alice')
                h.agent._occupancy = None
                spy = X.Spy(h.portal.relay)
                status, exam = await api(h, 'POST', '/api/exams', PROF, H.body(audience=['alice']))
                assert status == 201 and H.exam_file(h).exists()
                await h.portal.pool.refresh()
                page = await browser.page(url + '/projects')
                await page.wait_for(LOCAL, what="the exam taken at the workstation")
                bar = await page.evaluate(B.BAR)
                assert 'Partiel' in bar and 'you take it on the workstation a01' in bar
                assert await page.evaluate(B.COUNTDOWN) == ''
                assert 'You take the exam on the workstation a01' in await page.evaluate(B.NOTE)
                assert await page.evaluate(B.CARDS) == [] and await page.evaluate(B.OPEN_LINK_HIDDEN)
                # past the jitter of the automatic starts: nothing was started for her
                await page.wait_for("new Promise((resolve) => setTimeout(() => resolve(true), 7000))", 12,
                                    what="the delay of an automatic start")
                assert spy.starts == [] and await page.evaluate(LOCAL)
                # the Open page is refused like any page out of the exam
                await page.goto(url + '/open')
                await page.wait_for(B.ON_PROJECTS_PAGE, what="the Open page sent back")
                # the exam closed on the machine: unbound
                status, _ = await api(h, 'POST', f"/api/exams/{exam['id']}/close-projects", PROF, {'hosts': ['a01']})
                assert status == 200
                await page.wait_for(f"!{B.BOUND}", what="the usual pages back")
                assert await page.evaluate(B.BAR) == ''
                assert page.errors == []
        run(go())
