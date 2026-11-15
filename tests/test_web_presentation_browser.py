"""The presenter's mouse pointer and selection on a spectator's page, as a browser lives them: a
headless Chrome (``web_browser.py``; skipped without Google Chrome / Chromium, ``SRE_TEST_CHROME``
names one, and without the vendored xterm.js of ``make xterm``) on the real pages of ``web/``
served by the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on
the fake ``sre``, whose ``connect`` is a /bin/sh on a pty).  An instructor presents a project to
a student, each page in a window of its own (two computers: a hidden tab draws no xterm row):
the arrow labelled with the instructor's name follows their mouse over the Informations text on
the student's page, the text they select there is highlighted on the student's page; in a
floating terminal the student's read-only terminal has the instructor's grid, the arrow points at
the same cell and the text selected is selected on the same row; the pointer goes when the mouse
leaves the panes, the selection when the instructor clicks.

And an instructor of the audience, who is not kept under the presentation as a student is: the
Leave button of the presented page gives their own page back, a notice bar brings the
presentation back, in every tab of their browser, while the student stays covered."""
import asyncio

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (who, CSRF)
import test_web_presentation as T                             # noqa: E402  (start_project, present)
from test_web_terminal_browser import (browsing, project_page, point_in, type_command, until, no_errors,   # noqa: E402
                                       WINDOW_STATUS, WINDOW_TEXT, SHELL_WAIT, PROF, ALICE, CHROME, XTERM)

pytestmark = [pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)"),
              pytest.mark.skipif(not XTERM.is_file(), reason="xterm.js is not vendored: run `make xterm`")]
run = T.run

PARAGRAPH = '#panes .pane:not([hidden]) .content p'       # the paragraph of the mock lab's Informations text
SPECTATOR_DOC = "document.querySelector('#presentation-overlay iframe').contentDocument"
PRESENTED_PAGE_SHOWN = (f"(() => {{ const f = document.querySelector('#presentation-overlay iframe'); const d = f && {SPECTATOR_DOC}; "
                        f"return Boolean(d && d.querySelectorAll('#tabbar [role=tab]').length > 0); }})()")
OUTPUT = 'sel1ect'                                         # what the command typed in the terminal prints
PROF2 = P.who('prof2', 'Pr. Two', groups=P.TEACHERS)      # a second instructor: followed, or in an audience
OVERLAY = "Boolean(document.getElementById('presentation-overlay'))"
# the Leave button of the presented page: true when shown, false when hidden, null without one
LEAVE = (f"(() => {{ const f = document.querySelector('#presentation-overlay iframe'); const d = f && {SPECTATOR_DOC}; "
         f"const b = d && d.getElementById('leave-presentation'); return b ? !b.hidden : null; }})()")
LEFT = "window.localStorage.getItem('sreweb.presentation.left')"


def notice_of(element_id: str) -> str:
    """A notice bar of an instructor's page (base.html): ``{hidden, text, href}``, null without one."""
    return (f"(() => {{ const n = document.getElementById({element_id!r}); if (!n) {{ return null; }} "
            f"const a = n.querySelector('a'); "
            f"return {{hidden: n.hidden, text: n.querySelector('.text').textContent, href: a ? a.getAttribute('href') : null}}; }})()")


def notice_shown(element_id: str, path: str) -> str:
    """The notice bar shown on the page at *path* (its state, else null)."""
    return (f"(() => {{ const n = {notice_of(element_id)}; "
            f"return window.location.pathname === {path!r} && n && !n.hidden ? n : null; }})()")


def rect_of(selector: str) -> str:
    return (f"(() => {{ const e = document.querySelector({selector!r}); if (!e) {{ return null; }} "
            f"const r = e.getBoundingClientRect(); "
            f"return {{left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height}}; }})()")


def terminal_state(document: str, selector: str) -> str:
    """The terminal box at *selector* of *document* (a JavaScript expression): the number of rows
    of its grid, the rect of the row showing OUTPUT, the rects of the selection xterm draws, its
    non-empty rows (for the message of a failed wait), whether it has the keyboard focus, and the
    tip of the presenter's pointer of that document when it is shown."""
    return f"""(() => {{ const d = {document}; const box = d && d.querySelector({selector!r}); if (!box) {{ return null; }}
  const rect = (e) => {{ const r = e.getBoundingClientRect(); return {{left: r.left, top: r.top, width: r.width, height: r.height}}; }};
  const rows = [...box.querySelectorAll('.xterm-rows > div')];
  const output = rows.find((r) => r.textContent.includes({OUTPUT!r}));
  const pointer = d.getElementById('presenter-pointer');
  return {{rows: rows.length, row: output ? rect(output) : null,
          selection: [...box.querySelectorAll('.xterm-selection div')].map(rect).filter((r) => r.height > 0),
          text: rows.map((r, i) => i + ':' + r.textContent.trimEnd()).filter((t) => !t.endsWith(':')),
          focus: Boolean(box.querySelector('.xterm.focus')),
          pointer: pointer && !pointer.hidden ? {{x: pointer.getBoundingClientRect().left, y: pointer.getBoundingClientRect().top}} : null}};
}})()"""


PRESENTER_TERMINAL = terminal_state('document', '.terminal-window')
SPECTATOR_TERMINAL = terminal_state(SPECTATOR_DOC, '.terminal-window.readonly')
# the presenter's pointer on the student's page (its tip is the top-left corner of the element),
# the paragraph of the Informations text there, and the text highlighted as the presenter's
# selection ('' without one)
SPECTATOR_POINTER = f"""(() => {{ const d = {SPECTATOR_DOC}; if (!d) {{ return null; }}
  const p = d.getElementById('presenter-pointer'); if (!p) {{ return null; }}
  const r = p.getBoundingClientRect(); const para = d.querySelector({PARAGRAPH!r});
  const pr = para ? para.getBoundingClientRect() : null;
  return {{hidden: p.hidden, x: r.left, y: r.top, label: (p.querySelector('.label') || {{textContent: ''}}).textContent,
          para: pr ? {{left: pr.left, top: pr.top, right: pr.right, bottom: pr.bottom}} : null}}; }})()"""
SPECTATOR_HIGHLIGHT = f"""(() => {{ const d = {SPECTATOR_DOC}; if (!d) {{ return null; }} const w = d.defaultView;
  if (w.CSS && w.CSS.highlights) {{ const h = w.CSS.highlights.get('presenter-selection');
    return h ? [...h].map((r) => r.toString()).join('|') : ''; }}
  return d.getSelection().toString(); }})()"""


class TestPresenterPointerAndSelection:
    def test_pointer_and_selection_follow_the_presenter(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, PROF, ALICE) as (h, browser, urls):
                rln = await T.start_project(h, PROF)
                await T.present(h, PROF, rln, ['alice'])              # before the page loads: resume()
                prof = await project_page(browser, urls['prof'], rln)
                alice = await browser.page(f"{urls['alice']}/projects", new_window=True)
                await alice.wait_for(PRESENTED_PAGE_SHOWN, timeout=15.0, what="the presented page on the student's page")
                visible = "document.visibilityState === 'visible'"
                assert await prof.evaluate(visible) and await alice.evaluate(visible)

                async def terminals():
                    return f"the presenter's terminal {await prof.evaluate(PRESENTER_TERMINAL)}, " \
                           f"the student's {await alice.evaluate(SPECTATOR_TERMINAL)}"

                # the pointer over a paragraph of the Informations text: the arrow with the name, on
                # the same paragraph of the student's page
                await prof.click('#tabbar [data-tab="informations"]')
                at = await prof.wait_for(point_in(PARAGRAPH), what="a visible point of the Informations paragraph")
                await prof.hover(at['x'], at['y'])

                async def pointed():
                    seen = await alice.evaluate(SPECTATOR_POINTER)
                    if not seen or seen['hidden'] or not seen['para']:
                        return None
                    para = seen['para']
                    inside = para['left'] - 4 <= seen['x'] <= para['right'] + 4 and para['top'] - 4 <= seen['y'] <= para['bottom'] + 4
                    return seen if inside else None
                seen = await until(pointed, 10.0, "the presenter's pointer over the paragraph on the student's page")
                assert seen['label'] == 'Pr. Of', seen
                # the text selected in the paragraph (a drag over its first line): highlighted on the
                # student's page, the same text
                r = await prof.evaluate(rect_of(PARAGRAPH))
                y = r['top'] + min(r['height'] / 4, 8)
                await prof.drag(r['left'] + 2, y, r['left'] + r['width'] / 2, y)
                expected = await prof.wait_for("document.getSelection().toString()", what="a selection on the presenter's page")
                assert expected.strip(), expected

                async def highlighted():
                    return await alice.evaluate(SPECTATOR_HIGHLIGHT) == expected
                await until(highlighted, 10.0, f"the highlight of {expected!r} on the student's page")
                # a floating terminal: the student's read-only one has the same grid (the pty has the
                # size of the presenter's terminal)
                await prof.click('#tabbar [data-tab="machines"]')
                await prof.click('.machines button.connect')
                await prof.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the presenter's terminal")
                await type_command(prof, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo sel$((1))ect', OUTPUT)

                async def same_grid():
                    a, b = await alice.evaluate(SPECTATOR_TERMINAL), await prof.evaluate(PRESENTER_TERMINAL)
                    return a is not None and b is not None and a['row'] is not None and a['rows'] == b['rows']
                try:
                    await until(same_grid, SHELL_WAIT, "the grid of the presenter's terminal on the student's page")
                except AssertionError as e:
                    raise AssertionError(f"{e}; {await terminals()}") from None
                # the pointer over the output row: on the same row and column of the student's terminal
                row = (await prof.evaluate(PRESENTER_TERMINAL))['row']
                ry = row['top'] + row['height'] / 2
                fx = 0.04                                             # of the row's width: within its first cells
                await prof.hover(row['left'] + row['width'] * fx, ry)

                async def pointed_in_terminal():
                    seen = await alice.evaluate(SPECTATOR_TERMINAL)
                    if not seen or not seen['row'] or not seen['pointer']:
                        return None
                    r, p = seen['row'], seen['pointer']
                    on_row = r['top'] - 2 <= p['y'] <= r['top'] + r['height'] + 2
                    return seen if on_row and abs((p['x'] - r['left']) / r['width'] - fx) <= 0.02 else None
                try:
                    await until(pointed_in_terminal, 10.0, "the pointer on the output row of the student's terminal")
                except AssertionError as e:
                    raise AssertionError(f"{e}; {await terminals()}") from None
                # the text selected on the output row: selected on the same row of the student's
                # terminal, in the colour of an unfocused terminal; the page's highlight gone
                await prof.drag(row['left'] + 1, ry, row['left'] + row['width'] * 0.3, ry)
                await prof.wait_for("document.querySelectorAll('.terminal-window .xterm-selection div').length > 0",
                                    what="a selection in the presenter's terminal")

                async def mirrored():
                    seen = await alice.evaluate(SPECTATOR_TERMINAL)
                    if not seen or not seen['selection'] or not seen['row']:
                        return None
                    return seen if abs(seen['selection'][0]['top'] - seen['row']['top']) <= 2 else None
                try:
                    seen = await until(mirrored, SHELL_WAIT, "the selection on the output row of the student's terminal")
                except AssertionError as e:
                    raise AssertionError(f"{e}; {await terminals()}") from None
                assert seen['focus'] is False, seen
                assert await alice.evaluate(SPECTATOR_HIGHLIGHT) == ''        # the latest selection wins
                # the mouse away from the panes: the pointer hidden; a click in the terminal: the
                # selection gone
                title = await prof.evaluate(rect_of('#project-title'))
                await prof.hover(title['left'] + 5, title['top'] + title['height'] / 2)

                async def hidden():
                    seen = await alice.evaluate(SPECTATOR_POINTER)
                    return seen is not None and seen['hidden']
                await until(hidden, 10.0, "the pointer hidden on the student's page")
                await prof.click_at(row['left'] + row['width'] * 0.6, ry)

                async def cleared():
                    seen = await alice.evaluate(SPECTATOR_TERMINAL)
                    return seen is not None and not seen['selection']
                await until(cleared, 10.0, "the selection gone from the student's terminal")
                no_errors(prof)
                no_errors(alice)
        run(scenario())


class TestInstructorInTheAudience:
    def test_an_instructor_may_leave_and_come_back(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, PROF, PROF2, ALICE) as (h, browser, urls):
                rln = await T.start_project(h, PROF)
                pid = (await T.present(h, PROF, rln, ['alice', 'prof2']))['id']     # before the page loads: resume()
                prof = await project_page(browser, urls['prof'], rln)
                two = await browser.page(f"{urls['prof2']}/watch", new_window=True)
                alice = await browser.page(f"{urls['alice']}/projects", new_window=True)
                notice = notice_of('presentation-notice')

                async def watching(n: int):
                    resp = await h.client.get(f'/api/presentations/{pid}', headers=PROF)
                    return (await resp.json())['connected'] == n

                # both are covered by the presented project; the Leave button is the instructor's
                await two.wait_for(PRESENTED_PAGE_SHOWN, timeout=15.0, what="the presented page on the instructor's page")
                await alice.wait_for(PRESENTED_PAGE_SHOWN, timeout=15.0, what="the presented page on the student's page")
                await two.wait_for(f"{LEAVE} === true", what="the Leave button of the presented page of an instructor")
                assert await alice.evaluate(LEAVE) is None and await alice.evaluate(notice) is None
                assert (await two.evaluate(notice))['hidden'] and await two.evaluate(LEFT) is None
                await until(lambda: watching(2), 10.0, "two spectators watching")
                # they leave: their own page is back, the notice names the presenter
                await two.evaluate(f"{SPECTATOR_DOC}.getElementById('leave-presentation').click()")
                seen = await two.wait_for(notice_shown('presentation-notice', '/watch'), what="the notice of the presentation")
                assert 'Pr. Of' in seen['text'] and not await two.evaluate(OVERLAY), seen
                assert not await two.evaluate("document.body.classList.contains('has-presentation')")
                assert await two.evaluate(LEFT) == pid
                await until(lambda: watching(1), 10.0, "the student alone watching")
                # free to go elsewhere: another page is not covered, and shows the notice too
                await two.goto(f"{urls['prof2']}/projects")
                await two.wait_for(notice_shown('presentation-notice', '/projects'), what="the notice on another page")
                await asyncio.sleep(1.0)
                assert not await two.evaluate(OVERLAY) and await two.evaluate("window.location.pathname") == '/projects'
                # a page opened in another tab meanwhile: told of the presentation, left there too
                other = await browser.page(f"{urls['prof2']}/open", new_window=True)
                await other.wait_for(notice_shown('presentation-notice', '/open'), what="the notice in another tab")
                assert not await other.evaluate(OVERLAY)
                # they come back: the presentation again, in both tabs
                await two.click('#presentation-notice button')
                await two.wait_for(PRESENTED_PAGE_SHOWN, timeout=15.0, what="the presented page again")
                await other.wait_for(PRESENTED_PAGE_SHOWN, timeout=15.0, what="the presented page in the other tab")
                assert (await two.evaluate(notice))['hidden'] and await two.evaluate(LEFT) is None
                # ... and leave again, from the other tab: both tabs are free
                await other.wait_for(f"{LEAVE} === true", what="the Leave button in the other tab")
                await other.evaluate(f"{SPECTATOR_DOC}.getElementById('leave-presentation').click()")
                await other.wait_for(notice_shown('presentation-notice', '/open'), what="the notice back in the other tab")
                await two.wait_for(notice_shown('presentation-notice', '/projects'), what="the notice back in the first tab")
                assert not await two.evaluate(OVERLAY) and not await other.evaluate(OVERLAY)
                # the student never left
                assert await alice.evaluate(PRESENTED_PAGE_SHOWN) and await alice.evaluate(LEAVE) is None
                # the presentation ends: the notices go, the student's page is back
                resp = await h.client.delete(f'/api/presentations/{pid}', headers={**PROF, **P.CSRF})
                assert resp.status == 200, await resp.text()
                gone = f"(() => {{ const n = {notice}; return Boolean(n && n.hidden) && !{OVERLAY}; }})()"
                await two.wait_for(gone, what="the notice gone with the presentation")
                await other.wait_for(gone, what="the notice gone in the other tab")
                await alice.wait_for(f"!{OVERLAY}", what="the student's page uncovered")
                assert await two.evaluate(LEFT) is None                   # nothing kept of a presentation over
                for page in (prof, two, other, alice):
                    no_errors(page)
        run(scenario())
