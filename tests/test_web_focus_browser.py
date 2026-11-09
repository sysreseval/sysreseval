"""The instructor's mouse pointer and selection on the student's page while the instructor
focuses the student on the project, as a browser lives them: a headless Chrome (``web_browser.py``;
skipped without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one, and without the vendored
xterm.js of ``make xterm``) on the real pages of ``web/`` served by the portal of
test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake ``sre``, whose
``connect`` is a /bin/sh on a pty).  A student has a project with a terminal in a window, an
instructor opens it and turns *Focus student on project* on, each page in a window of its own:
the arrow labelled with the instructor's name follows their mouse over the Informations text on
the student's page and over the button of the same tab of the tab bar, the text they select is
highlighted there; in the student's terminal, which the instructor's page joined, the arrow is on
the same row and the text selected is selected on that row; nothing shows of the instructor's
private terminal; the arrow goes with the focus."""
import asyncio
from urllib.parse import quote

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_presentation as T                             # noqa: E402  (start_project)
from test_web_terminal_browser import (browsing, project_page, point_in, type_command, until, no_errors,   # noqa: E402
                                       TABBAR_SHOWN, SELECTED_TAB, WINDOW_STATUS, WINDOW_TEXT, WINDOWS, SHELL_WAIT,
                                       PROF, ALICE, CHROME, XTERM)
from test_web_presentation_browser import rect_of, terminal_state, PARAGRAPH, OUTPUT          # noqa: E402

pytestmark = [pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)"),
              pytest.mark.skipif(not XTERM.is_file(), reason="xterm.js is not vendored: run `make xterm`")]
run = T.run

DOCKED = '.terminal-host .terminal-box:not([hidden])'      # the sub-tab shown of the Terminals tab
INSTRUCTOR_TERMINAL = terminal_state('document', DOCKED)   # the student's session joined by the instructor's page
STUDENT_TERMINAL = terminal_state('document', '.terminal-window')
FOCUSED = "document.body.classList.contains('focused') && Boolean(document.getElementById('presenter-pointer'))"
# the instructor's pointer on the student's page (its tip is the top-left corner of the element)
POINTER = """(() => { const p = document.getElementById('presenter-pointer'); if (!p) { return null; }
  const r = p.getBoundingClientRect();
  return {hidden: p.hidden, x: r.left, y: r.top, label: (p.querySelector('.label') || {textContent: ''}).textContent}; })()"""
# the text highlighted as the instructor's selection ('' without one)
HIGHLIGHT = """(() => { if (window.CSS && CSS.highlights) { const h = CSS.highlights.get('presenter-selection');
    return h ? [...h].map((r) => r.toString()).join('|') : ''; }
  return document.getSelection().toString(); })()"""


class TestFocusPointerAndSelection:
    def test_pointer_and_selection_follow_the_instructor(self, tmp_path):
        async def scenario():
            async with browsing(tmp_path, PROF, ALICE) as (h, browser, urls):
                rln = await T.start_project(h, ALICE)
                prof = await project_page(browser, urls['prof'], rln)
                alice = await browser.page(f"{urls['alice']}/projects/a01/{quote(rln, safe='')}", new_window=True)
                await alice.wait_for(TABBAR_SHOWN, what="the tab bar of the student's page")
                # the student's terminal, in a window, with a line of output
                await alice.click('#tabbar [data-tab="machines"]')
                await alice.click('.machines button.connect')
                await alice.wait_for(f"{WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT, what="the student's terminal")
                await type_command(alice, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo sel$((1))ect', OUTPUT)
                visible = "document.visibilityState === 'visible'"
                assert await prof.evaluate(visible) and await alice.evaluate(visible)
                assert await alice.evaluate("document.getElementById('presenter-pointer')") is None
                await prof.wait_for("!document.getElementById('focus-student').hidden", what="the Focus button")
                await prof.click('#focus-student')
                await alice.wait_for(FOCUSED, what="the student's page followed, with a pointer view")

                async def pointer_in(selector: str, what: str):
                    """The instructor's pointer shown inside the element at *selector* of the student's page."""
                    async def check():
                        seen, r = await alice.evaluate(POINTER), await alice.evaluate(rect_of(selector))
                        if not seen or seen['hidden'] or not r:
                            return None
                        inside = r['left'] - 4 <= seen['x'] <= r['right'] + 4 and r['top'] - 4 <= seen['y'] <= r['bottom'] + 4
                        return seen if inside else None
                    return await until(check, 10.0, what)

                async def hidden():
                    seen = await alice.evaluate(POINTER)
                    return seen is not None and seen['hidden']

                # the pointer over a paragraph of the Informations text (the student's page follows
                # the tab): the arrow with the instructor's name on the same paragraph
                await prof.click('#tabbar [data-tab="informations"]')
                await alice.wait_for(f"{SELECTED_TAB} === 'informations'", what="the Informations tab on the student's page")
                at = await prof.wait_for(point_in(PARAGRAPH), what="a visible point of the Informations paragraph")
                await prof.hover(at['x'], at['y'])
                seen = await pointer_in(PARAGRAPH, "the instructor's pointer over the paragraph on the student's page")
                assert seen['label'] == 'Pr. Of', seen
                # the text selected in the paragraph: highlighted on the student's page, whose own
                # selection is left alone
                r = await prof.evaluate(rect_of(PARAGRAPH))
                y = r['top'] + min(r['height'] / 4, 8)
                await prof.drag(r['left'] + 2, y, r['left'] + r['width'] / 2, y)
                expected = await prof.wait_for("document.getSelection().toString()", what="a selection on the instructor's page")
                assert expected.strip(), expected

                async def highlighted():
                    return await alice.evaluate(HIGHLIGHT) == expected
                await until(highlighted, 10.0, f"the highlight of {expected!r} on the student's page")
                # the pointer over a button of the tab bar: on the button of the same tab of the
                # student's page (the two pages do not list the same tabs)
                button = '#tabbar [data-tab="networks"]'
                at = await prof.wait_for(point_in(button), what="a visible point of the Networks tab button")
                await prof.hover(at['x'], at['y'])
                await pointer_in(button, "the instructor's pointer over the Networks button of the student's page")
                # the student's terminal, joined by the instructor's page when its Terminals tab
                # opens: the pointer over the output row is on that row of the student's terminal
                await prof.click('#tabbar [data-tab="terminals"]')

                async def joined():
                    seen = await prof.evaluate(INSTRUCTOR_TERMINAL)
                    return seen if seen and seen['row'] else None
                row = (await until(joined, SHELL_WAIT, "the student's terminal on the instructor's page"))['row']
                ry = row['top'] + row['height'] / 2
                await prof.hover(row['left'] + row['width'] * 0.04, ry)

                async def terminals():
                    return f"the instructor's terminal {await prof.evaluate(INSTRUCTOR_TERMINAL)}, " \
                           f"the student's {await alice.evaluate(STUDENT_TERMINAL)}"

                async def pointed_in_terminal():
                    seen = await alice.evaluate(STUDENT_TERMINAL)
                    if not seen or not seen['row'] or not seen['pointer']:
                        return None
                    r, p = seen['row'], seen['pointer']
                    return seen if r['top'] - 2 <= p['y'] <= r['top'] + r['height'] + 2 and p['x'] >= r['left'] - 2 else None
                try:
                    await until(pointed_in_terminal, 10.0, "the pointer on the output row of the student's terminal")
                except AssertionError as e:
                    raise AssertionError(f"{e}; {await terminals()}") from None
                # the text selected on the output row: selected on the same row of the student's
                # terminal; the highlight of the page gone (the latest selection wins)
                await prof.drag(row['left'] + 1, ry, row['left'] + row['width'] * 0.3, ry)
                await prof.wait_for(f"document.querySelectorAll({DOCKED + ' .xterm-selection div'!r}).length > 0",
                                    what="a selection in the instructor's terminal")

                async def mirrored():
                    seen = await alice.evaluate(STUDENT_TERMINAL)
                    if not seen or not seen['selection'] or not seen['row']:
                        return None
                    return seen if abs(seen['selection'][0]['top'] - seen['row']['top']) <= 2 else None
                try:
                    await until(mirrored, SHELL_WAIT, "the selection on the output row of the student's terminal")
                except AssertionError as e:
                    raise AssertionError(f"{e}; {await terminals()}") from None
                assert await alice.evaluate(HIGHLIGHT) == ''
                # a click in the instructor's terminal: the selection gone from the student's
                await prof.click_at(row['left'] + row['width'] * 0.6, ry)

                async def cleared():
                    seen = await alice.evaluate(STUDENT_TERMINAL)
                    return seen is not None and not seen['selection']
                await until(cleared, 10.0, "the selection gone from the student's terminal")
                # a private terminal of the instructor (the Connect button of a helper): the pointer
                # shown on the Machines tab is hidden over it, nothing of it is selected
                await prof.click('#tabbar [data-tab="machines"]')
                await alice.wait_for(f"{SELECTED_TAB} === 'machines'", what="the Machines tab on the student's page")
                at = await prof.wait_for(point_in('.machines button.connect'), what="the Connect button")
                await prof.hover(at['x'], at['y'])
                await pointer_in('#panes .pane:not([hidden])', "the instructor's pointer on the Machines tab of the student's page")
                await prof.click_at(at['x'], at['y'])
                await prof.wait_for(f"{WINDOWS} === 1 && {WINDOW_STATUS} === 'Connected.'", timeout=SHELL_WAIT,
                                    what="the instructor's private terminal")
                assert 'private' in await prof.evaluate("document.querySelector('.terminal-window .terminal-window-title .title').textContent")
                await type_command(prof, '.terminal-window .xterm-screen', WINDOW_TEXT, 'echo pri$((1))vate', 'pri1vate')
                screen = await prof.evaluate(rect_of('.terminal-window .xterm-screen'))
                await prof.hover(screen['left'] + screen['width'] / 2, screen['top'] + screen['height'] / 2)
                await until(hidden, 10.0, "the pointer hidden over the private terminal")
                await prof.evaluate("""(() => { const p = window.__focusFrames = []; const send = WebSocket.prototype.send;
                    WebSocket.prototype.send = function (data) { if (typeof data === 'string') { p.push(data); } return send.call(this, data); };
                    return true; })()""")
                await prof.drag(screen['left'] + 2, screen['top'] + 6, screen['left'] + screen['width'] * 0.4, screen['top'] + 6)
                await prof.wait_for("document.querySelectorAll('.terminal-window .xterm-selection div').length > 0",
                                    what="a selection in the private terminal")
                await prof.hover(screen['left'] + screen['width'] / 2, screen['top'] + screen['height'] / 2)
                await asyncio.sleep(0.6)
                frames = await prof.evaluate("window.__focusFrames.join('\\n')")
                assert 'pri1vate' not in frames and '"terminal"' not in frames, frames
                assert (await alice.evaluate(POINTER))['hidden'] and await alice.evaluate(HIGHLIGHT) == ''
                assert await alice.evaluate(WINDOWS) == 1                 # her own terminal only
                # the focus off: the arrow goes with it
                await prof.click('#focus-student')
                await alice.wait_for("!document.body.classList.contains('focused') && !document.getElementById('presenter-pointer')",
                                     what="the student's page released, the pointer gone")
                no_errors(prof)
                no_errors(alice)
        run(scenario())
