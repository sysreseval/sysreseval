"""The Open page of the web front-end in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``): the project mode of the instructors (Standard / Instructor mode / Debug mode; the
students have none), the lab tree listing every lab of the host in debug mode and the student
catalog otherwise, the selection kept across the reload while the lab is still listed, a
debug project started from the page, the Projects page saying the mode of each project of
an instructor (the Mode line of the cards, the suffix of the title), the README of the directory
being browsed, the lab costs of the instructors, and the subtitles of the manual order of a
titles.json."""
import asyncio
import contextlib
import json
import time
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
ALICE = P.who('alice', 'Alice A', group='INFO1')
PROF = P.who('prof', groups=P.TEACHERS)
DHCP, EXAM_ONLY = 'sre/dhcp.py', 'sre/_EXAM_/exam1.py'       # the catalog of the fake sre, and its exam-only lab

# -- what the page shows, as JavaScript expressions ---------------------------------------------

LABS = "[...document.querySelectorAll('#labs button.lab')].map((b) => b.title)"
MODES = "[...document.querySelectorAll('input[name=\"mode\"]')].map((r) => r.value)"
MODE = "(document.querySelector('input[name=\"mode\"]:checked') || {value: ''}).value"
SELECTED = "document.getElementById('selected-lab').textContent"
HIGHLIGHTED = "[...document.querySelectorAll('#labs button.lab[aria-selected=\"true\"]')].map((b) => b.title)"
START_DISABLED = "document.getElementById('start-button').disabled"
ON_PROJECT_PAGE = "window.location.pathname.startsWith('/projects/a01/')"
# the cards of the Projects page: class, the suffix of the title, the Mode line of the meta block
CARDS = """[...document.querySelectorAll('#projects .card')].map((c) => [
  c.className,
  (c.querySelector('h2 .mode') || {textContent: ''}).textContent,
  (c.querySelector('.meta .mode') || {textContent: ''}).textContent])"""


# a Flavor form with an inline row (the fields named name~N) between a text and a field that
# has a row of its own
INLINE_FLAVOR_FORM = ("Network of the lab\n\n"
                      "- Clients: @@{nb~3:[0-9]+}@@ mode: @@{mode~:>easy|hard}@@ per subnet\n"
                      "- Comment: @@{comment:}@@")
FLAVOR_FORM_OPEN = "document.querySelector('dialog.flavor[open] input[name=\"nb\"]') !== null"
# the rows of the form: the tag, the text or the name, and the box of every item of the inline
# rows, then the box of the field with a row of its own
FLAVOR_FORM_ROWS = """(() => {
  const box = (e) => { const r = e.getBoundingClientRect(); return [r.left, r.top, r.right, r.bottom]; };
  const form = document.querySelector('dialog.flavor[open] .form');
  return {
    rows: [...form.querySelectorAll('.form-row.inline')].map((row) => [...row.children].map(
      (e) => [e.tagName, e.name || e.textContent.trim(), box(e)])),
    comment: box(form.querySelector('input[name="comment"]')),
    form: box(form),
    size: form.querySelector('input[name="nb"]').getAttribute('size'),
  };
})()"""


def lab_button(name: str) -> str:
    return f'#labs button.lab[title="{name}"]'


def has_lab(name: str) -> str:
    return f"document.querySelector({json.dumps(lab_button(name))}) !== null"


@contextlib.asynccontextmanager
async def browser_of(tmp_path, identity, over=None, host_over=None, mock_env=None):
    """The harness (proxy mode, the real web directory; *over*: another web.toml overlay,
    *host_over*: merged into its host entry, *mock_env*: the ``MOCK_*`` variables of the fake
    ``sre``), the identity proxy making the browser *identity*, and the browser:
    ``(h, browser, url)``."""
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over or P.PROXY_OVER, host_over=host_over,
                  mock_env=mock_env)
    h.web_dir = WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', identity)
        await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield h, browser, proxy.url
        finally:
            await proxy.close()


class TestOpenPage:
    def test_students_have_no_project_mode(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(MODES) == []
                assert EXAM_ONLY not in await page.evaluate(LABS)
        P.run(go())

    def test_debug_mode_lists_every_lab_and_keeps_the_selection(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, PROF) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(MODES) == ['standard', 'instructor', 'debug']
                assert await page.evaluate(MODE) == 'standard'
                labs = await page.evaluate(LABS)
                assert DHCP in labs and EXAM_ONLY not in labs
                # a lab selected, then the debug mode: the exam-only lab appears, the selection stays
                await page.click(lab_button(DHCP))
                assert await page.evaluate(SELECTED) == DHCP and not await page.evaluate(START_DISABLED)
                await page.click('#mode-debug')
                await page.wait_for(has_lab(EXAM_ONLY), what="the exam-only lab in debug mode")
                assert await page.evaluate(SELECTED) == DHCP and await page.evaluate(HIGHLIGHTED) == [DHCP]
                assert not await page.evaluate(START_DISABLED)
                # the instructor mode: the student catalog again, the lab selected still listed
                await page.click('#mode-instructor')
                await page.wait_for(f"!({has_lab(EXAM_ONLY)})", what="the student catalog in instructor mode")
                assert await page.evaluate(SELECTED) == DHCP and await page.evaluate(HIGHLIGHTED) == [DHCP]
                # an exam-only lab selected in debug mode is dropped by a mode that does not list it
                await page.click('#mode-debug')
                await page.wait_for(has_lab(EXAM_ONLY), what="the exam-only lab again")
                await page.click(lab_button(EXAM_ONLY))
                assert await page.evaluate(SELECTED) == EXAM_ONLY
                await page.click('#mode-standard')
                await page.wait_for(f"!({has_lab(EXAM_ONLY)})", what="the student catalog in standard mode")
                assert await page.evaluate(SELECTED) == '' and await page.evaluate(HIGHLIGHTED) == []
                assert await page.evaluate(START_DISABLED)
                # a debug project of the exam-only lab started from the page: sre start --debug-web-project
                await page.click('#mode-debug')
                await page.wait_for(has_lab(EXAM_ONLY), what="the exam-only lab once more")
                await page.click(lab_button(EXAM_ONLY))
                await page.click('#start-button')
                await page.wait_for(ON_PROJECT_PAGE, timeout=20.0, what="the page of the new project")
                rows = await (await h.client.get('/api/projects', headers=PROF)).json()
                assert [(r['lab_name'], r['debug_project'], r['instructor_mode']) for r in rows] == \
                    [('sre@_EXAM_@exam1.py', True, False)]      # the debug marker, the lab name of the catalog
        P.run(go())

    def test_inline_fields_of_a_flavor_form(self, tmp_path):
        """The inline fields of a form (``@@{name~N:spec}@@``, the ``Form`` of form.js shared by
        the form questions and the Flavor form): the label, the fields and the end of their
        source line are side by side on one row, an input as wide as its N characters; a field
        without the suffix keeps a row of its own; the answers go under the names without
        suffix."""
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env={'MOCK_FLAVOR_FORM': INLINE_FLAVOR_FORM}) \
                    as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                await page.click(lab_button(DHCP))
                await page.click('#start-button')
                await page.wait_for(FLAVOR_FORM_OPEN, what="the Flavor form")
                shown = await page.evaluate(FLAVOR_FORM_ROWS)
                assert len(shown['rows']) == 1
                row = shown['rows'][0]
                assert [(tag, text) for tag, text, _ in row] == [
                    ('DIV', 'Clients:'), ('INPUT', 'nb'), ('DIV', 'mode:'), ('SELECT', 'mode'),
                    ('DIV', 'per subnet')]
                boxes = [box for _, _, box in row]
                # side by side in the order of the text, on one line: every item crosses the
                # line of the input
                assert all(left[2] <= right[0] for left, right in zip(boxes, boxes[1:]))
                middle = (boxes[1][1] + boxes[1][3]) / 2
                assert all(top < middle < bottom for _, top, _, bottom in boxes)
                assert shown['size'] == '3' and boxes[1][2] - boxes[1][0] < 80
                # the field without the suffix: below the row, as wide as the form
                comment, form = shown['comment'], shown['form']
                assert comment[1] >= max(bottom for _, _, _, bottom in boxes) - 1
                assert comment[2] - comment[0] > 0.8 * (form[2] - form[0])
                # filled and submitted: the project starts with the answers of the three fields
                await page.evaluate("document.querySelector('dialog.flavor[open] input[name=\"nb\"]').focus()")
                await page.insert_text('2')
                await page.evaluate("""(() => {
                  const select = document.querySelector('dialog.flavor[open] select[name="mode"]');
                  select.value = 'hard';
                  select.dispatchEvent(new Event('change'));
                })()""")
                await page.click('dialog.flavor[open] .form-field button')
                await page.wait_for(ON_PROJECT_PAGE, timeout=20.0, what="the page of the new project")
                flavors = [json.loads(path.read_text()) for path in
                           (h.pub / 'projects').glob('*/.private/flavor.json')]
                assert flavors == [{'nb': '2', 'mode': 'hard', 'comment': ''}]
        P.run(go())

    def test_cards_say_the_mode(self, tmp_path):
        """The Projects page of an instructor says the mode of each project: the Mode line of the
        card (Standard / Instructor mode / Debug mode, the words of the radios of the Open page)
        and, for the two non-standard modes, a coloured suffix after the title; a student's cards
        have no Mode line. The four projects are started through the API (one start per
        start_interval from the page otherwise; the host of the harness takes 3 by default)."""
        async def go():
            over = {**P.PROXY_OVER, 'limits': {'start_interval': 0}}
            # four projects on the host, and room to spare: a status poll landing at the end of
            # a start counts the project (the agent has seen its info.json) and its reservation
            # (not released yet), so a cap of 4 refused the fourth start one time in forty
            async with browser_of(tmp_path, PROF, over=over, host_over={'max_projects': 6}) as (h, browser, url):
                for identity, body in ((PROF, {'lab': DHCP}), (PROF, {'lab': DHCP, 'instructor_mode': True}),
                                       (PROF, {'lab': EXAM_ONLY, 'debug_project': True}), (ALICE, {'lab': DHCP})):
                    resp = await h.client.post('/api/projects', json=body, headers={**identity, **P.CSRF})
                    result = [json.loads(line) for line in (await resp.text()).splitlines()][-1]
                    assert result['status'] == 'created', result
                page = await browser.page(f'{url}/projects')
                await page.wait_for("document.querySelectorAll('#projects .card').length === 3", what="the three cards")
                assert sorted(tuple(c) for c in await page.evaluate(CARDS)) == sorted([
                    ('card', '', 'Mode: Standard'),
                    ('card instructor', ' (instructor)', 'Mode: Instructor mode'),
                    # a debug project also names its container engine (no other project does)
                    ('card debug', ' (debug)', 'Mode: Debug mode (kathara)'),
                ])
                # the student: one standard card, without a Mode line (every project of theirs is standard)
                proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', ALICE)
                await proxy.start()
                try:
                    page = await browser.page(f'{proxy.url}/projects')
                    await page.wait_for("document.querySelectorAll('#projects .card').length === 1", what="the card")
                    assert await page.evaluate(CARDS) == [['card', '', '']]
                    assert await page.evaluate("document.querySelector('#projects .card .meta .mode')") is None
                finally:
                    await proxy.close()
        P.run(go())


# -- the README of the directory being browsed ---------------------------------------------------

#: the lab tree of the README tests: sre (README.md alone: a table, a link), s4 (no README), long
#: (a README higher than its pane), and the top directory with a variant per language
README_LABS = [DHCP, 's4/tp_ssh', 'long/a.py']
READMES = {
    '': {'': '# Welcome\n\nPick your course.', 'fr': '# Bienvenue\n\nChoisissez votre cours.',
         'en': '# Hello\n\nPick your course.'},
    'sre': {'': '# Shipped labs\n\n| Lab | Week |\n|---|---|\n| dhcp | 12 |\n\nSee [the docs](https://example.org/docs).'},
    'long': {'': '# Long\n\n' + '\n\n'.join(f'Paragraph {i}.' for i in range(120))},
}
README_ENV = {'MOCK_LAB_LIST': json.dumps(README_LABS), 'MOCK_LAB_READMES': json.dumps(READMES)}
#: the heading of the README shown, None when the pane is hidden
README = """(() => {
  const pane = document.getElementById('lab-readme');
  return pane.hidden ? null : (pane.querySelector('h1') || {textContent: ''}).textContent;
})()"""
LANGUAGE = "document.documentElement.lang"
TOP_HEADINGS = {'fr': 'Bienvenue', 'en': 'Hello'}
#: the boxes of the tree, of the README pane and of the Start row, and what the pane scrolls
README_LAYOUT = """(() => {
  const box = (id) => { const r = document.getElementById(id).getBoundingClientRect(); return [r.top, r.bottom]; };
  const pane = document.getElementById('lab-readme');
  return {tree: box('labs'), pane: box('lab-readme'), start: box('start-button'), window: window.innerHeight,
          scroll: pane.scrollHeight, client: pane.clientHeight, top: pane.scrollTop,
          overflow: document.querySelector('main').scrollHeight - document.querySelector('main').clientHeight};
})()"""


def directory(name: str) -> str:
    """The <summary> of the directory of the tree labelled *name*, as a JavaScript expression."""
    return f"[...document.querySelectorAll('#labs summary')].find((s) => s.textContent.trim() === {json.dumps(name)})"


def is_open(name: str) -> str:
    return f"{directory(name)}.parentElement.open"


async def toggle(page, name: str):
    await page.evaluate(f"({directory(name)}.click(), true)")


class TestReadmes:
    """Under the lab tree, the README of the directory being browsed: the top of the lab
    directory at first, a directory when it is opened, the directory holding it when it is
    closed, the directory of a lab when the lab is clicked; nothing for a directory without
    README; in the language of the page."""

    def test_readme_follows_the_directory(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env=README_ENV) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                language = await page.evaluate(LANGUAGE)
                # the top directory at first: the variant of the page language; no directory is open
                assert await page.evaluate(README) == TOP_HEADINGS[language]
                assert not await page.evaluate(is_open('sre'))
                # a directory opened: its README (README.md, whatever the language), rendered
                await toggle(page, 'sre')
                assert await page.evaluate(is_open('sre')) and await page.evaluate(README) == 'Shipped labs'
                assert await page.evaluate("document.querySelector('#lab-readme table td').textContent") == 'dhcp'
                assert await page.evaluate("""(() => {
                  const link = document.querySelector('#lab-readme a');
                  return [link.href, link.target, link.rel]; })()""") == [
                    'https://example.org/docs', '_blank', 'noopener noreferrer']
                # a lab of the directory selected: the README stays; the selection works as before
                await page.click(lab_button(DHCP))
                assert await page.evaluate(README) == 'Shipped labs'
                assert await page.evaluate(SELECTED) == DHCP and not await page.evaluate(START_DISABLED)
                # a directory without README opened: the pane is hidden; closed: back to the top
                await toggle(page, 's4')
                assert await page.evaluate(is_open('s4')) and await page.evaluate(README) is None
                assert await page.evaluate("document.getElementById('lab-readme').innerHTML") == ''
                await toggle(page, 's4')
                assert not await page.evaluate(is_open('s4'))
                assert await page.evaluate(README) == TOP_HEADINGS[language]
                # the lab still selected, clicked again: its directory; that directory closed: the top
                await page.click(lab_button(DHCP))
                assert await page.evaluate(README) == 'Shipped labs'
                await toggle(page, 'sre')
                assert not await page.evaluate(is_open('sre'))
                assert await page.evaluate(README) == TOP_HEADINGS[language]
                assert await page.evaluate(SELECTED) == DHCP        # closing a directory selects nothing else
        P.run(go())

    def test_pane_under_the_tree_scrolls_by_itself(self, tmp_path):
        """The pane lies between the tree and the Start row; a long README scrolls inside it and
        leaves the tree its room, the page itself does not scroll; another README starts at
        its top."""
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env=README_ENV) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                short = await page.evaluate(README_LAYOUT)
                assert short['tree'][1] <= short['pane'][0] and short['pane'][1] <= short['start'][0]
                assert short['scroll'] <= short['client']            # a short text takes its height only
                await toggle(page, 'long')
                assert await page.evaluate(README) == 'Long'
                layout = await page.evaluate(README_LAYOUT)
                assert layout['tree'][1] <= layout['pane'][0] and layout['pane'][1] <= layout['start'][0]
                assert layout['scroll'] > layout['client']           # it scrolls inside its pane
                assert layout['pane'][1] - layout['pane'][0] <= 0.46 * layout['window']
                assert layout['tree'][1] - layout['tree'][0] >= 120  # the tree keeps its room
                assert layout['start'][1] <= layout['window'] and layout['overflow'] <= 0
                await page.evaluate("(document.getElementById('lab-readme').scrollTop = 400, true)")
                await toggle(page, 'sre')
                assert await page.evaluate(README) == 'Shipped labs'
                assert (await page.evaluate(README_LAYOUT))['top'] == 0
        P.run(go())

    def test_language_of_the_page(self, tmp_path):
        """The variant of the language of the page (README.<lang>.md), README.md for a
        directory without one."""
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env=README_ENV) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                language = await page.evaluate(LANGUAGE)
                other = 'en' if language == 'fr' else 'fr'
                assert await page.evaluate(README) == TOP_HEADINGS[language]
                status = await page.evaluate(f"""fetch('/api/language', {{method: 'POST',
                    headers: {{'Content-Type': 'application/json', {json.dumps(P.S.CSRF_HEADER)}: {json.dumps(P.S.CSRF_VALUE)}}},
                    body: JSON.stringify({{language: {json.dumps(other)}}})}}).then((r) => r.status)""")
                assert status == 200
                await page.goto(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree in the other language")
                assert await page.evaluate(LANGUAGE) == other
                assert await page.evaluate(README) == TOP_HEADINGS[other]
                await toggle(page, 'sre')
                assert await page.evaluate(README) == 'Shipped labs'
        P.run(go())

    def test_readme_kept_across_the_reload_of_the_tree(self, tmp_path):
        """The tree is built again when an instructor enters or leaves the debug mode: the
        README shown is the one of the directory of the lab still selected, the top one when
        nothing is selected."""
        async def go():
            async with browser_of(tmp_path, PROF, mock_env=README_ENV) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                language = await page.evaluate(LANGUAGE)
                await page.click('#mode-debug')
                await page.wait_for(MODE + " === 'debug'", what="the debug mode")
                await page.wait_for(has_lab(DHCP), what="the lab tree of the debug mode")
                assert await page.evaluate(README) == TOP_HEADINGS[language]
                await page.evaluate(f"({directory('sre')}.parentElement.open = true, true)")   # opened without a click
                await page.click(lab_button(DHCP))
                assert await page.evaluate(README) == 'Shipped labs'
                await page.click('#mode-standard')
                await page.wait_for(MODE + " === 'standard'", what="the standard mode")
                await page.wait_for(f"{has_lab(DHCP)} && {is_open('sre')}", what="the tree built again, sre open")
                assert await page.evaluate(HIGHLIGHTED) == [DHCP] and await page.evaluate(README) == 'Shipped labs'
        P.run(go())

    def test_no_readme_no_pane(self, tmp_path):
        """A lab tree without README (and an agent that sends none): the page of before."""
        async def go():
            async with browser_of(tmp_path, ALICE) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(README) is None
                await toggle(page, 'sre')
                await page.click(lab_button(DHCP))
                assert await page.evaluate(README) is None and await page.evaluate(SELECTED) == DHCP
                assert await page.evaluate("getComputedStyle(document.getElementById('lab-readme')).display") == 'none'
        P.run(go())


# -- the lab costs beside the labs (instructors) -------------------------------------------------

#: a lab at the top of the tree, the two of the fake sre one directory down, one three down, and
#: the exam-only lab the debug mode adds; a weight for three of them
TOP, SSH, DEEP = 'top.py', 's4/tp_ssh', 'a/b/c/deep.py'
COSTS_ENV = {'MOCK_LAB_LIST': json.dumps([TOP, DHCP, SSH, DEEP, EXAM_ONLY]),
             'MOCK_LAB_WEIGHTS': json.dumps({DHCP: 15, DEEP: 4, EXAM_ONLY: 30})}
COSTS_TOGGLE = '#costs-toggle'
COSTS_PRESSED = "document.getElementById('costs-toggle').getAttribute('aria-pressed')"
#: the note above the tree: null while hidden, else its class and its text
COSTS_NOTE = """(() => {
  const note = document.getElementById('lab-costs-note');
  return note.hidden ? null : [note.className, note.textContent];
})()"""
COSTS_HEAD = "[...document.querySelectorAll('#labs .lab-costs-head .lab-costs > span')].map((s) => s.textContent)"
COSTS_COUNT = "document.querySelectorAll('#labs li.leaf > .lab-costs').length"
WITH_COSTS = "document.getElementById('labs').classList.contains('with-costs')"
#: the left and right edges of the six titles, then of the six cells of every lab shown, the box
#: of the tree, and whether the name of each lab stays on one line left of its cells
COSTS_LAYOUT = """(() => {
  const edges = (e) => { const r = e.getBoundingClientRect(); return [Math.round(r.left), Math.round(r.right)]; };
  const tree = document.getElementById('labs');
  const rows = {};
  for (const leaf of tree.querySelectorAll('li.leaf')) {
    const button = leaf.querySelector('button.lab');
    const cells = leaf.querySelector('.lab-costs');
    const b = button.getBoundingClientRect();
    const c = cells.getBoundingClientRect();
    rows[button.dataset.lab] = {cells: [...cells.children].map(edges), beside: b.right <= c.left + 1,
                                line: Math.abs(b.top - c.top) < b.height && b.height < 40};
  }
  return {head: [...tree.querySelectorAll('.lab-costs-head .lab-costs > span')].map(edges), rows,
          tree: edges(tree), headTop: Math.round(tree.querySelector('.lab-costs-head').getBoundingClientRect().top
                                                 - tree.getBoundingClientRect().top)};
})()"""
#: the tree made lower than its content and scrolled: how far it scrolled, where the titles and
#: the first lab are below its top, before the scroll and after it, and where the titles end (the
#: tree is as it was afterwards).  Nothing here depends on the height of the titles, which is that
#: of two lines of the font of the machine.
COSTS_SCROLLED = """(() => {
  const tree = document.getElementById('labs');
  const below = (y) => Math.round(y - tree.getBoundingClientRect().top);
  const head = tree.querySelector('.lab-costs-head');
  const first = tree.querySelector('li');
  const places = () => ({head: below(head.getBoundingClientRect().top), first: below(first.getBoundingClientRect().top),
                         headBottom: below(head.getBoundingClientRect().bottom)});
  Object.assign(tree.style, {flex: 'none', minHeight: '0', height: '70px'});
  const before = places();
  tree.scrollTop = 40;
  const out = {scrolled: tree.scrollTop, before, ...places()};
  Object.assign(tree.style, {flex: '', minHeight: '', height: ''});
  tree.scrollTop = 0;
  return out;
})()"""


def costs_of(name: str) -> str:
    """The texts of the six cells beside the lab *name* (null without cells), as a JavaScript expression."""
    return f"""(() => {{
  const button = document.querySelector({json.dumps(lab_button(name))});
  const cells = button && button.parentElement.querySelector(':scope > .lab-costs');
  return cells ? [...cells.children].map((s) => s.textContent) : null;
}})()"""


#: the costs table (the dialog of the Costs table… button): open or not, the titles of its columns,
#: its rows as lists of cell texts, the note above it, the text of its body
COSTS_TABLE = '#costs-table'
DIALOG = "document.querySelector('dialog.lab-costs-table[open]')"
DIALOG_OPEN = f"({DIALOG} !== null)"
DIALOG_GONE = "(document.querySelector('dialog.lab-costs-table') === null)"
# the titles and the cells an instructor sees: the Engine column is hidden unless the pool
# measured projects with two container engines
SHOWN_CELLS = "filter((cell) => getComputedStyle(cell).display !== 'none')"
DIALOG_TITLES = (f"[...{DIALOG}.querySelectorAll('thead th')].{SHOWN_CELLS}"
                 ".map((th) => [th.textContent, th.title !== ''])")
DIALOG_ROWS = (f"JSON.stringify([...{DIALOG}.querySelectorAll('tbody tr[data-lab]')]"
               f".map((tr) => [...tr.children].{SHOWN_CELLS}.map((td) => td.textContent)))")
DIALOG_NOTE = f"{DIALOG}.querySelector('.lab-costs-note').textContent"
DIALOG_BODY = f"[{DIALOG}.querySelector('tbody').textContent.trim(), {DIALOG}.querySelector('tbody td').className]"
DIALOG_CLOSE = 'dialog.lab-costs-table[open] .buttons button'
TABLE_POLL = 15.0                                             # the dialog asks the costs every 5 s


def shows(name: str, cells: list) -> str:
    return f"JSON.stringify({costs_of(name)}) === {json.dumps(json.dumps(cells, separators=(',', ':')))}"


class TestLabCosts:
    """The two buttons of the instructors.  Lab costs: not pressed at first, it shows beside each
    lab what one of its projects is counted for on a host (``GET /api/pool/costs``, never asked
    while the columns are hidden), under their titles; hidden again by a second click, and by a
    reload.  Costs table…: the dialog of every lab the pool heard of, with the same six columns,
    refreshed while it is open."""

    def test_costs_shown_and_hidden(self, tmp_path):
        from sreweb.portal.costs import Usage
        from sreweb.portal.pool import PoolError
        asked = []

        async def go():
            async with browser_of(tmp_path, PROF, mock_env=COSTS_ENV) as (h, browser, url):
                pool = h.portal.pool
                costs_view = pool.costs_view
                failing = []

                def counted():
                    asked.append(1)
                    if failing:
                        raise PoolError(503, "the costs are away")
                    return costs_view()
                pool.costs_view = counted
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                # hidden by default: the button not pressed, no note, no cell, and nothing asked
                assert await page.evaluate(COSTS_PRESSED) == 'false'
                assert await page.evaluate(COSTS_NOTE) is None and await page.evaluate(COSTS_COUNT) == 0
                assert await page.evaluate(WITH_COSTS) is False and await page.evaluate(COSTS_HEAD) == []
                assert asked == []
                # pressed: the weight each lab declares and what a project of it is counted for
                # (15 x 5 MiB and 15 x 0.001 core), the default cost for a lab the pool knows nothing of
                await page.click(COSTS_TOGGLE)
                await page.wait_for(shows(DHCP, ['15', '', '75 MiB', '0.015', '0', 'declared']), what="the costs of the labs")
                assert await page.evaluate(costs_of(DEEP)) == ['4', '', '20 MiB', '0.010', '0', 'declared']
                for lab in (TOP, SSH):
                    assert await page.evaluate(costs_of(lab)) == ['', '', '512 MiB', '0.200', '0', 'default'], lab
                assert await page.evaluate(COSTS_PRESSED) == 'true' and await page.evaluate(WITH_COSTS) is True
                assert await page.evaluate(COSTS_HEAD) == ['Weight', 'Containers', 'Memory', 'CPU', 'Measured projects', 'Source']
                cls, note = await page.evaluate(COSTS_NOTE)
                assert 'muted' in cls and 'error' not in cls
                assert note == ('a lab never seen, without weight: 512 MiB, 0.2 core'
                                ' — one unit of weight: 5 MiB, 0.001 core')
                assert len(asked) == 1 and await page.evaluate(COSTS_COUNT) == 4
                # the columns line up, the titles above them, at every depth of the tree; the name
                # of a lab stays on its line, left of its cells; the titles are the first line of the tree
                for name in ('sre', 's4', 'a', 'b', 'c'):
                    await toggle(page, name)
                layout = await page.evaluate(COSTS_LAYOUT)
                assert sorted(layout['rows']) == sorted([TOP, DHCP, SSH, DEEP])
                for lab, row in layout['rows'].items():
                    assert row['beside'] and row['line'], (lab, row)
                    for (left, right), (head_left, head_right) in zip(row['cells'], layout['head']):
                        assert abs(left - head_left) <= 1 and abs(right - head_right) <= 1, (lab, row, layout['head'])
                    assert row['cells'][-1][1] <= layout['tree'][1]
                assert 0 <= layout['headTop'] <= 12
                # ... and stay at the top of the tree while it scrolls, the labs going under them
                scrolled = await page.evaluate(COSTS_SCROLLED)
                before = scrolled['before']
                assert scrolled['scrolled'] == 40 and 0 <= scrolled['head'] <= 2, scrolled
                assert scrolled['head'] == before['head'] and before['first'] >= before['headBottom'] - 1, scrolled
                assert abs(scrolled['first'] - (before['first'] - 40)) <= 1, scrolled
                assert scrolled['first'] < scrolled['headBottom'], scrolled
                # a lab is still selected by a click, with its costs beside it
                await page.click(lab_button(DHCP))
                assert await page.evaluate(SELECTED) == DHCP and await page.evaluate(COSTS_COUNT) == 4
                # hidden again: nothing left on the tree, and nothing asked
                await page.click(COSTS_TOGGLE)
                assert await page.evaluate(COSTS_PRESSED) == 'false' and await page.evaluate(COSTS_COUNT) == 0
                assert await page.evaluate(COSTS_NOTE) is None and await page.evaluate(COSTS_HEAD) == []
                assert await page.evaluate(WITH_COSTS) is False and len(asked) == 1
                # three projects of the lab measured meanwhile: shown again, the costs are asked again
                pool.costs.observe([Usage(name=f'p{i}', lab=DHCP, containers=15, mem_mb=400.0, cpu=0.3, settled=True)
                                    for i in range(3)], time.time())
                await page.click(COSTS_TOGGLE)
                await page.wait_for(shows(DHCP, ['15', '15', '400 MiB', '0.300', '3', 'measured']), what="the measured cost")
                assert 'measured on this pool: 26.7 MiB, 0.02 core' in (await page.evaluate(COSTS_NOTE))[1]
                assert len(asked) == 2
                # the debug mode builds the tree again, with the exam-only lab: every lab has its cells
                await page.click('#mode-debug')
                await page.wait_for(has_lab(EXAM_ONLY), what="the exam-only lab in debug mode")
                await page.wait_for(shows(EXAM_ONLY, ['30', '', '150 MiB', '0.030', '0', 'declared']),
                                    what="the costs of the lab the debug mode lists")
                assert await page.evaluate(COSTS_COUNT) == 5 and await page.evaluate(SELECTED) == DHCP
                assert await page.evaluate(costs_of(DHCP)) == ['15', '15', '400 MiB', '0.300', '3', 'measured']
                assert len(await page.evaluate(COSTS_HEAD)) == 6 and len(asked) == 3
                # the costs cannot be read: the reason in place of the note, no cell left
                failing.append(1)
                await page.click('#mode-standard')
                await page.wait_for(f"({COSTS_NOTE} || ['', ''])[0].includes('error')", what="the error of the costs")
                assert 'the costs are away' in (await page.evaluate(COSTS_NOTE))[1]
                assert await page.evaluate(COSTS_COUNT) == 0 and await page.evaluate(COSTS_HEAD) == []
                assert await page.evaluate(has_lab(DHCP)) and not await page.evaluate(has_lab(EXAM_ONLY))
                failing.clear()
                # never remembered: the page loaded again has them hidden, and asks nothing
                before = len(asked)
                await page.goto(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree again")
                assert await page.evaluate(COSTS_PRESSED) == 'false' and await page.evaluate(COSTS_COUNT) == 0
                assert await page.evaluate(COSTS_NOTE) is None and len(asked) == before
        P.run(go())

    def test_costs_table(self, tmp_path):
        """The Costs table… button opens a dialog listing the labs the pool heard of (those of
        the lab list that declare a weight, those a project was measured for): the lab, then the
        six columns of the tree, under the same titles; asked when it opens and every 5 s while it
        is open, never once closed; it is apart from the columns of the tree."""
        from sreweb.portal.costs import Usage
        from sreweb.portal.pool import PoolError
        asked = []

        async def go():
            async with browser_of(tmp_path, PROF, mock_env=COSTS_ENV) as (h, browser, url):
                pool = h.portal.pool
                costs_view = pool.costs_view
                failing = []

                def counted():
                    asked.append(1)
                    if failing:
                        raise PoolError(503, "the costs are away")
                    return costs_view()
                pool.costs_view = counted
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(DIALOG_GONE) and asked == []
                await page.click(COSTS_TABLE)
                await page.wait_for(f"{DIALOG_OPEN} && {DIALOG_ROWS} !== '[]'", what="the costs table")
                # the two labs of the list that declare a weight, by name (4 x 0.001 core is below
                # the least cost); a lab without weight and never measured is not listed
                assert json.loads(await page.evaluate(DIALOG_ROWS)) == [
                    [DEEP, '4', '', '20 MiB', '0.010', '0', 'declared'],
                    [DHCP, '15', '', '75 MiB', '0.015', '0', 'declared']]
                assert await page.evaluate(DIALOG_TITLES) == [
                    ['Lab', False], ['Weight', True], ['Containers', True], ['Memory', True], ['CPU', True],
                    ['Measured projects', True], ['Source', True]]
                assert await page.evaluate(f"{DIALOG}.querySelector('h2').textContent") == 'Lab costs'
                note = await page.evaluate(DIALOG_NOTE)
                assert note == ('a lab never seen, without weight: 512 MiB, 0.2 core'
                                ' — one unit of weight: 5 MiB, 0.001 core')
                # apart from the columns of the tree: the Lab costs button is not pressed, no cell there
                assert await page.evaluate(COSTS_PRESSED) == 'false' and await page.evaluate(COSTS_COUNT) == 0
                # three projects of a lab measured: their figures replace its weight at the next poll
                pool.costs.observe([Usage(name=f'p{i}', lab=DHCP, containers=15, mem_mb=400.0, cpu=0.3, settled=True)
                                    for i in range(3)], time.time())
                await page.wait_for(f"{DIALOG_ROWS}.includes('measured')", timeout=TABLE_POLL, what="the measured cost")
                assert json.loads(await page.evaluate(DIALOG_ROWS))[1] == [DHCP, '15', '15', '400 MiB', '0.300', '3', 'measured']
                assert 'measured on this pool: 26.7 MiB, 0.02 core' in await page.evaluate(DIALOG_NOTE)
                # closed: the dialog is gone, and the costs are no longer asked
                await page.click(DIALOG_CLOSE)
                await page.wait_for(DIALOG_GONE, what="the dialog closed")
                before = len(asked)
                await asyncio.sleep(6.0)                      # more than one period of the dialog
                assert len(asked) == before
                # opened again while the costs cannot be read: the reason in place of the rows
                failing.append(1)
                await page.click(COSTS_TABLE)
                await page.wait_for(f"{DIALOG_OPEN} && {DIALOG_BODY}[1] === 'error'", what="the error of the costs")
                assert 'the costs are away' in (await page.evaluate(DIALOG_BODY))[0]
                assert await page.evaluate(DIALOG_ROWS) == '[]'
                await page.click(DIALOG_CLOSE)
                await page.wait_for(DIALOG_GONE, what="the dialog closed again")
            # a pool that heard of no lab with a weight: the table says so
            async with browser_of(tmp_path / 'empty', PROF) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                await page.click(COSTS_TABLE)
                await page.wait_for(f"{DIALOG_OPEN} && {DIALOG_BODY}[0] !== 'Loading…'", what="the empty costs table")
                assert await page.evaluate(DIALOG_BODY) == ['No lab measured or declared yet.', 'muted']
        P.run(go())

    def test_costs_table_per_engine(self, tmp_path):
        """A pool that measured projects with two container engines: the table gets an Engine
        column, and each lab is followed by one row per engine it was measured with; the
        columns beside the labs of the tree keep one cost per lab."""
        from sreweb.portal.costs import Usage

        async def go():
            async with browser_of(tmp_path, PROF, mock_env=COSTS_ENV) as (h, browser, url):
                pool = h.portal.pool
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                pool.costs.observe(
                    [Usage(name=f'k{i}', lab=DHCP, containers=12, mem_mb=100.0, cpu=0.01, settled=True, engine='kathara')
                     for i in range(3)]
                    + [Usage(name=f'p{i}', lab=DHCP, containers=12, mem_mb=300.0, cpu=0.02, settled=True, engine='podman')
                       for i in range(2)], time.time())
                await page.click(COSTS_TABLE)
                await page.wait_for(f"{DIALOG_OPEN} && {DIALOG_ROWS}.includes('kathara')", what="the rows of the engines")
                assert [title for title, _tip in await page.evaluate(DIALOG_TITLES)] == [
                    'Lab', 'Engine', 'Weight', 'Containers', 'Memory', 'CPU', 'Measured projects', 'Source']
                rows = json.loads(await page.evaluate(DIALOG_ROWS))
                assert rows == [
                    [DEEP, '', '4', '', '20 MiB', '0.010', '0', 'declared'],
                    [DHCP, '', '15', '12', '300 MiB', '0.020', '5', 'measured'],
                    # under the row of their lab, whose name is not said twice
                    ['', 'kathara', '15', '12', '100 MiB', '0.010', '3', 'measured'],
                    ['', 'podman', '15', '12', '300 MiB', '0.020', '2', 'as the lab']]
                tip = await page.evaluate(f"{DIALOG}.querySelector('tr[data-engine=\"podman\"] td.source').title")
                assert tip == 'Too few projects were measured with this engine yet: the cost is the one of the lab'
                await page.click(DIALOG_CLOSE)
                await page.wait_for(DIALOG_GONE, what="the dialog closed")
                # beside the lab of the tree: the lab itself, every engine together
                await page.click(COSTS_TOGGLE)
                await page.wait_for(shows(DHCP, ['15', '12', '300 MiB', '0.020', '5', 'measured']),
                                    what="the cost of the lab in the tree")
        P.run(go())

    def test_students_have_no_costs(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env=COSTS_ENV) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate("document.getElementById('costs-toggle')") is None
                assert await page.evaluate("document.getElementById('costs-table')") is None
                assert await page.evaluate("document.querySelector('#lab-costs-note, #lab-costs-head, .lab-costs')") is None
                assert (await h.client.get('/api/pool/costs', headers=ALICE)).status == 403
        P.run(go())


# -- the subtitles of the manual order -----------------------------------------------------------

#: the lab tree of the subtitle tests: three directories and a lab at the top, cut into three
#: groups, and a group inside "sre"; the first entry of a group carries its subtitle
DNS = 'sre/dns.py'
SUBTITLE_LABS = ['top.py', DHCP, DNS, 's4/tp_ssh', 'a/x.py']
FIRST_YEAR = {'en': 'First year', 'fr': 'Première année'}
NAMING = {'en': 'Naming', 'fr': 'Nommage'}
SUBTITLE_ENV = {'MOCK_LAB_LIST': json.dumps(SUBTITLE_LABS),
                'MOCK_LAB_SUBTITLES': json.dumps({'a': FIRST_YEAR, 's4': 'Second year', 'top.py': 'Tools',
                                                  DNS: NAMING})}


def tree_rows(directory_name: str | None = None) -> str:
    """The rows of a directory of the tree (the top one by default), in the order drawn, as a
    JavaScript expression: ``[class, text]``, the text of a subtitle, the label of a directory,
    the name of a lab."""
    holder = ("document.querySelector('#labs > ul')" if directory_name is None
              else f"{directory(directory_name)}.parentElement.querySelector(':scope > ul')")
    return f"""[...{holder}.children].map((li) => [li.className,
      li.className === 'subtitle' ? li.textContent
        : li.className === 'dir' ? li.querySelector('summary').textContent.trim()
        : li.querySelector('button.lab').title])"""


#: every subtitle row: its font weight, and whether it comes below the row before it and above
#: the row after it
SUBTITLE_BOXES = """[...document.querySelectorAll('#labs > ul > li.subtitle')].map((li) => {
  const top = (e) => (e ? e.getBoundingClientRect().top : null);
  const before = top(li.previousElementSibling), after = top(li.nextElementSibling);
  return [getComputedStyle(li).fontWeight, before === null || before < top(li), top(li) < after,
          li.getBoundingClientRect().height > 0];
})"""


class TestSubtitles:
    """A subtitle of the manual order of a titles.json is a row of text of the lab tree, right
    before the first entry of its group, in the language of the page: nothing to click."""

    def test_rows_of_the_tree(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env=SUBTITLE_ENV) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                language = await page.evaluate(LANGUAGE)
                assert await page.evaluate(tree_rows()) == [
                    ['subtitle', FIRST_YEAR[language]], ['dir', 'a'],
                    ['subtitle', 'Second year'], ['dir', 's4'], ['dir', 'sre'],
                    ['subtitle', 'Tools'], ['leaf', 'top.py']]
                assert await page.evaluate(tree_rows('sre')) == [
                    ['leaf', DHCP], ['subtitle', NAMING[language]], ['leaf', DNS]]
                assert await page.evaluate(tree_rows('s4')) == [['leaf', 's4/tp_ssh']]
                # drawn as a heading, each one between its neighbours
                assert await page.evaluate(SUBTITLE_BOXES) == [['600', True, True, True]] * 3
                # the labs are those of the list: a subtitle is none
                assert sorted(await page.evaluate(LABS)) == sorted(SUBTITLE_LABS)
                assert await page.evaluate(
                    "document.querySelectorAll('#labs li.subtitle button, #labs li.subtitle [tabindex]').length") == 0
        P.run(go())

    def test_a_subtitle_selects_nothing(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env=SUBTITLE_ENV) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                await page.click('#labs li.subtitle')
                assert await page.evaluate(SELECTED) == '' and await page.evaluate(START_DISABLED)
                assert await page.evaluate(HIGHLIGHTED) == []
                # the lab after a subtitle is selected as any other one, and the subtitle changes nothing
                await toggle(page, 'sre')
                await page.click(lab_button(DNS))
                assert await page.evaluate(SELECTED) == DNS and not await page.evaluate(START_DISABLED)
                await page.click('#labs details[open] li.subtitle')
                assert await page.evaluate(SELECTED) == DNS and await page.evaluate(HIGHLIGHTED) == [DNS]
        P.run(go())

    def test_directories_and_labs_group_by_group(self, tmp_path):
        """A manual directory holding sub-directories and labs: the list of the CLI goes group
        after group, each with its sub-directories then its labs, so the two kinds alternate in
        one directory; the tree draws that order (the fake ``sre`` only lists the
        sub-directories first: the list of the pool is replaced)."""
        def entry(name, kind='lab', subtitle=None):
            entry = {'name': name, 'title': None, 'kind': kind, 'sort': 'manual'}
            return dict(entry, subtitle=subtitle) if subtitle else entry

        mixed = [entry('intro.py'),
                 entry('a', 'dir', 'Group A'), entry('a/x.py'), entry('top.py'),
                 entry('sre', 'dir', 'Group B'), entry(DHCP, subtitle='Inside'), entry('sre/deep', 'dir'),
                 entry('sre/deep/y.py'), entry('last.py')]

        async def go():
            async with browser_of(tmp_path, ALICE) as (h, browser, url):
                async def labs(identity, *, all_labs=False):
                    return mixed
                h.portal.pool.labs = labs
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(tree_rows()) == [
                    ['leaf', 'intro.py'],
                    ['subtitle', 'Group A'], ['dir', 'a'], ['leaf', 'top.py'],
                    ['subtitle', 'Group B'], ['dir', 'sre'], ['leaf', 'last.py']]
                assert await page.evaluate(tree_rows('sre')) == [
                    ['subtitle', 'Inside'], ['leaf', DHCP], ['dir', 'deep']]
                # a lab below two directories is still found, selected and its directories opened
                await toggle(page, 'sre')
                await toggle(page, 'deep')
                await page.click(lab_button('sre/deep/y.py'))
                assert await page.evaluate(SELECTED) == 'sre/deep/y.py'
        P.run(go())

    def test_no_subtitle_no_row(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env={'MOCK_LAB_LIST': json.dumps(SUBTITLE_LABS)}) as (
                    h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate(tree_rows()) == [['dir', 'a'], ['dir', 's4'], ['dir', 'sre'],
                                                            ['leaf', 'top.py']]
                assert await page.evaluate("document.querySelectorAll('#labs li.subtitle').length") == 0
        P.run(go())


# ---------------------------------------------------------------------------------------------
# The Host and Engine selects of the instructors
# ---------------------------------------------------------------------------------------------

KATHARA_ONLY = 's4/tp_ssh'      # a lab of the catalog of the fake sre, told below to accept Kathara alone
BOTH_ENGINES = {'MOCK_ENGINES': '["podman", "kathara"]', 'MOCK_LAB_ENGINES': json.dumps({KATHARA_ONLY: ['kathara']})}
# [value, disabled] of every option of a select, and the value chosen
OPTIONS = "((id) => [...document.getElementById(id).options].map((o) => [o.value, o.disabled]))"
CHOSEN = "((id) => document.getElementById(id).value)"
SHOWN = "((id) => { const e = document.getElementById(id); return e !== null && !e.hidden; })"


def choose(element: str, value: str) -> str:
    """Pick *value* in the select *element*, as a user does (a JavaScript statement)."""
    return (f"(() => {{ const s = document.getElementById({json.dumps(element)}); s.value = {json.dumps(value)}; "
            f"s.dispatchEvent(new Event('change', {{bubbles: true}})); }})()")


def select_lab(name: str) -> str:
    """Select the lab *name* of the tree, wherever its directory is (a JavaScript statement)."""
    return f"document.querySelector({json.dumps(lab_button(name))}).click()"


class TestHostAndEngine:
    """An instructor may name the host and the container engine of a new project; both are
    automatic by default, and only what the selected lab can run with is offered."""

    def test_any_host_and_the_engines_of_the_pool(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, PROF, mock_env=BOTH_ENGINES) as (h, browser, url):
                await h.portal.pool.refresh()
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                await page.wait_for(f"{SHOWN}('engine-option')", what="the Engine select")
                # a host that is not reserved for instructors is listed too; automatic by default
                assert await page.evaluate(f"{SHOWN}('host-option')")
                assert await page.evaluate(f"{OPTIONS}('host')") == [['', False], ['a01', False]]
                assert await page.evaluate(f"{OPTIONS}('engine')") == [['', False], ['podman', False], ['kathara', False]]
                assert await page.evaluate(f"[{CHOSEN}('host'), {CHOSEN}('engine')]") == ['', '']
                text = await page.evaluate("document.querySelector('#host option[value=\"a01\"]').textContent")
                assert text == 'a01 (up, 0/3)'
        P.run(go())

    def test_only_what_the_selected_lab_can_run_with(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, PROF, mock_env=BOTH_ENGINES) as (h, browser, url):
                await h.portal.pool.refresh()
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                await page.wait_for(f"{SHOWN}('engine-option')", what="the Engine select")
                await page.click(lab_button(DHCP))
                await page.evaluate(choose('engine', 'podman'))
                assert await page.evaluate(f"{CHOSEN}('engine')") == 'podman'
                # a lab that accepts Kathara alone: Podman is greyed, and the choice goes back to automatic
                await page.evaluate(select_lab(KATHARA_ONLY))
                await page.wait_for(f"{CHOSEN}('engine') === ''", what="the engine back to automatic")
                assert await page.evaluate(f"{OPTIONS}('engine')") == [['', False], ['podman', True], ['kathara', False]]
                assert await page.evaluate(f"{OPTIONS}('host')") == [['', False], ['a01', False]]
                # back on a lab that accepts every engine: everything is offered again
                await page.click(lab_button(DHCP))
                await page.wait_for(f"JSON.stringify({OPTIONS}('engine')[1]) === '[\"podman\",false]'",
                                    what="Podman offered again")
        P.run(go())

    def test_a_project_started_on_the_host_and_with_the_engine_chosen(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, PROF, mock_env=BOTH_ENGINES) as (h, browser, url):
                await h.portal.pool.refresh()
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                await page.wait_for(f"{SHOWN}('engine-option')", what="the Engine select")
                await page.click(lab_button(DHCP))
                await page.evaluate(choose('host', 'a01'))
                await page.evaluate(choose('engine', 'kathara'))
                await page.click('#start-button')
                await page.wait_for("location.pathname.includes('/projects/')", what="the page of the new project")
                (project,) = (h.pub / 'projects').iterdir()
                assert json.loads((project / '.private' / 'origin.json').read_text())['engine'] == 'kathara'
        P.run(go())

    def test_a_pool_with_one_engine_has_nothing_to_choose(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, PROF) as (h, browser, url):
                await h.portal.pool.refresh()
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                await page.wait_for(f"{SHOWN}('host-option')", what="the Host select")
                assert not await page.evaluate(f"{SHOWN}('engine-option')")
                assert await page.evaluate(f"{OPTIONS}('engine')") == [['', False]]
        P.run(go())

    def test_a_reserved_host_is_said_so(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, PROF, host_over={'instructors_only': True}) as (h, browser, url):
                await h.portal.pool.refresh()
                page = await browser.page(f'{url}/open')
                await page.wait_for(f"{SHOWN}('host-option')", what="the Host select")
                text = await page.evaluate("document.querySelector('#host option[value=\"a01\"]').textContent")
                assert text == 'a01 (up, 0/3, reserved for instructors)'
        P.run(go())

    def test_students_have_neither(self, tmp_path):
        async def go():
            async with browser_of(tmp_path, ALICE, mock_env=BOTH_ENGINES) as (h, browser, url):
                page = await browser.page(f'{url}/open')
                await page.wait_for(has_lab(DHCP), what="the lab tree")
                assert await page.evaluate("document.getElementById('host') === null "
                                           "&& document.getElementById('engine') === null")
                assert 'ngine' not in await page.evaluate("document.body.textContent")
        P.run(go())
