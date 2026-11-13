"""The Open page of the web front-end in a headless Chrome (``web_browser.py``; skipped without
Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/`` served by
the portal of test_web_portal.py (proxy mode behind an identity proxy, a real agent on the fake
``sre``): the project mode of the instructors (Standard / Instructor mode / Debug mode; the
students have none), the lab tree listing every lab of the host in debug mode and the student
catalog otherwise, the selection kept across the reload while the lab is still listed, a
debug project started from the page, and the Projects page saying the mode of each project of
an instructor (the Mode line of the cards, the suffix of the title)."""
import contextlib
import json
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
            async with browser_of(tmp_path, PROF, over=over, host_over={'max_projects': 4}) as (h, browser, url):
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
                    ('card debug', ' (debug)', 'Mode: Debug mode'),
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
