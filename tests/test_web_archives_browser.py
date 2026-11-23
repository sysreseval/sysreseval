"""The archive file of an evaluation on the Archives page, in a headless Chrome (``web_browser.py``;
skipped without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of
``web/`` served by the portal of test_web_portal.py (proxy mode behind an identity proxy, the
archives table a fake database answering by statement, ``[archives] directory`` a directory of
real archive files): the button of the dialog of an evaluation, the dialog of the file with its
six tabs (the commands and their outputs, the answers, the data, the errors, the grades, the
saved files), a download, a file moved or removed while the page is open, and the page of a
portal without the files."""
import contextlib
import json
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                          # noqa: E402  (the harness of the portal)
from test_web_accessdb import FakeServer, Down                       # noqa: E402  (the fake database)
from test_web_archive_files import archive, write, NAME, RLN         # noqa: E402  (a real archive file)
from web_browser import Browser, IdentityProxy, find_chrome         # noqa: E402
from SRE.archive_summary import archive_record, read_archive         # noqa: E402
from sreweb.portal.archives import COLUMNS, row_of_record            # noqa: E402

CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
PROF = P.who('prof', 'Prof Essor', groups=P.TEACHERS)        # an instructor, the identity of the browser
DB = {'host': 'db.example.org', 'user': 'sre_web', 'name': 'sre'}
ROW_ID = 5

DETAIL, FILE = 'dialog.archive-detail', 'dialog.archive-file'


class ArchivesServer(FakeServer):
    """The archives table as far as the page reads it: one row (``row``: its columns, without
    the id), listed without its details, read whole by its id; its lab for the suggestions."""

    def __init__(self, row: tuple):
        super().__init__(table_exists=True)
        self.row = row

    def dispatch(self, cursor, sql, args) -> bool:
        if not sql.startswith('SELECT'):
            return False
        if sql.startswith('SELECT DISTINCT'):
            cursor.description = [('value',)]
            cursor._rows = [('sre/dhcp.py',)] if 'canonical_lab' in sql else []
        elif 't.details' in sql:
            cursor.description = [(name,) for name in ('id', *COLUMNS)]
            cursor._rows = [(ROW_ID, *self.row)] if args and args[0] == ROW_ID else []
        elif sql.startswith('SELECT t.id'):
            cursor.description = [(name,) for name in ('id', *COLUMNS[:-1])]
            cursor._rows = [(ROW_ID, *self.row[:-1])]
        else:
            return False
        return True


def texts(selector: str) -> str:
    return f"[...document.querySelectorAll({json.dumps(selector)})].map((e) => e.textContent)"


def count(selector: str) -> str:
    return f"document.querySelectorAll({json.dumps(selector)}).length"


def text(selector: str) -> str:
    return f"(document.querySelector({json.dumps(selector)}) || {{textContent: null}}).textContent"


async def tab(page, name: str):
    """Show the tab *name* of the dialog of the file."""
    await page.click(f'{FILE} .tabbar [data-tab="{name}"]')
    await page.wait_for(f"document.querySelector('{FILE} .tabbar [data-tab=\"{name}\"]').getAttribute('aria-selected') === 'true'",
                        what=f"the tab {name} selected")


async def open_file(page):
    """From the page: the dialog of the evaluation of the row, then the dialog of its file."""
    await page.wait_for(f"{count('#archives tbody tr')} === 1", what="the row of the evaluation")
    await page.click('#archives tbody tr td:nth-child(2)')
    await page.wait_for(f"{count(DETAIL + '[open] table.evaluation tr')} > 1", what="the dialog of the evaluation")
    await page.click(f'{DETAIL} .archive-file-open')
    await page.wait_for(count(f'{FILE}[open]'), what="the dialog of the archive file")


@contextlib.asynccontextmanager
async def browser_of(tmp_path, *, files: bool = True):
    """The harness (proxy mode, the real web directory, the archives table of one row whose file
    is in the directory given to the portal when *files*), the identity proxy making the browser
    an instructor, and the browser: ``(the path of the archive file, browser, url)``."""
    directory = tmp_path / 'archive-files'
    path = write(directory / 'current' / 'a12' / NAME)
    server = ArchivesServer(row_of_record('a01', archive_record(read_archive(str(path)), str(path))))
    over = {**P.PROXY_OVER, 'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False, 'database': DB},
            'archives': {'poll_interval': '1h', **({'directory': str(directory)} if files else {})}}
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over, db_connect=(server.connect, (Down,)))
    h.web_dir = WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', PROF)
        await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield path, browser, proxy.url
        finally:
            await proxy.close()


class TestArchiveFile:
    def test_the_sections_of_the_file(self, tmp_path):
        async def go():
            async with browser_of(tmp_path) as (path, browser, url):
                page = await browser.page(f'{url}/archives')
                await open_file(page)
                await page.wait_for(f"{count(FILE + ' .tabbar [role=tab]')} === 6", what="the six tabs")
                # the name of the file, where it was found, its size
                assert await page.evaluate(text(f'{FILE} h2')) == NAME
                caption = await page.evaluate(text(f'{FILE} .evaluation-caption'))
                assert caption.startswith('current/a12 · ') and ' B · ' in caption
                assert await page.evaluate(f"document.querySelector('{FILE} .archive-file-warning').hidden") is True
                assert await page.evaluate(texts(f'{FILE} .tabbar [role=tab]')) == \
                    ['Tests (4)', 'Answers', 'Data', 'Errors (3)', 'Grades', 'Files (2)']
                # the commands of each machine and step, unfolded (few of them), with their outcome
                assert await page.evaluate(texts(f'{FILE} details.archive-tests > summary strong')) == ['lan', 'pc1', 'r1']
                assert await page.evaluate(f"[...document.querySelectorAll('{FILE} details.archive-tests')].map((d) => d.open)") == \
                    [True, True, True]
                summaries = await page.evaluate(texts(f'{FILE} details.archive-tests > summary'))
                assert summaries[1] == 'pc1 — step 2 (1 command(s), 1 with a non-zero exit code)'
                assert summaries[2] == 'r1 — step 1 (2 command(s), 1 with a non-zero exit code)'
                assert await page.evaluate(texts(f'{FILE} .archive-command-line code')) == \
                    ['$ vlan/print', '$ ping -c1 10.0.1.1', '$ ip -br addr show eth0', '$ systemctl is-active isc-dhcp-server']
                assert await page.evaluate(texts(f'{FILE} .archive-code')) == ['exit 0', 'timeout', 'exit 0', 'exit 3']
                assert await page.evaluate(f"[...document.querySelectorAll('{FILE} .archive-code')].map((e) => e.className)") == \
                    ['archive-code ok', 'archive-code timeout', 'archive-code ok', 'archive-code error']
                assert await page.evaluate(texts(f'{FILE} pre.archive-output')) == ['ok', 'eth0 UP 10.0.1.1/24\n', 'inactive\n']
                assert await page.evaluate(texts(f'{FILE} .archive-no-output')) == ['(no output)']
                # Fold all / Unfold all
                await page.click(f'{FILE} .archive-file-tools button')
                assert await page.evaluate(f"[...document.querySelectorAll('{FILE} details.archive-tests')].some((d) => d.open)") is False
                assert await page.evaluate(text(f'{FILE} .archive-file-tools button')) == 'Unfold all'
                # the dialog stays in the window, over the dialog of the evaluation; its pane scrolls
                box = await page.evaluate(
                    f"(() => {{ const d = document.querySelector('{FILE}').getBoundingClientRect();"
                    f" const p = document.querySelector('{FILE} .archive-file-pane').getBoundingClientRect();"
                    " return {top: d.top, bottom: d.bottom, height: innerHeight, pane: [p.top, p.bottom]}; })()")
                assert 0 <= box['top'] < box['bottom'] <= box['height']
                assert box['top'] < box['pane'][0] < box['pane'][1] < box['bottom']
                assert await page.evaluate(count(f'{DETAIL}[open]')) == 1
                # the answers: who answered, then each answer under the hash of its question
                await tab(page, 'answers')
                assert await page.evaluate(texts(f'{FILE} table.archive-answers th[scope=row]')) == \
                    ['login', 'fullname', 'hostname', 'client', 'cfc14058', 'e8773696']
                assert await page.evaluate(texts(f'{FILE} table.archive-answers td pre')) == \
                    ['bob', 'Bob Test', 'a12', 'web', '{\n  "vlan": 10\n}', 'a text']
                # the data of the lab and the grades, as sre cat prints them
                await tab(page, 'data')
                assert json.loads(await page.evaluate(text(f'{FILE} pre.archive-json'))) == \
                    {'secret': 'x7', 'ips': {'r1': '10.0.1.1/24'}}
                await tab(page, 'grades')
                grades = json.loads(await page.evaluate(text(f'{FILE} pre.archive-json')))
                assert grades['running_lab_name'] == RLN and grades['grade_list'][0]['max_grade'] == 2.0
                # the errors first, then the warnings; a text with translations in the language of the page
                await tab(page, 'errors')
                assert await page.evaluate(texts(f'{FILE} .evaluation-errors li')) == \
                    ['[ERROR] pc1 unreachable', '[ERROR] an old entry', '[WARNING] slow']
                # the saved files, one of them downloaded: what the browser is given to save
                await tab(page, 'files')
                assert await page.evaluate(texts(f'{FILE} table.archive-saved tbody td:first-child')) == \
                    ['capture.pcap', 'notes.txt']
                assert await page.evaluate(texts(f'{FILE} table.archive-saved tbody td.number')) == ['6 B', '6 B']
                # (the link clicked and its blob are recorded instead of a file being written: the
                # policy of the page lets no script read a blob: address back)
                await page.evaluate(
                    "(() => { window.saved = []; window.blobs = []; const make = URL.createObjectURL;"
                    " URL.createObjectURL = (blob) => { window.blobs.push(blob); return make.call(URL, blob); };"
                    " HTMLAnchorElement.prototype.click = function () {"
                    " window.saved.push({name: this.download, href: this.href, inDialog: !!this.closest('dialog')}); }; })()")
                await page.click(f'{FILE} table.archive-saved tbody tr:nth-child(2) button')
                await page.wait_for("window.saved.length === 1", what="the saved file handed to the browser")
                saved = await page.evaluate("window.saved[0]")
                assert saved['name'] == 'notes.txt' and saved['href'].startswith('blob:') and saved['inDialog'] is True
                assert await page.evaluate("window.blobs[0].text()") == 'hello\n'
                # ... and the archive itself
                await page.click(f'{FILE} .buttons button:first-child')
                await page.wait_for("window.saved.length === 2", what="the archive handed to the browser")
                assert await page.evaluate("window.saved[1].name") == NAME
                assert await page.evaluate("window.blobs[1].size") == path.stat().st_size
                assert await page.evaluate(f"document.querySelector('{FILE} .archive-file-status').hidden") is True
                # Close: back to the dialog of the evaluation
                await page.click(f'{FILE} .buttons button:last-child')
                await page.wait_for(f"{count(FILE)} === 0 && {count(DETAIL + '[open]')} === 1", what="the dialog of the file closed")
                assert not page.errors
        P.run(go())

    def test_a_file_moved_then_removed_while_the_page_is_open(self, tmp_path):
        async def go():
            async with browser_of(tmp_path) as (path, browser, url):
                page = await browser.page(f'{url}/archives')
                await open_file(page)
                await page.wait_for(f"({text(FILE + ' .evaluation-caption')} || '').startsWith('current/a12')", what="the file found")
                await page.click(f'{FILE} .buttons button:last-child')
                # the nightly rotation: the directory renamed
                (path.parents[1]).rename(path.parents[2] / '2026-11-22')
                moved = path.parents[2] / '2026-11-22' / 'a12' / NAME
                await page.click(f'{DETAIL} .archive-file-open')
                await page.wait_for(f"({text(FILE + ' .evaluation-caption')} || '').startsWith('2026-11-22/a12')",
                                    what="the file found where it was moved")
                assert await page.evaluate(count(f'{FILE} .tabbar [role=tab]')) == 6
                await page.click(f'{FILE} .buttons button:last-child')
                # the file purged: said so, with a Retry button; a download says so in the dialog too
                kept = moved.read_bytes()
                moved.unlink()
                write(moved.parent / ('20261122100000_' + RLN + '.zst'))       # the directory still holds archives
                await page.click(f'{DETAIL} .archive-file-open')
                await page.wait_for(f"({text(FILE + ' .evaluation-caption')} || '').startsWith('Error')", what="the error shown")
                assert await page.evaluate(text(f'{FILE} .evaluation-caption')) == \
                    'Error: the archive file is not in the archives directory'
                assert await page.evaluate(f"[...document.querySelectorAll('{FILE} .buttons button')]"
                                           ".map((b) => [b.textContent, b.hidden, b.disabled])") == \
                    [['Download the archive', False, True], ['Retry', False, False], ['Close', False, False]]
                assert await page.evaluate(count(f'{FILE} .tabbar [role=tab]')) == 0
                # the file is back: Retry shows it
                moved.write_bytes(kept)
                await page.click(f'{FILE} .buttons button:nth-child(2)')
                await page.wait_for(f"{count(FILE + ' .tabbar [role=tab]')} === 6", what="the file shown after Retry")
                assert await page.evaluate(f"document.querySelector('{FILE} .buttons button:nth-child(2)').hidden") is True
                # removed between the view and a download: the error is in the dialog
                moved.unlink()
                await page.click(f'{FILE} .buttons button:first-child')
                await page.wait_for(f"!document.querySelector('{FILE} .archive-file-status').hidden", what="the download refused")
                assert await page.evaluate(text(f'{FILE} .archive-file-status')) == \
                    'Error: the archive file is not in the archives directory'
                assert not page.errors
        P.run(go())

    def test_no_button_without_the_files(self, tmp_path):
        """A portal without ``[archives] directory``: the dialog of an evaluation as before."""
        async def go():
            async with browser_of(tmp_path, files=False) as (_path, browser, url):
                page = await browser.page(f'{url}/archives')
                assert await page.evaluate("document.getElementById('archives').dataset.files") == 'false'
                await page.wait_for(f"{count('#archives tbody tr')} === 1", what="the row of the evaluation")
                await page.click('#archives tbody tr td:nth-child(2)')
                await page.wait_for(f"{count(DETAIL + '[open] table.evaluation tr')} > 1", what="the dialog of the evaluation")
                assert await page.evaluate(count(f'{DETAIL} .archive-file-open')) == 0
                assert await page.evaluate(texts(f'{DETAIL} .buttons button')) == ['Close']
                assert not page.errors
        P.run(go())
