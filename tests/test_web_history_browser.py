"""The History page of the administrators in a headless Chrome (``web_browser.py``; skipped
without Google Chrome / Chromium, ``SRE_TEST_CHROME`` names one) on the real pages of ``web/``
served by the portal of test_web_portal.py (proxy mode behind an identity proxy, the connection
log on the fake database of test_web_accessdb.py): the Sessions and Events tables sorted by a
click on their headers, on the rows shown (table_sort.js): the default orders are the server's,
a text column comes ascending on the first click and a time or a number descending, a second
click reverses, the logins and addresses follow the collation of the site (``etu9`` before
``etu10``, ``10.0.1.9`` before ``10.0.1.10``), a missing value is the smallest, an open session
counts as not ended yet, the ``aria-sort`` marks follow, and the sort of a view is kept when the
page comes back to it."""
import contextlib
import json
from datetime import datetime
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

import test_web_portal as P                                   # noqa: E402  (the harness of the portal)
from test_web_accessdb import FakeServer, Down, NAMES         # noqa: E402  (the fake database)
from web_browser import Browser, IdentityProxy, find_chrome  # noqa: E402

CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="no Google Chrome / Chromium found (SRE_TEST_CHROME names one)")

WEB = Path(__file__).resolve().parents[1] / 'web'            # the real pages, not the stubs of the harness
PROF = P.who('prof', 'Prof Essor', groups=P.TEACHERS)        # the administrator, the identity of the browser
DB = {'host': 'db.example.org', 'user': 'sre_web', 'name': 'sre'}
SESSIONS_TABLE, EVENTS_TABLE = 'history-sessions', 'history'


def session_row(id_, closed_utc, login, addr, duration, details) -> tuple:
    return (id_, closed_utc, 'session_close', login, addr, '', '', '', '', float(duration), json.dumps(details))


def event_row(id_, ts, event, login, addr, host, rln, lab, status, duration, details) -> tuple:
    return (id_, ts, event, login, addr, host, rln, lab, status, duration, json.dumps(details))


#: Three closed sessions as the database gives them (newest closing line first, the order of the
#: ids), whose end times come in the same order: the default order of the table is the server's.
SESSIONS = [
    session_row(9, datetime(2026, 10, 26, 9, 0, 0), 'etu10', '10.0.1.10', 1800,
                {'role': 'student', 'name': 'Zoé Dix', 'group': 'INFO1', 'reason': 'idle',
                 'since': '2026-10-26T09:00:00+0100', 'requests': 14, 'projects': ['1761466323@@@dhcp@@@etu10']}),
    session_row(5, datetime(2026, 10, 26, 7, 40, 0), 'bob', '10.0.1.2', 600,
                {'role': 'student', 'name': 'Bob Deux', 'group': 'INFO2', 'reason': 'logout',
                 'since': '2026-10-26T08:30:00+0100', 'requests': 2, 'projects': []}),
    session_row(3, datetime(2026, 10, 26, 7, 0, 0), 'etu9', '10.0.1.9', 7200,
                {'role': 'student', 'name': 'Alice Neuf', 'group': 'INFO1', 'reason': 'shutdown',
                 'since': '2026-10-26T06:00:00+0100', 'requests': 40,
                 'projects': ['1761466000@@@dhcp@@@etu9', '1761466100@@@dns@@@etu9']}),
]
#: Three events, newest first; the denied line has no duration.
EVENTS = [
    event_row(30, datetime(2026, 10, 26, 9, 5, 0), 'start', 'etu9', '10.0.1.9', 'a01', '1761466323@@@dhcp@@@etu9',
              'sre/dhcp.py', '200', 12.5, {'result': 'created'}),
    event_row(20, datetime(2026, 10, 26, 8, 5, 0), 'denied', 'bob', '10.0.1.10', '', '', '', '403', None, {'path': '/history'}),
    event_row(10, datetime(2026, 10, 26, 7, 5, 0), 'eval', 'etu10', '10.0.1.2', 'a01', '1761466323@@@dhcp@@@etu10', '',
              '200', 3.0, {}),
]

# -- what the page shows, as JavaScript expressions ---------------------------------------------


def column(table: str, index: int) -> str:
    """The texts of the cells of column *index* (from 1) of the rows of *table*."""
    return f"[...document.querySelectorAll('#{table} tbody tr td:nth-child({index})')].map((td) => td.textContent)"


def row_count(table: str) -> str:
    return f"document.querySelectorAll('#{table} tbody tr').length"


def aria_sort(table: str, key: str) -> str:
    return f"document.querySelector('#{table} th[data-sort=\"{key}\"]').getAttribute('aria-sort')"


def header(table: str, key: str) -> str:
    return f'#{table} th[data-sort="{key}"]'


async def sort_by(page, table: str, key: str, direction: str):
    """Click the header *key* of *table* and wait for its mark to be *direction*."""
    await page.click(header(table, key))
    await page.wait_for(f"{aria_sort(table, key)} === '{direction}'", what=f"the {key} header of #{table} marked {direction}")


@contextlib.asynccontextmanager
async def browser_of(tmp_path):
    """The harness (proxy mode, the real web directory, the fake database the connection log is
    written to and read from), the identity proxy making the browser the administrator, and the
    browser: ``(server, browser, url)``."""
    server = FakeServer(table_exists=True)
    over = {**P.PROXY_OVER, 'auth': {**P.PROXY_OVER['auth'], 'administrators': ['prof']},
            'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False, 'database': DB}}
    h = P.Harness(tmp_path, auth_mode='proxy', web_over=over, db_connect=(server.connect, (Down,)))
    h.web_dir = WEB
    async with h:
        proxy = IdentityProxy(f'http://127.0.0.1:{h.client.port}', PROF)
        await proxy.start()
        try:
            async with Browser(CHROME) as browser:
                yield server, browser, proxy.url
        finally:
            await proxy.close()


class TestHistorySort:
    def test_sessions_and_events_sorted_by_their_headers(self, tmp_path):
        async def go():
            async with browser_of(tmp_path) as (server, browser, url):
                server.select_names = NAMES
                server.select_rows = SESSIONS
                page = await browser.page(f'{url}/history')
                await page.wait_for(f"{row_count(SESSIONS_TABLE)} === 4", what="the three closed sessions and the open one")
                # the server's order: the open session of the administrator (not ended yet) first, then
                # the closed ones by end time, newest first; the End time header alone is marked
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['prof', 'etu10', 'bob', 'etu9']
                assert await page.evaluate(aria_sort(SESSIONS_TABLE, 'end')) == 'descending'
                assert await page.evaluate(aria_sort(SESSIONS_TABLE, 'login')) == 'none'
                # a text column: ascending first, the collation of the site (etu9 before etu10), the open
                # session among the others; a second click reverses
                await sort_by(page, SESSIONS_TABLE, 'login', 'ascending')
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['bob', 'etu9', 'etu10', 'prof']
                assert await page.evaluate(aria_sort(SESSIONS_TABLE, 'end')) == 'none'
                await sort_by(page, SESSIONS_TABLE, 'login', 'descending')
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['prof', 'etu10', 'etu9', 'bob']
                await sort_by(page, SESSIONS_TABLE, 'name', 'ascending')
                assert await page.evaluate(column(SESSIONS_TABLE, 2)) == ['Alice Neuf', 'Bob Deux', 'Prof Essor', 'Zoé Dix']
                # a time: descending first (the open session started now), then ascending
                await sort_by(page, SESSIONS_TABLE, 'start', 'descending')
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['prof', 'etu10', 'bob', 'etu9']
                await sort_by(page, SESSIONS_TABLE, 'start', 'ascending')
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['etu9', 'bob', 'etu10', 'prof']
                # a number: descending first; the open session lasted a few seconds, last
                await sort_by(page, SESSIONS_TABLE, 'duration', 'descending')
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['etu9', 'etu10', 'bob', 'prof']
                # the projects as the cell shows them (the labs): the two without any tie in the server's
                # order (the open session first), then dhcp, then "dhcp, dns"
                await sort_by(page, SESSIONS_TABLE, 'projects', 'ascending')
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['prof', 'bob', 'etu10', 'etu9']
                # the events view: newest first by default, the Time header marked; then by event name,
                # by address (10.0.1.2, 10.0.1.9, 10.0.1.10), by status (descending first, the ties in the
                # server's order) and by duration (the line without one last)
                server.select_rows = EVENTS
                await page.click('.history-views button[data-view="events"]')
                await page.wait_for(f"{row_count(EVENTS_TABLE)} === 3", what="the three events")
                assert await page.evaluate(column(EVENTS_TABLE, 3)) == ['etu9', 'bob', 'etu10']
                assert await page.evaluate(aria_sort(EVENTS_TABLE, 'ts')) == 'descending'
                await sort_by(page, EVENTS_TABLE, 'event', 'ascending')
                assert await page.evaluate(column(EVENTS_TABLE, 2)) == ['denied', 'eval', 'start']
                await sort_by(page, EVENTS_TABLE, 'addr', 'ascending')
                assert await page.evaluate(column(EVENTS_TABLE, 4)) == ['10.0.1.2', '10.0.1.9', '10.0.1.10']
                await sort_by(page, EVENTS_TABLE, 'status', 'descending')
                assert await page.evaluate(column(EVENTS_TABLE, 8)) == ['403', '200', '200']
                assert await page.evaluate(column(EVENTS_TABLE, 3)) == ['bob', 'etu9', 'etu10']
                await sort_by(page, EVENTS_TABLE, 'duration', 'descending')
                assert await page.evaluate(column(EVENTS_TABLE, 3)) == ['etu9', 'etu10', 'bob']
                # back to the sessions (two of them now, so that the reload is seen): their sort is kept
                server.select_rows = SESSIONS[:2]
                await page.click('.history-views button[data-view="sessions"]')
                await page.wait_for(f"{row_count(SESSIONS_TABLE)} === 3", what="the two closed sessions and the open one")
                assert await page.evaluate(aria_sort(SESSIONS_TABLE, 'projects')) == 'ascending'
                assert await page.evaluate(column(SESSIONS_TABLE, 1)) == ['prof', 'bob', 'etu10']
                assert await page.evaluate(aria_sort(EVENTS_TABLE, 'duration')) == 'descending'
        P.run(go())
