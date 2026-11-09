"""A headless Chrome driven through the DevTools protocol, and an identity proxy, for the
browser tests of the web front-end (``test_web_exam_browser.py``): no driver package, aiohttp
alone (the websocket of the protocol), the browser found on the machine (``SRE_TEST_CHROME``,
else Google Chrome / Chromium on the PATH or at its usual place: the tests skip without one).

    async with Browser() as browser:
        page = await browser.page(url)
        await page.wait_for("document.querySelector('#x') !== null")
        value = await page.evaluate("document.title")

``Page.evaluate`` runs one JavaScript expression in the page (a promise is awaited, the value
comes back by value), ``wait_for`` polls one until it is true (a navigation in between is no
error), ``console`` and ``errors`` collect what the page logged and the exceptions it threw.

``IdentityProxy`` puts the headers of proxy mode (``X-Remote-User``...) on every request of
the browser, HTTP and WebSocket, so that the browser is one given user of a portal in proxy
mode, as Apache would make it; the ``Host`` header is kept (the portal checks the ``Origin``
of the browser against it, like ProxyPreserveHost)."""
import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time

import aiohttp
from aiohttp import web

CHROME_ENV = 'SRE_TEST_CHROME'
CHROME_CANDIDATES = ('google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser',
                     '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                     '/Applications/Chromium.app/Contents/MacOS/Chromium')
# the headers a proxy never forwards (the connection ones and those the client library sets again)
HOP_HEADERS = {'connection', 'upgrade', 'sec-websocket-key', 'sec-websocket-version', 'sec-websocket-extensions',
               'sec-websocket-protocol', 'content-length', 'transfer-encoding', 'accept-encoding', 'keep-alive'}


def find_chrome() -> str | None:
    """The browser to run: ``SRE_TEST_CHROME`` (a name on the PATH or a path), else the first
    candidate found; ``None`` without one."""
    given = os.environ.get(CHROME_ENV)
    if given:
        return given if os.path.isabs(given) and os.access(given, os.X_OK) else shutil.which(given)
    for name in CHROME_CANDIDATES:
        if os.path.isabs(name):
            if os.access(name, os.X_OK):
                return name
        elif shutil.which(name):
            return shutil.which(name)
    return None


class BrowserError(Exception):
    """The browser could not be run, or the protocol refused a command."""


class JsError(Exception):
    """An expression threw in the page."""


class Page:
    """One tab, attached in flatten mode: the commands carry its session id."""

    def __init__(self, browser, target_id: str, session_id: str):
        self.browser = browser
        self.target_id = target_id
        self.session_id = session_id
        self.console = []        # (type, text) of the console calls of the page
        self.errors = []         # the uncaught exceptions of the page (their text)
        self.closed = False

    def _event(self, method: str, params: dict):
        if method == 'Runtime.consoleAPICalled':
            text = ' '.join(str(a.get('value', a.get('description', ''))) for a in params.get('args', []))
            self.console.append((params.get('type', 'log'), text))
        elif method == 'Runtime.exceptionThrown':
            details = params.get('exceptionDetails', {})
            exc = details.get('exception') or {}
            self.errors.append(exc.get('description') or details.get('text') or str(details))

    async def goto(self, url: str, timeout: float = 15.0):
        """Load *url* and wait for the page to be complete."""
        result = await self.browser.send('Page.navigate', {'url': url}, session_id=self.session_id)
        if result.get('errorText'):
            raise BrowserError(f"navigation to {url} failed: {result['errorText']}")
        await self.wait_for("document.readyState === 'complete'", timeout=timeout, what=f"the load of {url}")

    async def evaluate(self, expression: str):
        """The value of a JavaScript *expression* (a promise awaited); ``JsError`` when it
        throws, ``BrowserError`` when the page is between two documents."""
        result = await self.browser.send('Runtime.evaluate', {'expression': expression, 'returnByValue': True,
                                                              'awaitPromise': True}, session_id=self.session_id)
        details = result.get('exceptionDetails')
        if details:
            exc = details.get('exception') or {}
            raise JsError(exc.get('description') or details.get('text') or str(details))
        return result.get('result', {}).get('value')

    async def wait_for(self, expression: str, timeout: float = 10.0, *, interval: float = 0.2, what: str = ''):
        """Poll *expression* until it is true, and return its value; ``AssertionError`` after
        *timeout* seconds, naming *what* was expected, the page's address and its errors."""
        deadline = time.monotonic() + timeout
        last = None
        while True:
            try:
                last = await self.evaluate(expression)
                if last:
                    return last
            except (BrowserError, JsError) as e:          # a navigation in progress, or a page not loaded yet
                last = f'({e})'
            if time.monotonic() >= deadline:
                url = await self.url()
                raise AssertionError(f"timeout waiting for {what or expression!r} on {url}: last value {last!r}; "
                                     f"errors {self.errors}")
            await asyncio.sleep(interval)

    async def url(self) -> str:
        try:
            return await self.evaluate('window.location.href')
        except (BrowserError, JsError):
            return '?'

    async def click(self, selector: str):
        await self.evaluate(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); "
                            f"if (!e) throw new Error('no element {selector}'); e.click(); return true; }})()")

    # -- input events (the drag of a floating terminal window, typing in an xterm) --------------

    async def mouse(self, kind: str, x: float, y: float):
        """One left-button mouse event (``mousePressed`` / ``mouseMoved`` / ``mouseReleased``) at
        page coordinates; a move carries the pressed button (a drag)."""
        params = {'type': kind, 'x': x, 'y': y, 'button': 'left', 'clickCount': 1}
        if kind == 'mouseMoved':
            params['buttons'] = 1
        await self.browser.send('Input.dispatchMouseEvent', params, session_id=self.session_id)

    async def hover(self, x: float, y: float):
        """Move the mouse to page coordinates with no button pressed (the mousemove of a hover,
        not of a drag)."""
        await self.browser.send('Input.dispatchMouseEvent', {'type': 'mouseMoved', 'x': x, 'y': y, 'button': 'none',
                                                             'buttons': 0}, session_id=self.session_id)

    async def click_at(self, x: float, y: float):
        await self.mouse('mousePressed', x, y)
        await self.mouse('mouseReleased', x, y)

    async def drag(self, x0: float, y0: float, x1: float, y1: float, steps: int = 4):
        """Press at (x0, y0), move in *steps* to (x1, y1), release there."""
        await self.mouse('mousePressed', x0, y0)
        for i in range(1, steps + 1):
            await self.mouse('mouseMoved', x0 + (x1 - x0) * i / steps, y0 + (y1 - y0) * i / steps)
        await self.mouse('mouseReleased', x1, y1)

    async def insert_text(self, text: str):
        """Type *text* into the focused element (one ``input`` event, as an IME commits)."""
        await self.browser.send('Input.insertText', {'text': text}, session_id=self.session_id)

    async def press_enter(self):
        for kind in ('keyDown', 'keyUp'):
            params = {'type': kind, 'key': 'Enter', 'code': 'Enter', 'windowsVirtualKeyCode': 13,
                      'nativeVirtualKeyCode': 13}
            if kind == 'keyDown':
                params.update(text='\r', unmodifiedText='\r')
            await self.browser.send('Input.dispatchKeyEvent', params, session_id=self.session_id)

    async def close(self):
        if not self.closed:
            self.closed = True
            await self.browser.send('Target.closeTarget', {'targetId': self.target_id})


class Browser:
    """One headless Chrome process on a temporary profile, its DevTools websocket and its
    pages (``page()``); an async context manager."""

    def __init__(self, chrome: str | None = None, *, timeout: float = 20.0):
        self.chrome = chrome or find_chrome()
        self.timeout = timeout
        self.process = None
        self.profile = None
        self.session = None
        self.ws = None
        self.reader = None
        self.pending: dict[int, asyncio.Future] = {}
        self.pages: dict[str, Page] = {}
        self.next_id = 0

    async def __aenter__(self):
        if not self.chrome:
            raise BrowserError("no Chrome / Chromium found")
        self.profile = tempfile.mkdtemp(prefix='sre-chrome-')
        args = [self.chrome, '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
                '--disable-background-timer-throttling', '--disable-renderer-backgrounding',
                '--disable-backgrounding-occluded-windows', '--disable-extensions', '--disable-sync',
                '--disable-features=TranslateUI', '--window-size=1280,900', f'--user-data-dir={self.profile}',
                '--remote-debugging-port=0', 'about:blank']
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            args.insert(1, '--no-sandbox')          # Chrome refuses its sandbox as root
        # On Linux, Chrome asks the session bus (the desktop portal) for the proxy settings at its
        # first navigation; a session bus without a desktop (root over ssh: pam_systemd exports
        # DBUS_SESSION_BUS_ADDRESS, nothing answers) makes it wait the 25 s D-Bus timeout, longer
        # than the command timeout below (measured on a Debian 13 workstation, Chrome 157 and
        # Chromium 150 alike; 0.3 s with the address below, which Chrome takes as "no bus").
        env = {**os.environ, 'DBUS_SESSION_BUS_ADDRESS': '/dev/null'}
        try:
            self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL, env=env)
        except OSError as e:
            raise BrowserError(f"cannot run {self.chrome}: {e}") from e
        try:
            port, path = await self._devtools_address()
            self.session = aiohttp.ClientSession()
            self.ws = await self.session.ws_connect(f'ws://127.0.0.1:{port}{path}', max_msg_size=0)
        except BaseException:
            await self._stop()
            raise
        self.reader = asyncio.create_task(self._read())
        return self

    async def _devtools_address(self) -> tuple:
        """The port and the websocket path Chrome writes in DevToolsActivePort of the profile."""
        marker = os.path.join(self.profile, 'DevToolsActivePort')
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise BrowserError(f"Chrome exited with status {self.process.returncode}")
            try:
                lines = open(marker, encoding='utf-8').read().splitlines()
            except OSError:
                lines = []
            if len(lines) >= 2 and lines[0].strip().isdigit():
                return int(lines[0]), lines[1].strip()
            await asyncio.sleep(0.1)
        raise BrowserError("Chrome did not open its DevTools port")

    async def __aexit__(self, *exc):
        if self.reader:
            self.reader.cancel()
            try:
                await self.reader
            except (asyncio.CancelledError, Exception):
                pass
        await self._stop()

    async def _stop(self):
        if self.ws is not None and not self.ws.closed:
            try:
                await self.ws.close()
            except Exception:
                pass
        if self.session is not None:
            await self.session.close()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                await asyncio.to_thread(self.process.wait, 5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                await asyncio.to_thread(self.process.wait, 5)
        if self.profile:
            shutil.rmtree(self.profile, ignore_errors=True)

    async def _read(self):
        async for msg in self.ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                break
            data = json.loads(msg.data)
            if 'id' in data:
                future = self.pending.pop(data['id'], None)
                if future is not None and not future.done():
                    future.set_result(data)
            elif data.get('sessionId') in self.pages:
                self.pages[data['sessionId']]._event(data.get('method', ''), data.get('params', {}))
        for future in self.pending.values():
            if not future.done():
                future.set_exception(BrowserError("the DevTools connection closed"))

    async def send(self, method: str, params: dict | None = None, *, session_id: str | None = None) -> dict:
        """One command of the protocol; its result, or ``BrowserError`` with its error."""
        self.next_id += 1
        message = {'id': self.next_id, 'method': method, 'params': params or {}}
        if session_id:
            message['sessionId'] = session_id
        future = asyncio.get_running_loop().create_future()
        self.pending[self.next_id] = future
        await self.ws.send_str(json.dumps(message))
        async with asyncio.timeout(self.timeout):
            reply = await future
        if 'error' in reply:
            raise BrowserError(f"{method}: {reply['error'].get('message')} ({reply['error'].get('code')})")
        return reply.get('result', {})

    async def page(self, url: str | None = None, *, new_window: bool = False) -> Page:
        """A new tab, loaded with *url* when given; *new_window*: in a window of its own.  The tabs
        of one window take turns: only the last one opened is visible, and a hidden page gets no
        animation frame (xterm.js draws its rows in them), so two users watching each other (a
        presentation) each need a window."""
        params = {'url': 'about:blank'}
        if new_window:
            params['newWindow'] = True
        target = await self.send('Target.createTarget', params)
        attached = await self.send('Target.attachToTarget', {'targetId': target['targetId'], 'flatten': True})
        page = Page(self, target['targetId'], attached['sessionId'])
        self.pages[page.session_id] = page
        await self.send('Runtime.enable', session_id=page.session_id)
        await self.send('Page.enable', session_id=page.session_id)
        if url:
            await page.goto(url)
        return page


class IdentityProxy:
    """A reverse proxy on a loopback port adding *headers* (the identity of proxy mode) to
    every request, HTTP and WebSocket, forwarded to *target*; ``url`` once started."""

    def __init__(self, target: str, headers: dict):
        self.target = target.rstrip('/')
        self.headers = dict(headers)
        self.runner = None
        self.session = None
        self.url = None

    async def start(self) -> str:
        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())
        app = web.Application(client_max_size=16 * 1024 * 1024)
        app.router.add_route('*', '/{tail:.*}', self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        self.url = f'http://127.0.0.1:{port}'
        return self.url

    async def close(self):
        if self.runner is not None:
            await self.runner.cleanup()
        if self.session is not None:
            await self.session.close()

    async def _handle(self, request):
        url = self.target + request.path_qs
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS}
        headers.update(self.headers)
        if request.headers.get('Upgrade', '').lower() == 'websocket':
            protocols = [s.strip() for s in request.headers.get('Sec-WebSocket-Protocol', '').split(',') if s.strip()]
            upstream = await self.session.ws_connect(url, headers=headers, protocols=protocols)
            ws = web.WebSocketResponse(protocols=protocols)
            await ws.prepare(request)

            async def pump(src, dst):
                async for msg in src:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await dst.send_str(msg.data)
                    elif msg.type == aiohttp.WSMsgType.BINARY:
                        await dst.send_bytes(msg.data)
                    else:
                        break
                await dst.close()

            await asyncio.gather(pump(upstream, ws), pump(ws, upstream), return_exceptions=True)
            return ws
        body = await request.read()
        async with self.session.request(request.method, url, headers=headers, data=body,
                                        allow_redirects=False) as resp:
            data = await resp.read()
            out = {k: v for k, v in resp.headers.items()
                   if k.lower() not in ('content-length', 'transfer-encoding', 'content-encoding', 'connection')}
            return web.Response(status=resp.status, headers=out, body=data)
