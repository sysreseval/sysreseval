"""Relaying a browser request to the agent of a host: the identity headers are added, the
answer comes back as it is (JSON, a byte stream, an NDJSON stream) or, for a WebSocket, the two
sockets are piped frame by frame."""
import asyncio
import contextlib
import json
import logging

import aiohttp
from aiohttp import web, WSMsgType

from .pool import Pool, PoolError
from ..config import HostConfig
from ..identity import Identity

log = logging.getLogger('sreweb.portal')

#: Headers of the agent's answer copied to the browser.
COPIED_HEADERS = ('Content-Type', 'Content-Disposition', 'Cache-Control')
#: Response headers never copied (hop-by-hop or set by this server).
RELAY_TIMEOUT = aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=None)


class Relay:
    def __init__(self, pool: Pool, session: aiohttp.ClientSession):
        self.pool = pool
        self.session = session

    def _url(self, host: HostConfig, path: str) -> str:
        return f"{host.url}/v1{path}"

    async def json(self, host: HostConfig, identity: Identity, method: str, path: str, *, json=None,
                   params=None, timeout: float = 60.0) -> tuple[int, object]:
        """A JSON call: ``(status, body)`` (the body a dict, or ``{'error': ...}``)."""
        try:
            async with self.session.request(method, self._url(host, path), headers=self.pool.headers(host, identity),
                                            json=json, params=params,
                                            timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 204:
                    return 204, None
                try:
                    return resp.status, await resp.json()
                except (ValueError, aiohttp.ContentTypeError):
                    text = await resp.text()
                    return resp.status, {'error': text[:500] or f"agent answered {resp.status}", 'status': resp.status}
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise PoolError(502, f"the host {host.name} does not answer: {e or type(e).__name__}")

    async def forward(self, request: web.Request, host: HostConfig, identity: Identity, method: str, path: str,
                      *, data=None, params=None) -> web.StreamResponse:
        """Relay a request and stream the answer back whatever its kind (JSON, NDJSON, a file)."""
        try:
            async with self.session.request(method, self._url(host, path), headers=self.pool.headers(host, identity),
                                            data=data, params=params, timeout=RELAY_TIMEOUT) as upstream:
                headers = {k: upstream.headers[k] for k in COPIED_HEADERS if k in upstream.headers}
                response = web.StreamResponse(status=upstream.status, headers=headers)
                await response.prepare(request)
                async for chunk in upstream.content.iter_any():
                    await response.write(chunk)
                await response.write_eof()
                return response
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise PoolError(502, f"the host {host.name} does not answer: {e or type(e).__name__}")

    async def forward_ndjson(self, request: web.Request, host: HostConfig, identity: Identity, method: str,
                             path: str, *, data=None, params=None, headers=None) -> web.StreamResponse:
        """Relay a request whose answer is an NDJSON stream (``start``), line by
        line: the ``result`` line names the host as the browser knows it (``host.name``), not as
        the agent calls itself."""
        request_headers = self.pool.headers(host, identity)
        request_headers.update(headers or {})
        try:
            async with self.session.request(method, self._url(host, path), headers=request_headers, data=data,
                                            params=params, timeout=RELAY_TIMEOUT) as upstream:
                copied = {k: upstream.headers[k] for k in COPIED_HEADERS if k in upstream.headers}
                response = web.StreamResponse(status=upstream.status, headers=copied)
                await response.prepare(request)
                if upstream.status != 200:
                    await response.write(await upstream.read())
                    await response.write_eof()
                    return response
                async for line in upstream.content:
                    text = line.rstrip(b'\r\n')
                    if not text:
                        continue
                    try:
                        obj = json.loads(text)
                    except ValueError:
                        obj = None
                    if isinstance(obj, dict) and obj.get('phase') == 'result' and 'host' in obj:
                        obj['host'] = host.name
                        text = json.dumps(obj).encode('utf-8')
                    await response.write(text + b'\n')
                await response.write_eof()
                return response
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise PoolError(502, f"the host {host.name} does not answer: {e or type(e).__name__}")

    async def websocket(self, request: web.Request, host: HostConfig, identity: Identity, path: str, *,
                        protocols=(), params=None, heartbeat: float = 30.0) -> web.WebSocketResponse:
        """Pipe a WebSocket of the browser to the same path on the agent, frame by frame."""
        ws = web.WebSocketResponse(protocols=protocols, heartbeat=heartbeat, max_msg_size=1 << 20)
        try:
            upstream = await self.session.ws_connect(self._url(host, path), headers=self.pool.headers(host, identity),
                                                     protocols=protocols, params=params, heartbeat=heartbeat,
                                                     max_msg_size=1 << 20)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            await ws.prepare(request)
            await ws.close(code=4502, message=f"the host {host.name} does not answer".encode())
            log.warning("ws to %s failed: %s", host.name, e)
            return ws
        await ws.prepare(request)

        async def pump(src, dst, close_code_default=1000):
            try:
                async for msg in src:
                    if msg.type == WSMsgType.BINARY:
                        await dst.send_bytes(msg.data)
                    elif msg.type == WSMsgType.TEXT:
                        await dst.send_str(msg.data)
                    elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
            except (aiohttp.ClientError, ConnectionResetError, asyncio.CancelledError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    await dst.close(code=getattr(src, 'close_code', None) or close_code_default)

        down = asyncio.ensure_future(pump(upstream, ws))
        up = asyncio.ensure_future(pump(ws, upstream))
        try:
            await asyncio.wait({down, up}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (down, up):
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            with contextlib.suppress(Exception):
                await upstream.close()
            with contextlib.suppress(Exception):
                await ws.close()
        return ws
