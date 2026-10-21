"""The HTTP API of the agent (``/v1/...``), called by the portal only.

Every request carries the bearer token of the agent and the ``X-SRE-*`` identity headers of the
web user (``sreweb.identity``); the handlers check the access rules (``access.py``) and drive
``sre`` through the runner, the registry, the answers store and the schedulers.  Long
operations stream: ``start`` answers NDJSON (one JSON object per line, the events of
``SRE/progress.py`` then a final ``result`` line), ``export`` streams the bytes, the events and
the terminals are WebSockets.  Save and restore are not offered on the web.
"""
import asyncio
import base64
import binascii
import contextlib
import hmac
import json
import logging
import os
import socket
import time

from aiohttp import web, WSMsgType

from SRE import params
from SRE import common
from SRE.common import TranslatedText
from SRE.evaluation_table import build_evaluation_rows, header_labels, rows_to_json
from SRE.form_spec import parse_form_description, chunks_to_json

from . import access
from .access import AccessError
from .answers import AnswersStore
from .pty_session import PtySession
from .registry import Registry, Project, EVENT_INFO
from .runner import (SreRunner, CommandError, CommandTimeout, FlavorFormNeeded, FlavorError, build_argv,
                     build_env, PHASE_PROJECT)
from .schedulers import Schedulers
from ..config import AgentConfig
from ..identity import Identity, IdentityError, IDENTITY_KEY
from ..i18n import translator
from ..projectview import sanitise, schema_svg, lang_priority

log = logging.getLogger('sreweb.agent')

API_PREFIX = '/v1'
AGENT_KEY = web.AppKey('agent', object)
TERMINAL_SUBPROTOCOL = 'sre-term.v1'
NDJSON = 'application/x-ndjson'
#: Close codes of the terminal WebSocket.
WS_UNAUTHENTICATED = 4401
WS_FORBIDDEN = 4403
WS_NOT_FOUND = 4404
WS_LIMIT = 4409
MAX_TERMINAL_COLS, MAX_TERMINAL_ROWS = 500, 300
EARLY_INPUT_MAX = 4096       # keystrokes held until the first output of the terminal
EARLY_INPUT_HOLD = 20.0      # seconds after which they go through anyway
CLIENT_MAX_SIZE = 4 << 20        # the answers of a PUT (the portal caps them lower)
WS_HEARTBEAT = 30.0


def json_error(status: int, message: str) -> web.Response:
    return web.json_response({'error': message, 'status': status}, status=status)


def _mem_available_mb() -> int | None:
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith('MemAvailable:'):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


class Agent:
    def __init__(self, cfg: AgentConfig, *, pub_dir: str | None = None, projects_dir: str | None = None,
                 localedirs=None, hostname: str | None = None, extra_env: dict | None = None):
        self.cfg = cfg
        self.pub_dir = pub_dir or params.sre_pub_dir
        self.projects_dir = projects_dir or params.sre_projects_dir
        self.localedirs = list(localedirs if localedirs is not None else params.locale_dirs)
        self.hostname = hostname or socket.gethostname()
        self.runner = SreRunner(cfg.sre_exe, timeouts=cfg.timeouts, max_concurrent_starts=cfg.max_concurrent_starts,
                                max_concurrent_evals=cfg.max_concurrent_evals, extra_env=extra_env)
        self.registry = Registry(self.projects_dir, poll_interval=cfg.poll_interval, state_dir=cfg.state_dir)
        self.registry.info_event = self._info_event
        self.answers = AnswersStore(self.registry, hostname=self.hostname, pub_dir=self.pub_dir)
        self.schedulers = Schedulers(self.registry, self.runner, exam_mode=self.exam_mode,
                                     default_idle_timeout=cfg.max_idle)
        self._labs_cache: tuple[float, list] | None = None
        self._labs_lock = asyncio.Lock()

    # -- helpers --------------------------------------------------------------------------------

    def exam_mode(self) -> bool:
        return access.exam_mode_on(self.pub_dir)

    def _info_event(self, project: Project, identity: Identity) -> dict:
        return {'t': EVENT_INFO, 'project': sanitise(project.info, identity, exam_mode=self.exam_mode())}

    def _project(self, request) -> Project:
        rln = access.check_running_lab_name(request.match_info.get('rln', ''))
        project = self.registry.require(rln)
        access.check_owner(rln, request[IDENTITY_KEY])
        project.touch()
        return project

    async def labs(self, login: str) -> list:
        async with self._labs_lock:
            now = time.monotonic()
            if self._labs_cache is not None and now - self._labs_cache[0] < self.cfg.lab_list_cache_ttl:
                return self._labs_cache[1]
            result = await self.runner.run(login, ['list', '--with-titles'])
            try:
                labs = json.loads(result.stdout.decode('utf-8', 'replace'))
            except ValueError:
                raise CommandError(0, "sre list gave no JSON", result.stderr)
            if not isinstance(labs, list):
                raise CommandError(0, "sre list gave no list", result.stderr)
            self._labs_cache = (now, labs)
            return labs

    # -- application ----------------------------------------------------------------------------

    def make_app(self) -> web.Application:
        app = web.Application(middlewares=[self.auth_middleware, self.error_middleware],
                              client_max_size=CLIENT_MAX_SIZE)
        app[AGENT_KEY] = self
        p = API_PREFIX
        app.router.add_get(f'{p}/status', self.status)
        app.router.add_get(f'{p}/labs', self.labs_handler)
        app.router.add_get(f'{p}/projects', self.projects_list)
        app.router.add_post(f'{p}/projects', self.projects_create)
        app.router.add_get(f'{p}/projects/{{rln}}', self.project_get)
        app.router.add_delete(f'{p}/projects/{{rln}}', self.project_close)
        app.router.add_get(f'{p}/projects/{{rln}}/events', self.events_ws)
        app.router.add_get(f'{p}/projects/{{rln}}/schema.svg', self.schema)
        app.router.add_put(f'{p}/projects/{{rln}}/answers', self.answers_put)
        app.router.add_post(f'{p}/projects/{{rln}}/eval', self.eval_post)
        app.router.add_post(f'{p}/projects/{{rln}}/states/{{state}}', self.state_post)
        app.router.add_get(f'{p}/projects/{{rln}}/terminals/{{device}}', self.terminal_ws)
        app.router.add_get(f'{p}/projects/{{rln}}/log', self.log_get)
        app.router.add_post(f'{p}/projects/{{rln}}/touch', self.touch)
        app.router.add_get(f'{p}/projects/{{rln}}/export', self.export_get)
        app.on_startup.append(self._on_startup)
        app.on_shutdown.append(self._on_shutdown)
        return app

    async def _on_startup(self, app):
        await self.registry.tick()
        self.registry.start()

    async def _on_shutdown(self, app):
        await self.registry.stop()

    # -- middlewares ----------------------------------------------------------------------------

    @web.middleware
    async def auth_middleware(self, request, handler):
        auth = request.headers.get('Authorization', '')
        scheme, _, token = auth.partition(' ')
        if scheme.lower() != 'bearer' or not hmac.compare_digest(token.strip(), self.cfg.token):
            return json_error(401, "bad agent token")
        if request.path == f'{API_PREFIX}/status':
            request[IDENTITY_KEY] = None   # polled by the portal itself, no user behind it
            return await handler(request)
        try:
            request[IDENTITY_KEY] = Identity.from_headers(request.headers)
        except IdentityError as e:
            return json_error(400, str(e))
        return await handler(request)

    @web.middleware
    async def error_middleware(self, request, handler):
        try:
            return await handler(request)
        except AccessError as e:
            return json_error(e.status, e.message)
        except CommandTimeout as e:
            log.warning("%s %s: %s", request.method, request.path, e.message)
            return json_error(504, e.message)
        except CommandError as e:
            log.warning("%s %s: sre failed (%s): %s", request.method, request.path, e.rc,
                        e.message or e.stderr.strip()[-500:])
            return json_error(502, e.message or f"sre failed ({e.rc})")
        except FileNotFoundError as e:
            log.error("cannot run sre: %s", e)
            return json_error(500, "cannot run sre on this host")
        except web.HTTPException:
            raise
        except Exception:
            log.exception("unhandled error on %s %s", request.method, request.path)
            return json_error(500, "internal error")

    # -- host ------------------------------------------------------------------------------------

    async def status(self, request):
        try:
            load1 = os.getloadavg()[0]
        except OSError:
            load1 = None
        return web.json_response({
            'hostname': self.hostname, 'sre_version': params.sre_version,
            'projects': self.registry.count(),
            'terminals': sum(p.terminal_count() for p in self.registry.projects.values()),
            'exam_mode': self.exam_mode(), 'load1': load1, 'mem_available_mb': _mem_available_mb(),
        })

    async def labs_handler(self, request):
        if self.exam_mode():
            return web.json_response([])
        return web.json_response(await self.labs(request[IDENTITY_KEY].login))

    # -- projects --------------------------------------------------------------------------------

    async def projects_list(self, request):
        identity = request[IDENTITY_KEY]
        return web.json_response([dict(p.to_dict(), title=common.project_title(p.info, lang_priority(identity, p.info)))
                                  for p in self.registry.visible_to(identity)])

    async def _read_json(self, request) -> dict:
        try:
            body = await request.json()
        except ValueError:
            raise AccessError(400, "a JSON body is expected")
        if not isinstance(body, dict):
            raise AccessError(400, "a JSON object is expected")
        return body

    async def projects_create(self, request):
        identity = request[IDENTITY_KEY]
        body = await self._read_json(request)
        access.check_not_exam(self.pub_dir)
        lab = body.get('lab')
        if not isinstance(lab, str) or not lab:
            raise AccessError(400, "lab is required")
        labs = await self.labs(identity.login)
        if lab not in {entry.get('name') if isinstance(entry, dict) else entry for entry in labs}:
            raise AccessError(404, f"unknown lab {lab}")
        args = ['start']
        flavor = body.get('flavor_json')
        if flavor is not None:
            if not isinstance(flavor, dict):
                raise AccessError(400, "flavor_json must be an object")
            args += ['--flavor-json', json.dumps(flavor)]
        args.append(lab)
        return await self._stream_creation(request, identity, args, body.get('idle_timeout'))

    async def _stream_creation(self, request, identity: Identity, args: list, idle_timeout):
        """``sre start`` as an NDJSON stream."""
        try:
            idle = None if idle_timeout is None else max(0.0, float(idle_timeout))
        except (TypeError, ValueError):
            raise AccessError(400, "bad idle_timeout")
        resp = web.StreamResponse(status=200, headers={'Content-Type': NDJSON, 'Cache-Control': 'no-cache'})
        await resp.prepare(request)

        async def line(obj):
            await resp.write(json.dumps(obj).encode('utf-8') + b'\n')

        try:
            run = await self.runner.stream(identity.login, args, lang=identity.language)
            async for event in run.events():
                await line(event)
            run.result()
        except FlavorFormNeeded as e:
            form = TranslatedText.from_value(e.form).resolve_priority([identity.language, 'en'])
            chunks = chunks_to_json(parse_form_description(form, allow_submit=True), show_instructor=False)
            await line({'phase': 'result', 'status': 'flavor_form', 'form': form, 'form_size': e.form_size,
                        'chunks': chunks})
            return resp
        except FlavorError as e:
            await line({'phase': 'result', 'status': 'flavor_error', 'message': e.message})
            return resp
        except CommandTimeout as e:
            await line({'phase': 'result', 'status': 'error', 'message': e.message})
            return resp
        except CommandError as e:
            await line({'phase': 'result', 'status': 'error', 'message': e.message or f"sre failed ({e.rc})"})
            return resp
        except FileNotFoundError:
            await line({'phase': 'result', 'status': 'error', 'message': "cannot run sre on this host"})
            return resp
        rln = run.created_running_lab_name()
        project = await self.registry.adopt(rln) if rln else None
        if project is None:
            await line({'phase': 'result', 'status': 'error', 'message': "the new project was not found"})
            return resp
        if idle is not None:
            project.idle_timeout = idle
        project.touch()
        self.registry.write_state(project, force=True)
        await line({'phase': 'result', 'status': 'created', 'running_lab_name': project.rln, 'host': self.hostname})
        return resp

    async def project_get(self, request):
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        return web.json_response({
            'project': sanitise(project.info, identity, exam_mode=self.exam_mode()),
            'answers': AnswersStore.public(self.answers.read(project), project),
            'running_lab_name': project.rln, 'host': self.hostname,
        })

    async def project_close(self, request):
        project = self._project(request)
        await self.schedulers.close_project(project)
        with contextlib.suppress(Exception):
            await self.registry.tick()
        return web.json_response({'ok': True})

    async def touch(self, request):
        self._project(request)
        return web.Response(status=204)

    async def schema(self, request):
        project = self._project(request)
        try:
            svg = schema_svg(project.info, request[IDENTITY_KEY], request.query)
        except ValueError as e:
            raise AccessError(400, str(e))
        return web.Response(text=svg, content_type='image/svg+xml', headers={'Cache-Control': 'no-cache'})

    async def log_get(self, request):
        project = self._project(request)
        if not (project.info.get('debug_project') or
                access.instructor_view_allowed(project.info, request[IDENTITY_KEY])):
            raise AccessError(403, "no log for this project")
        try:
            offset = max(0, int(request.query.get('offset', 0)))
        except ValueError:
            raise AccessError(400, "bad offset")
        try:
            with open(project.log_path, 'rb') as f:
                f.seek(offset)
                data = f.read()
            end = offset + len(data)
        except OSError:
            data, end = b'', 0
        return web.json_response({'data': data.decode('utf-8', 'replace'), 'offset': offset, 'end': end})

    # -- answers, evaluation, states --------------------------------------------------------------

    async def answers_put(self, request):
        project = self._project(request)
        body = await self._read_json(request)
        patch = body.get('answers', body)
        if not isinstance(patch, dict):
            raise AccessError(400, "answers must be an object")
        data = await self.answers.put(project, patch, request[IDENTITY_KEY])
        return web.json_response({'answers': AnswersStore.public(data, project),
                                  'answers_updated_at': data.get(params.sysreseval_answers_updated_at, '')})

    async def eval_post(self, request):
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        access.check_self_grade(project.info)
        access.check_not_exam(self.pub_dir)
        if project.lock.locked():
            raise AccessError(409, "the project is busy")
        async with project.lock:
            result = await self.runner.run(project.owner, ['eval', '--auto-eval', project.rln], lang=identity.language)
        try:
            data = json.loads(result.stdout.decode('utf-8', 'replace'))
        except ValueError:
            raise CommandError(0, "sre eval gave no JSON", result.stderr)
        rows, header = [], []
        if data.get('grades') is not None:
            translate = translator(identity.language, self.localedirs)
            debug = bool(project.info.get('debug_project', False))
            rows = rows_to_json(build_evaluation_rows(
                data.get('grades', []), data.get('grade_parts', []) or [], mark=data.get('mark'),
                maximum_mark=data.get('maximum_mark'), debug=debug,
                lang_priority=lang_priority(identity, project.info), translate=translate))
            header = header_labels(debug=debug, translate=translate)
        return web.json_response({'result': data, 'rows': rows, 'header': header,
                                  'delay_before_self_grade': data.get('delay_before_self_grade', 0)})

    async def state_post(self, request):
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        state = request.match_info.get('state', '')
        access.check_state(project.info, state, identity)
        access.check_not_exam(self.pub_dir)
        if project.lock.locked():
            raise AccessError(409, "the project is busy")
        async with project.lock:
            await self.runner.run(project.owner, ['state', project.rln, state], lang=identity.language)
        answers = await self.answers.consume_cheat(project)
        if answers is None:
            answers = self.answers.read(project)
        return web.json_response({'ok': True, 'answers': AnswersStore.public(answers, project)})

    # -- export ---------------------------------------------------------------------------------

    async def export_get(self, request):
        project = self._project(request)
        access.check_export(project.info)
        q = request.query
        args = ['export', project.rln]
        if q.get('curved', '') in ('1', 'true'):
            args.append('--curved')
        if q.get('shapes', '') in ('1', 'true'):
            args.append('--shapes')
        if q.get('reverse', '') in ('1', 'true'):
            args.append('--reverse')
        for key, flag in (('sep', '--sep'), ('random_seed', '--random-seed')):
            if key in q:
                try:
                    args += [flag, str(int(q[key]))]
                except ValueError:
                    raise AccessError(400, f"bad {key}")
        name = params.get_abbreviated_lab_name_from_running_lab_name(project.rln)
        resp = web.StreamResponse(headers={'Content-Type': 'application/zip',
                                           'Content-Disposition': f'attachment; filename="{name}.zip"'})
        await resp.prepare(request)
        remainder = b''
        async with project.lock:
            async for chunk in self.runner.stream_stdout(project.owner, args):
                text = remainder + b''.join(chunk.split())
                usable = len(text) - len(text) % 4
                remainder = text[usable:]
                if usable:
                    try:
                        await resp.write(binascii.a2b_base64(text[:usable]))
                    except binascii.Error:
                        raise CommandError(0, "sre export gave no base64")
        if remainder:
            with contextlib.suppress(binascii.Error):
                await resp.write(base64.b64decode(remainder + b'=' * (-len(remainder) % 4)))
        await resp.write_eof()
        return resp

    # -- WebSockets -----------------------------------------------------------------------------

    async def events_ws(self, request):
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        ws = web.WebSocketResponse(heartbeat=WS_HEARTBEAT)
        await ws.prepare(request)
        sub = self.registry.subscribe(project, ws.send_json, identity)
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
                project.touch()
        finally:
            self.registry.unsubscribe(project, sub)
        return ws

    async def terminal_ws(self, request):
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        device = request.match_info.get('device', '')
        ws = web.WebSocketResponse(protocols=(TERMINAL_SUBPROTOCOL,), heartbeat=WS_HEARTBEAT, max_msg_size=1 << 20)
        try:
            access.check_device(project.info, device, identity)
            access.check_not_exam(self.pub_dir)
            if project.closing:
                raise AccessError(404, "the project is closing")
            if (project.terminal_count() >= self.cfg.terminals_per_project
                    or len(project.terminals.get(device, [])) >= self.cfg.terminals_per_device):
                raise AccessError(429, "too many terminals")
        except AccessError as e:
            await ws.prepare(request)
            await ws.send_json({'t': 'error', 'message': e.message})
            await ws.close(code={403: WS_FORBIDDEN, 404: WS_NOT_FOUND, 429: WS_LIMIT}.get(e.status, WS_FORBIDDEN),
                           message=e.message.encode())
            return ws
        await ws.prepare(request)
        cols, rows = self._size(request.query)
        buffer = bytearray()
        wake = asyncio.Event()
        exited = asyncio.Event()
        exit_code = [None]
        # Keystrokes typed before the shell shows up are held: Kathara switches the pty to raw
        # mode with TCSAFLUSH when it attaches, which discards whatever is queued on it.
        started = asyncio.Event()
        early_input = bytearray()

        def on_output(data: bytes):
            if not started.is_set():
                started.set()
                if early_input:
                    session.write(bytes(early_input))
                    early_input.clear()
            buffer.extend(data)
            session.output_pending(len(buffer))
            wake.set()

        def on_exit(rc):
            exit_code[0] = rc
            exited.set()
            wake.set()

        env = build_env(project.owner, term='xterm-256color', lang=identity.language)
        env.update(self.runner.extra_env)
        session = PtySession(build_argv(self.cfg.sre_exe, ['connect', project.rln, device]), env,
                             cols=cols, rows=rows, on_output=on_output, on_exit=on_exit)
        project.terminals.setdefault(device, []).append(session)
        try:
            await session.start()
        except OSError as e:
            project.terminals[device].remove(session)
            await ws.send_json({'t': 'error', 'message': f"cannot start the terminal: {e}"})
            await ws.close(code=WS_NOT_FOUND)
            return ws
        await ws.send_json({'t': 'ready'})
        log.info("terminal %s/%s opened for %s", project.rln, device, identity.login)

        async def sender():
            while True:
                await wake.wait()
                wake.clear()
                if buffer:
                    data = bytes(buffer)
                    buffer.clear()
                    session.output_pending(0)
                    project.touch()
                    await ws.send_bytes(data)
                if exited.is_set() and not buffer:
                    with contextlib.suppress(Exception):
                        await ws.send_json({'t': 'exit', 'code': exit_code[0]})
                    await ws.close()
                    return

        def type_in(data: bytes):
            if started.is_set():
                session.write(data)
            elif len(early_input) < EARLY_INPUT_MAX:
                early_input.extend(data)

        async def release_early_input():
            # a shell that prints nothing: the held keystrokes go through after a while anyway
            try:
                await asyncio.wait_for(started.wait(), EARLY_INPUT_HOLD)
            except TimeoutError:
                if not started.is_set():
                    started.set()
                    if early_input:
                        session.write(bytes(early_input))
                        early_input.clear()

        sender_task = asyncio.ensure_future(sender())
        release_task = asyncio.ensure_future(release_early_input())
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    type_in(msg.data)
                    project.touch()
                elif msg.type == WSMsgType.TEXT:
                    try:
                        obj = json.loads(msg.data)
                    except ValueError:
                        continue
                    if isinstance(obj, dict) and obj.get('t') == 'resize':
                        c, r = self._size({'cols': obj.get('cols'), 'rows': obj.get('rows')})
                        session.resize(c, r)
                    elif isinstance(obj, dict) and obj.get('t') == 'input' and isinstance(obj.get('data'), str):
                        type_in(obj['data'].encode('utf-8'))
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            for task in (sender_task, release_task):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            with contextlib.suppress(ValueError):
                project.terminals.get(device, []).remove(session)
            await session.close()
            log.info("terminal %s/%s closed", project.rln, device)
        return ws

    @staticmethod
    def _size(query) -> tuple[int, int]:
        def num(key, default, maximum):
            try:
                return max(2, min(maximum, int(query.get(key, default) or default)))
            except (TypeError, ValueError):
                return default
        return num('cols', 80, MAX_TERMINAL_COLS), num('rows', 24, MAX_TERMINAL_ROWS)
